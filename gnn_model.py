
import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
import tldextract

from sklearn.neighbors import NearestNeighbors
from torch_geometric.nn import GATConv
from torch_geometric.data import Data


class PhishGNN(torch.nn.Module):

    def __init__(self, input_dim):
        super().__init__()

        self.conv1 = GATConv(
            input_dim, 128, heads=2, dropout=0.5
        )

        self.conv2 = GATConv(
            256, 64, heads=1, dropout=0.4
        )

        self.skip_lin = torch.nn.Linear(input_dim, 64)

        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(64, 32),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.5),
            torch.nn.Linear(32, 1)
        )

    def forward(self, data):

        x = data.x
        edge_index = data.edge_index

        x_gnn = F.elu(self.conv1(x, edge_index))
        x_gnn = F.elu(self.conv2(x_gnn, edge_index))

        x_skip = F.elu(self.skip_lin(x))

        return self.classifier(
            x_gnn + x_skip
        ).squeeze(-1)


class GNNPhishingDetector:

    def __init__(
        self,
        preprocessor_path="preprocessors.pkl",
        checkpoint_path="phish_gnn_final.pt",
        dataset_path="Phishing.csv"
    ):

        self.device = torch.device("cpu")

        print("Loading GNN preprocessors...")

        self.preprocessors = joblib.load(preprocessor_path)

        self.scaler = self.preprocessors["scaler"]
        self.tld_encoder = self.preprocessors["tld_encoder"]
        self.feature_order = self.preprocessors["feature_order"]

        print("Loading reference dataset...")

        self.df = pd.read_csv(dataset_path)
        self.df.columns = self.df.columns.str.strip()

        self.df = self.df[["URL", "Label"]].dropna().copy()
        self.df["URL"] = self.df["URL"].astype(str).str.strip()

        self.df = self.df.reset_index(drop=True)

        print("Extracting reference URL features...")

        reference_features = pd.DataFrame([
            self.extract_features(url)
            for url in self.df["URL"]
        ], columns=self.feature_order)

        self.reference_x = self.preprocess(reference_features)

        print("Building reference graph...")

        self.neighbors = NearestNeighbors(
            n_neighbors=6,
            metric="cosine"
        )

        self.neighbors.fit(self.reference_x)

        _, indices = self.neighbors.kneighbors(self.reference_x)

        n_samples = len(self.reference_x)

        rows = np.repeat(np.arange(n_samples), 5)
        cols = indices[:, 1:].reshape(-1)

        mask = rows < cols

        rows = rows[mask]
        cols = cols[mask]

        self.reference_edges = torch.tensor(
            np.vstack([rows, cols]),
            dtype=torch.long
        )

        print("Loading trained checkpoint...")

        self.model = PhishGNN(
            input_dim=self.reference_x.shape[1]
        ).to(self.device)

        checkpoint = torch.load(
            checkpoint_path,
            map_location=self.device,
            weights_only=True
        )

        self.model.load_state_dict(checkpoint)
        self.model.eval()

        print("GNN detector initialized successfully.")

    @staticmethod
    def calculate_entropy(url):

        if len(url) <= 1:
            return 0.0

        counts = Counter(url)

        probabilities = [
            count / len(url)
            for count in counts.values()
        ]

        entropy = -sum(
            p * math.log2(p)
            for p in probabilities
        )

        return entropy / math.log2(len(url))

    def extract_features(self, url):

        url = str(url).strip()

        parsed_input = url if "://" in url else "http://" + url

        try:
            parsed = urlparse(parsed_input)
        except ValueError:
            parsed = urlparse("http://invalid.local")

        ext = tldextract.extract(url)

        hostname = parsed.hostname or ""

        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            has_ip = 1
        except ValueError:
            has_ip = 0

        subdomains = [
            part for part in ext.subdomain.split(".") if part
        ]

        features = {
            "url_length": len(url),
            "num_subdomains": len(subdomains),
            "domain_length": len(ext.domain),
            "tld": ext.suffix.lower(),
            "num_hyphens": url.count("-"),
            "num_digits": sum(c.isdigit() for c in url),
            "has_ip": has_ip,
            "path_depth": len([
                part for part in parsed.path.split("/") if part
            ]),
            "num_params": len(parse_qs(parsed.query)),
            "special_chars": sum(
                not c.isalnum() for c in url
            ),
            "is_https": int(parsed.scheme.lower() == "https"),
            "entropy": self.calculate_entropy(url),

            # Placeholder: original cached domain ages were zero.
            "domain_age": 0.0
        }

        return {
            name: features.get(name, 0.0)
            for name in self.feature_order
        }

    def preprocess(self, features_df):

        numeric_columns = [
            column for column in self.feature_order
            if column != "tld"
        ]

        numeric_features = features_df[numeric_columns]

        scaled_numeric = self.scaler.transform(
            numeric_features
        )

        tld_values = features_df[["tld"]].copy()

        try:
            encoded_tld = self.tld_encoder.transform(tld_values)

        except ValueError:

            known_tlds = set(
                self.tld_encoder.categories_[0]
            )

            tld_values["tld"] = tld_values["tld"].apply(
                lambda value:
                value if value in known_tlds else "OTHER"
            )

            encoded_tld = self.tld_encoder.transform(tld_values)

        if hasattr(encoded_tld, "toarray"):
            encoded_tld = encoded_tld.toarray()

        processed = np.hstack([
            scaled_numeric,
            encoded_tld
        ])

        return processed.astype(np.float32)

    def predict(self, url):

        if not isinstance(url, str) or not url.strip():
            raise ValueError("Please provide a valid URL.")

        features = self.extract_features(url)

        features_df = pd.DataFrame(
            [features],
            columns=self.feature_order
        )

        query_x = self.preprocess(features_df)

        # Find five nearest reference URLs.
        _, indices = self.neighbors.kneighbors(
            query_x,
            n_neighbors=5
        )

        reference_indices = indices[0]

        query_index = len(self.reference_x)

        # Connect reference neighbours to the new query node.
        query_edges = np.vstack([
            reference_indices,
            np.full(5, query_index)
        ])

        query_edge_tensor = torch.tensor(
            query_edges,
            dtype=torch.long
        )

        edge_index = torch.cat([
            self.reference_edges,
            query_edge_tensor
        ], dim=1)

        # Add the new URL as the final graph node.
        all_features = np.vstack([
            self.reference_x,
            query_x
        ])

        data = Data(
            x=torch.tensor(
                all_features,
                dtype=torch.float32
            ),
            edge_index=edge_index
        ).to(self.device)

        self.model.eval()

        with torch.no_grad():

            logits = self.model(data)

            probability_good = torch.sigmoid(
                logits[-1]
            ).item()

        probability_phishing = 1.0 - probability_good

        # App integration convention:
        # 1 = phishing, 0 = legitimate.
        prediction = int(probability_phishing >= 0.5)

        return prediction, probability_phishing


# Create detector instance
gnn_detector = GNNPhishingDetector()
