# Phishing URL Detection Using Graph Neural Networks (GNN), Rule-Based Analysis and Blockchain Technology

## Project Overview

This project is a web-based phishing URL detection system that combines Graph Neural Networks (GNN), rule-based analysis, and blockchain-based record storage to identify potentially malicious URLs.

The system analyzes URLs using two detection approaches and combines their results to produce a final prediction. Prediction records are stored in a hash-linked SQLite database to support integrity verification.

## Key Features

- **GNN-Based Detection:** Uses a Graph Attention Network (GAT) to analyze URL features and relationships between URLs.
- **Rule-Based Detection:** Identifies suspicious URL characteristics using predefined security rules.
- **Prediction Fusion:** Combines the outputs of both detection approaches.
- **Blockchain Integration:** Stores prediction records in hash-linked blocks using SHA-256.
- **Integrity Verification:** Checks block hashes and previous-block references to detect data modification.
- **Web Interface:** Provides a Flask-based interface for URL analysis.

## Technologies Used

- Python
- Flask
- PyTorch
- PyTorch Geometric
- Graph Attention Networks (GAT)
- Scikit-learn
- Pandas and NumPy
- SQLite
- SHA-256
- HTML

## Project Structure

Phishing-URL-Detection/
│
├── app.py
├── gnn_model.py
├── rule_based_model.py
├── blockchain_util.py
│
├── templates/
│   └── index.html
│
├── phish_gnn_final.pt
├── preprocessors.pkl
├── Phishing.csv
│
├── requirements.txt
├── README.md
└── .gitignore


**Note:** `Phishing.csv` is required to run the application but is not included in this repository.

## Dataset Setup

The dataset is not included in this repository.

To run the application:

1. Obtain the dataset separately, subject to its distribution licence.
2. Name the file `Phishing.csv`.
3. Place it in the project root directory, alongside `app.py`.
4. Ensure it contains the required `URL` and `Label` columns.

The GNN detector uses this dataset to construct its reference graph during initialization.

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Phishing-URL-Detection
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Install a compatible PyTorch build for your operating system and hardware if necessary.

### 4. Add the dataset

Place `Phishing.csv` in the project root directory.

### 5. Run the application

```bash
python app.py
```

Open the local Flask address displayed in your terminal, usually:

`http://127.0.0.1:5000`

## Blockchain Implementation

The application uses SQLite to store prediction records in hash-linked blocks.

Each block contains:

- Block ID
- URL
- Prediction data
- Previous block hash
- Current block hash
- Timestamp

SHA-256 is used to calculate block hashes.

The blockchain utility also provides an integrity verification function that checks whether stored block data and hash links have been modified.

**Note:** This is a local, SQLite-based hash-linked record system, not a decentralized blockchain network.

## Limitations

- Detection results depend on the quality of the dataset and trained model.
- The dataset must be obtained separately.
- The GNN reference graph is constructed using the supplied dataset.
- Prediction confidence and rule-based risk scores are heuristic outputs and should not be interpreted as calibrated probabilities.
- The system should be further evaluated using independent test data before real-world security deployment.

## Future Enhancements

- Improve GNN model evaluation using independent datasets.
- Enhance phishing feature extraction.
- Improve blockchain verification and storage mechanisms.
- Add real-time threat intelligence integration.
- Improve the web interface and reporting features.

## Author

Developed as an academic project exploring phishing URL detection through graph-based learning, rule-based analysis, and blockchain technology.

## Copyright and Usage

Copyright © 2026 Ankitha L S. All Rights Reserved.

This repository is publicly available for viewing and educational evaluation.

No permission is granted to copy, modify, redistribute, or commercially use this project's source code without prior written permission from the author.

Third-party libraries, datasets, and other external components remain subject to their respective licenses and terms.