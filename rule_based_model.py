
import re
import tldextract
from urllib.parse import urlparse
import math


def contains_typosquatting(domain, brand_list):
    return any(
        brand in domain and domain != brand
        for brand in brand_list
    )


def compute_shannon_entropy(s):
    if not s:
        return 0

    prob = [
        float(s.count(c)) / len(s)
        for c in dict.fromkeys(s)
    ]

    return -sum(p * math.log(p, 2) for p in prob)


class RuleBasedDetector:

    def __init__(self):

        self.brands = [
            'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
            'bank', 'wellsfargo', 'chase', 'citi', 'hsbc',
            'santander', 'appleid', 'netflix', 'facebook',
            'instagram', 'whatsapp', 'twitter', 'linkedin'
        ]

        self.suspicious_tlds = [
            'xyz', 'top', 'loan', 'tk', 'ml',
            'ga', 'cf', 'gq', 'men', 'work'
        ]

    def rule_based_check(self, url):

        if not url or not url.strip():
            return {
                'prediction': "LEGITIMATE",
                'confidence': 0,
                'score': 0,
                'explanation': "Empty URL",
                'triggered_rules': []
            }

        url = url.strip().lower()

        # Parse URL
        parsed = urlparse(url)

        domain = parsed.netloc or ''
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''

        extracted = tldextract.extract(url)

        subdomain = extracted.subdomain or ''
        tld = extracted.suffix or ''
        root_domain = extracted.domain or ''

        registered_domain = (
            f"{root_domain}.{tld}" if tld else root_domain
        )

        # Digit ratio
        digit_ratio = (
            sum(c.isdigit() for c in domain) / len(domain)
            if domain else 0
        )

        # Detection features and weights
        features = {

            'uses_ip': (
                2,
                bool(re.match(
                    r'^(http://|https://)?\d+\.\d+\.\d+\.\d+',
                    url
                ))
            ),

            'shortener': (
                2,
                any(
                    hostname == service or hostname.endswith('.' + service)
                    for service in [
                        'bit.ly',
                        'goo.gl',
                        'tinyurl.com',
                        't.co',
                        'ow.ly',
                        'rebrand.ly'
                    ]
                )
            ),

            'at_symbol': (
                2,
                '@' in url
            ),

            'typosquatting': (
                1.8,
                contains_typosquatting(domain, self.brands)
            ),

            'brand_in_path': (
                1.8,
                any(b in path for b in self.brands)
            ),

            'brand_domain_mismatch': (
                1.8,
                any(b in domain for b in self.brands)
                and not any(
                    b in registered_domain
                    for b in [
                        'paypal.com', 'ebay.com',
                        'amazon.com', 'apple.com',
                        'microsoft.com', 'wellsfargo.com'
                    ]
                )
            ),

            'sensitive_params': (
                1.5,
                any(param in query for param in [
                    'password', 'pin', 'ssn', 'ccv', 'dob'
                ])
            ),

            'redirect_param': (
                1.5,
                'redirect_url=' in query
                or 'return_to=' in query
            ),

            'hex_chars': (
                1.2,
                any(c in url for c in ['%', '\\x'])
            ),

            'non_std_port': (
                1.2,
                ':' in domain
                and any(p in domain for p in [
                    ':80', ':443', ':8080'
                ])
            ),

            'sensitive_ext': (
                1.2,
                any(url.endswith(ext) for ext in [
                    '.exe', '.js', '.jar', '.dll'
                ])
            ),

            'fake_https': (
                1.2,
                'https' in url and not url.startswith('https')
            ),

            'double_slash': (
                1,
                url.count('//') > 1
            ),

            'hyphen_count': (
                1,
                domain.count('-') > 3
            ),

            'subdomain_count': (
                1,
                subdomain.count('.') > 1
            ),

            # HTTP alone is not treated as proof of phishing.
            'suspicious_tld': (
                1,
                tld in self.suspicious_tlds
            ),

            'suspicious_keywords': (
                1,
                any(kw in path for kw in [
                    'login', 'verify', 'account', 'secure',
                    'update', 'banking', 'password',
                    'auth', 'signin'
                ])
            ),

            'long_path': (
                1,
                len(path) > 60
            ),

            'domain_len': (
                1,
                len(domain) > 30
            ),

            'digit_ratio': (
                1,
                digit_ratio > 0.3
            ),

            'multiple_subdomains': (
                1,
                len(subdomain.split('.')) > 3
            ),

            'high_entropy': (
                1,
                compute_shannon_entropy(root_domain) > 3.8
            )
        }

        # Calculate total risk score
        score = sum(
            weight
            for weight, condition in features.values()
            if condition
        )

        # Keep original threshold logic
        threshold = (
            2.7
            if any(b in url for b in [
                'bank', 'paypal', 'chase',
                'citi', 'login', 'account'
            ])
            else 3.0
        )

        is_phishing = score >= threshold

        # This is a heuristic phishing-risk score,
        # not a statistically calibrated probability.
        confidence = round(
            min(score / 6.0, 1.0) * 100,
            2
        )

        # Identify all triggered rules
        triggered_rules = [
            name
            for name, (weight, condition) in features.items()
            if condition
        ]

        # Generate explanations from triggered rules
        explanations = {

            'uses_ip':
                "Uses an IP address instead of a domain name.",

            'shortener':
                "Uses a URL shortening service.",

            'at_symbol':
                "Contains an @ symbol.",

            'typosquatting':
                "Possible brand impersonation detected.",

            'brand_in_path':
                "Contains a brand name in the URL path.",

            'brand_domain_mismatch':
                "Brand name does not match the registered domain.",

            'sensitive_params':
                "Contains sensitive information parameters.",

            'redirect_param':
                "Contains suspicious redirect parameters.",

            'hex_chars':
                "Contains encoded or escaped characters.",

            'non_std_port':
                "Uses a non-standard port.",

            'sensitive_ext':
                "Contains a potentially risky file extension.",

            'fake_https':
                "Contains a misleading HTTPS reference.",

            'double_slash':
                "Contains unusual repeated slashes.",

            'hyphen_count':
                "Domain contains many hyphens.",

            'subdomain_count':
                "Contains multiple subdomains.",

            'suspicious_tld':
                f"Uses a potentially suspicious top-level domain (.{tld}).",

            'suspicious_keywords':
                "Contains potentially sensitive URL keywords.",

            'long_path':
                "Contains an unusually long URL path.",

            'domain_len':
                "Domain name is unusually long.",

            'digit_ratio':
                "Domain contains an unusually high number of digits.",

            'multiple_subdomains':
                "Contains an unusually high number of subdomains.",

            'high_entropy':
                "Domain has high character randomness."
        }

        explanations_found = [
            explanations[name]
            for name in triggered_rules
            if name in explanations
        ]

        explanation_text = (
            "; ".join(explanations_found)
            if explanations_found
            else "No suspicious indicators detected."
        )

        return {
            'prediction': (
                "PHISHING" if is_phishing else "LEGITIMATE"
            ),

            'confidence': confidence,

            'score': score,

            'explanation': explanation_text,

            'triggered_rules': triggered_rules
        }

    def predict(self, url):
        return self.rule_based_check(url)


# Global detector instance
rule_based_detector = RuleBasedDetector()
