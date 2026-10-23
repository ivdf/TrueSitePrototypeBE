# analyzer.py
"""
TrueSite URL Analyzer — model-backed.

Loads model_cert_only.joblib and model_url_only.joblib, extracts features
using features.py, and fuses the two model scores into a final verdict.

Response shape is stable so the frontend's ResultsDisplay renders unchanged.
"""

import math
import os
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv

from features import (
    fetch_cert_features,
    fetch_url_features,
    hostname_of,
    registrable_domain,
    validation_type_label,
)

load_dotenv()


# ── Model paths ───────────────────────────────────────────────────────────
CERT_MODEL_PATH = os.getenv("CERT_MODEL_PATH", "model_cert_only.joblib")
URL_MODEL_PATH  = os.getenv("URL_MODEL_PATH",  "model_url_only.joblib")


# ── Fusion weights ────────────────────────────────────────────────────────
CERT_WEIGHT          = 0.70
URL_WEIGHT           = 0.30
PHISHING_THRESHOLD   = 0.65
SUSPICIOUS_THRESHOLD = 0.40
CERT_FAILURE_SCORE   = 1.0


KNOWN_LEGITIMATE = {
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "youtube.com", "netflix.com",
    "paypal.com", "ebay.com", "wikipedia.org", "reddit.com", "instagram.com",
    "whatsapp.com", "telegram.org", "dropbox.com", "stripe.com", "cloudflare.com",
    "anthropic.com", "openai.com", "zoom.us", "slack.com", "notion.so",
    "truesite.haitham.page",
}


# ── Model loading ─────────────────────────────────────────────────────────
def _load_model(path: str, label: str):
    p = Path(path)
    if not p.exists():
        print(f"⚠️  {label} model not found at {path}.")
        return None
    try:
        artifact = joblib.load(p)
        features = (
            artifact.get("feature_order")
            or artifact.get("features")
            or (artifact.get("numeric_features", [])
                + artifact.get("categorical_features", []))
        )
        if not features:
            raise ValueError("artifact has no feature list")
        print(f"✅ Loaded {label} model ({len(features)} features)")
        return {"model": artifact["model"], "features": list(features)}
    except Exception as exc:
        print(f"⚠️  Failed to load {label} model: {exc}")
        return None


MODEL_CERT = _load_model(CERT_MODEL_PATH, "certificate")
MODEL_URL  = _load_model(URL_MODEL_PATH,  "URL")

if MODEL_CERT is None and MODEL_URL is None:
    print(
        "⚠️  WARNING: No ML models loaded. "
        "All verdicts will be 50/50 fallback until models are present."
    )


# ── Inference ─────────────────────────────────────────────────────────────
def _score(model_bundle: dict, features: dict) -> float | None:
    try:
        cols = model_bundle["features"]
        row = {c: features.get(c, np.nan) for c in cols}
        X = pd.DataFrame([row])
        if X.isna().any(axis=None):
            missing = [c for c in cols if features.get(c) is None]
            print(f"  [model] missing features: {missing}")
            return None
        return float(model_bundle["model"].predict_proba(X)[0, 1])
    except Exception as exc:
        print(f"  [model error] {exc}")
        return None


# ── Whitelist ─────────────────────────────────────────────────────────────
def _whitelisted(host: str) -> bool:
    base = registrable_domain(host) or ""
    for known in KNOWN_LEGITIMATE:
        if base == known or host == known or host.endswith("." + known):
            return True
    return False


# ── Frontend domain block ─────────────────────────────────────────────────
def _build_domain_block(url: str, host: str) -> dict:
    from collections import Counter
    p = urlsplit(url)
    base = registrable_domain(host) or ""

    suspicious_kw = [
        kw for kw in (
            "login", "signin", "verify", "secure", "account", "update",
            "confirm", "password", "bank", "paypal", "support", "alert",
        )
        if kw in host.lower()
    ]

    if host:
        c = Counter(host.lower()); n = len(host)
        entropy = -sum((v / n) * math.log2(v / n) for v in c.values())
    else:
        entropy = 0.0

    sub = host[: -len(base) - 1] if base and host != base else ""

    return {
        "full_domain":         host,
        "protocol":            p.scheme or "https",
        "tld":                 base.split(".")[-1] if "." in base else "",
        "core_domain":         base.split(".")[0] if base else host,
        "subdomain":           sub,
        "subdomain_count":     len([s for s in sub.split(".") if s]) if sub else 0,
        "length":              len(host),
        "has_numbers":         any(ch.isdigit() for ch in host),
        "has_hyphens":         "-" in host,
        "is_ip_address":       host.replace(".", "").isdigit() if host else False,
        "suspicious_keywords": suspicious_kw,
        "entropy":             round(entropy, 4),
    }


# ── Verdict-aware reason builder ──────────────────────────────────────────
def _build_reasons(features_5: dict, cert_score: float | None,
                   url_score: float | None, status: str,
                   cert_available: bool = True) -> list[str]:
    r: list[str] = []

    # ── Missing certificate: replace all cert reasons with one clear line ──
    if not cert_available:
        r.append(
            "⚠ Could not retrieve a TLS certificate from this host — "
            "no HTTPS server responded, the handshake failed, "
            "or the certificate was malformed. This is a strong phishing signal."
        )
    else:
        age       = features_5["cert_age_days"]
        san       = features_5["san_count"]
        key       = features_5["key_length"]
        key_algo  = features_5.get("key_algorithm", "RSA")
        wild      = features_5["is_wildcard"]
        vtype     = features_5["validation_type"]

        is_phishing_verdict = status in ("scam", "suspicious")

        # Age
        if age < 30:
            if is_phishing_verdict:
                r.append(f"⚠ Certificate age: {age} days — very new, a phishing indicator")
            else:
                r.append(f"ℹ Certificate age: {age} days — recently renewed (low weight)")
        elif age < 90:
            r.append(f"✓ Certificate age: {age} days — relatively new")
        else:
            r.append(f"✓ Certificate age: {age} days — established certificate")

        # SAN count
        r.append(
            f"{'⚠' if san <= 1 else '✓'} SAN count: {san} "
            f"({'minimal coverage' if san <= 1 else 'normal'})"
        )

        # Key length
        key_strong = (key >= 256) if key_algo == "EC" else (key >= 2048)
        if key_strong:
            r.append(f"✓ Key length: {key} bits ({key_algo}) — meets industry standard")
        else:
            r.append(f"⚠ Key length: {key} bits ({key_algo}) — below industry standard")

        # Wildcard
        r.append(
            "⚠ Wildcard certificate detected — commonly abused in phishing"
            if wild else "✓ No wildcard certificate"
        )

        # Validation type
        r.append(
            f"{'✓' if vtype in ('EV', 'OV') else '⚠'} Validation type: {vtype} "
            f"({'organisation identity verified' if vtype in ('EV', 'OV') else 'DV only — no organisation verified'})"
        )

    # Model scores
    if cert_score is not None:
        r.append(f"Certificate model score: {cert_score:.2f}")
    if url_score is not None:
        r.append(f"URL model score: {url_score:.2f}")

    return r


# ── Main entry point ──────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    if "://" not in url:
        url = "https://" + url

    host = hostname_of(url)
    if not host:
        return _error_response(url, "Could not parse a hostname from the input.")

    domain_block = _build_domain_block(url, host)

    # ── Whitelist fast-path ──────────────────────────────────────────
    if _whitelisted(host):
        return {
            "result":     "legitimate",
            "confidence": 0.98,
            "risk_score": 0.02,
            "details": {
                "domain": domain_block,
                "ssl": {
                    "is_valid": True, "issuer": "Whitelisted",
                    "protocol": "TLS 1.3", "is_trusted_ca": True,
                    "issued_at": "", "expires_at": "",
                    "days_until_expiry": 365, "is_revoked": False,
                },
                "features": {
                    "cert_age_days": 365, "san_count": 10,
                    "key_length": 2048, "key_algorithm": "RSA",
                    "is_wildcard": False, "validation_type": "OV",
                },
                "classification": {
                    "reasons": [f"✓ Domain is in the trusted whitelist ({registrable_domain(host)})"],
                    "fused": 0.02,
                },
            },
        }

    # ── Certificate stage ────────────────────────────────────────────
    cert_feats = fetch_cert_features(host)
    cert_score: float | None = None
    cert_ran = False
    if cert_feats is not None and MODEL_CERT is not None:
        cert_score = _score(MODEL_CERT, cert_feats)
        cert_ran = cert_score is not None

    cert_failed = (cert_feats is None)

    # ── URL stage ────────────────────────────────────────────────────
    url_feats = fetch_url_features(url)
    url_score: float | None = None
    url_ran = False
    if url_feats is not None and MODEL_URL is not None:
        url_score = _score(MODEL_URL, url_feats)
        url_ran = url_score is not None

    # ── Fusion ───────────────────────────────────────────────────────
    if cert_failed:
        fused = CERT_FAILURE_SCORE
    elif cert_ran and url_ran:
        fused = CERT_WEIGHT * cert_score + URL_WEIGHT * url_score
    elif cert_ran:
        fused = cert_score
    elif url_ran:
        fused = url_score
    else:
        fused = 0.5

    if fused >= PHISHING_THRESHOLD:
        status = "scam"
    elif fused >= SUSPICIOUS_THRESHOLD:
        status = "suspicious"
    else:
        status = "legitimate"

    # ── Build the 5-feature display dict ────────────────────────────
    if cert_feats:
        features_5 = {
            "cert_age_days":   cert_feats["certificate_age_days"],
            "san_count":       max(0, cert_feats["san_count"]),
            "key_length":      cert_feats["key_length"],
            "key_algorithm":   cert_feats["key_algorithm"],
            "is_wildcard":     bool(cert_feats["wildcard"]),
            "validation_type": validation_type_label(cert_feats["validation_type"]),
        }
        ssl_block = {
            "is_valid":          cert_feats["is_valid"],
            "is_available":      True,               # ← new
            "issuer":            cert_feats["issuer"],
            "protocol":          "TLS 1.3",
            "is_trusted_ca":     cert_feats["validation_type"] >= 0,
            "issued_at":         cert_feats["issued_at"],
            "expires_at":        cert_feats["expires_at"],
            "days_until_expiry": cert_feats["days_until_expiry"],
            "is_revoked":        False,
        }
    else:
        features_5 = {
            "cert_age_days": 0, "san_count": 0, "key_length": 0,
            "key_algorithm": "Unknown", "is_wildcard": False,
            "validation_type": "Unknown",
        }
        ssl_block = {
            "is_valid":       False,
            "is_available":   False,                 # ← new
            "issuer":         "Not retrievable",
            "protocol":       "N/A",
            "is_trusted_ca":  False,
            "issued_at":      "",
            "expires_at":     "",
            "days_until_expiry": 0,
            "is_revoked":     False,
        }

    reasons = _build_reasons(features_5, cert_score, url_score, status,
                             cert_available=(cert_feats is not None))

    # Confidence is "how sure we are of the verdict"
    confidence = (1 - fused) if status == "legitimate" else fused

    return {
        "result":     status,
        "confidence": round(confidence, 4),
        "risk_score": round(fused, 4),
        "details": {
            "domain":         domain_block,
            "ssl":            ssl_block,
            "features":       features_5,
            "classification": {
                "reasons": reasons,
                "fused":   round(fused, 3),
            },
        },
    }


def _error_response(url: str, reason: str) -> dict:
    return {
        "result":     "suspicious",
        "confidence": 0.5,
        "risk_score": 0.5,
        "details": {
            "domain": {"full_domain": url, "suspicious_keywords": []},
            "ssl": {"is_valid": False, "issuer": "Unknown", "protocol": "Unknown",
                    "is_trusted_ca": False, "issued_at": "", "expires_at": "",
                    "days_until_expiry": 0, "is_revoked": False},
            "features": {"cert_age_days": 0, "san_count": 0, "key_length": 0,
                         "key_algorithm": "Unknown", "is_wildcard": False,
                         "validation_type": "Unknown"},
            "classification": {"reasons": [f"⚠ {reason}"]},
        },
    }