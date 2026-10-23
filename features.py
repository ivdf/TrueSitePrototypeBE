# features.py
"""
Shared TLS/URL feature extraction.

Both the training-time collector and the runtime analyzer import from this
module so that the feature definitions cannot drift apart.

Importers:
  * analyzer.py       — runtime inference
  * (future) any trainer that builds a fresh feature CSV

Conventions:
  * Certificate features mirror the layout used when model_cert_only.joblib
    was trained (see train_dual_models.py: CERT_NUM_FEATURES + CERT_CAT_FEATURES).
  * The sentinel -1 means "unknown / could not collect". Training code is
    responsible for filtering those rows out; this module only produces them.
"""

import ipaddress
import math
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

import tldextract
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier


# ── Config ────────────────────────────────────────────────────────────────
NETWORK_TIMEOUT = 5.0

# Public-suffix snapshot bundled with tldextract (no network at import).
_extractor = tldextract.TLDExtract(suffix_list_urls=())

# CA/Browser Forum policy OIDs
EV_POLICY = ObjectIdentifier("2.23.140.1.1")
DV_POLICY = ObjectIdentifier("2.23.140.1.2.1")
OV_POLICY = ObjectIdentifier("2.23.140.1.2.2")

# Sentinel value for "could not collect this feature"
UNKNOWN = -1


# ── Domain helpers ────────────────────────────────────────────────────────
def hostname_of(url: str) -> str | None:
    """Lowercase hostname from a URL or bare domain."""
    if not url:
        return None
    s = url.strip()
    if not s:
        return None
    if "://" not in s:
        s = "https://" + s
    try:
        host = urlsplit(s).hostname
        return host.lower().strip(".") if host else None
    except Exception:
        return None


def registrable_domain(host: str) -> str | None:
    """'example.com' from 'mail.example.co.uk'. Falls back to host for IPs."""
    if not host:
        return None
    try:
        ext = _extractor(host)
        if not ext.suffix:
            return host.lower()
        return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        return None


def san_is_related(san: str, target_base: str) -> bool:
    """True if the SAN shares a registrable domain with the target."""
    san = san.lower().strip(".")
    if san.startswith("*."):
        san = san[2:]
    san_base = registrable_domain(san)
    if not san_base or not target_base:
        return False
    return (
        san_base == target_base
        or san_base.endswith("." + target_base)
        or target_base.endswith("." + san_base)
    )


# ── Network ───────────────────────────────────────────────────────────────
def public_addresses(host: str):
    """Yield (family, socktype, proto, sockaddr) for globally routable IPs."""
    try:
        results = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return
    seen = set()
    for family, socktype, proto, _, sockaddr in results:
        ip_text = sockaddr[0]
        if ip_text in seen:
            continue
        seen.add(ip_text)
        try:
            if ipaddress.ip_address(ip_text).is_global:
                yield family, socktype, proto, sockaddr
        except ValueError:
            continue


def fetch_certificate_der(host: str, timeout: float = NETWORK_TIMEOUT) -> bytes:
    """
    Fetch the presented leaf certificate (DER bytes).

    Verification is intentionally disabled: we collect metadata from whatever
    the server presents. It does NOT mean the certificate is trusted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    last_error = None
    found = False
    for family, socktype, proto, sockaddr in public_addresses(host):
        found = True
        try:
            with socket.socket(family, socktype, proto) as raw:
                raw.settimeout(timeout)
                raw.connect(sockaddr)
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    if not der:
                        raise ValueError("empty certificate")
                    return der
        except (OSError, ssl.SSLError, ValueError) as exc:
            last_error = exc

    if not found:
        raise RuntimeError("no public IP address for host")
    raise RuntimeError(f"TLS fetch failed: {last_error}")


# ── Certificate parsing ───────────────────────────────────────────────────
def validation_type_from_cert(cert: x509.Certificate) -> int:
    """0=DV, 1=OV, 2=EV, -1=unknown."""
    try:
        policies = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value
    except (x509.ExtensionNotFound, ValueError):
        return UNKNOWN

    oids = {p.policy_identifier for p in policies}

    if EV_POLICY in oids:
        return 2
    has_dv = DV_POLICY in oids
    has_ov = OV_POLICY in oids
    if has_dv and has_ov:
        return UNKNOWN
    if has_ov:
        return 1
    if has_dv:
        return 0
    return UNKNOWN


def validation_type_label(value: int) -> str:
    """Convert the numeric code to the string the frontend expects."""
    return {0: "DV", 1: "OV", 2: "EV"}.get(value, "Unknown")


def key_features(cert: x509.Certificate) -> dict:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"key_algorithm": "RSA", "key_length": public_key.key_size}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {"key_algorithm": "EC", "key_length": public_key.key_size}
    algorithm = type(public_key).__name__.removesuffix("PublicKey")
    return {"key_algorithm": algorithm or "Other", "key_length": UNKNOWN}


def extract_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        return san.get_values_for_type(x509.DNSName)
    except (x509.ExtensionNotFound, ValueError):
        return []


def issuer_common_name(cert: x509.Certificate) -> str:
    """Best-effort Issuer CN for display purposes."""
    try:
        for attr in cert.issuer.get_attributes_for_oid(
            __import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME
        ):
            return attr.value
    except Exception:
        pass
    return "Unknown"


# ── High-level feature extractors ─────────────────────────────────────────
def fetch_cert_features(host: str) -> dict | None:
    """
    Return the full certificate feature dict, or None on failure.

    Keys match CERT_NUM_FEATURES + CERT_CAT_FEATURES from train_dual_models.py:
        certificate_age_days, certificate_duration_days, san_count,
        unrelated_san_count, has_unrelated_san, key_length, wildcard,
        validation_type, key_algorithm

    Also includes extra *display* fields (issuer, dates, is_valid) that the
    model does not use but the frontend renders.
    """
    try:
        der = fetch_certificate_der(host)
        cert = x509.load_der_x509_certificate(der)

        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc

        age_days = (now - not_before).days
        if age_days < 0:
            age_days = 0
        duration_days = (not_after - not_before).days
        if duration_days < 0:
            duration_days = 0
        days_until_expiry = (not_after - now).days

        dns_names = extract_dns_names(cert)
        kf = key_features(cert)

        target_base = registrable_domain(host)
        if target_base:
            unrelated = sum(
                1 for n in dns_names if not san_is_related(n, target_base)
            )
            san_count          = len(dns_names)
            unrelated_san_count = unrelated
            has_unrelated_san   = int(unrelated > 0)
        else:
            san_count           = UNKNOWN
            unrelated_san_count = UNKNOWN
            has_unrelated_san   = UNKNOWN

        vtype_int = validation_type_from_cert(cert)

        return {
            # ── Model features ──────────────────────────────────────
            "certificate_age_days":      age_days,
            "certificate_duration_days": duration_days,
            "san_count":                 san_count,
            "unrelated_san_count":       unrelated_san_count,
            "has_unrelated_san":         has_unrelated_san,
            "key_length":                kf["key_length"],
            "key_algorithm":             kf["key_algorithm"],
            "wildcard":                  int(any(n.startswith("*.") for n in dns_names)),
            "validation_type":           vtype_int,
            # ── Display-only fields ─────────────────────────────────
            "issuer":                    issuer_common_name(cert),
            "is_valid":                  days_until_expiry > 0,
            "issued_at":                 not_before.isoformat(),
            "expires_at":                not_after.isoformat(),
            "days_until_expiry":         max(0, days_until_expiry),
        }
    except Exception:
        return None


# ── URL lexical features ──────────────────────────────────────────────────
_SPECIAL_CHARS_RE = re.compile(r'[@!#$%^&*()_=+\[\]{}|;:"\'<>,/?~`]')


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text.lower())
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def fetch_url_features(url: str) -> dict | None:
    """Return the lexical URL feature dict used by model_url_only.joblib."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        ext = _extractor(host)
        subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0

        return {
            "full_url_length":        len(url),
            "path_length":            len(p.path),
            "path_depth":             p.path.count("/"),
            "query_length":           len(p.query),
            "has_query":              1 if p.query else 0,
            "has_fragment":           1 if p.fragment else 0,
            "subdomain_count":        subdomain_count,
            "url_digit_count":        sum(c.isdigit() for c in url),
            "url_special_char_count": len(_SPECIAL_CHARS_RE.findall(url)),
            "url_entropy":            round(shannon_entropy(p.netloc + p.path), 4),
            "protocol_https":         1 if p.scheme == "https" else 0,
        }
    except Exception:
        return None