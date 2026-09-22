"""ML-based URL phishing detection (NEXUSSCAN model).

Bundle: RandomForest (250 trees) + StandardScaler + SimpleImputer, 48 lexical features.
See /home/babai/Desktop/codeing/NEXUSSCAN/api/ml_detector.py for reference implementation.

Features 0-25 are URL-lexical (computed from URL string alone).
Features 26-47 are page-content features → NaN when only URL available; imputer fills them.

Usage:
    from .url_ml import predict_url, score_urls_batch
    result = predict_url("https://paypal-secure-login.example.com/verify")
    # {"is_phishing": True, "confidence": 94.2, "risk_score": 0.94}

Thread-safe lazy loading: model loaded once on first predict_url call.
If model unavailable/failed → ModelUnavailableError, caller should fallback gracefully.
"""
from __future__ import annotations

import logging
import os
import re
import warnings
from threading import Lock
from urllib.parse import urlparse, parse_qs

import numpy as np
import pandas as pd

logger = logging.getLogger("url_ml")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Model located at backend/ml_models/url_phishing_model.pkl
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_MODEL_PATH = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", "..", "ml_models", "url_phishing_model.pkl"))

_EXPECTED_FEATURE_COUNT = 48

_SENSITIVE_WORDS = [
    "login", "signin", "sign-in", "bank", "account", "update",
    "secure", "verify", "password", "confirm", "paypal", "ebay",
    "billing", "credential", "wallet",
]
_BRAND_NAMES = [
    "paypal", "ebay", "amazon", "google", "facebook", "microsoft",
    "apple", "chase", "wellsfargo", "citibank", "netflix", "instagram",
]

# ---------------------------------------------------------------------------
# Lazy loader
# ---------------------------------------------------------------------------

class ModelUnavailableError(RuntimeError):
    """Raised when the ML model cannot be loaded or is structurally invalid."""


_model_lock: Lock = Lock()
_model_bundle: dict | None = None
_model_error: str | None = None


def _load_bundle() -> dict:
    """Load and validate the model bundle from disk. Thread-safe, loads once."""
    global _model_bundle, _model_error

    with _model_lock:
        if _model_bundle is not None:
            return _model_bundle

        if _model_error is not None:
            raise ModelUnavailableError(_model_error)

        if not os.path.isfile(_MODEL_PATH):
            _model_error = f"Model file not found: {_MODEL_PATH}"
            logger.error("URL ML model unavailable — %s", _model_error)
            raise ModelUnavailableError(_model_error)

        try:
            import joblib
            bundle = joblib.load(_MODEL_PATH)
        except Exception as exc:
            _model_error = f"Failed to deserialise URL ML model: {exc}"
            logger.error("URL ML model load error — %s", _model_error)
            raise ModelUnavailableError(_model_error) from exc

        if not isinstance(bundle, dict):
            _model_error = "URL ML model bundle is not a dict"
            logger.error("URL ML model structure error — %s", _model_error)
            raise ModelUnavailableError(_model_error)

        required_keys = {"model", "feature_names"}
        missing = required_keys - bundle.keys()
        if missing:
            _model_error = f"URL ML model bundle missing keys: {missing}"
            logger.error("URL ML model structure error — %s", _model_error)
            raise ModelUnavailableError(_model_error)

        feature_names = bundle.get("feature_names", [])
        if len(feature_names) != _EXPECTED_FEATURE_COUNT:
            _model_error = (
                f"Expected {_EXPECTED_FEATURE_COUNT} features, "
                f"got {len(feature_names)}"
            )
            logger.error("URL ML model feature mismatch — %s", _model_error)
            raise ModelUnavailableError(_model_error)

        _model_bundle = bundle
        logger.info(
            "URL ML model loaded | features=%d | model_type=%s",
            len(feature_names),
            type(bundle["model"]).__name__,
        )
        return bundle


def warmup() -> None:
    """Pre-load model at startup (called from lifespan). Best-effort."""
    try:
        _load_bundle()
    except ModelUnavailableError as e:
        logger.warning("URL ML warmup deferred: %s", e)


def is_available() -> bool:
    """Check if model is loadable without raising."""
    try:
        _load_bundle()
        return True
    except ModelUnavailableError:
        return False


# ---------------------------------------------------------------------------
# Feature extraction (identical to NEXUSSCAN ml_detector.py)
# ---------------------------------------------------------------------------

def _extract_features(url: str, feature_names: list[str]) -> pd.DataFrame:
    """
    Extract the 48 features expected by the model and return a single-row
    DataFrame. Features requiring live page content are set to NaN; the
    imputer fills them with training-set medians at prediction time.
    """
    # Normalize www. URLs without scheme for correct parsing
    normalized = url if "://" in url else "http://" + url
    parsed = urlparse(normalized)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    url_lc = normalized.lower()

    parts = hostname.split(".")
    if parts and parts[0] == "www":
        parts = parts[1:]
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    domain_sld = domain.split(".")[0]
    subdomains = parts[:-2]

    subdomain_level = len(subdomains)
    path_level = len([p for p in parsed.path.split("/") if p])
    query_len = len(parsed.query)
    query_comps = len(parse_qs(parsed.query)) if parsed.query else 0
    num_numeric = sum(c.isdigit() for c in url)

    random_str = 1 if re.search(r"[a-z0-9]{15,}", re.sub(r"[.\-]", "", hostname)) else 0
    domain_in_sub = 1 if subdomains and domain_sld in ".".join(subdomains) else 0
    domain_in_path = 1 if domain_sld in path else 0
    https_in_host = 1 if "https" in hostname else 0
    double_slash = 1 if "//" in parsed.path else 0
    num_sensitive = sum(1 for w in _SENSITIVE_WORDS if w in url_lc)
    embedded_brand = (
        1
        if any(b in ".".join(subdomains) + path for b in _BRAND_NAMES)
        and domain_sld not in _BRAND_NAMES
        else 0
    )

    NaN = np.nan

    values = [
        url.count("."),            # NumDots
        subdomain_level,            # SubdomainLevel
        path_level,                 # PathLevel
        len(url),                   # UrlLength
        url.count("-"),             # NumDash
        hostname.count("-"),        # NumDashInHostname
        url.count("@"),             # AtSymbol
        url.count("~"),             # TildeSymbol
        url.count("_"),             # NumUnderscore
        url.count("%"),             # NumPercent
        query_comps,                # NumQueryComponents
        url.count("&"),             # NumAmpersand
        url.count("#"),             # NumHash
        num_numeric,                # NumNumericChars
        0 if parsed.scheme == "https" else 1,  # NoHttps
        random_str,                 # RandomString
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,  # IpAddress
        domain_in_sub,              # DomainInSubdomains
        domain_in_path,             # DomainInPaths
        https_in_host,              # HttpsInHostname
        len(hostname),              # HostnameLength
        len(parsed.path),           # PathLength
        query_len,                  # QueryLength
        double_slash,               # DoubleSlashInPath
        num_sensitive,              # NumSensitiveWords
        embedded_brand,             # EmbeddedBrandName
        NaN,  # PctExtHyperlinks
        NaN,  # PctExtResourceUrls
        NaN,  # ExtFavicon
        NaN,  # InsecureForms
        NaN,  # RelativeFormAction
        NaN,  # ExtFormAction
        NaN,  # AbnormalFormAction
        NaN,  # PctNullSelfRedirectHyperlinks
        NaN,  # FrequentDomainNameMismatch
        NaN,  # FakeLinkInStatusBar
        NaN,  # RightClickDisabled
        NaN,  # PopUpWindow
        NaN,  # SubmitInfoToEmail
        NaN,  # IframeOrFrame
        NaN,  # MissingTitle
        NaN,  # ImagesOnlyInForm
        subdomain_level,  # SubdomainLevelRT
        len(url),         # UrlLengthRT
        NaN,  # PctExtResourceUrlsRT
        NaN,  # AbnormalExtFormActionR
        NaN,  # ExtMetaScriptLinkRT
        NaN,  # PctExtNullSelfRedirectHyperlinksRT
    ]

    return pd.DataFrame([values], columns=feature_names)


# ---------------------------------------------------------------------------
# Public prediction API
# ---------------------------------------------------------------------------

def predict_url(url: str) -> dict:
    """
    Run the ML phishing classifier on a URL.

    Returns:
        {
            'is_phishing': bool,
            'confidence': float  # 0–100 probability of predicted class
            'risk_score': float  # 0–1 phishing probability
        }

    Raises:
        ModelUnavailableError – if the model cannot be loaded.
    """
    bundle = _load_bundle()

    model = bundle["model"]
    scaler = bundle.get("scaler")
    imputer = bundle.get("imputer")
    feature_names = bundle["feature_names"]

    X = _extract_features(url, feature_names)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        if imputer is not None:
            X = imputer.transform(X)
        if scaler is not None:
            X = scaler.transform(X)

    prediction = model.predict(X)[0]
    is_phishing = bool(prediction)

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        # Find index of phishing class (1)
        classes = list(model.classes_)
        try:
            phish_idx = classes.index(1)
        except ValueError:
            phish_idx = 1 if len(proba) > 1 else 0
        risk_score = float(proba[phish_idx])
        confidence = float(proba[1] if is_phishing else proba[0]) * 100 if len(proba) > 1 else (risk_score * 100 if is_phishing else (1 - risk_score) * 100)
    else:
        risk_score = 0.90 if is_phishing else 0.10
        confidence = 90.0

    logger.debug(
        "URL ML prediction | url=%s | is_phishing=%s | risk=%.3f | confidence=%.1f",
        url[:80], is_phishing, risk_score, confidence,
    )

    return {
        "is_phishing": is_phishing,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 4),
    }


def score_url(url: str) -> float:
    """
    Convenience: return phishing risk_score 0–1 for a single URL.
    Returns 0.0 if model unavailable (graceful fallback).
    """
    try:
        return predict_url(url)["risk_score"]
    except ModelUnavailableError:
        return 0.0
    except Exception as e:
        logger.warning("URL ML scoring failed for %s: %s", url[:80], e)
        return 0.0


def score_urls_batch(urls: list[str]) -> list[dict]:
    """
    Score a batch of URLs. Each entry: {"url": str, "is_phishing": bool, "confidence": float, "risk_score": float}
    Unavailable model → empty scores with is_phishing=False.
    """
    results = []
    for u in urls:
        try:
            r = predict_url(u)
            results.append({"url": u, **r})
        except ModelUnavailableError:
            results.append({"url": u, "is_phishing": False, "confidence": 0.0, "risk_score": 0.0, "error": "model_unavailable"})
        except Exception as e:
            results.append({"url": u, "is_phishing": False, "confidence": 0.0, "risk_score": 0.0, "error": str(e)[:100]})
    return results


# Backwards-compat helper for url_analyzer integration
def get_risk_label(risk_score: float) -> str:
    """Map 0-1 risk_score to human label."""
    if risk_score >= 0.85:
        return "critical"
    if risk_score >= 0.70:
        return "high"
    if risk_score >= 0.50:
        return "medium"
    if risk_score >= 0.30:
        return "low"
    return "clean"
