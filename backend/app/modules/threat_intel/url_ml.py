
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





class ModelUnavailableError(RuntimeError):
    pass


_model_lock: Lock = Lock()
_model_bundle: dict | None = None
_model_error: str | None = None


def _load_bundle() -> dict:

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
            from ..model_trust import verify_model_artifact, ModelTrustError
            verify_model_artifact(_MODEL_PATH, purpose="url-ml")
        except ModelTrustError as exc:
            _model_error = f"URL ML model trust failed: {exc}"
            logger.error("URL ML model unavailable — %s", _model_error)
            raise ModelUnavailableError(_model_error) from exc

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

    try:
        _load_bundle()
    except ModelUnavailableError as e:
        logger.warning("URL ML warmup deferred: %s", e)


def is_available() -> bool:

    try:
        _load_bundle()
        return True
    except ModelUnavailableError:
        return False






def _extract_features(url: str, feature_names: list[str]) -> pd.DataFrame:


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
        url.count("."),
        subdomain_level,
        path_level,
        len(url),
        url.count("-"),
        hostname.count("-"),
        url.count("@"),
        url.count("~"),
        url.count("_"),
        url.count("%"),
        query_comps,
        url.count("&"),
        url.count("#"),
        num_numeric,
        0 if parsed.scheme == "https" else 1,
        random_str,
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        domain_in_sub,
        domain_in_path,
        https_in_host,
        len(hostname),
        len(parsed.path),
        query_len,
        double_slash,
        num_sensitive,
        embedded_brand,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        NaN,
        subdomain_level,
        len(url),
        NaN,
        NaN,
        NaN,
        NaN,
    ]

    return pd.DataFrame([values], columns=feature_names)






def predict_url(url: str) -> dict:

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

    try:
        return predict_url(url)["risk_score"]
    except ModelUnavailableError:
        return 0.0
    except Exception as e:
        logger.warning("URL ML scoring failed for %s: %s", url[:80], e)
        return 0.0


def score_urls_batch(urls: list[str]) -> list[dict]:

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



def get_risk_label(risk_score: float) -> str:

    if risk_score >= 0.85:
        return "critical"
    if risk_score >= 0.70:
        return "high"
    if risk_score >= 0.50:
        return "medium"
    if risk_score >= 0.30:
        return "low"
    return "clean"
