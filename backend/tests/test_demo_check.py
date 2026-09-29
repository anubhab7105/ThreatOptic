
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import live_demo_check as ldc


def test_check_env_flags():
    env = {"APP_ENV": "production", "SECRET_KEY": "change-me-in-prod"}
    out = ldc.check_env(env)
    assert out["app_env"] == "production"
    assert out["secret_changed"] is False
    assert out["custody_key_set"] is False
    assert out["live_lookups"] is False

    env = {"SECRET_KEY": "x" * 40, "CUSTODY_KEY": "y", "ENABLE_LIVE_LOOKUPS": "1",
           "VIRUSTOTAL_API_KEY": "k", "GOOGLE_CLIENT_ID": "a", "GOOGLE_CLIENT_SECRET": "b",
           "MS_CLIENT_ID": "c", "MS_CLIENT_SECRET": "d", "NEO4J_URI": "bolt://x:7687"}
    out = ldc.check_env(env)
    assert out["secret_changed"] and out["custody_key_set"] and out["live_lookups"]
    assert out["virustotal_key"] and out["gmail_oauth"] and out["ms_oauth"] and out["neo4j"]


def test_sample_ingest_shape():
    assert "Received:" in ldc.SAMPLE and "wire" in ldc.SAMPLE
