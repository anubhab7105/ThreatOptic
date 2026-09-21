"""Test-suite environment: explicit dev posture + test-only secrets.

Production defaults are fail-closed (Step 1/C1), so the suite pins a
development posture with synthetic secrets. Never point these at real
infrastructure.
"""
import os

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "pytest-only-secret-key-32-chars-minimum")
os.environ.setdefault("CUSTODY_KEY", "pytest-only-custody-key-32-chars-min")
os.environ.setdefault("TOKEN_ENCRYPTION_KEY", "pytest-only-vault-key-32-chars-min!")
os.environ.setdefault("SETUP_TOKEN", "pytest-setup-token")
