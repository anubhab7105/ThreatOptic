"""Central configuration. All secrets via env, sane local defaults."""
import os
from functools import lru_cache
from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anchor environment file to backend/.env so cwd doesn't matter
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_path = os.path.join(_backend_dir, ".env")
load_dotenv(_env_path, override=True)


def _default_db_url() -> str:
    # Anchor sqlite to backend/ dir so cwd doesn't create stray DB files.
    return f"sqlite:///{os.path.join(_backend_dir, 'email_forensics.db')}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_env_path, extra="ignore")

    app_name: str = "Email Threat & Forensics Platform"
    api_prefix: str = "/api/v1"
    # No default: must be provisioned via env/secrets manager. Startup
    # refuses to boot outside development when unset, default, or short.
    secret_key: str = ""
    access_token_expire_minutes: int = 20
    # Explicit setup token that authorizes creation of the first Admin
    # account via POST /auth/register (replaces first-registrant bootstrap).
    setup_token: str = ""
    # Separate key for the mailbox-token vault (never reuse secret_key).
    # Required (min 32 chars); fail closed when empty.
    token_encryption_key: str = ""

    # Comma-separated browser origins allowed to call the API. Credentials
    # are only safe with an explicit list — never "*".
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in str(self.cors_origins).split(",") if o.strip()]

    database_url: str = ""
    # Optional production backends (empty = local fallback)
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    # Expected backend replica count (F8). With >1 replicas the in-memory
    # graph diverges per pod, so NEO4J_URI must be set for consistency.
    expected_replicas: int = 1
    # Extra known-legitimate domains for lookalike detection
    # (comma-separated, appended to the built-in list).
    known_legit_domains: str = ""
    # Rate limiting kill-switch (tests default it off; prod keeps it on).
    rate_limit_enabled: str = "1"
    elasticsearch_url: str = ""
    elasticsearch_user: str = ""
    elasticsearch_password: str = ""
    elastic_index: str = "emails"
    kafka_bootstrap: str = ""
    kafka_topic: str = "emails-ingest"
    # Redis shared cache (Phase 3). Empty = in-process dict cache (same API).
    redis_url: str = ""
    # Celery async ingestion (Phase 3). Empty = synchronous pipeline (default).
    celery_broker_url: str = ""
    celery_result_backend: str = "cache+memory://"

    maxmind_db_path: str = "./GeoLite2-City.mmdb"
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""

    # Chain-of-custody signing (F4). CUSTODY_KEY must come from a secrets
    # manager in any non-local deployment; the dev fallback only applies
    # when APP_ENV=development.
    # Production-safe posture by default: anything but an explicit
    # APP_ENV=development is treated as a real deployment.
    app_env: str = "production"
    custody_key: str = ""
    # Previous custody key accepted during rotation windows only.
    custody_key_previous: str = ""

    # Gmail OAuth2 demo connector (optional; per-request overrides also accepted).
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # Organization mailbox polling (F7): Microsoft Graph credentials,
    # frontend base URL for OAuth callbacks, poll interval (0 = disabled).
    ms_client_id: str = ""
    ms_client_secret: str = ""
    frontend_url: str = "http://localhost:5173"
    mail_poll_minutes: int = 0
    # Extra allowed OAuth redirect_uris, comma-separated, beyond the
    # configured frontend_url / google_redirect_uri (C3 allowlist).
    oauth_redirect_allowlist: str = ""

    def oauth_redirect_allowed(self, uri: str) -> bool:
        allowed = {
            (self.frontend_url or "").rstrip("/"),
            (self.google_redirect_uri or "").rstrip("/"),
            *((u.strip().rstrip("/") for u in str(self.oauth_redirect_allowlist).split(",") if u.strip())),
        }
        allowed.discard("")
        return (uri or "").rstrip("/") in allowed

    # When "0" (default) all live network enrichment is skipped for speed/
    # offline reliability; set to "1" to enable ip-api/whois/dns/urlhaus/dnsbl.
    enable_live_lookups: str = "0"
    lookup_timeout_s: float = 2.0

    retention_clean_days: int = 7
    retention_malicious_days: int = 90
    retention_hour: int = 3  # local hour of the daily APScheduler retention run

    # Inline SMTP ingestion (F3). Off by default; enable with SMTP_ENABLED=1.
    smtp_enabled: str = "0"
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 1025
    # Step 5 (C8): AUTH required when SMTP_REQUIRE_AUTH=1 (needs USERNAME +
    # PASSWORD set); TLS enforced when cert+key are configured; DATA capped.
    smtp_require_auth: str = "0"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_data_limit_bytes: int = 10 * 1024 * 1024
    smtp_tls_cert: str = ""
    smtp_tls_key: str = ""
    # In-memory ingest queue bound (Step 5); overflow answers 452, never OOMs.
    smtp_queue_max: int = 1000

    # Trust boundary for origin-IP extraction (Step 4): host suffixes / IPs
    # of our own relays (comma-separated). The hop below the first match is
    # the last-external-hop origin.
    trusted_relay_hosts: str = ""
    trusted_relay_ips: str = ""

    @property
    def smtp_on(self) -> bool:
        return str(self.smtp_enabled).lower() not in ("", "0", "false", "no")

    def resolved_db_url(self) -> str:
        # TEST_DATABASE_URL wins when set (CI + pytest isolation); it is
        # never read from .env files, only the real environment.
        test_url = os.environ.get("TEST_DATABASE_URL", "").strip()
        url = test_url or self.database_url or _default_db_url()
        # Normalize Supabase / Railway postgres URLs: Heroku-style `postgres://` and
        # bare `postgresql://` need the psycopg2 driver for SQLAlchemy.
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+psycopg2://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    @property
    def live_lookups(self) -> bool:
        return str(self.enable_live_lookups).lower() not in ("", "0", "false", "no")

    def is_development(self) -> bool:
        return self.app_env.strip().lower() == "development"


FORGEABLE_SECRET_MARKERS = {"", "change-me-in-prod", "changeme", "secret", "test"}
MIN_SECRET_BYTES = 32


def require_secrets() -> None:
    """Fail fast at startup unless secrets are provisioned (C1).

    Outside APP_ENV=development the JWT secret must be set, must not be a
    well-known default, and must be at least 32 characters. Development
    keeps working out of the box but logs a loud warning.
    """
    import logging

    settings = get_settings()
    secret = (settings.secret_key or "")
    if settings.is_development():
        if not secret or secret.strip().lower() in FORGEABLE_SECRET_MARKERS or len(secret) < MIN_SECRET_BYTES:
            logging.getLogger("config").warning(
                "JWT secret_key is unset/default/short — development only. "
                "Set a 32+ char SECRET_KEY before any non-local deployment."
            )
        return
    if not secret or secret.strip().lower() in FORGEABLE_SECRET_MARKERS:
        raise RuntimeError(
            "Refusing to boot: SECRET_KEY is unset or a well-known default. "
            "Provision it from a secrets manager (see SECURITY.md)."
        )
    if len(secret) < MIN_SECRET_BYTES:
        raise RuntimeError(
            f"Refusing to boot: SECRET_KEY is only {len(secret)} chars; minimum is {MIN_SECRET_BYTES}."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
