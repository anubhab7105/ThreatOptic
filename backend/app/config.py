"""Central configuration. All secrets via env, sane local defaults."""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_db_url() -> str:
    # Anchor sqlite to backend/ dir so cwd doesn't create stray DB files.
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return f"sqlite:///{os.path.join(base, 'email_forensics.db')}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Email Threat & Forensics Platform"
    api_prefix: str = "/api/v1"
    secret_key: str = "change-me-in-prod"
    access_token_expire_minutes: int = 480

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
    elasticsearch_url: str = ""
    kafka_bootstrap: str = ""
    kafka_topic: str = "emails-ingest"

    maxmind_db_path: str = "./GeoLite2-City.mmdb"
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""

    # Chain-of-custody signing (F4). CUSTODY_KEY must come from a secrets
    # manager in any non-local deployment; the dev fallback only applies
    # when APP_ENV=development.
    app_env: str = "development"
    custody_key: str = ""

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

    @property
    def smtp_on(self) -> bool:
        return str(self.smtp_enabled).lower() not in ("", "0", "false", "no")

    def resolved_db_url(self) -> str:
        return self.database_url or _default_db_url()

    @property
    def live_lookups(self) -> bool:
        return str(self.enable_live_lookups).lower() not in ("", "0", "false", "no")


@lru_cache
def get_settings() -> Settings:
    return Settings()
