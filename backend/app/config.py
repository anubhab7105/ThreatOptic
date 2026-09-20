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

    database_url: str = ""
    # Optional production backends (empty = local fallback)
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    elasticsearch_url: str = ""
    kafka_bootstrap: str = ""
    kafka_topic: str = "emails-ingest"

    maxmind_db_path: str = "./GeoLite2-City.mmdb"
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""

    # Gmail OAuth2 demo connector (optional; per-request overrides also accepted).
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # When "0" (default) all live network enrichment is skipped for speed/
    # offline reliability; set to "1" to enable ip-api/whois/dns/urlhaus/dnsbl.
    enable_live_lookups: str = "0"
    lookup_timeout_s: float = 2.0

    retention_clean_days: int = 7
    retention_malicious_days: int = 90

    def resolved_db_url(self) -> str:
        return self.database_url or _default_db_url()

    @property
    def live_lookups(self) -> bool:
        return str(self.enable_live_lookups).lower() not in ("", "0", "false", "no")


@lru_cache
def get_settings() -> Settings:
    return Settings()
