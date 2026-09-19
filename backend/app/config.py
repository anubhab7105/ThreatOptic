"""Central configuration. All secrets via env, sane local defaults."""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "Email Threat & Forensics Platform"
    api_prefix: str = "/api/v1"
    secret_key: str = "change-me-in-prod"
    access_token_expire_minutes: int = 480

    database_url: str = "sqlite:///./email_forensics.db"
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

    retention_clean_days: int = 7
    retention_malicious_days: int = 90

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
