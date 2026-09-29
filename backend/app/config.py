
import os
from functools import lru_cache
from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict



















_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_env_files(backend_dir: str) -> list[str]:

    repo_root = os.path.dirname(backend_dir)
    candidates = [
        os.path.join(backend_dir, ".env"),
        os.path.join(repo_root, ".env"),
    ]
    return [p for p in candidates if os.path.isfile(p)]


_env_files = resolve_env_files(_backend_dir)




_env_path = _env_files[0] if _env_files else os.path.join(_backend_dir, ".env")
for _path in _env_files:
    load_dotenv(_path, override=False)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_env_path, extra="ignore")

    app_name: str = "Email Threat & Forensics Platform"
    api_prefix: str = "/api/v1"


    secret_key: str = ""
    access_token_expire_minutes: int = 20


    supabase_jwt_secret: str = ""


    supabase_url: str = ""


    token_encryption_key: str = ""



    cors_origins: str = "https://email-scanner-chi.vercel.app"






    cors_origin_regex: str = ""

    @property
    def cors_origin_list(self) -> list[str]:



        seen: set[str] = set()
        out: list[str] = []
        for raw in str(self.cors_origins).split(","):
            cand = raw.strip().rstrip("/")
            if not cand:
                continue
            low = cand.lower()
            if "://" in low:
                scheme, _, host = low.partition("://")
                cand = f"{scheme}://{host}"
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
        return out

    @property
    def cors_origin_regex_list(self) -> list[str]:
        out: list[str] = []
        for raw in str(self.cors_origin_regex or "").split(","):
            cand = raw.strip()
            if cand and cand not in out:
                out.append(cand)
        return out

    @property
    def cors_regex_pattern(self) -> str | None:

        patterns = self.cors_origin_regex_list
        if not patterns:
            return None
        if len(patterns) == 1:
            return patterns[0]
        return "|".join(f"(?:{p})" for p in patterns)

    def cors_allows_remote_origins(self) -> bool:

        entries = self.cors_origin_list + self.cors_origin_regex_list
        return any(not _is_loopback_origin(o) for o in entries)

    def cors_allows(self, origin: str | None) -> bool:

        import re as _re
        if not origin:
            return False
        cand = origin.rstrip("/")
        if cand.lower() in self.cors_origin_list:
            return True
        return any(_re.fullmatch(p, origin) or _re.fullmatch(p, cand)
                   for p in self.cors_origin_regex_list)

    database_url: str = ""

    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""


    expected_replicas: int = 1


    known_legit_domains: str = ""

    rate_limit_enabled: str = "1"
    elasticsearch_url: str = ""
    elasticsearch_user: str = ""
    elasticsearch_password: str = ""
    elastic_index: str = "emails"
    kafka_bootstrap: str = ""
    kafka_topic: str = "emails-ingest"

    redis_url: str = ""

    celery_broker_url: str = ""
    celery_result_backend: str = "cache+memory://"

    maxmind_db_path: str = "./GeoLite2-City.mmdb"
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""






    app_env: str = "production"
    custody_key: str = ""

    custody_key_previous: str = ""


    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "https://email-scanner-chi.vercel.app"



    ms_client_id: str = ""
    ms_client_secret: str = ""
    frontend_url: str = "https://email-scanner-chi.vercel.app"
    mail_poll_minutes: int = 0


    oauth_redirect_allowlist: str = ""

    def oauth_redirect_allowed(self, uri: str) -> bool:


        frontends = [u.strip().rstrip("/") for u in str(self.frontend_url or "").split(",") if u.strip()]
        allowed = {
            *(frontends),
            (self.google_redirect_uri or "").rstrip("/"),
            *((u.strip().rstrip("/") for u in str(self.oauth_redirect_allowlist).split(",") if u.strip())),
        }
        allowed.discard("")
        return (uri or "").rstrip("/") in allowed



    enable_live_lookups: str = "0"
    lookup_timeout_s: float = 2.0

    retention_clean_days: int = 7
    retention_malicious_days: int = 90
    retention_hour: int = 3


    smtp_enabled: str = "0"
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 1025


    smtp_require_auth: str = "1"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_data_limit_bytes: int = 10 * 1024 * 1024
    smtp_tls_cert: str = ""
    smtp_tls_key: str = ""



    smtp_queue_max: int = 1000
    smtp_queue_max_bytes: int = 100 * 1024 * 1024




    trusted_relay_hosts: str = ""
    trusted_relay_ips: str = ""

    @property
    def smtp_on(self) -> bool:
        return str(self.smtp_enabled).lower() not in ("", "0", "false", "no")

    def resolved_db_url(self) -> str:


        test_url = os.environ.get("TEST_DATABASE_URL", "").strip()
        url = test_url or self.database_url
        if not url:
            raise RuntimeError("DATABASE_URL is not set. Provide a Supabase/Postgres connection string.")
        

        if "pgbouncer=" in url:
            import re
            url = re.sub(r'([?&])pgbouncer=[^&]+&?', r'\1', url).rstrip('?&')



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

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def _is_loopback_origin(origin: str) -> bool:

    cand = (origin or "").strip().lower().rstrip("/")
    if not cand:
        return False
    host = cand.partition("://")[2] or cand
    host = host.split("/")[0].split("@")[-1]
    if host.startswith("["):
        hostname = host.split("]", 1)[0] + "]"
    elif host.count(":") == 1:
        hostname = host.rsplit(":", 1)[0]
    else:
        hostname = host
    if not hostname:
        return False
    return hostname in LOOPBACK_HOSTS or hostname.endswith(".localhost")




_CORS_PROBE = "https://cors-probe.invalid"


def cors_regex_is_unbounded(settings: Settings) -> str | None:

    import re as _re
    for pattern in settings.cors_origin_regex_list:
        for probe in (_CORS_PROBE, "http://cors-probe.invalid", f"{_CORS_PROBE}:8443"):
            try:
                if _re.fullmatch(pattern, probe) or _re.fullmatch(pattern, probe.rstrip("/")):
                    return pattern
            except _re.error:


                continue
    return None


def require_secrets() -> None:

    import logging

    settings = get_settings()
    secret = (settings.secret_key or "")
    if settings.is_development():
        if not secret or secret.strip().lower() in FORGEABLE_SECRET_MARKERS or len(secret) < MIN_SECRET_BYTES:
            logging.getLogger("config").warning(
                "JWT secret_key is unset/default/short — development only. "
                "Set a 32+ char SECRET_KEY before any non-local deployment."
            )
        if (settings.elasticsearch_url or "").strip().lower().startswith("http://"):
            logging.getLogger("config").warning(
                "ELASTICSEARCH_URL uses plaintext http — development only. "
                "Use https:// before any non-local deployment."
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
    es_url = (settings.elasticsearch_url or "").strip()
    if es_url.lower().startswith("http://"):



        raise RuntimeError(
            "Refusing to boot: ELASTICSEARCH_URL uses plaintext http in "
            "production (basic_auth would leak). Use https://."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
