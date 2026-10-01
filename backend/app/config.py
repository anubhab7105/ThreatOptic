"""Central configuration. All secrets via env, sane local defaults."""
import os
from functools import lru_cache
from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Locate the environment file(s) relative to this file, never to the process
# working directory, so `uvicorn` behaves the same whether it is launched from
# the repo root or from backend/.
#
# Search order (first hit wins, later files do not override earlier ones):
#
#   1. backend/.env  — a per-service override, for when the backend must diverge
#                      from the shared file (e.g. a local Postgres the rest of
#                      the stack does not use).
#   2. <repo>/.env   — the shared file. This is the one you normally edit; it
#                      is also what docker-compose.yml injects, so the container
#                      stack and a locally-run backend read the same values
#                      instead of two hand-synced copies.
#
# Both may be absent: production supplies variables from the platform's
# environment (Railway / Vercel), not from a file on disk, so requiring a file
# here would break a correct deployment. require_secrets() is what enforces
# that the resulting values are actually usable.
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_env_files(backend_dir: str) -> list[str]:
    """Environment files that apply, highest precedence first.

    Split out from the import-time wiring below so the search order is
    testable without reimporting this module.
    """
    repo_root = os.path.dirname(backend_dir)
    candidates = [
        os.path.join(backend_dir, ".env"),
        os.path.join(repo_root, ".env"),
    ]
    return [p for p in candidates if os.path.isfile(p)]


_env_files = resolve_env_files(_backend_dir)
# First existing file is the pydantic-settings source of record; the rest are
# still loaded into os.environ below, with the earlier ones taking precedence
# (load_dotenv's override=False, and os.environ outranks env_file in
# pydantic-settings' priority order).
_env_path = _env_files[0] if _env_files else os.path.join(_backend_dir, ".env")
for _path in _env_files:
    load_dotenv(_path, override=False)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_env_path, extra="ignore")

    app_name: str = "Email Threat & Forensics Platform"
    api_prefix: str = "/api/v1"
    # No default: must be provisioned via env/secrets manager. Startup
    # refuses to boot outside development when unset, default, or short.
    secret_key: str = ""
    access_token_expire_minutes: int = 20
    # Supabase Auth JWT secret (kept for HS256 fallback / local dev).
    # Required for verifying Supabase access tokens in deps.get_current_user.
    supabase_jwt_secret: str = ""
    # Supabase project URL (e.g. https://<ref>.supabase.co).
    # Used to fetch the JWKS public keys for ES256/HS256 token verification.
    supabase_url: str = ""
    # Separate key for the mailbox-token vault (never reuse secret_key).
    # Required (min 32 chars); fail closed when empty.
    token_encryption_key: str = ""

    # Comma-separated browser origins allowed to call the API. Credentials
    # are only safe with an explicit list — never "*".
    cors_origins: str = "https://email-scanner-chi.vercel.app"
    # Optional regex origins for hosts that cannot be enumerated, e.g.
    # `https://[a-z0-9-]+\.vercel\.app` for per-PR Vercel preview deploys.
    # Opt-in only, and still refused at boot if it would match *any* origin
    # (allow_credentials=True + a match-everything regex would send
    # credentials to every site). Never a substitute for listing the
    # production origins explicitly.
    cors_origin_regex: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        # Normalize: strip whitespace + trailing slash so browsers' Origin
        # (which never carries a trailing slash) matches the setting, and
        # fold scheme/host case the way the URL spec compares them.
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
        """Comma-separated patterns as one alternation for CORSMiddleware.

        Starlette takes a single pattern and applies `fullmatch`, so the
        list is joined with non-capturing groups. None when unset.
        """
        patterns = self.cors_origin_regex_list
        if not patterns:
            return None
        if len(patterns) == 1:
            return patterns[0]
        return "|".join(f"(?:{p})" for p in patterns)

    def cors_allows_remote_origins(self) -> bool:
        """True when some configured origin/regex can serve a non-loopback browser.

        A loopback-only allowlist is the most common split-deploy
        misconfiguration: the API boots, Railway's health check passes, and
        every real browser is blocked by CORS with nothing in the logs.
        Callers use this to say so out loud at startup.
        """
        entries = self.cors_origin_list + self.cors_origin_regex_list
        return any(not _is_loopback_origin(o) for o in entries)

    def cors_allows(self, origin: str | None) -> bool:
        """Mirror of what CORSMiddleware will decide — used for diagnostics."""
        import re as _re
        if not origin:
            return False
        cand = origin.rstrip("/")
        if cand.lower() in self.cors_origin_list:
            return True
        return any(_re.fullmatch(p, origin) or _re.fullmatch(p, cand)
                   for p in self.cors_origin_regex_list)

    database_url: str = ""  # Required — set via DATABASE_URL env var (no SQLite fallback)
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
    google_redirect_uri: str = "https://email-scanner-chi.vercel.app"

    # Organization mailbox polling (F7): Microsoft Graph credentials,
    # frontend base URL for OAuth callbacks, poll interval (0 = disabled).
    ms_client_id: str = ""
    ms_client_secret: str = ""
    frontend_url: str = "https://email-scanner-chi.vercel.app"
    mail_poll_minutes: int = 0
    # Extra allowed OAuth redirect_uris, comma-separated, beyond the
    # configured frontend_url / google_redirect_uri (C3 allowlist).
    oauth_redirect_allowlist: str = ""

    def oauth_redirect_allowed(self, uri: str) -> bool:
        # FRONTEND_URL may contain multiple origins (comma-separated during
        # migration); treat each as an allowed redirect base.
        frontends = [u.strip().rstrip("/") for u in str(self.frontend_url or "").split(",") if u.strip()]
        allowed = {
            *(frontends),
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
    # Step 5 (C8): AUTH required by default (set SMTP_REQUIRE_AUTH=0 to
    # allow anonymous localhost injection in dev). TLS enforced when cert+key are configured; DATA capped.
    smtp_require_auth: str = "1"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_data_limit_bytes: int = 10 * 1024 * 1024
    smtp_tls_cert: str = ""
    smtp_tls_key: str = ""
    # In-memory ingest queue bounds (P0): item count AND byte budget —
    # 1000 items of 10MB mail would otherwise OOM the worker (~10GB).
    # Overflow answers 452, never OOMs.
    smtp_queue_max: int = 1000
    smtp_queue_max_bytes: int = 100 * 1024 * 1024

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
        url = test_url or self.database_url  # No SQLite default — fail-closed
        if not url:
            raise RuntimeError("DATABASE_URL is not set. Provide a Supabase/Postgres connection string.")
        
        # Remove pgbouncer query param as it causes psycopg2 ProgrammingError (invalid dsn)
        if "pgbouncer=" in url:
            import re
            url = re.sub(r'([?&])pgbouncer=[^&]+&?', r'\1', url).rstrip('?&')

        # Normalize Supabase / Railway postgres URLs: Heroku-style `postgres://` and
        # bare `postgresql://` need the psycopg2 driver for SQLAlchemy.
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+psycopg2://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    def redacted_db_url(self) -> str:
        """Safe database URL with password stripped for logging."""
        try:
            from sqlalchemy.engine import make_url
            return make_url(self.resolved_db_url()).render_as_string(hide_password=True)
        except Exception:
            import re
            return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", self.resolved_db_url())

    @property
    def live_lookups(self) -> bool:
        return str(self.enable_live_lookups).lower() not in ("", "0", "false", "no")

    def is_development(self) -> bool:
        return self.app_env.strip().lower() == "development"


FORGEABLE_SECRET_MARKERS = {"", "change-me-in-prod", "changeme", "secret", "test"}
MIN_SECRET_BYTES = 32

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def _is_loopback_origin(origin: str) -> bool:
    """True for http://localhost:5173-style entries.

    Regex patterns are treated as remote-capable unless they are explicitly
    loopback-only: a pattern's host can't be read off reliably, and
    erring toward "remote" only means we skip a warning, never that we
    widen the allowlist.
    """
    cand = (origin or "").strip().lower().rstrip("/")
    if not cand:
        return False
    host = cand.partition("://")[2] or cand
    host = host.split("/")[0].split("@")[-1]
    if host.startswith("["):          # IPv6 literal, possibly with a port
        hostname = host.split("]", 1)[0] + "]"
    elif host.count(":") == 1:        # host:port
        hostname = host.rsplit(":", 1)[0]
    else:
        hostname = host
    if not hostname:                 # bare ":5173"-ish nonsense
        return False
    return hostname in LOOPBACK_HOSTS or hostname.endswith(".localhost")


# A probe origin nothing legitimate would serve, used to detect a
# match-everything CORS regex before credentials are attached to it.
_CORS_PROBE = "https://cors-probe.invalid"


def cors_regex_is_unbounded(settings: Settings) -> str | None:
    """Return the offending pattern if any regex would match any origin."""
    import re as _re
    for pattern in settings.cors_origin_regex_list:
        for probe in (_CORS_PROBE, "http://cors-probe.invalid", f"{_CORS_PROBE}:8443"):
            try:
                if _re.fullmatch(pattern, probe) or _re.fullmatch(pattern, probe.rstrip("/")):
                    return pattern
            except _re.error:
                # An uncompilable pattern matches nothing; CORSMiddleware
                # ignores it, so this is not a boot-blocking problem.
                continue
    return None


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
        # Basic-auth credentials cross this connection — plaintext in a real
        # deployment leaks them. (Development returned above with its own
        # warning posture; this gate is production-only by construction.)
        raise RuntimeError(
            "Refusing to boot: ELASTICSEARCH_URL uses plaintext http in "
            "production (basic_auth would leak). Use https://."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
