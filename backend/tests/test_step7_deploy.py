"""Step 7 deploy/infra tests: k8s hardening, compose secrets, nginx, vercel, Dockerfile."""
import json
import os
import subprocess

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load(p):
    with open(os.path.join(ROOT, p)) as f:
        return f.read()


def test_k8s_hardening():
    docs = list(yaml.safe_load_all(_load("k8s/backend.yaml")))
    dep = next(d for d in docs if d["kind"] == "Deployment")
    # F8: replicas > 1 share no in-memory state (graph, rate-limit counters,
    # app.cache, _MISP_CACHE). graph_consistency_note() only warns, so the
    # manifest must not ask for 2. Was `replicas: 2`.
    assert dep["spec"]["replicas"] == 1
    pod = dep["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    c = pod["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["allowPrivilegeEscalation"] is False
    assert c["livenessProbe"]["httpGet"]["path"] == "/health"
    # Was /health/detailed: a per-IP rate-limited diagnostic shared by every
    # kubelet probe, so operator traffic could evict the probe (429 ->
    # NotReady -> pod pulled from the Service).
    assert c["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert c["resources"]["requests"] and c["resources"]["limits"]
    env = {e["name"]: e for e in c["env"]}
    # secrets via secretKeyRef, never plaintext values
    for name in ("DATABASE_URL", "SECRET_KEY", "CUSTODY_KEY", "NEO4J_PASSWORD"):
        assert "secretKeyRef" in env[name].get("valueFrom", {}), name
    assert "value" not in env["SECRET_KEY"]
    # F8 constraint documented; EXPECTED_REPLICAS must track spec.replicas
    assert "NEO4J_URI" in env
    assert env["EXPECTED_REPLICAS"]["value"] == str(dep["spec"]["replicas"])
    assert "share NO in-memory state" in _load("k8s/backend.yaml")
    # no probe may target a rate-limited endpoint
    for probe in ("livenessProbe", "readinessProbe"):
        assert c[probe]["httpGet"]["path"] != "/health/detailed", probe
    # release pinning documented (digest substituted at release; see Tracker)
    assert "sha256" in _load("k8s/backend.yaml")
    ing = next(d for d in docs if d["kind"] == "Ingress")
    assert ing["spec"]["tls"] and ing["spec"]["rules"]


def test_readiness_endpoint_reports_db_and_is_never_rate_limited():
    """A probe polling a per-IP rate limit can lock itself out."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        # more than the old 5/minute limit, and well past a 15s probe period
        codes = [c.get("/health/ready").status_code for _ in range(30)]
        assert set(codes) == {200}, codes
        assert c.get("/health/ready").json() == {"status": "ready", "db": True}
        # the detailed diagnostic is still reachable and still reports models
        d = c.get("/health/detailed")
        assert d.status_code == 200 and "url_ml" in d.json()


def test_readiness_fails_closed_when_the_database_is_down(monkeypatch):
    """A non-2xx is the signal the kubelet acts on; a 200 'degraded' body is not."""
    from fastapi.testclient import TestClient

    import app.database as dbmod
    from app.main import app

    class _Dead:
        def connect(self):
            raise RuntimeError("connection refused")

        def dispose(self):
            pass

    monkeypatch.setattr(dbmod, "engine", _Dead())
    with TestClient(app) as c:
        # patch AFTER startup: the lifespan calls rebuild_engine(), which
        # reassigns dbmod.engine and would undo the patch.
        monkeypatch.setattr(dbmod, "engine", _Dead())
        r = c.get("/health/ready")
        assert r.status_code == 503, r.text
        assert r.json()["db"] is False


def test_secret_template_has_no_values():
    doc = yaml.safe_load(_load("k8s/secret.yaml.example"))
    assert doc["metadata"]["name"].startswith("soc-secrets-EXAMPLE")
    vals = set(doc["stringData"].values())
    assert vals <= {"CHANGEME", ""}, vals
    for key in ("secret-key", "custody-key", "token-encryption-key", "elastic-password"):
        assert key in doc["stringData"]


def test_compose_secrets_and_ports():
    doc = yaml.safe_load(_load("docker-compose.yml"))
    svcs = doc["services"]
    # env-name consistency: backend + ES agree on ELASTICSEARCH_PASSWORD
    backend_env = svcs["backend"]["environment"]
    assert "ELASTICSEARCH_PASSWORD" in backend_env
    assert "ELASTIC_PASSWORD" not in backend_env
    assert svcs["elasticsearch"]["environment"]["ELASTIC_PASSWORD"] == \
        "${ELASTICSEARCH_PASSWORD:-}"
    dumped = yaml.safe_dump(doc)
    assert "soc:soc@" not in dumped and "socsoc123" not in dumped  # no hardcoded creds
    # data services not publicly exposed
    for svc in ("neo4j", "elasticsearch", "kafka"):
        for port in svcs[svc].get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (svc, port)
    # ES memory limits + kafka persistence
    assert svcs["elasticsearch"]["environment"]["ES_JAVA_OPTS"] == "-Xms512m -Xmx512m"
    assert "kavolume" in doc["volumes"]


def test_nginx_syntax_and_headers():
    import shutil
    if shutil.which("nginx") is None:
        import pytest
        pytest.skip("nginx not installed on this platform (Windows)")
    conf = _load("frontend/nginx.conf")
    for needle in ("Content-Security-Policy", "Strict-Transport-Security",
                   "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        assert needle in conf, needle
    # soft-404 scoped to location / only (assets keep real 404s)
    assert conf.count("error_page 404 /index.html;") == 1
    assert "location / {\n        try_files $uri $uri/ /index.html;\n        error_page 404 /index.html;" in conf
    import tempfile
    # Syntax-check a copy with the compose-DNS upstream pointed at loopback
    # (proxy_pass targets can't resolve outside compose; semantics unchanged).
    conf_text = _load("frontend/nginx.conf").replace("http://backend:8000", "http://127.0.0.1:8000")
    wrapper = ("pid /tmp/nginx-pytest.pid;\nerror_log /tmp/nginx-pytest-error.log;\n"
               "events {}\nhttp {\n"
               "access_log off;\n"
               "client_body_temp_path /tmp;\nproxy_temp_path /tmp;\n"
               "fastcgi_temp_path /tmp;\nuwsgi_temp_path /tmp;\nscgi_temp_path /tmp;\n"
               + conf_text + "\n}\n")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(wrapper)
        path = f.name
    try:
        r = subprocess.run(["nginx", "-t", "-c", path], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
    finally:
        os.unlink(path)


def test_vercel_rewrites_exclude_assets():
    for p in ("vercel.json", "frontend/vercel.json"):
        doc = json.loads(_load(p))
        rewrites = doc["rewrites"]
        asset_rule = next((r for r in rewrites if r["source"].startswith("/assets/")), None)
        assert asset_rule is not None, p
        catchall = [r for r in rewrites if r["source"] == "/(.*)"]
        assert catchall and rewrites.index(asset_rule) < rewrites.index(catchall[0]), p


def test_gitignore_covers_secrets():
    text = _load(".gitignore")
    assert "k8s/secret.yaml" in text
    assert ".env.*" in text
    assert "*.log" in text
    # the example template itself must stay committable
    assert "!k8s/secret.yaml.example" in text


def test_backend_dockerfile_hardened():
    text = _load("backend/Dockerfile")
    assert text.count("FROM python:") >= 2  # multi-stage
    assert "\nUSER appuser" in text  # non-root
    assert "USER root" not in text
    assert "backend/alembic" in text  # migration files ship in the image
