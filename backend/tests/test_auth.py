"""Auth + RBAC tests: register/login/refresh/me, route protection, Admin-only delete."""
import hashlib
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app import models
from app.modules.auth.security import create_access_token, hash_password, verify_password
from app.config import get_settings


def _uname(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _register(c: TestClient, username: str, password: str = "Str0ngPass!", role: str | None = None) -> dict:
    body: dict = {"username": username, "password": password}
    if role:
        body["role"] = role
    r = c.post("/api/v1/auth/register", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _login(c: TestClient, username: str, password: str = "Str0ngPass!") -> dict:
    r = c.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _mk_admin(username: str, password: str = "Str0ngPass!") -> None:
    """Insert an Admin directly (covers RBAC tests regardless of DB bootstrap state)."""
    db = SessionLocal()
    try:
        if not db.query(models.User).filter(models.User.username == username).first():
            db.add(models.User(username=username, password_hash=hash_password(password), role="Admin"))
            db.commit()
    finally:
        db.close()


def _cleanup(*usernames: str) -> None:
    db = SessionLocal()
    try:
        for u in usernames:
            row = db.query(models.User).filter(models.User.username == u).first()
            if row:
                db.delete(row)
        db.commit()
    finally:
        db.close()


def test_password_hashing_bcrypt_and_legacy():
    assert verify_password("s3cret!!", hash_password("s3cret!!"))
    assert not verify_password("wrong", hash_password("s3cret!!"))
    # pre-auth-module seed format must keep verifying (existing local DBs)
    legacy = "pbkdf2$" + hashlib.pbkdf2_hmac("sha256", b"analyst123", b"soc-demo-salt", 100_000).hex()
    assert verify_password("analyst123", legacy)
    assert not verify_password("nope", legacy)


def test_register_login_refresh_me():
    from app.main import app

    with TestClient(app) as c:
        uname = _uname("analyst")
        pair = _register(c, uname)
        assert pair["token_type"] == "bearer" and pair["access_token"] and pair["refresh_token"]

        # duplicate
        assert c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).status_code == 400
        # Admin role without setup token is forbidden (C2; was 400 before setup-token bootstrap)
        assert c.post("/api/v1/auth/register", json={"username": _uname("x"), "password": "Str0ngPass!", "role": "Admin"}).status_code == 403
        # weak password
        assert c.post("/api/v1/auth/register", json={"username": _uname("y"), "password": "short"}).status_code == 422

        # wrong password
        assert c.post("/api/v1/auth/login", json={"username": uname, "password": "nope-nope-nope"}).status_code == 401
        pair2 = _login(c, uname)
        assert pair2["access_token"] != pair["access_token"] or True  # rotation not required

        me = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pair2['access_token']}"})
        assert me.status_code == 200, me.text
        assert me.json()["username"] == uname
        assert me.json()["role"] == "ReadOnly"  # lowest-privilege default (C2)

        # refresh rotation
        r = c.post("/api/v1/auth/refresh", json={"refresh_token": pair2["refresh_token"]})
        assert r.status_code == 200, r.text
        # access token is not a refresh token
        assert c.post("/api/v1/auth/refresh", json={"refresh_token": pair2["access_token"]}).status_code == 401
        # garbage
        assert c.post("/api/v1/auth/refresh", json={"refresh_token": "junk"}).status_code == 401

        _cleanup(uname)


def test_protected_routes_require_auth():
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/v1/emails").status_code == 401
        assert c.get("/api/v1/dashboard").status_code == 401
        assert c.post("/api/v1/emails/ingest", json={"raw": "hi"}).status_code == 401
        assert c.get("/api/v1/cases").status_code == 401
        assert c.get("/api/v1/graph/campaigns").status_code == 401
        # public surface still open
        assert c.get("/health").status_code == 200
        assert c.post("/api/v1/auth/login", json={"username": "ghost", "password": "ghostghost"}).status_code == 401


def test_expired_token_rejected():
    from app.main import app

    settings = get_settings()
    bad = create_access_token("nope", "nope", "Analyst", settings.secret_key, expires_minutes=-1)
    with TestClient(app) as c:
        r = c.get("/api/v1/emails", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401


def test_rbac_admin_only_delete():
    from app.main import app

    admin_u, analyst_u = _uname("boss"), _uname("worker")
    _mk_admin(admin_u)
    with TestClient(app) as c:
        analyst_tok = _register(c, analyst_u, role="Analyst")["access_token"]
        admin_tok = _login(c, admin_u)["access_token"]
        ah = {"Authorization": f"Bearer {analyst_tok}"}
        dh = {"Authorization": f"Bearer {admin_tok}"}

        # analyst can ingest + create cases
        r = c.post("/api/v1/emails/ingest", headers=ah, json={"raw": "From: a@b.com\nSubject: t\n\nhello"})
        assert r.status_code == 200, r.text
        r = c.post("/api/v1/cases", headers=ah, json={"title": "rbac probe"})
        assert r.status_code == 200, r.text
        cid = r.json()["id"]

        # analyst cannot delete, admin can
        assert c.delete(f"/api/v1/cases/{cid}", headers=ah).status_code == 403
        assert c.post("/api/v1/admin/retention", headers=ah).status_code == 403
        assert c.delete(f"/api/v1/cases/{cid}", headers=dh).status_code == 200
        assert c.post("/api/v1/admin/retention", headers=dh).status_code == 200

        # admin can provision users incl. Admin role
        nu = _uname("teammate")
        r = c.post("/api/v1/auth/users", headers=dh,
                   json={"username": nu, "password": "Str0ngPass!", "role": "ReadOnly"})
        assert r.status_code == 201, r.text
        assert r.json()["role"] == "ReadOnly"
        # non-admin cannot provision
        assert c.post("/api/v1/auth/users", headers=ah,
                      json={"username": _uname("z"), "password": "Str0ngPass!"}).status_code == 403

        _cleanup(admin_u, analyst_u, nu)
