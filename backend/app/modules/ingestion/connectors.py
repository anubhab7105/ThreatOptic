import asyncio
import httpx

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


def _pkce_challenge(verifier: str) -> str:
    import base64
    import hashlib
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def _new_verifier() -> str:
    import secrets
    return secrets.token_urlsafe(64)


def build_gmail_auth_url(client_id: str, redirect_uri: str, state: str = "", code_challenge: str = "") -> str:
    """OAuth2 consent URL (read-only Gmail). Returns the URL the user must open."""
    from urllib.parse import urlencode
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return GOOGLE_AUTH_URL + "?" + urlencode(params)


async def exchange_gmail_code(code: str, client_id: str, client_secret: str, redirect_uri: str,
                              code_verifier: str = "") -> dict:
    """Exchange an auth code for {access_token, refresh_token, expires_in}."""
    async with httpx.AsyncClient(timeout=20) as client:
        data = {
            "code": code, "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        r = await client.post(GOOGLE_TOKEN_URL, data=data)
        r.raise_for_status()
        return r.json()


async def refresh_gmail_token(refresh_token: str, client_id: str, client_secret: str) -> dict:
    """Mint a fresh access token from a stored refresh token."""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(GOOGLE_TOKEN_URL, data={
            "refresh_token": refresh_token, "client_id": client_id,
            "client_secret": client_secret, "grant_type": "refresh_token",
        })
        r.raise_for_status()
        return r.json()


async def get_gmail_profile_email(access_token: str) -> str:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        return r.json().get("emailAddress", "")


MS_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MS_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_SCOPES = "Mail.Read User.Read offline_access"


def build_microsoft_auth_url(client_id: str, redirect_uri: str, state: str = "", code_challenge: str = "") -> str:
    from urllib.parse import urlencode
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": MS_SCOPES,
        "response_mode": "query",
    }
    if state:
        params["state"] = state
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return MS_AUTH_URL + "?" + urlencode(params)


async def exchange_microsoft_code(code: str, client_id: str, client_secret: str, redirect_uri: str,
                                  code_verifier: str = "") -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        data = {
            "client_id": client_id, "client_secret": client_secret,
            "code": code, "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        r = await client.post(MS_TOKEN_URL, data=data)
        r.raise_for_status()
        return r.json()


async def refresh_microsoft_token(refresh_token: str, client_id: str, client_secret: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(MS_TOKEN_URL, data={
            "client_id": client_id, "client_secret": client_secret,
            "refresh_token": refresh_token, "grant_type": "refresh_token",
            "scope": MS_SCOPES,
        })
        r.raise_for_status()
        return r.json()


async def get_microsoft_profile_email(access_token: str) -> str:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        j = r.json()
        return j.get("mail") or j.get("userPrincipalName") or ""


async def fetch_o365_messages(access_token: str, folder: str = "inbox", top: int = 25) -> list[dict]:
    """Fetch messages via Microsoft Graph. Returns list of {id, raw_mime} dicts. Supports any requested count."""
    target_count = max(1, int(top))
    url: str | None = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?$top={min(1000, target_count)}"
    headers = {"Authorization": f"Bearer {access_token}"}
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=30) as client:
        while url and len(items) < target_count:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink") if len(items) < target_count else None

        items = items[:target_count]
        sem = asyncio.Semaphore(10)

        async def fetch_one_o365(m: dict):
            mid = m.get("id")
            async with sem:
                try:
                    mime_url = f"https://graph.microsoft.com/v1.0/me/messages/{mid}/$value"
                    mr = await client.get(mime_url, headers=headers)
                    if mr.status_code == 200:
                        return {"id": mid, "raw": mr.content, "meta": m}
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*(fetch_one_o365(m) for m in items))
        out = [r for r in results if r is not None]
    return out


async def fetch_gmail_messages(access_token: str, query: str = "newer_than:1d", max_results: int = 25) -> list[dict]:
    """Fetch via Gmail API. Returns list of {id, raw} (base64 mime decoded). Supports any requested count."""
    import base64
    headers = {"Authorization": f"Bearer {access_token}"}
    target_count = max(1, int(max_results))
    ids: list[str] = []
    page_token = None

    async with httpx.AsyncClient(timeout=30) as client:
        while len(ids) < target_count:
            # Gmail API allows up to 500 per single list call
            batch_size = min(500, target_count - len(ids))
            params = {"q": query, "maxResults": batch_size}
            if page_token:
                params["pageToken"] = page_token
            r = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                headers=headers, params=params,
            )
            r.raise_for_status()
            data = r.json()
            msgs = data.get("messages", [])
            if not msgs:
                break
            ids.extend([m["id"] for m in msgs])
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        ids = ids[:target_count]
        sem = asyncio.Semaphore(10)

        async def fetch_one(mid: str):
            async with sem:
                try:
                    mr = await client.get(
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
                        headers=headers, params={"format": "raw"},
                    )
                    if mr.status_code == 200:
                        raw_b64 = mr.json().get("raw", "")
                        raw = base64.urlsafe_b64decode(raw_b64) if raw_b64 else b""
                        return {"id": mid, "raw": raw}
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*(fetch_one(mid) for mid in ids))
        out = [r for r in results if r is not None]
    return out
