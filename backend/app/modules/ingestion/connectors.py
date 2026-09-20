"""API connectors: O365 (Microsoft Graph) + Google Workspace polling stubs with real HTTP logic."""
import httpx

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


def build_gmail_auth_url(client_id: str, redirect_uri: str) -> str:
    """OAuth2 consent URL (read-only Gmail). Returns the URL the user must open."""
    from urllib.parse import urlencode
    return GOOGLE_AUTH_URL + "?" + urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
    })


async def exchange_gmail_code(code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict:
    """Exchange an auth code for {access_token, refresh_token, expires_in}."""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(GOOGLE_TOKEN_URL, data={
            "code": code, "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        })
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


def build_microsoft_auth_url(client_id: str, redirect_uri: str) -> str:
    from urllib.parse import urlencode
    return MS_AUTH_URL + "?" + urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": MS_SCOPES,
        "response_mode": "query",
    })


async def exchange_microsoft_code(code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(MS_TOKEN_URL, data={
            "client_id": client_id, "client_secret": client_secret,
            "code": code, "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        })
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
    """Fetch messages via Microsoft Graph. Returns list of {id, raw_mime} dicts."""
    url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?$top={top}"
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        items = r.json().get("value", [])
    out = []
    async with httpx.AsyncClient(timeout=20) as client:
        for m in items:
            mid = m.get("id")
            mime_url = f"https://graph.microsoft.com/v1.0/me/messages/{mid}/$value"
            mr = await client.get(mime_url, headers=headers)
            if mr.status_code == 200:
                out.append({"id": mid, "raw": mr.content, "meta": m})
    return out


async def fetch_gmail_messages(access_token: str, query: str = "newer_than:1d", max_results: int = 25) -> list[dict]:
    """Fetch via Gmail API. Returns list of {id, raw} (base64 mime decoded)."""
    import base64
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers=headers, params={"q": query, "maxResults": max_results},
        )
        r.raise_for_status()
        ids = [m["id"] for m in r.json().get("messages", [])]
        out = []
        for mid in ids:
            mr = await client.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
                headers=headers, params={"format": "raw"},
            )
            if mr.status_code == 200:
                raw_b64 = mr.json().get("raw", "")
                raw = base64.urlsafe_b64decode(raw_b64) if raw_b64 else b""
                out.append({"id": mid, "raw": raw})
    return out
