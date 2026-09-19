"""API connectors: O365 (Microsoft Graph) + Google Workspace polling stubs with real HTTP logic."""
import httpx


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
