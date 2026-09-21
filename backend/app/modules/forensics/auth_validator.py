"""SPF / DKIM / DMARC validation. Real checks via pyspf/dkimpy/dnspython, graceful fallback.

Live DNS checks only run when ENABLE_LIVE_LOOKUPS=1; otherwise every check
reports an explicit "unverifiable" status that is DISTINGUISHABLE from a
real DNS failure (Step 4): "unverifiable" means "we did not check",
"fail"/"temperror" mean "we checked and something is wrong".

For live deployments, ENABLE_LIVE_LOOKUPS=1 is the documented default
recommendation — without it, SPF/DKIM/DMARC contribute no negative signal.
"""
import os
import re
from typing import Any

UNVERIFIABLE = "unverifiable"


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def _clean_domain(raw: str) -> str:
    """Extract a bare domain from an address/header without lstrip() bugs."""
    m = re.search(r"@([\w.\-]+)", (raw or "").strip().lower())
    if not m:
        return ""
    return m.group(1).strip("<> \t").rstrip(".")


def _return_path_domain(raw_headers: dict) -> str:
    return _clean_domain(str(raw_headers.get("Return-Path", "") or ""))


def validate_spf(sender_ip: str, envelope_from: str, helo: str = "") -> dict[str, Any]:
    if not _live():
        return {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; SPF not checked"}
    if not sender_ip:
        # Never substitute 127.0.0.1: validating loopback as the sender
        # would vouch for mail we know nothing about.
        return {"status": UNVERIFIABLE, "detail": "no sender IP available; SPF not checked"}
    if not envelope_from:
        return {"status": "none", "detail": "no envelope sender; SPF not checked"}
    try:
        import spf
        result, comment = spf.check2(i=sender_ip, s=envelope_from, h=helo or None)
        return {"status": result, "detail": str(comment)}
    except Exception as e:
        return {"status": "temperror", "detail": f"spf-unavailable: {e}"}


def validate_dkim(raw_bytes: bytes) -> dict[str, Any]:
    try:
        import dkim
        res = dkim.verify(raw_bytes)
        return {"status": "pass" if res else "fail", "detail": "dkimpy-verify"}
    except Exception as e:
        return {"status": UNVERIFIABLE, "detail": f"dkim-unavailable: {e}"}


def dkim_signing_domain(raw_headers: dict) -> str:
    """The d= domain from DKIM-Signature ("" when absent/unparseable)."""
    m = re.search(r"\bd\s*=\s*([\w.\-]+)", str(raw_headers.get("DKIM-Signature", "") or ""), re.IGNORECASE)
    return (m.group(1).lower().rstrip(".") if m else "")


def _txt_records(name: str) -> list[str]:
    if not _live():
        return []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=2)
        return [b"".join(r.strings).decode(errors="ignore") for r in answers]
    except Exception:
        return []


def validate_dmarc(from_domain: str) -> dict[str, Any]:
    from_domain = _clean_domain(from_domain)
    if not from_domain:
        return {"status": UNVERIFIABLE, "detail": "no-from-domain"}
    if not _live():
        return {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; DMARC not checked"}
    recs = _txt_records(f"_dmarc.{from_domain}")
    dmarc = [r for r in recs if "v=DMARC1" in r]
    if dmarc:
        return {"status": "found", "detail": dmarc[0][:500], "policy": dmarc[0]}
    return {"status": "none", "detail": "no-dmarc-record"}


def validate_all(raw_bytes: bytes, raw_headers: dict, sender_ip: str, envelope_from: str = "") -> dict[str, Any]:
    from_domain = _clean_domain(str(raw_headers.get("From", "") or ""))
    # SPF authenticates the ENVELOPE sender (Return-Path), never display From.
    env_from = (envelope_from or "").strip() or str(raw_headers.get("Return-Path", "") or "") or from_domain
    spf_r = validate_spf((sender_ip or "").strip(), env_from)
    dkim_r = validate_dkim(raw_bytes)
    dmarc_r = validate_dmarc(from_domain)
    # DMARC-style alignment requires an actual domain match, not just a pass.
    spf_domain = _clean_domain(env_from)
    dkim_domain = dkim_signing_domain(raw_headers)
    spf_aligned = spf_r.get("status") == "pass" and bool(spf_domain) and spf_domain == from_domain
    dkim_aligned = dkim_r.get("status") == "pass" and bool(dkim_domain) and dkim_domain == from_domain
    aligned = spf_aligned or dkim_aligned
    return {"spf": spf_r, "dkim": dkim_r, "dmarc": dmarc_r, "aligned": aligned,
            "spf_domain": spf_domain, "dkim_domain": dkim_domain, "from_domain": from_domain}
