"""SPF / DKIM / DMARC validation. Real checks via pyspf/dkimpy/dnspython, graceful fallback."""
from typing import Any
import dns.resolver


def validate_spf(sender_ip: str, envelope_from: str, helo: str = "") -> dict[str, Any]:
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
        return {"status": "none", "detail": f"dkim-unavailable: {e}"}


def _txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [b"".join(r.strings).decode(errors="ignore") for r in answers]
    except Exception:
        return []


def validate_dmarc(from_domain: str) -> dict[str, Any]:
    from_domain = from_domain.strip().lower().lstrip("<>").split("@")[-1]
    if not from_domain:
        return {"status": "none", "detail": "no-from-domain"}
    recs = _txt_records(f"_dmarc.{from_domain}")
    dmarc = [r for r in recs if "v=DMARC1" in r]
    if dmarc:
        return {"status": "found", "detail": dmarc[0][:500], "policy": dmarc[0]}
    return {"status": "none", "detail": "no-dmarc-record"}


def validate_all(raw_bytes: bytes, raw_headers: dict, sender_ip: str, envelope_from: str = "") -> dict[str, Any]:
    from_domain = str(raw_headers.get("From", ""))
    spf_r = validate_spf(sender_ip or "127.0.0.1", envelope_from or from_domain)
    dkim_r = validate_dkim(raw_bytes)
    dmarc_r = validate_dmarc(from_domain)
    aligned = spf_r.get("status") == "pass" or dkim_r.get("status") == "pass"
    return {"spf": spf_r, "dkim": dkim_r, "dmarc": dmarc_r, "aligned": aligned}
