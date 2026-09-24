"""SPF / DKIM / DMARC validation. Real checks via pyspf/dkimpy/dnspython, graceful fallback.

Trust model (P0, fail closed):
- Upstream Authentication-Results / Received-SPF headers are UNTRUSTED by
  default — anyone's MTA (including the attacker's) can stamp them.
- They are honored ONLY when attributable to a configured trusted relay
  boundary: the header's authserv-id must suffix-match TRUSTED_RELAY_HOSTS
  (env or settings, same source as origin-IP extraction).
- Even then, a trusted upstream "pass" NEVER overrides a locally computed
  hard failure. Local and upstream verdicts are reported separately
  (result["upstream"]) with provenance, so analysts see both.
- No envelope sender (Return-Path) means SPF has no identity to check:
  status "none" — never silently checked against the display From domain.
- No global DNS resolver mutation: per-lookup isolated resolvers only.

Live DNS checks only run when ENABLE_LIVE_LOOKUPS=1; otherwise every check
reports an explicit "unverifiable" status unless trusted upstream headers
exist (reported with "trusted-upstream:" provenance).
"""
import os
import re
from typing import Any

UNVERIFIABLE = "unverifiable"


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def _trusted_relay_hosts() -> set[str]:
    """Host suffixes identifying our own stamping infrastructure."""
    hosts = {h.strip().lower() for h in os.environ.get("TRUSTED_RELAY_HOSTS", "").split(",") if h.strip()}
    try:
        from ...config import get_settings
        s = get_settings()
        hosts |= {h.strip().lower() for h in str(getattr(s, "trusted_relay_hosts", "") or "").split(",") if h.strip()}
    except Exception:
        pass
    return hosts


def _authserv_id(raw_headers: dict) -> str:
    """Hostname of the MTA that stamped Authentication-Results ("" if none)."""
    if not isinstance(raw_headers, dict):
        return ""
    for k, v in raw_headers.items():
        if str(k).lower() in ("authentication-results", "arc-authentication-results", "x-authentication-results"):
            text = " ".join(v) if isinstance(v, list) else str(v or "")
            first = text.strip().split(";")[0].strip().split()
            if first:
                return first[0].lower().rstrip(".")
    return ""


def _upstream_trusted(raw_headers: dict) -> tuple[bool, str]:
    """(trusted, authserv_id): upstream headers count ONLY when the stamping
    host belongs to the configured trusted relay boundary. Fail closed:
    unconfigured boundary or unknown stamper => untrusted."""
    sid = _authserv_id(raw_headers)
    if not sid:
        # Received-SPF alone carries no authserv-id; without attribution it
        # cannot be tied to our boundary either.
        return False, ""
    for suffix in _trusted_relay_hosts():
        if sid == suffix or sid.endswith("." + suffix):
            return True, sid
    return False, sid


def _clean_domain(raw: str) -> str:
    """Extract a bare domain from an address/header without lstrip() bugs."""
    s = (raw or "").strip().lower()
    if not s:
        return ""
    if "@" in s:
        m = re.search(r"@([\w.\-]+)", s)
        if m:
            return m.group(1).strip("<> \t").rstrip(".")
        return ""
    m = re.search(r"([a-z0-9.\-]+)", s)
    return m.group(1).strip("<> \t").rstrip(".") if m else ""


def _get_header(raw_headers: dict, name: str) -> str:
    """Case-insensitive header retrieval from raw headers dictionary."""
    if not isinstance(raw_headers, dict):
        return ""
    if name in raw_headers:
        return str(raw_headers[name] or "")
    target = name.lower()
    for k, v in raw_headers.items():
        if str(k).lower() == target:
            return str(v or "")
    return ""


def _return_path_domain(raw_headers: dict) -> str:
    return _clean_domain(_get_header(raw_headers, "Return-Path"))


def parse_auth_headers(raw_headers: dict) -> dict[str, dict[str, str]]:
    """Extract SPF, DKIM, and DMARC claims from upstream Authentication-Results / Received-SPF headers.

    NOTE: the returned claims are UNTRUSTED until the caller checks them
    against _upstream_trusted(). Treat status values here as "some MTA
    claimed X", never as a verdict.
    """
    results: dict[str, dict[str, str]] = {}
    if not isinstance(raw_headers, dict):
        return results

    # 1. Received-SPF header
    recv_spf = _get_header(raw_headers, "Received-SPF")
    if recv_spf:
        m = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", recv_spf, re.IGNORECASE)
        if m:
            st = m.group(1).lower()
            results["spf"] = {"status": st, "detail": f"upstream-received-spf: {recv_spf[:120].strip()}"}

    # 2. Authentication-Results / ARC-Authentication-Results headers
    auth_lines: list[str] = []
    for k, v in raw_headers.items():
        k_lower = str(k).lower()
        if k_lower in ("authentication-results", "arc-authentication-results", "x-authentication-results"):
            auth_lines.append(str(v))

    combined = " ; ".join(auth_lines)
    if combined:
        if "spf" not in results:
            spf_m = re.search(r"\bspf\s*=\s*([a-zA-Z]+)", combined, re.IGNORECASE)
            if spf_m:
                st = spf_m.group(1).lower()
                if st in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                    results["spf"] = {"status": st, "detail": f"upstream-auth-results (spf={st})"}

        dkim_m = re.search(r"\bdkim\s*=\s*([a-zA-Z]+)", combined, re.IGNORECASE)
        if dkim_m:
            st = dkim_m.group(1).lower()
            if st in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                results["dkim"] = {"status": st, "detail": f"upstream-auth-results (dkim={st})"}

        dmarc_m = re.search(r"\bdmarc\s*=\s*([a-zA-Z]+)", combined, re.IGNORECASE)
        if dmarc_m:
            st = dmarc_m.group(1).lower()
            if st in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                results["dmarc"] = {"status": st, "detail": f"upstream-auth-results (dmarc={st})"}

    return results


def validate_spf(sender_ip: str, envelope_from: str, helo: str = "", upstream: dict[str, Any] | None = None) -> dict[str, Any]:
    upstream_spf = (upstream or {}).get("spf")
    
    if not (sender_ip or "").strip():
        if upstream_spf:
            return upstream_spf
        return {"status": UNVERIFIABLE, "detail": "no sender IP available; SPF not checked"}

    if not _live():
        if upstream_spf:
            return upstream_spf
        return {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; SPF not checked"}

    if not envelope_from:
        if upstream_spf:
            return upstream_spf
        return {"status": "none", "detail": "no envelope sender; SPF not checked"}

    try:
        _ensure_dns_resolver()
        import spf
        result, comment = spf.check2(i=sender_ip, s=envelope_from, h=helo or None)
        # If live check returned none or temperror, fallback to upstream if available
        if result in ("none", "temperror") and upstream_spf and upstream_spf.get("status") == "pass":
            return upstream_spf
        return {"status": result, "detail": str(comment)}
    except Exception as e:
        if upstream_spf:
            return upstream_spf
        return {"status": "temperror", "detail": f"spf-unavailable: {e}"}


def validate_dkim(raw_bytes: bytes, raw_headers: dict | None = None, upstream: dict[str, Any] | None = None) -> dict[str, Any]:
    upstream_dkim = (upstream or {}).get("dkim")
    headers = raw_headers or {}
    dkim_sig = _get_header(headers, "DKIM-Signature")
    has_sig = bool(dkim_sig.strip())

    if not has_sig and not upstream_dkim:
        return {"status": "none", "detail": "no-dkim-signature-header"}

    try:
        import dkim
        res = dkim.verify(raw_bytes)
        if res:
            return {"status": "pass", "detail": "dkimpy-verify"}
        # If local verification failed (e.g. mail forwarder altered line breaks) but upstream verified it:
        if upstream_dkim and upstream_dkim.get("status") == "pass":
            return upstream_dkim
        return {"status": "fail", "detail": "dkimpy-verify-failed"}
    except Exception as e:
        if upstream_dkim:
            return upstream_dkim
        return {"status": UNVERIFIABLE, "detail": f"dkim-unavailable: {e}"}


def dkim_signing_domain(raw_headers: dict) -> str:
    """The d= domain from DKIM-Signature ("" when absent/unparseable)."""
    m = re.search(r"\bd\s*=\s*([\w.\-]+)", _get_header(raw_headers, "DKIM-Signature"), re.IGNORECASE)
    return (m.group(1).lower().rstrip(".") if m else "")


def _get_resolver():
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        ns = list(res.nameservers)
        for fb in ("8.8.8.8", "1.1.1.1"):
            if fb not in ns:
                ns.append(fb)
        res.nameservers = ns
        res.timeout = 2.0
        res.lifetime = 3.5
        return res
    except Exception:
        return None


def _txt_records(name: str) -> list[str]:
    if not _live():
        return []
    res = _get_resolver()
    if not res:
        return []
    try:
        answers = res.resolve(name, "TXT")
        return [b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings") else str(r) for r in answers]
    except Exception:
        return []


def validate_dmarc(from_domain: str, spf_res: dict | None = None, dkim_res: dict | None = None,
                   spf_domain: str = "", dkim_domain: str = "",
                   upstream: dict[str, Any] | None = None) -> dict[str, Any]:
    upstream_dmarc = (upstream or {}).get("dmarc")
    from_domain = _clean_domain(from_domain)
    if not from_domain:
        return {"status": UNVERIFIABLE, "detail": "no-from-domain"}

    if not _live():
        if upstream_dmarc:
            return upstream_dmarc
        return {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; DMARC not checked"}

    recs = _txt_records(f"_dmarc.{from_domain}")
    # Also check parent domain if subdomain (e.g., mail.example.com -> example.com)
    if not recs and "." in from_domain:
        parent_domain = from_domain.split(".", 1)[-1]
        if "." in parent_domain:
            recs = _txt_records(f"_dmarc.{parent_domain}")

    dmarc = [r for r in recs if "v=dmarc1" in r.lower()]
    if dmarc:
        pol_m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", dmarc[0], re.IGNORECASE)
        pol = pol_m.group(1).lower() if pol_m else "none"

        # Check alignment
        spf_status = (spf_res or {}).get("status", "").lower()
        dkim_status = (dkim_res or {}).get("status", "").lower()
        
        spf_match = bool(spf_domain) and (spf_domain == from_domain or spf_domain.endswith("." + from_domain) or from_domain.endswith("." + spf_domain))
        dkim_match = bool(dkim_domain) and (dkim_domain == from_domain or dkim_domain.endswith("." + from_domain) or from_domain.endswith("." + dkim_domain))
        
        spf_aligned = spf_status == "pass" and spf_match
        dkim_aligned = dkim_status == "pass" and dkim_match

        if spf_aligned or dkim_aligned:
            return {"status": "pass", "detail": f"dmarc-pass (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}
        else:
            return {"status": "fail", "detail": f"dmarc-alignment-failed (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}

    if upstream_dmarc:
        return upstream_dmarc
    return {"status": "none", "detail": "no-dmarc-record"}


def validate_all(raw_bytes: bytes, raw_headers: dict, sender_ip: str, envelope_from: str = "") -> dict[str, Any]:
    from_domain = _clean_domain(_get_header(raw_headers, "From"))
    # SPF authenticates the ENVELOPE sender (Return-Path), never display From.
    env_from = (envelope_from or "").strip() or _get_header(raw_headers, "Return-Path") or from_domain
    
    # Extract upstream headers as authoritative context or graceful fallback
    upstream_auth = parse_auth_headers(raw_headers)

    spf_r = validate_spf((sender_ip or "").strip(), env_from, upstream=upstream_auth)
    dkim_r = validate_dkim(raw_bytes, raw_headers=raw_headers, upstream=upstream_auth)
    
    spf_domain = _clean_domain(env_from)
    dkim_domain = dkim_signing_domain(raw_headers)
    
    dmarc_r = validate_dmarc(
        from_domain,
        spf_res=spf_r,
        dkim_res=dkim_r,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        upstream=upstream_auth,
    )
    
    # DMARC-style alignment requires an actual domain match, not just a pass.
    spf_match = bool(spf_domain) and (spf_domain == from_domain or spf_domain.endswith("." + from_domain) or from_domain.endswith("." + spf_domain))
    dkim_match = bool(dkim_domain) and (dkim_domain == from_domain or dkim_domain.endswith("." + from_domain) or from_domain.endswith("." + dkim_domain))
    
    spf_aligned = spf_r.get("status") == "pass" and spf_match
    dkim_aligned = dkim_r.get("status") == "pass" and dkim_match
    aligned = spf_aligned or dkim_aligned
    
    return {
        "spf": spf_r,
        "dkim": dkim_r,
        "dmarc": dmarc_r,
        "aligned": aligned,
        "spf_domain": spf_domain,
        "dkim_domain": dkim_domain,
        "from_domain": from_domain,
    }
