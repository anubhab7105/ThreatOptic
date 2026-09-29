
import os
import re
from typing import Any

UNVERIFIABLE = "unverifiable"


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def _trusted_relay_hosts() -> set[str]:

    hosts = {h.strip().lower() for h in os.environ.get("TRUSTED_RELAY_HOSTS", "").split(",") if h.strip()}
    try:
        from ...config import get_settings
        s = get_settings()
        hosts |= {h.strip().lower() for h in str(getattr(s, "trusted_relay_hosts", "") or "").split(",") if h.strip()}
    except Exception:
        pass
    return hosts


def _authserv_id(raw_headers: dict) -> str:

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

    sid = _authserv_id(raw_headers)
    if not sid:


        return False, ""
    for suffix in _trusted_relay_hosts():
        from .psl import is_subdomain_of
        if is_subdomain_of(sid, suffix):
            return True, sid
    return False, sid


def _clean_domain(raw: str) -> str:

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

    results: dict[str, dict[str, str]] = {}
    if not isinstance(raw_headers, dict):
        return results


    recv_spf = _get_header(raw_headers, "Received-SPF")
    if recv_spf:
        m = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", recv_spf, re.IGNORECASE)
        if m:
            st = m.group(1).lower()
            results["spf"] = {"status": st, "detail": f"upstream-received-spf: {recv_spf[:120].strip()}"}


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


def _with_upstream(result: dict[str, Any], upstream_claim: dict[str, Any] | None) -> dict[str, Any]:

    if upstream_claim:
        result = dict(result)
        result["upstream"] = dict(upstream_claim)
    return result


def validate_spf(sender_ip: str, envelope_from: str, helo: str = "",
                 upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_spf = (upstream or {}).get("spf")

    if not (sender_ip or "").strip():
        if trust_upstream and upstream_spf:
            return {"status": upstream_spf.get("status", UNVERIFIABLE),
                    "detail": f"trusted-upstream: {upstream_spf.get('detail', '')}"[:300],
                    "upstream": dict(upstream_spf)}
        return _with_upstream({"status": UNVERIFIABLE, "detail": "no sender IP available; SPF not checked"}, upstream_spf)

    if not _live():
        if trust_upstream and upstream_spf:
            return {"status": upstream_spf.get("status", UNVERIFIABLE),
                    "detail": f"trusted-upstream: {upstream_spf.get('detail', '')}"[:300],
                    "upstream": dict(upstream_spf)}
        return _with_upstream({"status": UNVERIFIABLE, "detail": "live-lookups-disabled; SPF not checked"}, upstream_spf)

    if not envelope_from:


        return _with_upstream({"status": "none", "detail": "no envelope sender; SPF not checked"}, upstream_spf)

    try:
        import spf
        result, comment = spf.check2(i=sender_ip, s=envelope_from, h=helo or None)
        if result == "fail":

            return _with_upstream({"status": result, "detail": str(comment)}, upstream_spf)
        if result in ("none", "temperror") and trust_upstream and upstream_spf:
            return {"status": upstream_spf.get("status", result),
                    "detail": f"trusted-upstream: {upstream_spf.get('detail', '')}"[:300],
                    "upstream": dict(upstream_spf)}
        return _with_upstream({"status": result, "detail": str(comment)}, upstream_spf)
    except Exception as e:
        if trust_upstream and upstream_spf:
            return {"status": upstream_spf.get("status", "temperror"),
                    "detail": f"trusted-upstream: {upstream_spf.get('detail', '')}"[:300],
                    "upstream": dict(upstream_spf)}
        return _with_upstream({"status": "temperror", "detail": f"spf-unavailable: {e}"}, upstream_spf)


def validate_dkim(raw_bytes: bytes, raw_headers: dict | None = None,
                  upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_dkim = (upstream or {}).get("dkim")
    headers = raw_headers or {}
    dkim_sig = _get_header(headers, "DKIM-Signature")
    has_sig = bool(dkim_sig.strip())

    if not has_sig:
        if trust_upstream and upstream_dkim:
            return {"status": upstream_dkim.get("status", "none"),
                    "detail": f"trusted-upstream: {upstream_dkim.get('detail', '')}"[:300],
                    "upstream": dict(upstream_dkim)}
        return _with_upstream({"status": "none", "detail": "no-dkim-signature-header"}, upstream_dkim)

    try:
        import dkim
        res = dkim.verify(raw_bytes)
        if res:
            return _with_upstream({"status": "pass", "detail": "dkimpy-verify"}, upstream_dkim)


        return _with_upstream({"status": "fail", "detail": "dkimpy-verify-failed"}, upstream_dkim)
    except Exception as e:
        if trust_upstream and upstream_dkim:
            return {"status": upstream_dkim.get("status", UNVERIFIABLE),
                    "detail": f"trusted-upstream: {upstream_dkim.get('detail', '')}"[:300],
                    "upstream": dict(upstream_dkim)}
        return _with_upstream({"status": UNVERIFIABLE, "detail": f"dkim-unavailable: {e}"}, upstream_dkim)


def dkim_signing_domain(raw_headers: dict) -> str:

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
                   upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_dmarc = (upstream or {}).get("dmarc")
    from_domain = _clean_domain(from_domain)
    if not from_domain:
        return _with_upstream({"status": UNVERIFIABLE, "detail": "no-from-domain"}, upstream_dmarc)

    if not _live():
        if trust_upstream and upstream_dmarc:
            return {"status": upstream_dmarc.get("status", UNVERIFIABLE),
                    "detail": f"trusted-upstream: {upstream_dmarc.get('detail', '')}"[:300],
                    "upstream": dict(upstream_dmarc)}
        return _with_upstream({"status": UNVERIFIABLE, "detail": "live-lookups-disabled; DMARC not checked"}, upstream_dmarc)

    recs = _txt_records(f"_dmarc.{from_domain}")

    if not recs and "." in from_domain:
        parent_domain = from_domain.split(".", 1)[-1]
        if "." in parent_domain:
            recs = _txt_records(f"_dmarc.{parent_domain}")

    dmarc = [r for r in recs if "v=dmarc1" in r.lower()]
    if dmarc:
        pol_m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", dmarc[0], re.IGNORECASE)
        pol = pol_m.group(1).lower() if pol_m else "none"


        spf_status = (spf_res or {}).get("status", "").lower()
        dkim_status = (dkim_res or {}).get("status", "").lower()

        from .psl import same_organization



        spf_match = same_organization(spf_domain, from_domain)
        dkim_match = same_organization(dkim_domain, from_domain)

        spf_aligned = spf_status == "pass" and spf_match
        dkim_aligned = dkim_status == "pass" and dkim_match

        if spf_aligned or dkim_aligned:
            return _with_upstream({"status": "pass", "detail": f"dmarc-pass (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}, upstream_dmarc)
        else:
            return _with_upstream({"status": "fail", "detail": f"dmarc-alignment-failed (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}, upstream_dmarc)

    if trust_upstream and upstream_dmarc:
        return {"status": upstream_dmarc.get("status", "none"),
                "detail": f"trusted-upstream: {upstream_dmarc.get('detail', '')}"[:300],
                "upstream": dict(upstream_dmarc)}
    return _with_upstream({"status": "none", "detail": "no-dmarc-record"}, upstream_dmarc)


def validate_all(raw_bytes: bytes, raw_headers: dict, sender_ip: str, envelope_from: str = "") -> dict[str, Any]:
    from_domain = _clean_domain(_get_header(raw_headers, "From"))


    return_path = _get_header(raw_headers, "Return-Path")
    has_envelope = bool((envelope_from or "").strip() or return_path.strip())
    env_from = (envelope_from or "").strip() or return_path.strip()


    upstream_auth = parse_auth_headers(raw_headers)
    trust_upstream, authserv_id = _upstream_trusted(raw_headers)

    if has_envelope:
        spf_r = validate_spf((sender_ip or "").strip(), env_from, upstream=upstream_auth, trust_upstream=trust_upstream)
        spf_domain = _clean_domain(env_from)
    else:
        spf_r = _with_upstream(
            {"status": "none", "detail": "no-return-path; SPF has no envelope identity to check"},
            upstream_auth.get("spf"))
        spf_domain = ""
    dkim_r = validate_dkim(raw_bytes, raw_headers=raw_headers, upstream=upstream_auth, trust_upstream=trust_upstream)

    dkim_domain = dkim_signing_domain(raw_headers)

    dmarc_r = validate_dmarc(
        from_domain,
        spf_res=spf_r,
        dkim_res=dkim_r,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        upstream=upstream_auth,
        trust_upstream=trust_upstream,
    )
    

    from .psl import same_organization


    spf_match = same_organization(spf_domain, from_domain)
    dkim_match = same_organization(dkim_domain, from_domain)

    spf_aligned = spf_r.get("status") == "pass" and spf_match
    dkim_aligned = dkim_r.get("status") == "pass" and dkim_match
    aligned = spf_aligned or dkim_aligned
    
    return {
        "spf": spf_r,
        "dkim": dkim_r,
        "dmarc": dmarc_r,
        "aligned": aligned,
        "upstream_trusted": trust_upstream,
        "upstream_authserv_id": authserv_id,
        "spf_domain": spf_domain,
        "dkim_domain": dkim_domain,
        "from_domain": from_domain,
    }
