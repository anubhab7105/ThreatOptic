"""SPF / DKIM / DMARC validation. Real checks via pyspf/dkimpy/dnspython, graceful fallback.

Trust model (P0, fail closed):
- Upstream Authentication-Results / Received-SPF headers are UNTRUSTED by
  default — anyone's MTA (including the attacker's) can stamp them.
- They are honored ONLY when attributable to a configured trusted relay
  boundary: the header's authserv-id must suffix-match TRUSTED_RELAY_HOSTS
  (env or settings, same source as origin-IP extraction).
- Even then, a trusted upstream verdict NEVER overrides a locally-attempted
  result. It may only stand in for `unverifiable` — no sender IP, live
  lookups disabled, or the validator library missing. A local `temperror`,
  `permerror`, `none` or `fail` is authoritative and is never upgraded to
  `pass`. Local and upstream verdicts are reported separately
  (result["upstream"]) with provenance, so analysts see both.
- Claims and authserv-id are read from the SAME header: the bottom-most
  Authentication-Results, i.e. the one stamped by our own MTAs. Prepending
  an AR header cannot make an attacker the speaker for our boundary.
- No envelope sender (Return-Path) means SPF has no identity to check:
  status "none" — never silently checked against the display From domain.
- No global DNS resolver mutation: per-lookup isolated resolvers only.

Live DNS checks only run when ENABLE_LIVE_LOOKUPS=1; otherwise every check
reports an explicit "unverifiable" status unless trusted upstream headers
exist (reported with "trusted-upstream:" provenance).
"""
import os
import re
import time
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


_AR_HEADER_NAMES = frozenset({
    "authentication-results", "arc-authentication-results", "x-authentication-results",
})


def _ar_headers(raw_headers: dict) -> list[str]:
    """Every Authentication-Results-style header value, in header order."""
    out: list[str] = []
    if not isinstance(raw_headers, dict):
        return out
    for k, v in raw_headers.items():
        if str(k).lower() in _AR_HEADER_NAMES:
            out.append(" ".join(v) if isinstance(v, list) else str(v or ""))
    return out


def _boundary_ar_header(raw_headers: dict) -> tuple[str, str]:
    """(authserv_id, text) of the ONE Authentication-Results header that is
    eligible for trust, or ("", "") when there is none.

    P0 path binding: in a Received chain, a header stamped by our own MTAs
    is the one appended LAST (lowest in the header block, nearest the
    delivery we observed). Everything above it was added by hosts the sender
    controls, so an attacker who prepends
    `Authentication-Results: mx.our-relay.example; spf=pass ...` must not be
    able to speak for our boundary. We therefore read ONLY the bottom-most
    AR header; if that one is not attributable to the trusted boundary, we
    do not trust the message at all — no earlier header gets a vote.

    Returning a single header for BOTH attribution and claim extraction is
    deliberate: previously _authserv_id() and parse_auth_headers() walked the
    header dict independently, so a planted `x-authentication-results` could
    supply the trusted authserv-id while the status claims were read from an
    attacker-authored `authentication-results`.
    """
    for text in reversed(_ar_headers(raw_headers)):
        first = text.strip().split(";")[0].strip().split()
        if first:
            return first[0].lower().rstrip("."), text
    return "", ""


def _authserv_id(raw_headers: dict) -> str:
    """Hostname of the MTA that stamped the trusted Authentication-Results."""
    return _boundary_ar_header(raw_headers)[0]


def _upstream_trusted(raw_headers: dict) -> tuple[bool, str]:
    """(trusted, authserv_id): upstream headers count ONLY when the stamping
    host belongs to the configured trusted relay boundary. Fail closed:
    unconfigured boundary or unknown stamper => untrusted."""
    sid, _text = _boundary_ar_header(raw_headers)
    if not sid:
        # Received-SPF alone carries no authserv-id; without attribution it
        # cannot be tied to our boundary either.
        return False, ""
    for suffix in _trusted_relay_hosts():
        from .psl import is_subdomain_of
        if is_subdomain_of(sid, suffix):
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

    # 2. Authentication-Results / ARC-Authentication-Results headers.
    # P0: read ONLY the boundary header (see _boundary_ar_header) so that
    # attribution and claims always come from the same, bottom-most AR
    # header. Joining every AR header let an attacker-authored one supply
    # the `spf=pass ...` claim that a trusted sibling stamped elsewhere.
    combined = _boundary_ar_header(raw_headers)[1]
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
    """Attach the (un)trusted upstream claim for analyst provenance without
    letting it change the local verdict."""
    if upstream_claim:
        result = dict(result)
        result["upstream"] = dict(upstream_claim)
    return result


# Statuses RFC 7489 / RFC 7208 define. Anything else in an upstream header is
# attacker noise and is never treated as a verdict.
_VERDICT_STATUSES = frozenset({
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", UNVERIFIABLE,
})


def _trusted_upstream_verdict(local_status: str, upstream_claim: dict[str, Any] | None,
                              trust_upstream: bool = False) -> dict[str, Any] | None:
    """Verdict to substitute for `local_status`, or None to keep the local one.

    Two conditions must BOTH hold, and neither defaults to satisfied:

    1. `trust_upstream` — the caller verified the stamping host is inside the
       configured trusted relay boundary via _upstream_trusted().
    2. `local_status == UNVERIFIABLE` — the one state meaning "we could not
       attempt the check at all" (no sender IP, live lookups disabled, the
       validator library missing).

    A locally-attempted verdict is authoritative and is NEVER upgraded. That
    includes:
      - `temperror`/`permerror` — a transient/permanent DNS failure must stay
        a DNS failure; reporting `pass` for a lookup we could not complete
        is the classic Authentication-Results fail-open.
      - `none` — we read the headers and there is no DKIM-Signature, or the
        _dmarc domain publishes no record. An upstream `pass` then means the
        signature/record was stripped, which is evidence, not a fallback.
      - `fail` — an explicit failure is never overruled.

    Callers attach the claim with _with_upstream() either way, so the analyst
    still sees the upstream reading and its provenance.
    """
    if not trust_upstream or local_status != UNVERIFIABLE or not upstream_claim:
        return None
    status = str(upstream_claim.get("status", "") or "").strip().lower()
    if status not in _VERDICT_STATUSES or status == UNVERIFIABLE:
        return None
    return {"status": status,
            "detail": f"trusted-upstream: {str(upstream_claim.get('detail', ''))[:300]}",
            "upstream": dict(upstream_claim)}


def validate_spf(sender_ip: str, envelope_from: str, helo: str = "",
                 upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_spf = (upstream or {}).get("spf")

    if not (sender_ip or "").strip():
        local = {"status": UNVERIFIABLE, "detail": "no sender IP available; SPF not checked"}
        sub = _trusted_upstream_verdict(UNVERIFIABLE, upstream_spf, trust_upstream)
        return sub or _with_upstream(local, upstream_spf)

    if not _live():
        local = {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; SPF not checked"}
        sub = _trusted_upstream_verdict(UNVERIFIABLE, upstream_spf, trust_upstream)
        return sub or _with_upstream(local, upstream_spf)

    if not envelope_from:
        # No envelope identity => SPF has nothing to check. "none", never
        # the display From domain and never an upstream override.
        return _with_upstream({"status": "none", "detail": "no envelope sender; SPF not checked"}, upstream_spf)

    try:
        import spf
        result, comment = spf.check2(i=sender_ip, s=envelope_from, h=helo or None)
        if result == "fail":
            # Hard failure stands even against a trusted upstream pass.
            return _with_upstream({"status": result, "detail": str(comment)}, upstream_spf)
        # P0: `none` and `temperror` are locally-attempted verdicts. A DNS
        # failure is never reported as an upstream `pass`, and neither is
        # the absence of an SPF record. The claim rides along for provenance.
        return _with_upstream({"status": result, "detail": str(comment)}, upstream_spf)
    except Exception as e:
        # P0: a validator crash is inconclusive, NOT "unverifiable". Scoring
        # weights unverifiable (5.0, meaning deliberately not checked) far
        # below temperror (15.0, meaning checked but inconclusive), so
        # relabelling a crash as unverifiable would quietly lower the risk
        # score. Keep temperror -- which also blocks upstream substitution,
        # since only `unverifiable` may be replaced.
        return _with_upstream({"status": "temperror", "detail": f"spf-unavailable: {e}"}, upstream_spf)


def validate_dkim(raw_bytes: bytes, raw_headers: dict | None = None,
                  upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_dkim = (upstream or {}).get("dkim")
    headers = raw_headers or {}
    dkim_sig = _get_header(headers, "DKIM-Signature")
    has_sig = bool(dkim_sig.strip())

    if not has_sig:
        # P0: we read the headers and there is no DKIM-Signature. That is a
        # definitive `none`, so a trusted upstream `pass` is NOT a fallback —
        # it would mean the signature was stripped between here and there.
        return _with_upstream({"status": "none", "detail": "no-dkim-signature-header"}, upstream_dkim)

    # RFC 6376 Section 3.5: x= Signature Expiration. If expired, fail closed.
    x_match = re.search(r"\bx\s*=\s*(\d+)", dkim_sig)
    if x_match:
        try:
            if int(x_match.group(1)) < time.time():
                return _with_upstream({"status": "fail", "detail": "dkim-signature-expired"}, upstream_dkim)
        except Exception:
            pass

    try:
        import dkim
        res = dkim.verify(raw_bytes)
        if res:
            return _with_upstream({"status": "pass", "detail": "dkimpy-verify"}, upstream_dkim)
        # Local cryptographic failure stands — a trusted upstream pass is
        # attached for provenance but never overrides the fail.
        return _with_upstream({"status": "fail", "detail": "dkimpy-verify-failed"}, upstream_dkim)
    except Exception as e:
        # The validator itself is unavailable (not a verification failure), so
        # this is the one DKIM case where a trusted upstream verdict may stand
        # in for `unverifiable`.
        local = {"status": UNVERIFIABLE, "detail": f"dkim-unavailable: {e}"}
        sub = _trusted_upstream_verdict(UNVERIFIABLE, upstream_dkim, trust_upstream)
        return sub or _with_upstream(local, upstream_dkim)


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
                   upstream: dict[str, Any] | None = None, trust_upstream: bool = False) -> dict[str, Any]:
    upstream_dmarc = (upstream or {}).get("dmarc")
    from_domain = _clean_domain(from_domain)
    if not from_domain:
        return _with_upstream({"status": UNVERIFIABLE, "detail": "no-from-domain"}, upstream_dmarc)

    if not _live():
        local = {"status": UNVERIFIABLE, "detail": "live-lookups-disabled; DMARC not checked"}
        sub = _trusted_upstream_verdict(UNVERIFIABLE, upstream_dmarc, trust_upstream)
        return sub or _with_upstream(local, upstream_dmarc)

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

        from .psl import same_organization
        # PSL-aware organizational alignment (DMARC relaxed): same
        # registrable domain in either direction — never raw endswith,
        # which equated evil.co.uk with bank.co.uk via "co.uk".
        spf_match = same_organization(spf_domain, from_domain)
        dkim_match = same_organization(dkim_domain, from_domain)

        spf_aligned = spf_status == "pass" and spf_match
        dkim_aligned = dkim_status == "pass" and dkim_match

        if spf_aligned or dkim_aligned:
            return _with_upstream({"status": "pass", "detail": f"dmarc-pass (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}, upstream_dmarc)
        else:
            return _with_upstream({"status": "fail", "detail": f"dmarc-alignment-failed (policy: {pol})", "policy": pol, "record": dmarc[0][:200]}, upstream_dmarc)

    # P0: no _dmarc record for this domain is a definitive `none` (RFC 7489
    # §6.6.3), not a gap to be filled by whatever the upstream claims. The
    # claim is attached for provenance only.
    return _with_upstream({"status": "none", "detail": "no-dmarc-record"}, upstream_dmarc)


def validate_all(raw_bytes: bytes, raw_headers: dict, sender_ip: str, envelope_from: str = "") -> dict[str, Any]:
    from_domain = _clean_domain(_get_header(raw_headers, "From"))
    # SPF authenticates the ENVELOPE sender (Return-Path), never the display
    # From. Missing envelope => SPF "none", not a From-domain check.
    return_path = _get_header(raw_headers, "Return-Path")
    has_envelope = bool((envelope_from or "").strip() or return_path.strip())
    env_from = (envelope_from or "").strip() or return_path.strip()

    # Upstream claims + trust gate: honored only when stamped by our boundary.
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
    
    # DMARC-style alignment requires an actual domain match, not just a pass.
    from .psl import same_organization
    # DMARC-style alignment requires same registrable domain (PSL-aware),
    # not just a pass and not raw endswith.
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
