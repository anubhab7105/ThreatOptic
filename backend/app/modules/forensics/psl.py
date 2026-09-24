"""Public-suffix-aware domain helpers (P0, shared).

Why this exists: naive last-two-labels logic treats ``evil.co.uk`` and
``bank.co.uk`` as the SAME domain (``co.uk``) — spoof/mismatch checks
then miss real cross-organization spoofs, while exact-match checks
false-positive on legitimate subdomains (``mail.company.com`` vs
``company.com``).

Single consolidated implementation used by forensics (header_parser,
received_chain, auth_validator), threat intel (lookalikes) and
traceability (ip_extractor) instead of six independent copies.

Method: longest-match against a curated snapshot of multi-label public
suffixes (common ccTLD second levels + well-known SaaS suffixes);
anything unmatched falls back to last-two-labels. Dependency-free
(stdlib only) so offline mode keeps working.

Limitations (documented, not silent):
- Snapshot, not the live Mozilla PSL: exotic/new suffixes fall back to
  last-two-labels. Update _MULTI_SUFFIXES when adding coverage.
- Wildcard PSL rules (e.g. ``*.kobe.jp``, ``*.ck``) are not modeled;
  such hosts fall back to last-two-labels (fail toward mismatch, which
  is the safe direction for spoof detection).
- NOT used by url_ml feature extraction: that model was trained on
  last-two-labels features, so changing its input would silently shift
  inference. Deliberately out of scope.
"""

# Curated multi-label public suffixes (lowercase, no leading dot).
# Covers the most-abused ccTLD second levels + major SaaS suffixes.
_MULTI_SUFFIXES = frozenset({
    # UK + Crown dependencies
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "gov.uk", "ac.uk", "nhs.uk", "mod.uk", "mil.uk", "police.uk",
    "co.im", "co.je", "co.gg",
    # Australia / NZ / Pacific
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "geek.nz", "gen.nz", "kiwi.nz", "maori.nz",
    "com.fj", "com.pg", "com.ws",
    # Japan / Korea / Asia
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp", "ad.jp",
    "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr",
    "ac.kr", "hs.kr", "ms.kr", "es.kr", "sc.kr", "kg.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "res.in", "nic.in", "gen.in", "firm.in", "ind.in",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "com.pk", "com.bd", "com.np", "com.lk",
    "co.id", "or.id", "ac.id", "go.id", "mil.id", "web.id",
    "co.th", "ac.th", "go.th", "mil.th", "net.th", "in.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.kh", "com.mm", "com.la",
    # South Africa / Africa
    "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
    "school.za", "law.za", "mil.za", "ngo.za", "nom.za",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke", "sc.ke",
    "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng",
    "com.gh", "com.eg", "com.tn", "com.ma", "co.ma",
    # Brazil / Latin America (common second levels)
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    "ecn.br", "adm.br", "adv.br", "agr.br", "am.br", "arq.br",
    "art.br", "ato.br", "bio.br", "blog.br", "bmd.br", "cim.br",
    "cng.br", "cnt.br", "com.br", "coop.br", "cri.br", "def.br",
    "ecn.br", "eco.br", "edu.br", "emp.br", "eng.br", "esp.br",
    "etc.br", "eti.br", "far.br", "flog.br", "fm.br", "fnd.br",
    "fot.br", "fst.br", "g12.br", "ggf.br", "gov.br", "imb.br",
    "ind.br", "inf.br", "jor.br", "jus.br", "leg.br", "lel.br",
    "mat.br", "med.br", "mil.br", "mus.br", "net.br", "nom.br",
    "not.br", "ntr.br", "odo.br", "org.br", "ppg.br", "pro.br",
    "psc.br", "psi.br", "qsl.br", "radio.br", "rec.br", "slg.br",
    "srv.br", "taxi.br", "teo.br", "tmp.br", "trd.br", "tur.br",
    "tv.br", "vet.br", "vlog.br", "wiki.br", "zlg.br",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar", "mil.ar",
    "com.co", "net.co", "nom.co", "edu.co", "gov.co", "mil.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe", "mil.pe",
    "com.ve", "net.ve", "org.ve", "gob.ve", "edu.ve", "mil.ve",
    "com.cl", "net.cl", "gov.cl",
    "com.ec", "net.ec", "info.ec", "fin.ec", "med.ec",
    "com.uy", "net.uy", "org.uy", "gub.uy", "edu.uy", "mil.uy",
    "com.py", "net.py", "org.py", "gov.py", "edu.py",
    "com.bo", "net.bo", "org.bo", "tv.bo",
    # Europe
    "co.at", "or.at", "gv.at", "ac.at",
    "com.de", "co.de",
    "com.fr", "asso.fr", "nom.fr", "prd.fr", "presse.fr",
    "tm.fr", "com.fr",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "edu.pt", "gov.pt", "int.pt", "publ.pt",
    "co.it", "gov.it", "edu.it",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "mil.pl",
    "com.ro", "org.ro", "tm.ro", "nt.ro", "nom.ro", "info.ro",
    "rec.ro", "arts.ro", "firm.ro", "store.ro", "www.ro",
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua",
    "kiev.ua", "lviv.ua", "odesa.ua", "dnipro.ua", "kharkiv.ua",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "mil.tr",
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr", "mil.gr",
    "com.hr", "com.cy", "com.mt",
    "co.hu", "org.hu", "priv.hu",
    "co.cz", "co.sk",
    "com.ru", "net.ru", "org.ru", "pp.ru",
    "com.by", "com.kz", "com.ge",
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "idf.il",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "med.sa",
    "com.ae", "net.ae", "org.ae", "gov.ae", "edu.ae",
    "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb",
    # North America extras
    "co.ca", "ab.ca", "bc.ca", "mb.ca", "nb.ca", "nf.ca", "nl.ca",
    "ns.ca", "nt.ca", "nu.ca", "on.ca", "pe.ca", "qc.ca", "sk.ca",
    "yk.ca",
    # Well-known SaaS / cloud public suffixes
    "github.io", "herokuapp.com", "azurewebsites.net",
    "cloudfront.net", "s3.amazonaws.com", "blogspot.com",
    "blogspot.co.uk", "appspot.com", "gitlab.io", "pages.dev",
    "web.app", "firebaseapp.com",
})


def _labels(host: str) -> list[str]:
    return [p for p in (host or "").lower().strip().strip(".").split(".") if p]


def _is_ip_literal(host: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address((host or "").strip().strip("[] "))
        return True
    except Exception:
        return False


def public_suffix(host: str) -> str:
    """Longest matching multi-label suffix, else the last label.

    Returns "" for empty/hostnames without a dot.
    """
    parts = _labels(host)
    if len(parts) < 2:
        return ""
    # Longest match: try 3-label, then 2-label suffixes.
    for width in (3, 2):
        if len(parts) >= width:
            cand = ".".join(parts[-width:])
            if cand in _MULTI_SUFFIXES:
                return cand
    return parts[-1]


def registrable_domain(host: str) -> str:
    """Effective second-level domain: one label + public suffix.

    Examples: mail.google.com -> google.com; a.b.mail.co.uk -> mail.co.uk;
    evil.co.uk vs bank.co.uk stay DISTINCT (the naive last-two-labels bug
    collapsed both to co.uk). Single-label/IP-literal input echoes back.
    """
    parts = _labels(host)
    if len(parts) < 2 or _is_ip_literal(host):
        return (host or "").lower().strip().strip(".")
    suffix = public_suffix(host)
    if not suffix:
        return (host or "").lower().strip().strip(".")
    n_suffix = len(suffix.split("."))
    if len(parts) <= n_suffix:
        # Host IS (or is under) a public suffix: nothing registrable.
        return ".".join(parts)
    return ".".join(parts[-(n_suffix + 1):])


def same_organization(a: str, b: str) -> bool:
    """True when both hosts share a non-empty registrable domain.

    Fail closed: empty/unparseable inputs never compare equal.
    """
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra and rb) and ra == rb


def is_subdomain_of(host: str, domain: str) -> bool:
    """True when host == domain or host is a proper subdomain of it."""
    h, d = (host or "").lower().strip().strip("."), (domain or "").lower().strip().strip(".")
    if not h or not d:
        return False
    return h == d or h.endswith("." + d)
