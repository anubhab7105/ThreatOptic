"""Lookalike / homograph domain detection (shared by URL + header analysis).

- `KNOWN_LEGIT_DOMAINS`: built-in high-value targets, extendable via the
  `known_legit_domains` config value (comma-separated).
- `normalize_homoglyphs()`: fold common confusables (0→o, 1→l, rn→m …).
- `decode_punycode()`: stdlib idna decode for xn-- labels.
- `levenshtein()`: dependency-free edit distance.
- `lookalike_of()`: returns the impersonated legit domain + evidence, or None.
"""
import os

BUILTIN_LEGIT = (
    "paypal.com", "microsoft.com", "google.com", "gmail.com", "apple.com",
    "amazon.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "facebook.com", "instagram.com", "linkedin.com", "netflix.com",
    "ebay.com", "outlook.com", "office365.com", "dhl.com", "fedex.com",
)

# single-char confusables -> ascii
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "6": "b", "8": "b",
    "à": "a", "á": "a", "â": "a", "ä": "a", "ç": "c", "è": "e",
    "é": "e", "ê": "e", "ë": "e", "ì": "i", "í": "i", "î": "i",
    "ï": "i", "ñ": "n", "ò": "o", "ó": "o", "ô": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ý": "y", "ÿ": "y",
    "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "ł": "l", "đ": "d",
    "ı": "i", "ſ": "s", "а": "a", "е": "e", "і": "i", "о": "o",
    "р": "p", "с": "c", "х": "x", "у": "y", "к": "k", "м": "m",
    "н": "h", "т": "t",
}
# multi-char visual pairs, applied first
DIGRAPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))


def known_legit_domains() -> list[str]:
    extra = [d.strip().lower().lstrip(".") for d in
             os.environ.get("KNOWN_LEGIT_DOMAINS", "").split(",") if d.strip()]
    try:
        from ...config import get_settings
        extra += [d.strip().lower().lstrip(".") for d in
                  str(get_settings().known_legit_domains or "").split(",") if d.strip()]
    except Exception:
        pass
    seen = list(BUILTIN_LEGIT)
    for d in extra:
        if d and d not in seen:
            seen.append(d)
    return seen


def registrable(domain: str) -> str:
    """Naive registrable domain (last two labels). No publicsuffix dep."""
    parts = (domain or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "").lower()


def normalize_homoglyphs(domain: str) -> str:
    d = (domain or "").lower()
    for pair, single in DIGRAPHS:
        d = d.replace(pair, single)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in d)


def decode_punycode(domain: str) -> str:
    """Decode xn-- labels via stdlib idna; returns input unchanged on failure."""
    try:
        return ".".join(
            part.encode("ascii").decode("idna") if part.startswith("xn--") else part
            for part in (domain or "").split(".")
        )
    except Exception:
        return domain or ""


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str) -> dict | None:
    """Return impersonation evidence vs known-legit domains, else None.

    Shape: {"impersonates": <legit>, "distance": int, "via": [...]} where via
    may contain "homograph" (punycode/confusable fold matched) and/or
    "typosquat" (small edit distance).
    """
    dom = (domain or "").lower().strip(".")
    if not dom or "." not in dom:
        return None
    reg = registrable(dom)
    decoded = decode_punycode(dom)
    folded = normalize_homoglyphs(decoded)
    for legit in known_legit_domains():
        if reg == legit:
            return None  # the real thing
        via: list[str] = []
        folded_reg = registrable(folded)
        if folded_reg == legit and folded != dom.lower():
            via.append("homograph")
        dist = levenshtein(folded_reg, legit)
        threshold = 1 if len(legit) <= 10 else 2
        if 0 < dist <= threshold:
            via.append("typosquat")
        # decoded-punycode exact hit counts as homograph even at distance 0
        if not via and registrable(decoded) == legit and decoded != dom:
            via.append("homograph")
        # combo-squat: brand SLD embedded with extra words
        # (paypa1-secure.top, paypal-login.com) — checked on folded form
        sld = legit.split(".")[0]
        squashed = folded_reg.replace(".", "")
        if not via and len(sld) >= 4 and sld in squashed:
            via.append("combo-squat")
            dist = min(dist, 3)
        if via:
            return {"impersonates": legit, "distance": dist, "via": via}
    return None
