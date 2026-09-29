
import os
from functools import lru_cache
from typing import Any


VT_MAX_ATTACHMENTS = 5

MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".docb"}
EXEC_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".vbe",
             ".js", ".jse", ".wsf", ".wsh", ".jar", ".dll", ".cpl", ".gadget", ".hta"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".cab", ".iso", ".img"}


MAGIC = {
    "4d5a": "mz-executable",
    "25504446": "pdf",
    "504b0304": "zip-ooxml",
    "d0cf11e0": "ole-cfb",
    "7f454c46": "elf",
    "52617221": "rar",
    "377abcaf271c": "7z",
}


def _ext(name: str) -> str:
    name = (name or "").lower()
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def _magic_desc(magic_hex: str) -> str:
    m = (magic_hex or "").lower()
    for prefix, desc in MAGIC.items():
        if m.startswith(prefix):
            return desc
    return "unknown" if not m else "other"


def static_heuristics(filename: str, content_type: str = "", magic: str = "") -> list[str]:
    flags: list[str] = []
    name = (filename or "").lower()
    ext = _ext(name)
    base = name[: name.rfind(".")] if "." in name else name

    if ext in MACRO_EXTS:
        flags.append("macro-enabled-document")
    if ext in EXEC_EXTS:
        flags.append("executable-attachment")


    if ext in EXEC_EXTS | MACRO_EXTS and "." in base:
        flags.append("double-extension")

    kind = _magic_desc(magic)
    if kind in ("mz-executable", "elf") and ext not in EXEC_EXTS:
        flags.append(f"magic-mismatch:{kind}-as-{ext or 'noext'}")
    if kind == "ole-cfb" and ext not in MACRO_EXTS | {".doc", ".xls", ".ppt"}:
        flags.append(f"magic-mismatch:ole-as-{ext or 'noext'}")
    if ext in ARCHIVE_EXTS:
        flags.append("archive-attachment")
    return flags


@lru_cache(maxsize=4096)
def _lookup_hash_cached(sha256: str, api_key: str) -> tuple:

    import requests
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": api_key}, timeout=5,
    )
    if r.status_code == 200:
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return ("ok", int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)))
    if r.status_code == 404:
        return ("unknown", 0, 0)
    return ("status", r.status_code, 0)


def lookup_hash_virustotal(sha256: str, api_key: str = "") -> dict[str, Any]:
    if not api_key:
        return {"source": "virustotal-file", "skipped": True}
    if not sha256:
        return {"source": "virustotal-file", "skipped": True, "reason": "no-hash"}
    try:
        kind, a, b = _lookup_hash_cached(sha256, api_key)
        if kind == "ok":
            return {"source": "virustotal-file", "malicious": a, "suspicious": b}
        if kind == "unknown":
            return {"source": "virustotal-file", "unknown": True}
        return {"source": "virustotal-file", "status": a}
    except Exception as e:
        return {"source": "virustotal-file", "error": str(e)[:300]}


def analyze_attachments(attachments: list[dict] | None, vt_key: str = "") -> dict[str, Any]:

    vt_key = vt_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    findings: list[dict] = []
    risk = 0.0
    vt_lookups = 0
    for a in attachments or []:
        fname = a.get("filename", "")
        entry: dict[str, Any] = {"filename": fname, "sha256": a.get("sha256", ""),
                                 "size": a.get("size", 0)}
        reasons = static_heuristics(fname, a.get("content_type", ""), a.get("magic", ""))
        if "executable-attachment" in reasons:
            risk = max(risk, 70.0)
        if "macro-enabled-document" in reasons:
            risk = max(risk, 60.0)
        if any(r.startswith("magic-mismatch") for r in reasons):
            risk = max(risk, 80.0)
        if "double-extension" in reasons:
            risk = max(risk, 65.0)
        if reasons and risk < 30.0:
            risk = max(risk, 30.0)
        if vt_key and vt_lookups < VT_MAX_ATTACHMENTS:
            vt_lookups += 1
            vt = lookup_hash_virustotal(a.get("sha256", ""), vt_key)
        else:
            vt = {"source": "virustotal-file", "skipped": True,
                  "reason": "no-key" if not vt_key else "cap-reached"}
        if vt.get("malicious"):
            reasons.append(f"virustotal-malicious:{vt['malicious']}")
            risk = 100.0
        entry["reasons"] = reasons
        entry["virustotal"] = vt
        if reasons:
            findings.append(entry)
    return {"findings": findings, "risk": round(min(100.0, risk), 2),
            "malicious_count": sum(1 for f in findings if any("virustotal-malicious" in r for r in f["reasons"]))}
