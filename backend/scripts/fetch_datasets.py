"""Fetch real labeled corpora for the NLP classifier (F5).

Sources (all public, no API key needed):
  - SpamAssassin easy_ham  (~2.5k legitimate mails -> label "clean")
  - SpamAssassin spam       (~500 spam mails        -> label "phishing")
  - BEC rows are curated in train_nlp.py (no public BEC corpus is freely
    downloadable); they are appended here so dataset.csv is self-contained.

Usage:
    python backend/scripts/fetch_datasets.py [--force]

Output:
    backend/ml_models/dataset.csv  (columns: text,label)
    backend/ml_models/raw/         (downloaded tarballs + extracts, gitignored)

train_nlp.py prefers dataset.csv when present and falls back to the small
hand-written lists otherwise, so training works fully offline too.
"""
import argparse
import csv
import email
import os
import re
import sys
import tarfile
import urllib.request

BASE = "https://spamassassin.apache.org/old/publiccorpus"
ARCHIVES = {
    "20030228_easy_ham.tar.bz2": "clean",
    "20030228_spam.tar.bz2": "phishing",
}
HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.abspath(os.path.join(HERE, "..", "ml_models", "raw"))
CSV_PATH = os.path.abspath(os.path.join(HERE, "..", "ml_models", "dataset.csv"))
MAX_CHARS = 5000


def _body_text(msg) -> str:
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True) or b""
                    parts.append(payload.decode("utf-8", errors="ignore"))
                except Exception:
                    continue
            elif ctype == "text/html" and not parts:
                try:
                    payload = part.get_payload(decode=True) or b""
                    html = payload.decode("utf-8", errors="ignore")
                    parts.append(re.sub(r"<[^>]+>", " ", html))
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode("utf-8", errors="ignore"))
            else:
                parts.append(str(msg.get_payload() or ""))
        except Exception:
            pass
    text = re.sub(r"\s+", " ", " ".join(parts)).strip()
    return text[:MAX_CHARS]


def fetch(force: bool = False) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    rows: list[tuple[str, str]] = []
    for archive, label in ARCHIVES.items():
        dest = os.path.join(RAW_DIR, archive)
        if force or not os.path.exists(dest):
            print(f"downloading {archive} ...")
            urllib.request.urlretrieve(f"{BASE}/{archive}", dest)
        print(f"extracting {archive} ...")
        with tarfile.open(dest, "r:bz2") as tf:
            members = [m for m in tf.getmembers() if m.isfile() and not m.name.endswith("cmds")]
            for m in members:
                f = tf.extractfile(m)
                if not f:
                    continue
                try:
                    msg = email.message_from_bytes(f.read())
                    subject = str(msg.get("Subject", "") or "")
                    body = _body_text(msg)
                    text = f"{subject}\n{body}".strip()
                    if len(text) >= 20:
                        rows.append((text, label))
                except Exception:
                    continue
    # curated BEC rows keep the third class alive (no public BEC corpus)
    sys.path.insert(0, HERE)
    from train_nlp import BEC
    rows.extend((t, "bec") for t in BEC)

    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)
    from collections import Counter
    print(f"wrote {CSV_PATH}: {len(rows)} rows {dict(Counter(l for _, l in rows))}")
    return CSV_PATH


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    fetch(force=args.force)
