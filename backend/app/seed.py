"""Seed demo org + users + 2 sample emails through the pipeline."""
import asyncio


def _hash(pw: str) -> str:
    from .modules.auth.security import hash_password

    return hash_password(pw)


PHISH_EML = b"""From: "CEO" <ceo@xn--paypa1-secure.top>
To: finance@company.com
Subject: Urgent: Confidential wire transfer needed ASAP
Message-ID: <abc123@xn--paypa1-secure.top>
Return-Path: <bounce@evil-relay.test>
Received: from evil-relay.test (evil-relay.test [45.148.10.88]) by mx.company.com with ESMTPS id x1
Received: from internal ([10.0.0.5]) by evil-relay.test with SMTP id y2
DKIM-Signature: v=1; d=xn--paypa1-secure.top; s=default;
Content-Type: text/plain

Hi, kindly wire $48,000 to new vendor bank details immediately. Do not disclose. Verify account now at http://malicious-example.com/login
"""

CLEAN_EML = b"""From: Alice <alice@company.com>
To: bob@company.com
Subject: Lunch tomorrow?
Message-ID: <lunch1@company.com>
Return-Path: <alice@company.com>
Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.company.com with ESMTPS id z9
Content-Type: text/plain

Hi Bob, lunch tomorrow at noon? Let me know if cafeteria works.
"""


async def main():
    from .database import SessionLocal, init_db
    from .models import Organization, User
    init_db()
    db = SessionLocal()
    try:
        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Demo SOC", compliance_policy={"retention_clean_days": 7, "retention_malicious_days": 90})
            db.add(org)
            db.flush()
        if not db.query(User).filter_by(username="admin").first():
            db.add(User(username="admin", password_hash=_hash("admin123"), role="Admin", organization_id=org.id))
        if not db.query(User).filter_by(username="analyst").first():
            db.add(User(username="analyst", password_hash=_hash("analyst123"), role="Analyst", organization_id=org.id))
        db.commit()
        from .services.pipeline import process_raw_email
        for raw in (PHISH_EML, CLEAN_EML):
            try:
                res = await process_raw_email(db, raw, source="seed")
                print({k: res.get(k) for k in ("email_id", "fraud_score", "classification", "action")})
            except Exception as e:
                print("seed error:", e)
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
