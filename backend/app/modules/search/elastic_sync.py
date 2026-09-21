"""Elasticsearch mirror for full-text forensic search (F10).

- `index_email()` is called after each pipeline run (best-effort; skipped
  when ELASTICSEARCH_URL is unset, so SQLite-first dev is unaffected).
- `search_emails()` uses ES when configured, else falls back to the same
  SQLite ilike search as GET /emails so the endpoint always works.
"""
import logging
from typing import Any

log = logging.getLogger("elastic")


def _client():
    from ...config import get_settings

    settings = get_settings()
    if not settings.elasticsearch_url:
        return None
    try:
        from elasticsearch import Elasticsearch
        kwargs: dict[str, Any] = {"request_timeout": 5}
        if settings.elasticsearch_user:
            kwargs["basic_auth"] = (settings.elasticsearch_user, settings.elasticsearch_password)
        return Elasticsearch(settings.elasticsearch_url, **kwargs)
    except Exception as e:
        log.warning("elasticsearch client init failed: %s", e)
        return None


def index_email(email_id: str, email_doc: dict, analysis_doc: dict) -> dict:
    from ...config import get_settings

    es = _client()
    if es is None:
        return {"indexed": False, "skipped": True}
    try:
        es.index(
            index=get_settings().elastic_index,
            id=email_id,
            document={"email": email_doc, "analysis": analysis_doc},
        )
        return {"indexed": True}
    except Exception as e:
        log.warning("elastic index failed for %s: %s", email_id, e)
        return {"indexed": False, "error": str(e)[:300]}


def _escape_like(raw: str) -> str:
    """Escape LIKE wildcards so user input can't trigger full scans (Step 3)."""
    return raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_emails(query: str, limit: int = 50, db=None, organization_id="__all__") -> dict:
    from ...config import get_settings

    es = _client()
    if es is not None:
        try:
            es_query: dict = {"multi_match": {
                "query": query,
                "fields": ["email.subject^3", "email.sender_address^2",
                           "email.recipient_address", "email.body_text_masked"],
            }}
            if organization_id != "__all__":
                # Tenant filter inside ES; docs without org match NULL-org tenants.
                should = [{"term": {"organization_id": organization_id}}]
                if organization_id is None:
                    should = [{"bool": {"must_not": {"exists": {"field": "organization_id"}}}}]
                es_query = {"bool": {"must": [es_query], "filter": should}}
            res = es.search(
                index=get_settings().elastic_index,
                query=es_query,
                size=min(max(limit, 1), 100),
            )
            hits = [{"id": h["_id"], **(h.get("_source") or {})} for h in res["hits"]["hits"]]
            return {"backend": "elasticsearch", "hits": hits}
        except Exception as e:
            log.warning("elastic search failed, falling back to sqlite: %s", e)
    # SQLite fallback (mirrors list_emails filtering)
    from sqlalchemy import desc, or_
    from ... import models
    like = f"%{query}%"
    q = db.query(models.EmailRecord).filter(or_(
        models.EmailRecord.subject.ilike(like),
        models.EmailRecord.sender_address.ilike(like),
        models.EmailRecord.recipient_address.ilike(like),
        models.EmailRecord.body_text_masked.ilike(like)))
    if organization_id != "__all__":
        q = q.filter(models.EmailRecord.organization_id == organization_id)
    rows = q.order_by(desc(models.EmailRecord.timestamp)).limit(limit).all()
    return {"backend": "sqlite", "hits": [
        {"id": r.id, "email": {"subject": r.subject, "sender_address": r.sender_address,
                              "recipient_address": r.recipient_address}} for r in rows]}
