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
        # Store organization_id both nested and top-level for filtering robustness
        org = email_doc.get("organization_id")
        doc = {"email": email_doc, "analysis": analysis_doc, "organization_id": org}
        es.index(
            index=get_settings().elastic_index,
            id=email_id,
            document=doc,
        )
        return {"indexed": True}
    except Exception as e:
        log.warning("elastic index failed for %s: %s", email_id, e)
        return {"indexed": False, "error": str(e)[:300]}


def _escape_like(raw: str) -> str:
    """Escape LIKE wildcards so user input can't trigger full scans (Step 3)."""
    return raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def delete_email(email_id: str) -> dict:
    """Best-effort ES doc deletion (retention cascade)."""
    es = _client()
    if es is None:
        return {"deleted": False, "skipped": True}
    try:
        from ...config import get_settings
        es.delete(index=get_settings().elastic_index, id=email_id, ignore=[404])
        return {"deleted": True}
    except Exception as e:
        log.warning("elastic delete failed for %s: %s", email_id, e)
        return {"deleted": False, "error": str(e)[:300]}


def _extract_snippet(row: Any, query: str, window: int = 60) -> str:
    """Extract a surrounding snippet from masked body or subject matching query."""
    if not query:
        return ""
    q_lower = query.lower()
    for text in (getattr(row, "body_text_masked", "") or "", getattr(row, "subject", "") or ""):
        idx = text.lower().find(q_lower)
        if idx != -1:
            start = max(0, idx - window)
            end = min(len(text), idx + len(query) + window)
            snippet = text[start:end].strip()
            if start > 0:
                snippet = "..." + snippet
            if end < len(text):
                snippet = snippet + "..."
            return snippet
    return (getattr(row, "subject", "") or "")[:120]


class _Unset:
    """Sentinel that refuses to stand in for a tenant scope."""
    def __repr__(self):
        return "<unset organization_id>"


# Fail closed: a forgotten tenant scope used to default to "__all__", which
# silently searched every organization in both backends. Callers must now
# state the scope explicitly.
_UNSET = _Unset()


def search_emails(query: str, limit: int = 50, db=None,
                  organization_id: str | None | _Unset = _UNSET,
                  all_orgs: bool = False) -> dict:
    """Full-text search, scoped to one tenant by default.

    `organization_id` semantics:
      - a string  -> only that organization
      - None       -> only rows that have no organization assigned
      - all_orgs=True -> every organization (Admin cross-tenant search)

    Passing neither raises, so a new caller cannot leak all tenants by
    omission.
    """
    if isinstance(organization_id, _Unset) and not all_orgs:
        raise ValueError(
            "search_emails requires an explicit organization_id "
            "(or all_orgs=True for a deliberate cross-tenant search)")
    scope_all = bool(all_orgs)
    org = None if isinstance(organization_id, _Unset) else organization_id
    limit = min(max(int(limit), 1), 100)

    from ...config import get_settings

    es = _client()
    if es is not None:
        try:
            es_query: dict = {"multi_match": {
                "query": query,
                "fields": ["email.subject^3", "email.sender_address^2",
                           "email.recipient_address", "email.body_text_masked"],
            }}
            if not scope_all:
                # Tenant filter inside ES; docs without org match NULL-org tenants.
                # Legacy docs may only have email.organization_id, so check both.
                if org is None:
                    es_query = {"bool": {"must": [es_query], "filter": [{"bool": {"must_not": {"exists": {"field": "organization_id"}}}}]}}
                else:
                    should = [
                        {"term": {"organization_id": org}},
                        {"term": {"email.organization_id": org}},
                    ]
                    es_query = {"bool": {"must": [es_query], "filter": [{"bool": {"should": should, "minimum_should_match": 1}}]}}
            res = es.search(
                index=get_settings().elastic_index,
                query=es_query,
                size=limit,
            )
            hits = [{"id": h["_id"], **(h.get("_source") or {})} for h in res["hits"]["hits"]]
            return {"backend": "elasticsearch", "hits": hits}
        except Exception as e:
            log.warning("elastic search failed, falling back to sqlite: %s", e)
    # SQLite fallback (mirrors list_emails filtering)
    from sqlalchemy import desc, or_
    from ... import models
    if db is None:
        return {"backend": "none", "hits": []}
    like = f"%{_escape_like(query)}%"
    q = db.query(models.EmailRecord).filter(or_(
        models.EmailRecord.subject.ilike(like, escape="\\"),
        models.EmailRecord.sender_address.ilike(like, escape="\\"),
        models.EmailRecord.recipient_address.ilike(like, escape="\\"),
        models.EmailRecord.body_text_masked.ilike(like, escape="\\")))
    if not scope_all:
        q = q.filter(models.EmailRecord.organization_id == org)
    rows = q.order_by(desc(models.EmailRecord.timestamp)).limit(limit).all()
    return {"backend": "sqlite", "hits": [
        {"id": r.id, "email": {"subject": r.subject, "sender_address": r.sender_address,
                              "recipient_address": r.recipient_address},
         "snippet": _extract_snippet(r, query)} for r in rows]}
