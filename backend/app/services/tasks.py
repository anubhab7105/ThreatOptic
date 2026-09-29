
import asyncio
import base64
import logging

log = logging.getLogger("tasks")


def _celery_app():
    from celery import Celery
    from ..config import get_settings

    settings = get_settings()
    broker = (settings.celery_broker_url or "").strip()
    backend = (settings.celery_result_backend or "cache+memory://").strip()
    app = Celery("soc", broker=broker or "memory://", backend=backend)
    app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1,
                    task_store_eager_result=True)
    return app


celery_app = _celery_app()


def broker_configured() -> bool:
    from ..config import get_settings

    return bool((get_settings().celery_broker_url or "").strip())


@celery_app.task(name="soc.analyze_email", bind=True, max_retries=2)
def analyze_email_task(self, raw_b64: str, source: str = "api",
                       envelope_from: str = "", organization_id: str | None = None) -> dict:

    try:
        res = _run_pipeline(raw_b64, source, envelope_from, organization_id)
    except Exception as e:
        log.warning("celery task retry: %s", type(e).__name__)
        raise self.retry(exc=e, countdown=5)
    try:
        from ..modules.cache import cache_delete_prefix
        cache_delete_prefix("dash:")
    except Exception:
        pass
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


def _run_pipeline(raw_b64: str, source: str, envelope_from: str, organization_id: str | None) -> dict:

    from ..database import SessionLocal
    from .pipeline import process_raw_email

    def _work() -> dict:
        raw = base64.b64decode(raw_b64.encode())
        db = SessionLocal()
        try:
            return asyncio.run(process_raw_email(
                db, raw, source=source, envelope_from=envelope_from,
                organization_id=organization_id))
        finally:
            db.close()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _work()
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_work).result()
