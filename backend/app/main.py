"""FastAPI entrypoint."""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from .config import get_settings
from .database import SessionLocal, init_db
from .modules.auth.rate_limit import apply_limiter_setting, limiter
from .routers.api import router
from .routers.auth import router as auth_router
from .routers.gmail import router as gmail_router
from .routers.oauth import router as oauth_router
from .routers.ws import router as ws_router
from .routers.deps import get_current_user

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
log = logging.getLogger("main")
settings = get_settings()


async def _smtp_consumer() -> None:
    """Background loop: SMTP queue -> forensic pipeline (F3)."""
    from .modules.ingestion.queue import dequeue_email
    from .services.pipeline import process_raw_email
    log.info("SMTP consumer started")
    while True:
        try:
            try:
                payload = await dequeue_email()
            except asyncio.CancelledError:
                raise
            raw = payload.get("raw", b"")
            if isinstance(raw, str):
                raw = raw.encode()
            db = SessionLocal()
            try:
                res = await process_raw_email(
                    db, raw, source=payload.get("source", "smtp"),
                    envelope_from=payload.get("envelope_from", ""),
                    envelope_tos=payload.get("rcpt_tos") or [],
                )
                log.info("SMTP mail analyzed: %s score=%s", res["email_id"], res["fraud_score"])
                try:
                    from .modules.cache import cache_delete_prefix
                    cache_delete_prefix("dash:")
                except Exception:
                    pass
            except Exception:
                log.exception("SMTP pipeline run failed")
            finally:
                db.close()
        except asyncio.CancelledError:
            log.info("SMTP consumer stopped")
            break


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .config import require_secrets
    from .modules.privacy.chain_of_custody import require_custody_key

    require_secrets()
    if "*" in settings.cors_origin_list:
        # allow_credentials=True + "*" is a real misconfiguration: browsers
        # would send credentials anywhere. Refuse to boot like this.
        raise RuntimeError("Refusing to boot: CORS_ORIGINS contains '*' with credentials enabled.")
    apply_limiter_setting()
    init_db()
    log.info("DB ready at %s", settings.resolved_db_url())
    try:
        from .modules.nlp.engine import warmup
        warmup()
        log.info("NLP model warmed up")
    except Exception as ex:
        log.warning("NLP warmup deferred: %s", ex)
    require_custody_key()
    from .modules.graph.store import graph_consistency_note
    note = graph_consistency_note()
    if note:
        log.warning(note)
    try:
        from .services.campaigns import _ensure_graph
        with SessionLocal() as _db:
            _ensure_graph(_db)
    except Exception as ex:
        log.warning("Initial graph seed deferred: %s", ex)
    controller = None
    consumer = None
    scheduler = None
    if settings.smtp_on:
        from .modules.ingestion.smtp_server import start_smtp
        controller = start_smtp(settings.smtp_host, settings.smtp_port)
        consumer = asyncio.create_task(_smtp_consumer())
        log.info("SMTP ingestion listening on %s:%s", settings.smtp_host, settings.smtp_port)
    try:
        from .services.scheduler import start_scheduler
        scheduler = start_scheduler()
    except Exception:
        log.exception("scheduler failed to start (retention must be run manually)")
    try:
        yield
    finally:
        try:
            from .modules.ingestion.queue import close_producer, set_shutdown
            set_shutdown()
            await close_producer()
        except Exception:
            pass
        if scheduler:
            scheduler.shutdown(wait=False)
        if consumer:
            consumer.cancel()
        if controller:
            controller.stop()
        try:
            from .modules.graph.store import close_neo
            close_neo()
        except Exception:
            pass


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _ratelimit_exceeded(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"detail": "rate limit exceeded, slow down"}, status_code=429)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router, prefix=settings.api_prefix)
# All threat-intel routes require a valid JWT; the auth router above stays public.
app.include_router(router, prefix=settings.api_prefix, dependencies=[Depends(get_current_user)])
app.include_router(gmail_router, prefix=settings.api_prefix, dependencies=[Depends(get_current_user)])
app.include_router(oauth_router, prefix=settings.api_prefix)
# WebSocket authenticates via ?token= (browsers can't set WS headers).
app.include_router(ws_router, prefix=settings.api_prefix)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)
    msg = f"internal error: {exc}" if settings.app_env.lower() == "development" else "Internal server error"
    return JSONResponse({"detail": msg}, status_code=500)


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name}


@app.get("/health/detailed")
def health_detailed():
    from .database import engine
    db_ok = True
    try:
        with engine.connect() as c:
            c.exec_driver_sql("SELECT 1")
    except Exception as e:
        db_ok = False
        log.warning("db health check failed: %s", e)
    try:
        from .modules.nlp.engine import analyze_text
        r = analyze_text("test", "hello world")
        nlp_ok = "ml_score" in r
    except Exception:
        nlp_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "nlp": nlp_ok,
            "live_lookups": settings.live_lookups}


@app.get("/")
def root():
    return {"app": settings.app_name, "docs": "/docs", "api": settings.api_prefix}
