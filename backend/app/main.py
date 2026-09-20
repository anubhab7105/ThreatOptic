"""FastAPI entrypoint."""
import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .config import get_settings
from .database import init_db
from .routers.api import router
from .routers.auth import router as auth_router
from .routers.gmail import router as gmail_router
from .routers.deps import get_current_user

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
log = logging.getLogger("main")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("DB ready at %s", settings.resolved_db_url())
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router, prefix=settings.api_prefix)
# All threat-intel routes require a valid JWT; the auth router above stays public.
app.include_router(router, prefix=settings.api_prefix, dependencies=[Depends(get_current_user)])
app.include_router(gmail_router, prefix=settings.api_prefix, dependencies=[Depends(get_current_user)])


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse({"detail": f"internal error: {exc}"}, status_code=500)


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
