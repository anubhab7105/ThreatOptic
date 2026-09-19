"""FastAPI entrypoint."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import get_settings
from .database import init_db
from .routers.api import router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(router, prefix=settings.api_prefix)


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name}


@app.get("/")
def root():
    return {"app": settings.app_name, "docs": "/docs", "api": settings.api_prefix}
