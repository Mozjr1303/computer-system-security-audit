"""FastAPI entry point for the Windows Security Audit System."""
from contextlib import asynccontextmanager
import logging
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as api_router
from app.config import (
    ALLOWED_ORIGINS,
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
)
from app.database import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("winsecaudit")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite tables on application startup."""
    init_db()
    logger.info("SQLite database initialized.")
    yield


app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_local_access_only(request: Request, call_next):
    """Ensure API endpoints are only accessible from loopback addresses."""
    client_host = request.client.host if request.client else "127.0.0.1"
    allowed_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
    if client_host not in allowed_hosts:
        logger.warning("Blocked non-local API request from %s", client_host)
        return JSONResponse(
            status_code=403,
            content={"detail": "Access denied: WinSecAudit API is restricted to localhost only."},
        )
    return await call_next(request)


@app.get("/api/health", tags=["System"])
def health_check():
    """Verify backend operational status."""
    return {
        "status": "healthy",
        "service": APP_TITLE,
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


app.include_router(api_router)
