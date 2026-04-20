"""
FastAPI application entry point.

Configures:
  - CORS middleware (restricted origins)
  - Request logging middleware
  - Global exception handlers
  - Rate limiting (via SlowAPI)
  - Database initialisation
  - API router mounting
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging 
import time
import uuid

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import CORS_ORIGINS, RATE_LIMIT, LOG_LEVEL
from app.routes.analysis import router as analysis_router
from app.models.database import connect_db, close_db
from app.schemas.analysis_schema import HealthResponse

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Rate limiter
# ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

# ──────────────────────────────────────────────
# Application factory
# ──────────────────────────────────────────────


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("Connecting to MongoDB...")
    await connect_db()
    logger.info("File Security Analyzer API is ready.")
    try:
        yield
    finally:
        logger.info("Shutting down...")
        await close_db()


app = FastAPI(
    title="File Security Analyzer",
    description=(
        "Upload a file and receive a comprehensive static security analysis "
        "report including hash verification, entropy measurement, MIME "
        "validation, suspicious string detection, and heuristic risk scoring."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ──────────────────────────────────────────────
# CORS middleware
# SECURITY: In production, restrict origins to your frontend domain only.
# ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# Request logging middleware
# ──────────────────────────────────────────────
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """
    Log every request with a unique correlation ID,
    method, path, status code, and duration.
    """
    request_id = uuid.uuid4().hex[:8]
    start = time.perf_counter()

    logger.info(
        "[%s] → %s %s", request_id, request.method, request.url.path
    )

    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("[%s] Unhandled exception: %s", request_id, exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error."},
        )

    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "[%s] ← %s %s → %d (%.1f ms)",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )

    # Add security headers to every response
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Request-ID"] = request_id

    return response


# ──────────────────────────────────────────────
# Global exception handlers
# ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions.
    SECURITY: Never leak stack traces or internal details to clients.
    """
    logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.warning("ValueError on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────
app.include_router(analysis_router)


@app.get("/", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health / readiness probe."""
    return HealthResponse()
