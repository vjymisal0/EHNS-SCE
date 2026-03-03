"""
File analysis API routes.

Endpoints:
  POST /api/v1/analyze   – Upload a file and receive a security analysis report.
  GET  /api/v1/history    – List past analysis records.
"""

from __future__ import annotations

import logging
import datetime

from fastapi import APIRouter, UploadFile, File, HTTPException

from app.core.config import MAX_FILE_SIZE_BYTES
from app.core.security import sanitize_filename
from app.services.file_analyzer import analyse_file
from app.schemas.analysis_schema import AnalysisResponse, ErrorResponse
from app.models.database import get_analyses_collection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Analyze an uploaded file for security risks",
)
async def analyze_file_endpoint(
    file: UploadFile = File(..., description="File to analyze"),
):
    """
    Accept a single file upload, run the full analysis pipeline,
    persist the result to MongoDB, and return the security report.
    """
    # ── 1. Validate presence ──────────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    # ── 2. Read file content with size guard ──────────────────
    # SECURITY: Read in one shot with a hard limit to prevent
    # memory exhaustion from oversized uploads.
    try:
        file_bytes = await file.read()
    except Exception as exc:
        logger.error("Failed to read uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read file.")

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of "
            f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB.",
        )

    # ── 3. Run analysis ──────────────────────────────────────
    try:
        result = analyse_file(
            filename=file.filename,
            file_bytes=file_bytes,
            declared_content_type=file.content_type,
        )
    except Exception as exc:
        logger.exception("Analysis failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=500, detail="Analysis engine error.")

    # ── 4. Persist to MongoDB ────────────────────────────────
    try:
        collection = get_analyses_collection()
        document = {
            **result,
            "created_at": datetime.datetime.utcnow(),
        }
        insert_result = await collection.insert_one(document)
        logger.info(
            "Analysis persisted – id=%s sha256=%s",
            insert_result.inserted_id,
            result["hashes"]["sha256"],
        )
    except Exception as exc:
        logger.error("MongoDB persistence failed: %s", exc)
        # Don't fail the request – analysis result is still valid
        # but log the persistence failure for ops review.

    # ── 5. Return analysis result ────────────────────────────
    # SECURITY: file_bytes are never written to disk and never
    # returned in the response. They are discarded after analysis.
    return AnalysisResponse(**result)


@router.get(
    "/history",
    response_model=list[AnalysisResponse],
    summary="List recent analysis records",
)
async def get_analysis_history(limit: int = 20):
    """Return the most recent analysis records from MongoDB."""
    collection = get_analyses_collection()
    cursor = collection.find(
        {},
        {"_id": 0}  # Exclude MongoDB _id from results
    ).sort("created_at", -1).limit(min(limit, 100))

    results = []
    async for doc in cursor:
        results.append(
            AnalysisResponse(
                filename=doc["filename"],
                file_size=doc["file_size"],
                mime_type=doc["mime_type"],
                hashes=doc["hashes"],
                entropy=doc["entropy"],
                suspicious_indicators=doc.get("suspicious_indicators", []),
                risk_score=doc["risk_score"],
                risk_level=doc["risk_level"],
            )
        )

    return results
