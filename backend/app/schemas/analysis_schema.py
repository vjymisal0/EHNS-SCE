"""
Pydantic v2 response schemas for the analysis API.

These schemas enforce strict typing on all API responses and
serve as living documentation via OpenAPI/Swagger.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class HashesSchema(BaseModel):
    """Cryptographic hash digests."""

    md5: str = Field(..., description="MD5 hex digest (32 chars)")
    sha1: str = Field(..., description="SHA-1 hex digest (40 chars)")
    sha256: str = Field(..., description="SHA-256 hex digest (64 chars)")


class AnalysisResponse(BaseModel):
    """Full file security analysis result."""

    filename: str = Field(..., description="Original (unsanitized) filename")
    file_size: int = Field(..., ge=0, description="File size in bytes")
    mime_type: str = Field(..., description="Detected MIME type via magic numbers")
    hashes: HashesSchema
    entropy: float = Field(
        ..., ge=0.0, le=8.0, description="Shannon entropy (0–8 scale)"
    )
    suspicious_indicators: list[str] = Field(
        default_factory=list,
        description="Human-readable list of detected risk indicators",
    )
    risk_score: int = Field(..., ge=0, description="Heuristic risk score")
    risk_level: str = Field(
        ...,
        description="Risk classification: LOW | MEDIUM | HIGH",
        pattern="^(LOW|MEDIUM|HIGH)$",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "filename": "report.pdf.exe",
                    "file_size": 204800,
                    "mime_type": "application/x-dosexec",
                    "hashes": {
                        "md5": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                    "entropy": 7.92,
                    "suspicious_indicators": [
                        "Double extension detected",
                        "High entropy: 7.9200",
                        "MIME mismatch: declared=application/pdf, actual=application/x-dosexec",
                    ],
                    "risk_score": 90,
                    "risk_level": "HIGH",
                }
            ]
        }
    }


class ErrorResponse(BaseModel):
    """Standard error payload."""

    detail: str = Field(..., description="Human-readable error message")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str = "1.0.0"
