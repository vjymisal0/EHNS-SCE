"""
Core file analysis engine.

Orchestrates every inspection step and produces the final risk assessment.
Each function is deliberately stateless and side-effect-free so it can be
unit-tested in isolation.
"""

from __future__ import annotations

import re
import logging
from pathlib import PurePosixPath, Path

import magic  # python-magic – reads real MIME via libmagic / magic numbers

from app.core.config import SUSPICIOUS_PATTERNS
from app.services.hashing import calculate_hashes
from app.services.entropy import calculate_entropy

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# MIME validation
# ──────────────────────────────────────────────

def validate_mime(file_bytes: bytes, declared_type: str | None = None) -> dict:
    """
    Determine the real MIME type from magic numbers and compare
    it with the client-declared Content-Type.

    SECURITY: Attackers frequently send a benign Content-Type header
    while the actual payload is an executable or script. Detecting
    this mismatch is a high-value signal (risk +40).
    """
    real_mime = magic.from_buffer(file_bytes, mime=True)
    is_mismatch = False

    if declared_type and declared_type != real_mime:
        # Some flexibility: application/octet-stream is a generic fallback
        if declared_type != "application/octet-stream":
            is_mismatch = True
            logger.warning(
                "MIME mismatch detected – declared: %s, actual: %s",
                declared_type,
                real_mime,
            )

    return {
        "real_mime": real_mime,
        "declared_mime": declared_type,
        "is_mismatch": is_mismatch,
    }


# ──────────────────────────────────────────────
# Double-extension detection
# ──────────────────────────────────────────────

def detect_double_extension(filename: str) -> bool:
    """
    Detect filenames with double extensions like ``report.pdf.exe``.

    SECURITY: Double extensions are a classic social-engineering trick.
    Windows hides "known" extensions by default, so ``invoice.pdf.exe``
    appears as ``invoice.pdf`` to many users.
    """
    # Get all suffixes (e.g., .tar.gz → ['.tar', '.gz'])
    suffixes = PurePosixPath(filename).suffixes

    if len(suffixes) < 2:
        return False

    # Known dangerous final extensions
    dangerous_exts = {
        ".exe", ".bat", ".cmd", ".com", ".msi", ".scr",
        ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf",
        ".wsh", ".ps1", ".hta", ".cpl", ".reg", ".dll",
        ".sys", ".jar", ".py", ".sh", ".bash",
    }

    last_ext = suffixes[-1].lower()
    has_double = last_ext in dangerous_exts and len(suffixes) >= 2

    if has_double:
        logger.warning("Double extension detected: %s", filename)

    return has_double


# ──────────────────────────────────────────────
# Suspicious string detection
# ──────────────────────────────────────────────

def detect_suspicious_strings(file_bytes: bytes) -> list[str]:
    """
    Scan the file content for known suspicious strings/patterns.

    SECURITY: This is a lightweight static-analysis heuristic.
    It will NOT catch obfuscated payloads but catches low-effort
    attacks and scripts containing well-known dangerous calls.
    """
    found: list[str] = []

    try:
        # Attempt UTF-8 decode; fall back to latin-1 (never fails)
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = file_bytes.decode("latin-1", errors="replace")

    text_lower = text.lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.lower() in text_lower:
            found.append(pattern)
            logger.info("Suspicious pattern matched: %s", pattern)

    return found


# ──────────────────────────────────────────────
# Risk scoring engine
# ──────────────────────────────────────────────

def generate_risk_score(
    *,
    has_double_extension: bool,
    entropy: float,
    suspicious_strings: list[str],
    mime_mismatch: bool,
) -> dict:
    """
    Compute a heuristic risk score from all analysis signals.

    Scoring rules (additive):
      - Double extension detected  → +20
      - High entropy (>7.5)        → +30
      - Suspicious keywords found  → +25
      - MIME type mismatch         → +40

    Risk levels:
      0–30   → LOW
      31–60  → MEDIUM
      61+    → HIGH

    SECURITY: This is a heuristic model, not a guarantee.
    The score should guide human review, not replace it.
    """
    score = 0
    breakdown: list[str] = []

    if has_double_extension:
        score += 20
        breakdown.append("Double extension detected (+20)")

    if entropy > 7.5:
        score += 30
        breakdown.append(f"High entropy {entropy:.2f} > 7.5 (+30)")

    if suspicious_strings:
        score += 25
        breakdown.append(f"Suspicious strings found: {len(suspicious_strings)} (+25)")

    if mime_mismatch:
        score += 40
        breakdown.append("MIME type mismatch (+40)")

    # Determine risk level
    if score <= 30:
        risk_level = "LOW"
    elif score <= 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    logger.info(
        "Risk assessment: score=%d level=%s breakdown=%s",
        score,
        risk_level,
        breakdown,
    )

    return {
        "score": score,
        "level": risk_level,
        "breakdown": breakdown,
    }


# ──────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────

def analyse_file(
    filename: str,
    file_bytes: bytes,
    declared_content_type: str | None = None,
) -> dict:
    """
    Run the full analysis pipeline on a file and return a
    consolidated result dictionary.
    """
    logger.info("Starting analysis for: %s (%d bytes)", filename, len(file_bytes))

    # 1. Hashes
    hashes = calculate_hashes(file_bytes)

    # 2. Entropy
    entropy = calculate_entropy(file_bytes)

    # 3. MIME validation
    mime_info = validate_mime(file_bytes, declared_content_type)

    # 4. Double extension
    has_double_ext = detect_double_extension(filename)

    # 5. Suspicious strings
    suspicious = detect_suspicious_strings(file_bytes)

    # 6. Risk scoring
    risk = generate_risk_score(
        has_double_extension=has_double_ext,
        entropy=entropy,
        suspicious_strings=suspicious,
        mime_mismatch=mime_info["is_mismatch"],
    )

    # Build consolidated indicators list
    indicators: list[str] = []
    if has_double_ext:
        indicators.append("Double extension detected")
    if mime_info["is_mismatch"]:
        indicators.append(
            f"MIME mismatch: declared={mime_info['declared_mime']}, "
            f"actual={mime_info['real_mime']}"
        )
    if entropy > 7.5:
        indicators.append(f"High entropy: {entropy:.4f}")
    for s in suspicious:
        indicators.append(f"Suspicious string: {s}")

    return {
        "filename": filename,
        "file_size": len(file_bytes),
        "mime_type": mime_info["real_mime"],
        "hashes": hashes,
        "entropy": entropy,
        "suspicious_indicators": indicators,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
    }
