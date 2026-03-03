"""
Security utilities for file handling.

This module centralises all filename-sanitisation and path-safety logic
so that every upload path goes through one audited code path.
"""

from __future__ import annotations

import os
import re
import uuid
import logging
from pathlib import Path, PurePosixPath

from app.core.config import UPLOAD_DIR

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Dangerous characters / patterns
# ──────────────────────────────────────────────
# SECURITY: Strip everything that is not alphanumeric, dash, underscore, or dot.
_SAFE_FILENAME_RE = re.compile(r"[^\w\-.]", re.ASCII)

# SECURITY: Prevent path traversal components
_TRAVERSAL_PATTERNS = ["..", "/", "\\", "\x00"]


def sanitize_filename(filename: str) -> str:
    """
    Produce a safe filename from untrusted user input.

    Steps:
    1. Take only the basename – strips directory components.
    2. Remove any null bytes (classic C-string truncation attack).
    3. Replace unsafe characters with underscores.
    4. Prepend a UUID to prevent collisions and predictable names.
    5. Limit total length to avoid filesystem issues.

    SECURITY: Never trust client-supplied filenames. This function
    guarantees the result is a flat name safe for the upload directory.
    """
    if not filename:
        filename = "unnamed"

    # Step 1: Take only the final path component
    # Handles both Windows and POSIX separators.
    name = PurePosixPath(filename).name
    name = Path(name).name  # also handles backslashes

    # Step 2: Reject null bytes
    name = name.replace("\x00", "")

    # Step 3: Strip unsafe characters
    name = _SAFE_FILENAME_RE.sub("_", name)

    # Step 4: Limit length (preserve extension)
    if len(name) > 200:
        stem, _, ext = name.rpartition(".")
        name = f"{stem[:190]}.{ext}" if ext else name[:200]

    # Step 5: Prepend UUID for uniqueness and unpredictability
    unique_prefix = uuid.uuid4().hex[:12]
    safe_name = f"{unique_prefix}_{name}"

    logger.debug("Sanitized filename: %s -> %s", filename, safe_name)
    return safe_name


def validate_path_safety(filepath: Path) -> bool:
    """
    Verify that the resolved filepath stays within the upload directory.

    SECURITY: This is the last line of defence against path traversal.
    Even if sanitize_filename has a bug, this check will catch any
    attempt to write outside the designated upload directory.
    """
    try:
        resolved = filepath.resolve()
        upload_resolved = UPLOAD_DIR.resolve()
        # The file path MUST start with the upload directory path
        is_safe = str(resolved).startswith(str(upload_resolved))
        if not is_safe:
            logger.warning(
                "Path traversal blocked: %s resolved outside upload dir", filepath
            )
        return is_safe
    except (OSError, ValueError) as exc:
        logger.error("Path validation error: %s", exc)
        return False


def get_safe_upload_path(original_filename: str) -> Path:
    """
    Return a validated, safe absolute path for storing an uploaded file.

    Combines sanitization + path validation in one call.
    Raises ValueError if the resulting path is unsafe.
    """
    safe_name = sanitize_filename(original_filename)
    target = UPLOAD_DIR / safe_name

    if not validate_path_safety(target):
        raise ValueError(f"Unsafe file path generated for: {original_filename}")

    return target
