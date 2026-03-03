"""
Cryptographic hash generation service.

Generates MD5, SHA-1, and SHA-256 digests of file content.
These hashes serve multiple purposes:
  - File integrity verification
  - Malware signature lookup (VirusTotal, etc.)
  - Duplicate detection

SECURITY NOTE: MD5 and SHA-1 are included for compatibility with
existing threat-intelligence databases, NOT for cryptographic security.
SHA-256 is the primary integrity hash.
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)


def calculate_hashes(file_bytes: bytes) -> dict[str, str]:
    """
    Compute MD5, SHA-1, and SHA-256 hex digests for the given bytes.

    Uses hashlib which delegates to OpenSSL – no custom crypto.
    """
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    logger.info("Hashes computed – SHA-256: %s", sha256)

    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }
