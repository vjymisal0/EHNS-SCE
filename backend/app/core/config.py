"""
Application configuration module.

All security-sensitive values are loaded from environment variables
with safe defaults for development. In production, these MUST be
overridden via environment variables or a .env file.
"""

from __future__ import annotations

import os
from pathlib import Path


# ──────────────────────────────────────────────
# Path configuration
# ──────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent

# SECURITY: Upload directory is kept OUTSIDE static/public paths
# so files are never directly served by the web server.
UPLOAD_DIR: Path = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────
# Upload limits
# ──────────────────────────────────────────────
# SECURITY: Hard limit prevents denial-of-service via oversized uploads.
MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10 MB

# ──────────────────────────────────────────────
# CORS – restrict in production
# ──────────────────────────────────────────────
CORS_ORIGINS: list[str] = os.getenv(
    "CORS_ORIGINS", "http://localhost:3000"
).split(",")

# ──────────────────────────────────────────────
# Rate limiting
# ──────────────────────────────────────────────
RATE_LIMIT: str = os.getenv("RATE_LIMIT", "10/minute")

# ──────────────────────────────────────────────
# Database – MongoDB
# ──────────────────────────────────────────────
MONGO_URL: str = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "file_security_analyzer")

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ──────────────────────────────────────────────
# Allowed MIME types (whitelist approach)
# SECURITY: Only analyse files whose real MIME matches this list.
# Extend as needed; rejecting unknown types reduces attack surface.
# ──────────────────────────────────────────────
ALLOWED_MIME_TYPES: set[str] = {
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/octet-stream",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/javascript",
    "application/json",
    "application/xml",
    "text/plain",
    "text/html",
    "text/css",
    "text/javascript",
    "text/csv",
    "text/xml",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "audio/mpeg",
    "video/mp4",
}

# ──────────────────────────────────────────────
# Suspicious string patterns (static analysis)
# ──────────────────────────────────────────────
SUSPICIOUS_PATTERNS: list[str] = [
    "eval(",
    "exec(",
    "subprocess",
    "os.system",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "powershell",
    "Invoke-Expression",
    "WScript.Shell",
    "ShellExecute",
    "CreateObject",
    "Runtime.getRuntime",
    "ProcessBuilder",
    "<script",
    "document.cookie",
    "fromCharCode",
    "\\x00",
    "\\x90\\x90",  # NOP sled indicator
    "SELECT.*FROM",
    "DROP TABLE",
    "UNION SELECT",
    "base64_decode",
    "php://input",
    "<?php",
    "import socket",
    "import requests",
    "urllib.request",
    "wget ",
    "curl ",
    "nc -e",
    "netcat",
    "reverse_tcp",
    "meterpreter",
    "mimikatz",
    "keylog",
]
