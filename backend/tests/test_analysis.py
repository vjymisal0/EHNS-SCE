from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.hashing import calculate_hashes
from app.services.entropy import calculate_entropy
from app.services.file_analyzer import (
    detect_double_extension,
    detect_suspicious_strings,
    generate_risk_score,
    analyse_file,
)


class TestHashing:
    def test_empty_bytes(self):
        result = calculate_hashes(b"")
        assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert result["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_known_string(self):
        result = calculate_hashes(b"hello")
        assert result["md5"] == "5d41402abc4b2a76b9719d911017c592"
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64

    def test_returns_all_keys(self):
        result = calculate_hashes(b"test")
        assert set(result.keys()) == {"md5", "sha1", "sha256"}


class TestEntropy:
    def test_empty_bytes(self):
        assert calculate_entropy(b"") == 0.0

    def test_uniform_bytes(self):
        assert calculate_entropy(b"\x00" * 1024) == 0.0

    def test_high_entropy(self):
        data = os.urandom(4096)
        entropy = calculate_entropy(data)
        assert entropy > 7.0

    def test_text_entropy(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 20
        entropy = calculate_entropy(text)
        assert 3.0 < entropy < 6.0


class TestDoubleExtension:
    def test_normal_file(self):
        assert detect_double_extension("report.pdf") is False

    def test_double_exe(self):
        assert detect_double_extension("report.pdf.exe") is True

    def test_double_bat(self):
        assert detect_double_extension("image.jpg.bat") is True

    def test_double_ps1(self):
        assert detect_double_extension("data.csv.ps1") is True

    def test_no_extension(self):
        assert detect_double_extension("README") is False

    def test_tar_gz_not_dangerous(self):
        assert detect_double_extension("archive.tar.gz") is False


class TestSuspiciousStrings:
    def test_clean_text(self):
        result = detect_suspicious_strings(b"Hello, this is a clean file.")
        assert result == []

    def test_detects_eval(self):
        result = detect_suspicious_strings(b"var x = eval('alert(1)');")
        assert "eval(" in result

    def test_detects_powershell(self):
        result = detect_suspicious_strings(b"Run-Command powershell -enc base64")
        assert "powershell" in result

    def test_detects_multiple(self):
        payload = b"import subprocess; os.system('rm -rf /')"
        result = detect_suspicious_strings(payload)
        assert "subprocess" in result
        assert "os.system" in result


class TestRiskScoring:
    def test_clean_file(self):
        result = generate_risk_score(
            has_double_extension=False,
            entropy=4.5,
            suspicious_strings=[],
            mime_mismatch=False,
        )
        assert result["score"] == 0
        assert result["level"] == "LOW"

    def test_double_extension_only(self):
        result = generate_risk_score(
            has_double_extension=True,
            entropy=4.5,
            suspicious_strings=[],
            mime_mismatch=False,
        )
        assert result["score"] == 20
        assert result["level"] == "LOW"

    def test_medium_risk(self):
        result = generate_risk_score(
            has_double_extension=True,
            entropy=7.8,
            suspicious_strings=[],
            mime_mismatch=False,
        )
        assert result["score"] == 50
        assert result["level"] == "MEDIUM"

    def test_high_risk(self):
        result = generate_risk_score(
            has_double_extension=True,
            entropy=7.8,
            suspicious_strings=["eval("],
            mime_mismatch=True,
        )
        assert result["score"] == 115
        assert result["level"] == "HIGH"

    def test_mime_mismatch_alone(self):
        result = generate_risk_score(
            has_double_extension=False,
            entropy=3.0,
            suspicious_strings=[],
            mime_mismatch=True,
        )
        assert result["score"] == 40
        assert result["level"] == "MEDIUM"


class TestAnalyseFile:
    def test_clean_text_file(self):
        result = analyse_file(
            filename="readme.txt",
            file_bytes=b"This is a simple readme file with nothing suspicious.",
            declared_content_type="text/plain",
        )
        assert result["risk_level"] == "LOW"
        assert result["risk_score"] == 0
        assert result["mime_type"] == "text/plain"
        assert len(result["hashes"]["sha256"]) == 64

    def test_suspicious_script(self):
        payload = b"#!/bin/bash\neval('malicious')\nsubprocess.call('rm -rf /')"
        result = analyse_file(
            filename="script.sh",
            file_bytes=payload,
            declared_content_type="text/plain",
        )
        assert result["risk_score"] > 0
        assert len(result["suspicious_indicators"]) > 0


from app.models.database import init_db
init_db()

client = TestClient(app)


class TestAPI:
    def test_health_check(self):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_upload_text_file(self):
        content = b"Just a normal text file with no malware."
        resp = client.post(
            "/api/v1/analyze",
            files={"file": ("test.txt", content, "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["filename"] == "test.txt"
        assert data["risk_level"] == "LOW"
        assert "md5" in data["hashes"]

    def test_upload_empty_file(self):
        resp = client.post(
            "/api/v1/analyze",
            files={"file": ("empty.txt", b"", "text/plain")},
        )
        assert resp.status_code == 400

    def test_upload_suspicious_file(self):
        payload = b"<?php eval(cmd); subprocess os.system('cmd.exe /c dir')"
        resp = client.post(
            "/api/v1/analyze",
            files={"file": ("payload.php.exe", payload, "application/pdf")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("MEDIUM", "HIGH")
        assert data["risk_score"] > 30

    def test_history_endpoint(self):
        resp = client.get("/api/v1/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
