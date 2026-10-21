"""The TLS artifacts are documentation-adjacent, so keep them executable and honest."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "tls" / "make-certs.sh"
CONF = REPO / "deploy" / "tls" / "edge-tls.conf"
COMPOSE = REPO / "deploy" / "tls" / "docker-compose.edge-tls.yml"

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


def _run(out: Path, *args: str) -> None:
    subprocess.run(
        ["sh", str(SCRIPT), "--out", str(out), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_make_certs_covers_a_dns_name_and_an_ip(tmp_path):
    _run(tmp_path, "--name", "trellis.internal", "--ip", "10.0.0.41")

    cert = (tmp_path / "cert.pem").read_bytes()
    san = subprocess.run(
        ["openssl", "x509", "-in", str(tmp_path / "cert.pem"), "-noout", "-ext", "subjectAltName"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "DNS:trellis.internal" in san
    assert "IP Address:10.0.0.41" in san
    assert cert

    verify = subprocess.run(
        ["openssl", "verify", "-CAfile", str(tmp_path / "ca.pem"), str(tmp_path / "cert.pem")],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr

    # Keys stay private; the CA and leaf are readable.
    assert os.stat(tmp_path / "key.pem").st_mode & 0o077 == 0
    assert os.stat(tmp_path / "ca.key").st_mode & 0o077 == 0


def test_make_certs_requires_a_dial_target(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        _run(tmp_path)


def test_make_certs_refuses_to_overwrite_without_force(tmp_path):
    _run(tmp_path, "--name", "trellis.internal")
    with pytest.raises(subprocess.CalledProcessError):
        _run(tmp_path, "--name", "trellis.internal")


def test_the_terminator_artifacts_stay_linked():
    """The compose example must mount a file that exists, or it starts and dies."""
    text = COMPOSE.read_text()
    assert "./deploy/tls/edge-tls.conf:/etc/nginx/conf.d/default.conf:ro" in text
    assert "nginx-gateway:80" in CONF.read_text()
    assert "listen 8443 ssl" in CONF.read_text()
