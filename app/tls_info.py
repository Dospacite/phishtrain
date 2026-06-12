from __future__ import annotations

import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509


def _empty() -> dict[str, Any]:
    return {"enabled": False, "issuer": None, "subject": None}


def get_tls_info(url: str, timeout_seconds: float = 3.0) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return _empty()

    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, port), timeout=max(0.5, timeout_seconds)) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                cert_bytes = tls_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_bytes)
        return {
            "enabled": True,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
        }
    except Exception:
        return _empty()

