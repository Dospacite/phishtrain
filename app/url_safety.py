from __future__ import annotations

import ipaddress
import socket
from urllib.parse import quote, unquote, urldefrag, urlsplit, urlunsplit


class UrlValidationError(ValueError):
    pass


def normalize_url(raw_url: str) -> str:
    stripped = raw_url.strip()
    if not stripped:
        raise UrlValidationError("URL is required")

    parsed = urlsplit(stripped)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UrlValidationError("Only http and https URLs are supported")
    if not parsed.hostname:
        raise UrlValidationError("URL must include a hostname")

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = hostname if port is None else f"{hostname}:{port}"
    if parsed.username or parsed.password:
        raise UrlValidationError("Credentials in URLs are not supported")

    path = quote(unquote(parsed.path or "/"), safe="/:@!$&'()*+,;=-._~%")
    normalized = urlunsplit((scheme, netloc, path, parsed.query, ""))
    return normalized


def cache_key_for_url(url: str) -> str:
    return urldefrag(normalize_url(url)).url


def _is_disallowed_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def validate_public_url(url: str, allow_private: bool = False) -> str:
    normalized = normalize_url(url)
    if allow_private:
        return normalized

    parsed = urlsplit(normalized)
    host = parsed.hostname
    if not host:
        raise UrlValidationError("URL must include a hostname")
    if host.lower() == "localhost":
        raise UrlValidationError("Private and localhost URLs are not allowed")

    try:
        host_is_disallowed = _is_disallowed_ip(host)
    except ValueError:
        host_is_disallowed = False
    if host_is_disallowed:
        raise UrlValidationError("Private and localhost URLs are not allowed")

    try:
        address_infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        return normalized

    for info in address_infos:
        address = info[4][0]
        try:
            address_is_disallowed = _is_disallowed_ip(address)
        except ValueError:
            continue
        if address_is_disallowed:
            raise UrlValidationError("Private and localhost URLs are not allowed")

    return normalized
