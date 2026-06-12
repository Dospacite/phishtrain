from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
import tldextract


PRIVACY_TERMS = ("privacy", "proxy", "protect", "redacted", "whoisguard", "domains by proxy")


def _empty() -> dict[str, Any]:
    return {
        "domain_age_days": None,
        "days_since_updated": None,
        "privacy_or_proxy_registration": False,
        "registrar": None,
        "registrant_country": None,
        "statuses": [],
    }


def _registered_domain(url: str) -> str | None:
    host = urlsplit(url).hostname
    if not host:
        return None
    extracted = tldextract.extract(host)
    return getattr(extracted, "top_domain_under_public_suffix", None) or getattr(extracted, "registered_domain", None)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _event_date(data: dict[str, Any], actions: set[str], newest: bool = False) -> datetime | None:
    dates: list[datetime] = []
    for event in data.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action in actions:
            parsed = _parse_datetime(event.get("eventDate"))
            if parsed:
                dates.append(parsed)
    if not dates:
        return None
    return max(dates) if newest else min(dates)


def _vcard_value(entity: dict[str, Any], name: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if not item or item[0] != name:
            continue
        value = item[3]
        if isinstance(value, list):
            flattened = [str(part) for part in value if part]
            return ", ".join(flattened) if flattened else None
        return str(value) if value else None
    return None


def _entity_with_role(data: dict[str, Any], role: str) -> dict[str, Any] | None:
    for entity in data.get("entities", []):
        roles = {str(item).lower() for item in entity.get("roles", [])}
        if role in roles:
            return entity
    return None


def _registrar(data: dict[str, Any]) -> str | None:
    registrar_obj = data.get("registrar")
    if isinstance(registrar_obj, dict) and registrar_obj.get("name"):
        return str(registrar_obj["name"])
    entity = _entity_with_role(data, "registrar")
    if entity:
        return _vcard_value(entity, "fn")
    return None


def _registrant_country(data: dict[str, Any]) -> str | None:
    entity = _entity_with_role(data, "registrant")
    if not entity:
        return None
    country = _vcard_value(entity, "country")
    if country:
        return country
    address = _vcard_value(entity, "adr")
    if address:
        parts = [part.strip() for part in address.split(",") if part.strip()]
        return parts[-1] if parts else None
    return None


def _privacy_flag(data: dict[str, Any]) -> bool:
    haystack = str(data).lower()
    return any(term in haystack for term in PRIVACY_TERMS)


def lookup_rdap_whois_raw(url: str, timeout_seconds: float = 3.0) -> dict[str, Any]:
    domain = _registered_domain(url)
    lookup_url = f"https://rdap.org/domain/{domain}" if domain else None
    if not domain:
        return {"domain": None, "lookup_url": None, "status_code": None, "headers": {}, "raw": None, "error": "no registered domain"}

    try:
        response = httpx.get(
            lookup_url,
            timeout=max(0.5, timeout_seconds),
            follow_redirects=True,
        )
        try:
            data = response.json()
        except Exception:
            data = None
        return {
            "domain": domain,
            "lookup_url": lookup_url,
            "status_code": response.status_code,
            "headers": {str(key).lower(): value for key, value in response.headers.items()},
            "raw": data,
            "error": None if response.is_success else f"HTTP {response.status_code}",
        }
    except Exception as exc:
        return {
            "domain": domain,
            "lookup_url": lookup_url,
            "status_code": None,
            "headers": {},
            "raw": None,
            "error": str(exc)[:2_000],
        }


def summarize_rdap_whois(value: dict[str, Any] | None) -> dict[str, Any]:
    if not value:
        return _empty()
    data = value.get("raw") if isinstance(value.get("raw"), dict) else value
    if not isinstance(data, dict):
        return _empty()

    now = datetime.now(timezone.utc)
    created = _event_date(data, {"registration", "registered"})
    updated = _event_date(
        data,
        {"last changed", "last update of rdap database", "last update", "last modified", "modified"},
        newest=True,
    )

    result = _empty()
    if created:
        result["domain_age_days"] = max(0, (now - created).days)
    if updated:
        result["days_since_updated"] = max(0, (now - updated).days)
    result["privacy_or_proxy_registration"] = _privacy_flag(data)
    result["registrar"] = _registrar(data)
    result["registrant_country"] = _registrant_country(data)
    result["statuses"] = [str(status) for status in data.get("status", [])]
    return result


def lookup_rdap_whois(url: str, timeout_seconds: float = 3.0) -> dict[str, Any]:
    return summarize_rdap_whois(lookup_rdap_whois_raw(url, timeout_seconds=timeout_seconds))
