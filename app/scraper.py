from __future__ import annotations

import hashlib
import io
import time
from dataclasses import dataclass
from email.message import Message
from email.parser import HeaderParser
from typing import Any

from PIL import Image

from app.extractors import extract_download_candidates, format_observed_downloads
from app.models import utc_now
from app.rdap import lookup_rdap_whois_raw
from app.settings import Settings
from app.tls_info import get_tls_info
from app.url_safety import cache_key_for_url


@dataclass
class ScrapeArtifact:
    raw_doc: dict[str, Any]
    screenshot_webp: bytes | None = None
    screenshot_metadata: dict[str, Any] | None = None
    rendered_html: str = ""


def _remaining_seconds(deadline: float, default: float = 1.0) -> float:
    return max(0.25, min(default, deadline - time.monotonic()))


def _headers_to_dict(headers: Any) -> dict[str, str | list[str]]:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(key).lower(): value for key, value in headers.items()}
    return {}


def _response_url(response: Any, fallback: str) -> str:
    for attr in ("url", "final_url"):
        value = getattr(response, attr, None)
        if value:
            return str(value)
    return fallback


def _redirect_chain(response: Any, submitted_url: str, final_url: str) -> list[str]:
    chain = [submitted_url]
    for item in getattr(response, "history", []) or []:
        url = getattr(item, "url", None)
        if url and str(url) not in chain:
            chain.append(str(url))
    if final_url not in chain:
        chain.append(final_url)
    return chain


def _body_to_html(response: Any) -> str:
    body = getattr(response, "body", b"")
    if isinstance(body, str):
        return body
    encoding = getattr(response, "encoding", None) or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except Exception:
        return body.decode("utf-8", errors="replace")


def _content_disposition_filename(header: str | None) -> str | None:
    if not header:
        return None
    parser = HeaderParser()
    message: Message = parser.parsestr(f"Content-Disposition: {header}\n")
    return message.get_filename()


def _observed_from_response(response: Any) -> dict[str, str | None] | None:
    try:
        headers = response.headers
        disposition = headers.get("content-disposition")
        content_type = headers.get("content-type")
        url = response.url
    except Exception:
        return None
    if not disposition and content_type not in {"application/octet-stream", "application/zip", "application/x-msdownload"}:
        return None
    return {"url": url, "filename": _content_disposition_filename(disposition), "content_type": content_type}


def _convert_png_to_webp(png_bytes: bytes) -> tuple[bytes, dict[str, Any]]:
    with Image.open(io.BytesIO(png_bytes)) as image:
        output = io.BytesIO()
        if image.mode not in {"RGB", "RGBA"}:
            image = image.convert("RGB")
        image.save(output, format="WEBP", quality=82, method=4)
        data = output.getvalue()
        return data, {"width": image.width, "height": image.height, "sha256": hashlib.sha256(data).hexdigest()}


def scrape_url(
    submitted_url: str,
    settings: Settings,
    *,
    wait_ms: int | None = None,
    timeout_ms: int | None = None,
    capture_screenshot: bool = True,
) -> ScrapeArtifact:
    from scrapling.fetchers import StealthyFetcher

    effective_wait_ms = settings.scrape_wait_ms if wait_ms is None else wait_ms
    effective_timeout_ms = settings.scrape_url_timeout_ms if timeout_ms is None else timeout_ms
    effective_browser_timeout_ms = max(1_000, effective_timeout_ms - effective_wait_ms)
    deadline = time.monotonic() + (effective_timeout_ms / 1000)
    captured: dict[str, Any] = {"observed_downloads": []}

    def page_setup(page: Any) -> None:
        def on_download(download: Any) -> None:
            captured["observed_downloads"].append(
                {
                    "url": getattr(download, "url", None),
                    "filename": getattr(download, "suggested_filename", None),
                    "content_type": None,
                }
            )

        def on_response(response: Any) -> None:
            observed = _observed_from_response(response)
            if observed:
                captured["observed_downloads"].append(observed)

        page.on("download", on_download)
        page.on("response", on_response)

    def page_action(page: Any) -> None:
        try:
            page.set_viewport_size({"width": settings.screenshot_width, "height": settings.screenshot_height})
        except Exception:
            pass
        page.wait_for_timeout(effective_wait_ms)
        captured["title"] = page.title()
        try:
            captured["visible_text"] = page.locator("body").inner_text(timeout=1_000)
        except Exception:
            captured["visible_text"] = ""
        try:
            captured["html"] = page.content()
        except Exception:
            captured["html"] = ""
        if capture_screenshot:
            captured["screenshot_png"] = page.screenshot(type="png", full_page=False, scale="css")

    page = StealthyFetcher.fetch(
        submitted_url,
        headless=True,
        disable_resources=False,
        block_webrtc=True,
        hide_canvas=True,
        load_dom=True,
        network_idle=False,
        timeout=effective_browser_timeout_ms,
        wait=0,
        page_setup=page_setup,
        page_action=page_action,
    )

    final_url = _response_url(page, submitted_url)
    html = captured.get("html") or _body_to_html(page)
    visible_text = captured.get("visible_text") or ""
    title = captured.get("title") or ""

    redirect_chain = _redirect_chain(page, submitted_url, final_url)
    headers = _headers_to_dict(getattr(page, "headers", {}))
    tls = get_tls_info(final_url, timeout_seconds=_remaining_seconds(deadline, 2.0))
    rdap_whois = lookup_rdap_whois_raw(final_url, timeout_seconds=_remaining_seconds(deadline, 3.0))
    downloads = {
        "candidates": extract_download_candidates(html, final_url),
        "observed": format_observed_downloads(captured.get("observed_downloads", [])),
    }

    screenshot_webp = None
    screenshot_metadata = None
    if captured.get("screenshot_png"):
        screenshot_webp, screenshot_metadata = _convert_png_to_webp(captured["screenshot_png"])

    raw_doc = {
        "submitted_url": submitted_url,
        "final_url": final_url,
        "cache_key": cache_key_for_url(submitted_url),
        "status": "ok",
        "rdap_whois": rdap_whois,
        "html": html,
        "downloads": downloads,
        "metadata": {
            "redirect_chain": redirect_chain,
            "headers": headers,
            "tls": tls,
            "title": title,
            "visible_text": visible_text,
            "html_size_bytes": len(html.encode("utf-8", errors="replace")),
            "html_sha256": hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest(),
            "viewport": {"width": settings.screenshot_width, "height": settings.screenshot_height},
            "scraper": {
                "library": "scrapling",
                "mode": "stealth",
                "wait_ms": effective_wait_ms,
                "timeout_ms": effective_timeout_ms,
            },
        },
        "fetched_at": utc_now(),
    }
    return ScrapeArtifact(
        raw_doc=raw_doc,
        screenshot_webp=screenshot_webp,
        screenshot_metadata=screenshot_metadata,
        rendered_html=html,
    )
