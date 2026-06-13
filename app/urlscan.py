from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.settings import Settings
from app.url_safety import UrlValidationError, validate_public_url


URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
PHISHING_QUERY = 'task.tags:"phishing"'


class UrlscanError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 503, retry_after: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


@dataclass(frozen=True)
class UrlscanCandidate:
    scan_id: str | None
    submitted_url: str
    page_url: str | None
    result_url: str | None
    raw_result: dict[str, Any]

    def dataset_metadata(self) -> dict[str, Any]:
        return {
            "kind": "urlscan_phishing",
            "urlscan": {
                "scan_id": self.scan_id,
                "submitted_url": self.submitted_url,
                "page_url": self.page_url,
                "result_url": self.result_url,
                "search_result": self.raw_result,
            },
        }


@dataclass(frozen=True)
class UrlscanSearchPage:
    candidates: list[UrlscanCandidate]
    search_after: str | None
    has_more: bool


def _search_after_value(value: Any) -> str | None:
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    if value is None:
        return None
    return str(value)


def _candidate_from_result(result: Any, settings: Settings) -> UrlscanCandidate | None:
    if not isinstance(result, dict):
        return None
    task = result.get("task") if isinstance(result.get("task"), dict) else {}
    page = result.get("page") if isinstance(result.get("page"), dict) else {}
    raw_url = task.get("url") or page.get("url")
    if not raw_url:
        return None
    try:
        submitted_url = validate_public_url(str(raw_url), allow_private=settings.allow_private_urls)
    except UrlValidationError:
        return None
    page_url = page.get("url")
    scan_id = result.get("_id") or task.get("uuid")
    result_url = result.get("result")
    return UrlscanCandidate(
        scan_id=str(scan_id) if scan_id else None,
        submitted_url=submitted_url,
        page_url=str(page_url) if page_url else None,
        result_url=str(result_url) if result_url else None,
        raw_result=result,
    )


def search_phishing_candidate_page(settings: Settings, *, search_after: str | None = None) -> UrlscanSearchPage:
    if not settings.urlscan_api_key:
        raise UrlscanError("URLSCAN_API_KEY is not configured", status_code=503)

    headers = {
        "api-key": settings.urlscan_api_key,
        "user-agent": "PhishTrain/0.1 dataset-curation",
    }
    params = {"q": PHISHING_QUERY, "size": str(settings.urlscan_search_size)}
    if search_after:
        params["search_after"] = search_after

    try:
        with httpx.Client(headers=headers, follow_redirects=True, timeout=15.0) as client:
            response = client.get(URLSCAN_SEARCH_URL, params=params)
    except httpx.HTTPError as exc:
        raise UrlscanError(f"URLScan search request failed: {exc}", status_code=502) from exc

    if response.status_code == 429:
        raise UrlscanError(
            "URLScan search rate limit exceeded",
            status_code=429,
            retry_after=response.headers.get("x-rate-limit-reset-after") or response.headers.get("retry-after"),
        )
    if response.status_code >= 400:
        detail = response.text[:500]
        raise UrlscanError(f"URLScan search failed with HTTP {response.status_code}: {detail}", status_code=502)

    payload = response.json()
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not results:
        return UrlscanSearchPage(candidates=[], search_after=None, has_more=False)

    candidates = [candidate for result in results if (candidate := _candidate_from_result(result, settings))]
    next_search_after = _search_after_value(results[-1].get("sort") if isinstance(results[-1], dict) else None)
    return UrlscanSearchPage(candidates=candidates, search_after=next_search_after, has_more=bool(payload.get("has_more")) and bool(next_search_after))


def search_phishing_candidates(settings: Settings, *, needed: int) -> list[UrlscanCandidate]:
    candidates: list[UrlscanCandidate] = []
    search_after = None
    for _ in range(settings.dataset_refill_max_pages):
        page = search_phishing_candidate_page(settings, search_after=search_after)
        candidates.extend(page.candidates)
        if len(candidates) >= needed:
            return candidates[:needed]
        if not page.has_more:
            break
        search_after = page.search_after
    return candidates
