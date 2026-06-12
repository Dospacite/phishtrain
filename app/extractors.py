from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from bs4 import BeautifulSoup, Tag


FILE_EXTENSIONS = {
    ".7z",
    ".apk",
    ".bat",
    ".bin",
    ".cab",
    ".cmd",
    ".deb",
    ".dmg",
    ".doc",
    ".docm",
    ".docx",
    ".exe",
    ".iso",
    ".jar",
    ".js",
    ".msi",
    ".pdf",
    ".pkg",
    ".ppt",
    ".pptm",
    ".pptx",
    ".ps1",
    ".rar",
    ".rpm",
    ".rtf",
    ".scr",
    ".tar",
    ".vbs",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".zip",
}
DOWNLOAD_TEXT_RE = re.compile(
    r"\b(download|install|update|get\s+file|invoice|document|export|save|setup|"
    r"statement|receipt|attachment|open\s+file)\b",
    re.IGNORECASE,
)
DOWNLOAD_ENDPOINT_RE = re.compile(r"(^|[/_-])(download|export|get-?file|file|invoice|document)([/_.-]|$)", re.IGNORECASE)
INLINE_EVENT_ATTRS = {"onclick", "onmousedown", "onpointerdown"}


@dataclass(frozen=True)
class ScreenshotImage:
    data: bytes
    width: int
    height: int


def _raw_tag(tag: Tag) -> str:
    return " ".join(str(tag).split())


def _text_for_tag(tag: Tag) -> str:
    parts = [
        tag.get_text(" ", strip=True),
        tag.get("value", ""),
        tag.get("aria-label", ""),
        tag.get("title", ""),
        tag.get("alt", ""),
    ]
    return " ".join(part for part in parts if part).strip()


def _absolute_url(value: str | None, base_url: str) -> str:
    if not value:
        return ""
    return urljoin(base_url, value)


def _path_has_file_extension(url: str | None) -> bool:
    if not url:
        return False
    path = unquote(urlsplit(url).path).lower()
    return any(path.endswith(ext) for ext in FILE_EXTENSIONS)


def _looks_like_download_endpoint(url: str | None) -> bool:
    if not url:
        return False
    path = unquote(urlsplit(url).path)
    return _path_has_file_extension(url) or bool(DOWNLOAD_ENDPOINT_RE.search(path))


def _text_suggests_download(text: str) -> bool:
    return bool(text and DOWNLOAD_TEXT_RE.search(text))


def _has_inline_event(tag: Tag) -> bool:
    return any(attr in tag.attrs for attr in INLINE_EVENT_ATTRS)


def _candidate(text: str, url: str, tag: Tag) -> dict[str, str]:
    return {"text": text[:500], "url": url, "html": _raw_tag(tag)[:2_000]}


def _dedupe(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for item in items:
        key = (item.get("text", ""), item.get("url", ""), item.get("html", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def extract_download_candidates(html: str, base_url: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html or "", "html.parser")
    candidates: list[dict[str, str]] = []

    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        absolute = _absolute_url(href, base_url)
        text = _text_for_tag(anchor)
        raw_html = _raw_tag(anchor)
        if (
            anchor.has_attr("download")
            or _path_has_file_extension(absolute)
            or _text_suggests_download(text)
            or (_has_inline_event(anchor) and (_text_suggests_download(text) or _looks_like_download_endpoint(raw_html)))
        ):
            candidates.append(_candidate(text, absolute, anchor))

    for tag in soup.find_all(["button", "input"]):
        text = _text_for_tag(tag)
        raw_html = _raw_tag(tag)
        if _text_suggests_download(text) or (
            _has_inline_event(tag) and (_text_suggests_download(text) or _looks_like_download_endpoint(raw_html))
        ):
            candidates.append(_candidate(text, _absolute_url(tag.get("formaction"), base_url), tag))

    for form in soup.find_all("form"):
        action = _absolute_url(form.get("action"), base_url)
        text = _text_for_tag(form)
        raw_html = _raw_tag(form)
        if _looks_like_download_endpoint(action) or _text_suggests_download(text) or (
            _has_inline_event(form) and (_text_suggests_download(text) or _looks_like_download_endpoint(raw_html))
        ):
            candidates.append(_candidate(text, action, form))

    return _dedupe(candidates)


def _raw_tags(soup: BeautifulSoup, names: str | list[str]) -> list[str]:
    return [_raw_tag(tag) for tag in soup.find_all(names)]


def extract_html_artifacts(html: str, base_url: str, visible_text: str = "", title: str = "") -> dict[str, Any]:
    soup = BeautifulSoup(html or "", "html.parser")
    resolved_title = title or ""
    if not resolved_title and soup.title and soup.title.string:
        resolved_title = soup.title.string.strip()

    if not visible_text:
        body = soup.body or soup
        visible_text = body.get_text("\n", strip=True)

    return {
        "title": resolved_title,
        "meta": _raw_tags(soup, "meta"),
        "forms": _raw_tags(soup, "form"),
        "inputs": _raw_tags(soup, "input"),
        "anchors": _raw_tags(soup, "a"),
        "buttons": _raw_tags(soup, "button"),
        "iframes": _raw_tags(soup, "iframe"),
        "images": _raw_tags(soup, "img"),
        "visible_text": visible_text,
    }


def format_observed_downloads(observed: Iterable[dict[str, Any]]) -> list[dict[str, str | None]]:
    formatted: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, str | None, str | None]] = set()
    for item in observed:
        candidate = {
            "url": item.get("url"),
            "filename": item.get("filename"),
            "content_type": item.get("content_type"),
        }
        key = (candidate["url"], candidate["filename"], candidate["content_type"])
        if key in seen:
            continue
        seen.add(key)
        formatted.append(candidate)
    return formatted

