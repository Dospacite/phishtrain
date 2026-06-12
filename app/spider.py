from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import tldextract
from bs4 import BeautifulSoup, Tag

from app.settings import Settings
from app.url_safety import UrlValidationError, cache_key_for_url, validate_public_url


TARGET_CATEGORY_TERMS: dict[str, tuple[str, ...]] = {
    "authentication": (
        "login",
        "log in",
        "signin",
        "sign in",
        "sso",
        "mfa",
        "2fa",
        "password",
        "reset password",
        "email login",
    ),
    "payment": (
        "checkout",
        "card",
        "credit card",
        "billing",
        "fee",
        "payment",
        "confirmation",
        "cvv",
    ),
    "download": (
        "download",
        "installer",
        "install",
        "update",
        "invoice",
        "archive",
        "document",
        "setup",
        "executable",
    ),
    "document_or_file_access": (
        "pdf",
        "viewer",
        "shared document",
        "cloud file",
        "file access",
        "voicemail",
        "fax",
        "document portal",
    ),
    "account_security": (
        "locked",
        "suspicious",
        "verify",
        "identity",
        "recovery",
        "account security",
    ),
    "personal_information_collection": (
        "name",
        "address",
        "phone",
        "id",
        "date of birth",
        "dob",
        "personal information",
        "profile",
    ),
    "financial_or_banking": (
        "bank",
        "banking",
        "investment",
        "tax refund",
        "payroll",
        "invoice payment",
        "finance",
    ),
    "crypto_or_wallet": (
        "crypto",
        "wallet",
        "seed phrase",
        "recovery phrase",
        "wallet connect",
        "walletconnect",
        "exchange",
        "transaction",
    ),
    "delivery_or_order": (
        "delivery",
        "shipping",
        "tracking",
        "failed delivery",
        "order",
        "order confirmation",
    ),
    "support_or_remote_access": (
        "support",
        "tech support",
        "live chat",
        "remote access",
        "remote support",
        "anydesk",
        "teamviewer",
    ),
    "consent_or_authorization": (
        "oauth",
        "consent",
        "authorize",
        "authorization",
        "permission",
        "grant",
        "app authorization",
    ),
    "interstitial_or_gate": (
        "captcha",
        "hcaptcha",
        "recaptcha",
        "age gate",
        "anti bot",
        "anti-bot",
        "continue to view",
        "verify you are human",
    ),
}


DICTIONARY_PATHS: tuple[str, ...] = (
    "/login",
    "/log-in",
    "/signin",
    "/sign-in",
    "/sso",
    "/mfa",
    "/2fa",
    "/password-reset",
    "/forgot-password",
    "/checkout",
    "/payment",
    "/payments",
    "/billing",
    "/pay",
    "/card",
    "/download",
    "/downloads",
    "/install",
    "/installer",
    "/update",
    "/invoice",
    "/invoices",
    "/archive",
    "/document",
    "/documents",
    "/file",
    "/files",
    "/pdf",
    "/viewer",
    "/shared",
    "/portal",
    "/voicemail",
    "/fax",
    "/verify",
    "/verify-identity",
    "/identity",
    "/recovery",
    "/account-recovery",
    "/security",
    "/account-security",
    "/profile",
    "/personal-information",
    "/bank",
    "/banking",
    "/finance",
    "/investment",
    "/tax-refund",
    "/payroll",
    "/wallet",
    "/wallet-connect",
    "/walletconnect",
    "/crypto",
    "/exchange",
    "/transaction",
    "/delivery",
    "/shipping",
    "/tracking",
    "/track",
    "/order",
    "/orders",
    "/support",
    "/chat",
    "/live-chat",
    "/remote-support",
    "/remote-access",
    "/authorize",
    "/authorization",
    "/oauth",
    "/consent",
    "/permissions",
    "/captcha",
    "/continue",
    "/continue-to-view",
    "/age-gate",
)


URLISH_RE = re.compile(
    r"""(?:https?://[^\s"'<>\\]+|/[^\s"'<>\\]+|(?:[A-Za-z0-9_.~%-]+/)+[A-Za-z0-9_.~%/?#=&:-]*)"""
)
META_REFRESH_URL_RE = re.compile(r"url\s*=\s*([^;]+)", re.IGNORECASE)
TOKEN_RE = re.compile(r"[a-z0-9]+")
INLINE_EVENT_ATTRS = ("onclick", "onmousedown", "onpointerdown")
DATA_URL_ATTRS = ("data-href", "data-url", "data-target")


@dataclass
class SpiderCandidate:
    url: str
    score: int = 0
    sources: set[str] = field(default_factory=set)


def _registered_domain(host: str | None) -> str | None:
    if not host:
        return None
    extracted = tldextract.extract(host)
    return getattr(extracted, "top_domain_under_public_suffix", None) or getattr(extracted, "registered_domain", None)


def _same_site(url: str, seed_url: str) -> bool:
    parsed = urlsplit(url)
    seed = urlsplit(seed_url)
    if not parsed.hostname or not seed.hostname:
        return False
    url_domain = _registered_domain(parsed.hostname)
    seed_domain = _registered_domain(seed.hostname)
    if url_domain and seed_domain:
        return url_domain == seed_domain
    return parsed.hostname.lower() == seed.hostname.lower()


def _text_for_tag(tag: Tag) -> str:
    parts = [
        tag.get_text(" ", strip=True),
        tag.get("value", ""),
        tag.get("aria-label", ""),
        tag.get("title", ""),
        tag.get("alt", ""),
        tag.get("name", ""),
        tag.get("id", ""),
        " ".join(str(item) for item in tag.get("class", []) if item),
    ]
    return " ".join(part for part in parts if part).strip()


def _term_score(haystack: str) -> int:
    lowered = haystack.lower()
    score = 0
    for terms in TARGET_CATEGORY_TERMS.values():
        for term in terms:
            if term in lowered:
                score += 3 if "/" in haystack or "-" in haystack or "_" in haystack else 2
    return score


def _token_score(url: str) -> int:
    path = " ".join(TOKEN_RE.findall(urlsplit(url).path.lower()))
    query = " ".join(TOKEN_RE.findall(urlsplit(url).query.lower()))
    return _term_score(f"{path} {query}")


def _add_candidate(
    candidates: dict[str, SpiderCandidate],
    raw_url: str | None,
    *,
    base_url: str,
    seed_url: str,
    allow_private: bool,
    source: str,
    context: str = "",
) -> None:
    if not raw_url:
        return
    value = raw_url.strip().strip("\"'")
    if not value or value.startswith("#"):
        return
    scheme = urlsplit(value).scheme.lower()
    if scheme and scheme not in {"http", "https"}:
        return

    absolute = urljoin(base_url, value)
    try:
        normalized = validate_public_url(absolute, allow_private=allow_private)
    except UrlValidationError:
        return
    normalized = cache_key_for_url(normalized)
    if not _same_site(normalized, seed_url):
        return

    candidate = candidates.setdefault(normalized, SpiderCandidate(url=normalized))
    candidate.sources.add(source)
    candidate.score = max(candidate.score, _token_score(normalized) + _term_score(context))


def _extract_urlish_values(value: str) -> list[str]:
    return [match.group(0).rstrip(").,;") for match in URLISH_RE.finditer(value or "")]


def _add_tag_attr_candidate(
    candidates: dict[str, SpiderCandidate],
    tag: Tag,
    attr: str,
    *,
    base_url: str,
    seed_url: str,
    allow_private: bool,
    source: str,
) -> None:
    value = tag.get(attr)
    if not isinstance(value, str):
        return
    _add_candidate(
        candidates,
        value,
        base_url=base_url,
        seed_url=seed_url,
        allow_private=allow_private,
        source=source,
        context=_text_for_tag(tag),
    )


def discover_spider_candidates(html: str, seed_url: str, final_url: str, settings: Settings) -> list[SpiderCandidate]:
    soup = BeautifulSoup(html or "", "html.parser")
    candidates: dict[str, SpiderCandidate] = {}

    for anchor in soup.find_all("a"):
        _add_tag_attr_candidate(
            candidates,
            anchor,
            "href",
            base_url=final_url,
            seed_url=seed_url,
            allow_private=settings.allow_private_urls,
            source="link_href",
        )

    for form in soup.find_all("form"):
        _add_tag_attr_candidate(
            candidates,
            form,
            "action",
            base_url=final_url,
            seed_url=seed_url,
            allow_private=settings.allow_private_urls,
            source="form_action",
        )

    for iframe in soup.find_all("iframe"):
        _add_tag_attr_candidate(
            candidates,
            iframe,
            "src",
            base_url=final_url,
            seed_url=seed_url,
            allow_private=settings.allow_private_urls,
            source="iframe_src",
        )

    for tag in soup.find_all(True):
        if not isinstance(tag, Tag):
            continue
        context = _text_for_tag(tag)
        for attr in DATA_URL_ATTRS:
            _add_tag_attr_candidate(
                candidates,
                tag,
                attr,
                base_url=final_url,
                seed_url=seed_url,
                allow_private=settings.allow_private_urls,
                source=attr.replace("-", "_"),
            )
        for attr in INLINE_EVENT_ATTRS:
            value = tag.get(attr)
            if not isinstance(value, str):
                continue
            for found in _extract_urlish_values(value):
                _add_candidate(
                    candidates,
                    found,
                    base_url=final_url,
                    seed_url=seed_url,
                    allow_private=settings.allow_private_urls,
                    source="inline_event",
                    context=context,
                )

    for meta in soup.find_all("meta"):
        http_equiv = str(meta.get("http-equiv", "")).lower()
        if http_equiv != "refresh":
            continue
        content = meta.get("content")
        if not isinstance(content, str):
            continue
        match = META_REFRESH_URL_RE.search(content)
        if match:
            _add_candidate(
                candidates,
                match.group(1),
                base_url=final_url,
                seed_url=seed_url,
                allow_private=settings.allow_private_urls,
                source="meta_refresh",
                context=content,
            )

    origin = f"{urlsplit(seed_url).scheme}://{urlsplit(seed_url).netloc}"
    for path in DICTIONARY_PATHS:
        _add_candidate(
            candidates,
            path,
            base_url=origin,
            seed_url=seed_url,
            allow_private=settings.allow_private_urls,
            source="directory",
            context=path,
        )

    seed_key = cache_key_for_url(seed_url)
    filtered = [candidate for candidate in candidates.values() if candidate.url != seed_key]
    filtered.sort(key=lambda item: (item.sources != {"directory"}, item.score, item.url), reverse=True)
    return filtered[: settings.spider_candidate_limit]


def selected_spider_child_urls(html: str, seed_url: str, final_url: str, settings: Settings) -> list[str]:
    candidates = discover_spider_candidates(html, seed_url, final_url, settings)
    return [candidate.url for candidate in candidates[: settings.spider_max_child_pages]]


def candidate_sources(candidate: SpiderCandidate) -> list[str]:
    return sorted(candidate.sources)
