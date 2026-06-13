from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_SUCCEEDED = "succeeded"
JOB_FAILED = "failed"
JOB_TIMEOUT = "timeout"
JOB_STATUSES = {JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_FAILED, JOB_TIMEOUT}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def empty_format_result(submitted_url: str, final_url: str | None = None) -> dict[str, Any]:
    return {
        "submitted_url": submitted_url,
        "final_url": final_url or submitted_url,
        "redirect_chain": [submitted_url],
        "headers": {},
        "tls": {"enabled": False, "issuer": None, "subject": None},
        "rdap_whois": {
            "domain_age_days": None,
            "days_since_updated": None,
            "privacy_or_proxy_registration": False,
            "registrar": None,
            "registrant_country": None,
            "statuses": [],
        },
        "downloads": {"candidates": [], "observed": []},
        "html": {
            "title": "",
            "meta": [],
            "forms": [],
            "inputs": [],
            "anchors": [],
            "buttons": [],
            "iframes": [],
            "images": [],
            "visible_text": "",
        },
    }


class ScrapeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class SpiderRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class ReferenceSelection(BaseModel):
    pointer: str = Field(min_length=1, max_length=1024)


class CurationBlock(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    references: list[ReferenceSelection] = Field(default_factory=list, max_length=100)


class CuratedDatasetRequest(BaseModel):
    raw_id: str = Field(min_length=1, max_length=128)
    verdict: Literal["phishing", "benign"]
    confidence: float = Field(ge=0, le=1)
    organization_brand: str = Field(min_length=1, max_length=512)
    response_text: str = Field(min_length=1, max_length=50_000)
    blocks: list[CurationBlock] = Field(default_factory=list, max_length=100)


class SkipDatasetRequest(BaseModel):
    raw_id: str = Field(min_length=1, max_length=128)
    reason: str | None = Field(default=None, max_length=2_000)


class JobHandle(BaseModel):
    job_id: str
    status: str
    cache_hit: bool
    result_url: str
