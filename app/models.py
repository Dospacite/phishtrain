from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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


class JobHandle(BaseModel):
    job_id: str
    status: str
    cache_hit: bool
    result_url: str
