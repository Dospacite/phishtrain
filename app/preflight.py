from __future__ import annotations

import asyncio
from typing import Any, Literal

import aiohttp
from rq import Queue

from app.jobs import create_or_enqueue_scrape_job, create_or_enqueue_spider_job, handle_for_job, make_job_id, spider_cache_key_for_url
from app.models import JOB_QUEUED, JOB_SUCCEEDED, JobHandle
from app.queue import get_queue
from app.settings import Settings, get_settings
from app.storage import MongoStorage
from app.url_safety import cache_key_for_url


PreflightMode = Literal["scrape", "spider"]


def _target_cache_key(mode: PreflightMode, submitted_url: str) -> str:
    if mode == "spider":
        return spider_cache_key_for_url(submitted_url)
    return cache_key_for_url(submitted_url)


async def _attempt_connect(submitted_url: str, settings: Settings) -> str | None:
    timeout = aiohttp.ClientTimeout(total=settings.preflight_timeout_seconds, connect=settings.preflight_timeout_seconds)
    headers = {"user-agent": "PhishTrain/0.1 preflight"}
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(submitted_url, allow_redirects=True) as response:
                await response.content.read(1)
                return None
    except Exception as exc:
        return str(exc)


def create_or_enqueue_preflight_job(
    *,
    submitted_url: str,
    mode: PreflightMode,
    force_new: bool,
    storage: MongoStorage,
    queue: Queue,
    settings: Settings,
    dataset: dict[str, Any] | None = None,
) -> JobHandle:
    target_cache_key = _target_cache_key(mode, submitted_url)
    job_id = make_job_id()

    if not force_new:
        cached = storage.find_latest_successful(target_cache_key)
        if cached:
            storage.create_job(
                job_id=job_id,
                submitted_url=submitted_url,
                cache_key=target_cache_key,
                status=JOB_SUCCEEDED,
                cache_hit=True,
                raw_id=cached["_id"],
                dataset=dataset,
            )
            return handle_for_job(job_id, JOB_SUCCEEDED, True)

    storage.create_job(
        job_id=job_id,
        submitted_url=submitted_url,
        cache_key=f"preflight:{mode}:{target_cache_key}",
        status=JOB_QUEUED,
        cache_hit=False,
        preflight={
            "mode": mode,
            "target_cache_key": target_cache_key,
            "force_new": force_new,
            "dataset": dataset or None,
        },
    )
    try:
        queue.enqueue(
            run_preflight_job,
            job_id,
            job_timeout=max(settings.preflight_timeout_seconds + 15, 30),
            retry=None,
            result_ttl=0,
            failure_ttl=0,
        )
    except Exception:
        storage.delete_job(job_id)
        raise
    return handle_for_job(job_id, JOB_QUEUED, False)


def _handle_document(handle: JobHandle) -> dict[str, Any]:
    if hasattr(handle, "model_dump"):
        return handle.model_dump()
    return handle.dict()


def run_preflight_job(job_id: str) -> str:
    settings = get_settings()
    storage = MongoStorage(settings)
    storage.ensure_indexes()
    job = storage.get_job(job_id)
    if not job:
        return "missing"

    preflight = job.get("preflight") if isinstance(job.get("preflight"), dict) else {}
    mode = preflight.get("mode")
    if mode not in {"scrape", "spider"}:
        storage.mark_job_failed(job_id, "Invalid preflight mode")
        return "failed"

    storage.mark_job_running(job_id)
    error = asyncio.run(_attempt_connect(job["submitted_url"], settings))
    if error:
        storage.mark_job_failed(job_id, f"Preflight connection failed: {error}")
        return "rejected"

    main_queue = get_queue(settings)
    dataset = preflight.get("dataset") if isinstance(preflight.get("dataset"), dict) else None
    force_new = bool(preflight.get("force_new"))
    if mode == "scrape":
        handle = create_or_enqueue_scrape_job(
            submitted_url=job["submitted_url"],
            force_new=force_new,
            storage=storage,
            queue=main_queue,
            settings=settings,
            dataset=dataset,
        )
    else:
        handle = create_or_enqueue_spider_job(
            submitted_url=job["submitted_url"],
            force_new=force_new,
            storage=storage,
            queue=main_queue,
            settings=settings,
        )
    storage.mark_preflight_succeeded(job_id, _handle_document(handle))
    return "accepted"
