from __future__ import annotations

from uuid import uuid4

from rq import Queue

from app.models import JOB_QUEUED, JOB_SUCCEEDED, JobHandle
from app.settings import Settings
from app.storage import MongoStorage
from app.url_safety import cache_key_for_url


def make_job_id() -> str:
    return str(uuid4())


def handle_for_job(job_id: str, status: str, cache_hit: bool) -> JobHandle:
    return JobHandle(job_id=job_id, status=status, cache_hit=cache_hit, result_url=f"/jobs/{job_id}/result")


def create_or_enqueue_scrape_job(
    *,
    submitted_url: str,
    force_new: bool,
    storage: MongoStorage,
    queue: Queue,
    settings: Settings,
    dataset: dict | None = None,
) -> JobHandle:
    cache_key = cache_key_for_url(submitted_url)
    job_id = make_job_id()

    if not force_new:
        cached = storage.find_latest_successful(cache_key)
        if cached:
            storage.create_job(
                job_id=job_id,
                submitted_url=submitted_url,
                cache_key=cache_key,
                status=JOB_SUCCEEDED,
                cache_hit=True,
                raw_id=cached["_id"],
                dataset=dataset,
            )
            return handle_for_job(job_id, JOB_SUCCEEDED, True)

    storage.create_job(
        job_id=job_id,
        submitted_url=submitted_url,
        cache_key=cache_key,
        status=JOB_QUEUED,
        cache_hit=False,
        dataset=dataset,
    )
    from app.worker import run_scrape_job

    try:
        queue.enqueue(run_scrape_job, job_id, job_timeout=settings.rq_job_timeout_seconds, retry=None, result_ttl=0, failure_ttl=0)
    except Exception:
        storage.delete_job(job_id)
        raise
    return handle_for_job(job_id, JOB_QUEUED, False)


def spider_cache_key_for_url(submitted_url: str) -> str:
    return f"spider:v1:{cache_key_for_url(submitted_url)}"


def create_or_enqueue_spider_job(
    *,
    submitted_url: str,
    force_new: bool,
    storage: MongoStorage,
    queue: Queue,
    settings: Settings,
) -> JobHandle:
    cache_key = spider_cache_key_for_url(submitted_url)
    job_id = make_job_id()

    if not force_new:
        cached = storage.find_latest_successful(cache_key)
        if cached:
            storage.create_job(
                job_id=job_id,
                submitted_url=submitted_url,
                cache_key=cache_key,
                status=JOB_SUCCEEDED,
                cache_hit=True,
                raw_id=cached["_id"],
            )
            return handle_for_job(job_id, JOB_SUCCEEDED, True)

    storage.create_job(job_id=job_id, submitted_url=submitted_url, cache_key=cache_key, status=JOB_QUEUED, cache_hit=False)
    from app.worker import run_spider_job

    queue.enqueue(run_spider_job, job_id, job_timeout=settings.spider_job_timeout_seconds, retry=None, result_ttl=0, failure_ttl=0)
    return handle_for_job(job_id, JOB_QUEUED, False)
