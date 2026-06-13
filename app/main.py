from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from redis import Redis
from rq import Queue

from app.dashboard import create_dashboard_router
from app.jobs import create_or_enqueue_scrape_job, create_or_enqueue_spider_job
from app.models import JOB_FAILED, JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_TIMEOUT, ScrapeRequest, SpiderRequest
from app.queue import get_queue
from app.settings import Settings, get_settings
from app.storage import MongoStorage, project_api_result, serialize_job
from app.url_safety import UrlValidationError, validate_public_url


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        get_storage().ensure_indexes()
    except Exception as exc:
        logger.warning("MongoDB startup initialization failed: %s", exc)
    yield


app = FastAPI(title="PhishTrain Scrape Queue API", version="0.1.0", lifespan=lifespan)


@lru_cache(maxsize=1)
def get_storage() -> MongoStorage:
    settings = get_settings()
    return MongoStorage(settings)


def storage_dep() -> MongoStorage:
    return get_storage()


def queue_dep(settings: Settings = Depends(get_settings)) -> Queue:
    return get_queue(settings)


app.include_router(create_dashboard_router(storage_dep, queue_dep))


@app.post("/scrape")
def scrape(
    payload: ScrapeRequest,
    forceNew: bool = Query(False),
    settings: Settings = Depends(get_settings),
    storage: MongoStorage = Depends(storage_dep),
    queue: Queue = Depends(queue_dep),
):
    try:
        submitted_url = validate_public_url(payload.url, allow_private=settings.allow_private_urls)
    except UrlValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        handle = create_or_enqueue_scrape_job(
            submitted_url=submitted_url,
            force_new=forceNew,
            storage=storage,
            queue=queue,
            settings=settings,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not create scrape job: {exc}") from exc

    return handle


@app.post("/spider")
def spider(
    payload: SpiderRequest,
    forceNew: bool = Query(False),
    settings: Settings = Depends(get_settings),
    storage: MongoStorage = Depends(storage_dep),
    queue: Queue = Depends(queue_dep),
):
    try:
        submitted_url = validate_public_url(payload.url, allow_private=settings.allow_private_urls)
    except UrlValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        handle = create_or_enqueue_spider_job(
            submitted_url=submitted_url,
            force_new=forceNew,
            storage=storage,
            queue=queue,
            settings=settings,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not create spider job: {exc}") from exc

    return handle


@app.get("/jobs/{job_id}")
def get_job(job_id: str, storage: MongoStorage = Depends(storage_dep)):
    job = storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return serialize_job(job)


@app.get("/jobs/{job_id}/result")
def get_job_result(job_id: str, storage: MongoStorage = Depends(storage_dep)):
    job = storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    status = job.get("status")
    if status in {JOB_QUEUED, JOB_RUNNING}:
        return JSONResponse(status_code=202, content=serialize_job(job))
    if status == JOB_TIMEOUT:
        storage.delete_job(job_id)
        raise HTTPException(status_code=504, detail=job.get("error") or "Job timed out")
    if status == JOB_FAILED:
        storage.delete_job(job_id)
        raise HTTPException(status_code=500, detail=job.get("error") or "Job failed")
    if status != JOB_SUCCEEDED:
        storage.delete_job(job_id)
        raise HTTPException(status_code=500, detail="Job is in an unknown state")

    raw_doc = storage.get_raw(job.get("raw_id"))
    if not raw_doc:
        storage.delete_job(job_id)
        raise HTTPException(status_code=500, detail="Job result is missing")
    result = project_api_result(raw_doc)
    storage.delete_job(job_id)
    return result


@app.get("/health")
def health(settings: Settings = Depends(get_settings), storage: MongoStorage = Depends(storage_dep)):
    status_code = 200
    checks: dict[str, str] = {}
    try:
        storage.ping()
        checks["mongo"] = "ok"
    except Exception as exc:
        checks["mongo"] = f"error: {exc}"
        status_code = 503

    try:
        Redis.from_url(settings.redis_url).ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"
        status_code = 503

    return JSONResponse(status_code=status_code, content={"status": "ok" if status_code == 200 else "error", "checks": checks})
