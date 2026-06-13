from __future__ import annotations

import signal
import threading
from contextlib import contextmanager
from typing import Any

from redis import Redis
from rq.worker_pool import WorkerPool

from app.models import utc_now
from app.settings import get_settings
from app.storage import MongoStorage


class UrlTimeoutError(BaseException):
    pass


@contextmanager
def url_time_limit(seconds: float):
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)

    def handler(signum: int, frame: Any) -> None:
        raise UrlTimeoutError(f"URL scrape exceeded {seconds:.0f}s timeout")

    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _error_raw_doc(job: dict[str, Any], status: str, error: str) -> dict[str, Any]:
    submitted_url = job.get("submitted_url", "")
    return {
        "submitted_url": submitted_url,
        "final_url": submitted_url,
        "cache_key": job.get("cache_key"),
        "status": status,
        "error": error[:2_000],
        "rdap_whois": {"domain": None, "lookup_url": None, "status_code": None, "headers": {}, "raw": None, "error": "scrape failed"},
        "html": "",
        "downloads": {"candidates": [], "observed": []},
        "metadata": {
            "redirect_chain": [submitted_url] if submitted_url else [],
            "headers": {},
            "tls": {"enabled": False, "issuer": None, "subject": None},
            "title": "",
            "visible_text": "",
            "scraper": {"library": "scrapling", "mode": "stealth"},
        },
        "fetched_at": utc_now(),
    }


def run_scrape_job(job_id: str) -> str:
    settings = get_settings()
    storage = MongoStorage(settings)
    storage.ensure_indexes()
    job = storage.get_job(job_id)
    if not job:
        return "missing"

    storage.mark_job_running(job_id)
    try:
        from app.scraper import scrape_url

        with url_time_limit(settings.scrape_url_timeout_ms / 1000):
            artifact = scrape_url(job["submitted_url"], settings)
        if isinstance(job.get("dataset"), dict):
            artifact.raw_doc["dataset"] = job["dataset"]
            urlscan = job["dataset"].get("urlscan") if isinstance(job["dataset"].get("urlscan"), dict) else None
            if urlscan:
                artifact.raw_doc["urlscan"] = urlscan
        raw_id = storage.insert_raw(artifact.raw_doc, artifact.screenshot_webp, artifact.screenshot_metadata)
        storage.mark_job_succeeded(job_id, raw_id)
        return "succeeded"
    except UrlTimeoutError as exc:
        raw_id = storage.insert_raw(_error_raw_doc(job, "timeout", str(exc)))
        storage.mark_job_timeout(job_id, str(exc), raw_id)
        return "timeout"
    except Exception as exc:
        raw_id = storage.insert_raw(_error_raw_doc(job, "error", str(exc)))
        storage.mark_job_failed(job_id, str(exc), raw_id)
        return "failed"


def run_spider_job(job_id: str) -> str:
    settings = get_settings()
    storage = MongoStorage(settings)
    storage.ensure_indexes()
    job = storage.get_job(job_id)
    if not job:
        return "missing"

    storage.mark_job_running(job_id)
    try:
        from app.scraper import scrape_url
        from app.spider import selected_spider_child_urls

        with url_time_limit(settings.spider_job_timeout_seconds):
            seed_artifact = scrape_url(job["submitted_url"], settings)
            child_urls = selected_spider_child_urls(
                seed_artifact.rendered_html,
                job["submitted_url"],
                seed_artifact.raw_doc.get("final_url") or job["submitted_url"],
                settings,
            )

            child_raw_ids = []
            for child_url in child_urls:
                try:
                    child_artifact = scrape_url(
                        child_url,
                        settings,
                        wait_ms=settings.spider_page_wait_ms,
                        timeout_ms=settings.spider_page_timeout_ms,
                        capture_screenshot=False,
                    )
                except Exception:
                    continue
                child_raw_ids.append(storage.insert_raw(child_artifact.raw_doc))

            seed_artifact.raw_doc["cache_key"] = job.get("cache_key")
            seed_artifact.raw_doc["spider_child_raw_ids"] = child_raw_ids
            raw_id = storage.insert_raw(seed_artifact.raw_doc, seed_artifact.screenshot_webp, seed_artifact.screenshot_metadata)
        storage.mark_job_succeeded(job_id, raw_id)
        return "succeeded"
    except UrlTimeoutError as exc:
        raw_id = storage.insert_raw(_error_raw_doc(job, "timeout", str(exc)))
        storage.mark_job_timeout(job_id, str(exc), raw_id)
        return "timeout"
    except Exception as exc:
        raw_id = storage.insert_raw(_error_raw_doc(job, "error", str(exc)))
        storage.mark_job_failed(job_id, str(exc), raw_id)
        return "failed"


def main() -> None:
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url)
    worker_pool = WorkerPool([settings.rq_queue_name], connection=redis, num_workers=settings.worker_concurrency)
    worker_pool.start()


if __name__ == "__main__":
    main()
