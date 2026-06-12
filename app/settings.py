from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


load_dotenv()


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _bounded_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, _int_env(name, default)))


@dataclass(frozen=True)
class Settings:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    mongo_db: str = os.getenv("MONGO_DB", "phishtrain")
    mongo_collection: str = os.getenv("MONGO_COLLECTION", "raw")
    mongo_jobs_collection: str = os.getenv("MONGO_JOBS_COLLECTION", "jobs")
    screenshot_bucket: str = os.getenv("SCREENSHOT_BUCKET", "screenshots")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    rq_queue_name: str = os.getenv("RQ_QUEUE_NAME", "scrape")
    worker_concurrency: int = _bounded_int_env("WORKER_CONCURRENCY", 4, minimum=1, maximum=4)
    scrape_wait_ms: int = _int_env("SCRAPE_WAIT_MS", 10_000)
    scrape_url_timeout_ms: int = _int_env("SCRAPE_URL_TIMEOUT_MS", 30_000)
    rq_job_timeout_seconds: int = _int_env("RQ_JOB_TIMEOUT_SECONDS", 45)
    spider_max_child_pages: int = _int_env("SPIDER_MAX_CHILD_PAGES", 25)
    spider_candidate_limit: int = _int_env("SPIDER_CANDIDATE_LIMIT", 120)
    spider_page_wait_ms: int = _int_env("SPIDER_PAGE_WAIT_MS", 1_500)
    spider_page_timeout_ms: int = _int_env("SPIDER_PAGE_TIMEOUT_MS", 8_000)
    spider_job_timeout_seconds: int = _int_env("SPIDER_JOB_TIMEOUT_SECONDS", 180)
    allow_private_urls: bool = _bool_env("ALLOW_PRIVATE_URLS", False)
    screenshot_width: int = _int_env("SCREENSHOT_WIDTH", 1365)
    screenshot_height: int = _int_env("SCREENSHOT_HEIGHT", 768)

    @property
    def browser_timeout_ms(self) -> int:
        return max(1_000, self.scrape_url_timeout_ms - self.scrape_wait_ms)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
