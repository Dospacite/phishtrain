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
    mongo_curated_collection: str = os.getenv("MONGO_CURATED_COLLECTION", "curated")
    screenshot_bucket: str = os.getenv("SCREENSHOT_BUCKET", "screenshots")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    rq_queue_name: str = os.getenv("RQ_QUEUE_NAME", "scrape")
    preflight_queue_name: str = os.getenv("PREFLIGHT_QUEUE_NAME", "preflight")
    worker_concurrency: int = _bounded_int_env("WORKER_CONCURRENCY", 4, minimum=1, maximum=12)
    preflight_timeout_seconds: int = _bounded_int_env("PREFLIGHT_TIMEOUT_SECONDS", 8, minimum=1, maximum=30)
    pipeline_enqueue_batch_size: int = _bounded_int_env("PIPELINE_ENQUEUE_BATCH_SIZE", 50, minimum=1, maximum=50)
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
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "")
    dashboard_log_tail: int = _int_env("DASHBOARD_LOG_TAIL", 200)
    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")
    urlscan_search_size: int = _bounded_int_env("URLSCAN_SEARCH_SIZE", 50, minimum=1, maximum=100)
    dataset_queue_target: int = _bounded_int_env("DATASET_QUEUE_TARGET", 12, minimum=1, maximum=100)
    dataset_refill_interval_seconds: int = _bounded_int_env("DATASET_REFILL_INTERVAL_SECONDS", 10, minimum=3, maximum=300)
    dataset_refill_max_pages: int = _bounded_int_env("DATASET_REFILL_MAX_PAGES", 3, minimum=1, maximum=10)
    urlscan_pipeline_progress_path: str = os.getenv("URLSCAN_PIPELINE_PROGRESS_PATH", "urlscan-phishing-progress.json")
    urlscan_pipeline_control_path: str = os.getenv("URLSCAN_PIPELINE_CONTROL_PATH", "urlscan-phishing-control.json")
    urlscan_pipeline_max_pages: int = _int_env("URLSCAN_PIPELINE_MAX_PAGES", 1_000)
    top_1m_pipeline_csv_path: str = os.getenv("TOP_1M_PIPELINE_CSV_PATH", "top-1m.csv")
    top_1m_pipeline_progress_path: str = os.getenv("TOP_1M_PIPELINE_PROGRESS_PATH", "top-1m-spider-progress.json")
    top_1m_pipeline_control_path: str = os.getenv("TOP_1M_PIPELINE_CONTROL_PATH", "top-1m-spider-control.json")
    top_1m_pipeline_max_rank: int = _int_env("TOP_1M_PIPELINE_MAX_RANK", 1_000_000)

    @property
    def browser_timeout_ms(self) -> int:
        return max(1_000, self.scrape_url_timeout_ms - self.scrape_wait_ms)

    @property
    def curated_collection(self) -> str:
        return self.mongo_curated_collection

    @property
    def urlscan_refill_target(self) -> int:
        return self.dataset_queue_target

    @property
    def urlscan_refill_max_pages(self) -> int:
        return self.dataset_refill_max_pages


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
