import importlib

from app.scraper import ScrapeArtifact
from app.settings import Settings


def test_worker_concurrency_is_capped_at_four(monkeypatch):
    from app import settings as settings_module

    monkeypatch.setenv("WORKER_CONCURRENCY", "8")
    settings_module = importlib.reload(settings_module)

    assert settings_module.Settings().worker_concurrency == 4


def test_worker_main_starts_pool_with_configured_concurrency(monkeypatch):
    from app import worker as worker_module

    started = {}
    settings = Settings(worker_concurrency=3)

    class FakeRedis:
        @classmethod
        def from_url(cls, url):
            started["redis_url"] = url
            return "redis-connection"

    class FakeWorkerPool:
        def __init__(self, queues, connection, num_workers):
            started["queues"] = queues
            started["connection"] = connection
            started["num_workers"] = num_workers

        def start(self):
            started["started"] = True

    monkeypatch.setattr(worker_module, "get_settings", lambda: settings)
    monkeypatch.setattr(worker_module, "Redis", FakeRedis)
    monkeypatch.setattr(worker_module, "WorkerPool", FakeWorkerPool)

    worker_module.main()

    assert started == {
        "redis_url": settings.redis_url,
        "queues": [settings.rq_queue_name],
        "connection": "redis-connection",
        "num_workers": 3,
        "started": True,
    }


def test_run_scrape_job_copies_dataset_urlscan_metadata(monkeypatch):
    from app import worker as worker_module

    inserted = {}
    job = {
        "job_id": "job-dataset",
        "submitted_url": "https://example.com/",
        "cache_key": "https://example.com/",
        "dataset": {
            "kind": "urlscan_phishing",
            "urlscan": {
                "scan_id": "scan-1",
                "submitted_url": "https://example.com/",
                "result_url": "https://urlscan.io/api/v1/result/scan-1/",
            },
        },
    }

    class FakeStorage:
        def __init__(self, settings):
            self.settings = settings

        def ensure_indexes(self):
            pass

        def get_job(self, job_id):
            return job if job_id == job["job_id"] else None

        def mark_job_running(self, job_id):
            inserted["running"] = job_id

        def insert_raw(self, raw_doc, screenshot_webp=None, screenshot_metadata=None):
            inserted["raw_doc"] = raw_doc
            return "raw-id"

        def mark_job_succeeded(self, job_id, raw_id):
            inserted["succeeded"] = (job_id, raw_id)

        def mark_job_failed(self, job_id, error, raw_id=None):
            raise AssertionError(error)

        def mark_job_timeout(self, job_id, error, raw_id=None):
            raise AssertionError(error)

    def fake_scrape_url(url, settings):
        return ScrapeArtifact(
            raw_doc={
                "submitted_url": url,
                "final_url": url,
                "cache_key": url,
                "status": "ok",
                "rdap_whois": {"raw": None},
                "html": "",
                "downloads": {"candidates": [], "observed": []},
                "metadata": {},
            }
        )

    monkeypatch.setattr(worker_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(worker_module, "MongoStorage", FakeStorage)
    monkeypatch.setattr("app.scraper.scrape_url", fake_scrape_url)

    assert worker_module.run_scrape_job("job-dataset") == "succeeded"
    assert inserted["raw_doc"]["dataset"]["kind"] == "urlscan_phishing"
    assert inserted["raw_doc"]["urlscan"]["scan_id"] == "scan-1"
    assert inserted["succeeded"] == ("job-dataset", "raw-id")
