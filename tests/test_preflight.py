from __future__ import annotations

from app.settings import Settings


class FakeQueue:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, func, *args, **kwargs):
        self.enqueued.append((func, args, kwargs))


class FakeStorage:
    def __init__(self, settings):
        self.job = {
            "job_id": "preflight-1",
            "submitted_url": "https://example.com/",
            "cache_key": "preflight:scrape:https://example.com/",
            "preflight": {
                "mode": "scrape",
                "target_cache_key": "https://example.com/",
                "force_new": False,
                "dataset": {"kind": "urlscan_phishing", "urlscan": {"scan_id": "scan-1"}},
            },
        }
        self.created = []
        self.events = []

    def ensure_indexes(self):
        pass

    def get_job(self, job_id):
        return self.job if job_id == self.job["job_id"] else None

    def mark_job_running(self, job_id):
        self.events.append(("running", job_id))

    def mark_job_failed(self, job_id, error, raw_id=None):
        self.events.append(("failed", job_id, error))

    def mark_preflight_succeeded(self, job_id, downstream):
        self.events.append(("succeeded", job_id, downstream))

    def find_latest_successful(self, cache_key):
        return None

    def create_job(self, **kwargs):
        self.created.append(kwargs)
        return kwargs

    def delete_job(self, job_id):
        self.created = [job for job in self.created if job.get("job_id") != job_id]


async def _connect_ok(url, settings):
    return None


async def _connect_failed(url, settings):
    return "connection refused"


def test_preflight_rejects_failed_connection_without_main_queue(monkeypatch):
    from app import preflight as preflight_module

    storage = FakeStorage(Settings())
    main_queue = FakeQueue()

    monkeypatch.setattr(preflight_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(preflight_module, "MongoStorage", lambda settings: storage)
    monkeypatch.setattr(preflight_module, "get_queue", lambda settings: main_queue)
    monkeypatch.setattr(preflight_module, "_attempt_connect", _connect_failed)

    assert preflight_module.run_preflight_job("preflight-1") == "rejected"
    assert main_queue.enqueued == []
    assert storage.events[-1] == ("failed", "preflight-1", "Preflight connection failed: connection refused")


def test_preflight_success_enqueues_main_scrape_job(monkeypatch):
    from app import preflight as preflight_module

    storage = FakeStorage(Settings())
    main_queue = FakeQueue()

    monkeypatch.setattr(preflight_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(preflight_module, "MongoStorage", lambda settings: storage)
    monkeypatch.setattr(preflight_module, "get_queue", lambda settings: main_queue)
    monkeypatch.setattr(preflight_module, "_attempt_connect", _connect_ok)
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "main-scrape-1")

    assert preflight_module.run_preflight_job("preflight-1") == "accepted"
    assert main_queue.enqueued[0][0].__name__ == "run_scrape_job"
    assert storage.created[0]["job_id"] == "main-scrape-1"
    assert storage.created[0]["dataset"]["kind"] == "urlscan_phishing"
    assert storage.events[-1][0] == "succeeded"
    assert storage.events[-1][2]["job_id"] == "main-scrape-1"
