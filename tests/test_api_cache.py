from datetime import datetime, timezone

from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app, queue_dep, storage_dep
from app.models import empty_format_result


class FakeQueue:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, func, *args, **kwargs):
        self.enqueued.append((func, args, kwargs))


class FakeStorage:
    def __init__(self, cached=None):
        self.cached = cached
        self.jobs = {}

    def find_latest_successful(self, cache_key):
        return self.cached

    def create_job(self, **kwargs):
        doc = {"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc), **kwargs}
        self.jobs[kwargs["job_id"]] = doc
        return doc


def test_cached_url_creates_succeeded_job_without_queueing(monkeypatch):
    raw = {**empty_format_result("https://example.com/"), "_id": ObjectId(), "status": "ok"}
    storage = FakeStorage(cached=raw)
    queue = FakeQueue()

    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-1")
    try:
        client = TestClient(app)
        response = client.post("/scrape", json={"url": "https://example.com/"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "job_id": "job-1",
        "status": "succeeded",
        "cache_hit": True,
        "result_url": "/jobs/job-1/result",
    }
    assert queue.enqueued == []
    assert storage.jobs["job-1"]["raw_id"] == raw["_id"]


def test_force_new_queues_even_when_cache_exists(monkeypatch):
    raw = {**empty_format_result("https://example.com/"), "_id": ObjectId(), "status": "ok"}
    storage = FakeStorage(cached=raw)
    queue = FakeQueue()

    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-2")
    try:
        client = TestClient(app)
        response = client.post("/scrape?forceNew=true", json={"url": "https://example.com/"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert response.json()["cache_hit"] is False
    assert len(queue.enqueued) == 1


def test_spider_endpoint_queues_spider_job(monkeypatch):
    storage = FakeStorage()
    queue = FakeQueue()

    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-spider")
    try:
        client = TestClient(app)
        response = client.post("/spider", json={"url": "https://example.com/"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "job_id": "job-spider",
        "status": "queued",
        "cache_hit": False,
        "result_url": "/jobs/job-spider/result",
    }
    assert len(queue.enqueued) == 1
    assert queue.enqueued[0][0].__name__ == "run_spider_job"
    assert storage.jobs["job-spider"]["cache_key"] == "spider:v1:https://example.com/"


def test_spider_force_new_queues_even_when_cache_exists(monkeypatch):
    raw = {**empty_format_result("https://example.com/"), "_id": ObjectId(), "status": "ok"}
    storage = FakeStorage(cached=raw)
    queue = FakeQueue()

    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-spider-force")
    try:
        client = TestClient(app)
        response = client.post("/spider?forceNew=true", json={"url": "https://example.com/"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert response.json()["cache_hit"] is False
    assert len(queue.enqueued) == 1


def test_spider_cache_hit_uses_spider_cache_key(monkeypatch):
    raw = {**empty_format_result("https://example.com/"), "_id": ObjectId(), "status": "ok"}
    storage = FakeStorage(cached=raw)
    queue = FakeQueue()

    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-spider-cache")
    try:
        client = TestClient(app)
        response = client.post("/spider", json={"url": "https://example.com/"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["cache_hit"] is True
    assert queue.enqueued == []
    assert storage.jobs["job-spider-cache"]["cache_key"] == "spider:v1:https://example.com/"
