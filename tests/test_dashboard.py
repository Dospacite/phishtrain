from __future__ import annotations

import json
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app, queue_dep, storage_dep
from app.models import JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, empty_format_result
from app.settings import Settings, get_settings


class FakeRegistry:
    def __init__(self, count):
        self.count = count


class FakeQueue:
    name = "scrape"
    count = 7
    started_job_registry = FakeRegistry(2)
    finished_job_registry = FakeRegistry(9)
    failed_job_registry = FakeRegistry(1)
    deferred_job_registry = FakeRegistry(0)
    scheduled_job_registry = FakeRegistry(0)

    def empty(self):
        self.count = 0


class FakeStorage:
    def job_status_counts(self):
        return {
            "queued": 4,
            "running": 2,
            "succeeded": 12,
            "failed": 1,
            "timeout": 0,
        }

    def recent_jobs(self, statuses=None, limit=25):
        now = datetime.now(timezone.utc)
        if statuses == [JOB_QUEUED, JOB_RUNNING]:
            return [
                {
                    "job_id": "job-active",
                    "status": JOB_RUNNING,
                    "cache_hit": False,
                    "submitted_url": "https://active.test/",
                    "created_at": now,
                    "updated_at": now,
                }
            ]
        return [
            {
                "job_id": "job-done",
                "status": JOB_SUCCEEDED,
                "cache_hit": False,
                "submitted_url": "https://done.test/",
                "created_at": now,
                "updated_at": now,
            }
        ]

    def raw_capture_count(self):
        return 15

    def raw_status_counts(self):
        return {"ok": 14, "error": 1}


def dashboard_client(tmp_path, monkeypatch):
    progress_path = tmp_path / "progress.json"
    progress_path.write_text(
        json.dumps(
            {
                "starts": [1, 250000, 500000, 750000],
                "next_ranks": {"1": 11, "250000": 250005, "500000": 500001, "750000": 750000},
                "processed": 16,
                "updated_at": "2026-06-13T01:00:00+00:00",
            }
        )
    )
    settings = Settings(
        dashboard_password="secret",
        top_1m_pipeline_progress_path=str(progress_path),
        top_1m_pipeline_control_path=str(tmp_path / "control.json"),
        top_1m_pipeline_max_rank=1_000_000,
    )

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[storage_dep] = lambda: FakeStorage()
    app.dependency_overrides[queue_dep] = lambda: FakeQueue()
    monkeypatch.setattr(
        "app.dashboard.docker_service_statuses",
        lambda: {"available": True, "services": [{"service": "api", "status": "running"}]},
    )
    def fake_docker_logs(service, tail):
        if service not in {"api", "worker", "redis"}:
            raise HTTPException(status_code=400, detail="Unknown service")
        return f"{service}:{tail}\n"

    monkeypatch.setattr("app.dashboard.docker_logs", fake_docker_logs)
    return TestClient(app)


def test_dashboard_requires_password(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        response = client.get("/dashboard")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Basic realm="PhishTrain Dashboard"'


def test_dashboard_page_is_served_with_password(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        response = client.get("/dashboard", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "PhishTrain Dashboard" in response.text
    assert "Dataset Curation" in response.text


def test_phishing_dataset_page_is_served_with_password(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        unauthorized = client.get("/dashboard/phishing-dataset")
        response = client.get("/dashboard/phishing-dataset", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert "Phishing Dataset Curation" in response.text


def test_dashboard_status_includes_jobs_pipeline_queue_and_runtime(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        response = client.get("/dashboard/api/status", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["jobs"]["counts"]["running"] == 2
    assert data["jobs"]["active"][0]["job_id"] == "job-active"
    assert data["jobs"]["completed"][0]["job_id"] == "job-done"
    assert data["raw"]["total"] == 15
    assert data["queue"]["queued"] == 7
    assert data["pipeline"]["processed"] == 16
    assert data["pipeline"]["paused"] is False
    assert data["pipeline"]["running"] is False
    assert data["pipeline"]["lanes"][0]["next_rank"] == 11
    assert data["docker"]["services"][0]["service"] == "api"


def test_dashboard_logs_endpoint_is_protected_and_validates_services(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        unauthorized = client.get("/dashboard/api/logs?service=api")
        ok = client.get("/dashboard/api/logs?service=worker&tail=50", auth=("admin", "secret"))
        bad_service = client.get("/dashboard/api/logs?service=unknown", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert unauthorized.status_code == 401
    assert ok.status_code == 200
    assert ok.text == "worker:50\n"
    assert bad_service.status_code == 400


def test_dashboard_pipeline_controls_are_protected_and_write_control_file(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    try:
        unauthorized = client.post("/dashboard/api/pipeline/pause")
        pause = client.post("/dashboard/api/pipeline/pause", auth=("admin", "secret"))
        status = client.get("/dashboard/api/status", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert unauthorized.status_code == 401
    assert pause.status_code == 200
    assert pause.json()["paused"] is True
    assert status.json()["pipeline"]["paused"] is True


def test_dashboard_pipeline_start_uses_runtime_start_function(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    monkeypatch.setattr("app.dashboard.start_pipeline", lambda settings: {"status": "started", "running": True})
    try:
        response = client.post("/dashboard/api/pipeline/start", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "started", "running": True}


def test_dashboard_clear_queue_is_protected_and_clears_main_and_preflight(tmp_path, monkeypatch):
    class ClearableQueue(FakeQueue):
        def __init__(self, name, count):
            self.name = name
            self.count = count
            self.started_job_registry = FakeRegistry(0)
            self.finished_job_registry = FakeRegistry(0)
            self.failed_job_registry = FakeRegistry(0)
            self.deferred_job_registry = FakeRegistry(0)
            self.scheduled_job_registry = FakeRegistry(0)

    main_queue = ClearableQueue("scrape", 7)
    preflight_queue = ClearableQueue("preflight", 11)
    client = dashboard_client(tmp_path, monkeypatch)
    app.dependency_overrides[queue_dep] = lambda: main_queue
    monkeypatch.setattr("app.dashboard.get_preflight_queue", lambda settings: preflight_queue)

    try:
        unauthorized = client.post("/dashboard/api/queue/clear")
        response = client.post("/dashboard/api/queue/clear", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert response.json()["cleared"] == 18
    assert main_queue.count == 0
    assert preflight_queue.count == 0


def test_dashboard_urlscan_pipeline_start_uses_runtime_start_function(tmp_path, monkeypatch):
    client = dashboard_client(tmp_path, monkeypatch)
    monkeypatch.setattr("app.dashboard.start_urlscan_pipeline", lambda settings: {"status": "started", "running": True})
    try:
        response = client.post("/dashboard/api/urlscan-pipeline/start", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "started", "running": True}


class DatasetQueue:
    name = "scrape"
    count = 0
    started_job_registry = FakeRegistry(0)
    finished_job_registry = FakeRegistry(0)
    failed_job_registry = FakeRegistry(0)
    deferred_job_registry = FakeRegistry(0)
    scheduled_job_registry = FakeRegistry(0)

    def __init__(self):
        self.enqueued = []

    def enqueue(self, func, *args, **kwargs):
        self.enqueued.append({"func": func, "args": args, "kwargs": kwargs})


class DatasetStorage:
    def __init__(self):
        self.raw_id = ObjectId()
        self.raw_doc = {
            **empty_format_result("https://example.com/"),
            "_id": self.raw_id,
            "status": "ok",
            "urlscan": {"scan_id": "scan-1", "result_url": "https://urlscan.io/api/v1/result/scan-1/"},
            "screenshot": {"gridfs_file_id": ObjectId(), "content_type": "image/webp"},
        }
        self.jobs = {}
        self.curated_doc = None

    def dataset_queue_items(self, limit=50):
        if self.curated_doc:
            return []
        items = []
        for job in self.jobs.values():
            status = "ready" if job["status"] == JOB_SUCCEEDED else job["status"]
            item = {
                "job_id": job["job_id"],
                "status": status,
                "submitted_url": job["submitted_url"],
                "urlscan": job.get("dataset", {}).get("urlscan", {}),
            }
            if status == "ready":
                item["raw_id"] = str(job["raw_id"])
            items.append(item)
        return items[:limit]

    def dataset_ready_items(self, limit=50):
        return [
            {
                "job_id": "job-ready",
                "status": "ready",
                "submitted_url": self.raw_doc["submitted_url"],
                "raw_id": str(self.raw_id),
                "urlscan": self.raw_doc["urlscan"],
            }
        ][:limit] if not self.curated_doc else []

    def dataset_queue_counts(self):
        counts = {"queued": 0, "running": 0, "ready": 0, "failed": 0, "timeout": 0}
        for item in self.dataset_queue_items(500):
            counts[item["status"]] += 1
        return counts

    def dataset_candidate_exists(self, scan_id=None, url=None):
        return False

    def find_latest_successful(self, cache_key):
        return None

    def create_job(self, **kwargs):
        now = datetime.now(timezone.utc)
        doc = {**kwargs, "created_at": now, "updated_at": now}
        self.jobs[kwargs["job_id"]] = doc
        return doc

    def get_raw(self, raw_id):
        return self.raw_doc if str(raw_id) == str(self.raw_id) else None

    def dataset_source_for_raw(self, raw_id):
        return self.raw_doc["urlscan"]

    def get_raw_screenshot(self, raw_id):
        if str(raw_id) != str(self.raw_id):
            return None
        return b"webp", {"content_type": "image/webp"}

    def insert_curated_decision(self, **kwargs):
        self.curated_doc = kwargs
        return {"decision": kwargs["decision"], "raw_id": str(kwargs["raw_doc"]["_id"]), "blocks": kwargs.get("blocks", [])}


def dataset_client(storage, queue, monkeypatch):
    settings = Settings(dashboard_password="secret", urlscan_api_key="key", dataset_queue_target=2)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[storage_dep] = lambda: storage
    app.dependency_overrides[queue_dep] = lambda: queue
    monkeypatch.setattr("app.dashboard.docker_service_statuses", lambda: {"available": True, "services": []})
    monkeypatch.setattr("app.dashboard.docker_logs", lambda service, tail: "")
    return TestClient(app)


def test_phishing_dataset_queue_returns_ready_captures(monkeypatch):
    storage = DatasetStorage()
    queue = DatasetQueue()
    client = dataset_client(storage, queue, monkeypatch)

    try:
        response = client.get("/dashboard/api/phishing-dataset/queue", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["items"][0]["status"] == "ready"
    assert response.json()["items"][0]["raw_id"] == str(storage.raw_id)


def test_phishing_dataset_raw_detail_and_screenshot(monkeypatch):
    storage = DatasetStorage()
    queue = DatasetQueue()
    client = dataset_client(storage, queue, monkeypatch)

    try:
        detail = client.get(f"/dashboard/api/phishing-dataset/raw/{storage.raw_id}", auth=("admin", "secret"))
        screenshot = client.get(f"/dashboard/api/phishing-dataset/raw/{storage.raw_id}/screenshot", auth=("admin", "secret"))
    finally:
        app.dependency_overrides.clear()

    assert detail.status_code == 200
    data = detail.json()
    assert data["api_document"]["submitted_url"] == "https://example.com/"
    assert any(item["pointer"] == "/html/title" for item in data["references"])
    assert data["screenshot_url"].endswith(f"/{storage.raw_id}/screenshot")
    assert screenshot.status_code == 200
    assert screenshot.headers["content-type"].startswith("image/webp")
    assert screenshot.content == b"webp"


def test_phishing_dataset_curate_and_skip_store_decisions(monkeypatch):
    storage = DatasetStorage()
    queue = DatasetQueue()
    client = dataset_client(storage, queue, monkeypatch)

    try:
        curate = client.post(
            "/dashboard/api/phishing-dataset/curate",
            json={
                "raw_id": str(storage.raw_id),
                "verdict": "phishing",
                "confidence": 0.93,
                "organization_brand": "Example Bank",
                "response_text": "The page asks for credentials.",
                "blocks": [{"text": "The page asks for credentials.", "references": [{"pointer": "/html/title"}]}],
            },
            auth=("admin", "secret"),
        )
        accepted = storage.curated_doc
        skip = client.post(
            "/dashboard/api/phishing-dataset/skip",
            json={"raw_id": str(storage.raw_id)},
            auth=("admin", "secret"),
        )
    finally:
        app.dependency_overrides.clear()

    assert curate.status_code == 200
    assert accepted["decision"] == "accepted"
    assert accepted["verdict"] == "phishing"
    assert accepted["confidence"] == 0.93
    assert accepted["organization_brand"] == "Example Bank"
    assert accepted["blocks"][0]["references"][0]["label"] == "html.title"
    assert skip.status_code == 200
    assert storage.curated_doc["decision"] == "skipped"
