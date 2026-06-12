from datetime import datetime, timezone

from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app, storage_dep
from app.models import JOB_QUEUED, JOB_SUCCEEDED, empty_format_result


class FakeStorage:
    def __init__(self):
        self.raw_id = ObjectId()
        self.raw = {**empty_format_result("https://example.com/"), "_id": self.raw_id, "status": "ok"}
        self.jobs = {}

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def get_raw(self, raw_id):
        return self.raw if str(raw_id) == str(self.raw_id) else None

    def delete_job(self, job_id):
        self.jobs.pop(job_id, None)


def test_pending_job_result_returns_202():
    storage = FakeStorage()
    storage.jobs["job-pending"] = {
        "job_id": "job-pending",
        "status": JOB_QUEUED,
        "cache_hit": False,
        "submitted_url": "https://example.com/",
        "created_at": datetime.now(timezone.utc),
    }
    app.dependency_overrides[storage_dep] = lambda: storage
    try:
        client = TestClient(app)
        response = client.get("/jobs/job-pending/result")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 202
    assert response.json()["status"] == JOB_QUEUED


def test_successful_job_result_matches_format_shape():
    storage = FakeStorage()
    storage.jobs["job-done"] = {
        "job_id": "job-done",
        "status": JOB_SUCCEEDED,
        "cache_hit": False,
        "submitted_url": "https://example.com/",
        "raw_id": storage.raw_id,
        "created_at": datetime.now(timezone.utc),
    }
    app.dependency_overrides[storage_dep] = lambda: storage
    try:
        client = TestClient(app)
        response = client.get("/jobs/job-done/result")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "job-done" not in storage.jobs
    assert set(response.json()) == {
        "submitted_url",
        "final_url",
        "redirect_chain",
        "headers",
        "tls",
        "rdap_whois",
        "downloads",
        "html",
    }
