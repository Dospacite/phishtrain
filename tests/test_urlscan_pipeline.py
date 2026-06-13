from __future__ import annotations

from app.settings import Settings
from app.urlscan import UrlscanCandidate, UrlscanSearchPage
from app.urlscan_pipeline import queue_urlscan_phishing_jobs


class FakeQueue:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, func, *args, **kwargs):
        self.enqueued.append((func, args, kwargs))


class FakeStorage:
    def __init__(self):
        self.created = []

    def dataset_candidate_exists(self, *, scan_id=None, url=None):
        return False

    def find_latest_successful(self, cache_key):
        return None

    def create_job(self, **kwargs):
        self.created.append(kwargs)
        return kwargs

    def delete_job(self, job_id):
        self.created = [job for job in self.created if job.get("job_id") != job_id]


def test_urlscan_pipeline_queues_single_page_scrape_jobs(tmp_path, monkeypatch):
    candidate = UrlscanCandidate(
        scan_id="scan-1",
        submitted_url="https://phish.example/",
        page_url="https://phish.example/login",
        result_url="https://urlscan.io/api/v1/result/scan-1/",
        raw_result={"_id": "scan-1", "task": {"url": "https://phish.example/"}},
    )
    storage = FakeStorage()
    queue = FakeQueue()

    monkeypatch.setattr("app.jobs.make_job_id", lambda: "job-urlscan")
    monkeypatch.setattr(
        "app.urlscan_pipeline.search_phishing_candidate_page",
        lambda settings, search_after=None: UrlscanSearchPage(candidates=[candidate], search_after=None, has_more=False),
    )

    summary = queue_urlscan_phishing_jobs(
        storage=storage,
        queue=queue,
        settings=Settings(urlscan_api_key="key"),
        progress_path=tmp_path / "urlscan-progress.json",
        max_pages=1,
    )

    assert summary.queued == 1
    assert len(queue.enqueued) == 1
    assert queue.enqueued[0][0].__name__ == "run_scrape_job"
    assert storage.created[0]["cache_key"] == "https://phish.example/"
    assert not storage.created[0]["cache_key"].startswith("spider:v1:")
    assert storage.created[0]["dataset"]["kind"] == "urlscan_phishing"
