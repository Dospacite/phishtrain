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


def test_urlscan_pipeline_queues_preflight_jobs_for_single_page_scrapes(tmp_path, monkeypatch):
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
    assert queue.enqueued[0][0].__name__ == "run_preflight_job"
    assert storage.created[0]["cache_key"] == "preflight:scrape:https://phish.example/"
    assert storage.created[0]["preflight"]["mode"] == "scrape"
    assert storage.created[0]["preflight"]["dataset"]["kind"] == "urlscan_phishing"
    assert not storage.created[0]["cache_key"].startswith("spider:v1:")


def test_urlscan_pipeline_honors_enqueue_batch_cap(tmp_path, monkeypatch):
    candidates = [
        UrlscanCandidate(
            scan_id=f"scan-{index}",
            submitted_url=f"https://phish-{index}.example/",
            page_url=None,
            result_url=None,
            raw_result={"_id": f"scan-{index}"},
        )
        for index in range(10)
    ]
    storage = FakeStorage()
    queue = FakeQueue()

    monkeypatch.setattr(
        "app.urlscan_pipeline.search_phishing_candidate_page",
        lambda settings, search_after=None: UrlscanSearchPage(candidates=candidates, search_after="next", has_more=True),
    )

    summary = queue_urlscan_phishing_jobs(
        storage=storage,
        queue=queue,
        settings=Settings(urlscan_api_key="key", pipeline_enqueue_batch_size=4),
        progress_path=tmp_path / "urlscan-progress.json",
        max_pages=1,
    )

    assert summary.queued == 4
    assert len(queue.enqueued) == 4
