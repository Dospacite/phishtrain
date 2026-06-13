from __future__ import annotations

import json

from bson import ObjectId

from app.settings import Settings
from app.top_spider_pipeline import (
    build_arg_parser,
    queue_top_1m_spider_jobs,
)


class FakeQueue:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, func, *args, **kwargs):
        self.enqueued.append((func, args, kwargs))


class FakeStorage:
    def __init__(self, cached_urls=None):
        self.cached_urls = set(cached_urls or [])
        self.created = []

    def find_latest_successful(self, cache_key):
        if cache_key in self.cached_urls:
            return {"_id": ObjectId(), "status": "ok"}
        return None

    def create_job(self, **kwargs):
        self.created.append(kwargs)
        return kwargs


class FakeTqdm:
    instances = []

    def __init__(self, *args, **kwargs):
        self.total = kwargs["total"]
        self.disable = kwargs["disable"]
        self.updated = 0
        self.postfixes = []
        FakeTqdm.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def update(self, amount):
        self.updated += amount

    def set_postfix(self, **kwargs):
        self.postfixes.append(kwargs)


def write_top_csv(path, domains):
    path.write_text("".join(f"{rank},{domain}\n" for rank, domain in enumerate(domains, start=1)))


def test_pipeline_interleaves_start_positions_and_updates_tqdm(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, ["a.test", "b.test", "c.test", "d.test", "e.test", "f.test"])
    storage = FakeStorage()
    queue = FakeQueue()

    ids = iter([f"job-{index}" for index in range(1, 7)])
    monkeypatch.setattr("app.jobs.make_job_id", lambda: next(ids))
    monkeypatch.setattr("app.top_spider_pipeline.tqdm", FakeTqdm)
    FakeTqdm.instances = []

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(),
        progress_path=progress_path,
        start_positions=(1, 3, 5),
    )

    assert [job["submitted_url"] for job in storage.created] == [
        "https://a.test/",
        "https://c.test/",
        "https://e.test/",
        "https://b.test/",
        "https://d.test/",
        "https://f.test/",
    ]
    assert len(queue.enqueued) == 6
    assert {item[0].__name__ for item in queue.enqueued} == {"run_preflight_job"}
    assert {job["preflight"]["mode"] for job in storage.created} == {"spider"}
    assert summary.processed == 6
    assert summary.queued == 6
    assert FakeTqdm.instances[0].total == 6
    assert FakeTqdm.instances[0].updated == 6

    progress = json.loads(progress_path.read_text())
    assert progress["next_ranks"] == {"1": 3, "3": 5, "5": 7}


def test_pipeline_continue_resumes_from_progress_file(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, ["a.test", "b.test", "c.test", "d.test", "e.test", "f.test"])
    progress_path.write_text(
        json.dumps(
            {
                "starts": [1, 3, 5],
                "next_ranks": {"1": 2, "3": 4, "5": 6},
                "processed": 3,
                "updated_at": "2026-06-13T00:00:00+00:00",
            }
        )
    )
    storage = FakeStorage()
    queue = FakeQueue()

    ids = iter([f"job-{index}" for index in range(1, 4)])
    monkeypatch.setattr("app.jobs.make_job_id", lambda: next(ids))
    monkeypatch.setattr("app.top_spider_pipeline.tqdm", FakeTqdm)
    FakeTqdm.instances = []

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(),
        progress_path=progress_path,
        continue_run=True,
        start_positions=(1, 3, 5),
    )

    assert [job["submitted_url"] for job in storage.created] == [
        "https://b.test/",
        "https://d.test/",
        "https://f.test/",
    ]
    assert summary.total == 3
    assert summary.processed == 3
    assert FakeTqdm.instances[0].total == 3
    assert json.loads(progress_path.read_text())["next_ranks"] == {"1": 3, "3": 5, "5": 7}


def test_pipeline_counts_cache_hits_without_queueing(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, ["a.test", "b.test"])
    storage = FakeStorage(cached_urls={"spider:v1:https://a.test/"})
    queue = FakeQueue()

    ids = iter(["job-cache", "job-queued"])
    monkeypatch.setattr("app.jobs.make_job_id", lambda: next(ids))

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(),
        progress_path=progress_path,
        start_positions=(1,),
        show_progress=False,
    )

    assert summary.processed == 2
    assert summary.cache_hits == 1
    assert summary.queued == 1
    assert len(queue.enqueued) == 1
    assert queue.enqueued[0][0].__name__ == "run_preflight_job"
    assert storage.created[0]["status"] == "succeeded"
    assert storage.created[1]["status"] == "queued"


def test_pipeline_stops_cleanly_when_pause_hook_requests_pause(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, ["a.test", "b.test", "c.test"])
    storage = FakeStorage()
    queue = FakeQueue()

    ids = iter(["job-1", "job-2"])
    monkeypatch.setattr("app.jobs.make_job_id", lambda: next(ids))

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(),
        progress_path=progress_path,
        start_positions=(1,),
        show_progress=False,
        should_pause=lambda: len(storage.created) >= 1,
    )

    assert summary.processed == 1
    assert [job["submitted_url"] for job in storage.created] == ["https://a.test/"]
    assert json.loads(progress_path.read_text())["next_ranks"] == {"1": 2}


def test_pipeline_honors_enqueue_batch_cap(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, [f"{index}.test" for index in range(1, 8)])
    storage = FakeStorage()
    queue = FakeQueue()

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(pipeline_enqueue_batch_size=3),
        progress_path=progress_path,
        start_positions=(1,),
        show_progress=False,
    )

    assert summary.queued == 3
    assert len(queue.enqueued) == 3
    assert [job["submitted_url"] for job in storage.created] == ["https://1.test/", "https://2.test/", "https://3.test/"]


def test_pipeline_tops_up_only_available_queue_capacity(tmp_path, monkeypatch):
    csv_path = tmp_path / "top-1m.csv"
    progress_path = tmp_path / "progress.json"
    write_top_csv(csv_path, [f"{index}.test" for index in range(1, 8)])
    storage = FakeStorage()
    queue = FakeQueue()

    summary = queue_top_1m_spider_jobs(
        csv_path=csv_path,
        storage=storage,
        queue=queue,
        settings=Settings(pipeline_enqueue_batch_size=5),
        progress_path=progress_path,
        start_positions=(1,),
        show_progress=False,
        capacity_count=lambda: 3,
    )

    assert summary.queued == 2
    assert len(queue.enqueued) == 2
    assert [job["submitted_url"] for job in storage.created] == ["https://1.test/", "https://2.test/"]


def test_parser_exposes_continue_option():
    args = build_arg_parser().parse_args(["--continue", "--starts", "1,250000,500000,750000"])

    assert args.continue_run is True
    assert args.starts == (1, 250_000, 500_000, 750_000)
