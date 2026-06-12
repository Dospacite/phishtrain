import importlib

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
