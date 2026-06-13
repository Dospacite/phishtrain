from __future__ import annotations

from functools import lru_cache

from redis import Redis
from rq import Queue

from app.settings import Settings, get_settings


@lru_cache(maxsize=1)
def get_redis_connection(redis_url: str | None = None) -> Redis:
    settings = get_settings()
    return Redis.from_url(redis_url or settings.redis_url)


def get_queue(settings: Settings | None = None) -> Queue:
    settings = settings or get_settings()
    return Queue(settings.rq_queue_name, connection=get_redis_connection(settings.redis_url))


def get_preflight_queue(settings: Settings | None = None) -> Queue:
    settings = settings or get_settings()
    return Queue(settings.preflight_queue_name, connection=get_redis_connection(settings.redis_url))
