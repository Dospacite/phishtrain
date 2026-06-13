from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rq import Queue

from app.models import JOB_QUEUED
from app.preflight import create_or_enqueue_preflight_job
from app.queue import get_preflight_queue
from app.settings import Settings, get_settings
from app.storage import MongoStorage
from app.urlscan import search_phishing_candidate_page


DEFAULT_PROGRESS_PATH = Path("urlscan-phishing-progress.json")


@dataclass(frozen=True)
class UrlscanPipelineSummary:
    pages: int
    candidates: int
    queued: int
    cache_hits: int
    skipped: int


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _initial_progress() -> dict[str, object]:
    return {
        "search_after": None,
        "pages": 0,
        "candidates": 0,
        "queued": 0,
        "cache_hits": 0,
        "skipped": 0,
        "updated_at": _utc_iso(),
    }


def load_progress(progress_path: Path, continue_run: bool) -> dict[str, object]:
    if not continue_run or not progress_path.exists():
        return _initial_progress()
    with progress_path.open() as fp:
        data = json.load(fp)
    progress = _initial_progress()
    progress.update({key: data.get(key, progress[key]) for key in progress})
    return progress


def save_progress(progress_path: Path, progress: dict[str, object]) -> None:
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress = {**progress, "updated_at": _utc_iso()}
    with progress_path.open("w") as fp:
        json.dump(progress, fp, indent=2, sort_keys=True)
        fp.write("\n")


def queue_urlscan_phishing_jobs(
    *,
    storage: MongoStorage,
    queue: Queue,
    settings: Settings,
    progress_path: Path = DEFAULT_PROGRESS_PATH,
    continue_run: bool = True,
    force_new: bool = False,
    max_pages: int | None = None,
    should_pause: Callable[[], bool] | None = None,
) -> UrlscanPipelineSummary:
    progress = load_progress(progress_path, continue_run)
    search_after = progress.get("search_after") if isinstance(progress.get("search_after"), str) else None
    page_limit = settings.urlscan_pipeline_max_pages if max_pages is None else max_pages
    batch_limit = settings.pipeline_enqueue_batch_size
    pages = candidates_count = queued = cache_hits = skipped = 0

    while page_limit <= 0 or pages < page_limit:
        if should_pause and should_pause():
            break
        if queued >= batch_limit:
            break

        page = search_phishing_candidate_page(settings, search_after=search_after)
        if not page.candidates and not page.has_more:
            progress["search_after"] = None
            save_progress(progress_path, progress)
            break

        pages += 1
        page_candidates = page_queued = page_cache_hits = page_skipped = 0
        batch_full = False
        for candidate in page.candidates:
            if queued >= batch_limit:
                batch_full = True
                break
            candidates_count += 1
            page_candidates += 1
            if storage.dataset_candidate_exists(scan_id=candidate.scan_id, url=candidate.submitted_url):
                skipped += 1
                page_skipped += 1
                continue

            handle = create_or_enqueue_preflight_job(
                submitted_url=candidate.submitted_url,
                mode="scrape",
                force_new=force_new,
                storage=storage,
                queue=queue,
                settings=settings,
                dataset=candidate.dataset_metadata(),
            )
            if handle.status == JOB_QUEUED:
                queued += 1
                page_queued += 1
            elif handle.cache_hit:
                cache_hits += 1
                page_cache_hits += 1
            else:
                skipped += 1
                page_skipped += 1

        if not batch_full:
            search_after = page.search_after
            progress["search_after"] = search_after
        progress["pages"] = int(progress.get("pages", 0)) + 1
        progress["candidates"] = int(progress.get("candidates", 0)) + page_candidates
        progress["queued"] = int(progress.get("queued", 0)) + page_queued
        progress["cache_hits"] = int(progress.get("cache_hits", 0)) + page_cache_hits
        progress["skipped"] = int(progress.get("skipped", 0)) + page_skipped
        save_progress(progress_path, progress)

        if batch_full or not page.has_more:
            break

    return UrlscanPipelineSummary(pages=pages, candidates=candidates_count, queued=queued, cache_hits=cache_hits, skipped=skipped)


def main() -> None:
    settings = get_settings()
    storage = MongoStorage(settings)
    storage.ensure_indexes()
    queue = get_preflight_queue(settings)
    summary = queue_urlscan_phishing_jobs(
        storage=storage,
        queue=queue,
        settings=settings,
        progress_path=Path(settings.urlscan_pipeline_progress_path),
        continue_run=True,
    )
    print(
        f"pages={summary.pages} candidates={summary.candidates} queued={summary.queued} "
        f"cache_hits={summary.cache_hits} skipped={summary.skipped}"
    )


if __name__ == "__main__":
    main()
