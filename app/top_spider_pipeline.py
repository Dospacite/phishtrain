from __future__ import annotations

import argparse
import csv
import json
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

from rq import Queue
from tqdm import tqdm

from app.models import JOB_QUEUED
from app.preflight import create_or_enqueue_preflight_job
from app.queue import get_preflight_queue
from app.settings import Settings, get_settings
from app.storage import MongoStorage
from app.url_safety import UrlValidationError, normalize_url


DEFAULT_CSV_PATH = Path("top-1m.csv")
DEFAULT_PROGRESS_PATH = Path("top-1m-spider-progress.json")
DEFAULT_START_POSITIONS = (1, 250_000, 500_000, 750_000)


@dataclass(frozen=True)
class TopSite:
    rank: int
    lane_start: int
    domain: str
    url: str


@dataclass(frozen=True)
class QueueSummary:
    total: int
    processed: int
    queued: int
    cache_hits: int
    skipped: int


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_start_positions(value: str) -> tuple[int, ...]:
    starts = tuple(sorted({int(item.strip().replace("_", "")) for item in value.split(",") if item.strip()}))
    if not starts or any(start < 1 for start in starts):
        raise argparse.ArgumentTypeError("start positions must be positive 1-based ranks")
    return starts


def _domain_to_url(domain: str) -> str:
    candidate = domain if "://" in domain else f"https://{domain}/"
    return normalize_url(candidate)


def load_top_sites(csv_path: Path) -> dict[int, str]:
    rows: dict[int, str] = {}
    with csv_path.open(newline="") as fp:
        for row in csv.reader(fp):
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            domain = row[1].strip()
            if rank > 0 and domain:
                rows[rank] = domain
    return rows


def rank_ranges(start_positions: Sequence[int], max_rank: int) -> list[tuple[int, int]]:
    starts = tuple(sorted(start_positions))
    ranges: list[tuple[int, int]] = []
    for index, start in enumerate(starts):
        next_start = starts[index + 1] if index + 1 < len(starts) else max_rank + 1
        end = min(max_rank, next_start - 1)
        if start <= end:
            ranges.append((start, end))
    return ranges


def _initial_progress(start_positions: Sequence[int]) -> dict[str, object]:
    return {
        "starts": list(start_positions),
        "next_ranks": {str(start): start for start in start_positions},
        "processed": 0,
        "updated_at": _utc_iso(),
    }


def load_progress(progress_path: Path, start_positions: Sequence[int], continue_run: bool) -> dict[str, object]:
    if not continue_run or not progress_path.exists():
        return _initial_progress(start_positions)

    with progress_path.open() as fp:
        progress = json.load(fp)

    if tuple(progress.get("starts", ())) != tuple(start_positions):
        raise ValueError(f"{progress_path} was created for different start positions")

    next_ranks = progress.get("next_ranks")
    if not isinstance(next_ranks, dict):
        raise ValueError(f"{progress_path} does not contain next_ranks")

    normalized = _initial_progress(start_positions)
    normalized["processed"] = int(progress.get("processed", 0))
    normalized["next_ranks"] = {
        str(start): max(start, int(next_ranks.get(str(start), start)))
        for start in start_positions
    }
    return normalized


def save_progress(progress_path: Path, progress: dict[str, object]) -> None:
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress = {**progress, "updated_at": _utc_iso()}
    with progress_path.open("w") as fp:
        json.dump(progress, fp, indent=2, sort_keys=True)
        fp.write("\n")


def _remaining_count(
    ranks: Sequence[int],
    ranges: Sequence[tuple[int, int]],
    next_ranks: dict[str, int],
) -> int:
    total = 0
    for start, end in ranges:
        next_rank = next_ranks[str(start)]
        total += max(0, bisect_right(ranks, end) - bisect_left(ranks, next_rank))
    return total


def iter_top_sites(
    rows_by_rank: dict[int, str],
    start_positions: Sequence[int],
    next_ranks: dict[str, int],
) -> Iterable[TopSite]:
    max_rank = max(rows_by_rank, default=0)
    ranges = rank_ranges(start_positions, max_rank)
    lane_next = dict(next_ranks)

    while True:
        yielded = False
        for start, end in ranges:
            rank = lane_next[str(start)]
            while rank <= end and rank not in rows_by_rank:
                rank += 1
            lane_next[str(start)] = rank
            if rank > end:
                continue

            domain = rows_by_rank[rank]
            try:
                url = _domain_to_url(domain)
            except UrlValidationError:
                lane_next[str(start)] = rank + 1
                continue

            yield TopSite(rank=rank, lane_start=start, domain=domain, url=url)
            lane_next[str(start)] = rank + 1
            yielded = True

        if not yielded:
            break


def queue_top_1m_spider_jobs(
    *,
    csv_path: Path,
    storage: MongoStorage,
    queue: Queue,
    settings: Settings,
    progress_path: Path = DEFAULT_PROGRESS_PATH,
    continue_run: bool = False,
    start_positions: Sequence[int] = DEFAULT_START_POSITIONS,
    limit: int | None = None,
    force_new: bool = False,
    show_progress: bool = True,
    state_save_interval: int = 1,
    should_pause: Callable[[], bool] | None = None,
    capacity_count: Callable[[], int] | None = None,
) -> QueueSummary:
    starts = tuple(sorted(start_positions))
    rows_by_rank = load_top_sites(csv_path)
    ranks = sorted(rows_by_rank)
    ranges = rank_ranges(starts, max(rows_by_rank, default=0))
    progress = load_progress(progress_path, starts, continue_run)
    next_ranks = {str(key): int(value) for key, value in dict(progress["next_ranks"]).items()}

    remaining = _remaining_count(ranks, ranges, next_ranks)
    total = min(remaining, limit) if limit is not None else remaining
    batch_limit = settings.pipeline_enqueue_batch_size
    processed = queued = cache_hits = skipped = 0
    save_every = max(1, state_save_interval)

    def current_backlog() -> int:
        if capacity_count is not None:
            return max(0, int(capacity_count()))
        return max(0, int(getattr(queue, "count", 0)))

    with tqdm(total=total, desc="Queue spider jobs", unit="url", disable=not show_progress) as progress_bar:
        for site in iter_top_sites(rows_by_rank, starts, next_ranks):
            if should_pause and should_pause():
                break
            if limit is not None and processed >= limit:
                break
            if current_backlog() + queued >= batch_limit:
                break

            handle = create_or_enqueue_preflight_job(
                submitted_url=site.url,
                mode="spider",
                force_new=force_new,
                storage=storage,
                queue=queue,
                settings=settings,
            )

            processed += 1
            if handle.status == JOB_QUEUED:
                queued += 1
            elif handle.cache_hit:
                cache_hits += 1
            else:
                skipped += 1

            next_ranks[str(site.lane_start)] = site.rank + 1
            progress["next_ranks"] = next_ranks
            progress["processed"] = int(progress.get("processed", 0)) + 1

            if processed % save_every == 0:
                save_progress(progress_path, progress)

            progress_bar.update(1)
            if processed % 100 == 0 or processed == total:
                progress_bar.set_postfix(queued=queued, cached=cache_hits, skipped=skipped)

    save_progress(progress_path, progress)
    return QueueSummary(total=total, processed=processed, queued=queued, cache_hits=cache_hits, skipped=skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Queue spider jobs from top-1m.csv.")
    parser.add_argument("--csv", type=Path, default=None, help="Path to rank,domain CSV.")
    parser.add_argument("--progress-file", type=Path, default=None, help="JSON file used for --continue.")
    parser.add_argument("--continue", dest="continue_run", action="store_true", help="Resume from the progress file.")
    parser.add_argument("--starts", type=parse_start_positions, default=DEFAULT_START_POSITIONS, help="Comma-separated 1-based rank starts.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum URLs to process in this run.")
    parser.add_argument("--force-new", action="store_true", help="Queue even if a successful spider result is cached.")
    parser.add_argument("--no-progress", action="store_true", help="Disable tqdm output.")
    parser.add_argument("--state-save-interval", type=int, default=1, help="Save progress after this many processed URLs.")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_arg_parser().parse_args(argv)
    settings = get_settings()
    storage = MongoStorage(settings)
    storage.ensure_indexes()
    queue = get_preflight_queue(settings)

    summary = queue_top_1m_spider_jobs(
        csv_path=args.csv or Path(settings.top_1m_pipeline_csv_path),
        storage=storage,
        queue=queue,
        settings=settings,
        progress_path=args.progress_file or Path(settings.top_1m_pipeline_progress_path),
        continue_run=args.continue_run,
        start_positions=args.starts,
        limit=args.limit,
        force_new=args.force_new,
        show_progress=not args.no_progress,
        state_save_interval=args.state_save_interval,
    )
    print(
        f"processed={summary.processed} queued={summary.queued} "
        f"cache_hits={summary.cache_hits} skipped={summary.skipped}"
    )


if __name__ == "__main__":
    main()
