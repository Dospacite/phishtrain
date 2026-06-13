from __future__ import annotations

import html
import io
import json
import secrets
import threading
import traceback
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from rq import Queue

from app.models import JOB_FAILED, JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_TIMEOUT
from app.models import CuratedDatasetRequest, SkipDatasetRequest
from app.queue import get_preflight_queue, get_queue
from app.settings import Settings, get_settings
from app.storage import MongoStorage, project_api_result, reference_options_for_document, resolve_json_pointer, serialize_job
from app.top_spider_pipeline import DEFAULT_START_POSITIONS, queue_top_1m_spider_jobs, rank_ranges
from app.urlscan_pipeline import queue_urlscan_phishing_jobs


LOG_SERVICES = ("api", "worker", "preflight-worker", "redis")
security = HTTPBasic(auto_error=False)
_pipeline_lock = threading.Lock()
_pipeline_thread: threading.Thread | None = None
_pipeline_last_run: dict[str, Any] = {}
_urlscan_pipeline_lock = threading.Lock()
_urlscan_pipeline_thread: threading.Thread | None = None
_urlscan_pipeline_last_run: dict[str, Any] = {}


def require_dashboard_auth(
    credentials: HTTPBasicCredentials | None = Depends(security),
    settings: Settings = Depends(get_settings),
) -> None:
    if not settings.dashboard_password:
        raise HTTPException(status_code=503, detail="DASHBOARD_PASSWORD is not configured")

    supplied = credentials.password if credentials else ""
    if not secrets.compare_digest(supplied, settings.dashboard_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dashboard authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"PhishTrain Dashboard\""},
        )


def _safe_call(default: Any, func: Callable[[], Any]) -> Any:
    try:
        return func()
    except Exception as exc:
        return {"error": str(exc)} if isinstance(default, dict) else default


def queue_details(queue: Queue) -> dict[str, Any]:
    def registry_count(name: str) -> int:
        registry = getattr(queue, name)
        count = registry.count
        return int(count() if callable(count) else count)

    return {
        "name": queue.name,
        "queued": int(queue.count),
        "started": _safe_call(0, lambda: registry_count("started_job_registry")),
        "finished": _safe_call(0, lambda: registry_count("finished_job_registry")),
        "failed": _safe_call(0, lambda: registry_count("failed_job_registry")),
        "deferred": _safe_call(0, lambda: registry_count("deferred_job_registry")),
        "scheduled": _safe_call(0, lambda: registry_count("scheduled_job_registry")),
    }


def _utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def pipeline_control(settings: Settings) -> dict[str, Any]:
    path = Path(settings.top_1m_pipeline_control_path)
    if not path.exists():
        return {"paused": False, "control_file": str(path)}
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        return {"paused": False, "control_file": str(path), "error": str(exc)}
    return {"paused": bool(data.get("paused", False)), "control_file": str(path), "updated_at": data.get("updated_at")}


def set_pipeline_paused(settings: Settings, paused: bool) -> dict[str, Any]:
    path = Path(settings.top_1m_pipeline_control_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"paused": paused, "updated_at": _utc_iso()}
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return {"status": "paused" if paused else "ready", **data, "control_file": str(path)}


def _pipeline_is_running() -> bool:
    return _pipeline_thread is not None and _pipeline_thread.is_alive()


def _run_pipeline(settings: Settings) -> None:
    global _pipeline_last_run
    started_at = _utc_iso()
    try:
        storage = MongoStorage(settings)
        storage.ensure_indexes()
        queue = get_preflight_queue(settings)
        summary = queue_top_1m_spider_jobs(
            csv_path=Path(settings.top_1m_pipeline_csv_path),
            storage=storage,
            queue=queue,
            settings=settings,
            progress_path=Path(settings.top_1m_pipeline_progress_path),
            continue_run=True,
            force_new=False,
            show_progress=False,
            should_pause=lambda: pipeline_control(settings).get("paused") is True,
        )
        _pipeline_last_run = {
            "status": "finished",
            "started_at": started_at,
            "finished_at": _utc_iso(),
            "summary": summary.__dict__,
        }
    except Exception as exc:
        _pipeline_last_run = {
            "status": "failed",
            "started_at": started_at,
            "finished_at": _utc_iso(),
            "error": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }


def start_pipeline(settings: Settings) -> dict[str, Any]:
    global _pipeline_thread, _pipeline_last_run
    with _pipeline_lock:
        if _pipeline_is_running():
            return {"status": "already_running", "running": True}
        set_pipeline_paused(settings, False)
        _pipeline_last_run = {"status": "running", "started_at": _utc_iso()}
        _pipeline_thread = threading.Thread(target=_run_pipeline, args=(settings,), name="top-1m-spider-pipeline", daemon=True)
        _pipeline_thread.start()
        return {"status": "started", "running": True}


def pause_pipeline(settings: Settings) -> dict[str, Any]:
    return {**set_pipeline_paused(settings, True), "running": _pipeline_is_running()}


def pipeline_status(settings: Settings) -> dict[str, Any]:
    path = Path(settings.top_1m_pipeline_progress_path)
    control = pipeline_control(settings)
    starts = DEFAULT_START_POSITIONS
    status_doc: dict[str, Any] = {
        "progress_file": str(path),
        "control_file": settings.top_1m_pipeline_control_path,
        "exists": path.exists(),
        "running": _pipeline_is_running(),
        "paused": bool(control.get("paused", False)),
        "last_run": dict(_pipeline_last_run),
        "max_rank": settings.top_1m_pipeline_max_rank,
        "starts": list(starts),
        "processed": 0,
        "updated_at": None,
        "lanes": [],
    }

    progress: dict[str, Any] = {}
    if path.exists():
        try:
            progress = json.loads(path.read_text())
            starts = tuple(int(item) for item in progress.get("starts", starts))
        except Exception as exc:
            status_doc["error"] = str(exc)
            progress = {}

    next_ranks = progress.get("next_ranks") if isinstance(progress.get("next_ranks"), dict) else {}
    ranges = rank_ranges(starts, settings.top_1m_pipeline_max_rank)
    lanes = []
    for start, end in ranges:
        next_rank = max(start, int(next_ranks.get(str(start), start)))
        completed = min(max(next_rank - start, 0), end - start + 1)
        size = max(1, end - start + 1)
        lanes.append(
            {
                "start": start,
                "end": end,
                "next_rank": next_rank,
                "completed": completed,
                "remaining": max(0, end - next_rank + 1),
                "percent": round((completed / size) * 100, 2),
            }
        )

    status_doc.update(
        {
            "starts": list(starts),
            "processed": int(progress.get("processed", 0)) if progress else 0,
            "updated_at": progress.get("updated_at") if progress else None,
            "lanes": lanes,
        }
    )
    return status_doc


def urlscan_pipeline_control(settings: Settings) -> dict[str, Any]:
    path = Path(settings.urlscan_pipeline_control_path)
    if not path.exists():
        return {"paused": False, "control_file": str(path)}
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        return {"paused": False, "control_file": str(path), "error": str(exc)}
    return {"paused": bool(data.get("paused", False)), "control_file": str(path), "updated_at": data.get("updated_at")}


def set_urlscan_pipeline_paused(settings: Settings, paused: bool) -> dict[str, Any]:
    path = Path(settings.urlscan_pipeline_control_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"paused": paused, "updated_at": _utc_iso()}
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return {"status": "paused" if paused else "ready", **data, "control_file": str(path)}


def _urlscan_pipeline_is_running() -> bool:
    return _urlscan_pipeline_thread is not None and _urlscan_pipeline_thread.is_alive()


def _run_urlscan_pipeline(settings: Settings) -> None:
    global _urlscan_pipeline_last_run
    started_at = _utc_iso()
    try:
        storage = MongoStorage(settings)
        storage.ensure_indexes()
        queue = get_preflight_queue(settings)
        summary = queue_urlscan_phishing_jobs(
            storage=storage,
            queue=queue,
            settings=settings,
            progress_path=Path(settings.urlscan_pipeline_progress_path),
            continue_run=True,
            force_new=False,
            should_pause=lambda: urlscan_pipeline_control(settings).get("paused") is True,
        )
        _urlscan_pipeline_last_run = {
            "status": "finished",
            "started_at": started_at,
            "finished_at": _utc_iso(),
            "summary": summary.__dict__,
        }
    except Exception as exc:
        _urlscan_pipeline_last_run = {
            "status": "failed",
            "started_at": started_at,
            "finished_at": _utc_iso(),
            "error": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }


def start_urlscan_pipeline(settings: Settings) -> dict[str, Any]:
    global _urlscan_pipeline_thread, _urlscan_pipeline_last_run
    with _urlscan_pipeline_lock:
        if _urlscan_pipeline_is_running():
            return {"status": "already_running", "running": True}
        set_urlscan_pipeline_paused(settings, False)
        _urlscan_pipeline_last_run = {"status": "running", "started_at": _utc_iso()}
        _urlscan_pipeline_thread = threading.Thread(target=_run_urlscan_pipeline, args=(settings,), name="urlscan-phishing-pipeline", daemon=True)
        _urlscan_pipeline_thread.start()
        return {"status": "started", "running": True}


def pause_urlscan_pipeline(settings: Settings) -> dict[str, Any]:
    return {**set_urlscan_pipeline_paused(settings, True), "running": _urlscan_pipeline_is_running()}


def urlscan_pipeline_status(settings: Settings, storage: MongoStorage | None = None) -> dict[str, Any]:
    path = Path(settings.urlscan_pipeline_progress_path)
    control = urlscan_pipeline_control(settings)
    progress: dict[str, Any] = {}
    if path.exists():
        try:
            progress = json.loads(path.read_text())
        except Exception as exc:
            progress = {"error": str(exc)}
    status_doc = {
        "progress_file": str(path),
        "control_file": settings.urlscan_pipeline_control_path,
        "exists": path.exists(),
        "running": _urlscan_pipeline_is_running(),
        "paused": bool(control.get("paused", False)),
        "last_run": dict(_urlscan_pipeline_last_run),
        "updated_at": progress.get("updated_at"),
        "search_after": progress.get("search_after"),
        "pages": int(progress.get("pages", 0)) if isinstance(progress.get("pages", 0), int) else 0,
        "candidates": int(progress.get("candidates", 0)) if isinstance(progress.get("candidates", 0), int) else 0,
        "queued": int(progress.get("queued", 0)) if isinstance(progress.get("queued", 0), int) else 0,
        "cache_hits": int(progress.get("cache_hits", 0)) if isinstance(progress.get("cache_hits", 0), int) else 0,
        "skipped": int(progress.get("skipped", 0)) if isinstance(progress.get("skipped", 0), int) else 0,
        "queue_counts": {},
    }
    if storage is not None:
        status_doc["queue_counts"] = _safe_call({}, lambda: storage.dataset_queue_counts())
    if progress.get("error"):
        status_doc["error"] = progress["error"]
    return status_doc


def docker_service_statuses() -> dict[str, Any]:
    try:
        import docker

        client = docker.from_env()
        containers = client.containers.list(all=True)
    except Exception as exc:
        return {"available": False, "error": str(exc), "services": []}

    services = []
    for container in containers:
        service = container.labels.get("com.docker.compose.service")
        if service not in LOG_SERVICES:
            continue
        services.append(
            {
                "service": service,
                "name": container.name,
                "status": container.status,
                "image": ", ".join(container.image.tags) if container.image.tags else container.image.short_id,
                "created": container.attrs.get("Created"),
            }
        )
    services.sort(key=lambda item: LOG_SERVICES.index(item["service"]))
    return {"available": True, "services": services}


def docker_logs(service: str, tail: int) -> str:
    if service not in LOG_SERVICES:
        raise HTTPException(status_code=400, detail="Unknown service")

    try:
        import docker

        client = docker.from_env()
        containers = [
            container
            for container in client.containers.list(all=True)
            if container.labels.get("com.docker.compose.service") == service
        ]
    except Exception as exc:
        return f"Docker logs unavailable: {exc}\n"

    if not containers:
        return f"No container found for service '{service}'.\n"

    container = containers[0]
    output = container.logs(tail=max(1, min(tail, 2_000)), timestamps=True)
    return output.decode("utf-8", errors="replace")


def dashboard_payload(storage: MongoStorage, queue: Queue, settings: Settings) -> dict[str, Any]:
    active_statuses = [JOB_QUEUED, JOB_RUNNING]
    terminal_statuses = [JOB_SUCCEEDED, JOB_FAILED, JOB_TIMEOUT]
    return {
        "jobs": {
            "counts": _safe_call({}, storage.job_status_counts),
            "active": [serialize_job(job) for job in _safe_call([], lambda: storage.recent_jobs(active_statuses, 50))],
            "completed": [serialize_job(job) for job in _safe_call([], lambda: storage.recent_jobs(terminal_statuses, 50))],
        },
        "raw": {
            "total": _safe_call(0, storage.raw_capture_count),
            "status_counts": _safe_call({}, storage.raw_status_counts),
        },
        "queue": _safe_call({}, lambda: queue_details(queue)),
        "pipeline": pipeline_status(settings),
        "urlscan_pipeline": urlscan_pipeline_status(settings, storage),
        "docker": docker_service_statuses(),
        "settings": {
            "redis_url": settings.redis_url,
            "mongo_db": settings.mongo_db,
            "mongo_collection": settings.mongo_collection,
            "jobs_collection": settings.mongo_jobs_collection,
            "worker_concurrency": settings.worker_concurrency,
            "preflight_queue_name": settings.preflight_queue_name,
            "preflight_timeout_seconds": settings.preflight_timeout_seconds,
            "pipeline_enqueue_batch_size": settings.pipeline_enqueue_batch_size,
            "rq_job_timeout_seconds": settings.rq_job_timeout_seconds,
            "spider_job_timeout_seconds": settings.spider_job_timeout_seconds,
            "allow_private_urls": settings.allow_private_urls,
        },
    }


def _raw_or_404(storage: MongoStorage, raw_id: str) -> dict[str, Any]:
    raw_doc = storage.get_raw(raw_id)
    if not raw_doc:
        raise HTTPException(status_code=404, detail="Raw capture not found")
    return raw_doc


def _dataset_raw_detail(storage: MongoStorage, raw_id: str) -> dict[str, Any]:
    raw_doc = _raw_or_404(storage, raw_id)
    if raw_doc.get("status") != "ok":
        raise HTTPException(status_code=409, detail="Raw capture is not successful")
    api_document = project_api_result(raw_doc)
    screenshot = raw_doc.get("screenshot") if isinstance(raw_doc.get("screenshot"), dict) else {}
    return {
        "raw_id": str(raw_doc.get("_id")),
        "raw_url": raw_doc.get("submitted_url"),
        "final_url": raw_doc.get("final_url"),
        "urlscan": storage.dataset_source_for_raw(raw_id),
        "api_document": api_document,
        "references": reference_options_for_document(api_document),
        "screenshot_url": f"/dashboard/api/phishing-dataset/raw/{raw_id}/screenshot" if screenshot.get("gridfs_file_id") else None,
    }


def _resolve_curation_blocks(blocks: list[Any], api_document: dict[str, Any]) -> list[dict[str, Any]]:
    resolved_blocks: list[dict[str, Any]] = []
    option_lookup = {item["pointer"]: item for item in reference_options_for_document(api_document)}
    for block in blocks:
        refs = []
        for reference in block.references:
            value = resolve_json_pointer(api_document, reference.pointer)
            option = option_lookup.get(reference.pointer, {"label": reference.pointer})
            preview = option.get("preview")
            if not preview:
                preview = json.dumps(value, ensure_ascii=False)[:240]
            refs.append({"pointer": reference.pointer, "label": option.get("label", reference.pointer), "preview": preview})
        resolved_blocks.append({"text": block.text, "references": refs})
    return resolved_blocks


def dashboard_html() -> str:
    services = "".join(f'<button class="tab" data-service="{service}">{html.escape(service)}</button>' for service in LOG_SERVICES)
    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishTrain Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0c0f0e;
      --panel: #141917;
      --panel-2: #101412;
      --line: #26302c;
      --text: #eef4f0;
      --muted: #94a39a;
      --accent: #4ade80;
      --warn: #facc15;
      --bad: #fb7185;
      --blue: #60a5fa;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }}
    header {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 24px;
      padding: 28px 32px 18px;
      border-bottom: 1px solid var(--line);
      background: #0e1311;
    }}
    h1, h2 {{ margin: 0; font-weight: 650; }}
    h1 {{ font-size: 28px; }}
    h2 {{ font-size: 15px; color: var(--muted); text-transform: uppercase; }}
    main {{ padding: 24px 32px 36px; display: grid; gap: 22px; }}
    .meta {{ color: var(--muted); font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }}
    .metric {{ padding: 16px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .metric .value {{ font-size: 28px; font-weight: 680; margin-top: 6px; }}
    .metric .sub {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
    .columns {{ display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr); gap: 22px; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 560; }}
    td {{ overflow-wrap: anywhere; }}
    tr:last-child td {{ border-bottom: 0; }}
    .status {{ color: var(--accent); font-weight: 620; }}
    .status.failed, .status.timeout {{ color: var(--bad); }}
    .status.running {{ color: var(--blue); }}
    .status.queued {{ color: var(--warn); }}
    .pipeline {{ display: grid; gap: 12px; padding: 16px; }}
    .lane {{ display: grid; grid-template-columns: 150px 1fr 92px; gap: 12px; align-items: center; }}
    .bar {{ height: 9px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 999px; overflow: hidden; }}
    .fill {{ height: 100%; width: 0; background: var(--accent); transition: width 220ms ease; }}
    .tabs {{ display: flex; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line); }}
    .actions {{ display: flex; gap: 8px; align-items: center; }}
    .nav-link {{ color: var(--accent); text-decoration: none; font-size: 13px; }}
    button {{
      min-height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel-2);
      color: var(--text);
      cursor: pointer;
    }}
    button.active {{ border-color: var(--accent); color: var(--accent); }}
    pre {{
      margin: 0;
      min-height: 300px;
      max-height: 520px;
      overflow: auto;
      padding: 16px;
      background: #070908;
      color: #c8d5ce;
      font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space: pre-wrap;
    }}
    .kv {{ display: grid; grid-template-columns: 190px 1fr; gap: 8px 14px; padding: 16px; font-size: 13px; }}
    .kv div:nth-child(odd) {{ color: var(--muted); }}
    .empty {{ padding: 18px 16px; color: var(--muted); font-size: 13px; }}
    @media (max-width: 960px) {{
      header {{ align-items: flex-start; flex-direction: column; padding: 22px 18px 14px; }}
      main {{ padding: 18px; }}
      .grid, .columns {{ grid-template-columns: 1fr; }}
      .lane {{ grid-template-columns: 1fr; gap: 7px; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>PhishTrain Dashboard</h1>
      <div class="meta" id="updated">Waiting for status</div>
    </div>
    <div class="actions"><a class="nav-link" href="/dashboard/phishing-dataset">Dataset Curation</a><div class="meta" id="health">Connected</div></div>
  </header>
  <main>
    <section class="grid" id="metrics"></section>
    <section class="columns">
      <div class="panel">
        <div class="panel-head">
          <div><h2>Top 1M Pipeline</h2><span class="meta" id="pipeline-file"></span></div>
          <div class="actions">
            <button id="pipeline-start">Start</button>
            <button id="pipeline-pause">Pause</button>
          </div>
        </div>
        <div class="pipeline" id="pipeline"></div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <div><h2>URLScan Pipeline</h2><span class="meta" id="urlscan-pipeline-file"></span></div>
          <div class="actions">
            <button id="urlscan-pipeline-start">Start</button>
            <button id="urlscan-pipeline-pause">Pause</button>
          </div>
        </div>
        <div class="pipeline" id="urlscan-pipeline"></div>
      </div>
    </section>
    <section class="panel">
      <div class="panel-head"><h2>Operations</h2><span class="meta">runtime</span></div>
      <div class="kv" id="ops"></div>
    </section>
    <section class="columns">
      <div class="panel">
        <div class="panel-head"><h2>Active Jobs</h2><span class="meta" id="active-count"></span></div>
        <div id="active"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Completed Jobs</h2><span class="meta" id="completed-count"></span></div>
        <div id="completed"></div>
      </div>
    </section>
    <section class="panel">
      <div class="panel-head"><h2>Docker Logs</h2><span class="meta" id="log-service"></span></div>
      <div class="tabs">__SERVICES__</div>
      <pre id="logs">Loading logs...</pre>
    </section>
  </main>
  <script>
    const state = {{ service: "api" }};
    const fmt = value => value === undefined || value === null || value === "" ? "-" : value;
    const number = value => new Intl.NumberFormat().format(value || 0);

    function statusClass(status) {{
      return `status ${{status || ""}}`;
    }}

    function table(rows) {{
      if (!rows.length) return '<div class="empty">No jobs in this group.</div>';
      const body = rows.map(job => `
        <tr>
          <td>${{fmt(job.job_id)}}</td>
          <td><span class="${{statusClass(job.status)}}">${{fmt(job.status)}}</span></td>
          <td>${{fmt(job.submitted_url)}}</td>
          <td>${{fmt(job.updated_at || job.created_at)}}</td>
        </tr>`).join("");
      return `<table><thead><tr><th>Job</th><th>Status</th><th>URL</th><th>Updated</th></tr></thead><tbody>${{body}}</tbody></table>`;
    }}

    function render(data) {{
      document.getElementById("updated").textContent = `Last refresh ${{new Date().toLocaleTimeString()}}`;
      const counts = data.jobs.counts || {{}};
      const rawCounts = data.raw.status_counts || {{}};
      document.getElementById("metrics").innerHTML = [
        ["Queued", counts.queued, `RQ waiting ${{number(data.queue.queued)}}`],
        ["Running", counts.running, `Started ${{number(data.queue.started)}}`],
        ["Completed", counts.succeeded, `Failed ${{number(counts.failed)}} / timeout ${{number(counts.timeout)}}`],
        ["Raw Captures", data.raw.total, Object.entries(rawCounts).map(([k,v]) => `${{k}} ${{number(v)}}`).join(" | ")]
      ].map(([label, value, sub]) => `<div class="metric"><div class="label">${{label}}</div><div class="value">${{number(value)}}</div><div class="sub">${{fmt(sub)}}</div></div>`).join("");

      const pipelineState = data.pipeline.running ? "running" : (data.pipeline.paused ? "paused" : (data.pipeline.last_run?.status || "idle"));
      document.getElementById("pipeline-file").textContent = data.pipeline.exists ? data.pipeline.progress_file : "no progress file";
      document.getElementById("pipeline").innerHTML = `<div class="meta">State: ${pipelineState} | processed ${number(data.pipeline.processed)}</div>` + (data.pipeline.lanes || []).map(lane => `
        <div class="lane">
          <div><strong>${{number(lane.start)}}</strong> to ${{number(lane.end)}}<br><span class="meta">next ${{number(lane.next_rank)}}</span></div>
          <div class="bar"><div class="fill" style="width:${{lane.percent}}%"></div></div>
          <div class="meta">${{lane.percent}}%</div>
        </div>`).join("");

      const urlscan = data.urlscan_pipeline || {};
      const urlscanCounts = urlscan.queue_counts || {};
      const urlscanState = urlscan.running ? "running" : (urlscan.paused ? "paused" : (urlscan.last_run?.status || "idle"));
      document.getElementById("urlscan-pipeline-file").textContent = urlscan.exists ? urlscan.progress_file : "no progress file";
      document.getElementById("urlscan-pipeline").innerHTML = `
        <div class="meta">State: ${urlscanState} | mode single-page scrape | pages ${number(urlscan.pages)} | candidates ${number(urlscan.candidates)}</div>
        <div class="lane">
          <div><strong>${number(urlscan.queued)}</strong> queued<br><span class="meta">cached ${number(urlscan.cache_hits)} / skipped ${number(urlscan.skipped)}</span></div>
          <div class="bar"><div class="fill" style="width:${urlscan.running ? 66 : 0}%"></div></div>
          <div class="meta">ready ${number(urlscanCounts.ready)}</div>
        </div>
        <div class="meta">Search cursor: ${fmt(urlscan.search_after)}</div>`;

      document.getElementById("active-count").textContent = `${{data.jobs.active.length}} shown`;
      document.getElementById("completed-count").textContent = `${{data.jobs.completed.length}} shown`;
      document.getElementById("active").innerHTML = table(data.jobs.active);
      document.getElementById("completed").innerHTML = table(data.jobs.completed);

      const services = (data.docker.services || []).map(s => `${{s.service}}: ${{s.status}}`).join(" | ");
      document.getElementById("ops").innerHTML = Object.entries({
        "Queue": data.queue.name,
        "Preflight queue": data.settings.preflight_queue_name,
        "Redis": data.settings.redis_url,
        "Mongo DB": data.settings.mongo_db,
        "Raw collection": data.settings.mongo_collection,
        "Jobs collection": data.settings.jobs_collection,
        "Worker concurrency": data.settings.worker_concurrency,
        "Pipeline batch cap": data.settings.pipeline_enqueue_batch_size,
        "Preflight timeout": `${{data.settings.preflight_timeout_seconds}}s`,
        "Scrape timeout": `${{data.settings.rq_job_timeout_seconds}}s`,
        "Spider timeout": `${{data.settings.spider_job_timeout_seconds}}s`,
        "Docker": data.docker.available ? services : data.docker.error
      }).map(([key, value]) => `<div>${{key}}</div><div>${{fmt(value)}}</div>`).join("");
    }}

    async function loadStatus() {{
      try {{
        const response = await fetch("/dashboard/api/status", {{ cache: "no-store" }});
        if (!response.ok) throw new Error(`status ${{response.status}}`);
        render(await response.json());
        document.getElementById("health").textContent = "Live";
      }} catch (error) {{
        document.getElementById("health").textContent = `Status unavailable: ${{error.message}}`;
      }}
    }}

    async function loadLogs() {{
      document.getElementById("log-service").textContent = state.service;
      const response = await fetch(`/dashboard/api/logs?service=${{state.service}}&tail=200`, {{ cache: "no-store" }});
      document.getElementById("logs").textContent = await response.text();
    }}

    async function pipelineAction(action) {{
      const response = await fetch(`/dashboard/api/pipeline/${{action}}`, {{ method: "POST", cache: "no-store" }});
      if (!response.ok) {{
        document.getElementById("health").textContent = `Pipeline ${{action}} failed: status ${{response.status}}`;
        return;
      }}
      await loadStatus();
    }}

    async function urlscanPipelineAction(action) {{
      const response = await fetch(`/dashboard/api/urlscan-pipeline/${{action}}`, {{ method: "POST", cache: "no-store" }});
      if (!response.ok) {{
        document.getElementById("health").textContent = `URLScan pipeline ${{action}} failed: status ${{response.status}}`;
        return;
      }}
      await loadStatus();
    }}

    document.querySelectorAll(".tab").forEach(button => {{
      button.addEventListener("click", () => {{
        state.service = button.dataset.service;
        document.querySelectorAll(".tab").forEach(item => item.classList.toggle("active", item === button));
        loadLogs();
      }});
      button.classList.toggle("active", button.dataset.service === state.service);
    }});

    document.getElementById("pipeline-start").addEventListener("click", () => pipelineAction("start"));
    document.getElementById("pipeline-pause").addEventListener("click", () => pipelineAction("pause"));
    document.getElementById("urlscan-pipeline-start").addEventListener("click", () => urlscanPipelineAction("start"));
    document.getElementById("urlscan-pipeline-pause").addEventListener("click", () => urlscanPipelineAction("pause"));

    loadStatus();
    loadLogs();
    setInterval(loadStatus, 5000);
    setInterval(loadLogs, 10000);
  </script>
</body>
</html>"""
    return template.replace("__SERVICES__", services).replace("{{", "{").replace("}}", "}")


def phishing_dataset_html(settings: Settings) -> str:
    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishTrain Dataset Curation</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0c0f0e;
      --panel: #141917;
      --panel-2: #101412;
      --line: #26302c;
      --text: #eef4f0;
      --muted: #94a39a;
      --accent: #4ade80;
      --warn: #facc15;
      --bad: #fb7185;
      --blue: #60a5fa;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      overflow: hidden;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 20px;
      padding: 24px 28px 16px;
      border-bottom: 1px solid var(--line);
      background: #0e1311;
    }
    h1, h2, h3 { margin: 0; font-weight: 650; }
    h1 { font-size: 24px; }
    h2 { font-size: 12px; color: var(--muted); text-transform: uppercase; }
    h3 { font-size: 14px; }
    a { color: var(--accent); text-decoration: none; }
    main {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      min-height: 0;
      overflow: hidden;
    }
    aside, .workspace, .composer { min-height: 0; }
    aside {
      border-right: 1px solid var(--line);
      background: var(--panel-2);
      display: grid;
      grid-template-rows: auto auto 1fr;
    }
    .side-head, .section-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }
    .queue-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1px;
      background: var(--line);
      border-bottom: 1px solid var(--line);
    }
    .stat { background: var(--panel-2); padding: 10px 12px; }
    .stat strong { display: block; font-size: 18px; }
    .stat span, .meta { color: var(--muted); font-size: 12px; }
    .queue {
      overflow: auto;
      padding: 10px;
      display: grid;
      align-content: start;
      gap: 10px;
    }
    .queue-item {
      width: 100%;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 6px;
      text-align: left;
      padding: 11px 10px;
      border: 1px solid transparent;
      border-radius: 8px;
      background: transparent;
      color: var(--text);
      cursor: pointer;
      line-height: 1.35;
      min-height: 76px;
      height: auto;
      overflow: hidden;
    }
    .queue-item:hover, .queue-item.active { background: var(--panel); border-color: var(--line); }
    .queue-item.ready { border-color: rgba(74, 222, 128, .35); }
    .url {
      display: block;
      width: 100%;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
      line-height: 1.35;
    }
    .status { width: fit-content; font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--accent); }
    .status.queued { color: var(--warn); }
    .status.running { color: var(--blue); }
    .status.failed, .status.timeout { color: var(--bad); }
    .workspace {
      display: block;
      min-width: 0;
      overflow: auto;
    }
    .screenshot-wrap {
      background: #070908;
      border-bottom: 1px solid var(--line);
      display: block;
      text-align: center;
      overflow: visible;
      min-height: 360px;
      padding: 16px;
    }
    .screenshot-wrap img {
      width: auto;
      max-width: 100%;
      height: auto;
      max-height: none;
      display: none;
      margin: 0 auto;
    }
    .placeholder { color: var(--muted); font-size: 13px; padding: 18px; text-align: center; }
    .json-panel {
      min-height: 460px;
      border-bottom: 1px solid var(--line);
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      background: #070908;
    }
    .json-tree {
      min-height: 0;
      overflow: auto;
      padding: 12px 14px 18px;
      background: #070908;
      color: #c8d5ce;
      font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .json-node { display: grid; gap: 1px; }
    .json-row {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      min-height: 24px;
      min-width: 0;
      padding: 2px 4px;
      border-radius: 5px;
    }
    .json-row:hover { background: rgba(255, 255, 255, .035); }
    .json-row.selected { background: rgba(74, 222, 128, .11); }
    .twist, .select-ref {
      flex: 0 0 auto;
      min-height: 22px;
      height: 22px;
      padding: 0;
      border-radius: 5px;
      font: inherit;
      color: var(--muted);
      background: transparent;
    }
    .twist { width: 22px; border-color: transparent; }
    .select-ref { width: 22px; border-color: var(--line); }
    .select-ref.selected { color: var(--accent); border-color: var(--accent); }
    .json-key { color: #93c5fd; flex: 0 0 auto; }
    .json-value {
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: normal;
    }
    .json-string { color: #bbf7d0; }
    .json-number { color: #fde68a; }
    .json-boolean { color: #fca5a5; }
    .json-null { color: var(--muted); }
    .json-children { margin-left: 24px; display: grid; gap: 1px; }
    .json-children.collapsed { display: none; }
    .composer {
      background: var(--panel);
      display: grid;
      grid-template-rows: auto auto;
      min-width: 0;
      min-height: 0;
    }
    .blocks {
      overflow: auto;
      padding: 14px;
      display: grid;
      align-content: start;
      gap: 10px;
    }
    .block {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: var(--panel-2);
      display: grid;
      gap: 8px;
    }
    .block p { margin: 0; font-size: 13px; line-height: 1.45; white-space: pre-wrap; overflow-wrap: anywhere; }
    .block-meta { color: var(--muted); font-size: 11px; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip {
      border: 1px solid rgba(74, 222, 128, .4);
      color: var(--accent);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 11px;
      max-width: 100%;
      overflow-wrap: anywhere;
    }
    .editor {
      border-top: 1px solid var(--line);
      padding: 14px;
      display: grid;
      gap: 10px;
    }
    textarea {
      width: 100%;
      min-height: 130px;
      resize: vertical;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #070908;
      color: var(--text);
      padding: 10px;
      font: 13px/1.45 inherit;
    }
    .judgment-grid {
      display: grid;
      grid-template-columns: 160px 130px minmax(0, 1fr);
      gap: 10px;
      align-items: end;
    }
    .field {
      display: grid;
      gap: 5px;
      min-width: 0;
    }
    .field label {
      color: var(--muted);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    select, input {
      width: 100%;
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #070908;
      color: var(--text);
      padding: 0 10px;
      font: 13px/1.45 inherit;
    }
    .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    button {
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel-2);
      color: var(--text);
      cursor: pointer;
      padding: 0 12px;
    }
    button.primary { border-color: var(--accent); color: var(--accent); }
    button.danger { border-color: rgba(251, 113, 133, .55); color: var(--bad); }
    button:disabled { cursor: not-allowed; opacity: .45; }
    @media (max-width: 1180px) {
      body { height: auto; min-height: 100vh; overflow: auto; }
      main { min-height: 0; overflow: visible; grid-template-columns: 1fr; }
      aside, .composer { border: 0; border-bottom: 1px solid var(--line); }
      .workspace { min-height: 720px; overflow: visible; }
      .judgment-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Phishing Dataset Curation</h1>
      <div class="meta" id="health">Loading ready captures</div>
    </div>
    <a href="/dashboard">Dashboard</a>
  </header>
  <main>
    <aside>
      <div class="side-head">
        <div><h2>Ready Captures</h2><span class="meta" id="queue-updated">Waiting</span></div>
      </div>
      <div class="queue-stats">
        <div class="stat"><strong id="queued-count">0</strong><span>queued</span></div>
        <div class="stat"><strong id="running-count">0</strong><span>running</span></div>
        <div class="stat"><strong id="ready-count">0</strong><span>ready</span></div>
      </div>
      <div class="queue" id="queue"></div>
    </aside>
    <section class="workspace">
      <div class="screenshot-wrap">
        <img id="screenshot" alt="Captured website screenshot">
        <div class="placeholder" id="screenshot-placeholder">Select a ready capture from the queue.</div>
      </div>
      <div class="json-panel">
        <div class="section-head">
          <h2>LLM Input JSON</h2>
          <span class="meta" id="ref-count">0 selected</span>
        </div>
        <div class="json-tree" id="json-tree">No capture selected.</div>
      </div>
      <section class="composer">
        <div class="section-head">
          <h2>Response</h2>
          <span class="meta" id="response-status">No capture selected</span>
        </div>
        <div class="blocks" id="blocks"></div>
        <div class="editor">
          <div class="judgment-grid">
            <div class="field">
              <label for="verdict">Verdict</label>
              <select id="verdict">
                <option value="phishing">Phishing</option>
                <option value="benign">Benign</option>
              </select>
            </div>
            <div class="field">
              <label for="confidence">Confidence</label>
              <input id="confidence" type="number" min="0" max="1" step="0.01" value="1">
            </div>
            <div class="field">
              <label for="organization-brand">Organization / brand</label>
              <input id="organization-brand" type="text" maxlength="512" placeholder="Brand or organization being impersonated">
            </div>
          </div>
          <textarea id="paragraph" placeholder="Write a sentence or paragraph for this phishing example."></textarea>
          <div class="chips" id="selected-refs"></div>
          <div class="actions">
            <button id="add-block">Add paragraph</button>
            <button class="primary" id="save">Save</button>
            <button class="danger" id="skip">Skip</button>
          </div>
        </div>
      </section>
    </section>
  </main>
  <script>
    const state = { items: [], activeRawId: null, detail: null, selectedRefs: new Set(), blocks: [], referenceIndex: new Map() };
    const el = id => document.getElementById(id);

    function setText(id, text) { el(id).textContent = text == null ? "" : String(text); }
    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
    function fmt(value) { return value == null || value === "" ? "-" : String(value); }
    function pointerEscape(value) { return String(value).replaceAll("~", "~0").replaceAll("/", "~1"); }
    function pointerFor(path) { return "/" + path.map(pointerEscape).join("/"); }
    function labelForPointer(pointer) {
      const match = state.referenceIndex.get(pointer);
      if (match?.label) return match.label;
      return pointer.slice(1).split("/").map(part => part.replaceAll("~1", "/").replaceAll("~0", "~")).reduce((label, part) => {
        return /^\\d+$/.test(part) ? `${label}[${part}]` : (label ? `${label}.${part}` : part);
      }, "");
    }
    function previewValue(value) {
      const text = typeof value === "string" ? value : JSON.stringify(value);
      if (text === undefined) return "";
      const compact = text.replace(/\\s+/g, " ").trim();
      return compact.length > 240 ? `${compact.slice(0, 237)}...` : compact;
    }
    async function responseBody(response) {
      const text = await response.text();
      if (!text) return {};
      try { return JSON.parse(text); }
      catch (_) { return { detail: text }; }
    }
    function errorMessage(data, fallback) {
      if (data?.detail?.message) return data.detail.message;
      if (typeof data?.detail === "string") return data.detail;
      if (data?.message) return data.message;
      return fallback;
    }

    function renderStats(counts) {
      setText("queued-count", counts?.queued || 0);
      setText("running-count", counts?.running || 0);
      setText("ready-count", counts?.ready || 0);
    }

    function renderQueue() {
      const queue = el("queue");
      clear(queue);
      if (!state.items.length) {
        const empty = document.createElement("div");
        empty.className = "placeholder";
        empty.textContent = "No dataset jobs yet.";
        queue.appendChild(empty);
        return;
      }
      for (const item of state.items) {
        const button = document.createElement("button");
        button.className = `queue-item ${item.status || ""}`;
        if (item.raw_id && item.raw_id === state.activeRawId) button.classList.add("active");
        button.disabled = item.status !== "ready";
        button.addEventListener("click", () => loadRaw(item.raw_id));
        const status = document.createElement("span");
        status.className = `status ${item.status || ""}`;
        status.textContent = item.status || "unknown";
        const url = document.createElement("span");
        url.className = "url";
        url.textContent = item.submitted_url || item.final_url || item.job_id || "-";
        const meta = document.createElement("span");
        meta.className = "meta";
        meta.textContent = item.urlscan?.scan_id ? `scan ${item.urlscan.scan_id}` : fmt(item.updated_at);
        button.append(status, url, meta);
        queue.appendChild(button);
      }
    }

    function renderSelectedRefs() {
      const wrap = el("selected-refs");
      clear(wrap);
      const refs = Array.from(state.selectedRefs).map(pointer => ({
        pointer,
        label: labelForPointer(pointer),
      }));
      setText("ref-count", `${refs.length} selected`);
      for (const ref of refs) {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.textContent = ref.label;
        wrap.appendChild(chip);
      }
    }

    function valueClass(value) {
      if (value === null) return "json-null";
      if (typeof value === "string") return "json-string";
      if (typeof value === "number") return "json-number";
      if (typeof value === "boolean") return "json-boolean";
      return "";
    }

    function scalarText(value) {
      if (typeof value === "string") return JSON.stringify(value);
      if (value === null) return "null";
      return String(value);
    }

    function renderJsonTree() {
      const root = el("json-tree");
      clear(root);
      if (!state.detail?.api_document) {
        root.textContent = "No capture selected.";
        return;
      }
      root.appendChild(jsonNode(state.detail.api_document, [], "document"));
      renderSelectedRefs();
    }

    function jsonNode(value, path, keyLabel) {
      const isArray = Array.isArray(value);
      const isObject = value && typeof value === "object" && !isArray;
      const isContainer = isArray || isObject;
      const pointer = path.length ? pointerFor(path) : "";
      const wrapper = document.createElement("div");
      wrapper.className = "json-node";

      const row = document.createElement("div");
      row.className = "json-row";
      if (pointer && state.selectedRefs.has(pointer)) row.classList.add("selected");

      const twist = document.createElement("button");
      twist.className = "twist";
      twist.type = "button";
      twist.textContent = isContainer ? "v" : "";
      twist.disabled = !isContainer;
      row.appendChild(twist);

      if (pointer) {
        const select = document.createElement("button");
        select.className = "select-ref";
        if (state.selectedRefs.has(pointer)) select.classList.add("selected");
        select.type = "button";
        select.title = `Reference ${labelForPointer(pointer)}`;
        select.textContent = state.selectedRefs.has(pointer) ? "x" : "+";
        select.addEventListener("click", event => {
          event.stopPropagation();
          if (state.selectedRefs.has(pointer)) state.selectedRefs.delete(pointer);
          else state.selectedRefs.add(pointer);
          renderJsonTree();
        });
        row.appendChild(select);
      } else {
        const spacer = document.createElement("span");
        spacer.style.width = "22px";
        row.appendChild(spacer);
      }

      const key = document.createElement("span");
      key.className = "json-key";
      key.textContent = `${keyLabel}:`;
      row.appendChild(key);

      const renderedValue = document.createElement("span");
      renderedValue.className = `json-value ${valueClass(value)}`;
      if (isContainer) {
        const size = isArray ? value.length : Object.keys(value).length;
        renderedValue.textContent = isArray ? `Array(${size})` : `Object(${size})`;
      } else {
        renderedValue.textContent = scalarText(value);
      }
      row.appendChild(renderedValue);
      wrapper.appendChild(row);

      if (isContainer) {
        const children = document.createElement("div");
        children.className = "json-children";
        const entries = isArray ? value.map((item, index) => [String(index), item]) : Object.entries(value);
        for (const [childKey, childValue] of entries) {
          children.appendChild(jsonNode(childValue, [...path, childKey], childKey));
        }
        twist.addEventListener("click", () => {
          children.classList.toggle("collapsed");
          twist.textContent = children.classList.contains("collapsed") ? ">" : "v";
        });
        row.addEventListener("dblclick", () => twist.click());
        wrapper.appendChild(children);
      }
      return wrapper;
    }

    function renderBlocks() {
      const list = el("blocks");
      clear(list);
      if (!state.blocks.length) {
        const empty = document.createElement("div");
        empty.className = "placeholder";
        empty.textContent = "No paragraphs added.";
        list.appendChild(empty);
        return;
      }
      state.blocks.forEach((block, index) => {
        const item = document.createElement("div");
        item.className = "block";
        const text = document.createElement("p");
        text.textContent = block.text;
        const meta = document.createElement("div");
        meta.className = "block-meta";
        meta.textContent = `${block.references.length} reference${block.references.length === 1 ? "" : "s"}`;
        const chips = document.createElement("div");
        chips.className = "chips";
        for (const ref of block.references) {
          const chip = document.createElement("span");
          chip.className = "chip";
          chip.textContent = ref.label || ref.pointer;
          chips.appendChild(chip);
        }
        const remove = document.createElement("button");
        remove.textContent = "Remove";
        remove.addEventListener("click", () => {
          state.blocks.splice(index, 1);
          renderBlocks();
        });
        item.append(text, meta, chips, remove);
        list.appendChild(item);
      });
    }

    function addBlockFromEditor() {
      const text = el("paragraph").value.trim();
      if (!text) return false;
      const refs = (state.detail?.references || [])
        .filter(ref => state.selectedRefs.has(ref.pointer))
        .map(ref => ({ pointer: ref.pointer, label: ref.label, preview: ref.preview }));
      for (const pointer of state.selectedRefs) {
        if (!refs.find(ref => ref.pointer === pointer)) {
          let value = null;
          try {
            value = pointer.slice(1).split("/").reduce((current, rawPart) => {
              const part = rawPart.replaceAll("~1", "/").replaceAll("~0", "~");
              return Array.isArray(current) ? current[Number(part)] : current[part];
            }, state.detail.api_document);
          } catch (_) {
            value = null;
          }
          refs.push({ pointer, label: labelForPointer(pointer), preview: previewValue(value) });
        }
      }
      state.blocks.push({ text, references: refs });
      el("paragraph").value = "";
      state.selectedRefs.clear();
      renderJsonTree();
      renderBlocks();
      return true;
    }

    async function loadQueue() {
      try {
        const response = await fetch("/dashboard/api/phishing-dataset/queue", { cache: "no-store" });
        const data = await responseBody(response);
        if (!response.ok) throw new Error(errorMessage(data, `status ${response.status}`));
        state.items = data.items || [];
        renderStats(data.counts || {});
        renderQueue();
        setText("queue-updated", `Updated ${new Date().toLocaleTimeString()}`);
        setText("health", `${state.items.length} ready captures`);
        if (!state.activeRawId) {
          const ready = state.items.find(item => item.status === "ready" && item.raw_id);
          if (ready) loadRaw(ready.raw_id);
        }
      } catch (error) {
        setText("health", `Queue unavailable: ${error.message}`);
      }
    }

    async function loadRaw(rawId) {
      if (!rawId) return;
      const response = await fetch(`/dashboard/api/phishing-dataset/raw/${rawId}`, { cache: "no-store" });
      const data = await responseBody(response);
      if (!response.ok) {
        setText("health", errorMessage(data, `Could not load raw ${rawId}`));
        return;
      }
      state.activeRawId = rawId;
      state.detail = data;
      state.referenceIndex = new Map((data.references || []).map(ref => [ref.pointer, ref]));
      state.selectedRefs.clear();
      state.blocks = [];
      setText("response-status", "Editing capture");
      const image = el("screenshot");
      const placeholder = el("screenshot-placeholder");
      if (data.screenshot_url) {
        image.onload = () => {
          image.style.display = "block";
          placeholder.style.display = "none";
          if (image.naturalWidth <= 1 && image.naturalHeight <= 1) {
            placeholder.style.display = "block";
            placeholder.textContent = "Screenshot loaded, but the captured image is very small.";
          }
        };
        image.onerror = () => {
          image.style.display = "none";
          placeholder.style.display = "block";
          placeholder.textContent = "Screenshot could not be loaded.";
        };
        image.src = `${data.screenshot_url}?t=${Date.now()}`;
      } else {
        image.removeAttribute("src");
        image.style.display = "none";
        placeholder.style.display = "block";
        placeholder.textContent = "No screenshot stored for this capture.";
      }
      renderQueue();
      renderJsonTree();
      renderBlocks();
    }

    async function saveDecision() {
      if (!state.activeRawId) return;
      if (el("paragraph").value.trim()) addBlockFromEditor();
      if (!state.blocks.length) {
        setText("health", "Add at least one paragraph before saving.");
        return;
      }
      const confidence = Number(el("confidence").value);
      const organizationBrand = el("organization-brand").value.trim();
      if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
        setText("health", "Confidence must be a number from 0 to 1.");
        return;
      }
      if (!organizationBrand) {
        setText("health", "Organization / brand is required.");
        return;
      }
      const responseText = state.blocks.map(block => block.text).join("\\n\\n");
      const payload = {
        raw_id: state.activeRawId,
        verdict: el("verdict").value,
        confidence,
        organization_brand: organizationBrand,
        response_text: responseText,
        blocks: state.blocks.map(block => ({
          text: block.text,
          references: block.references.map(ref => ({ pointer: ref.pointer }))
        }))
      };
      const response = await fetch("/dashboard/api/phishing-dataset/curate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        cache: "no-store"
      });
      if (!response.ok) {
        const data = await responseBody(response);
        setText("health", errorMessage(data, `Save failed: ${response.status}`));
        return;
      }
      resetActive();
      await loadQueue();
      setText("health", "Curation saved.");
    }

    async function skipDecision() {
      if (!state.activeRawId) return;
      const response = await fetch("/dashboard/api/phishing-dataset/skip", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ raw_id: state.activeRawId }),
        cache: "no-store"
      });
      if (!response.ok) {
        const data = await responseBody(response);
        setText("health", errorMessage(data, `Skip failed: ${response.status}`));
        return;
      }
      resetActive();
      await loadQueue();
      setText("health", "Capture skipped.");
    }

    function resetActive() {
      state.activeRawId = null;
      state.detail = null;
      state.selectedRefs.clear();
      state.blocks = [];
      el("verdict").value = "phishing";
      el("confidence").value = "1";
      el("organization-brand").value = "";
      setText("response-status", "No capture selected");
      renderJsonTree();
      renderBlocks();
      const image = el("screenshot");
      image.removeAttribute("src");
      image.style.display = "none";
      el("screenshot-placeholder").style.display = "block";
      el("screenshot-placeholder").textContent = "Select a ready capture from the queue.";
    }

    el("add-block").addEventListener("click", addBlockFromEditor);
    el("save").addEventListener("click", saveDecision);
    el("skip").addEventListener("click", skipDecision);

    loadQueue();
    setInterval(loadQueue, 5000);
  </script>
</body>
</html>"""
    return template


def create_dashboard_router(storage_dependency: Callable[..., MongoStorage], queue_dependency: Callable[..., Queue]) -> APIRouter:
    router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_dashboard_auth)])

    @router.get("", response_class=HTMLResponse)
    def dashboard_page() -> HTMLResponse:
        return HTMLResponse(dashboard_html())

    @router.get("/phishing-dataset", response_class=HTMLResponse)
    def dashboard_phishing_dataset_page(settings: Settings = Depends(get_settings)) -> HTMLResponse:
        return HTMLResponse(phishing_dataset_html(settings))

    @router.get("/api/status")
    def dashboard_status(
        settings: Settings = Depends(get_settings),
        storage: MongoStorage = Depends(storage_dependency),
        queue: Queue = Depends(queue_dependency),
    ):
        return dashboard_payload(storage, queue, settings)

    @router.get("/api/logs", response_class=PlainTextResponse)
    def dashboard_logs(
        service: str = Query("api"),
        tail: int | None = Query(None, ge=1, le=2_000),
        settings: Settings = Depends(get_settings),
    ) -> PlainTextResponse:
        return PlainTextResponse(docker_logs(service, tail or settings.dashboard_log_tail))

    @router.get("/api/phishing-dataset/queue")
    def dashboard_phishing_dataset_queue(
        settings: Settings = Depends(get_settings),
        storage: MongoStorage = Depends(storage_dependency),
    ):
        counts = storage.dataset_queue_counts()
        return {
            "target": settings.dataset_queue_target,
            "counts": counts,
            "items": storage.dataset_ready_items(limit=settings.dataset_queue_target),
        }

    @router.get("/api/phishing-dataset/raw/{raw_id}")
    def dashboard_phishing_dataset_raw(raw_id: str, storage: MongoStorage = Depends(storage_dependency)):
        return _dataset_raw_detail(storage, raw_id)

    @router.get("/api/phishing-dataset/raw/{raw_id}/screenshot")
    def dashboard_phishing_dataset_screenshot(raw_id: str, storage: MongoStorage = Depends(storage_dependency)):
        screenshot = storage.get_raw_screenshot(raw_id)
        if not screenshot:
            raise HTTPException(status_code=404, detail="Screenshot not found")
        data, metadata = screenshot
        return StreamingResponse(io.BytesIO(data), media_type=metadata.get("content_type") or "image/webp")

    @router.post("/api/phishing-dataset/curate")
    def dashboard_phishing_dataset_curate(payload: CuratedDatasetRequest, storage: MongoStorage = Depends(storage_dependency)):
        raw_doc = _raw_or_404(storage, payload.raw_id)
        if raw_doc.get("status") != "ok":
            raise HTTPException(status_code=409, detail="Raw capture is not successful")
        api_document = project_api_result(raw_doc)
        try:
            blocks = _resolve_curation_blocks(payload.blocks, api_document)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return storage.insert_curated_decision(
            raw_doc=raw_doc,
            decision="accepted",
            api_document=api_document,
            verdict=payload.verdict,
            confidence=payload.confidence,
            organization_brand=payload.organization_brand,
            response_text=payload.response_text,
            blocks=blocks,
        )

    @router.post("/api/phishing-dataset/skip")
    def dashboard_phishing_dataset_skip(payload: SkipDatasetRequest, storage: MongoStorage = Depends(storage_dependency)):
        raw_doc = _raw_or_404(storage, payload.raw_id)
        api_document = project_api_result(raw_doc)
        return storage.insert_curated_decision(
            raw_doc=raw_doc,
            decision="skipped",
            api_document=api_document,
            reason=payload.reason,
        )

    @router.post("/api/pipeline/start")
    def dashboard_pipeline_start(settings: Settings = Depends(get_settings)):
        return start_pipeline(settings)

    @router.post("/api/pipeline/pause")
    def dashboard_pipeline_pause(settings: Settings = Depends(get_settings)):
        return pause_pipeline(settings)

    @router.post("/api/urlscan-pipeline/start")
    def dashboard_urlscan_pipeline_start(settings: Settings = Depends(get_settings)):
        return start_urlscan_pipeline(settings)

    @router.post("/api/urlscan-pipeline/pause")
    def dashboard_urlscan_pipeline_pause(settings: Settings = Depends(get_settings)):
        return pause_urlscan_pipeline(settings)

    return router
