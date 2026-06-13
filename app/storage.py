from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime
from typing import Any

from bson import ObjectId
from gridfs import GridFSBucket
from gridfs.errors import NoFile
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import CollectionInvalid

from app.extractors import extract_html_artifacts
from app.models import JOB_FAILED, JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_TIMEOUT, empty_format_result, utc_now
from app.rdap import summarize_rdap_whois
from app.settings import Settings
from app.url_safety import UrlValidationError, cache_key_for_url


def _canonical_url_key(raw_doc: dict[str, Any]) -> str | None:
    for key in ("submitted_url", "final_url"):
        value = raw_doc.get(key)
        if not value:
            continue
        try:
            return cache_key_for_url(str(value))
        except UrlValidationError:
            continue
    cache_key = raw_doc.get("cache_key")
    return str(cache_key) if cache_key else None


def _metadata(raw_doc: dict[str, Any]) -> dict[str, Any]:
    value = raw_doc.get("metadata")
    return value if isinstance(value, dict) else {}


def _object_id(value: Any) -> ObjectId | None:
    if isinstance(value, ObjectId):
        return value
    if isinstance(value, str) and ObjectId.is_valid(value):
        return ObjectId(value)
    return None


def _jsonable(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _pointer_unescape(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def _pointer_for_path(path: list[str]) -> str:
    return "/" + "/".join(_pointer_escape(part) for part in path)


def _label_for_path(path: list[str]) -> str:
    label = ""
    for part in path:
        if part.isdigit():
            label += f"[{part}]"
        else:
            label = part if not label else f"{label}.{part}"
    return label or "$"


def _preview(value: Any, limit: int = 240) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise ValueError("Reference pointer must start with /")
    current = document
    for raw_part in pointer.split("/")[1:]:
        part = _pointer_unescape(raw_part)
        if isinstance(current, list):
            if not part.isdigit():
                raise ValueError(f"Invalid list reference: {pointer}")
            index = int(part)
            if index >= len(current):
                raise ValueError(f"Reference is out of range: {pointer}")
            current = current[index]
        elif isinstance(current, dict):
            if part not in current:
                raise ValueError(f"Reference does not exist: {pointer}")
            current = current[part]
        else:
            raise ValueError(f"Reference cannot be resolved: {pointer}")
    return current


def reference_options_for_document(document: dict[str, Any]) -> list[dict[str, str]]:
    options: list[dict[str, str]] = []

    def walk(value: Any, path: list[str]) -> None:
        if isinstance(value, dict):
            if not value and path:
                options.append({"pointer": _pointer_for_path(path), "label": _label_for_path(path), "preview": "{}"})
            for key in sorted(value):
                walk(value[key], [*path, str(key)])
            return
        if isinstance(value, list):
            if not value and path:
                options.append({"pointer": _pointer_for_path(path), "label": _label_for_path(path), "preview": "[]"})
            for index, item in enumerate(value):
                walk(item, [*path, str(index)])
            return
        if path:
            options.append({"pointer": _pointer_for_path(path), "label": _label_for_path(path), "preview": _preview(value)})

    walk(document, [])
    return options


def project_api_result(raw_doc: dict[str, Any] | None) -> dict[str, Any]:
    if not raw_doc:
        return empty_format_result("")
    metadata = _metadata(raw_doc)
    submitted_url = raw_doc.get("submitted_url", "")
    final_url = raw_doc.get("final_url") or submitted_url
    result = empty_format_result(submitted_url, final_url)

    result["redirect_chain"] = raw_doc.get("redirect_chain") or metadata.get("redirect_chain") or result["redirect_chain"]
    result["headers"] = raw_doc.get("headers") or metadata.get("headers") or result["headers"]
    result["tls"] = raw_doc.get("tls") or metadata.get("tls") or result["tls"]

    rdap_whois = raw_doc.get("rdap_whois")
    if isinstance(rdap_whois, dict) and ("raw" in rdap_whois or "lookup_url" in rdap_whois):
        result["rdap_whois"] = summarize_rdap_whois(rdap_whois)
    elif isinstance(rdap_whois, dict):
        result["rdap_whois"] = rdap_whois

    if isinstance(raw_doc.get("downloads"), dict):
        result["downloads"] = raw_doc["downloads"]

    html = raw_doc.get("html")
    if isinstance(html, str):
        result["html"] = extract_html_artifacts(
            html,
            final_url,
            visible_text=str(metadata.get("visible_text") or ""),
            title=str(metadata.get("title") or ""),
        )
    elif isinstance(html, dict):
        result["html"] = html

    if "spider_child_raw_ids" in raw_doc:
        result["spider_child_raw_ids"] = raw_doc["spider_child_raw_ids"]
    return _jsonable(result)


def serialize_job(job: dict[str, Any]) -> dict[str, Any]:
    visible = {
        "job_id": job.get("job_id"),
        "status": job.get("status"),
        "cache_hit": bool(job.get("cache_hit", False)),
        "submitted_url": job.get("submitted_url"),
        "result_url": f"/jobs/{job.get('job_id')}/result",
        "error": job.get("error"),
        "raw_id": job.get("raw_id"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }
    return _jsonable({key: value for key, value in visible.items() if value is not None})


class MongoStorage:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5_000)
        self.db = self.client[settings.mongo_db]
        self.raw = self.db[settings.mongo_collection]
        self.jobs = self.db[settings.mongo_jobs_collection]
        self.curated = self.db[settings.mongo_curated_collection]
        self.screenshot_bucket = GridFSBucket(self.db, bucket_name=settings.screenshot_bucket)

    def ping(self) -> None:
        self.client.admin.command("ping")

    def ensure_indexes(self) -> None:
        existing = set(self.db.list_collection_names())
        if self.settings.mongo_collection not in existing:
            try:
                self.db.create_collection(self.settings.mongo_collection)
            except CollectionInvalid:
                pass
        if self.settings.mongo_jobs_collection not in existing:
            try:
                self.db.create_collection(self.settings.mongo_jobs_collection)
            except CollectionInvalid:
                pass
        if self.settings.mongo_curated_collection not in existing:
            try:
                self.db.create_collection(self.settings.mongo_curated_collection)
            except CollectionInvalid:
                pass

        self.raw.create_index([("url_key", ASCENDING)], unique=True, sparse=True)
        self.raw.create_index([("cache_keys", ASCENDING), ("fetched_at", DESCENDING)])
        self.raw.create_index([("cache_key", ASCENDING), ("fetched_at", DESCENDING)])
        self.raw.create_index([("submitted_url", ASCENDING)])
        self.raw.create_index([("final_url", ASCENDING)])
        self.jobs.create_index([("job_id", ASCENDING)], unique=True)
        self.jobs.create_index([("status", ASCENDING), ("created_at", DESCENDING)])
        self.jobs.create_index([("dataset.kind", ASCENDING), ("updated_at", DESCENDING)])
        self.jobs.create_index([("dataset.urlscan.scan_id", ASCENDING)], sparse=True)
        self.curated.create_index([("raw_id", ASCENDING)], unique=True, sparse=True)
        self.curated.create_index([("decision", ASCENDING), ("created_at", DESCENDING)])
        self.curated.create_index([("urlscan.scan_id", ASCENDING)], sparse=True)

    def find_latest_successful(self, cache_key: str) -> dict[str, Any] | None:
        return self.raw.find_one(
            {"$or": [{"cache_keys": cache_key}, {"cache_key": cache_key}], "status": "ok"},
            sort=[("fetched_at", DESCENDING)],
        )

    def get_raw(self, raw_id: Any) -> dict[str, Any] | None:
        oid = _object_id(raw_id)
        if not oid:
            return None
        return self.raw.find_one({"_id": oid})

    def insert_raw(
        self,
        raw_doc: dict[str, Any],
        screenshot_webp: bytes | None = None,
        screenshot_metadata: dict[str, Any] | None = None,
    ) -> ObjectId:
        doc = dict(raw_doc)
        doc.setdefault("fetched_at", utc_now())
        url_key = _canonical_url_key(doc)
        if url_key:
            doc["url_key"] = url_key

        existing = self.raw.find_one({"url_key": url_key}) if url_key else None
        raw_id = existing["_id"] if existing else ObjectId()
        doc["_id"] = raw_id

        cache_keys = set(existing.get("cache_keys", []) if existing else [])
        if existing and existing.get("cache_key"):
            cache_keys.add(existing["cache_key"])
        if doc.get("cache_key"):
            cache_keys.add(doc["cache_key"])
        if url_key:
            cache_keys.add(url_key)
        doc["cache_keys"] = sorted(str(item) for item in cache_keys if item)

        if screenshot_webp:
            if existing and existing.get("screenshot", {}).get("gridfs_file_id"):
                try:
                    self.screenshot_bucket.delete(existing["screenshot"]["gridfs_file_id"])
                except Exception:
                    pass
            metadata = {
                "submitted_url": doc.get("submitted_url"),
                "final_url": doc.get("final_url"),
                "cache_key": doc.get("cache_key"),
                "raw_id": str(raw_id),
                "content_type": "image/webp",
                "format": "webp",
                **(screenshot_metadata or {}),
            }
            filename = f"{raw_id}.webp"
            file_id = self.screenshot_bucket.upload_from_stream(
                filename,
                io.BytesIO(screenshot_webp),
                metadata=metadata,
            )
            doc["screenshot"] = {
                "bucket": self.settings.screenshot_bucket,
                "gridfs_file_id": file_id,
                "filename": filename,
                "content_type": "image/webp",
                "format": "webp",
                "size_bytes": len(screenshot_webp),
                "sha256": hashlib.sha256(screenshot_webp).hexdigest(),
                "width": screenshot_metadata.get("width") if screenshot_metadata else None,
                "height": screenshot_metadata.get("height") if screenshot_metadata else None,
            }
        elif existing and existing.get("screenshot"):
            doc["screenshot"] = existing["screenshot"]

        self.raw.replace_one({"_id": raw_id}, doc, upsert=True)
        return raw_id

    def create_job(
        self,
        *,
        job_id: str,
        submitted_url: str,
        cache_key: str,
        status: str = JOB_QUEUED,
        cache_hit: bool = False,
        raw_id: Any = None,
        dataset: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        doc = {
            "job_id": job_id,
            "submitted_url": submitted_url,
            "cache_key": cache_key,
            "status": status,
            "cache_hit": cache_hit,
            "created_at": now,
            "updated_at": now,
        }
        if raw_id is not None:
            doc["raw_id"] = raw_id
            doc["finished_at"] = now
        if dataset:
            doc["dataset"] = dataset
        self.jobs.insert_one(doc)
        return doc

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self.jobs.find_one({"job_id": job_id})

    def job_status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in (JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_FAILED, JOB_TIMEOUT)}
        for row in self.jobs.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]):
            status = row.get("_id")
            if status:
                counts[str(status)] = int(row.get("count", 0))
        return counts

    def recent_jobs(self, statuses: list[str] | None = None, limit: int = 25) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if statuses:
            query["status"] = {"$in": statuses}
        return list(self.jobs.find(query).sort("updated_at", DESCENDING).limit(limit))

    def raw_status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for row in self.raw.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]):
            status = str(row.get("_id") or "unknown")
            counts[status] = int(row.get("count", 0))
        return counts

    def raw_capture_count(self) -> int:
        return int(self.raw.count_documents({}))

    def dataset_decision_exists(self, *, raw_id: Any = None, scan_id: str | None = None, url: str | None = None) -> bool:
        clauses: list[dict[str, Any]] = []
        oid = _object_id(raw_id)
        if oid:
            clauses.append({"raw_id": oid})
        if scan_id:
            clauses.append({"urlscan.scan_id": scan_id})
        if url:
            clauses.extend([{"raw_url": url}, {"final_url": url}, {"urlscan.submitted_url": url}, {"urlscan.page_url": url}])
        return bool(clauses and self.curated.find_one({"$or": clauses}, {"_id": 1}))

    def dataset_candidate_exists(self, *, scan_id: str | None = None, url: str | None = None) -> bool:
        if self.dataset_decision_exists(scan_id=scan_id, url=url):
            return True
        clauses: list[dict[str, Any]] = []
        if scan_id:
            clauses.append({"dataset.urlscan.scan_id": scan_id})
        if url:
            clauses.append({"submitted_url": url})
        if clauses and self.jobs.find_one({"dataset.kind": "urlscan_phishing", "$or": clauses}, {"_id": 1}):
            return True
        return False

    def dataset_queue_counts(self) -> dict[str, int]:
        counts = {"queued": 0, "running": 0, "ready": 0, "failed": 0, "timeout": 0}
        for item in self.dataset_queue_items(limit=500):
            status = item.get("status")
            if status in counts:
                counts[status] += 1
        return counts

    def dataset_ready_count(self) -> int:
        return len(self.dataset_ready_items(limit=500))

    def dataset_queue_items(self, limit: int = 50) -> list[dict[str, Any]]:
        query = {"dataset.kind": "urlscan_phishing", "status": {"$in": [JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_FAILED, JOB_TIMEOUT]}}
        jobs = list(self.jobs.find(query).sort("updated_at", DESCENDING).limit(limit * 4))
        items: list[dict[str, Any]] = []
        for job in jobs:
            dataset = job.get("dataset") if isinstance(job.get("dataset"), dict) else {}
            urlscan = dataset.get("urlscan") if isinstance(dataset.get("urlscan"), dict) else {}
            raw_id = job.get("raw_id")
            status = job.get("status")
            raw_doc = None
            if status == JOB_SUCCEEDED and raw_id:
                raw_doc = self.get_raw(raw_id)
                if not raw_doc or raw_doc.get("status") != "ok":
                    continue
                if self.dataset_decision_exists(raw_id=raw_id, scan_id=urlscan.get("scan_id"), url=job.get("submitted_url")):
                    continue
                status = "ready"
            elif self.dataset_decision_exists(scan_id=urlscan.get("scan_id"), url=job.get("submitted_url")):
                continue

            item = {
                "job_id": job.get("job_id"),
                "status": status,
                "submitted_url": job.get("submitted_url"),
                "updated_at": job.get("updated_at"),
                "raw_id": raw_id,
                "final_url": raw_doc.get("final_url") if raw_doc else None,
                "urlscan": {
                    "scan_id": urlscan.get("scan_id"),
                    "result_url": urlscan.get("result_url"),
                    "page_url": urlscan.get("page_url"),
                },
            }
            items.append(_jsonable({key: value for key, value in item.items() if value is not None}))
            if len(items) >= limit:
                break
        return items

    def dataset_ready_items(self, limit: int = 50) -> list[dict[str, Any]]:
        query = {"dataset.kind": "urlscan_phishing", "status": JOB_SUCCEEDED, "raw_id": {"$exists": True}}
        jobs = list(self.jobs.find(query).sort("finished_at", DESCENDING).limit(limit * 4))
        items: list[dict[str, Any]] = []
        for job in jobs:
            raw_id = job.get("raw_id")
            raw_doc = self.get_raw(raw_id)
            if not raw_doc or raw_doc.get("status") != "ok":
                continue

            dataset = job.get("dataset") if isinstance(job.get("dataset"), dict) else {}
            urlscan = dataset.get("urlscan") if isinstance(dataset.get("urlscan"), dict) else {}
            submitted_url = job.get("submitted_url") or raw_doc.get("submitted_url")
            if self.dataset_decision_exists(raw_id=raw_id, scan_id=urlscan.get("scan_id"), url=submitted_url):
                continue

            items.append(
                _jsonable(
                    {
                        "job_id": job.get("job_id"),
                        "status": "ready",
                        "submitted_url": submitted_url,
                        "final_url": raw_doc.get("final_url"),
                        "updated_at": job.get("finished_at") or job.get("updated_at"),
                        "raw_id": raw_id,
                        "urlscan": {
                            "scan_id": urlscan.get("scan_id"),
                            "result_url": urlscan.get("result_url"),
                            "page_url": urlscan.get("page_url"),
                        },
                    }
                )
            )
            if len(items) >= limit:
                break
        return items

    def dataset_source_for_raw(self, raw_id: Any) -> dict[str, Any]:
        oid = _object_id(raw_id)
        raw_doc = self.get_raw(oid) if oid else None
        urlscan = raw_doc.get("urlscan") if raw_doc and isinstance(raw_doc.get("urlscan"), dict) else {}
        if not urlscan and oid:
            job = self.jobs.find_one({"dataset.kind": "urlscan_phishing", "raw_id": oid}, sort=[("updated_at", DESCENDING)])
            dataset = job.get("dataset") if job and isinstance(job.get("dataset"), dict) else {}
            urlscan = dataset.get("urlscan") if isinstance(dataset.get("urlscan"), dict) else {}
        return _jsonable(urlscan or {})

    def get_raw_screenshot(self, raw_id: Any) -> tuple[bytes, dict[str, Any]] | None:
        raw_doc = self.get_raw(raw_id)
        if not raw_doc:
            return None
        screenshot = raw_doc.get("screenshot") if isinstance(raw_doc.get("screenshot"), dict) else {}
        file_id = screenshot.get("gridfs_file_id")
        if not file_id:
            return None
        output = io.BytesIO()
        try:
            self.screenshot_bucket.download_to_stream(file_id, output)
        except NoFile:
            return None
        return output.getvalue(), screenshot

    def insert_curated_decision(
        self,
        *,
        raw_doc: dict[str, Any],
        decision: str,
        api_document: dict[str, Any],
        verdict: str | None = None,
        confidence: float | None = None,
        organization_brand: str | None = None,
        response_text: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        raw_id = _object_id(raw_doc.get("_id"))
        if not raw_id:
            raise ValueError("Raw document is missing a valid _id")
        now = utc_now()
        urlscan = raw_doc.get("urlscan") if isinstance(raw_doc.get("urlscan"), dict) else {}
        if not urlscan:
            urlscan = self.dataset_source_for_raw(raw_id)
        doc: dict[str, Any] = {
            "decision": decision,
            "raw_id": raw_id,
            "raw_url": raw_doc.get("submitted_url"),
            "final_url": raw_doc.get("final_url"),
            "urlscan": urlscan,
            "api_document": api_document,
            "created_at": now,
            "updated_at": now,
        }
        if decision == "accepted":
            doc["verdict"] = verdict
            doc["confidence"] = confidence
            doc["organization_brand"] = organization_brand
            doc["response_text"] = response_text or ""
            doc["blocks"] = blocks or []
        else:
            doc["reason"] = reason
        self.curated.replace_one({"raw_id": raw_id}, doc, upsert=True)
        return _jsonable(doc)

    def delete_job(self, job_id: str) -> None:
        self.jobs.delete_one({"job_id": job_id})

    def mark_job_running(self, job_id: str) -> None:
        now = utc_now()
        self.jobs.update_one(
            {"job_id": job_id},
            {"$set": {"status": JOB_RUNNING, "started_at": now, "updated_at": now}},
        )

    def mark_job_succeeded(self, job_id: str, raw_id: Any) -> None:
        now = utc_now()
        self.jobs.update_one(
            {"job_id": job_id},
            {"$set": {"status": JOB_SUCCEEDED, "raw_id": raw_id, "finished_at": now, "updated_at": now}, "$unset": {"error": ""}},
        )

    def mark_job_failed(self, job_id: str, error: str, raw_id: Any = None) -> None:
        self._mark_terminal(job_id, JOB_FAILED, error, raw_id)

    def mark_job_timeout(self, job_id: str, error: str, raw_id: Any = None) -> None:
        self._mark_terminal(job_id, JOB_TIMEOUT, error, raw_id)

    def _mark_terminal(self, job_id: str, status: str, error: str, raw_id: Any = None) -> None:
        now = utc_now()
        update: dict[str, Any] = {
            "status": status,
            "error": error[:2_000],
            "finished_at": now,
            "updated_at": now,
        }
        if raw_id is not None:
            update["raw_id"] = raw_id
        self.jobs.update_one({"job_id": job_id}, {"$set": update})
