from bson import ObjectId

from app.settings import Settings
from app.storage import MongoStorage


class FakeRawCollection:
    def __init__(self):
        self.docs = {}

    def find_one(self, query, *args, **kwargs):
        if "url_key" in query:
            for doc in self.docs.values():
                if doc.get("url_key") == query["url_key"]:
                    return dict(doc)
        return None

    def replace_one(self, query, doc, upsert=False):
        self.docs[query["_id"]] = dict(doc)


class FakeScreenshotBucket:
    def __init__(self):
        self.uploads = []
        self.deleted = []

    def upload_from_stream(self, filename, stream, metadata=None):
        self.uploads.append({"filename": filename, "data": stream.read(), "metadata": metadata})
        return ObjectId()

    def delete(self, file_id):
        self.deleted.append(file_id)


def storage_with_fakes():
    storage = MongoStorage.__new__(MongoStorage)
    storage.settings = Settings()
    storage.raw = FakeRawCollection()
    storage.screenshot_bucket = FakeScreenshotBucket()
    return storage


def test_insert_raw_upserts_by_url_and_names_screenshot_after_raw_id():
    storage = storage_with_fakes()
    raw_doc = {
        "submitted_url": "https://example.com/",
        "final_url": "https://example.com/login",
        "cache_key": "https://example.com/",
        "status": "ok",
        "rdap_whois": {"raw": None},
        "html": "<html></html>",
        "downloads": {"candidates": [], "observed": []},
        "metadata": {},
    }

    raw_id = storage.insert_raw(raw_doc, b"webp", {"width": 10, "height": 20})
    second_id = storage.insert_raw({**raw_doc, "cache_key": "spider:v1:https://example.com/", "html": "<html>new</html>"})

    assert second_id == raw_id
    assert len(storage.raw.docs) == 1
    assert storage.screenshot_bucket.uploads[0]["filename"] == f"{raw_id}.webp"
    stored = storage.raw.docs[raw_id]
    assert stored["html"] == "<html>new</html>"
    assert stored["screenshot"]["filename"] == f"{raw_id}.webp"
    assert stored["cache_keys"] == ["https://example.com/", "spider:v1:https://example.com/"]
