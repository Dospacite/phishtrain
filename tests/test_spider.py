from bson import ObjectId

from app.models import empty_format_result
from app.scraper import ScrapeArtifact
from app.settings import Settings
from app.spider import candidate_sources, discover_spider_candidates
from app.worker import run_spider_job


def test_discover_spider_candidates_from_supported_sources():
    html = """
    <html>
      <head><meta http-equiv="refresh" content="0;url=/continue"></head>
      <body>
        <a href="/login">Login</a>
        <form action="/checkout"><button>Pay invoice</button></form>
        <iframe src="https://files.example.com/viewer"></iframe>
        <button data-href="/wallet">Wallet connect</button>
        <button onclick="location.href='/verify'">Verify identity</button>
      </body>
    </html>
    """
    settings = Settings(allow_private_urls=True, spider_candidate_limit=20, spider_max_child_pages=10)

    candidates = discover_spider_candidates(html, "https://example.com/start", "https://example.com/start", settings)
    by_url = {candidate.url: candidate for candidate in candidates}

    assert "https://example.com/login" in by_url
    assert "https://example.com/checkout" in by_url
    assert "https://files.example.com/viewer" in by_url
    assert "https://example.com/wallet" in by_url
    assert "https://example.com/verify" in by_url
    assert "https://example.com/continue" in by_url
    assert "link_href" in candidate_sources(by_url["https://example.com/login"])
    assert "form_action" in candidate_sources(by_url["https://example.com/checkout"])
    assert "iframe_src" in candidate_sources(by_url["https://files.example.com/viewer"])
    assert "data_href" in candidate_sources(by_url["https://example.com/wallet"])
    assert "inline_event" in candidate_sources(by_url["https://example.com/verify"])
    assert "meta_refresh" in candidate_sources(by_url["https://example.com/continue"])


def test_discover_spider_candidates_keeps_same_site_and_rejects_external():
    html = """
    <a href="https://login.example.com/sso">SSO</a>
    <a href="https://evil.test/login">External login</a>
    """
    settings = Settings(allow_private_urls=True, spider_candidate_limit=10, spider_max_child_pages=10)

    urls = {
        candidate.url
        for candidate in discover_spider_candidates(html, "https://www.example.com/", "https://www.example.com/", settings)
    }

    assert "https://login.example.com/sso" in urls
    assert "https://evil.test/login" not in urls


class FakeStorage:
    def __init__(self):
        self.ids = [ObjectId(), ObjectId()]
        self.inserted = []
        self.job = {
            "job_id": "job-spider",
            "submitted_url": "https://example.com/",
            "cache_key": "spider:v1:https://example.com/",
        }
        self.status = None
        self.raw_id = None

    def ensure_indexes(self):
        pass

    def get_job(self, job_id):
        return self.job if job_id == "job-spider" else None

    def mark_job_running(self, job_id):
        self.status = "running"

    def insert_raw(self, raw_doc, screenshot_webp=None, screenshot_metadata=None):
        self.inserted.append(dict(raw_doc))
        return self.ids[len(self.inserted) - 1]

    def mark_job_succeeded(self, job_id, raw_id):
        self.status = "succeeded"
        self.raw_id = raw_id

    def mark_job_failed(self, job_id, error, raw_id=None):
        self.status = "failed"

    def mark_job_timeout(self, job_id, error, raw_id=None):
        self.status = "timeout"


def test_run_spider_job_stores_child_pages_as_normal_raw_docs(monkeypatch):
    storage = FakeStorage()
    settings = Settings(
        allow_private_urls=True,
        spider_candidate_limit=1,
        spider_max_child_pages=1,
        spider_page_wait_ms=0,
        spider_page_timeout_ms=1000,
        spider_job_timeout_seconds=10,
    )

    def fake_scrape_url(url, settings, **kwargs):
        raw = {**empty_format_result(url), "cache_key": url, "status": "ok", "scraper": {"library": "test"}}
        if url == "https://example.com/":
            return ScrapeArtifact(raw_doc=raw, rendered_html='<a href="/login">Login</a>')
        return ScrapeArtifact(raw_doc=raw, rendered_html="")

    monkeypatch.setattr("app.worker.get_settings", lambda: settings)
    monkeypatch.setattr("app.worker.MongoStorage", lambda settings: storage)
    monkeypatch.setattr("app.scraper.scrape_url", fake_scrape_url)

    result = run_spider_job("job-spider")

    assert result == "succeeded"
    assert storage.status == "succeeded"
    child_doc = storage.inserted[0]
    seed_doc = storage.inserted[1]
    assert set(child_doc) >= {"submitted_url", "final_url", "redirect_chain", "headers", "tls", "rdap_whois", "downloads", "html"}
    assert "spider_child_raw_ids" not in child_doc
    assert seed_doc["cache_key"] == "spider:v1:https://example.com/"
    assert seed_doc["spider_child_raw_ids"] == [storage.ids[0]]
    assert storage.raw_id == storage.ids[1]
