from app.models import empty_format_result
from app.storage import project_api_result
from app.url_safety import UrlValidationError, validate_public_url
from bson import ObjectId


def test_project_api_result_omits_screenshot_metadata():
    raw = {
        **empty_format_result("https://example.com/"),
        "cache_key": "https://example.com/",
        "status": "ok",
        "screenshot": {
            "gridfs_file_id": "abc",
            "content_type": "image/webp",
            "size_bytes": 100,
        },
    }

    projected = project_api_result(raw)

    assert "screenshot" not in projected
    assert set(projected) == {
        "submitted_url",
        "final_url",
        "redirect_chain",
        "headers",
        "tls",
        "rdap_whois",
        "downloads",
        "html",
    }


def test_private_urls_rejected_by_default():
    for url in ("http://localhost/", "http://127.0.0.1/", "http://10.0.0.1/"):
        try:
            validate_public_url(url)
        except UrlValidationError:
            continue
        raise AssertionError(f"{url} should have been rejected")


def test_project_api_result_includes_spider_child_raw_ids():
    child_id = ObjectId()
    raw = {
        **empty_format_result("https://example.com/"),
        "cache_key": "spider:v1:https://example.com/",
        "status": "ok",
        "spider_child_raw_ids": [child_id],
    }

    projected = project_api_result(raw)

    assert projected["spider_child_raw_ids"] == [str(child_id)]


def test_project_api_result_derives_current_format_from_raw_capture():
    raw = {
        "submitted_url": "https://example.com/",
        "final_url": "https://example.com/login",
        "cache_key": "https://example.com/",
        "status": "ok",
        "rdap_whois": {
            "domain": "example.com",
            "lookup_url": "https://rdap.org/domain/example.com",
            "status_code": 200,
            "headers": {"content-type": "application/rdap+json"},
            "raw": {
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                "status": ["active"],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            },
            "error": None,
        },
        "html": "<html><head><title>Ignored</title></head><body><a href='/invoice.pdf'>Invoice</a></body></html>",
        "downloads": {"candidates": [{"text": "Invoice", "url": "https://example.com/invoice.pdf", "html": "<a>Invoice</a>"}], "observed": []},
        "metadata": {
            "redirect_chain": ["https://example.com/", "https://example.com/login"],
            "headers": {"content-type": "text/html"},
            "tls": {"enabled": True, "issuer": "issuer", "subject": "subject"},
            "title": "Captured title",
            "visible_text": "Captured text",
        },
        "screenshot": {"filename": "abc.webp"},
    }

    projected = project_api_result(raw)

    assert projected["redirect_chain"] == ["https://example.com/", "https://example.com/login"]
    assert projected["headers"] == {"content-type": "text/html"}
    assert projected["tls"]["enabled"] is True
    assert projected["rdap_whois"]["registrar"] == "Example Registrar"
    assert projected["rdap_whois"]["statuses"] == ["active"]
    assert projected["html"]["title"] == "Captured title"
    assert projected["html"]["visible_text"] == "Captured text"
    assert projected["html"]["anchors"] == ['<a href="/invoice.pdf">Invoice</a>']
    assert projected["downloads"] == raw["downloads"]
    assert "screenshot" not in projected
