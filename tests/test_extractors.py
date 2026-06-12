from app.extractors import extract_download_candidates, extract_html_artifacts


def test_extract_download_candidates_from_download_md_cases():
    html = """
    <html>
      <head><title>Invoice</title><meta name="x" content="y"></head>
      <body>
        <a href="/invoice.zip" download>Download invoice</a>
        <a href="/manual.pdf">Manual</a>
        <button onclick="location.href='/setup.exe'">Install update</button>
        <form action="/export/document"><input type="submit" value="Export"></form>
        <a href="/about">About</a>
      </body>
    </html>
    """

    candidates = extract_download_candidates(html, "https://example.com/start")

    urls = {item["url"] for item in candidates}
    texts = " ".join(item["text"] for item in candidates)
    assert "https://example.com/invoice.zip" in urls
    assert "https://example.com/manual.pdf" in urls
    assert "https://example.com/export/document" in urls
    assert "Install update" in texts
    assert all(set(item) == {"text", "url", "html"} for item in candidates)


def test_extract_html_artifacts_shape():
    html = """
    <title>Example</title>
    <meta name="description" content="demo">
    <form><input name="email"></form>
    <a href="/x">X</a><button>Download</button><iframe src="/f"></iframe><img src="/i.png">
    """

    artifacts = extract_html_artifacts(html, "https://example.com")

    assert artifacts["title"] == "Example"
    assert artifacts["meta"]
    assert artifacts["forms"]
    assert artifacts["inputs"]
    assert artifacts["anchors"]
    assert artifacts["buttons"]
    assert artifacts["iframes"]
    assert artifacts["images"]
    assert "X" in artifacts["visible_text"]

