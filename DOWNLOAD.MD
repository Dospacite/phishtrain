### Download Candidate Extraction

Download candidates are controls or links that may initiate a file download. They can be extracted from the rendered DOM without including full JavaScript sources.

Collect candidates from:

- `<a>` elements with a `download` attribute.
- `<a href>` values ending in file-like extensions such as `.exe`, `.zip`, `.rar`, `.7z`, `.pdf`, `.docm`, `.xlsm`, `.iso`, `.apk`, etc.
- Buttons, links, or form controls whose visible text suggests a download action, such as `Download`, `Install`, `Update`, `Get file`, `Invoice`, `Document`, or `Export`.
- Elements with inline event attributes such as `onclick`, `onmousedown`, or `onpointerdown`, especially when their text or HTML suggests a download.
- Forms whose `action` URL points to a file-like path or download endpoint.

For each candidate, store only the minimal evidence needed for classification:

```json
{
  "text": "Download invoice",
  "url": "https://example.com/invoice.zip",
  "html": "<a href=\"/invoice.zip\" download>Download invoice</a>"
}
