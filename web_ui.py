"""Read-only web UI for the captures written by icap_server.py.

Serves a list of captured transactions, a "forms" view of request bodies that
were submitted as web forms (urlencoded or multipart), a detail page per
transaction, and downloads of the captured files.

Captured content is untrusted: every file is served as an attachment with
nosniff and a locked-down CSP, and only files listed in a capture's metadata
can be fetched. Only the Python standard library is used. There is no
authentication, so bind it to localhost or put it behind a proxy you trust.
"""

import html
import json
import mimetypes
import os
import threading
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlsplit

FIELD_PREVIEW = 2000  # characters of a field value shown in listings
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")

CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}
header{background:#1d2330;color:#fff;padding:12px 16px}
header a{color:#fff;text-decoration:none;margin-right:16px;font-weight:600}
main{padding:16px;max-width:1200px;margin:auto}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{padding:6px 8px;border-bottom:1px solid #e3e6ea;text-align:left;vertical-align:top;word-break:break-all}
th{background:#eef1f5;font-size:12px;text-transform:uppercase;color:#4a5263}
code,pre{font:12px ui-monospace,Menlo,monospace}
pre{background:#fff;padding:10px;overflow:auto;white-space:pre-wrap;border:1px solid #e3e6ea}
.muted{color:#6b7385}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;background:#dfe7ff;font-size:12px}
form.filter input,form.filter select{padding:5px;margin-right:6px}
section{margin-top:18px}
h2{font-size:16px;margin:0 0 8px}
"""


def _esc(value):
    return html.escape("" if value is None else str(value), quote=True)


class CaptureReader:
    """Reads the capture directory tree. Safe to call from several threads."""

    def __init__(self, root):
        self.root = root
        self._lock = threading.Lock()

    def index(self):
        path = os.path.join(self.root, "index.jsonl")
        if not os.path.exists(path):
            return []
        with self._lock, open(path, encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        records.reverse()  # newest first
        return records

    def find(self, capture_id):
        for rec in self.index():
            if rec["id"] == capture_id:
                return rec
        return None

    def metadata(self, rec):
        with open(os.path.join(self.root, rec["path"], "metadata.json"), encoding="utf-8") as f:
            return json.load(f)

    def body_path(self, rec, meta):
        """The best body to show: decoded if available, otherwise the raw body."""
        files = meta.get("capture", {}).get("files", [])
        for name in files:
            if name.startswith("body_decoded"):
                return os.path.join(self.root, rec["path"], name)
        for name in files:
            if name.startswith("body."):
                return os.path.join(self.root, rec["path"], name)
        return None

    def form_fields(self, rec, meta):
        """Return (kind, fields, files) for a form submission, or None."""
        # Keep the original case: multipart boundaries are case-sensitive.
        raw_ctype = meta.get("http", {}).get("content_type") or ""
        ctype = raw_ctype.lower()
        body = self.body_path(rec, meta)
        if not body or not any(ctype.startswith(t) for t in FORM_TYPES):
            return None
        with open(body, "rb") as f:
            raw = f.read()
        if ctype.startswith("application/x-www-form-urlencoded"):
            pairs = parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
            return "urlencoded", pairs, []
        msg = BytesParser(policy=policy.HTTP).parsebytes(
            b"Content-Type: " + raw_ctype.encode("latin-1") + b"\r\n\r\n" + raw)
        fields, files = [], []
        if msg.is_multipart():
            for part in msg.iter_parts():
                name = part.get_param("name", header="content-disposition") or "(unnamed)"
                filename = part.get_filename()
                payload = part.get_payload(decode=True) or b""
                if filename:
                    files.append((name, filename, len(payload), part.get_content_type()))
                else:
                    fields.append((name, payload.decode("utf-8", errors="replace")))
        return "multipart", fields, files


def _page(title, body, nav=True):
    nav_html = ('<header><a href="/">Captures</a><a href="/forms">Forms</a></header>'
                if nav else "")
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)} · Forensics ICAP</title><style>{CSS}</style></head>"
            f"<body>{nav_html}<main>{body}</main></body></html>").encode("utf-8")


def render_list(records, query, forms_only):
    rows = []
    needle = query.lower()
    for rec in records:
        ctype = (rec.get("content_type") or "").lower()
        if forms_only and not any(ctype.startswith(t) for t in FORM_TYPES):
            continue
        haystack = " ".join(str(rec.get(k) or "") for k in ("url", "user", "client_ip", "method"))
        if needle and needle not in haystack.lower():
            continue
        rows.append(
            f"<tr><td>{_esc(rec.get('time', ''))[:19]}</td>"
            f"<td><span class=tag>{_esc(rec.get('method'))}</span> {_esc(rec.get('http_method'))}</td>"
            f"<td>{_esc(rec.get('user') or '')}</td>"
            f"<td>{_esc(rec.get('client_ip') or '')}</td>"
            f"<td><a href='/capture/{_esc(rec['id'])}'>{_esc(rec.get('url') or '')}</a></td>"
            f"<td>{_esc(rec.get('content_type') or '')}</td>"
            f"<td>{rec.get('bytes', 0)}</td></tr>")
    title = "Forms" if forms_only else "Captures"
    table = ("<table><tr><th>Time (UTC)</th><th>Method</th><th>User</th><th>Client</th>"
             "<th>URL</th><th>Content-Type</th><th>Bytes</th></tr>" + "".join(rows) + "</table>"
             if rows else "<p class=muted>No captures match.</p>")
    filter_form = (
        "<form class=filter method=get>"
        f"<input name=q value='{_esc(query)}' placeholder='Filter by URL, user, IP or method'>"
        "<button>Filter</button></form>")
    return _page(title,
                 f"<h2>{title} ({len(rows)})</h2>{filter_form}<section>{table}</section>")


def render_detail(rec, meta, reader):
    cap = meta.get("capture", {})
    http = meta.get("http", {})
    icap = meta.get("icap", {})
    cid = _esc(rec["id"])

    def kv(pairs):
        return "<table>" + "".join(
            f"<tr><th style='width:200px'>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
            for k, v in pairs) + "</table>"

    summary = kv([
        ("Capture ID", rec["id"]), ("Time (UTC)", meta.get("time")),
        ("ICAP method", icap.get("method")), ("ICAP service", icap.get("service")),
        ("ICAP peer", icap.get("peer")), ("Client IP", icap.get("client_ip")),
        ("User", icap.get("user")), ("HTTP method", http.get("method")),
        ("URL", http.get("url")), ("Status", http.get("status")),
        ("Content-Type", http.get("content_type")), ("Filename", http.get("filename")),
        ("Body bytes", cap.get("body_bytes")), ("Stored bytes", cap.get("body_bytes_stored")),
        ("Truncated", cap.get("truncated")), ("SHA-256", cap.get("sha256")),
        ("MD5", cap.get("md5")),
    ])

    form_html = ""
    parsed = reader.form_fields(rec, meta)
    if parsed:
        kind, fields, files = parsed
        field_rows = "".join(
            f"<tr><th style='width:200px'>{_esc(k)}</th>"
            f"<td><pre>{_esc(v[:FIELD_PREVIEW])}{'…' if len(v) > FIELD_PREVIEW else ''}</pre></td></tr>"
            for k, v in fields)
        file_rows = "".join(
            f"<tr><td>{_esc(field)}</td><td>{_esc(name)}</td><td>{_esc(ctype)}</td>"
            f"<td>{size}</td></tr>" for field, name, size, ctype in files)
        form_html = (
            f"<section><h2>Form fields ({kind})</h2>"
            + (f"<table>{field_rows}</table>" if field_rows else "<p class=muted>No text fields.</p>")
            + "</section>")
        if file_rows:
            form_html += ("<section><h2>Uploaded files</h2><table><tr><th>Field</th><th>Name</th>"
                          "<th>Type</th><th>Bytes</th></tr>" + file_rows + "</table></section>")

    files_html = "".join(
        f"<li><a href='/capture/{cid}/files/{quote(name)}'>{_esc(name)}</a></li>"
        for name in cap.get("files", []))
    header_html = ""
    for title, key in (("Request headers", "request_headers"), ("Response headers", "response_headers")):
        hdrs = http.get(key) or {}
        if hdrs:
            header_html += f"<h2>{title}</h2>" + kv(
                [(k, ", ".join(v)) for k, v in sorted(hdrs.items())])

    body = (f"<h2>Transaction {cid}</h2><section>{summary}</section>{form_html}"
            f"<section><h2>Files</h2><ul>{files_html or '<li class=muted>None</li>'}</ul></section>"
            f"<section>{header_html}</section>"
            f"<section><h2>Raw metadata</h2><pre>{_esc(json.dumps(meta, indent=2, ensure_ascii=False))}</pre></section>")
    return _page(f"Capture {rec['id']}", body)


class WebHandler(BaseHTTPRequestHandler):
    reader: CaptureReader = None
    server_version = "ForensicsWeb/2.0"

    def log_message(self, fmt, *args):  # keep the ICAP log clean
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                         "form-action 'self'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._send(404, _page("Not found", "<h2>Not found</h2>"))

    def do_GET(self):
        url = urlsplit(self.path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        query = dict(parse_qsl(url.query))
        try:
            if not parts:
                records = self.reader.index()
                return self._send(200, render_list(records, query.get("q", ""), False))
            if parts == ["forms"]:
                records = self.reader.index()
                return self._send(200, render_list(records, query.get("q", ""), True))
            if parts == ["healthz"]:
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if len(parts) == 2 and parts[0] == "capture":
                rec = self.reader.find(parts[1])
                if not rec:
                    return self._not_found()
                meta = self.reader.metadata(rec)
                return self._send(200, render_detail(rec, meta, self.reader))
            if len(parts) >= 4 and parts[0] == "capture" and parts[2] == "files":
                return self._serve_file(parts[1], "/".join(parts[3:]))
            return self._not_found()
        except (OSError, json.JSONDecodeError, KeyError):
            return self._send(500, _page("Error", "<h2>Could not read capture</h2>"))

    def _serve_file(self, capture_id, name):
        rec = self.reader.find(capture_id)
        if not rec:
            return self._not_found()
        meta = self.reader.metadata(rec)
        listed = meta.get("capture", {}).get("files", [])
        if name not in listed:  # only files recorded in metadata; blocks path traversal
            return self._not_found()
        path = os.path.join(self.reader.root, rec["path"], name)
        with open(path, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        filename = os.path.basename(name).replace('"', "")
        return self._send(200, data, ctype, headers=[
            ("Content-Disposition", f'attachment; filename="{filename}"')])


def build_web_server(config):
    """Return a ThreadingHTTPServer serving the capture UI for config.capture_dir."""
    handler = type("Handler", (WebHandler,), {"reader": CaptureReader(config.capture_dir)})
    server = ThreadingHTTPServer((config.web_host, config.web_port), handler)
    server.daemon_threads = True
    return server
