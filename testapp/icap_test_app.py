#!/usr/bin/env python3
"""ICAP test bench for Forensics-ICAP.

A small web app that plays the part of a proxy / secure web gateway: it takes
file uploads and web-form submissions from your browser, wraps them in ICAP
REQMOD (or RESPMOD) requests, sends them to the ICAP server you configure, and
then looks in the server's capture directory to confirm the transaction was
recorded.

Only the Python standard library is used (3.9+).

    python3 testapp/icap_test_app.py            # then open http://127.0.0.1:8088
    python3 testapp/icap_test_app.py --port 9000
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONFIG_FILE = os.path.join(HERE, "config.json")
INDEX_HTML = os.path.join(HERE, "index.html")

DEFAULT_CONFIG = {
    "icap_host": "127.0.0.1",
    "icap_port": 1344,
    "use_tls": False,
    "tls_verify": False,
    "reqmod_service": "reqmod",
    "respmod_service": "respmod",
    "allow_204": True,
    "preview": -1,                      # -1 = do not send a Preview header
    "timeout": 15,
    "client_ip": "10.20.30.40",
    "username": "alice@example.com",
    "target_url": "https://upload.example.com/api/upload",
    "form_url": "https://forms.example.com/contact/submit",
    "download_url": "https://files.example.com/download",
    "user_agent": "Mozilla/5.0 (ICAP-TestBench) Chrome/129.0",
    "capture_dir": os.path.join(REPO, "captures"),
}

_config_lock = threading.Lock()
_local_server = {"proc": None, "log": []}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def coerce_config(data):
    cfg = dict(DEFAULT_CONFIG)
    for key, default in DEFAULT_CONFIG.items():
        if key not in data:
            continue
        value = data[key]
        if isinstance(default, bool):
            value = value in (True, "true", "on", "1", 1)
        elif isinstance(default, int):
            value = int(value)
        else:
            value = str(value).strip()
        cfg[key] = value
    cfg["reqmod_service"] = cfg["reqmod_service"].strip("/")
    cfg["respmod_service"] = cfg["respmod_service"].strip("/")
    return cfg


# ---------------------------------------------------------------------------
# ICAP client
# ---------------------------------------------------------------------------

class ICAPClientError(Exception):
    pass


def _connect(cfg):
    sock = socket.create_connection((cfg["icap_host"], cfg["icap_port"]), timeout=cfg["timeout"])
    if cfg["use_tls"]:
        ctx = ssl.create_default_context()
        if not cfg["tls_verify"]:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=cfg["icap_host"])
    return sock


def _read_headers(rfile):
    lines = []
    while True:
        line = rfile.readline(65536)
        if not line:
            raise ICAPClientError("connection closed while reading ICAP response headers")
        if line in (b"\r\n", b"\n"):
            break
        lines.append(line)
    return b"".join(lines)


def _parse_response(rfile):
    raw = _read_headers(rfile)
    text = raw.decode("latin-1")
    status_line, _, rest = text.partition("\r\n")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("ICAP/"):
        raise ICAPClientError("bad ICAP status line: %r" % status_line)
    headers = []
    for line in rest.split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append([k.strip(), v.strip()])
    return {"status_line": status_line, "code": int(parts[1]), "headers": headers, "raw": text}


def _header(headers, name):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def _read_encapsulated(rfile, resp):
    """Read the encapsulated HTTP part of a 200 response (headers + chunked body)."""
    enc = _header(resp["headers"], "Encapsulated") or ""
    offsets = []
    for item in enc.split(","):
        if "=" in item:
            name, off = item.strip().split("=", 1)
            offsets.append((name.strip(), int(off)))
    offsets.sort(key=lambda x: x[1])
    if not offsets:
        return "", 0
    last_name, last_off = offsets[-1]
    http_headers = rfile.read(last_off).decode("latin-1") if last_off else ""
    body_len = 0
    if last_name.endswith("-body") and last_name != "null-body":
        while True:
            raw_line = rfile.readline(65536)
            if not raw_line:
                raise ICAPClientError("connection closed inside chunked body")
            line = raw_line.strip()
            if not line:
                continue
            size = int(line.split(b";")[0], 16)
            if size == 0:
                while rfile.readline(65536) not in (b"\r\n", b"\n", b""):
                    pass
                break
            body_len += len(rfile.read(size))
            rfile.readline()
    return http_headers, body_len


def icap_options(cfg, service):
    uri = "icap://%s:%s/%s" % (cfg["icap_host"], cfg["icap_port"], service)
    request = ("OPTIONS %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: ICAP-TestBench/1.0\r\n"
               "Encapsulated: null-body=0\r\nConnection: close\r\n\r\n" % (uri, cfg["icap_host"]))
    t0 = time.monotonic()
    with _connect(cfg) as sock:
        sock.sendall(request.encode("latin-1"))
        rfile = sock.makefile("rb")
        resp = _parse_response(rfile)
    resp["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
    resp["request"] = request
    return resp


def _chunk(data):
    return b"%x\r\n" % len(data) + data + b"\r\n" if data else b""


def icap_modify(cfg, method, service, req_hdr, res_hdr=None, body=b""):
    """Send REQMOD/RESPMOD. Returns a dict describing the exchange."""
    uri = "icap://%s:%s/%s" % (cfg["icap_host"], cfg["icap_port"], service)
    sections = [("req-hdr", req_hdr)]
    if res_hdr is not None:
        sections.append(("res-hdr", res_hdr))
    body_tag = ("res-body" if res_hdr is not None else "req-body") if body else "null-body"
    enc_parts, offset, encapsulated = [], 0, b""
    for name, data in sections:
        enc_parts.append("%s=%d" % (name, offset))
        offset += len(data)
        encapsulated += data
    enc_parts.append("%s=%d" % (body_tag, offset))

    icap_hdrs = [
        ("Host", cfg["icap_host"]),
        ("User-Agent", "ICAP-TestBench/1.0"),
    ]
    if cfg["allow_204"]:
        icap_hdrs.append(("Allow", "204"))
    if cfg["client_ip"]:
        icap_hdrs.append(("X-Client-IP", cfg["client_ip"]))
    if cfg["username"]:
        icap_hdrs.append(("X-Authenticated-User", cfg["username"]))
        icap_hdrs.append(("X-Client-Username", cfg["username"]))
    preview = cfg["preview"]
    use_preview = preview >= 0 and bool(body)
    if use_preview:
        icap_hdrs.append(("Preview", str(preview)))
    icap_hdrs.append(("Encapsulated", ", ".join(enc_parts)))

    head = "%s %s ICAP/1.0\r\n" % (method, uri)
    head += "".join("%s: %s\r\n" % kv for kv in icap_hdrs) + "\r\n"
    head_bytes = head.encode("latin-1")

    log = []
    t0 = time.monotonic()
    with _connect(cfg) as sock:
        rfile = sock.makefile("rb")
        if not body:
            sock.sendall(head_bytes + encapsulated)
            log.append("sent headers (no body)")
        elif use_preview:
            first, rest = body[:preview], body[preview:]
            tail = b"0; ieof\r\n\r\n" if not rest else b"0\r\n\r\n"
            sock.sendall(head_bytes + encapsulated + _chunk(first) + tail)
            log.append("sent %d-byte preview%s" % (len(first), " (ieof)" if not rest else ""))
            if rest:
                interim = _parse_response(rfile)
                log.append("server answered: %s" % interim["status_line"])
                if interim["code"] == 100:
                    _send_chunked(sock, rest)
                    log.append("sent remaining %d bytes" % len(rest))
                else:
                    resp = interim
                    return _finish(resp, rfile, head, encapsulated, body, log, t0)
        else:
            sock.sendall(head_bytes + encapsulated)
            _send_chunked(sock, body)
            log.append("sent %d-byte body (chunked)" % len(body))
        resp = _parse_response(rfile)
        return _finish(resp, rfile, head, encapsulated, body, log, t0)


def _send_chunked(sock, data, size=65536):
    for i in range(0, len(data), size):
        sock.sendall(_chunk(data[i:i + size]))
    sock.sendall(b"0\r\n\r\n")


def _finish(resp, rfile, head, encapsulated, body, log, t0):
    if resp["code"] == 200:
        http_headers, body_len = _read_encapsulated(rfile, resp)
        resp["returned_http_headers"] = http_headers
        resp["returned_body_bytes"] = body_len
        log.append("server returned the message (%d body bytes) - unmodified echo" % body_len)
    elif resp["code"] == 204:
        log.append("204 No Content - server left the message unchanged")
    resp["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
    resp["request"] = head
    resp["encapsulated"] = encapsulated.decode("latin-1")
    resp["body_bytes"] = len(body)
    resp["log"] = log
    return resp


def build_http_request(method, url, headers, body_len):
    parts = urlsplit(url)
    host = parts.netloc or "example.com"
    lines = ["%s %s HTTP/1.1" % (method, url), "Host: %s" % host]
    lines += ["%s: %s" % (k, v) for k, v in headers if v is not None]
    if body_len:
        lines.append("Content-Length: %d" % body_len)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def with_test_id(url, test_id):
    return url + ("&" if "?" in url else "?") + "icap_test=" + test_id


# ---------------------------------------------------------------------------
# Capture lookup
# ---------------------------------------------------------------------------

def read_index(capture_dir, limit=50):
    path = os.path.join(capture_dir, "index.jsonl")
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 512 * 1024))
            lines = f.read().splitlines()
    except OSError:
        return None
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
        if len(out) >= limit:
            break
    return out


def find_capture(capture_dir, test_id):
    for rec in read_index(capture_dir, limit=500) or []:
        if test_id in (rec.get("url") or ""):
            return rec
    return None


def safe_capture_path(capture_dir, rel):
    root = os.path.realpath(capture_dir)
    full = os.path.realpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        raise ValueError("path outside capture dir")
    return full


def capture_details(capture_dir, rel):
    full = safe_capture_path(capture_dir, rel)
    with open(os.path.join(full, "metadata.json")) as f:
        meta = json.load(f)
    files = []
    for dirpath, _dirs, names in os.walk(full):
        for name in sorted(names):
            p = os.path.join(dirpath, name)
            files.append({"name": os.path.relpath(p, full), "size": os.path.getsize(p)})
    files.sort(key=lambda x: x["name"])
    return {"metadata": meta, "files": files, "path": rel}


# ---------------------------------------------------------------------------
# Local ICAP server management (optional convenience)
# ---------------------------------------------------------------------------

def start_local_server(cfg):
    proc = _local_server["proc"]
    if proc and proc.poll() is None:
        return "already running (pid %d)" % proc.pid
    os.makedirs(cfg["capture_dir"], exist_ok=True)
    env = dict(os.environ, ICAP_PORT=str(cfg["icap_port"]), ICAP_HOST="127.0.0.1",
               CAPTURE_DIR=cfg["capture_dir"], LOG_LEVEL="INFO")
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "icap_server.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    _local_server["proc"] = proc
    _local_server["log"] = []

    def pump():
        for line in proc.stdout:
            _local_server["log"].append(line.decode("utf-8", "replace").rstrip())
            del _local_server["log"][:-200]
    threading.Thread(target=pump, daemon=True).start()
    time.sleep(0.5)
    if proc.poll() is not None:
        return "exited immediately (code %s) - is port %s already in use?" % (proc.returncode, cfg["icap_port"])
    return "started (pid %d)" % proc.pid


def stop_local_server():
    proc = _local_server["proc"]
    if not proc or proc.poll() is not None:
        return "not running"
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
    return "stopped"


def local_server_status():
    proc = _local_server["proc"]
    running = bool(proc and proc.poll() is None)
    return {"running": running, "pid": proc.pid if running else None, "log": _local_server["log"][-60:]}


# ---------------------------------------------------------------------------
# Web app
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "ICAP-TestBench/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[testbench] %s\n" % (fmt % args))

    # helpers
    def send_json(self, obj, code=200):
        data = json.dumps(obj, indent=1, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def query(self):
        return {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}

    def cfg(self):
        with _config_lock:
            return dict(self.server.config)

    # routing
    def do_GET(self):
        path = urlsplit(self.path).path
        q = self.query()
        try:
            if path == "/":
                with open(INDEX_HTML, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
            elif path == "/api/config":
                self.send_json({"config": self.cfg(), "defaults": DEFAULT_CONFIG})
            elif path == "/api/captures":
                cfg = self.cfg()
                recs = read_index(cfg["capture_dir"], int(q.get("limit", 30)))
                self.send_json({"capture_dir": cfg["capture_dir"], "available": recs is not None,
                                "records": recs or []})
            elif path == "/api/capture":
                self.send_json(capture_details(self.cfg()["capture_dir"], q["path"]))
            elif path == "/api/capture/file":
                cfg = self.cfg()
                full = safe_capture_path(cfg["capture_dir"], q["path"])
                with open(full, "rb") as f:
                    data = f.read()
                self.send_response(200)
                # Served as plain text / attachment so captured HTML or scripts never execute here.
                if q.get("download"):
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition",
                                     "attachment; filename*=UTF-8''" + quote(os.path.basename(full)))
                else:
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif path == "/api/find":
                rec = find_capture(self.cfg()["capture_dir"], q["id"])
                self.send_json({"found": rec is not None, "record": rec})
            elif path == "/api/local-server":
                self.send_json(local_server_status())
            else:
                self.send_error(404)
        except (KeyError, ValueError, OSError) as e:
            self.send_json({"error": str(e)}, 400)

    def do_POST(self):
        path = urlsplit(self.path).path
        q = self.query()
        try:
            if path == "/api/config":
                data = json.loads(self.read_body() or b"{}")
                cfg = DEFAULT_CONFIG.copy() if data.get("reset") else coerce_config(data)
                with _config_lock:
                    self.server.config = cfg
                save_config(cfg)
                self.send_json({"config": cfg})
            elif path == "/api/options":
                cfg = self.cfg()
                service = cfg["respmod_service"] if q.get("mode") == "respmod" else cfg["reqmod_service"]
                self.send_json({"ok": True, "response": icap_options(cfg, service)})
            elif path == "/api/send":
                self.handle_send(q)
            elif path == "/api/local-server/start":
                self.send_json({"message": start_local_server(self.cfg())})
            elif path == "/api/local-server/stop":
                self.send_json({"message": stop_local_server()})
            else:
                self.send_error(404)
        except (OSError, ICAPClientError, ssl.SSLError) as e:
            self.send_json({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}, 502)
        except (KeyError, ValueError) as e:
            self.send_json({"ok": False, "error": str(e)}, 400)

    def handle_send(self, q):
        """Wrap the browser's request body in an ICAP REQMOD/RESPMOD."""
        cfg = self.cfg()
        body = self.read_body()
        kind = q.get("kind", "upload")          # upload | form | download
        test_id = uuid.uuid4().hex[:12]
        content_type = self.headers.get("Content-Type")
        common = [("User-Agent", cfg["user_agent"]), ("X-ICAP-Test-Id", test_id),
                  ("Accept", "*/*")]

        if kind == "download":
            # RESPMOD: pretend the user downloaded this file from the web.
            filename = q.get("filename", "file.bin")
            url = with_test_id(cfg["download_url"].rstrip("/") + "/" + quote(filename), test_id)
            req_hdr = build_http_request("GET", url, common, 0)
            res_lines = ["HTTP/1.1 200 OK",
                         "Content-Type: %s" % (content_type or "application/octet-stream"),
                         "Content-Length: %d" % len(body),
                         "Content-Disposition: attachment; filename=\"%s\"" % filename.replace('"', ""),
                         "Date: %s" % time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())]
            res_hdr = ("\r\n".join(res_lines) + "\r\n\r\n").encode("latin-1", "replace")
            method, service = "RESPMOD", cfg["respmod_service"]
        else:
            base = cfg["form_url"] if kind == "form" else cfg["target_url"]
            url = with_test_id(base, test_id)
            req_hdr = build_http_request(
                q.get("http_method", "POST").upper(), url,
                common + [("Content-Type", content_type),
                          ("Origin", "%s://%s" % (urlsplit(base).scheme, urlsplit(base).netloc)),
                          ("Cookie", "session=testbench-%s" % test_id)],
                len(body))
            res_hdr = None
            method, service = "REQMOD", cfg["reqmod_service"]

        result = icap_modify(cfg, method, service, req_hdr, res_hdr, body)
        self.send_json({"ok": True, "test_id": test_id, "method": method, "url": url,
                        "kind": kind, "response": result})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.config = load_config()
    print("ICAP test bench on http://%s:%d  (ICAP target %s:%s, captures %s)" % (
        args.host, args.port, httpd.config["icap_host"], httpd.config["icap_port"],
        httpd.config["capture_dir"]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_local_server()


if __name__ == "__main__":
    main()
