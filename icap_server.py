#!/usr/bin/env python3
"""Forensics ICAP server.

A passive ICAP (RFC 3507) server that never modifies traffic. Every REQMOD /
RESPMOD transaction it receives is written to disk so the content can be
reviewed later. Each transaction gets its own directory:

    <CAPTURE_DIR>/YYYY/MM/DD/<HHMMSS>_<method>_<id>/
        metadata.json               who / what / when, hashes, ICAP headers
        http_request_headers.txt    encapsulated HTTP request headers
        http_response_headers.txt   encapsulated HTTP response headers (RESPMOD)
        body.<ext>                  raw HTTP body exactly as received
        body_decoded.<ext>          body with gzip/deflate Content-Encoding removed
        parts/NN_<filename>         files extracted from multipart/form-data uploads

and a one-line summary is appended to <CAPTURE_DIR>/index.jsonl.

Only the Python standard library is used. Configuration is via environment
variables (see Config below).
"""

import argparse
import hashlib
import json
import logging
import mimetypes
import os
import random
import re
import shutil
import signal
import socket
import socketserver
import ssl
import string
import sys
import tempfile
import threading
import time
import uuid
import zlib
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import unquote

__version__ = "2.0.0"

log = logging.getLogger("forensics-icap")

MAX_LINE = 65536
COPY_CHUNK = 64 * 1024


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        self.host = os.environ.get("ICAP_HOST", "0.0.0.0")
        self.port = int(os.environ.get("ICAP_PORT", "1344"))
        self.capture_dir = os.environ.get("CAPTURE_DIR", "/data/captures")
        # Bodies larger than this are truncated on disk (traffic is unaffected).
        self.max_body_bytes = int(os.environ.get("MAX_BODY_BYTES", str(100 * 1024 * 1024)))
        # Save transactions that carry no HTTP body (e.g. plain GET requests).
        self.save_empty = _env_bool("SAVE_EMPTY", True)
        # Preview size advertised in OPTIONS. 0 = client sends headers first,
        # we always ask for the rest, which is what we want for full capture.
        self.preview = int(os.environ.get("ICAP_PREVIEW", "0"))
        self.options_ttl = int(os.environ.get("ICAP_OPTIONS_TTL", "3600"))
        self.max_connections = int(os.environ.get("ICAP_MAX_CONNECTIONS", "100"))
        self.timeout = float(os.environ.get("ICAP_SOCKET_TIMEOUT", "300"))
        self.tls_cert = os.environ.get("TLS_CERT") or None
        self.tls_key = os.environ.get("TLS_KEY") or None
        self.log_level = os.environ.get("LOG_LEVEL", "INFO").upper()


class ICAPError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


REASONS = {
    100: "Continue", 200: "OK", 204: "No Content", 400: "Bad Request",
    404: "ICAP Service Not Found", 405: "Method Not Allowed for Service",
    500: "Server Error", 501: "Method Not Implemented",
    505: "ICAP Version Not Supported",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name, default="file"):
    name = os.path.basename(name.replace("\\", "/"))
    name = _SAFE_NAME.sub("_", name).strip("._")
    return name[:120] or default


def parse_http_headers(raw):
    """Parse an HTTP header block into (start_line, {lower-name: [values]})."""
    text = raw.decode("latin-1")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    start_line = lines[0].strip() if lines else ""
    headers = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.setdefault(k.strip().lower(), []).append(v.strip())
    return start_line, headers


def first(headers, name):
    values = headers.get(name)
    return values[0] if values else None


def extension_for(content_type, filename=None):
    if filename:
        ext = _SAFE_NAME.sub("", os.path.splitext(filename)[1].lstrip("."))[:10]
        if ext:
            return "." + ext
    if content_type:
        ext = mimetypes.guess_extension(content_type.split(";")[0].strip().lower())
        if ext:
            return ext
    return ".bin"


def filename_from_disposition(value):
    if not value:
        return None
    m = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", value, re.I)
    if m:
        return unquote(m.group(1).strip().strip('"'))
    m = re.search(r'filename\s*=\s*"([^"]*)"', value, re.I) or \
        re.search(r"filename\s*=\s*([^;]+)", value, re.I)
    return m.group(1).strip() if m else None


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

class CaptureStore:
    def __init__(self, root, max_body_bytes, save_empty=True):
        self.root = root
        self.max_body_bytes = max_body_bytes
        self.save_empty = save_empty
        self._index_lock = threading.Lock()
        os.makedirs(root, exist_ok=True)

    def begin(self):
        return Capture(self)

    def append_index(self, record):
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._index_lock:
            with open(os.path.join(self.root, "index.jsonl"), "a", encoding="utf-8") as f:
                f.write(line)


class Capture:
    """One transaction being written to disk.

    Data lands in a hidden ".partial-*" directory and is renamed into place
    only once complete, so reviewers never see half-written captures.
    """

    def __init__(self, store):
        self.store = store
        self.id = uuid.uuid4().hex[:12]
        self.started = datetime.now(timezone.utc)
        self.day_dir = os.path.join(store.root, self.started.strftime("%Y/%m/%d"))
        os.makedirs(self.day_dir, exist_ok=True)
        self.dir = os.path.join(self.day_dir, ".partial-" + self.id)
        os.makedirs(self.dir, mode=0o750)
        self._body = None
        self._sha256 = hashlib.sha256()
        self._md5 = hashlib.md5()
        self.size = 0          # bytes received
        self.stored = 0        # bytes written to disk
        self.truncated = False

    def write(self, data):
        if not data:
            return
        self.size += len(data)
        self._sha256.update(data)
        self._md5.update(data)
        room = self.store.max_body_bytes - self.stored
        if room <= 0:
            self.truncated = True
            return
        if len(data) > room:
            data = data[:room]
            self.truncated = True
        if self._body is None:
            self._body = open(os.path.join(self.dir, "body.part"), "wb")
        self._body.write(data)
        self.stored += len(data)

    def abort(self):
        if self._body:
            self._body.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def finish(self, meta, req_hdr_raw, res_hdr_raw):
        if self._body:
            self._body.close()

        if self.size == 0 and not self.store.save_empty:
            self.abort()
            return None

        files = []
        if req_hdr_raw:
            self._write_file("http_request_headers.txt", req_hdr_raw)
            files.append("http_request_headers.txt")
        if res_hdr_raw:
            self._write_file("http_response_headers.txt", res_hdr_raw)
            files.append("http_response_headers.txt")

        body = meta["http"]
        if self._body:
            ext = extension_for(body.get("content_type"), body.get("filename"))
            body_name = "body" + ext
            os.rename(os.path.join(self.dir, "body.part"), os.path.join(self.dir, body_name))
            files.append(body_name)
            try:
                files += self._post_process(body_name, ext, body)
            except Exception:
                log.exception("capture %s: post-processing failed", self.id)

        meta["capture"] = {
            "id": self.id,
            "body_bytes": self.size,
            "body_bytes_stored": self.stored,
            "truncated": self.truncated,
            "sha256": self._sha256.hexdigest() if self.size else None,
            "md5": self._md5.hexdigest() if self.size else None,
            "files": files,
        }
        self._write_file("metadata.json",
                         json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8"))

        method = meta["icap"]["method"].lower()
        final = os.path.join(self.day_dir, f"{self.started:%H%M%S}_{method}_{self.id}")
        os.rename(self.dir, final)
        self.dir = final

        self.store.append_index({
            "id": self.id,
            "time": meta["time"],
            "method": meta["icap"]["method"],
            "client_ip": meta["icap"].get("client_ip"),
            "user": meta["icap"].get("user"),
            "http_method": body.get("method"),
            "url": body.get("url"),
            "status": body.get("status"),
            "content_type": body.get("content_type"),
            "bytes": self.size,
            "sha256": meta["capture"]["sha256"],
            "path": os.path.relpath(final, self.store.root),
        })
        return final

    def _write_file(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o640)
        return path

    def _post_process(self, body_name, ext, http):
        """Produce reviewer-friendly derivatives of the raw body."""
        produced = []
        if self.truncated:
            return produced
        body_path = os.path.join(self.dir, body_name)
        limit = self.store.max_body_bytes

        encoding = (http.get("content_encoding") or "").lower()
        if encoding in ("gzip", "x-gzip", "deflate"):
            wbits = 47 if "gzip" in encoding else 15  # 47 = auto-detect gzip/zlib
            with open(body_path, "rb") as f:
                raw = f.read()
            try:
                d = zlib.decompressobj(wbits)
                decoded = d.decompress(raw, limit)
            except zlib.error:
                try:
                    d = zlib.decompressobj(-15)  # raw deflate
                    decoded = d.decompress(raw, limit)
                except zlib.error:
                    decoded = None
            if decoded is not None:
                name = "body_decoded" + ext
                self._write_file(name, decoded)
                produced.append(name)
                body_path = os.path.join(self.dir, name)

        ctype = http.get("content_type") or ""
        if ctype.lower().startswith("multipart/"):
            with open(body_path, "rb") as f:
                raw = f.read()
            msg = BytesParser(policy=policy.HTTP).parsebytes(
                b"Content-Type: " + ctype.encode("latin-1") + b"\r\n\r\n" + raw)
            if msg.is_multipart():
                parts_dir = os.path.join(self.dir, "parts")
                os.makedirs(parts_dir, mode=0o750, exist_ok=True)
                for i, part in enumerate(msg.iter_parts(), 1):
                    payload = part.get_payload(decode=True) or b""
                    fname = part.get_filename()
                    field = part.get_param("name", header="content-disposition")
                    label = fname or (f"field_{field}" if field else "part")
                    pext = "" if fname else extension_for(part.get_content_type())
                    name = f"{i:02d}_{safe_filename(str(label))}{pext}"
                    self._write_file(os.path.join("parts", name), payload)
                    produced.append("parts/" + name)
        return produced


# --------------------------------------------------------------------------
# ICAP protocol
# --------------------------------------------------------------------------

class ICAPHandler(socketserver.StreamRequestHandler):
    config: Config = None
    store: CaptureStore = None
    istag = None

    def setup(self):
        self.request.settimeout(self.config.timeout)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def handle(self):
        try:
            while self.handle_one():
                pass
        except (ConnectionError, socket.timeout, ssl.SSLError) as e:
            log.debug("connection %s closed: %s", self.client_address[0], e)

    # -- low-level reading ------------------------------------------------

    def readline(self):
        line = self.rfile.readline(MAX_LINE + 1)
        if len(line) > MAX_LINE:
            raise ICAPError(400, "Line too long")
        return line

    def read_exact(self, n):
        data = self.rfile.read(n)
        if len(data) != n:
            raise ConnectionError("unexpected EOF")
        return data

    def read_chunked(self, sink):
        """Read an ICAP chunked body, passing data to sink().

        Returns True if the terminating chunk carried the "ieof" extension.
        """
        while True:
            line = self.readline()
            if not line:
                raise ConnectionError("unexpected EOF in chunked body")
            line = line.strip()
            if not line:
                continue
            size_part, _, ext = line.partition(b";")
            try:
                size = int(size_part.strip(), 16)
            except ValueError:
                raise ICAPError(400, "Bad chunk size")
            if size == 0:
                # Skip optional trailers up to the blank line.
                while True:
                    t = self.readline()
                    if t in (b"\r\n", b"\n", b""):
                        break
                return b"ieof" in ext.lower()
            data = self.read_exact(size)
            self.readline()  # CRLF after chunk data
            sink(data)

    # -- writing ----------------------------------------------------------

    def send_response(self, code, headers=(), encapsulated=b""):
        out = [f"ICAP/1.0 {code} {REASONS.get(code, '')}".encode()]
        base = [
            ("ISTag", f'"{self.istag}"'),
            ("Date", time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())),
            ("Server", f"Forensics-ICAP/{__version__}"),
        ]
        for k, v in list(base) + list(headers):
            out.append(f"{k}: {v}".encode("latin-1"))
        self.wfile.write(b"\r\n".join(out) + b"\r\n\r\n" + encapsulated)

    def write_chunk(self, data):
        self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")

    # -- request handling -------------------------------------------------

    def handle_one(self):
        line = self.readline()
        if not line:
            return False
        if not line.strip():
            return True
        self.close_after = False
        try:
            parts = line.strip().split()
            if len(parts) != 3:
                raise ICAPError(400, "Bad request line")
            method, uri, version = (p.decode("latin-1") for p in parts)
            if not version.startswith("ICAP/"):
                raise ICAPError(400, "Bad protocol")
            if version != "ICAP/1.0":
                raise ICAPError(505, "Only ICAP/1.0 is supported")

            icap_headers = self.read_icap_headers()
            if (first(icap_headers, "connection") or "").lower() == "close":
                self.close_after = True

            service = uri.split("://", 1)[-1].split("/", 1)[-1].split("?", 1)[0].strip("/")
            if method == "OPTIONS":
                self.do_options(service)
            elif method in ("REQMOD", "RESPMOD"):
                self.do_modify(method, uri, service, icap_headers)
            else:
                raise ICAPError(501, f"{method} not implemented")
        except ICAPError as e:
            log.warning("%s: ICAP %d %s", self.client_address[0], e.code, e.message)
            self.send_response(e.code, [("Connection", "close"),
                                        ("Encapsulated", "null-body=0")])
            self.close_after = True
        self.wfile.flush()
        return not self.close_after

    def read_icap_headers(self):
        raw = b""
        while True:
            line = self.readline()
            if not line:
                raise ConnectionError("EOF in ICAP headers")
            if line in (b"\r\n", b"\n"):
                break
            raw += line
        return parse_http_headers(b"x\r\n" + raw)[1]

    def do_options(self, service):
        if service.lower() in ("reqmod", "request"):
            methods = "REQMOD"
        elif service.lower() in ("respmod", "response"):
            methods = "RESPMOD"
        else:
            methods = "REQMOD, RESPMOD"
        self.send_response(200, [
            ("Methods", methods),
            ("Service", f"Forensics-ICAP/{__version__} passive capture"),
            ("Allow", "204"),
            ("Preview", str(self.config.preview)),
            ("Transfer-Preview", "*"),
            ("Options-TTL", str(self.config.options_ttl)),
            ("Max-Connections", str(self.config.max_connections)),
            ("Encapsulated", "null-body=0"),
        ])
        log.debug("%s: OPTIONS %s", self.client_address[0], service)

    def read_encapsulated_headers(self, icap_headers):
        enc = first(icap_headers, "encapsulated")
        if not enc:
            raise ICAPError(400, "Missing Encapsulated header")
        sections = []
        for item in enc.split(","):
            try:
                name, off = item.strip().split("=")
                sections.append((name.strip().lower(), int(off)))
            except ValueError:
                raise ICAPError(400, "Malformed Encapsulated header")
        sections.sort(key=lambda s: s[1])
        raw = {}
        body_type = None
        for i, (name, off) in enumerate(sections):
            if name.endswith("-hdr"):
                if i + 1 >= len(sections):
                    raise ICAPError(400, "Encapsulated header section without end")
                raw[name] = self.read_exact(sections[i + 1][1] - off)
            else:
                body_type = name
        return raw, body_type

    def do_modify(self, method, uri, service, icap_headers):
        raw, body_type = self.read_encapsulated_headers(icap_headers)
        req_raw = raw.get("req-hdr", b"")
        res_raw = raw.get("res-hdr", b"")
        has_body = body_type in ("req-body", "res-body")

        allow = first(icap_headers, "allow") or ""
        allow_204 = "204" in [a.strip() for a in allow.split(",")]
        preview = first(icap_headers, "preview")

        capture = None
        try:
            capture = self.store.begin()
        except Exception:
            log.exception("cannot create capture directory; traffic will pass uncaptured")

        # If we may have to echo the message back, keep a full copy.
        echo = None if allow_204 else tempfile.SpooledTemporaryFile(max_size=4 * 1024 * 1024)

        def sink(data):
            nonlocal capture
            if echo is not None:
                echo.write(data)
            if capture is not None:
                try:
                    capture.write(data)
                except Exception:
                    log.exception("capture write failed; continuing without capture")
                    capture.abort()
                    capture = None

        try:
            preview_done = False
            if has_body:
                ieof = self.read_chunked(sink)
                if preview is not None:
                    if ieof:
                        preview_done = True
                    else:
                        self.wfile.write(b"ICAP/1.0 100 Continue\r\n\r\n")
                        self.wfile.flush()
                        self.read_chunked(sink)
        except BaseException:
            if capture is not None:
                capture.abort()
            raise

        if capture is not None:
            try:
                meta = self.build_metadata(method, uri, service, icap_headers, req_raw, res_raw)
                path = capture.finish(meta, req_raw, res_raw)
                if path:
                    log.info("%s %s %s %s -> %s (%d bytes)", self.client_address[0], method,
                             meta["http"].get("method") or "-", meta["http"].get("url") or "-",
                             os.path.relpath(path, self.store.root), capture.size)
            except Exception:
                log.exception("failed to finalise capture %s", capture.id)
                capture.abort()

        # We never change anything: tell the client to use its original copy.
        if allow_204 or preview_done:
            self.send_response(204, [("Encapsulated", "null-body=0")])
        else:
            self.echo_original(method, req_raw, res_raw, has_body, echo)
        if echo is not None:
            echo.close()

    def echo_original(self, method, req_raw, res_raw, has_body, echo):
        hdr = res_raw if method == "RESPMOD" else req_raw
        kind = "res" if method == "RESPMOD" else "req"
        if not hdr:
            self.send_response(200, [("Encapsulated", "null-body=0")])
            return
        body_tag = f"{kind}-body" if has_body else "null-body"
        self.send_response(200, [("Encapsulated", f"{kind}-hdr=0, {body_tag}={len(hdr)}")], hdr)
        if has_body:
            echo.seek(0)
            while True:
                data = echo.read(COPY_CHUNK)
                if not data:
                    break
                self.write_chunk(data)
            self.wfile.write(b"0\r\n\r\n")

    def build_metadata(self, method, uri, service, icap_headers, req_raw, res_raw):
        req_line, req_h = parse_http_headers(req_raw) if req_raw else ("", {})
        res_line, res_h = parse_http_headers(res_raw) if res_raw else ("", {})

        http_method = url = None
        if req_line:
            bits = req_line.split(" ")
            http_method = bits[0]
            url = bits[1] if len(bits) > 1 else None
            if url and url.startswith("/") and first(req_h, "host"):
                url = "http://" + first(req_h, "host") + url

        status = None
        if res_line:
            bits = res_line.split(" ")
            if len(bits) > 1 and bits[1].isdigit():
                status = int(bits[1])

        body_h = res_h if method == "RESPMOD" else req_h
        content_type = first(body_h, "content-type")
        filename = filename_from_disposition(first(body_h, "content-disposition"))
        if not filename and url:
            last = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            if "." in last:
                filename = last

        user = (first(icap_headers, "x-authenticated-user")
                or first(icap_headers, "x-client-username")
                or first(icap_headers, "x-user"))

        return {
            "time": datetime.now(timezone.utc).isoformat(),
            "icap": {
                "method": method,
                "uri": uri,
                "service": service,
                "peer": f"{self.client_address[0]}:{self.client_address[1]}",
                "client_ip": first(icap_headers, "x-client-ip"),
                "user": user,
                "headers": icap_headers,
            },
            "http": {
                "method": http_method,
                "url": url,
                "status": status,
                "request_line": req_line or None,
                "status_line": res_line or None,
                "content_type": content_type,
                "content_encoding": first(body_h, "content-encoding"),
                "filename": filename,
                "request_headers": req_h,
                "response_headers": res_h,
            },
        }


class ThreadingICAPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def build_server(config):
    store = CaptureStore(config.capture_dir, config.max_body_bytes, config.save_empty)
    istag = "FI-" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
    handler = type("Handler", (ICAPHandler,), {"config": config, "store": store, "istag": istag})
    server = ThreadingICAPServer((config.host, config.port), handler)
    if config.tls_cert and config.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(config.tls_cert, config.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                        do_handshake_on_connect=False)
    return server


def healthcheck(config):
    """Send OPTIONS to the local server; exit 0 if it answers 200."""
    try:
        sock = socket.create_connection(("127.0.0.1", config.port), timeout=5)
        if config.tls_cert:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        with sock:
            sock.sendall(b"OPTIONS icap://127.0.0.1/respmod ICAP/1.0\r\n"
                         b"Host: 127.0.0.1\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n")
            ok = sock.recv(64).startswith(b"ICAP/1.0 200")
    except OSError:
        ok = False
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--healthcheck", action="store_true",
                        help="probe the running server and exit 0/1")
    args = parser.parse_args(argv)
    config = Config()

    if args.healthcheck:
        return healthcheck(config)

    logging.basicConfig(level=config.log_level,
                        format="%(asctime)s %(levelname)s %(threadName)s %(message)s")
    server = build_server(config)

    def stop(signum, _frame):
        log.info("signal %d received, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    log.info("Forensics ICAP %s listening on %s:%d (%s), saving to %s",
             __version__, config.host, config.port,
             "ICAPS/TLS" if config.tls_cert else "plain", config.capture_dir)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
