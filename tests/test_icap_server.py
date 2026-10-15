"""End-to-end tests: start the server on a random port and talk raw ICAP to it."""

import gzip
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import icap_server  # noqa: E402


def chunk(data):
    return b"%x\r\n" % len(data) + data + b"\r\n"


class ICAPServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.update(CAPTURE_DIR=self.tmp.name, ICAP_HOST="127.0.0.1", ICAP_PORT="0",
                          MAX_BODY_BYTES="1000000", SAVE_EMPTY="1")
        self.config = icap_server.Config()
        self.server = icap_server.build_server(self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def exchange(self, payload, preview_continue=False):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            if preview_continue:
                head, rest = payload
                s.sendall(head)
                resp = s.recv(100)
                self.assertTrue(resp.startswith(b"ICAP/1.0 100"), resp)
                s.sendall(rest)
            else:
                s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                b = s.recv(65536)
                if not b:
                    return data
                data += b

    def captures(self):
        with open(os.path.join(self.tmp.name, "index.jsonl")) as f:
            return [json.loads(line) for line in f]

    def capture_dir(self, rec):
        return os.path.join(self.tmp.name, rec["path"])

    @staticmethod
    def reqmod(body, http_headers, allow204=True, preview=None, ieof=False):
        req = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n" + http_headers + b"\r\n"
        icap = b"REQMOD icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: 127.0.0.1\r\n"
        icap += b"X-Client-IP: 10.1.2.3\r\nX-Authenticated-User: alice\r\n"
        if allow204:
            icap += b"Allow: 204\r\n"
        if preview is not None:
            icap += b"Preview: %d\r\n" % preview
        icap += b"Connection: close\r\n"
        icap += b"Encapsulated: req-hdr=0, req-body=%d\r\n\r\n" % len(req)
        return icap + req, body

    def test_options(self):
        resp = self.exchange(b"OPTIONS icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: x\r\n"
                             b"Connection: close\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 200 OK"))
        self.assertIn(b"Methods: REQMOD", resp)
        self.assertIn(b"Allow: 204", resp)

    def test_reqmod_saves_body_and_returns_204(self):
        body = b"secret=1234-5678-9012-3456"
        head, _ = self.reqmod(body, b"Content-Type: text/plain\r\nContent-Length: 26\r\n")
        resp = self.exchange(head + chunk(body[:10]) + chunk(body[10:]) + b"0\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 204"), resp)

        [rec] = self.captures()
        self.assertEqual(rec["url"], "http://example.com/upload")
        self.assertEqual(rec["client_ip"], "10.1.2.3")
        self.assertEqual(rec["user"], "alice")
        self.assertEqual(rec["bytes"], len(body))
        d = self.capture_dir(rec)
        with open(os.path.join(d, "body.txt"), "rb") as f:
            self.assertEqual(f.read(), body)
        with open(os.path.join(d, "metadata.json")) as f:
            meta = json.load(f)
        self.assertEqual(meta["capture"]["sha256"], rec["sha256"])
        self.assertTrue(os.path.exists(os.path.join(d, "http_request_headers.txt")))

    def test_echo_when_204_not_allowed(self):
        body = b"x" * 5000
        head, _ = self.reqmod(body, b"Content-Type: application/octet-stream\r\n", allow204=False)
        resp = self.exchange(head + chunk(body) + b"0\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 200"), resp[:100])
        self.assertIn(b"POST /upload HTTP/1.1", resp)
        self.assertTrue(resp.endswith(b"1388\r\n" + body + b"\r\n0\r\n\r\n"))

    def test_preview_then_continue(self):
        body = b"A" * 100 + b"B" * 100
        head, _ = self.reqmod(body, b"Content-Type: text/plain\r\n", preview=100)
        first = head + chunk(body[:100]) + b"0\r\n\r\n"
        rest = chunk(body[100:]) + b"0\r\n\r\n"
        resp = self.exchange((first, rest), preview_continue=True)
        self.assertIn(b"ICAP/1.0 204", resp)
        [rec] = self.captures()
        with open(os.path.join(self.capture_dir(rec), "body.txt"), "rb") as f:
            self.assertEqual(f.read(), body)

    def test_preview_ieof(self):
        body = b"small"
        head, _ = self.reqmod(body, b"Content-Type: text/plain\r\n", allow204=False, preview=1024)
        resp = self.exchange(head + chunk(body) + b"0; ieof\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 204"), resp)
        self.assertEqual(self.captures()[0]["bytes"], 5)

    def test_multipart_upload_extracted(self):
        boundary = b"XyZ"
        body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
                b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../evil.pdf\"\r\n"
                b"Content-Type: application/pdf\r\n\r\n%PDF-1.4 fake\r\n--XyZ--\r\n")
        head, _ = self.reqmod(body, b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n")
        self.exchange(head + chunk(body) + b"0\r\n\r\n")
        d = self.capture_dir(self.captures()[0])
        parts = sorted(os.listdir(os.path.join(d, "parts")))
        self.assertEqual(parts, ["01_field_note.txt", "02_evil.pdf"])
        with open(os.path.join(d, "parts", "02_evil.pdf"), "rb") as f:
            self.assertEqual(f.read(), b"%PDF-1.4 fake")

    def test_respmod_gzip_decoded(self):
        plain = b"<html>leaked data</html>"
        body = gzip.compress(plain)
        req = b"GET /page HTTP/1.1\r\nHost: example.org\r\n\r\n"
        res = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n")
        icap = (b"RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\nHost: x\r\nAllow: 204\r\n"
                b"Connection: close\r\n"
                b"Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n"
                % (len(req), len(req) + len(res)))
        resp = self.exchange(icap + req + res + chunk(body) + b"0\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 204"))
        [rec] = self.captures()
        self.assertEqual(rec["status"], 200)
        self.assertEqual(rec["url"], "http://example.org/page")
        with open(os.path.join(self.capture_dir(rec), "body_decoded.html"), "rb") as f:
            self.assertEqual(f.read(), plain)

    def test_keepalive_multiple_requests_and_truncation(self):
        self.server.RequestHandlerClass.store.max_body_bytes = 10
        body = b"0123456789ABCDEF"
        head, _ = self.reqmod(body, b"Content-Type: text/plain\r\n")
        head = head.replace(b"Connection: close\r\n", b"")
        one = head + chunk(body) + b"0\r\n\r\n"
        resp = self.exchange(one + one + b"OPTIONS icap://x/ ICAP/1.0\r\nConnection: close\r\n\r\n")
        self.assertEqual(resp.count(b"ICAP/1.0 204"), 2)
        self.assertEqual(resp.count(b"ICAP/1.0 200"), 1)
        recs = self.captures()
        self.assertEqual(len(recs), 2)
        with open(os.path.join(self.capture_dir(recs[0]), "metadata.json")) as f:
            cap = json.load(f)["capture"]
        self.assertTrue(cap["truncated"])
        self.assertEqual(cap["body_bytes"], 16)
        self.assertEqual(cap["body_bytes_stored"], 10)

    def test_null_body_get(self):
        req = b"GET /x HTTP/1.1\r\nHost: a.b\r\n\r\n"
        icap = (b"REQMOD icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: x\r\nConnection: close\r\n"
                b"Encapsulated: req-hdr=0, null-body=%d\r\n\r\n" % len(req))
        resp = self.exchange(icap + req)
        self.assertTrue(resp.startswith(b"ICAP/1.0 200"))
        self.assertTrue(resp.endswith(req))
        [rec] = self.captures()
        self.assertEqual(rec["bytes"], 0)

    def test_bad_request(self):
        resp = self.exchange(b"GARBAGE\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 400"))

    def test_healthcheck(self):
        os.environ["ICAP_PORT"] = str(self.port)
        self.assertEqual(icap_server.healthcheck(icap_server.Config()), 0)


if __name__ == "__main__":
    unittest.main()
