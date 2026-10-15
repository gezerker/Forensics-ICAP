"""Tests for the capture web UI: captures are sent over real ICAP, then read back over HTTP."""

import os
import re
import socket
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import icap_server  # noqa: E402
import web_ui  # noqa: E402
import test_icap_server as base  # noqa: E402  (reuse the ICAP request helpers)


class WebUITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.update(CAPTURE_DIR=self.tmp.name, ICAP_HOST="127.0.0.1", ICAP_PORT="0",
                          WEB_HOST="127.0.0.1", WEB_PORT="0",
                          MAX_BODY_BYTES="1000000", SAVE_EMPTY="1")
        self.config = icap_server.Config()
        self.icap = icap_server.build_server(self.config)
        self.icap_port = self.icap.server_address[1]
        self.web = web_ui.build_web_server(self.config)
        self.web_base = "http://127.0.0.1:%d" % self.web.server_address[1]
        for srv in (self.icap, self.web):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def tearDown(self):
        for srv in (self.icap, self.web):
            srv.shutdown()
            srv.server_close()
        self.tmp.cleanup()

    def send_icap(self, head, body_chunks):
        with socket.create_connection(("127.0.0.1", self.icap_port), timeout=5) as s:
            s.sendall(head + body_chunks)
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                b = s.recv(65536)
                if not b:
                    return data
                data += b

    def get(self, path):
        try:
            with urlopen(self.web_base + path, timeout=5) as r:
                return r.status, r.headers, r.read().decode("utf-8", errors="replace")
        except HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", errors="replace")

    def post_urlencoded(self, body):
        head, _ = base.ICAPServerTest.reqmod(
            body, b"Content-Type: application/x-www-form-urlencoded\r\n"
                  b"Content-Length: %d\r\n" % len(body))
        resp = self.send_icap(head, base.chunk(body) + b"0\r\n\r\n")
        self.assertTrue(resp.startswith(b"ICAP/1.0 204"), resp)

    def post_multipart(self):
        boundary = b"BND"
        body = (b"--BND\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<b>hi</b>\r\n"
                b"--BND\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"report.pdf\"\r\n"
                b"Content-Type: application/pdf\r\n\r\n%PDF-1.4 test\r\n--BND--\r\n")
        head, _ = base.ICAPServerTest.reqmod(
            body, b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n")
        self.send_icap(head, base.chunk(body) + b"0\r\n\r\n")

    def capture_ids(self):
        return [rec["id"] for rec in web_ui.CaptureReader(self.tmp.name).index()]

    def test_list_shows_captures(self):
        self.post_urlencoded(b"user=alice&password=hunter2")
        status, _, page = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("http://example.com/upload", page)
        self.assertIn("alice", page)

    def test_forms_page_lists_form_submissions(self):
        self.post_urlencoded(b"user=alice&password=hunter2")
        self.post_multipart()
        status, _, page = self.get("/forms")
        self.assertEqual(status, 200)
        self.assertIn("Forms (2)", page)

    def test_urlencoded_fields_are_shown(self):
        self.post_urlencoded(b"user=alice&password=hunter2&note=a+b")
        [cid] = self.capture_ids()
        status, _, page = self.get("/capture/" + cid)
        self.assertEqual(status, 200)
        self.assertIn("Form fields (urlencoded)", page)
        self.assertIn("hunter2", page)
        self.assertIn("a b", page)

    def test_multipart_fields_and_files_are_shown_and_escaped(self):
        self.post_multipart()
        [cid] = self.capture_ids()
        status, _, page = self.get("/capture/" + cid)
        self.assertEqual(status, 200)
        self.assertIn("Form fields (multipart)", page)
        self.assertIn("&lt;b&gt;hi&lt;/b&gt;", page)
        self.assertNotIn("<b>hi</b>", page)
        self.assertIn("report.pdf", page)

    def test_listed_file_downloads_as_attachment(self):
        self.post_multipart()
        [cid] = self.capture_ids()
        _, _, page = self.get("/capture/" + cid)
        href = re.search(r"href='(/capture/[^']+/files/parts/02_report\.pdf)'", page).group(1)
        status, headers, body = self.get(href)
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Disposition"].startswith("attachment"))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("%PDF-1.4 test", body)

    def test_unlisted_file_is_not_served(self):
        self.post_urlencoded(b"a=b")
        [cid] = self.capture_ids()
        for name in ("metadata.json", "../../index.jsonl", "..%2F..%2Findex.jsonl"):
            status, _, _ = self.get("/capture/%s/files/%s" % (cid, quote(name, safe="")))
            self.assertEqual(status, 404, name)

    def test_unknown_capture_is_404(self):
        status, _, _ = self.get("/capture/doesnotexist")
        self.assertEqual(status, 404)

    def test_healthz(self):
        status, _, body = self.get("/healthz")
        self.assertEqual((status, body), (200, "ok"))


if __name__ == "__main__":
    unittest.main()
