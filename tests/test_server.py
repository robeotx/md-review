"""Server tests: the LAN-only guard, every route, and an end-to-end comment
flow against a real server on an ephemeral loopback port."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from mdreview import store
from mdreview.server import ReviewHandler, ReviewServer, is_lan_client, vendored_ds_dir


class LanGuardTests(unittest.TestCase):
    """The guard is the one feature that must never regress: a tool holding
    unauthenticated comments must not become reachable from the internet."""

    def test_public_ips_refused(self) -> None:
        public = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "9.255.255.1", "2606:4700:4700::1111", "100.128.0.1"]
        for addr in public:
            self.assertFalse(is_lan_client(addr), f"{addr} must be refused")

    def test_special_registries_refused(self) -> None:
        # The explicit allowlist (NOT ipaddress.is_private) must refuse
        # documentation/benchmarking/reserved ranges — they are not LAN
        # addresses even though they are never globally routed. This is what
        # makes the guard stable across CPython upgrades that reshuffle
        # is_private's meaning.
        special = ["203.0.113.9", "192.0.2.1", "198.51.100.2", "198.18.0.5", "240.0.0.1", "0.0.0.0", "2001:db8::1"]
        for addr in special:
            self.assertFalse(is_lan_client(addr), f"{addr} must be refused by the explicit allowlist")

    def test_private_loopback_linklocal_allowed(self) -> None:
        local = [
            "127.0.0.1",
            "127.34.56.7",
            "10.0.0.2",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.20",
            "169.254.10.20",
            "100.64.0.1",  # RFC 6598 shared space — Tailscale range (VPN remote-access story)
            "100.96.0.9",
            "100.127.255.254",
            "::1",
            "fe80::1",
            "fd00::1234",
            "fc12:abcd::1",
        ]
        for addr in local:
            self.assertTrue(is_lan_client(addr), f"{addr} must be admitted")

    def test_ipv4_mapped_normalized(self) -> None:
        # IPv4-mapped IPv6 must classify by the MAPPED address: private mapped
        # in, public mapped out. Unnormalized, ::ffff:8.8.8.8 would be "v6,
        # not in v6 lists → refused" (lucky), but ::ffff:10.x needs the map to
        # be admitted — and a future v6-list change must never launder a
        # public v4 address through it.
        self.assertTrue(is_lan_client("::ffff:10.1.2.3"))
        self.assertTrue(is_lan_client("::ffff:127.0.0.1"))
        self.assertFalse(is_lan_client("::ffff:8.8.8.8"))
        self.assertFalse(is_lan_client("::ffff:203.0.113.9"))

    def test_zone_id_stripped_and_garbage_refused(self) -> None:
        self.assertTrue(is_lan_client("fe80::1%eth0"))
        self.assertFalse(is_lan_client("not-an-ip"))
        self.assertFalse(is_lan_client(""))

    def test_server_verify_request_refuses_public_client(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            server = ReviewServer(
                ("127.0.0.1", 0),
                ReviewHandler,
                data_dir=Path(td),
                ds_dir=vendored_ds_dir(),
                default_author="Tester",
            )
            try:
                self.assertFalse(server.verify_request(None, ("8.8.8.8", 5000)))
                self.assertTrue(server.verify_request(None, ("192.168.1.5", 5000)))
                self.assertTrue(server.verify_request(None, ("127.0.0.1", 5000)))
            finally:
                server.server_close()


class HostHeaderTests(unittest.TestCase):
    def test_lan_ip_literals_and_localhost_allowed(self) -> None:
        from mdreview.server import host_allowed

        for host in ["127.0.0.1:8779", "10.0.0.45:8779", "192.168.1.10", "localhost", "localhost:8779", "[::1]:8779"]:
            self.assertTrue(host_allowed(host), host)

    def test_machine_hostname_allowed(self) -> None:
        import socket as _socket

        from mdreview.server import host_allowed

        self.assertTrue(host_allowed(_socket.gethostname()))
        self.assertTrue(host_allowed(f"{_socket.gethostname()}.local:8779"))

    def test_foreign_names_refused(self) -> None:
        from mdreview.server import host_allowed

        # DNS-rebinding shape: attacker domain → 127.0.0.1. Never resolved,
        # simply not a known local name.
        for host in ["evil.example", "attacker.com:8779", "8.8.8.8:8779", "203.0.113.5", "", "victim-host.evil.example"]:
            self.assertFalse(host_allowed(host), host)

    def test_garbage_port_suffix_refused(self) -> None:
        from mdreview.server import host_allowed

        # `127.0.0.1:evil.com` used to pass (everything after the
        # last colon was blindly stripped). A non-numeric port poisons the
        # whole header.
        self.assertFalse(host_allowed("127.0.0.1:evil.com"))
        self.assertFalse(host_allowed("127.0.0.1:8779/x"))
        self.assertTrue(host_allowed("127.0.0.1:8779"))

    def test_out_of_range_port_refused(self) -> None:
        from mdreview.server import host_allowed

        self.assertFalse(host_allowed("127.0.0.1:99999"))
        self.assertFalse(host_allowed("127.0.0.1:0"))
        self.assertTrue(host_allowed("127.0.0.1:65535"))

    def test_unicode_digit_port_refused_without_crash(self) -> None:
        # '\xb2' (superscript two) passes str.isdigit() but explodes int() — must refuse, never raise.
        from mdreview.server import host_allowed

        self.assertFalse(host_allowed("127.0.0.1:\xb2"))
        self.assertFalse(host_allowed("127.0.0.1:8²79"))

    def test_extra_hosts_env_allowlist(self) -> None:
        from mdreview.server import host_allowed

        with mock.patch.dict(os.environ, {"MD_REVIEW_EXTRA_HOSTS": "review.lan, nas.internal"}):
            self.assertTrue(host_allowed("review.lan"))
            self.assertTrue(host_allowed("nas.internal:8779"))
            self.assertFalse(host_allowed("other.lan"))


class ServerTestCase(unittest.TestCase):
    """Spins a real server on an ephemeral loopback port per test class."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.data_dir = Path(cls._tmp.name) / "data"
        cls.server = ReviewServer(
            ("127.0.0.1", 0),
            ReviewHandler,
            data_dir=cls.data_dir,
            ds_dir=vendored_ds_dir(),
            default_author="Tester",
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls._tmp.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path: str) -> tuple[int, bytes, str]:
        try:
            with urllib.request.urlopen(self.url(path), timeout=10) as resp:
                return resp.status, resp.read(), resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers.get("Content-Type", "") if exc.headers else ""

    def post(self, path: str, payload: object, headers: dict | None = None, raw_body: bytes | None = None) -> tuple[int, dict]:
        merged_headers = {"Content-Type": "application/json"}
        if headers:
            merged_headers.update(headers)
        body = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.url(path), data=body, headers=merged_headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8")
            try:
                return exc.code, json.loads(body_text)
            except json.JSONDecodeError:
                return exc.code, {"raw": body_text}


class BrowserAttackDefenseTests(ServerTestCase):
    """CSRF / DNS-rebinding / framing defenses."""

    def _doc(self) -> str:
        md = self.data_dir.parent / "csrf-target.md"
        md.write_text("# T\n\nbody\n", encoding="utf-8")
        return store.render_document(md, self.data_dir, "T").parent.name

    def test_text_plain_post_refused_415(self) -> None:
        # The drive-by shape: a cross-origin "simple request" needs no
        # preflight, so text/plain must never reach the JSON parser.
        status, payload = self.post(
            "/api/render",
            {},
            headers={"Content-Type": "text/plain"},
            raw_body=b'{"markdown": "# x", "sourcePath": "x.md"}',
        )
        self.assertEqual(status, 415)

    def test_form_post_refused_415(self) -> None:
        status, _ = self.post(
            "/comments", {}, headers={"Content-Type": "application/x-www-form-urlencoded"}, raw_body=b"docId=x"
        )
        self.assertEqual(status, 415)

    def test_foreign_host_header_refused_403(self) -> None:
        request = urllib.request.Request(self.url("/health"), headers={"Host": "attacker.example:8779"})
        try:
            urllib.request.urlopen(request, timeout=10)
            self.fail("foreign Host must be refused")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 403)

    def test_cross_origin_header_refused_403(self) -> None:
        doc_id = self._doc()
        status, payload = self.post(
            "/comments",
            {
                "docId": doc_id,
                "anchor": {
                    "type": "md-element",
                    "anchorId": "a-1",
                    "semanticKey": "root::paragraph::1",
                    "elementKind": "paragraph",
                    "label": "paragraph · Document",
                },
                "text": "cross-origin attempt",
            },
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("cross-origin", payload["error"])

    def test_cross_site_fetch_metadata_refused_403(self) -> None:
        status, _ = self.post("/api/render", {}, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

    def test_same_origin_headers_pass(self) -> None:
        # Same-origin browser shape: Origin host == Host header. urllib sends
        # Host: 127.0.0.1:<port>; mirror that in Origin.
        status, _ = self.post(
            "/api/render",
            {"markdown": "# ok\n", "sourcePath": "ok.md", "provenance": {}},
            headers={"Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 201)

    def test_missing_content_length_411(self) -> None:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/comments", skip_accept_encoding=True)
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()  # no Content-Length at all
        response = conn.getresponse()
        response.read()
        self.assertEqual(response.status, 411)
        conn.close()

    def test_chunked_transfer_encoding_501(self) -> None:
        request = urllib.request.Request(
            self.url("/comments"),
            data=b"4\r\ntest\r\n0\r\n\r\n",
            headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=10)
            self.fail("chunked bodies must be refused")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 501)

    def test_rejected_post_cannot_smuggle_a_second_request(self) -> None:
        # a text/plain POST is rejected
        # 415 BEFORE the body is read; on keep-alive the undrained body used to
        # be parsed as the NEXT request — carrying none of the headers the
        # gates inspect. Post-fix the rejection must close the connection and
        # the store must stay untouched.
        import socket as _socket

        smuggled_body = (
            "POST /api/render HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 62\r\n"
            "\r\n"
            '{"markdown": "# SMUGGLED", "sourcePath": "attacker/smuggled.md"}'
        )
        outer = (
            "POST /decoy HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Content-Type: text/plain\r\n"
            "Origin: https://evil.example\r\n"
            "Sec-Fetch-Site: cross-site\r\n"
            f"Content-Length: {len(smuggled_body.encode())}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            f"{smuggled_body}"
        )
        with _socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(outer.encode())
            response = sock.recv(65536).decode("utf-8", errors="replace")
        self.assertIn("415", response.split("\r\n", 1)[0])
        # The smuggled request must NOT have executed: no 201, no doc.
        self.assertNotIn("201 Created", response)
        status, body, _ = self.get("/api/docs")
        self.assertEqual(status, 200)
        titles = [d["title"] for d in json.loads(body)["docs"]]
        self.assertNotIn("SMUGGLED", titles)

    def test_get_with_body_rejected_and_closed(self) -> None:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/health", body=b"x" * 10, headers={"Content-Length": "10"})
        response = conn.getresponse()
        response.read()
        self.assertEqual(response.status, 400)
        conn.close()

    def test_security_headers_on_pages(self) -> None:
        doc_id = self._doc()
        for path in ("/", f"/rendered/{doc_id}/index.html"):
            request = urllib.request.Request(self.url(path))
            with urllib.request.urlopen(request, timeout=10) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")
                self.assertIn("connect-src 'self'", csp, path)
                self.assertIn("style-src 'self' 'unsafe-inline'", csp, path)  # without 'self', /ds/ css is blocked
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY", path)

    def test_ds_nul_rejected_400(self) -> None:
        status, _, _ = self.get("/ds/%00")
        self.assertEqual(status, 400)
        status, _, _ = self.get("/ds/a%00b.css")
        self.assertEqual(status, 400)

    def test_render_caps_enforced(self) -> None:
        status, payload = self.post(
            "/api/render", {"markdown": "x" * (2 * 1024 * 1024 + 10), "sourcePath": "big.md"}
        )
        self.assertEqual(status, 413)
        status, payload = self.post("/api/render", {"markdown": "# ok\n", "sourcePath": "p" * 2000})
        self.assertEqual(status, 400)

    def test_render_failure_error_is_generic(self) -> None:
        # A sourcePath whose derived doc dir cannot be created must not leak
        # the server's absolute data-dir path into the response.
        from mdreview.store import doc_id_for

        doc_id = doc_id_for("conflict.md", "")
        blocker = self.data_dir / "rendered" / doc_id
        blocker.parent.mkdir(parents=True, exist_ok=True)
        blocker.write_text("i am a file, not a dir", encoding="utf-8")
        status, payload = self.post(
            "/api/render", {"markdown": "# x\n", "sourcePath": "conflict.md", "provenance": {}}
        )
        self.assertEqual(status, 500)
        self.assertNotIn(str(self.data_dir), json.dumps(payload))
        self.assertIn("server log", payload["error"])

    def test_head_matches_get_status(self) -> None:
        doc_id = self._doc()
        for path, want in [
            ("/health", 200),
            ("/", 200),
            (f"/rendered/{doc_id}/index.html", 200),
            (f"/rendered/{doc_id}/secret.txt", 403),
            ("/rendered/nope/index.html", 404),
            ("/ds/design-app/tokens.css", 200),
            ("/ds/../store.py", 403),
            ("/nope", 404),
        ]:
            request = urllib.request.Request(self.url(path), method="HEAD")
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    self.assertEqual(resp.status, want, path)
                    self.assertEqual(resp.read(), b"", f"HEAD must not return a body: {path}")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, want, path)


class ProvenanceNormalizationTests(ServerTestCase):
    def test_hostile_provenance_types_cannot_crash_index(self) -> None:
        # an int sessionId used to persist fine, then raise
        # inside html.escape on every subsequent GET /.
        status, result = self.post(
            "/api/render",
            {
                "markdown": "# typed\n",
                "sourcePath": "typed.md",
                "provenance": {"sessionId": 7, "sourceRepoName": {"nested": True}, "agentCwd": 3.5},
            },
        )
        self.assertEqual(status, 201)
        manifest = json.loads((self.data_dir / "rendered" / result["docId"] / "manifest.json").read_text("utf-8"))
        prov = manifest["provenance"]
        self.assertEqual(prov["sessionId"], "7")  # scalar coerced to string
        self.assertIsNone(prov["sourceRepoName"])  # nested object rejected
        self.assertEqual(prov["agentCwd"], "3.5")
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)

    def test_numeric_filename_falls_back_instead_of_500(self) -> None:
        status, result = self.post(
            "/api/render", {"markdown": "# fn\n", "sourcePath": "dir/fn.md", "filename": 123}
        )
        self.assertEqual(status, 201)
        self.assertIn("fn", result["title"])


class RouteTests(ServerTestCase):
    def test_health(self) -> None:
        status, body, _ = self.get("/health")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertIn("version", payload)

    def test_index_lists_rendered_doc_with_provenance(self) -> None:
        md = self.data_dir.parent / "x.md"
        md.write_text("# Hello\n\nworld\n", encoding="utf-8")
        store.render_document(md, self.data_dir, "X", session_id="sess-xyz", agent="test-agent")
        status, body, _ = self.get("/")
        text = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn(">X</a>", text)
        self.assertIn("session sess-xyz", text)
        self.assertIn("test-agent", text)

    def test_api_docs(self) -> None:
        status, body, _ = self.get("/api/docs")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIsInstance(payload["docs"], list)

    def test_rendered_page_and_allowlist(self) -> None:
        md = self.data_dir.parent / "y.md"
        md.write_text("# Page\n\nbody\n", encoding="utf-8")
        out = store.render_document(md, self.data_dir, "Y")
        doc_id = out.parent.name
        status, body, ctype = self.get(f"/rendered/{doc_id}/index.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"data-doc-root", body)
        status, body, _ = self.get(f"/rendered/{doc_id}/manifest.json")
        self.assertEqual(status, 200)
        self.assertIn("provenance", json.loads(body))
        # not allowlisted → refused even though the file exists
        (out.parent / "secret.txt").write_text("nope", encoding="utf-8")
        status, _, _ = self.get(f"/rendered/{doc_id}/secret.txt")
        self.assertEqual(status, 403)
        # traversal attempts → refused
        status, _, _ = self.get(f"/rendered/{doc_id}/../{doc_id}/index.html")
        self.assertIn(status, (400, 403, 404))
        status, _, _ = self.get("/rendered/..%2f..%2fetc/index.html")
        self.assertIn(status, (400, 403, 404))

    def test_ds_assets_served_and_guarded(self) -> None:
        status, body, ctype = self.get("/ds/design-app/tokens.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", ctype)
        self.assertIn(b"--rds-", body)
        status, body, ctype = self.get("/ds/components/components.css")
        self.assertEqual(status, 200)
        self.assertIn(b"rds-cmt-pop", body)
        # fonts referenced by tokens.css must resolve
        status, _, ctype = self.get("/ds/fonts/JetBrainsMono-latin.woff2")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "font/woff2")
        # traversal + suffix guard
        status, _, _ = self.get("/ds/../store.py")
        self.assertEqual(status, 403)
        status, _, _ = self.get("/ds/design-app/tokens.py")
        self.assertIn(status, (403, 404))

    def test_unknown_route_is_json_404(self) -> None:
        status, body, _ = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertIn("error", json.loads(body))


class CommentFlowTests(ServerTestCase):
    # Each test renders its OWN filename: doc ids derive from the source path,
    # and this class shares one server/store, so reusing a filename would pool
    # comments across tests.
    def _render_doc(self, name: str) -> str:
        md = self.data_dir.parent / name
        md.write_text("# Flow\n\nanchor me\n", encoding="utf-8")
        return store.render_document(md, self.data_dir, "Flow").parent.name

    def _anchor(self) -> dict:
        return {
            "type": "md-element",
            "anchorId": "a-1",
            "semanticKey": "root::paragraph::1",
            "elementKind": "paragraph",
            "label": "paragraph · Document",
            "quote": "anchor me",
        }

    def test_full_comment_lifecycle(self) -> None:
        doc_id = self._render_doc("flow-lifecycle.md")
        status, created = self.post(
            "/comments", {"docId": doc_id, "anchor": self._anchor(), "text": "first note", "quote": "anchor me"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["author"], "Tester", "default author should apply when body omits it")
        self.assertFalse(created["resolved"])
        self.assertEqual(created["doc_id"], doc_id)

        status, body, _ = self.get(f"/comments?doc={doc_id}")
        comments = json.loads(body)
        self.assertEqual(len(comments), 1)

        status, updated = self.post("/comments/resolve", {"docId": doc_id, "id": created["id"], "resolved": True})
        self.assertEqual(status, 200)
        self.assertTrue(updated["resolved"])

        status, missing = self.post("/comments/resolve", {"docId": doc_id, "id": "nope", "resolved": True})
        self.assertEqual(status, 404)

    def test_explicit_author_wins(self) -> None:
        doc_id = self._render_doc("flow-author.md")
        status, created = self.post(
            "/comments",
            {"docId": doc_id, "anchor": self._anchor(), "text": "hi", "author": "reviewer-on-phone"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["author"], "reviewer-on-phone")

    def test_comment_on_unknown_doc_404s(self) -> None:
        status, payload = self.post("/comments", {"docId": "ghost-doc", "anchor": self._anchor(), "text": "hi"})
        self.assertEqual(status, 404)

    def test_malformed_comment_bodies_get_400_not_dropped_connection(self) -> None:
        # _post_comment used to reference doc_id
        # from an except that runs before doc_id binds — malformed bodies got
        # a dropped connection (UnboundLocalError) instead of a clean 400.
        doc_id = self._render_doc("flow-malformed.md")
        bad_bodies = [
            {},
            {"docId": doc_id},
            {"docId": doc_id, "anchor": {}},
            {"docId": doc_id, "anchor": {"type": "other", "anchorId": "a", "semanticKey": "s",
                                         "elementKind": "paragraph", "label": "l"}, "text": "x"},
            {"docId": doc_id, "anchor": self._anchor(), "text": "   "},
            {"docId": doc_id, "anchor": {**self._anchor(), "docId": "other-doc"}, "text": "mismatch"},
        ]
        for body in bad_bodies:
            status, payload = self.post("/comments", body)
            self.assertEqual(status, 400, body)
            self.assertIn("error", payload, body)

    def test_comments_persisted_to_disk(self) -> None:
        doc_id = self._render_doc("flow-persist.md")
        self.post("/comments", {"docId": doc_id, "anchor": self._anchor(), "text": "persisted"})
        on_disk = json.loads((self.data_dir / "rendered" / doc_id / "comments.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk[-1]["text"], "persisted")

    def test_anchor_whitelist_drops_junk_and_caps_quote(self) -> None:
        # unknown anchor keys and unbounded values walked straight
        # past the size caps (a 706 KB single comment demonstrated).
        doc_id = self._render_doc("flow-anchor.md")
        anchor = self._anchor()
        anchor["junk"] = "J" * 500_000
        anchor["quote"] = "Q" * 200_000
        status, created = self.post("/comments", {"docId": doc_id, "anchor": anchor, "text": "bounded"})
        self.assertEqual(status, 201)
        self.assertNotIn("junk", created["anchor"])
        from mdreview import store as _store

        self.assertEqual(len(created["anchor"]["quote"]), _store.MAX_QUOTE_LENGTH)
        raw = (self.data_dir / "rendered" / doc_id / "comments.json").read_text(encoding="utf-8")
        self.assertLess(len(raw), 50_000)


class PathDisclosureTests(ServerTestCase):
    """no response may leak the server's absolute data-dir path."""

    def test_new_manifest_has_relative_comments_path(self) -> None:
        md = self.data_dir.parent / "rel.md"
        md.write_text("# rel\n", encoding="utf-8")
        out = store.render_document(md, self.data_dir, "Rel")
        manifest = json.loads((out.parent / "manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(Path(manifest["commentsPath"]).is_absolute())
        self.assertTrue(manifest["commentsPath"].endswith("comments.json"))

    def test_legacy_absolute_comments_path_redacted_on_serve(self) -> None:
        md = self.data_dir.parent / "legacy.md"
        md.write_text("# legacy\n", encoding="utf-8")
        out = store.render_document(md, self.data_dir, "Legacy")
        doc_id = out.parent.name
        manifest_file = out.parent / "manifest.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest["commentsPath"] = str(manifest_file.parent / "comments.json")  # simulate legacy absolute
        manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
        status, body, _ = self.get(f"/rendered/{doc_id}/manifest.json")
        self.assertEqual(status, 200)
        served = json.loads(body)
        self.assertFalse(Path(served["commentsPath"]).is_absolute())
        # on-disk file is left untouched (redaction is serve-time only)
        self.assertTrue(Path(json.loads(manifest_file.read_text(encoding="utf-8"))["commentsPath"]).is_absolute())

    def test_corrupt_comments_store_error_is_generic(self) -> None:
        md = self.data_dir.parent / "corrupt.md"
        md.write_text("# corrupt\n", encoding="utf-8")
        out = store.render_document(md, self.data_dir, "Corrupt")
        doc_id = out.parent.name
        (out.parent / "comments.json").write_text("{broken", encoding="utf-8")
        status, body, _ = self.get(f"/comments?doc={doc_id}")
        self.assertEqual(status, 500)
        self.assertNotIn(str(self.data_dir), body.decode("utf-8"))
        self.assertIn("server log", body.decode("utf-8"))

    def test_document_ceiling(self) -> None:
        import mdreview.server as srv

        # This class shares one store across tests — set the ceiling relative
        # to what's already there rather than assuming an empty store.
        current = len(list((self.data_dir / "rendered").glob("*/")))
        with mock.patch.object(srv, "MAX_DOCUMENTS", current + 1):
            status, first = self.post("/api/render", {"markdown": "# one\n", "sourcePath": "one.md", "provenance": {}})
            self.assertEqual(status, 201)
            status, payload = self.post("/api/render", {"markdown": "# two\n", "sourcePath": "two.md", "provenance": {}})
            self.assertEqual(status, 429)
            # re-rendering the SAME doc must still work under the ceiling
            status, _ = self.post("/api/render", {"markdown": "# one v2\n", "sourcePath": "one.md", "provenance": {}})
            self.assertEqual(status, 201)


class ApiRenderTests(ServerTestCase):
    def test_post_render_creates_doc_with_client_provenance(self) -> None:
        status, result = self.post(
            "/api/render",
            {
                "markdown": "# Remote\n\nshipped over http\n",
                "filename": "remote.md",
                "sourcePath": "docs/remote.md",
                "title": "Remote Doc",
                "provenance": {
                    "sourceRepoName": "some-repo",
                    "sourceRepoBranch": "main",
                    "agentCwd": "/other/machine/cwd",
                    "agent": "claude-code",
                    "sessionId": "remote-sess-1",
                },
            },
        )
        self.assertEqual(status, 201)
        doc_id = result["docId"]
        self.assertEqual(result["url"], f"/rendered/{doc_id}/index.html")

        manifest = json.loads((self.data_dir / "rendered" / doc_id / "manifest.json").read_text(encoding="utf-8"))
        prov = manifest["provenance"]
        self.assertEqual(prov["sourceRepoName"], "some-repo")
        self.assertEqual(prov["agentCwd"], "/other/machine/cwd")
        self.assertEqual(prov["sessionId"], "remote-sess-1")
        self.assertEqual(prov["receivedFrom"], "127.0.0.1")
        self.assertIn("receivedAt", prov)

        status, body, _ = self.get(result["url"])
        self.assertEqual(status, 200)
        self.assertIn(b"shipped over http", body)
        self.assertIn(b"some-repo:main", body)

    def test_post_render_validation(self) -> None:
        status, payload = self.post("/api/render", {"markdown": "   "})
        self.assertEqual(status, 400)
        status, payload = self.post("/api/render", {"markdown": "# x\n"})
        self.assertEqual(status, 400)
        self.assertIn("sourcePath", payload["error"])

    def test_post_render_rerender_preserves_created_at(self) -> None:
        payload = {"markdown": "# A\n\nv1\n", "sourcePath": "a.md", "provenance": {}}
        status, first = self.post("/api/render", payload)
        self.assertEqual(status, 201)
        payload["markdown"] = "# A\n\nv2\n"
        status, second = self.post("/api/render", payload)
        self.assertEqual(status, 201)
        self.assertEqual(first["docId"], second["docId"])
        manifest = json.loads(
            (self.data_dir / "rendered" / first["docId"] / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn("v2", (self.data_dir / "rendered" / first["docId"] / "index.html").read_text(encoding="utf-8"))
        self.assertEqual(manifest["createdAt"], manifest["provenance"]["createdAt"])


class VerifyRequestIntegrationTests(ServerTestCase):
    def test_handler_level_guard_blocks_when_verify_bypassed(self) -> None:
        # The server-level verify_request is the primary gate; the handler-level
        # _client_permitted is the second layer. Simulate a non-LAN client
        # address reaching the handler (as if verify_request had been
        # subclassed away) and confirm the 403 still fires. A PropertyMock is
        # required because client_address is an instance attribute (set by
        # BaseRequestHandler.__init__); only a data descriptor on the class
        # shadows it.
        with mock.patch.object(
            ReviewHandler,
            "client_address",
            new_callable=mock.PropertyMock,
            return_value=("8.8.8.8", 9000),
            create=True,  # client_address exists only on instances, not the class
        ):
            status, body, _ = self.get("/health")
            self.assertEqual(status, 403)
            self.assertIn("LAN-only", json.loads(body)["error"])


class ThemeResolutionTests(unittest.TestCase):
    """--theme flag > MD_REVIEW_THEME env > 'system', chatty-fail on junk."""

    def test_flag_beats_env_beats_default(self) -> None:
        from mdreview.server import resolve_theme

        with mock.patch.dict(os.environ, {"MD_REVIEW_THEME": "dusk"}):
            self.assertEqual(resolve_theme("dark"), "dark")
            self.assertEqual(resolve_theme(None), "dusk")
        env = os.environ.copy()
        env.pop("MD_REVIEW_THEME", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(resolve_theme(None), "system")

    def test_unknown_theme_fails_chatty(self) -> None:
        from mdreview.server import resolve_theme

        with self.assertRaises(SystemExit) as ctx:
            resolve_theme("midnight")
        self.assertIn("unknown theme 'midnight'", str(ctx.exception))
        self.assertIn("light, dusk, dark, system", str(ctx.exception))
        # The env var is validated too — a typo there must not silently fall
        # back to system (the operator would think the flag was ignored).
        with mock.patch.dict(os.environ, {"MD_REVIEW_THEME": "bogus"}), self.assertRaises(SystemExit):
            resolve_theme(None)

    def test_cli_flag_choices_reject_bad_value(self) -> None:
        from mdreview.cli import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(["serve", "--theme", "midnight"])
        args = build_parser().parse_args(["serve", "--theme", "dusk"])
        self.assertEqual(args.theme, "dusk")


class ThemeServingTests(unittest.TestCase):
    """The server-level default theme as it appears on the wire: stamped as
    data-theme on <html> for explicit themes (index AND static doc pages —
    the doc-page stamp happens at serve time so pre-existing docs pick it
    up), absent for `system` so the page bootstrap resolves the device."""

    def _start(self, theme: str):
        tmp = tempfile.TemporaryDirectory()
        data_dir = Path(tmp.name) / "data"
        server = ReviewServer(
            ("127.0.0.1", 0),
            ReviewHandler,
            data_dir=data_dir,
            ds_dir=vendored_ds_dir(),
            default_author="Tester",
            theme=theme,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        md = Path(tmp.name) / "themed.md"
        md.write_text("# T\n\nbody\n", encoding="utf-8")
        doc_id = store.render_document(md, data_dir, "T").parent.name
        return tmp, server, thread, doc_id

    def _stop(self, tmp, server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        tmp.cleanup()

    def _get(self, server, path: str) -> bytes:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.read()

    def test_system_theme_stamps_nothing_and_ships_the_bootstrap(self) -> None:
        tmp, server, thread, doc_id = self._start("system")
        try:
            for path in ("/", f"/rendered/{doc_id}/index.html"):
                page = self._get(server, path)
                self.assertIn(b'<html lang="en">', page, path)
                self.assertNotIn(b'<html lang="en" data-theme', page, path)
                # The system-resolution script is what makes `system` work:
                # it must be present on both pages...
                self.assertIn(b"prefers-color-scheme: dark", page, path)
                # ...and the per-device override toggle must be offered.
                self.assertIn(b"data-theme-set", page, path)
                self.assertIn(b"mdReviewTheme", page, path)
        finally:
            self._stop(tmp, server, thread)

    def test_system_serves_doc_page_bytes_untouched(self) -> None:
        # No silent rewriting under `system`: what is on disk is what is
        # served (the theme stamp must be a no-op, not a transformation).
        tmp, server, thread, doc_id = self._start("system")
        try:
            served = self._get(server, f"/rendered/{doc_id}/index.html")
            on_disk = (Path(tmp.name) / "data" / "rendered" / doc_id / "index.html").read_bytes()
            self.assertEqual(served, on_disk)
        finally:
            self._stop(tmp, server, thread)

    def test_explicit_themes_stamped_on_index_and_doc_pages(self) -> None:
        for theme in ("light", "dusk", "dark"):
            tmp, server, thread, doc_id = self._start(theme)
            try:
                stamped = f'<html lang="en" data-theme="{theme}">'.encode()
                for path in ("/", f"/rendered/{doc_id}/index.html"):
                    page = self._get(server, path)
                    self.assertIn(stamped, page, f"{theme} missing on {path}")
                    # The bootstrap still ships under an explicit theme: the
                    # per-device localStorage override must be able to beat
                    # the server default (it reads storage BEFORE honoring
                    # the stamped attribute).
                    self.assertIn(b"mdReviewTheme", page, path)
                    self.assertIn(b"data-theme-set", page, path)
            finally:
                self._stop(tmp, server, thread)


class CacheHeaderTests(unittest.TestCase):
    """Everything the server can mutate in place must be no-store.

    A re-render overwrites a doc's files at the SAME url, and the index,
    /api/docs, and /health change whenever any doc is rendered or commented
    on. Without Cache-Control: no-store a browser is free to serve a stale
    cached copy that actively lies (missing docs, pre-fix pages). The DS
    assets under /ds/ are the exception: vendored, content-stable across
    requests, and deliberately left cacheable.
    """

    def _start(self):
        tmp = tempfile.TemporaryDirectory()
        data_dir = Path(tmp.name) / "data"
        server = ReviewServer(
            ("127.0.0.1", 0),
            ReviewHandler,
            data_dir=data_dir,
            ds_dir=vendored_ds_dir(),
            default_author="Tester",
            theme="system",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        md = Path(tmp.name) / "cached.md"
        md.write_text("# T\n\nbody\n", encoding="utf-8")
        doc_id = store.render_document(md, data_dir, "T").parent.name
        return tmp, server, thread, doc_id

    def _stop(self, tmp, server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        tmp.cleanup()

    def _cache_control(self, server, path: str) -> str | None:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.headers.get("Cache-Control")

    def test_mutable_routes_are_no_store(self) -> None:
        tmp, server, thread, doc_id = self._start()
        try:
            mutable = [
                "/",
                "/health",
                "/api/docs",
                f"/rendered/{doc_id}/index.html",
                f"/rendered/{doc_id}/anchors.json",
                f"/rendered/{doc_id}/manifest.json",
                f"/rendered/{doc_id}/comments.json",
            ]
            for path in mutable:
                self.assertEqual(
                    self._cache_control(server, path),
                    "no-store",
                    f"{path} is mutable in place and must not be browser-cacheable",
                )
        finally:
            self._stop(tmp, server, thread)

    def test_ds_assets_stay_cacheable(self) -> None:
        # Vendored design-system files never change under a running server;
        # no-store there would re-download fonts/css on every page view.
        tmp, server, thread, _doc_id = self._start()
        try:
            cache_control = self._cache_control(server, "/ds/design-app/tokens.css")
            self.assertNotEqual(cache_control, "no-store")
        finally:
            self._stop(tmp, server, thread)


class ThemeTokenCoverageTests(ServerTestCase):
    """Static guarantee: every ``var(--*)`` the tool's own CSS (doc page +
    index page) references resolves under ALL THREE design-system palettes —
    defined either at ``:root`` (applies to every theme) or inside that
    theme's ``[data-theme]`` block. A custom property that is missing for a
    scope falls back to its initial value in that theme (usually black or
    transparent), which is exactly the dark-mode breakage this test catches
    at CI time instead of on a phone at night."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        md = cls.data_dir.parent / "themed.md"
        md.write_text("# T\n\nbody\n", encoding="utf-8")
        cls.doc_id = store.render_document(md, cls.data_dir, "T").parent.name

    def _tool_css(self) -> str:
        _, doc_page, _ = self.get(f"/rendered/{self.doc_id}/index.html")
        _, index_page, _ = self.get("/")
        combined = doc_page.decode("utf-8") + index_page.decode("utf-8")
        return "\n".join(re.findall(r"<style>(.*?)</style>", combined, re.DOTALL))

    def _ds_definitions(self) -> dict[str, set[str]]:
        # Parse the vendored DS into the three scopes the tool can render
        # under. Selector matching is EXACT: the lamplit-umber alt block
        # ([data-theme="dark"][data-dark="lamplit-umber"]) is an opt-in the
        # tool never emits, and must not count toward "dark" coverage.
        # Comments are stripped first so a token named in prose isn't
        # mistaken for a definition. Nested-braced blocks (@keyframes,
        # @media) match as their inner rules, which are never :root or a
        # plain [data-theme] selector — they simply contribute nothing.
        scopes: dict[str, set[str]] = {"root": set(), "dusk": set(), "dark": set()}
        block_re = re.compile(r"([^{}@]+)\{([^{}]*)\}")
        ds_dir = vendored_ds_dir()
        for rel in ("themes.css", "design-app/tokens.css", "components/components.css"):
            text = (ds_dir / rel).read_text(encoding="utf-8")
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
            for selector, body in block_re.findall(text):
                defined = set(re.findall(r"(--[A-Za-z0-9-]+)\s*:", body))
                if not defined:
                    continue
                for part in selector.split(","):
                    part = part.strip()
                    if part == ":root":
                        scopes["root"] |= defined
                    elif part == '[data-theme="dusk"]':
                        scopes["dusk"] |= defined
                    elif part == '[data-theme="dark"]':
                        scopes["dark"] |= defined
        return scopes

    def test_every_tool_token_defined_for_all_three_themes(self) -> None:
        used = set(re.findall(r"var\(\s*(--[A-Za-z0-9-]+)", self._tool_css()))
        self.assertGreater(len(used), 10, "sanity: the tool CSS should reference a real slice of the palette")
        scopes = self._ds_definitions()
        missing = []
        for token in sorted(used):
            for scope in ("root", "dusk", "dark"):
                if token not in scopes["root"] and token not in scopes[scope]:
                    missing.append(f"{token} (undefined under {scope})")
        self.assertEqual(missing, [], "tool CSS tokens with no definition: " + ", ".join(missing))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
