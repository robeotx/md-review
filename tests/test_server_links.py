"""Server side of relative links: GET /link and the /api/render links field."""

from __future__ import annotations

import base64
import http.client
import json
import unittest

from test_server import ServerTestCase

from mdreview import links, server

REPO = {"sourceRepoRoot": "/w/repo", "sourceRepoRemote": "https://github.com/acme/r.git"}


class LinkTestCase(ServerTestCase):
    def publish(self, source: str, markdown: str, *, files=None, reasons=None, prov=None, links_field=None) -> str:
        payload = {"markdown": markdown, "sourcePath": source, "provenance": dict(prov or REPO)}
        if links_field is not None:
            payload["links"] = links_field
        elif files is not None or reasons is not None:
            payload["links"] = {
                "files": {k: base64.b64encode(v).decode("ascii") for k, v in (files or {}).items()},
                "reasons": reasons or {},
            }
        status, result = self.post("/api/render", payload)
        self.assertEqual(201, status, result)
        return result["docId"]

    def raw_get(self, path: str) -> tuple[int, dict[str, str], bytes]:
        """GET without following redirects."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
        finally:
            conn.close()

    def link(self, doc_id: str, target: str) -> str:
        return f"/link/{doc_id}/{links.link_key(target)}"


class LinkRouteTests(LinkTestCase):
    def test_published_target_redirects_to_its_review_page(self) -> None:
        target = self.publish("docs/b.md", "# B\n\n## Install\n")
        source = self.publish("docs/a.md", "[b](b.md#install)\n")
        status, headers, _ = self.raw_get(self.link(source, "docs/b.md"))
        self.assertEqual(302, status)
        self.assertEqual(f"/rendered/{target}/index.html", headers["location"])
        self.assertIn("no-store", headers["cache-control"])

    def test_target_published_after_the_link_still_redirects(self) -> None:
        source = self.publish("docs/later-a.md", "[b](later-b.md)\n")
        status, _, body = self.raw_get(self.link(source, "docs/later-b.md"))
        self.assertEqual(404, status)
        self.assertIn(b"not published", body)
        target = self.publish("docs/later-b.md", "# B\n")
        status, headers, _ = self.raw_get(self.link(source, "docs/later-b.md"))
        self.assertEqual((302, f"/rendered/{target}/index.html"), (status, headers["location"]))

    def test_namespace_drift_falls_back_to_a_unique_same_repo_match(self) -> None:
        # Target rendered before the repo had a remote (namespace = root), source after.
        target = self.publish("docs/drift-b.md", "# B\n", prov={"sourceRepoRoot": "/w/repo"})
        source = self.publish("docs/drift-a.md", "[b](drift-b.md)\n")
        status, headers, _ = self.raw_get(self.link(source, "docs/drift-b.md"))
        self.assertEqual((302, f"/rendered/{target}/index.html"), (status, headers["location"]))

    def test_unpublished_captured_markdown_opens_an_escaped_read_only_viewer(self) -> None:
        md = b"# Report\n\n<script>alert(1)</script>\n"
        source = self.publish("docs/v-a.md", "[r](reports/r.md)\n", files={"docs/reports/r.md": md})
        status, headers, body = self.raw_get(self.link(source, "docs/reports/r.md"))
        self.assertEqual(200, status)
        self.assertTrue(headers["content-type"].startswith("text/html"))
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn(b"<script>alert", body)
        self.assertIn(b"docs/reports/r.md", body)
        self.assertIn(b"md-review render", body)
        self.assertNotIn(b"data-cmt-anchor", body)  # no comment UI on a copy
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        status, headers, raw = self.raw_get(self.link(source, "docs/reports/r.md") + "?raw=1")
        self.assertEqual((200, md), (status, raw))
        self.assertEqual("text/plain; charset=utf-8", headers["content-type"])
        self.assertEqual("nosniff", headers["x-content-type-options"])

    def test_captured_text_named_html_is_never_served_as_html(self) -> None:
        source = self.publish("docs/h-a.md", "[p](page.html)\n", files={"docs/page.html": b"<b>x</b>"})
        status, headers, _ = self.raw_get(self.link(source, "docs/page.html") + "?raw=1")
        self.assertEqual("text/plain; charset=utf-8", headers["content-type"])

    def test_captured_images_serve_with_a_closed_mime_map_and_svg_is_sandboxed(self) -> None:
        png, svg = b"\x89PNG\r\n\x1a\nxx", b"<svg xmlns='http://www.w3.org/2000/svg'><script>x</script></svg>"
        source = self.publish("docs/i-a.md", "![p](p.png) ![s](s.svg)\n", files={"docs/p.png": png, "docs/s.svg": svg})
        status, headers, body = self.raw_get(self.link(source, "docs/p.png"))
        self.assertEqual((200, "image/png", png), (status, headers["content-type"], body))
        status, headers, body = self.raw_get(self.link(source, "docs/s.svg"))
        self.assertEqual("image/svg+xml", headers["content-type"])
        self.assertIn("sandbox", headers["content-security-policy"])
        self.assertIn("script-src 'none'", headers["content-security-policy"].replace("default-src 'none'", "script-src 'none'"))

    def test_unavailable_target_explains_why_with_escaped_reason(self) -> None:
        reason = '<img src=x onerror=alert(1)>'
        source = self.publish("docs/u-a.md", "[x](x.txt)\n", reasons={"docs/x.txt": reason})
        status, headers, body = self.raw_get(self.link(source, "docs/x.txt"))
        self.assertEqual(404, status)
        self.assertTrue(headers["content-type"].startswith("text/html"))
        self.assertIn(b"&lt;img src=x onerror=alert(1)&gt;", body)
        self.assertNotIn(b"<img src=x", body)

    def test_unknown_key_and_bad_doc_id(self) -> None:
        source = self.publish("docs/k-a.md", "# none\n")
        status, _, body = self.raw_get(f"/link/{source}/0123456789abcdef")
        self.assertEqual(404, status)
        self.assertIn(b"no such link", body)
        status, _, _ = self.raw_get("/link/..%2Fetc/0123456789abcdef")
        self.assertIn(status, (400, 404))
        status, _, _ = self.raw_get(f"/link/{source}/not-a-key")
        self.assertEqual(404, status)

    def test_rendered_page_links_through_the_link_route(self) -> None:
        source = self.publish("docs/p-a.md", "[r](r.md#sec)\n")
        status, body, _ = self.get(f"/rendered/{source}/index.html")
        self.assertIn(f'href="{self.link(source, "docs/r.md")}#sec"'.encode(), body)


class RenderLinksFieldTests(LinkTestCase):
    def test_older_client_without_links_field_still_gets_doc_links(self) -> None:
        source = self.publish("docs/o-a.md", "[r](r.md) [t](t.txt)\n")
        entries = json.loads((self.data_dir / "rendered" / source / "links.json").read_text(encoding="utf-8"))
        kinds = sorted(e["kind"] for e in entries.values())
        self.assertEqual(["doc", "text"], kinds)

    def test_disabled_capture_is_recorded(self) -> None:
        source = self.publish("docs/d-a.md", "[t](t.txt)\n", links_field={"disabled": True})
        status, _, body = self.raw_get(self.link(source, "docs/t.txt"))
        self.assertIn(b"capture turned off", body)

    def test_malformed_links_field_is_rejected(self) -> None:
        for bad in ([], {"files": []}, {"files": {"docs/a.txt": "%%%not-base64"}}, {"reasons": {"x": 3}}):
            status, payload = self.post(
                "/api/render", {"markdown": "[a](a.txt)\n", "sourcePath": "docs/m.md", "provenance": {}, "links": bad}
            )
            self.assertEqual(400, status, (bad, payload))

    def test_render_route_accepts_bodies_over_the_general_cap(self) -> None:
        big = b"z" * (server.MAX_BODY_BYTES // 2)
        files = {f"docs/b{i}.txt": big for i in range(3)}  # ~6 MiB base64-ish, over the 4 MiB general cap
        md = " ".join(f"[b{i}](b{i}.txt)" for i in range(3)) + "\n"
        source = self.publish("docs/big-a.md", md, files=files)
        status, _, _ = self.raw_get(self.link(source, "docs/b0.txt") + "?raw=1")
        self.assertEqual(200, status)

    def declared_post(self, path: str, length: int) -> int:
        """POST headers declaring ``length`` bytes but send no body: a server
        that refuses before reading must answer without waiting for it."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("POST", path)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(length))
            conn.endheaders()
            return conn.getresponse().status
        finally:
            conn.close()

    def test_general_cap_still_applies_to_other_routes_and_render_has_its_own(self) -> None:
        self.assertEqual(413, self.declared_post("/comments", server.MAX_BODY_BYTES + 1))
        self.assertEqual(413, self.declared_post("/api/render", server.MAX_RENDER_BODY_BYTES + 1))

    def test_a_second_oversized_render_is_refused_while_one_runs(self) -> None:
        self.assertTrue(self.server.large_render_slot.acquire(blocking=False))
        try:
            status = self.declared_post("/api/render", server.MAX_BODY_BYTES + 1)
        finally:
            self.server.large_render_slot.release()
        self.assertEqual(503, status)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
