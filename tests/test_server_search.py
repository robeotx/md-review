"""HTTP surface for search: /api/search validation and the index page's search state.

The ServerTestCase harness runs a real loopback server. The index is
throttled (2 s), so tests force a sync after writing to the store.
"""

from __future__ import annotations

import json
import unittest
import urllib.request

from test_server import ServerTestCase

from mdreview import store


class SearchRouteTests(ServerTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        md = cls.data_dir.parent / "orchid.md"
        md.write_text("# Orchid Plan\n\nthe orchid bloom schedule\n", encoding="utf-8")
        cls.doc_id = store.render_document(
            md,
            cls.data_dir,
            "Orchid Plan",
            provenance={
                "sourceRepoRoot": "/work/greenhouse",
                "sourceRepoName": "greenhouse",
                "sourceRepoBranch": "main",
            },
            session_id="sess-orchid",
            agent="test-agent",
        ).parent.name
        store.add_comment(
            cls.doc_id,
            {
                "id": "c-marigold",
                "text": "check the marigold row",
                "author": "reviewer",
                "quote": "",
                "resolved": False,
                "createdAt": "2026-10-08T00:00:00+00:00",
            },
            cls.data_dir,
        )
        page_dir = store.rendered_dir(cls.data_dir) / "standalone-map"
        page_dir.mkdir(parents=True)
        (page_dir / "index.html").write_text(
            '<html><head><title>Standalone Map</title></head><body><script>var D = {"lede": "orchid lineage"};</script></body></html>',
            encoding="utf-8",
        )
        cls.server.search_index.sync()

    def _search(self, query: str) -> tuple[int, dict]:
        status, body, _ = self.get(f"/api/search{query}")
        return status, json.loads(body)

    def test_search_responses_are_no_store(self) -> None:
        with urllib.request.urlopen(self.url("/api/search?q=bloom"), timeout=10) as resp:
            self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
            self.assertEqual(resp.headers.get_content_type(), "application/json")

    def test_search_returns_groups_with_doc_and_snippet(self) -> None:
        status, payload = self._search("?q=bloom")
        self.assertEqual(status, 200)
        group = payload["groups"][0]
        self.assertEqual(group["doc"]["docId"], self.doc_id)
        self.assertEqual(group["doc"]["repo"], {"key": "/work/greenhouse", "label": "greenhouse"})
        self.assertIn("bloom", group["doc"]["snippet"])
        self.assertEqual(group["doc"]["url"], f"/rendered/{self.doc_id}/index.html")

    def test_comment_and_standalone_page_are_searchable(self) -> None:
        _, payload = self._search("?q=marigold")
        self.assertEqual(payload["groups"][0]["matches"][0]["kind"], "comment")
        _, payload = self._search("?q=lineage")
        self.assertEqual(payload["groups"][0]["doc"]["kind"], "page")
        self.assertEqual(payload["groups"][0]["doc"]["repo"]["label"], "Standalone pages")

    def test_default_listing_and_facets(self) -> None:
        _, payload = self._search("")
        self.assertGreaterEqual(payload["total"], 2)
        keys = {facet["key"] for facet in payload["facets"]["repos"]}
        self.assertIn("/work/greenhouse", keys)
        self.assertIn("standalone", keys)

    def test_repo_filter_is_repeatable(self) -> None:
        _, payload = self._search("?repo=/work/greenhouse&repo=standalone")
        self.assertEqual(payload["total"], 2)
        _, payload = self._search("?repo=/work/greenhouse")
        self.assertEqual([g["doc"]["docId"] for g in payload["groups"]], [self.doc_id])

    def test_rejections_say_how_to_fix_them(self) -> None:
        cases = {
            "?sort=relevance": "sort must be one of",
            "?from=2026-10-8T00": "YYYY-MM-DD",
            "?limit=500": "limit must be between 1 and 200",
            "?offset=20000": "offset must be between 0 and 10000",
            "?q=%00": "NUL bytes",
            "?q=" + "x" * 300: "256 characters",
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                status, payload = self._search(query)
                self.assertEqual(status, 400)
                self.assertIn(expected, payload["error"])

    def test_index_page_renders_search_state_server_side(self) -> None:
        status, body, _ = self.get("/?q=bloom&sort=created")
        text = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn(">Orchid Plan</a>", text)
        self.assertIn("id='search'", text)
        self.assertIn("value='bloom'", text)
        self.assertIn("<option value='created' selected>", text)
        self.assertIn("/api/search", text)

    def test_index_page_lists_standalone_pages(self) -> None:
        _, body, _ = self.get("/")
        text = body.decode("utf-8")
        self.assertIn(">Standalone Map</a>", text)
        self.assertIn("standalone page", text)

    def test_index_page_pager_appears_past_one_page(self) -> None:
        _, body, _ = self.get("/?limit=1")
        text = body.decode("utf-8")
        self.assertIn("1–1 of", text)
        self.assertIn("offset=1", text)


if __name__ == "__main__":
    unittest.main()
