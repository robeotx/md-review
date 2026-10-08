"""Search index: query parsing, text extraction, repo keys, sync, and search.

Design contract: `.requests/261008-ui-search-design.md`. The index is in
memory and derived from the store; these tests build real store layouts
in a temp dir and exercise the public surface only.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from mdreview import search, store


def _write_doc_dir(
    data_dir: Path,
    doc_id: str,
    *,
    title: str,
    body_html: str,
    manifest: dict | None = None,
    comments: list | None = None,
    links: dict | None = None,
    blobs: dict[str, bytes] | None = None,
) -> Path:
    doc_dir = store.rendered_dir(data_dir) / doc_id
    doc_dir.mkdir(parents=True, exist_ok=True)
    (doc_dir / "index.html").write_text(
        f"<!doctype html><html><head><title>{title}</title></head><body>{body_html}</body></html>",
        encoding="utf-8",
    )
    if manifest is not None:
        (doc_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if comments is not None:
        (doc_dir / "comments.json").write_text(json.dumps(comments), encoding="utf-8")
    if links is not None:
        (doc_dir / "links.json").write_text(json.dumps(links), encoding="utf-8")
    for sha, data in (blobs or {}).items():
        (doc_dir / "files").mkdir(exist_ok=True)
        (doc_dir / "files" / sha).write_bytes(data)
    return doc_dir


def _manifest(title: str, rendered_at: str, *, created_at: str | None = None, provenance: dict | None = None) -> dict:
    manifest = {
        "docId": "x",
        "title": title,
        "sourcePath": f"docs/{title.lower().replace(' ', '-')}.md",
        "renderedAt": rendered_at,
        "commentsPath": "rendered/x/comments.json",
        "anchorPolicy": "test",
        "provenance": provenance or {},
    }
    if created_at is not None:
        manifest["createdAt"] = created_at
    return manifest


def _article(text: str) -> str:
    return f'<nav>chrome-only</nav><article class="doc" data-doc-root><p>{text}</p></article>'


class QueryParsingTests(unittest.TestCase):
    def test_empty_query_has_no_terms(self) -> None:
        self.assertEqual(search.parse_query(""), [])
        self.assertEqual(search.parse_query("   \t "), [])

    def test_terms_are_split_on_whitespace_and_casefolded(self) -> None:
        self.assertEqual(search.parse_query("  Open_Thread   LOGIN "), ["open_thread", "login"])

    def test_nul_byte_is_rejected_with_a_fix(self) -> None:
        with self.assertRaisesRegex(search.QueryError, "NUL"):
            search.parse_query("abc\x00def")

    def test_query_length_is_capped(self) -> None:
        with self.assertRaisesRegex(search.QueryError, "256"):
            search.parse_query("a" * 257)

    def test_term_count_is_capped(self) -> None:
        with self.assertRaisesRegex(search.QueryError, "8 terms"):
            search.parse_query(" ".join(f"t{i}" for i in range(9)))

    def test_term_length_is_capped(self) -> None:
        with self.assertRaisesRegex(search.QueryError, "64"):
            search.parse_query("x" * 65)


class DateParsingTests(unittest.TestCase):
    def test_none_and_empty_mean_no_bound(self) -> None:
        self.assertIsNone(search.parse_date(None))
        self.assertIsNone(search.parse_date(""))

    def test_iso_day_parses(self) -> None:
        self.assertEqual(search.parse_date("2026-10-08"), date(2026, 10, 8))

    def test_timestamps_and_bad_dates_are_rejected(self) -> None:
        for bad in ("2026-13-01", "2026-10-08T00:00", "10/08/2026"):
            with self.subTest(bad=bad), self.assertRaisesRegex(search.QueryError, "YYYY-MM-DD"):
                search.parse_date(bad)


class ExtractionTests(unittest.TestCase):
    def test_doc_text_comes_only_from_the_doc_root(self) -> None:
        html_text = _article("the body words") + "<footer>outside words</footer>"
        text, truncated = search.extract_doc_text(html_text.encode("utf-8"))
        self.assertIn("the body words", text)
        self.assertNotIn("chrome-only", text)
        self.assertNotIn("outside words", text)
        self.assertFalse(truncated)

    def test_doc_text_is_cut_at_the_cap_and_flagged(self) -> None:
        text, truncated = search.extract_doc_text(_article("abcdefghij").encode(), max_chars=4)
        self.assertEqual(len(text), 4)
        self.assertTrue(truncated)

    def test_page_text_skips_code_but_keeps_string_literals(self) -> None:
        page = (
            b"<html><head><title>Execution Map</title><style>.x{color:red}</style></head><body>"
            b"<p>visible words</p>"
            b'<script>const DATA = {"lede": "sessions become descriptors", "n": 3}; function go() { return 1; }</script>'
            b"</body></html>"
        )
        title, text, truncated = search.extract_page(page)
        self.assertEqual(title, "Execution Map")
        self.assertIn("visible words", text)
        self.assertIn("sessions become descriptors", text)
        self.assertNotIn("color:red", text)
        self.assertNotIn("function go", text)
        self.assertFalse(truncated)

    def test_page_string_literals_shorter_than_three_chars_are_ignored(self) -> None:
        page = b'<script>var a = ["x", "yy", "zzz"];</script>'
        _, text, _ = search.extract_page(page)
        self.assertIn("zzz", text)
        self.assertNotIn("yy", text.split())

    def test_page_text_is_cut_at_the_cap(self) -> None:
        _, text, truncated = search.extract_page(b"<body>" + b"q" * 50 + b"</body>", max_chars=10)
        self.assertEqual(len(text), 10)
        self.assertTrue(truncated)


class RepoKeyTests(unittest.TestCase):
    def test_source_repo_root_is_the_key(self) -> None:
        key, name = search.repo_key(
            {"sourceRepoRoot": "/srv/code/alpha", "sourceRepoName": "alpha", "agentCwd": "/x/y"}
        )
        self.assertEqual((key, name), ("/srv/code/alpha", "alpha"))

    def test_agent_cwd_is_the_fallback(self) -> None:
        key, name = search.repo_key({"agentCwd": "/srv/scratch/notes"})
        self.assertEqual((key, name), ("/srv/scratch/notes", "notes"))

    def test_nothing_known_is_unknown(self) -> None:
        self.assertEqual(search.repo_key({}), ("", ""))

    def test_labels_disambiguate_colliding_names(self) -> None:
        labels = search.repo_labels({"/a/work/app": "app", "/b/play/app": "app", "/c/solo": "solo"})
        self.assertEqual(labels["/c/solo"], "solo")
        self.assertEqual(labels["/a/work/app"], "app (work)")
        self.assertEqual(labels["/b/play/app"], "app (play)")


class SyncAndSearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "data"
        store.ensure_data_dir(self.data_dir)
        self.index = search.SearchIndex(self.data_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _doc(
        self,
        doc_id: str,
        title: str,
        text: str,
        rendered_at: str,
        *,
        created_at: str | None = None,
        provenance: dict | None = None,
        comments: list | None = None,
        links: dict | None = None,
        blobs: dict[str, bytes] | None = None,
    ) -> None:
        _write_doc_dir(
            self.data_dir,
            doc_id,
            title=title,
            body_html=_article(text),
            manifest=_manifest(title, rendered_at, created_at=created_at, provenance=provenance),
            comments=comments if comments is not None else [],
            links=links,
            blobs=blobs,
        )

    def _ids(self, result: dict) -> list[str]:
        return [group["doc"]["docId"] for group in result["groups"]]

    def test_body_title_and_substring_matches_are_case_insensitive(self) -> None:
        self._doc("alpha-doc", "Alpha Notes", "the open_thread helper", "2026-10-01T00:00:00+00:00")
        self._doc("beta-doc", "Beta", "nothing relevant", "2026-10-02T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["thread"])), ["alpha-doc"])
        self.assertEqual(self._ids(self.index.search(terms=["alpha"])), ["alpha-doc"])
        self.assertEqual(self._ids(self.index.search(terms=["OPEN_THREAD"])), ["alpha-doc"])

    def test_terms_are_anded_within_one_item(self) -> None:
        self._doc("both", "Both", "red fish blue fish", "2026-10-01T00:00:00+00:00")
        self._doc("one", "One", "red only", "2026-10-01T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["red", "fish"])), ["both"])

    def test_default_sort_is_last_modified_newest_first(self) -> None:
        self._doc("older", "Older", "t", "2026-10-01T00:00:00+00:00", created_at="2026-10-05T00:00:00+00:00")
        self._doc("newer", "Newer", "t", "2026-10-09T00:00:00+00:00", created_at="2026-10-02T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search()), ["newer", "older"])
        self.assertEqual(self._ids(self.index.search(sort="created")), ["older", "newer"])

    def test_unknown_creation_sorts_last_and_is_excluded_by_date_filter(self) -> None:
        self._doc("dated", "Dated", "t", "2026-10-01T00:00:00+00:00", created_at="2026-10-01T00:00:00+00:00")
        _write_doc_dir(self.data_dir, "standalone-page", title="Page", body_html="<p>t</p>")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(sort="created")), ["dated", "standalone-page"])
        # The page's modified time is its real mtime (known), so only the
        # created-date filter can exclude it.
        self.assertEqual(self._ids(self.index.search(sort="created", date_from=date(2026, 1, 1))), ["dated"])

    def test_date_range_is_inclusive_on_both_ends(self) -> None:
        self._doc("day1", "D1", "t", "2026-10-01T00:00:00+00:00")
        self._doc("day3", "D3", "t", "2026-10-03T23:59:59+00:00")
        self._doc("day4", "D4", "t", "2026-10-04T00:00:00+00:00")
        self.index.sync()
        result = self.index.search(date_from=date(2026, 10, 1), date_to=date(2026, 10, 3))
        self.assertEqual(sorted(self._ids(result)), ["day1", "day3"])

    def test_repo_filter_matches_any_selected_key(self) -> None:
        self._doc(
            "a", "A", "t", "2026-10-01T00:00:00+00:00", provenance={"sourceRepoRoot": "/x/one", "sourceRepoName": "one"}
        )
        self._doc(
            "b", "B", "t", "2026-10-01T00:00:00+00:00", provenance={"sourceRepoRoot": "/x/two", "sourceRepoName": "two"}
        )
        self._doc("c", "C", "t", "2026-10-01T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(sorted(self._ids(self.index.search(repos=["/x/one", "/x/two"]))), ["a", "b"])
        self.assertEqual(self._ids(self.index.search(repos=[""])), ["c"])

    def test_facets_count_distinct_docs_ignoring_the_repo_filter(self) -> None:
        self._doc(
            "a",
            "A",
            "shared word",
            "2026-10-01T00:00:00+00:00",
            provenance={"sourceRepoRoot": "/x/one", "sourceRepoName": "one"},
        )
        self._doc(
            "b",
            "B",
            "shared word",
            "2026-10-01T00:00:00+00:00",
            provenance={"sourceRepoRoot": "/x/two", "sourceRepoName": "two"},
        )
        self.index.sync()
        facets = self.index.search(terms=["shared"], repos=["/x/one"])["facets"]["repos"]
        counts = {facet["key"]: facet["count"] for facet in facets}
        self.assertEqual(counts, {"/x/one": 1, "/x/two": 1})

    def test_selected_repo_with_no_matching_docs_stays_in_facets_with_zero(self) -> None:
        # Otherwise a checked repo vanishes from the multi-select and cannot be unchecked.
        self._doc(
            "a", "A", "t", "2026-10-01T00:00:00+00:00", provenance={"sourceRepoRoot": "/x/one", "sourceRepoName": "one"}
        )
        self.index.sync()
        facets = self.index.search(terms=["nomatchzzz"], repos=["/x/one"])["facets"]["repos"]
        self.assertEqual(facets, [{"key": "/x/one", "label": "one", "count": 0}])

    def test_doc_without_comments_file_has_zero_comments_not_unreadable(self) -> None:
        # An absent comments.json means no comments; only a corrupt one is "unreadable" (None).
        _write_doc_dir(self.data_dir, "bare", title="Bare", body_html=_article("t"), manifest=_manifest("Bare", "2026-10-01T00:00:00+00:00"))
        self.index.sync()
        doc = self.index.search(terms=["bare"])["groups"][0]["doc"]
        self.assertEqual((doc["openComments"], doc["totalComments"]), (0, 0))

    def test_pagination_counts_docs_not_items(self) -> None:
        for i in range(3):
            self._doc(f"doc-{i}", f"Doc {i}", "t", f"2026-10-0{i + 1}T00:00:00+00:00")
        self.index.sync()
        first = self.index.search(limit=2, offset=0)
        second = self.index.search(limit=2, offset=2)
        self.assertEqual(first["total"], 3)
        self.assertEqual(len(first["groups"]), 2)
        self.assertEqual(len(second["groups"]), 1)
        self.assertEqual(self._ids(first) + self._ids(second), ["doc-2", "doc-1", "doc-0"])

    def test_comment_match_returns_its_doc_as_context(self) -> None:
        comment = {
            "id": "c1",
            "text": "needs a rewrite of the close-out",
            "author": "reviewer",
            "quote": "close",
            "resolved": False,
            "createdAt": "2026-10-01T00:00:00+00:00",
        }
        self._doc("with-comment", "Plan", "unrelated body", "2026-10-01T00:00:00+00:00", comments=[comment])
        self.index.sync()
        result = self.index.search(terms=["rewrite"])
        self.assertEqual(self._ids(result), ["with-comment"])
        match = result["groups"][0]["matches"][0]
        self.assertEqual(match["kind"], "comment")
        self.assertIn("rewrite", match["snippet"])

    def test_captured_text_file_is_searchable_by_content_and_path(self) -> None:
        blob = b"def close_out():\n    return 'ok'\n"
        sha = hashlib.sha256(blob).hexdigest()
        links = {
            "abcdef0123456789": {"target": "scripts/tools.py", "kind": "text", "docId": "x", "sha256": sha, "size": len(blob)}
        }
        self._doc("linked", "Linked", "t", "2026-10-01T00:00:00+00:00", links=links, blobs={sha: blob})
        self.index.sync()
        result = self.index.search(terms=["close_out"])
        match = result["groups"][0]["matches"][0]
        self.assertEqual((match["kind"], match["ext"], match["url"]), ("file", "py", "/link/linked/abcdef0123456789"))
        self.assertEqual(self._ids(self.index.search(terms=["tools.py"])), ["linked"])

    def test_binary_or_oversized_capture_is_indexed_by_path_only(self) -> None:
        blob = b"\x89PNG\x00\x00binary"
        sha = hashlib.sha256(blob).hexdigest()
        links = {"1234567890abcdef": {"target": "shots/hero.png", "kind": "image", "docId": "x", "sha256": sha, "size": len(blob)}}
        self._doc("pics", "Pics", "t", "2026-10-01T00:00:00+00:00", links=links, blobs={sha: blob})
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["hero"])), ["pics"])
        self.assertEqual(self._ids(self.index.search(terms=["binary"])), [])

    def test_standalone_page_is_listed_with_unknown_creation(self) -> None:
        _write_doc_dir(
            self.data_dir, "aes-map", title="AES Map", body_html='<script>var D = {"lede": "execution graph"};</script>'
        )
        self.index.sync()
        result = self.index.search(terms=["execution"])
        group = result["groups"][0]
        self.assertEqual(group["doc"]["kind"], "page")
        self.assertIsNone(group["doc"]["created"])
        self.assertEqual(group["doc"]["repo"], {"key": "standalone", "label": "Standalone pages"})

    def test_directory_without_index_or_manifest_is_not_listed(self) -> None:
        comments_only = store.rendered_dir(self.data_dir) / "comments-only"
        comments_only.mkdir(parents=True)
        (comments_only / "comments.json").write_text("[]", encoding="utf-8")
        self.index.sync()
        self.assertEqual(self.index.search()["total"], 0)

    def test_corrupt_manifest_is_skipped_without_failing_the_index(self) -> None:
        self._doc("good", "Good", "t", "2026-10-01T00:00:00+00:00")
        bad = _write_doc_dir(self.data_dir, "broken", title="Broken", body_html="<p>t</p>")
        (bad / "manifest.json").write_text("{not json", encoding="utf-8")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search()), ["good"])

    def test_symlinked_doc_dir_is_never_followed(self) -> None:
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (outside / "index.html").write_text("<article data-doc-root>secret outside text</article>", encoding="utf-8")
        try:
            os.symlink(outside, store.rendered_dir(self.data_dir) / "linked-out", target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")
        self.index.sync()
        self.assertEqual(self.index.search(terms=["secret"])["total"], 0)

    def test_changed_file_is_reindexed_and_removed_dir_is_dropped(self) -> None:
        self._doc("moving", "Moving", "first draft", "2026-10-01T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["first"])), ["moving"])
        # Renders replace files by rename (new inode), so the signature moves
        # even when a same-size rewrite lands within one mtime tick.
        page = store.rendered_dir(self.data_dir) / "moving" / "index.html"
        replacement = page.with_suffix(".tmp")
        replacement.write_text(
            f"<html><head><title>Moving</title></head><body>{_article('second draft')}</body></html>",
            encoding="utf-8",
        )
        os.replace(replacement, page)
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["second"])), ["moving"])
        self.assertEqual(self._ids(self.index.search(terms=["first"])), [])
        self.index.sync()
        self.assertEqual(self._ids(self.index.search(terms=["second"])), ["moving"])

        import shutil

        shutil.rmtree(store.rendered_dir(self.data_dir) / "moving")
        self.index.sync()
        self.assertEqual(self.index.search()["total"], 0)

    def test_truncated_items_are_flagged_and_counted(self) -> None:
        big = "w" * (search.MAX_ITEM_CHARS + 10)
        self._doc("huge", "Huge", big, "2026-10-01T00:00:00+00:00")
        self.index.sync()
        result = self.index.search(terms=["w"])
        self.assertTrue(result["groups"][0]["doc"]["truncated"])
        self.assertEqual(result["truncatedItems"], 1)

    def test_doc_snippet_is_plain_text_around_the_match(self) -> None:
        self._doc(
            "snip", "Snip", "<em>tag</em> lead-in words before the needle and words after", "2026-10-01T00:00:00+00:00"
        )
        self.index.sync()
        doc = self.index.search(terms=["needle"])["groups"][0]["doc"]
        self.assertIn("needle", doc["snippet"])
        self.assertNotIn("<", doc["snippet"])

    def test_doc_snippet_is_null_when_only_a_child_matches(self) -> None:
        comment = {"id": "c2", "text": "pointed remark", "author": "reviewer", "quote": "", "resolved": False}
        self._doc("parent", "Parent", "plain body", "2026-10-01T00:00:00+00:00", comments=[comment])
        self.index.sync()
        group = self.index.search(terms=["pointed"])["groups"][0]
        self.assertIsNone(group["doc"]["snippet"])
        self.assertIn("pointed", group["matches"][0]["snippet"])

    def test_index_reports_progress_until_first_build_completes(self) -> None:
        self._doc("only", "Only", "t", "2026-10-01T00:00:00+00:00")
        self.assertEqual(self.index.search()["indexing"], {"done": 0, "total": 0})
        self.index.sync()
        self.assertEqual(self.index.search()["indexing"], {"done": 1, "total": 1})

    def test_maybe_sync_is_throttled(self) -> None:
        clock = [100.0]
        index = search.SearchIndex(self.data_dir, clock=lambda: clock[0])
        self._doc("first", "First", "t", "2026-10-01T00:00:00+00:00")
        index.maybe_sync()
        self._doc("second", "Second", "t", "2026-10-01T00:00:00+00:00")
        index.maybe_sync()
        self.assertEqual(index.search()["total"], 1)
        clock[0] += search.SYNC_INTERVAL_S
        index.maybe_sync()
        self.assertEqual(index.search()["total"], 2)


class ReviewFindingTests(unittest.TestCase):
    """Regression tests for findings from the Kimi K3 review of ec31319."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "data"
        store.ensure_data_dir(self.data_dir)
        self.index = search.SearchIndex(self.data_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs POSIX permissions and a non-root user")
    def test_unreadable_doc_dir_is_skipped_and_the_rest_still_indexes(self) -> None:
        _write_doc_dir(self.data_dir, "good-doc", title="Good", body_html=_article("findme text"), manifest=_manifest("Good", "2026-10-01T00:00:00+00:00"))
        locked = _write_doc_dir(self.data_dir, "locked-doc", title="Locked", body_html=_article("hidden"), manifest=_manifest("Locked", "2026-10-01T00:00:00+00:00"))
        os.chmod(locked, 0)
        try:
            self.index.sync()
            self.index.sync()
            result = self.index.search(terms=["findme"])
            self.assertEqual(self._ids(result), ["good-doc"])
            self.assertEqual(self.index.search()["indexing"], {"done": 2, "total": 2})
        finally:
            os.chmod(locked, 0o755)

    def _ids(self, result: dict) -> list[str]:
        return [group["doc"]["docId"] for group in result["groups"]]

    def test_snippet_found_when_casefold_changes_length(self) -> None:
        # casefold("weiß") == "weiss": the term matches the folded text but has no
        # equal-length position in the original, so the snippet must still show context.
        _write_doc_dir(self.data_dir, "sharp", title="Sharp", body_html=_article("weiß and more words"), manifest=_manifest("Sharp", "2026-10-01T00:00:00+00:00"))
        self.index.sync()
        doc = self.index.search(terms=["ss"])["groups"][0]["doc"]
        self.assertIsNotNone(doc["snippet"])
        self.assertIn("weiß", doc["snippet"])

    def test_snippet_is_marked_position_in_original_text(self) -> None:
        _write_doc_dir(self.data_dir, "plain", title="Plain", body_html=_article("ABC needle XYZ"), manifest=_manifest("Plain", "2026-10-01T00:00:00+00:00"))
        self.index.sync()
        doc = self.index.search(terms=["NEEDLE"])["groups"][0]["doc"]
        self.assertIn("ABC needle XYZ", doc["snippet"])

    def test_title_only_match_has_no_body_snippet(self) -> None:
        _write_doc_dir(self.data_dir, "titled", title="Quartz Report", body_html=_article("unrelated body"), manifest=_manifest("Quartz Report", "2026-10-01T00:00:00+00:00"))
        self.index.sync()
        group = self.index.search(terms=["quartz"])["groups"][0]
        self.assertEqual(group["doc"]["docId"], "titled")
        self.assertIsNone(group["doc"]["snippet"])

    def test_capture_keys_the_link_route_cannot_serve_are_not_indexed(self) -> None:
        links_map = {"not-a-link-key": {"target": "zzfile.py", "kind": "text", "docId": "x", "sha256": "0" * 64, "size": 1}}
        _write_doc_dir(self.data_dir, "odd-keys", title="Odd", body_html=_article("t"), manifest=_manifest("Odd", "2026-10-01T00:00:00+00:00"), links=links_map)
        self.index.sync()
        self.assertEqual(self.index.search(terms=["zzfile"])["total"], 0)

    def test_matches_per_group_are_capped_with_true_count(self) -> None:
        comments = [{"id": f"c{i}", "text": f"rewrite note {i}", "author": "reviewer", "quote": "", "resolved": False} for i in range(25)]
        _write_doc_dir(self.data_dir, "chatty", title="Chatty", body_html=_article("body"), manifest=_manifest("Chatty", "2026-10-01T00:00:00+00:00"), comments=comments)
        self.index.sync()
        group = self.index.search(terms=["rewrite"])["groups"][0]
        self.assertEqual(len(group["matches"]), search.MAX_MATCHES_PER_GROUP)
        self.assertEqual(group["matchCount"], 25)


class PinningTests(unittest.TestCase):
    """A createdAt more than a day in the future pins a doc to the top."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "data"
        store.ensure_data_dir(self.data_dir)
        self.index = search.SearchIndex(self.data_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _doc(self, doc_id: str, rendered_at: str, created_at: str | None = None) -> None:
        _write_doc_dir(
            self.data_dir,
            doc_id,
            title=doc_id,
            body_html=_article("t"),
            manifest=_manifest(doc_id, rendered_at, created_at=created_at),
            comments=[],
        )

    def _ids(self, result: dict) -> list[str]:
        return [group["doc"]["docId"] for group in result["groups"]]

    def test_future_dated_doc_stays_on_top_over_newer_activity(self) -> None:
        self._doc("board", "2026-10-01T00:00:00+00:00", created_at="2099-01-01T00:00:00+00:00")
        self._doc("busy", "2026-10-09T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search()), ["board", "busy"])
        self.assertEqual(self._ids(self.index.search(sort="created")), ["board", "busy"])

    def test_pinned_docs_sort_by_the_active_key_among_themselves(self) -> None:
        self._doc("pin-a", "2026-10-01T00:00:00+00:00", created_at="2099-02-01T00:00:00+00:00")
        self._doc("pin-b", "2026-10-02T00:00:00+00:00", created_at="2099-01-01T00:00:00+00:00")
        self._doc("plain", "2026-10-09T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search()), ["pin-b", "pin-a", "plain"])
        self.assertEqual(self._ids(self.index.search(sort="created")), ["pin-a", "pin-b", "plain"])

    def test_a_near_future_date_from_clock_skew_does_not_pin(self) -> None:
        near = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self._doc("skewed", "2026-10-01T00:00:00+00:00", created_at=near)
        self._doc("busy", "2026-10-09T00:00:00+00:00")
        self.index.sync()
        self.assertEqual(self._ids(self.index.search()), ["busy", "skewed"])


if __name__ == "__main__":
    unittest.main()
