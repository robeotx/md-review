"""Store side of relative links: link entries, captured blobs, cleanup, limits."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mdreview import links, store

REPO_PROV = {"sourceRepoRoot": "/w/repo", "sourceRepoRemote": "https://github.com/acme/r.git"}


def render(data_dir: Path, markdown: str, captures: store.Captures | None, source: str = "docs/plan.md") -> Path:
    namespace = store.doc_namespace(REPO_PROV)
    return store.render_payload(
        markdown=markdown,
        source_path=source,
        doc_id=store.doc_id_for(source, namespace),
        title="Plan",
        data_dir=data_dir,
        provenance=dict(REPO_PROV),
        captures=captures,
    )


def entries(page: Path) -> dict:
    return json.loads((page.parent / "links.json").read_text(encoding="utf-8"))


def by_target(page: Path) -> dict:
    return {e["target"]: e for e in entries(page).values()}


class LinkEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_entries_cover_doc_links_captures_and_unavailable_targets(self) -> None:
        md = (
            "[r](reports/a.md#sec) [d](data.csv) ![img](d.png) [s](.env) [gone](gone.txt) [out](../../x.md)\n"
        )
        captures = store.Captures(
            files={"docs/reports/a.md": b"# A\n", "docs/data.csv": b"a,b\n", "docs/d.png": b"\x89PNG"},
            reasons={"docs/.env": "not captured (looks like a secret)"},
        )
        page = render(self.data, md, captures)
        got = by_target(page)
        doc = got["docs/reports/a.md"]
        self.assertEqual("doc", doc["kind"])
        self.assertEqual(store.doc_id_for("docs/reports/a.md", store.doc_namespace(REPO_PROV)), doc["docId"])
        self.assertIn("sha256", doc)
        self.assertEqual("text", got["docs/data.csv"]["kind"])
        self.assertEqual("image", got["docs/d.png"]["kind"])
        self.assertEqual("not captured (looks like a secret)", got["docs/.env"]["reason"])
        self.assertEqual("not captured by the publisher", got["docs/gone.txt"]["reason"])
        unresolved = [e for e in entries(page).values() if e["target"] is None]
        self.assertEqual(["outside the repository"], [e["reason"] for e in unresolved])

        html = page.read_text(encoding="utf-8")
        doc_id = page.parent.name
        key = links.link_key("docs/reports/a.md")
        self.assertIn(f'href="/link/{doc_id}/{key}#sec"', html)
        self.assertIn(f'<img src="/link/{doc_id}/{links.link_key("docs/d.png")}"', html)
        self.assertEqual(3, html.count('<span class="md-link-unavailable-mark"'))

    def test_blobs_are_content_addressed_and_unreferenced_ones_removed_on_rerender(self) -> None:
        page = render(self.data, "[d](data.csv)\n", store.Captures(files={"docs/data.csv": b"v1\n"}, reasons={}))
        files_dir = page.parent / "files"
        first = {p.name for p in files_dir.iterdir()}
        self.assertEqual(1, len(first))
        page2 = render(self.data, "[d](data.csv)\n", store.Captures(files={"docs/data.csv": b"v2\n"}, reasons={}))
        self.assertEqual(page.parent, page2.parent)
        second = {p.name for p in files_dir.iterdir()}
        self.assertEqual(1, len(second))
        self.assertNotEqual(first, second)

    def test_captures_not_linked_from_the_markdown_are_ignored(self) -> None:
        page = render(self.data, "no links\n", store.Captures(files={"docs/sneaky.txt": b"x"}, reasons={}))
        self.assertFalse((page.parent / "files").exists() and any((page.parent / "files").iterdir()))
        self.assertEqual({}, entries(page))

    def test_per_doc_capture_budget_marks_overflow_unavailable(self) -> None:
        big = b"x" * (links.MAX_FILE_BYTES - 1)
        files = {f"docs/f{i}.txt": big for i in range(6)}
        md = " ".join(f"[f{i}](f{i}.txt)" for i in range(6)) + "\n"
        page = render(self.data, md, store.Captures(files=files, reasons={}))
        got = by_target(page)
        captured = [t for t, e in got.items() if "sha256" in e]
        self.assertEqual(4, len(captured))  # 4 x ~2 MiB fits in 8 MiB, the 5th does not
        self.assertIn("per-document", got["docs/f5.txt"]["reason"])

    def test_oversized_single_capture_is_refused(self) -> None:
        page = render(
            self.data,
            "[b](b.txt)\n",
            store.Captures(files={"docs/b.txt": b"x" * (links.MAX_FILE_BYTES + 1)}, reasons={}),
        )
        self.assertIn("too large", by_target(page)["docs/b.txt"]["reason"])

    def test_store_quota_drops_captures_but_render_succeeds(self) -> None:
        with mock.patch.object(store, "STORE_ATTACHMENT_QUOTA", 3):
            page = render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"four"}, reasons={}))
        self.assertIn("storage limit", by_target(page)["docs/d.txt"]["reason"])
        self.assertTrue(page.is_file())

    def test_hostile_publisher_reason_is_capped_and_escaped(self) -> None:
        reason = '"><script>alert(1)</script>' + "x" * 1000
        page = render(self.data, "[s](s.txt)\n", store.Captures(files={}, reasons={"docs/s.txt": reason}))
        self.assertLessEqual(len(by_target(page)["docs/s.txt"]["reason"]), store.MAX_LINK_REASON_LENGTH)
        self.assertNotIn("<script>alert", page.read_text(encoding="utf-8"))

    def test_without_captures_doc_links_still_resolve(self) -> None:
        page = render(self.data, "[r](r.md) [t](t.txt)\n", None)
        got = by_target(page)
        self.assertIn("docId", got["docs/r.md"])
        self.assertEqual("not captured by the publisher", got["docs/t.txt"]["reason"])


class CaptureLinksTests(unittest.TestCase):
    """Publisher side: reading linked files under the capture policy."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name).resolve() / "repo"
        (self.repo / "docs" / "reports").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_captures_linked_files_and_records_reasons(self) -> None:
        (self.repo / "docs" / "reports" / "a.md").write_bytes(b"# A\n")
        (self.repo / "docs" / ".env").write_bytes(b"K=v\n")
        md = "[a](reports/a.md) [e](.env) [m](missing.txt) [x](https://e.com) [o](../../out.md)\n"
        caps = store.capture_links(md, "docs/plan.md", self.repo)
        self.assertEqual({"docs/reports/a.md": b"# A\n"}, caps.files)
        self.assertIn("secret", caps.reasons["docs/.env"])
        self.assertEqual("file not found", caps.reasons["docs/missing.txt"])
        self.assertNotIn("../out.md", caps.reasons)  # unresolvable: the server derives that reason itself

    def test_non_repo_doc_captures_within_its_folder(self) -> None:
        folder = Path(self.tmp.name).resolve() / "notes"
        folder.mkdir()
        (folder / "b.md").write_bytes(b"b\n")
        source = (folder / "a.md").as_posix()
        caps = store.capture_links("[b](b.md)\n", source, None)
        self.assertEqual({(folder / "b.md").as_posix(): b"b\n"}, caps.files)

    def test_capture_budget_applies_before_shipping(self) -> None:
        for i in range(6):
            (self.repo / "docs" / f"f{i}.txt").write_bytes(b"y" * (links.MAX_FILE_BYTES - 1))
        md = " ".join(f"[f{i}](f{i}.txt)" for i in range(6)) + "\n"
        caps = store.capture_links(md, "docs/plan.md", self.repo)
        self.assertEqual(4, len(caps.files))
        self.assertIn("per-document", caps.reasons["docs/f5.txt"])


class RenderDocumentCaptureTests(unittest.TestCase):
    def test_local_render_captures_and_can_opt_out(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td).resolve() / "repo"
            (repo / "docs").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True, capture_output=True)
            (repo / "docs" / "note.txt").write_bytes(b"hello\n")
            md = repo / "docs" / "plan.md"
            md.write_text("[n](note.txt)\n", encoding="utf-8")
            page = store.render_document(md, Path(td) / "data", "Plan")
            self.assertIn("sha256", by_target(page)["docs/note.txt"])
            page = store.render_document(md, Path(td) / "data", "Plan", capture=False)
            self.assertEqual("capture turned off by the publisher", by_target(page)["docs/note.txt"]["reason"])


class ReviewFindingsTests(unittest.TestCase):
    """Regressions from the cross-model code review (2026-10-07)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_failed_render_writes_no_blobs(self) -> None:
        with self.assertRaises(UnicodeEncodeError):
            store.render_payload(
                markdown="[d](d.txt)\n",
                source_path="docs/plan.md",
                doc_id="docs-plan-x",
                title="\ud800",  # unencodable: the page write must fail BEFORE any blob lands
                data_dir=self.data,
                provenance=dict(REPO_PROV),
                captures=store.Captures(files={"docs/d.txt": b"data"}, reasons={}),
            )
        self.assertEqual([], list((self.data / "rendered").glob("*/files/*")))

    def test_refresh_at_quota_replaces_the_documents_own_attachment(self) -> None:
        with mock.patch.object(store, "STORE_ATTACHMENT_QUOTA", 6):
            render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"1111"}, reasons={}))
            page = render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"2222"}, reasons={}))
        # The doc's own referenced bytes are credited (they are replaced), so a
        # refresh keeps its attachment; afterwards only the new blob remains.
        self.assertIn("sha256", by_target(page)["docs/d.txt"])
        self.assertEqual([b"2222"], [p.read_bytes() for p in (page.parent / "files").iterdir()])

    def test_retained_attachments_are_charged_so_refreshes_cannot_grow_past_quota(self) -> None:
        stored_sizes = []
        md = ""
        with mock.patch.object(store, "STORE_ATTACHMENT_QUOTA", 4):
            files: dict[str, bytes] = {}
            for i in range(3):
                files[f"docs/f{i}.txt"] = f"{i}{i}{i}{i}".encode()
                md += f"[f{i}](f{i}.txt) "
                page = render(self.data, md + "\n", store.Captures(files=dict(files), reasons={}))
                stored_sizes.append(sum(p.stat().st_size for p in (page.parent / "files").iterdir()))
        self.assertEqual([4, 4, 4], stored_sizes)

    def test_failed_write_after_blobs_removes_this_renders_new_blobs(self) -> None:
        page = render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"1111"}, reasons={}))
        real_write = store._atomic_write

        def fail_on_links(path, content, **kwargs):
            if path.name == "links.json":
                raise OSError("disk full")
            return real_write(path, content, **kwargs)

        with mock.patch.object(store, "_atomic_write", fail_on_links), self.assertRaises(OSError):
            render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"2222"}, reasons={}))
        self.assertEqual([b"1111"], [p.read_bytes() for p in (page.parent / "files").iterdir()])

    def _fail_writing(self, name: str):
        real_write = store._atomic_write

        def failing(path, content, **kwargs):
            if path.name == name:
                raise OSError("disk full")
            return real_write(path, content, **kwargs)

        return mock.patch.object(store, "_atomic_write", failing)

    def test_failure_after_links_json_lands_prunes_the_old_blobs(self) -> None:
        page = render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"1111"}, reasons={}))
        with self._fail_writing("index.html"), self.assertRaises(OSError):
            render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"2222"}, reasons={}))
        # The new links.json is in charge, so only its blob may remain.
        self.assertEqual([b"2222"], [p.read_bytes() for p in (page.parent / "files").iterdir()])

    def test_failure_cleanup_never_deletes_a_blob_the_current_links_json_references(self) -> None:
        caps = store.Captures(files={"docs/a.txt": b"AAAA", "docs/b.txt": b"BBBB"}, reasons={})
        page = render(self.data, "[a](a.txt) [b](b.txt)\n", caps)
        files = page.parent / "files"
        a_blob = files / hashlib.sha256(b"AAAA").hexdigest()
        a_blob.unlink()  # degraded store: referenced blob A missing
        with self._fail_writing("links.json"), self.assertRaises(OSError):
            render(self.data, "[a](a.txt)\n", store.Captures(files={"docs/a.txt": b"AAAA"}, reasons={}))
        # The OLD links.json (A+B) is still current: the repaired A stays, B stays.
        self.assertTrue(a_blob.exists())
        self.assertTrue((files / hashlib.sha256(b"BBBB").hexdigest()).exists())

    def test_orphans_from_failed_renders_are_removed_and_never_credited(self) -> None:
        page = render(self.data, "[d](d.txt)\n", store.Captures(files={"docs/d.txt": b"1111"}, reasons={}))
        orphan = page.parent / "files" / ("f" * 64)  # a blob no links.json references
        orphan.write_bytes(b"xxxxxxxx")
        with mock.patch.object(store, "STORE_ATTACHMENT_QUOTA", 6):
            page = render(self.data, "[e](e.txt)\n", store.Captures(files={"docs/e.txt": b"22222222"}, reasons={}))
        self.assertFalse(orphan.exists())
        # Orphan removed, own referenced 4 bytes credited: room 6, and 8 > 6.
        self.assertIn("storage limit", by_target(page)["docs/e.txt"]["reason"])

    def test_namespace_drift_never_crosses_repos_with_different_remotes(self) -> None:
        def publish(source: str, remote: str, markdown: str) -> Path:
            prov = {"sourceRepoRoot": "/workspace/project", "sourceRepoRemote": remote}
            return store.render_payload(
                markdown=markdown,
                source_path=source,
                doc_id=store.doc_id_for(source, store.doc_namespace(prov)),
                title="t",
                data_dir=self.data,
                provenance=prov,
            )

        publish("docs/b.md", "https://e.com/other.git", "# B\n")
        source = publish("docs/a.md", "https://e.com/mine.git", "[b](b.md)\n")
        entry = next(iter(entries(source).values()))
        self.assertIsNone(store.find_published_doc(entry, source.parent.name, self.data))

    def test_render_and_gc_hold_a_cross_process_store_lock(self) -> None:
        if not hasattr(store, "_store_file_lock"):
            self.fail("render_payload must take a cross-process lock")
        with mock.patch.object(store, "_store_file_lock", wraps=store._store_file_lock) as lock:
            render(self.data, "# x\n", None)
        lock.assert_called_once()


if __name__ == "__main__":
    raise SystemExit(unittest.main())
