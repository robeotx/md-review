"""Store tests: render pipeline, manifest v2 (provenance), comment channel."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mdreview import store


class RenderDocumentTests(unittest.TestCase):
    def test_render_creates_expected_anchors_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data_dir = root / "data"
            md = root / "sample.md"
            md.write_text(
                "# Title\n\n"
                "Paragraph with **bold** text.\n\n"
                "- First item\n"
                "- Second item\n\n"
                "| A | B |\n"
                "|---|---|\n"
                "| 1 | 2 |\n\n"
                "```python\nprint('x')\n```\n",
                encoding="utf-8",
            )
            out = store.render_document(md, data_dir, "Sample")
            anchors = json.loads((out.parent / "anchors.json").read_text(encoding="utf-8"))
            kinds = [a["elementKind"] for a in anchors]
            self.assertIn("heading", kinds)
            self.assertIn("paragraph", kinds)
            self.assertEqual(kinds.count("list-item"), 2)
            self.assertEqual(kinds.count("table-row"), 2)
            self.assertIn("code", kinds)
            self.assertEqual(json.loads((out.parent / "comments.json").read_text(encoding="utf-8")), [])

    def test_manifest_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            md = root / "doc.md"
            md.write_text("# T\n\nbody\n", encoding="utf-8")
            out = store.render_document(
                md, root / "data", "Doc", agent="test-harness", session_id="sess-123", agent_cwd=str(root)
            )
            manifest = json.loads((out.parent / "manifest.json").read_text(encoding="utf-8"))
            prov = manifest["provenance"]
            self.assertEqual(prov["sessionId"], "sess-123")
            self.assertEqual(prov["agent"], "test-harness")
            self.assertEqual(prov["agentCwd"], str(root.resolve()))
            self.assertEqual(prov["sourceAbsPath"], str(md.resolve()))
            self.assertIn("createdAt", prov)
            self.assertIn("renderedAt", prov)
            # The page itself must carry the provenance for the Source panel.
            page = (out.parent / "index.html").read_text(encoding="utf-8")
            self.assertIn("sess-123", page)
            self.assertIn("data-prov-toggle", page)

    def test_dual_anchor_keys_survive_common_rerenders(self) -> None:
        from mdreview.renderer import MarkdownRenderer

        first = MarkdownRenderer()
        first.render("# H\n\nOriginal paragraph.\n")
        original_para = [a for a in first.anchors if a.element_kind == "paragraph"][0]

        edited = MarkdownRenderer()
        edited.render("# H\n\nOriginal paragraph with edit.\n")
        edited_para = [a for a in edited.anchors if a.element_kind == "paragraph"][0]
        self.assertEqual(original_para.semantic_key, edited_para.semantic_key)
        self.assertNotEqual(original_para.anchor_id, edited_para.anchor_id)

        inserted = MarkdownRenderer()
        inserted.render("# H\n\nInserted paragraph.\n\nOriginal paragraph.\n")
        inserted_paras = [a for a in inserted.anchors if a.element_kind == "paragraph"]
        self.assertEqual(original_para.anchor_id, inserted_paras[1].anchor_id)

    def test_created_at_survives_rerender(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            md = root / "doc.md"
            md.write_text("# T\n\nv1\n", encoding="utf-8")
            data_dir = root / "data"
            out1 = store.render_document(md, data_dir, "Doc")
            first = json.loads((out1.parent / "manifest.json").read_text(encoding="utf-8"))
            md.write_text("# T\n\nv2\n", encoding="utf-8")
            out2 = store.render_document(md, data_dir, "Doc")
            second = json.loads((out2.parent / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(out1, out2, "same source path must map to the same doc id")
            self.assertEqual(first["createdAt"], second["createdAt"])
            self.assertIn("v2", (out2.parent / "index.html").read_text(encoding="utf-8"))

    def test_render_rejects_non_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            not_md = Path(td) / "doc.txt"
            not_md.write_text("nope", encoding="utf-8")
            with self.assertRaises(ValueError):
                store.render_document(not_md, Path(td) / "data")


class DocIdTests(unittest.TestCase):
    def test_cross_repo_collision_prevented(self) -> None:
        # two repos that both contain docs/design.md used to share ONE doc id — the second render
        # replaced the first's page while pooling its comments.
        id_a = store.doc_id_for("docs/design.md", "https://github.com/acme/repo-a")
        id_b = store.doc_id_for("docs/design.md", "https://github.com/acme/repo-b")
        self.assertNotEqual(id_a, id_b)
        # Slug stays human-readable and path-derived; only the hash differs.
        self.assertTrue(id_a.startswith("docs-design-"))
        self.assertTrue(id_b.startswith("docs-design-"))

    def test_same_repo_same_path_stable(self) -> None:
        ns = "https://github.com/acme/repo"
        self.assertEqual(store.doc_id_for("docs/design.md", ns), store.doc_id_for("docs/design.md", ns))

    def test_no_namespace_matches_legacy_format(self) -> None:
        # Legacy stores (and non-repo files) hash the bare display path;
        # keep that exact shape so migrated docs never move.
        from mdreview.renderer import short_hash, slugify

        legacy = f"{slugify('docs-design', 'doc')}-{short_hash('docs/design.md', 10)}"
        self.assertEqual(store.doc_id_for("docs/design.md", ""), legacy)

    def test_namespace_prefers_remote_over_root(self) -> None:
        prov = {"sourceRepoRemote": "https://github.com/acme/r", "sourceRepoRoot": "/home/u/r"}
        self.assertEqual(store.doc_namespace(prov), "https://github.com/acme/r")
        self.assertEqual(store.doc_namespace({"sourceRepoRoot": "/home/u/r"}), "/home/u/r")
        self.assertEqual(store.doc_namespace({}), "")

    def test_two_git_repos_same_relative_path_render_distinctly(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            ids = []
            for name in ("repo-a", "repo-b"):
                root = Path(td) / name
                (root / "docs").mkdir(parents=True)
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True, capture_output=True)
                subprocess.run(
                    ["git", "remote", "add", "origin", f"https://github.com/acme/{name}.git"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
                md = root / "docs" / "design.md"
                md.write_text(f"# {name}\n", encoding="utf-8")
                out = store.render_document(md, Path(td) / "data", name)
                ids.append(out.parent.name)
            self.assertNotEqual(ids[0], ids[1])


class CommentStoreTests(unittest.TestCase):
    def test_comment_store_validation_and_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            doc_dir = data_dir / "rendered" / "sample-doc"
            doc_dir.mkdir(parents=True)
            (doc_dir / "comments.json").write_text("[]\n", encoding="utf-8")
            body = {
                "docId": "sample-doc",
                "anchor": {
                    "type": "md-element",
                    "anchorId": "a-123",
                    "semanticKey": "root::paragraph::1",
                    "elementKind": "paragraph",
                    "label": "paragraph · Document",
                    "quote": "quoted text",
                },
                "text": "review note",
            }
            doc_id, anchor, text, quote = store.validate_comment_body(body)
            self.assertEqual(doc_id, "sample-doc")
            self.assertEqual(text, "review note")
            self.assertEqual(quote, "quoted text")
            comments = store.load_comments(doc_id, data_dir)
            comments.append({"id": "c1", "anchor": anchor, "text": text, "quote": quote, "resolved": False})
            store.save_comments(doc_id, comments, data_dir)
            saved = json.loads((doc_dir / "comments.json").read_text(encoding="utf-8"))
            self.assertEqual(saved[0]["text"], "review note")

    def test_validate_rejects_bad_bodies(self) -> None:
        bad_bodies = [
            None,
            [],
            {},
            {"docId": "d"},
            {"docId": "d", "anchor": {}},
            {"docId": "d", "anchor": {"type": "md-element", "anchorId": "a", "semanticKey": "s",
                                       "elementKind": "paragraph", "label": "l"}},
            {"docId": "d", "anchor": {"type": "other", "anchorId": "a", "semanticKey": "s",
                                      "elementKind": "paragraph", "label": "l"}, "text": "x"},
            {"docId": "d", "anchor": {"type": "md-element", "anchorId": "a", "semanticKey": "s",
                                      "elementKind": "paragraph", "label": "l"}, "text": "   "},
        ]
        for body in bad_bodies:
            with self.assertRaises(ValueError, msg=f"body should be rejected: {body!r}"):
                store.validate_comment_body(body)

    def _valid_body(self) -> dict:
        return {
            "docId": "d",
            "anchor": {
                "type": "md-element",
                "anchorId": "a",
                "semanticKey": "s",
                "elementKind": "paragraph",
                "label": "l",
            },
            "text": "note",
        }

    def test_anchor_doc_id_mismatch_rejected_match_normalized(self) -> None:
        body = self._valid_body()
        body["anchor"]["docId"] = "someone-else"
        with self.assertRaises(ValueError):
            store.validate_comment_body(body)
        body["anchor"]["docId"] = "d"
        doc_id, anchor, _, _ = store.validate_comment_body(body)
        self.assertEqual(anchor["docId"], doc_id)
        del body["anchor"]["docId"]
        _, anchor2, _, _ = store.validate_comment_body(body)
        self.assertEqual(anchor2["docId"], "d", "missing anchor.docId is normalized to the comment's")

    def test_metadata_caps_enforced(self) -> None:
        body = self._valid_body()
        body["quote"] = "q" * 10_000
        body["anchor"]["label"] = "l" * 1_000
        _, anchor, _, quote = store.validate_comment_body(body)
        self.assertEqual(len(quote), store.MAX_QUOTE_LENGTH)
        self.assertEqual(len(anchor["label"]), store.MAX_LABEL_LENGTH)
        self.assertEqual(store.validate_author("a" * 500), "a" * store.MAX_AUTHOR_LENGTH)
        self.assertIsNone(store.validate_author(42))
        self.assertIsNone(store.validate_author("   "))
        body["text"] = "x" * (store.MAX_COMMENT_TEXT_LENGTH + 1)
        with self.assertRaises(ValueError):
            store.validate_comment_body(body)

    def test_corrupt_store_fails_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            doc_dir = data_dir / "rendered" / "broken-doc"
            doc_dir.mkdir(parents=True)
            (doc_dir / "comments.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                store.load_comments("broken-doc", data_dir)
            (doc_dir / "comments.json").write_text('{"not": "a list"}', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                store.load_comments("broken-doc", data_dir)

    def test_doc_id_traversal_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            for bad in ["../etc", "..", "a/b", "", "UPPER"]:
                with self.assertRaises(ValueError, msg=f"doc id should be rejected: {bad!r}"):
                    store.doc_dir_for_id(bad, data_dir)

    def test_resolve_comment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            doc_dir = data_dir / "rendered" / "d1"
            doc_dir.mkdir(parents=True)
            (doc_dir / "comments.json").write_text(
                json.dumps([{"id": "c1", "text": "note", "resolved": False}]), encoding="utf-8"
            )
            updated = store.set_comment_resolved("d1", "c1", True, data_dir)
            self.assertTrue(updated["resolved"])
            self.assertTrue(store.load_comments("d1", data_dir)[0]["resolved"])
            with self.assertRaises(LookupError):
                store.set_comment_resolved("d1", "nope", True, data_dir)


class ListDocumentsTests(unittest.TestCase):
    def test_lists_newest_first_with_counts_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            base = data_dir / "rendered"
            for doc_id, created in [("old-doc", "2026-07-01T00:00:00+00:00"), ("new-doc", "2026-07-30T00:00:00+00:00")]:
                doc_dir = base / doc_id
                doc_dir.mkdir(parents=True)
                (doc_dir / "manifest.json").write_text(
                    json.dumps(
                        {
                            "docId": doc_id,
                            "title": doc_id,
                            "sourcePath": f"{doc_id}.md",
                            "createdAt": created,
                            "provenance": {"sourceRepoName": "repo", "sessionId": "s123456789"},
                        }
                    ),
                    encoding="utf-8",
                )
            (base / "new-doc" / "comments.json").write_text(
                json.dumps([{"id": "a", "resolved": False}, {"id": "b", "resolved": True}]), encoding="utf-8"
            )
            (base / "old-doc" / "comments.json").write_text("[]\n", encoding="utf-8")
            entries = store.list_documents(data_dir)
            self.assertEqual([e["docId"] for e in entries], ["new-doc", "old-doc"])
            self.assertEqual(entries[0]["openComments"], 1)
            self.assertEqual(entries[0]["totalComments"], 2)
            self.assertEqual(entries[1]["openComments"], 0)
            self.assertEqual(entries[0]["provenance"]["sourceRepoName"], "repo")

    def test_tolerates_missing_and_corrupt_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            base = data_dir / "rendered"
            good = base / "good"
            good.mkdir(parents=True)
            (good / "manifest.json").write_text(json.dumps({"docId": "good", "createdAt": "2026-07-30"}), encoding="utf-8")
            # no comments.json at all → counts are None, not an error
            broken = base / "broken"
            broken.mkdir(parents=True)
            (broken / "manifest.json").write_text("{corrupt", encoding="utf-8")
            entries = store.list_documents(data_dir)
            self.assertEqual([e["docId"] for e in entries], ["good"])
            self.assertIsNone(entries[0]["openComments"])

    def test_non_dict_manifest_skipped_and_hostile_fields_coerced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            base = data_dir / "rendered"
            weird = base / "weird"
            weird.mkdir(parents=True)
            (weird / "manifest.json").write_text("[1, 2, 3]", encoding="utf-8")
            hostile = base / "hostile"
            hostile.mkdir(parents=True)
            (hostile / "manifest.json").write_text(
                json.dumps({"docId": "hostile", "title": 42, "createdAt": "2026-07-30", "provenance": {"sessionId": 7}}),
                encoding="utf-8",
            )
            entries = store.list_documents(data_dir)
            self.assertEqual([e["docId"] for e in entries], ["hostile"])
            self.assertEqual(entries[0]["title"], "hostile")  # non-string title falls back to doc id
            self.assertEqual(entries[0]["provenance"]["sessionId"], "7")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
