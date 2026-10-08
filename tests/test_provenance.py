"""Provenance tests: session-id resolution, git detection, never-fail contract."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mdreview import provenance


class SessionIdTests(unittest.TestCase):
    def test_explicit_wins_over_env(self) -> None:
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "env-sess"}):
            self.assertEqual(provenance.detect_session_id("flag-sess"), "flag-sess")

    def test_known_harness_env_vars_detected_in_priority_order(self) -> None:
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "cc-sess", "CODEX_SESSION_ID": "cx-sess"}, clear=False):
            self.assertEqual(provenance.detect_session_id(), "cc-sess")

    def test_md_review_session_id_beats_harness_vars(self) -> None:
        with mock.patch.dict(os.environ, {"MD_REVIEW_SESSION_ID": "mr-sess", "CLAUDE_CODE_SESSION_ID": "cc-sess"}):
            self.assertEqual(provenance.detect_session_id(), "mr-sess")

    def test_none_when_nothing_set(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(provenance.detect_session_id())

    def test_agent_detection(self) -> None:
        with mock.patch.dict(os.environ, {"AI_AGENT": "claude-code_2-1-220_agent"}):
            self.assertEqual(provenance.detect_agent(), "claude-code_2-1-220_agent")
        with mock.patch.dict(os.environ, {"AI_AGENT": "env-agent"}):
            self.assertEqual(provenance.detect_agent("flag-agent"), "flag-agent")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(provenance.detect_agent())


class GitDetectionTests(unittest.TestCase):
    def test_git_repo_fields_collected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            doc = root / "docs"
            doc.mkdir()
            md = doc / "thing.md"
            md.write_text("# t\n", encoding="utf-8")
            prov = provenance.collect_provenance(md, session_id="s1")
            self.assertEqual(prov["sourceRepoName"], root.name)
            self.assertEqual(Path(prov["sourceRepoRoot"]).resolve(), root.resolve())
            self.assertEqual(prov["sourceRepoBranch"], "main")
            self.assertEqual(prov["sourceRepoRelPath"], "docs/thing.md")
            self.assertEqual(prov["sessionId"], "s1")
            self.assertEqual(prov["agentCwd"], str(Path.cwd().resolve()))

    def test_outside_git_repo_still_collects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # /tmp is not a git repo; if it somehow is on this machine, skip.
            if provenance.git_root_for(Path(td)) is not None:
                self.skipTest("temp dir unexpectedly inside a git repo")
            md = Path(td) / "lone.md"
            md.write_text("# t\n", encoding="utf-8")
            prov = provenance.collect_provenance(md)
            self.assertIsNone(prov["sourceRepoRoot"])
            self.assertIsNone(prov["sourceRepoName"])
            self.assertEqual(prov["sourceAbsPath"], str(md.resolve()))

    def test_agent_cwd_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            md = Path(td) / "x.md"
            md.write_text("# t\n", encoding="utf-8")
            prov = provenance.collect_provenance(md, agent_cwd="/some/other/place")
            # agentCwd is a machine-local display path, so the value is
            # legitimately NATIVE (backslashes on Windows) — assert the
            # resolved form, not a POSIX literal.
            self.assertEqual(prov["agentCwd"], str(Path("/some/other/place").resolve()))


class RemoteSanitizationTests(unittest.TestCase):
    def test_https_userinfo_stripped(self) -> None:
        self.assertEqual(
            provenance.sanitize_remote_url("https://alice:ghp_SECRET@github.com/acme/private.git"),
            "https://github.com/acme/private.git",
        )
        self.assertEqual(
            provenance.sanitize_remote_url("https://oauth2:token123@gitlab.com/org/repo.git"),
            "https://gitlab.com/org/repo.git",
        )

    def test_ssh_scp_like_and_clean_urls_untouched(self) -> None:
        self.assertEqual(
            provenance.sanitize_remote_url("git@github.com:acme/repo.git"),
            "git@github.com:acme/repo.git",
        )
        self.assertEqual(
            provenance.sanitize_remote_url("https://github.com/acme/repo.git"),
            "https://github.com/acme/repo.git",
        )
        self.assertIsNone(provenance.sanitize_remote_url(None))

    def test_credential_remote_never_reaches_manifest(self) -> None:
        import subprocess

        from mdreview import store

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "remote", "add", "origin", "https://alice:ghp_SECRET@github.com/acme/private.git"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            md = root / "doc.md"
            md.write_text("# t\n", encoding="utf-8")
            out = store.render_document(md, Path(td) / "data", "Doc")
            manifest_text = (out.parent / "manifest.json").read_text(encoding="utf-8")
            page_text = (out.parent / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("ghp_SECRET", manifest_text)
            self.assertNotIn("ghp_SECRET", page_text)
            self.assertIn("https://github.com/acme/private.git", manifest_text)


class NormalizeProvenanceTests(unittest.TestCase):
    def test_fixed_schema_with_explicit_nulls(self) -> None:
        normalized = provenance.normalize_provenance({"sessionId": "s1", "unknownField": "dropped"})
        self.assertEqual(set(normalized.keys()), set(provenance.PROVENANCE_FIELDS))
        self.assertEqual(normalized["sessionId"], "s1")
        self.assertNotIn("unknownField", normalized)
        self.assertIsNone(normalized["sourceRepoName"])

    def test_types_coerced_or_nulled(self) -> None:
        normalized = provenance.normalize_provenance(
            {"sessionId": 7, "agentCwd": 3.5, "agent": {"x": 1}, "hostname": ["h"], "user": True}
        )
        self.assertEqual(normalized["sessionId"], "7")
        self.assertEqual(normalized["agentCwd"], "3.5")
        self.assertIsNone(normalized["agent"])
        self.assertIsNone(normalized["hostname"])
        self.assertIsNone(normalized["user"])

    def test_non_dict_input_becomes_all_nulls(self) -> None:
        for bad in (None, 42, "string", ["list"]):
            normalized = provenance.normalize_provenance(bad)
            self.assertTrue(all(v is None for v in normalized.values()), bad)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
