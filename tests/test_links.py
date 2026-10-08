"""Relative-link resolution and publish-time capture policy."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mdreview import links


class SplitHrefTests(unittest.TestCase):
    def test_relative_paths_split_into_path_and_fragment(self) -> None:
        self.assertEqual(("reports/a.md", "sec"), links.split_relative_href("reports/a.md#sec"))
        self.assertEqual(("a b.md", ""), links.split_relative_href("a%20b.md"))
        self.assertEqual(("./x.png", ""), links.split_relative_href("./x.png?v=2"))
        self.assertEqual("docs/x.png", links.resolve_target("docs/a.md", "./x.png", in_repo=True))

    def test_non_relative_hrefs_are_not_ours(self) -> None:
        for href in ("#top", "/abs/x.md", "//host/x", "https://e.com/a.md", "mailto:a@b.c", ""):
            self.assertIsNone(links.split_relative_href(href), href)


class ResolveTargetTests(unittest.TestCase):
    def test_repo_relative_resolution(self) -> None:
        self.assertEqual("docs/reports/a.md", links.resolve_target("docs/plan.md", "reports/a.md", in_repo=True))
        self.assertEqual("README.md", links.resolve_target("docs/plan.md", "../README.md", in_repo=True))

    def test_escaping_the_repo_is_refused(self) -> None:
        with self.assertRaises(links.Unavailable):
            links.resolve_target("docs/plan.md", "../../etc/passwd", in_repo=True)

    def test_non_repo_docs_stay_inside_their_own_directory(self) -> None:
        self.assertEqual("/n/sub/b.md", links.resolve_target("/n/a.md", "sub/b.md", in_repo=False))
        with self.assertRaises(links.Unavailable):
            links.resolve_target("/n/a.md", "../other/b.md", in_repo=False)

    def test_hostile_path_characters_are_refused(self) -> None:
        for bad in ("a\x00b.md", "dir\\x.md", "secret.txt:stream", "C:/x.md"):
            with self.assertRaises(links.Unavailable, msg=bad):
                links.resolve_target("docs/plan.md", bad, in_repo=True)


class LinkKeyTests(unittest.TestCase):
    def test_key_is_stable_hex_of_identity(self) -> None:
        key = links.link_key("docs/a.md")
        self.assertRegex(key, r"^[0-9a-f]{16}$")
        self.assertEqual(key, links.link_key("docs/a.md"))
        self.assertNotEqual(key, links.link_key("docs/b.md"))


class KindTests(unittest.TestCase):
    def test_kinds_and_mime_come_from_a_closed_map(self) -> None:
        self.assertEqual("doc", links.kind_for("x/a.MD"))
        self.assertEqual("image", links.kind_for("x/a.PNG"))
        self.assertEqual("text", links.kind_for("x/a.html"))  # never served as html
        self.assertEqual("text", links.kind_for("x/a.svgz"))
        self.assertEqual("image/svg+xml", links.image_mime("a.svg"))
        self.assertEqual("image/jpeg", links.image_mime("a.JPG"))


class DenyPolicyTests(unittest.TestCase):
    def test_secret_names_and_credential_dirs_are_denied(self) -> None:
        for path in (".env", "app/.ENV.local", ".aws/config", "x/.kube/config", ".docker/config.json",
                     ".ssh/id_rsa", "keys/server.PEM", "id_ed25519.pub", "Credentials.json", ".git/config",
                     ".netrc", "secrets.yaml", ".config/gcloud/creds.db"):
            self.assertIsNotNone(links.denied_reason(path), path)

    def test_ordinary_files_including_hidden_work_dirs_are_allowed(self) -> None:
        for path in ("docs/a.md", ".tmp/report.md", "img/diagram.png", "data/results.csv", "config.example.toml"):
            self.assertIsNone(links.denied_reason(path), path)

    def test_content_that_looks_like_a_secret_is_denied(self) -> None:
        self.assertIsNotNone(links.secret_content_reason(b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"))
        self.assertIsNotNone(links.secret_content_reason(b"token = ghp_" + b"a" * 36))
        self.assertIsNotNone(links.secret_content_reason(b"AWS_ACCESS_KEY_ID=AKIA" + b"A" * 16))
        self.assertIsNone(links.secret_content_reason(b"# just notes\nnothing here"))


class TempRootCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, rel: str, data: bytes) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


class CaptureFileTests(TempRootCase):
    def test_captures_a_regular_text_file(self) -> None:
        self.write("docs/r.md", b"# hi\n")
        self.assertEqual(b"# hi\n", links.capture_file(self.root / "docs/r.md", self.root, "docs/r.md"))

    def test_missing_and_directory_targets_are_unavailable(self) -> None:
        (self.root / "dir").mkdir()
        for rel in ("nope.md", "dir"):
            with self.assertRaises(links.Unavailable, msg=rel):
                links.capture_file(self.root / rel, self.root, rel)

    def test_over_cap_is_unavailable(self) -> None:
        self.write("big.txt", b"x" * (links.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(links.Unavailable, "too large"):
            links.capture_file(self.root / "big.txt", self.root, "big.txt")

    def test_binary_non_image_is_unavailable_but_images_are_kept(self) -> None:
        self.write("blob.bin", b"\x00\x01\x02")
        with self.assertRaisesRegex(links.Unavailable, "binary"):
            links.capture_file(self.root / "blob.bin", self.root, "blob.bin")
        self.write("p.png", b"\x89PNG\x00\x01")
        self.assertEqual(b"\x89PNG\x00\x01", links.capture_file(self.root / "p.png", self.root, "p.png"))

    def test_secret_content_is_unavailable(self) -> None:
        self.write("notes.txt", b"-----BEGIN RSA PRIVATE KEY-----\n")
        with self.assertRaisesRegex(links.Unavailable, "secret"):
            links.capture_file(self.root / "notes.txt", self.root, "notes.txt")

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "posix symlinks")
    def test_symlink_escaping_the_boundary_is_unavailable(self) -> None:
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        target = Path(outside.name) / "secret.txt"
        target.write_bytes(b"outside")
        (self.root / "link.txt").symlink_to(target)
        with self.assertRaisesRegex(links.Unavailable, "outside"):
            links.capture_file(self.root / "link.txt", self.root, "link.txt")

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "posix symlinks")
    def test_symlink_into_a_denied_dir_is_unavailable(self) -> None:
        self.write(".aws/config", b"[default]\n")
        (self.root / "innocent.txt").symlink_to(self.root / ".aws/config")
        with self.assertRaises(links.Unavailable):
            links.capture_file(self.root / "innocent.txt", self.root, "innocent.txt")


class CaptureReviewFindingsTests(TempRootCase):
    """Regressions from the cross-model code review (2026-10-07)."""

    def test_images_are_screened_for_secret_contents_too(self) -> None:
        self.write("token.svg", b"<svg><metadata>ghp_" + b"a" * 36 + b"</metadata></svg>")
        with self.assertRaisesRegex(links.Unavailable, "secret"):
            links.capture_file(self.root / "token.svg", self.root, "token.svg")

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "posix symlinks")
    def test_symlink_loop_is_unavailable_not_a_crash(self) -> None:
        (self.root / "loop.txt").symlink_to(self.root / "loop.txt")
        with self.assertRaises(links.Unavailable):
            links.capture_file(self.root / "loop.txt", self.root, "loop.txt")

    @unittest.skipUnless(os.name == "posix", "posix openat walk")
    def test_ancestor_swapped_for_a_symlink_after_resolution_is_refused(self) -> None:
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        (Path(outside.name) / "r.txt").write_bytes(b"outside")
        self.write("docs/r.txt", b"inside")
        real_resolve = Path.resolve

        def swap_then_resolve(path: Path, *args, **kwargs) -> Path:
            resolved = real_resolve(path, *args, **kwargs)
            docs = self.root / "docs"
            if docs.is_dir() and not docs.is_symlink():
                (docs / "r.txt").unlink()
                docs.rmdir()
                docs.symlink_to(outside.name)
            return resolved

        with mock.patch.object(Path, "resolve", swap_then_resolve), self.assertRaises(links.Unavailable):
            links.capture_file(self.root / "docs/r.txt", self.root, "docs/r.txt")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
