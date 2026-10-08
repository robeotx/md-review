"""CLI side of relative links: capture summary, --no-capture, upload budget."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mdreview import cli, store


class LinksPayloadTests(unittest.TestCase):
    def test_files_ship_base64_with_reasons(self) -> None:
        caps = store.Captures(files={"docs/a.txt": b"hi"}, reasons={"docs/.env": "secret"})
        field = cli.links_payload(caps, {"markdown": "x"}, limit=10_000)
        self.assertEqual({"docs/a.txt": base64.b64encode(b"hi").decode()}, field["files"])
        self.assertEqual({"docs/.env": "secret"}, field["reasons"])

    def test_largest_captures_drop_until_the_whole_body_fits(self) -> None:
        caps = store.Captures(files={"docs/big.txt": b"x" * 3000, "docs/small.txt": b"y" * 10}, reasons={})
        base = {"markdown": "m" * 100}
        field = cli.links_payload(caps, base, limit=1000)
        self.assertEqual(["docs/small.txt"], list(field["files"]))
        self.assertEqual("over the upload size limit", field["reasons"]["docs/big.txt"])
        self.assertLessEqual(len(json.dumps({**base, "links": field}).encode()), 1000)
        self.assertNotIn("docs/big.txt", caps.files)  # the summary must reflect the drop

    def test_reasons_are_bounded_so_the_server_never_rejects_the_render(self) -> None:
        from mdreview import links

        reasons = {f"docs/m{i}.txt": "file not found" for i in range(links.MAX_TARGETS + 50)}
        caps = store.Captures(files={"docs/a.txt": b"a"}, reasons=reasons)
        field = cli.links_payload(caps, {}, limit=10_000_000)
        self.assertLessEqual(len(field["files"]) + len(field["reasons"]), links.MAX_TARGETS)
        self.assertEqual(links.MAX_TARGETS + 50, len(caps.reasons))  # the local summary keeps them all

    def test_disabled_capture_ships_the_flag_only(self) -> None:
        self.assertEqual({"disabled": True}, cli.links_payload(store.Captures(disabled=True), {}, limit=100))


class SummaryTests(unittest.TestCase):
    def test_summary_lists_captured_and_skipped(self) -> None:
        lines = cli.capture_summary(store.Captures(files={"docs/a.md": b"x" * 2048}, reasons={"docs/.env": "secret"}))
        self.assertIn("1 captured (2.0 KiB), 1 not captured", lines[0])
        self.assertIn("docs/a.md", lines[1])
        self.assertIn("docs/.env", lines[2])
        self.assertIn("secret", lines[2])

    def test_no_links_no_summary(self) -> None:
        self.assertEqual([], cli.capture_summary(store.Captures()))


class RenderCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name).resolve() / "repo"
        (self.repo / "docs").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        (self.repo / "docs" / "note.txt").write_bytes(b"hello\n")
        self.md = self.repo / "docs" / "plan.md"
        self.md.write_text("# Plan\n\n[n](note.txt)\n", encoding="utf-8")
        self.data = Path(self.tmp.name) / "data"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch.dict("os.environ", {}, clear=False):
            args = cli.build_parser().parse_args(list(argv))
            code = cli.cmd_render(args)
        return code, out.getvalue(), err.getvalue()

    def links_json(self, page_path: str) -> dict:
        entries = json.loads((Path(page_path.strip()).parent / "links.json").read_text(encoding="utf-8"))
        return {e["target"]: e for e in entries.values()}

    def test_local_render_captures_and_prints_summary_to_stderr(self) -> None:
        code, out, err = self.run_cli("render", str(self.md), "--data-dir", str(self.data))
        self.assertEqual(0, code)
        self.assertIn("sha256", self.links_json(out)["docs/note.txt"])
        self.assertIn("1 captured", err)
        self.assertNotIn("captured", out)  # stdout stays just the page path

    def test_no_capture_flag(self) -> None:
        code, out, err = self.run_cli("render", str(self.md), "--data-dir", str(self.data), "--no-capture")
        self.assertEqual(store.CAPTURE_OFF_REASON, self.links_json(out)["docs/note.txt"]["reason"])
        self.assertIn("capture turned off", err)

    def test_remote_render_ships_the_links_field(self) -> None:
        sent = {}

        def fake_post(server_url: str, payload: dict) -> dict:
            sent.update(payload)
            return {"url": "/rendered/x/index.html", "docId": "x"}

        with mock.patch.object(cli, "post_render", fake_post):
            code, out, _ = self.run_cli("render", str(self.md), "--server", "http://127.0.0.1:1")
        self.assertEqual(0, code)
        self.assertEqual(base64.b64encode(b"hello\n").decode(), sent["links"]["files"]["docs/note.txt"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
