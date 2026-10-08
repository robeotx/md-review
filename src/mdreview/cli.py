"""md-review command line.

Commands
--------
- ``md-review render <file.md>``   render into the local store (or POST to a
  running server with ``--server``)
- ``md-review serve``              run the review server (loopback by default,
  ``--host 0.0.0.0`` to share with your LAN — non-LAN clients are always
  refused)
- ``md-review docs``               list documents in the store

Configuration is flag > environment variable > default; nothing is hardcoded:

+----------------+----------------------------+------------------------------+
| flag           | environment                | default                      |
+================+============================+==============================+
| --data-dir     | MD_REVIEW_DATA_DIR         | ~/.local/share/md-review     |
| --ds-dir       | MD_REVIEW_DS_DIR           | vendored snapshot            |
| --default-author / --author | MD_REVIEW_AUTHOR | OS username       |
| --session-id   | MD_REVIEW_SESSION_ID       | harness env (auto-detected)  |
| --server       | MD_REVIEW_SERVER           | none (render locally)        |
| --theme        | MD_REVIEW_THEME            | system                       |
+----------------+----------------------------+------------------------------+
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, links, store
from .provenance import collect_provenance
from .server import MAX_RENDER_BODY_BYTES, THEMES, resolve_ds_dir, resolve_theme, serve


def _default_author() -> str:
    env = os.environ.get("MD_REVIEW_AUTHOR", "").strip()
    if env:
        return env
    try:
        return getpass.getuser() or "Reviewer"
    except (OSError, KeyError):
        return "Reviewer"


def _port(value: str) -> int:
    """argparse type: a TCP port, with a chatty error instead of a traceback."""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port must be a number, got '{value}'") from None
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"port must be between 1 and 65535, got {port}")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="md-review",
        description="Render markdown into commentable review pages; serve them LAN-only.",
    )
    parser.add_argument("--version", action="version", version=f"md-review {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    render_p = sub.add_parser("render", help="render markdown to a review page")
    render_p.add_argument("input", type=Path)
    render_p.add_argument("--title")
    render_p.add_argument("--data-dir", type=Path, help="store location (env: MD_REVIEW_DATA_DIR)")
    render_p.add_argument(
        "--server",
        help="POST to a running server instead of writing locally, e.g. http://192.168.1.10:8779 "
        "(env: MD_REVIEW_SERVER)",
    )
    render_p.add_argument("--agent", help="agent harness name (default: $AI_AGENT)")
    render_p.add_argument("--session-id", help="agent session id (default: harness env auto-detect)")
    render_p.add_argument(
        "--agent-cwd",
        help="working directory of the invoking agent (default: this process's cwd)",
    )
    render_p.add_argument(
        "--no-capture",
        action="store_true",
        help="don't copy the files this document links to (by default they are captured so "
        "reviewers can open them; credential-like files are never captured)",
    )

    serve_p = sub.add_parser("serve", help="serve rendered pages and the comments API")
    serve_p.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (default 127.0.0.1; use 0.0.0.0 to share with your LAN — "
        "non-LAN clients are ALWAYS refused regardless of bind)",
    )
    serve_p.add_argument("--port", type=_port, default=8779)
    serve_p.add_argument(
        "--mdns",
        action="store_true",
        default=os.environ.get("MD_REVIEW_MDNS", "").strip().lower() in ("1", "true", "yes"),
        help="advertise a friendly .local name via mDNS so LAN devices don't need the IP "
        "(env: MD_REVIEW_MDNS=1)",
    )
    serve_p.add_argument(
        "--mdns-name",
        default=os.environ.get("MD_REVIEW_MDNS_NAME", "md-review"),
        help="mDNS name to advertise (env: MD_REVIEW_MDNS_NAME; default: md-review → "
        "http://md-review.local:<port>/)",
    )
    serve_p.add_argument("--data-dir", type=Path, help="store location (env: MD_REVIEW_DATA_DIR)")
    serve_p.add_argument(
        "--ds-dir",
        type=Path,
        help="live design-system checkout to serve at /ds/ (env: MD_REVIEW_DS_DIR; "
        "default: the vendored snapshot bundled with the package)",
    )
    serve_p.add_argument(
        "--default-author",
        help="comment author when the page doesn't send one (env: MD_REVIEW_AUTHOR; default: OS user)",
    )
    serve_p.add_argument(
        "--theme",
        choices=THEMES,
        default=None,
        help="default UI theme for every served page: light, dusk (Dusk Slate), dark (Warm "
        "Chalkboard), or system (env: MD_REVIEW_THEME; default: system — follows each device's "
        "OS light/dark preference; viewers can override per device in the page)",
    )

    docs_p = sub.add_parser("docs", help="list documents in the store")
    docs_p.add_argument("--data-dir", type=Path, help="store location (env: MD_REVIEW_DATA_DIR)")
    docs_p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    return parser


def post_render(server_url: str, payload: dict) -> dict:
    url = server_url.rstrip("/") + "/api/render"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"ERROR: server refused the render ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"ERROR: cannot reach md-review server at {server_url}: {exc.reason}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SystemExit(f"ERROR: server at {server_url} returned a malformed response: {exc}") from exc
    if not isinstance(result, dict) or not isinstance(result.get("url"), str):
        raise SystemExit(f"ERROR: server at {server_url} returned an unexpected payload: {result!r:.200}")
    return result


UPLOAD_LIMIT_REASON = "over the upload size limit"


def links_payload(captures: store.Captures, base_payload: dict, *, limit: int) -> dict:
    """The /api/render ``links`` field, budgeted against the WHOLE serialized
    request body (JSON escaping can grow markdown well past its byte size).
    Largest captures are dropped first and recorded as unavailable — in
    ``captures`` itself, so the printed summary matches what was sent."""
    if captures.disabled:
        return {"disabled": True}

    def field() -> dict:
        encoded = {k: base64.b64encode(v).decode("ascii") for k, v in captures.files.items()}
        # The server describes at most MAX_TARGETS targets per doc; skips past
        # that stay in the local summary (the server marks them itself).
        room = max(0, links.MAX_TARGETS - len(encoded))
        return {"files": encoded, "reasons": dict(list(captures.reasons.items())[:room])}

    while True:
        candidate = field()
        if not captures.files or len(json.dumps({**base_payload, "links": candidate}).encode("utf-8")) <= limit:
            return candidate
        largest = max(captures.files, key=lambda target: len(captures.files[target]))
        del captures.files[largest]
        captures.reasons[largest] = UPLOAD_LIMIT_REASON


def capture_summary(captures: store.Captures) -> list[str]:
    """What the publisher is exposing: every captured path and every skip."""
    if captures.disabled:
        return ["[md-review] linked files: capture turned off (--no-capture)"]
    if not captures.files and not captures.reasons:
        return []
    total_kib = sum(len(data) for data in captures.files.values()) / 1024
    lines = [
        f"[md-review] linked files: {len(captures.files)} captured ({total_kib:.1f} KiB), "
        f"{len(captures.reasons)} not captured"
    ]
    lines += [f"  captured      {target}" for target in captures.files]
    lines += [f"  not captured  {target} — {reason}" for target, reason in captures.reasons.items()]
    return lines


def _print_summary(captures: store.Captures) -> None:
    # stderr: stdout stays exactly the page path/URL that scripts consume.
    for line in capture_summary(captures):
        print(line, file=sys.stderr)


def _read_markdown(input_path: Path) -> str:
    try:
        # utf-8-sig: a BOM is silently dropped rather than breaking a leading heading
        return input_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"ERROR: {input_path} is not valid UTF-8 ({exc}); convert it and retry") from exc
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot read {input_path}: {exc}") from exc


def cmd_render(args: argparse.Namespace) -> int:
    input_path: Path = args.input.expanduser()
    if input_path.suffix.lower() != ".md":
        raise SystemExit(f"ERROR: render input must be a .md file: {input_path}")
    if not input_path.is_file():
        raise SystemExit(f"ERROR: input not found: {input_path}")
    markdown = _read_markdown(input_path)
    if not markdown.strip():
        raise SystemExit(f"ERROR: refusing to render an empty document: {input_path}")

    provenance = collect_provenance(
        input_path, agent=args.agent, session_id=args.session_id, agent_cwd=args.agent_cwd
    )
    repo_root = Path(provenance["sourceRepoRoot"]) if provenance.get("sourceRepoRoot") else None
    source_path = store.display_path_for(input_path, repo_root)
    title = args.title or input_path.stem.replace("-", " ")
    if args.no_capture:
        captures = store.Captures(disabled=True)
    else:
        captures = store.capture_links(markdown, source_path, repo_root)

    server_url = args.server or os.environ.get("MD_REVIEW_SERVER", "").strip()
    if server_url:
        payload = {
            "markdown": markdown,
            "filename": input_path.name,
            "sourcePath": source_path,
            "title": title,
            "provenance": provenance,
        }
        payload["links"] = links_payload(captures, payload, limit=MAX_RENDER_BODY_BYTES)
        result = post_render(server_url, payload)
        _print_summary(captures)
        print(f"{server_url.rstrip('/')}{result['url']}")
        return 0

    data_dir = store.resolve_data_dir(args.data_dir)
    out = store.render_document(input_path, data_dir, args.title, provenance=provenance, captures=captures)
    _print_summary(captures)
    print(out)
    return 0


def cmd_docs(args: argparse.Namespace) -> int:
    data_dir = store.resolve_data_dir(args.data_dir)
    entries = store.list_documents(data_dir)
    if args.json:
        print(json.dumps(entries, indent=2, ensure_ascii=False))
        return 0
    if not entries:
        print(f"no documents in {data_dir}")
        return 0
    for entry in entries:
        prov = entry["provenance"]
        repo = prov.get("sourceRepoName") or "?"
        session = (prov.get("sessionId") or "")[:8]
        counts = (
            "comments unreadable"
            if entry["openComments"] is None
            else f"{entry['openComments']} open / {entry['totalComments']} total"
        )
        session_label = f" · session {session}" if session else ""
        print(f"{entry['docId']}\n  {entry['title']}\n  {repo} · {entry['sourcePath']}{session_label} · {counts}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows legacy consoles default to cp1252: an em-dash in a banner or a
    # doc title in a log line would otherwise kill the process with
    # UnicodeEncodeError. backslashreplace keeps every byte visible without
    # changing behavior on UTF-8 terminals (the common case elsewhere).
    for stream in (sys.stdout, sys.stderr):
        # TextIOWrapper has reconfigure; other stream types may not — and a
        # closed/redirected stream may reject the call. Both are fine to skip.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    if args.cmd == "render":
        return cmd_render(args)
    if args.cmd == "serve":
        data_dir = store.resolve_data_dir(args.data_dir)
        ds_dir = resolve_ds_dir(args.ds_dir)
        serve(
            args.host,
            args.port,
            data_dir=data_dir,
            ds_dir=ds_dir,
            default_author=args.default_author or _default_author(),
            mdns=args.mdns,
            mdns_name=args.mdns_name,
            theme=resolve_theme(args.theme),
        )
        return 0
    if args.cmd == "docs":
        return cmd_docs(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
