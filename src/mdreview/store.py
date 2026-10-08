"""Document store: rendered pages, manifests, and the comment channel.

Layout under the data directory::

    <data-dir>/rendered/<doc-id>/index.html     — the review page
    <data-dir>/rendered/<doc-id>/anchors.json   — every commentable element
    <data-dir>/rendered/<doc-id>/manifest.json  — source, title, times, provenance
    <data-dir>/rendered/<doc-id>/comments.json  — the persisted comment channel
    <data-dir>/rendered/<doc-id>/links.json     — relative-link targets (see links.py)
    <data-dir>/rendered/<doc-id>/files/<sha256> — linked files captured by the publisher

Comments are the contract: a JSON array per document, written atomically
(unique tmp file, fsync, rename), and the store fails loud — never silently
resets — when the file is corrupt or not an array. Agents read comments back
out of the same files; the server and the CLI are just two front-ends over
this layout.

Concurrency model: ONE module-level lock serializes every store mutation
(render + comment add/resolve). Renders take well under a second, so a
single lock is simpler and strictly safer than per-doc locks that would have
to compose (render also touches comments.json initialization). Cross-
PROCESS safety is best-effort: unique tmp names prevent temp-file
interleaving, but two servers pointed at one data dir can still lose
updates — one server per data dir is the supported deployment (documented
in the README).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import posixpath
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import links
from .provenance import collect_provenance, normalize_provenance
from .renderer import LinkRendering, MarkdownRenderer, page_html, short_hash, slugify

ENV_DATA_DIR = "MD_REVIEW_DATA_DIR"

# One lock for every store mutation; see the module docstring.
_store_lock = threading.Lock()

# A doc id is a slug plus a short content hash of the document's identity;
# only these characters ever appear, which is what makes the URL routes and
# the on-disk layout safe to join without a traversal escape.
DOC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Store-wide ceiling on captured linked-file bytes; past it a render still
# succeeds but its captures are dropped and marked unavailable.
STORE_ATTACHMENT_QUOTA = 2 * 1024 * 1024 * 1024
MAX_LINK_REASON_LENGTH = 200
NO_CAPTURE_REASON = "not captured by the publisher"
CAPTURE_OFF_REASON = "capture turned off by the publisher"
PER_DOC_REASON = f"over the per-document capture limit ({links.MAX_DOC_CAPTURE_BYTES // (1024 * 1024)} MiB)"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Characters left as-is when a link's #fragment is copied onto the rewritten href.
_FRAGMENT_SAFE = "-._~!$&'()*+,;=:@/?%"


@dataclass
class Captures:
    """What the publisher shipped for a doc's relative links: file bytes keyed
    by target identity, plus a reason for each target it could not capture.
    ``disabled`` means the publisher turned capture off (``--no-capture``)."""

    files: dict[str, bytes] = field(default_factory=dict)
    reasons: dict[str, str] = field(default_factory=dict)
    disabled: bool = False


def _relative_hrefs(markdown: str) -> list[str]:
    """Every relative href exactly as the renderer itself sees it, in order —
    collected through the renderer's own link path, never a second scanner."""
    seen: list[str] = []

    def collect(href: str, is_image: bool) -> None:
        seen.append(href)

    MarkdownRenderer(link_resolver=collect).render(markdown)
    return seen


def capture_links(markdown: str, source_display: str, repo_root: Path | None) -> Captures:
    """Publisher side: read the files ``markdown`` links to, under the capture
    policy in links.capture_file and the per-document budget. Runs only where
    the files live (a local render, or the CLI before a --server POST)."""
    in_repo = repo_root is not None
    boundary = repo_root.resolve() if repo_root is not None else Path(posixpath.dirname(source_display)).resolve()
    captures = Captures()
    seen: set[str] = set()
    total = 0
    for href in _relative_hrefs(markdown):
        split = links.split_relative_href(href)
        if split is None:
            continue
        try:
            identity = links.resolve_target(source_display, split[0], in_repo=in_repo)
        except links.Unavailable:
            continue  # the server derives the same reason from the markdown itself
        if identity in seen:
            continue
        seen.add(identity)
        if len(seen) > links.MAX_TARGETS:
            captures.reasons[identity] = "too many linked files"
            continue
        native = repo_root / identity if repo_root is not None else Path(identity)
        try:
            data = links.capture_file(native, boundary, identity)
        except links.Unavailable as exc:
            captures.reasons[identity] = str(exc)
            continue
        if total + len(data) > links.MAX_DOC_CAPTURE_BYTES:
            captures.reasons[identity] = PER_DOC_REASON
            continue
        total += len(data)
        captures.files[identity] = data
    return captures


def _attachment_bytes(data_dir: Path, exclude_doc_id: str) -> int:
    total = 0
    for files_dir in rendered_dir(data_dir).glob("*/files"):
        if files_dir.parent.name == exclude_doc_id:
            continue
        for blob in files_dir.iterdir():
            with contextlib.suppress(OSError):  # removed by a concurrent re-render
                total += blob.stat().st_size
    return total


class _LinkTable:
    """Server side: turns each relative link the renderer meets into a
    links.json entry and a /link href. Trusts nothing the client sent except
    file BYTES for identities this render itself found: kinds, MIME types and
    doc ids are all derived here."""

    def __init__(self, *, source_path: str, namespace: str, doc_id: str, captures: Captures | None, quota_room: int):
        self.source_path = source_path
        self.in_repo = links.is_repo_relative(source_path)
        self.namespace = namespace
        self.doc_id = doc_id
        self.captures = captures
        self.quota_room = quota_room
        self.captured_total = 0
        self.entries: dict[str, dict] = {}
        self.blobs: dict[str, bytes] = {}

    def resolve(self, href: str, is_image: bool) -> LinkRendering:
        split = links.split_relative_href(href)
        assert split is not None  # the renderer only consults us for relative hrefs
        path, fragment = split
        try:
            identity: str | None = links.resolve_target(self.source_path, path, in_repo=self.in_repo)
            unresolved = ""
            key = links.link_key(identity)
        except links.Unavailable as exc:
            identity, unresolved = None, str(exc)
            key = links.link_key("\x00unresolved\x00" + path)
        entry = self.entries.get(key)
        if entry is None:
            if len(self.entries) >= links.MAX_TARGETS:
                return LinkRendering(href="#", css_class="md-link-unavailable", title="too many linked files")
            entry = self._entry(identity, unresolved)
            self.entries[key] = entry
        url = f"/link/{self.doc_id}/{key}"
        if fragment:
            url += "#" + quote(fragment, safe=_FRAGMENT_SAFE)
        captured = "sha256" in entry
        available = entry["kind"] == "doc" or captured
        title = entry["target"] or path
        if not available:
            title = f"{title} — {entry['reason']}"
        return LinkRendering(
            href=url,
            css_class="md-link-local" if available else "md-link-unavailable",
            title=title,
            image=is_image and entry["kind"] == "image" and captured,
        )

    def _entry(self, identity: str | None, unresolved: str) -> dict:
        if identity is None:
            return {"target": None, "kind": "unavailable", "reason": unresolved}
        entry: dict = {"target": identity, "kind": links.kind_for(identity)}
        if entry["kind"] == "doc":
            entry["docId"] = doc_id_for(identity, self.namespace)
        captures = self.captures
        data = captures.files.get(identity) if captures is not None else None
        if data is not None:
            if len(data) > links.MAX_FILE_BYTES:
                reason = f"too large (over {links.MAX_FILE_BYTES // (1024 * 1024)} MiB)"
            elif self.captured_total + len(data) > links.MAX_DOC_CAPTURE_BYTES:
                reason = PER_DOC_REASON
            elif len(data) > self.quota_room:
                reason = "not captured (server storage limit reached)"
            else:
                sha = hashlib.sha256(data).hexdigest()
                self.blobs[sha] = data
                self.captured_total += len(data)
                self.quota_room -= len(data)
                entry.update(sha256=sha, size=len(data))
                return entry
        elif captures is None:
            reason = NO_CAPTURE_REASON
        elif captures.disabled:
            reason = CAPTURE_OFF_REASON
        else:
            reason = str(captures.reasons.get(identity) or NO_CAPTURE_REASON)
        entry["reason"] = reason[:MAX_LINK_REASON_LENGTH]
        return entry


def default_data_dir() -> Path:
    """Default store location: $XDG_DATA_HOME/md-review (~/.local/share/md-review)."""
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "md-review"


def resolve_data_dir(explicit: Path | None = None) -> Path:
    """Data dir precedence: --data-dir flag > $MD_REVIEW_DATA_DIR > XDG default."""
    if explicit is not None:
        return explicit.expanduser().resolve()
    env = os.environ.get(ENV_DATA_DIR, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return default_data_dir()


def ensure_data_dir(data_dir: Path) -> None:
    """Create the store root (and rendered/) with owner-only permissions.

    Review docs and comments can be confidential; a shared machine should not
    casually read them. chmod only what WE create — never tighten an existing
    directory the operator may have deliberately shared. POSIX only: chmod
    permission bits are a documented no-op on Windows (ACLs are the mechanism
    there, and stdlib has no ACL API).
    """
    rendered = data_dir / "rendered"
    for path in (data_dir, rendered):
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                os.chmod(path, 0o700)


def rendered_dir(data_dir: Path) -> Path:
    return data_dir / "rendered"


def display_path_for(input_path: Path, repo_root: Path | None) -> str:
    """Human-facing source path: repo-relative when in a repo, absolute otherwise.

    Always POSIX separators: on Windows ``str(Path)`` yields backslashes,
    which would leak into doc ids, URLs, and manifests and make the same
    repo file hash differently across OSes. Provenance keeps the native
    absolute form; the display path is the cross-OS identity surface.
    """
    resolved = input_path.resolve()
    if repo_root is not None:
        try:
            return resolved.relative_to(repo_root).as_posix()
        except ValueError:
            pass
    return resolved.as_posix()


def doc_id_for(display_path: str, namespace: str = "") -> str:
    """Stable document identity.

    ``namespace`` is the repository identity (credential-stripped remote URL
    preferred, absolute repo root as fallback) or "" for files outside a
    repo. It is mixed into the hash because the display path alone is only
    unique WITHIN one repo: two repos that both contain ``docs/design.md``
    used to collide into one doc id — the second render silently replaced
    the first's page while pooling its comments into the wrong document.
    The human-readable slug stays
    path-only; the hash carries the namespace. With namespace == "" the hash
    input is exactly the pre-namespace format, so ids of non-repo documents
    (and legacy migrated stores) are unchanged. The slug is clamped so even
    a near-limit sourcePath produces a filesystem-legal directory name.
    """
    stem = re.sub(r"\.md$", "", display_path, flags=re.IGNORECASE)
    stem = slugify(stem.replace("/", "-"), "doc")[:80]
    hash_input = f"{namespace}|{display_path}" if namespace else display_path
    return f"{stem}-{short_hash(hash_input, 10)}"


def doc_namespace(provenance: dict) -> str:
    """Repository identity used to namespace doc ids (see doc_id_for)."""
    return provenance.get("sourceRepoRemote") or provenance.get("sourceRepoRoot") or ""


def render_document(
    input_path: Path,
    data_dir: Path,
    title: str | None = None,
    *,
    provenance: dict | None = None,
    agent: str | None = None,
    session_id: str | None = None,
    agent_cwd: str | None = None,
    capture: bool = True,
    captures: Captures | None = None,
) -> Path:
    """Render ``input_path`` into the store and return the page path.

    ``provenance`` may be supplied by a caller that collected it on another
    machine (see the /api/render route); otherwise it is collected locally.
    ``capture`` copies the files the document links to (see capture_links);
    a caller that already captured (to report on it) passes ``captures``.
    """
    if input_path.suffix.lower() != ".md":
        raise ValueError(f"render input must be a .md file: {input_path}")
    if not input_path.is_file():
        raise FileNotFoundError(f"input not found: {input_path}")

    if provenance is None:
        provenance = collect_provenance(input_path, agent=agent, session_id=session_id, agent_cwd=agent_cwd)
    else:
        provenance = normalize_provenance(provenance)
    repo_root = Path(provenance["sourceRepoRoot"]) if provenance.get("sourceRepoRoot") else None
    source_path = display_path_for(input_path, repo_root)
    doc_id = doc_id_for(source_path, doc_namespace(provenance))
    # utf-8-sig: a BOM is silently dropped rather than breaking a leading
    # heading (the renderer has no BOM handling, by design)
    markdown = input_path.read_text(encoding="utf-8-sig")
    if captures is None:
        captures = capture_links(markdown, source_path, repo_root) if capture else Captures(disabled=True)
    return render_payload(
        markdown=markdown,
        source_path=source_path,
        doc_id=doc_id,
        title=title or input_path.stem.replace("-", " "),
        data_dir=data_dir,
        provenance=provenance,
        captures=captures,
    )


def _atomic_write(path: Path, content: str | bytes, *, private: bool = False) -> None:
    """Write via a uniquely-named sibling tmp file, fsync, then rename.

    Unique tmp names keep two WRITERS (threads or processes) from
    interleaving on the same temp path; fsync before and after the rename
    makes a returned success mean the bytes are actually on disk. The tmp
    carries the final mode across the rename, so privacy bits must be set on
    the TMP — otherwise the first write silently undoes the creation-time
    chmod.
    Text is encoded to UTF-8 and written in binary mode, which keeps store
    bytes identical across OSs (no CRLF translation on Windows).
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if private and os.name == "posix":  # chmod is a documented no-op on Windows
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass  # directory fsync is best-effort (Windows forbids opening dirs)
    finally:
        tmp.unlink(missing_ok=True)


def render_payload(
    *,
    markdown: str,
    source_path: str,
    doc_id: str,
    title: str,
    data_dir: Path,
    provenance: dict,
    captures: Captures | None = None,
) -> Path:
    """Render already-loaded markdown into the store. Shared by local renders
    and the /api/render route (where the markdown arrives over HTTP).

    ``captures`` are the publisher's linked-file bytes; None means an older
    publisher that captures nothing (doc links still resolve by id)."""
    provenance = normalize_provenance(provenance, keep=("receivedFrom", "receivedAt"))
    ensure_data_dir(data_dir)
    with _store_lock:
        out_dir = rendered_dir(data_dir) / doc_id
        out_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":  # chmod is a documented no-op on Windows
            os.chmod(out_dir, 0o700)
        comments_file = out_dir / "comments.json"
        # Exclusive create: a concurrent first comment must never be clobbered
        # by a render that checked existence before the comment landed.
        try:
            with comments_file.open("x", encoding="utf-8", newline="") as fh:
                fh.write("[]\n")
            if os.name == "posix":
                os.chmod(comments_file, 0o600)
        except FileExistsError:
            pass
        table = _LinkTable(
            source_path=source_path,
            namespace=doc_namespace(provenance),
            doc_id=doc_id,
            captures=captures,
            quota_room=max(0, STORE_ATTACHMENT_QUOTA - _attachment_bytes(data_dir, doc_id)),
        )
        renderer = MarkdownRenderer(link_resolver=table.resolve)
        body = renderer.render(markdown)
        # Blobs first (content-addressed, so a reader of the OLD links.json
        # still finds its files), then links.json, then the page; obsolete
        # blobs are removed only after nothing written here references them.
        files_dir = out_dir / "files"
        if table.blobs:
            files_dir.mkdir(exist_ok=True)
            if os.name == "posix":
                os.chmod(files_dir, 0o700)
            for sha, data in table.blobs.items():
                if not (files_dir / sha).exists():
                    _atomic_write(files_dir / sha, data)
        _atomic_write(out_dir / "links.json", json.dumps(table.entries, indent=2, ensure_ascii=False) + "\n")

        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        created_at = now_iso
        manifest_file = out_dir / "manifest.json"
        if manifest_file.exists():
            try:
                prior_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                if isinstance(prior_manifest, dict):
                    # createdAt survives re-renders: first render wins (index sorts by it)
                    created_at = prior_manifest.get("createdAt") or prior_manifest.get("renderedAt") or now_iso
            except (json.JSONDecodeError, OSError):
                pass  # unreadable prior manifest: treat this render as the doc's creation

        manifest = {
            "docId": doc_id,
            "title": title,
            "sourcePath": source_path,
            "createdAt": created_at,
            "renderedAt": now_iso,
            # Store-RELATIVE form only: manifest.json is served verbatim, and
            # an absolute commentsPath would leak the server's data-dir
            # layout (OS username, home path) to every client.
            "commentsPath": f"rendered/{doc_id}/comments.json",
            "anchorPolicy": "content-derived anchorId plus heading/kind/ordinal semanticKey fallback",
            "provenance": {
                **provenance,
                "createdAt": created_at,
                "renderedAt": now_iso,
            },
        }
        page = page_html(
            title,
            source_path,
            doc_id,
            body,
            [a.as_json() for a in renderer.anchors],
            renderer.toc,
            provenance=manifest["provenance"],
        )
        _atomic_write(out_dir / "index.html", page)
        _atomic_write(
            out_dir / "anchors.json",
            json.dumps([a.as_json() for a in renderer.anchors], indent=2, ensure_ascii=False) + "\n",
        )
        _atomic_write(manifest_file, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        if files_dir.is_dir():
            for blob in files_dir.iterdir():
                if SHA256_RE.match(blob.name) and blob.name not in table.blobs:
                    blob.unlink(missing_ok=True)
        return out_dir / "index.html"


def doc_dir_for_id(doc_id: str, data_dir: Path) -> Path:
    if not DOC_ID_RE.match(doc_id):
        raise ValueError("invalid doc id")
    base = rendered_dir(data_dir)
    path = (base / doc_id).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError("doc id escapes rendered dir") from exc
    if not path.is_dir():
        raise FileNotFoundError(f"unknown rendered doc: {doc_id}")
    return path


def _read_json_dict(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load_manifest(doc_id: str, data_dir: Path) -> dict | None:
    try:
        return _read_json_dict(doc_dir_for_id(doc_id, data_dir) / "manifest.json")
    except (ValueError, FileNotFoundError):
        return None


def load_link(doc_id: str, key: str, data_dir: Path) -> tuple[dict, bytes | None] | None:
    """A links.json entry and its captured bytes (None when nothing was captured).

    A re-render can delete a blob between this read of links.json and the
    open of the file. The new links.json is always written BEFORE obsolete
    blobs are removed, so re-reading the entry once is enough.
    """
    try:
        doc_dir = doc_dir_for_id(doc_id, data_dir)
    except (ValueError, FileNotFoundError):
        return None
    entry: object = None
    for _attempt in range(2):
        entry = (_read_json_dict(doc_dir / "links.json") or {}).get(key)
        if not isinstance(entry, dict):
            return None
        sha = entry.get("sha256")
        if not (isinstance(sha, str) and SHA256_RE.match(sha)):
            return entry, None
        try:
            return entry, (doc_dir / "files" / sha).read_bytes()
        except FileNotFoundError:
            continue
    return (entry, None) if isinstance(entry, dict) else None


def find_published_doc(entry: dict, source_doc_id: str, data_dir: Path) -> str | None:
    """The published review page a doc link should open, if any.

    First the computed id. If that misses, the target may have been rendered
    under a different namespace (e.g. before the repo had a remote): accept a
    doc with the same source path from the same repo (equal remote or equal
    root), but only when exactly one matches — never guess between two.
    """
    target_id = entry.get("docId")
    if (
        isinstance(target_id, str)
        and DOC_ID_RE.match(target_id)
        and (rendered_dir(data_dir) / target_id / "index.html").is_file()
    ):
        return target_id
    target = entry.get("target")
    source = load_manifest(source_doc_id, data_dir)
    source_prov = source.get("provenance") if source else None
    if not isinstance(target, str) or not isinstance(source_prov, dict):
        return None
    remote = source_prov.get("sourceRepoRemote") or ""
    root = source_prov.get("sourceRepoRoot") or ""
    if not (remote or root):
        return None
    matches = []
    for manifest_file in rendered_dir(data_dir).glob("*/manifest.json"):
        manifest = _read_json_dict(manifest_file)
        if not manifest or manifest.get("sourcePath") != target:
            continue
        prov = manifest.get("provenance")
        if not isinstance(prov, dict):
            continue
        if (remote and prov.get("sourceRepoRemote") == remote) or (root and prov.get("sourceRepoRoot") == root):
            matches.append(manifest_file.parent.name)
    return matches[0] if len(matches) == 1 else None


def comments_path(doc_id: str, data_dir: Path) -> Path:
    path = doc_dir_for_id(doc_id, data_dir) / "comments.json"
    if not path.exists():
        try:
            with path.open("x", encoding="utf-8", newline="") as fh:
                fh.write("[]\n")
            if os.name == "posix":
                os.chmod(path, 0o600)
        except FileExistsError:
            pass  # created concurrently between the check and the open — fine
    return path


def load_comments(doc_id: str, data_dir: Path) -> list[dict]:
    path = comments_path(doc_id, data_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"comments store at {path} is unreadable ({exc}); fix it manually") from exc
    except (UnicodeDecodeError, OSError) as exc:
        raise RuntimeError(f"comments store at {path} could not be read ({exc}); fix it manually") from exc
    if not isinstance(data, list):
        raise RuntimeError(f"comments store at {path} must be a JSON array")
    return data


def save_comments(doc_id: str, comments: list[dict], data_dir: Path) -> None:
    _atomic_write(comments_path(doc_id, data_dir), json.dumps(comments, indent=2, ensure_ascii=False) + "\n", private=True)


MAX_COMMENTS_PER_DOC = 5_000


def add_comment(doc_id: str, comment: dict, data_dir: Path) -> dict:
    """Append a comment under the store lock; returns the stored record."""
    with _store_lock:
        comments = load_comments(doc_id, data_dir)
        if len(comments) >= MAX_COMMENTS_PER_DOC:
            raise ValueError(f"document already has {MAX_COMMENTS_PER_DOC} comments; resolve or prune some first")
        comments.append(comment)
        save_comments(doc_id, comments, data_dir)
    return comment


def set_comment_resolved(doc_id: str, comment_id: str, resolved: bool, data_dir: Path) -> dict:
    with _store_lock:
        comments = load_comments(doc_id, data_dir)
        for comment in comments:
            if comment.get("id") == comment_id:
                comment["resolved"] = resolved
                save_comments(doc_id, comments, data_dir)
                return comment
    raise LookupError(f"no comment with id '{comment_id}'")


# Server-enforced size caps. `text` is the payload a reviewer actually types;
# the rest are metadata that must not become a disk-flood vector (the 16 MiB
# body cap alone would let a LAN client store multi-megabyte authors/quotes
# per comment).
MAX_COMMENT_TEXT_LENGTH = 100_000
MAX_AUTHOR_LENGTH = 200
MAX_QUOTE_LENGTH = 4_096
MAX_LABEL_LENGTH = 500
MAX_DOC_PATH_LENGTH = 1_024


# Anchor keys the page legitimately sends (see anchorFromElement in
# renderer.py). The anchor is stored verbatim in comments.json, so it is
# WHITELISTED, not passed through: unknown keys and unbounded values would
# walk straight past the size caps below.
ANCHOR_FIELDS = ("type", "docId", "docPath", "anchorId", "semanticKey", "elementKind", "headingPath", "label", "contentHash", "quote")
MAX_ANCHOR_FIELD_LENGTH = 512
MAX_HEADING_PATH_ITEMS = 32


def validate_comment_body(body: object) -> tuple[str, dict, str, str]:
    if not isinstance(body, dict):
        raise ValueError("request body must be an object")
    doc_id = body.get("docId")
    if not isinstance(doc_id, str) or not doc_id:
        raise ValueError("comment requires docId")
    raw_anchor = body.get("anchor")
    if not isinstance(raw_anchor, dict):
        raise ValueError("comment requires anchor object")
    for key in ["anchorId", "semanticKey", "elementKind", "label"]:
        if not isinstance(raw_anchor.get(key), str) or not raw_anchor[key]:
            raise ValueError(f"anchor requires non-empty {key}")
    if raw_anchor.get("type") != "md-element":
        raise ValueError("anchor.type must be md-element")
    # The page computes anchor.docId itself; a client-supplied value that
    # disagrees with the top-level docId would let one comment pollute two
    # matching scopes. Reject mismatches, then normalize — one source of truth.
    anchor_doc_id = raw_anchor.get("docId")
    if anchor_doc_id is not None and anchor_doc_id != doc_id:
        raise ValueError("anchor.docId does not match comment docId")
    anchor: dict = {}
    for key in ANCHOR_FIELDS:
        if key in raw_anchor:
            value = raw_anchor[key]
            if isinstance(value, str) and len(value) > MAX_ANCHOR_FIELD_LENGTH and key != "quote":
                value = value[:MAX_ANCHOR_FIELD_LENGTH]
            anchor[key] = value
    anchor["docId"] = doc_id
    anchor["label"] = anchor["label"][:MAX_LABEL_LENGTH]
    heading_path = anchor.get("headingPath")
    anchor["headingPath"] = [str(h)[:MAX_LABEL_LENGTH] for h in heading_path[:MAX_HEADING_PATH_ITEMS]] if isinstance(heading_path, list) else []
    anchor["quote"] = str(anchor.get("quote") or "")[:MAX_QUOTE_LENGTH]
    text = body.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("comment requires non-empty text")
    if len(text) > MAX_COMMENT_TEXT_LENGTH:
        raise ValueError(f"comment text exceeds {MAX_COMMENT_TEXT_LENGTH} characters")
    quote = body.get("quote") or anchor.get("quote") or ""
    if not isinstance(quote, str):
        quote = str(quote)
    return doc_id, anchor, text.strip(), quote.strip()[:MAX_QUOTE_LENGTH]


def validate_author(value: object) -> str | None:
    """A usable author string (capped) or None → the server default applies."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:MAX_AUTHOR_LENGTH] if value else None


def validate_doc_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip()[:MAX_DOC_PATH_LENGTH] or None


def list_documents(data_dir: Path) -> list[dict]:
    """All manifests in the store, newest first, with comment stats attached.

    Tolerates the messiness of a real store: non-dict/corrupt manifests are
    skipped, missing/corrupt comment files report ``None`` counts rather than
    failing the whole listing, and every surfaced field is coerced to a plain
    string so a hostile or damaged manifest cannot crash the index.
    """

    def _text(value: object) -> str:
        return value if isinstance(value, str) else ""

    entries: list[dict] = []
    base = rendered_dir(data_dir)
    for manifest_path in sorted(base.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
        if not isinstance(manifest, dict):
            continue
        doc_id = manifest_path.parent.name
        open_count: int | None = None
        total_count: int | None = None
        comments_file = manifest_path.parent / "comments.json"
        if comments_file.exists():
            try:
                stored = json.loads(comments_file.read_text(encoding="utf-8"))
                if isinstance(stored, list):
                    total_count = len(stored)
                    open_count = sum(1 for c in stored if isinstance(c, dict) and not c.get("resolved"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                pass
        provenance = normalize_provenance(manifest.get("provenance"))
        # Receipt fields the server stamps on remote renders are display-only;
        # coerce them through the same string-only rule.
        raw_prov = manifest.get("provenance")
        for extra in ("receivedFrom", "receivedAt", "createdAt", "renderedAt"):
            provenance[extra] = _text(raw_prov.get(extra)) if isinstance(raw_prov, dict) else ""
        entries.append(
            {
                "docId": doc_id,
                "title": _text(manifest.get("title")) or doc_id,
                "sourcePath": _text(manifest.get("sourcePath")),
                "createdAt": _text(manifest.get("createdAt")) or _text(manifest.get("renderedAt")),
                "renderedAt": _text(manifest.get("renderedAt")),
                "provenance": provenance,
                "openComments": open_count,
                "totalComments": total_count,
            }
        )
    # newest first; ISO-8601 UTC strings order lexically, undated docs sink to the bottom
    entries.sort(key=lambda entry: entry["createdAt"], reverse=True)
    return entries
