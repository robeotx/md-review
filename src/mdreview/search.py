"""Search over everything the server serves: docs, standalone pages, captured text, comments.

The index lives in process memory and is derived from the store on disk, so
it creates no files and cannot be left half-written. Design and the review
trail: ``.requests/261008-ui-search-design.md``.

Freshness: each doc dir carries a stat signature (inode, mtime, size of the
four files that feed an entry). A sync re-reads only dirs whose signature
moved. Signatures are taken BEFORE reading, so a file replaced mid-read is
caught by the next sync. Readers use a snapshot reference and never block
on a sync.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote

from mdreview import links, store

MAX_ITEM_CHARS = 2_000_000
MAX_QUERY_CHARS = 256
MAX_TERMS = 8
MAX_TERM_CHARS = 64
MAX_REPO_FILTERS = 50
MAX_OFFSET = 10_000
MAX_LIMIT = 200
DEFAULT_LIMIT = 50
MAX_MATCHES_PER_GROUP = 20
SYNC_INTERVAL_S = 2.0
PUBLISH_EVERY = 25
SNIPPET_RADIUS = 60
MIN_LITERAL_CHARS = 3
SORT_FIELDS = ("modified", "created")
STANDALONE_KEY = "standalone"
UNKNOWN_KEY = ""
SIGNATURE_FILES = ("index.html", "manifest.json", "comments.json", "links.json")

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_LINK_KEY_RE = re.compile(r"[0-9a-f]{16}")  # the /link route serves only keys of this shape
_STRING_LITERAL_RE = re.compile(rf'"(?:[^"\\\n]|\\.){{{MIN_LITERAL_CHARS},}}"')
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_UTC = timezone.utc


class QueryError(ValueError):
    """A search request the server refuses. The message says how to fix it."""


def parse_query(text: str) -> list[str]:
    if "\x00" in text:
        raise QueryError("search text may not contain NUL bytes; remove them and retry")
    if len(text) > MAX_QUERY_CHARS:
        raise QueryError(f"search text is limited to {MAX_QUERY_CHARS} characters; shorten it")
    terms = [term.casefold() for term in text.split()]
    if len(terms) > MAX_TERMS:
        raise QueryError(f"search takes at most {MAX_TERMS} terms; remove some")
    for term in terms:
        if len(term) > MAX_TERM_CHARS:
            raise QueryError(f"each search term is limited to {MAX_TERM_CHARS} characters")
    return terms


def parse_date(text: str | None) -> date | None:
    if not text:
        return None
    if _DATE_RE.fullmatch(text):
        try:
            return date.fromisoformat(text)
        except ValueError:
            pass
    raise QueryError(f"date {text!r} must be YYYY-MM-DD (UTC day)")


def _cap(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


class _DocRootText(HTMLParser):
    """Text under the first ``data-doc-root`` element, ignoring everything else."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._open: list[str] = []
        self._root_depth: int | None = None
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _VOID_TAGS:
            return
        self._open.append(tag)
        if self._root_depth is None and any(name == "data-doc-root" for name, _ in attrs):
            self._root_depth = len(self._open)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS or tag not in self._open:
            return
        while self._open:
            closed = self._open.pop()
            if self._root_depth is not None and len(self._open) < self._root_depth:
                self._root_depth = None
            if closed == tag:
                break

    def handle_data(self, data: str) -> None:
        if self._root_depth is not None:
            self.chunks.append(data)


class _PageText(HTMLParser):
    """Title, visible text, and the string literals inside script bodies.

    Standalone pages keep their data in scripts (``const DATA = {...}``), so
    quoted literals are indexed. Code itself is not.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self._in_script = False
        self._suppressed = 0
        self._script_chunks: list[str] = []
        self.title = ""
        self.visible: list[str] = []
        self.literals: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            self._in_script = True
            self._script_chunks = []
        elif tag in ("style", "template"):
            self._suppressed += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.literals.extend(_string_literals("".join(self._script_chunks)))
        elif tag in ("style", "template") and self._suppressed:
            self._suppressed -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif self._in_script:
            self._script_chunks.append(data)
        elif not self._suppressed:
            self.visible.append(data)


def _string_literals(code: str) -> list[str]:
    found: dict[str, None] = {}
    for match in _STRING_LITERAL_RE.finditer(code):
        raw = match.group(0)
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw[1:-1]
        if isinstance(value, str) and len(value) >= MIN_LITERAL_CHARS:
            found.setdefault(value, None)
    return list(found)


def extract_doc_text(data: bytes, max_chars: int = MAX_ITEM_CHARS) -> tuple[str, bool]:
    parser = _DocRootText()
    parser.feed(data.decode("utf-8", errors="replace"))
    parser.close()
    return _cap("".join(parser.chunks), max_chars)


def extract_page(data: bytes, max_chars: int = MAX_ITEM_CHARS) -> tuple[str, str, bool]:
    parser = _PageText()
    parser.feed(data.decode("utf-8", errors="replace"))
    parser.close()
    body = "\n".join(parser.visible) + "\n" + "\n".join(parser.literals)
    text, truncated = _cap(body, max_chars)
    return parser.title.strip(), text, truncated


def _last_segment(path: str) -> str:
    return re.split(r"[\\/]+", path.rstrip("\\/"))[-1]


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def repo_key(provenance: dict) -> tuple[str, str]:
    """(key, name) for the repo a doc came from. The key is opaque; never resolve it."""
    root = _text(provenance.get("sourceRepoRoot"))
    if root:
        return root, _text(provenance.get("sourceRepoName")) or _last_segment(root)
    cwd = _text(provenance.get("agentCwd"))
    if cwd:
        return cwd, _last_segment(cwd)
    return UNKNOWN_KEY, ""


def repo_labels(names_by_key: dict[str, str]) -> dict[str, str]:
    """Display labels; a name shared by several keys gets its parent segment added."""
    labels: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    for key, name in names_by_key.items():
        if key == STANDALONE_KEY:
            labels[key] = "Standalone pages"
        elif key == UNKNOWN_KEY:
            labels[key] = "Unknown"
        else:
            by_name.setdefault(name or _last_segment(key), []).append(key)
    for name, keys in by_name.items():
        if len(keys) == 1:
            labels[keys[0]] = name
            continue
        for key in keys:
            segments = [seg for seg in re.split(r"[\\/]+", key) if seg]
            parent = segments[-2] if len(segments) >= 2 else key
            labels[key] = f"{name} ({parent})"
    return labels


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_UTC)
    return moment.astimezone(_UTC)


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _signature(doc_dir: Path) -> tuple:
    parts: list[tuple | None] = []
    for name in SIGNATURE_FILES:
        try:
            st = os.lstat(doc_dir / name)
        except OSError:
            # Missing, or unreadable (a dir the publisher locked): either way there is no usable signature.
            parts.append(None)
            continue
        parts.append((st.st_ino, st.st_mtime_ns, st.st_size) if stat.S_ISREG(st.st_mode) else None)
    return tuple(parts)


@dataclass(frozen=True)
class Item:
    kind: str
    ext: str
    title: str
    path: str
    text: str
    title_f: str
    path_f: str
    text_f: str
    url: str
    truncated: bool


@dataclass(frozen=True)
class DocRecord:
    doc_id: str
    kind: str
    title: str
    source_path: str
    repo_key: str
    repo_name: str
    branch: str
    session_id: str
    agent: str
    created: datetime | None
    modified: datetime | None
    open_comments: int | None
    total_comments: int | None
    doc_item: Item
    children: tuple[Item, ...]
    signature: tuple

    @property
    def truncated_items(self) -> int:
        return int(self.doc_item.truncated) + sum(1 for child in self.children if child.truncated)


def _make_item(kind: str, ext: str, title: str, path: str, text: str, url: str, truncated: bool) -> Item:
    """An Item with its folded copies. Matching uses the folds; snippets use the original text."""
    return Item(kind, ext, title, path, text, title.casefold(), path.casefold(), text.casefold(), url, truncated)


def _file_items(doc_dir: Path, doc_id: str) -> list[Item]:
    raw = _read_json(doc_dir / "links.json")
    if not isinstance(raw, dict):
        return []
    items: list[Item] = []
    for key, entry in raw.items():
        if not isinstance(key, str) or not _LINK_KEY_RE.fullmatch(key):
            continue
        if not isinstance(entry, dict) or entry.get("kind") == "doc":
            continue
        target = _text(entry.get("target"))
        if not target:
            continue
        text, truncated = _captured_text(doc_dir, entry)
        url = f"/link/{quote(doc_id, safe='')}/{quote(key, safe='')}"
        ext = posixpath.splitext(target.replace("\\", "/"))[1].lower().lstrip(".")
        items.append(_make_item("file", ext, _last_segment(target), target, text, url, truncated))
    return items


def _captured_text(doc_dir: Path, entry: dict) -> tuple[str, bool]:
    sha = _text(entry.get("sha256"))
    if entry.get("kind") == "image" or not _SHA256_RE.fullmatch(sha):
        return "", False
    blob = doc_dir / "files" / sha
    try:
        if os.lstat(blob).st_size > links.MAX_FILE_BYTES:
            return "", False
        data = blob.read_bytes()
    except OSError:
        return "", False
    if b"\x00" in data:
        return "", False
    try:
        return _cap(data.decode("utf-8"), MAX_ITEM_CHARS)
    except UnicodeDecodeError:
        return "", False


def _comment_items(doc_id: str, comments: list) -> list[Item]:
    url = f"/rendered/{doc_id}/index.html"
    items: list[Item] = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        author = _text(comment.get("author"))
        body = "\n".join(part for part in (_text(comment.get("text")), author, _text(comment.get("quote"))) if part)
        text, truncated = _cap(body, MAX_ITEM_CHARS)
        title = f"comment by {author}" if author else "comment"
        items.append(_make_item("comment", "comment", title, "", text, url, truncated))
    return items


def _build_record(doc_dir: Path, doc_id: str, signature: tuple) -> DocRecord | None:
    """One doc dir as an index record, or None when it is not indexable.

    A manifest that exists but is corrupt skips the doc (same rule as
    ``store.list_documents``) and says so on stderr. A dir with only
    ``index.html`` is a standalone page. A dir with neither is skipped quietly.
    """
    manifest_path = doc_dir / "manifest.json"
    index_path = doc_dir / "index.html"
    comments_path = doc_dir / "comments.json"
    # Absent means no comments; present-but-unreadable is None ("comments unreadable").
    comments_raw = _read_json(comments_path) if comments_path.exists() else []
    comments = comments_raw if isinstance(comments_raw, list) else []
    open_count = (
        sum(1 for c in comments if isinstance(c, dict) and not c.get("resolved"))
        if isinstance(comments_raw, list)
        else None
    )
    total_count = len(comments) if isinstance(comments_raw, list) else None

    if manifest_path.exists():
        manifest = _read_json(manifest_path)
        if not isinstance(manifest, dict):
            sys.stderr.write(f"[md-review] search: skipped {doc_id}: manifest.json is unreadable\n")
            return None
        raw_provenance = manifest.get("provenance")
        provenance: dict = raw_provenance if isinstance(raw_provenance, dict) else {}
        key, name = repo_key(provenance)
        rendered = _text(manifest.get("renderedAt"))
        source_path = _text(manifest.get("sourcePath"))
        title = _text(manifest.get("title")) or doc_id
        body = _read_body(index_path, extract_doc_text)
        text, truncated = body
        doc_item = _make_item("doc", "md", title, source_path, text, f"/rendered/{doc_id}/index.html", truncated)
        return DocRecord(
            doc_id=doc_id,
            kind="doc",
            title=title,
            source_path=source_path,
            repo_key=key,
            repo_name=name,
            branch=_text(provenance.get("sourceRepoBranch")),
            session_id=_text(provenance.get("sessionId")),
            agent=_text(provenance.get("agent")),
            created=_parse_ts(_text(manifest.get("createdAt")) or rendered),
            modified=_parse_ts(rendered),
            open_comments=open_count,
            total_comments=total_count,
            doc_item=doc_item,
            children=tuple(_comment_items(doc_id, comments) + _file_items(doc_dir, doc_id)),
            signature=signature,
        )

    if not index_path.is_file():
        return None
    page_title, text, truncated = _read_page(index_path)
    title = page_title or doc_id
    try:
        modified = datetime.fromtimestamp(os.stat(index_path).st_mtime, tz=_UTC)
    except OSError:
        modified = None
    doc_item = _make_item("page", "html", title, "", text, f"/rendered/{doc_id}/index.html", truncated)
    return DocRecord(
        doc_id=doc_id,
        kind="page",
        title=title,
        source_path="",
        repo_key=STANDALONE_KEY,
        repo_name="Standalone pages",
        branch="",
        session_id="",
        agent="",
        created=None,
        modified=modified,
        open_comments=open_count,
        total_comments=total_count,
        doc_item=doc_item,
        children=tuple(_comment_items(doc_id, comments) + _file_items(doc_dir, doc_id)),
        signature=signature,
    )


def _read_body(path: Path, extractor: Callable[[bytes], tuple[str, bool]]) -> tuple[str, bool]:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return "", False
    except OSError as exc:
        sys.stderr.write(f"[md-review] search: unreadable {path}: {exc}\n")
        return "", False
    return extractor(data)


def _read_page(path: Path) -> tuple[str, str, bool]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"[md-review] search: unreadable {path}: {exc}\n")
        return "", "", False
    return extract_page(data)


def _doc_dir_names(base: Path) -> list[str]:
    if not base.is_dir():
        return []
    names: list[str] = []
    with os.scandir(base) as entries:
        for entry in entries:
            if not store.DOC_ID_RE.match(entry.name):
                continue
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
            names.append(entry.name)
    return sorted(names)


def _matches(item: Item, terms: list[str]) -> bool:
    # Terms hold no whitespace, so a term cannot straddle the parts: "each term appears in some part"
    # is the same test as "each term appears in title + path + text".
    parts = (item.title_f, item.path_f, item.text_f)
    return all(any(term in part for part in parts) for term in terms)


def _window(text: str, start: int, end: int) -> str:
    left = max(0, start - SNIPPET_RADIUS)
    right = min(len(text), end + SNIPPET_RADIUS)
    body = " ".join(text[left:right].split())
    return ("…" if left > 0 else "") + body + ("…" if right < len(text) else "")


def _snippet(item: Item, terms: list[str]) -> str | None:
    """Context around the first term found in the item's body, or None when the body has no match.

    Terms are located in the folded text. When folding kept the text's length, the same offset is
    valid in the original, so the window shows the original spelling. When it did not ("ß" folds to
    "ss"), the match is real but has no exact original position: the window then shows the start.
    """
    for term in terms:
        position = item.text_f.find(term)
        if position < 0:
            continue
        if len(item.text_f) != len(item.text):
            return _window(item.text, 0, 0)
        return _window(item.text, position, position + len(term))
    return None


def _sort_date(record: DocRecord, sort: str) -> datetime | None:
    return record.created if sort == "created" else record.modified


def _in_date_range(record: DocRecord, sort: str, date_from: date | None, date_to: date | None) -> bool:
    if date_from is None and date_to is None:
        return True
    moment = _sort_date(record, sort)
    if moment is None:
        return False
    day = moment.date()
    return (date_from is None or day >= date_from) and (date_to is None or day <= date_to)


def _doc_payload(record: DocRecord, labels: dict[str, str], snippet: str | None) -> dict:
    return {
        "docId": record.doc_id,
        "kind": record.kind,
        "ext": record.doc_item.ext,
        "title": record.title,
        "sourcePath": record.source_path,
        "repo": {"key": record.repo_key, "label": labels[record.repo_key]},
        "created": record.created.isoformat() if record.created else None,
        "modified": record.modified.isoformat() if record.modified else None,
        "url": record.doc_item.url,
        "openComments": record.open_comments,
        "totalComments": record.total_comments,
        "branch": record.branch,
        "sessionId": record.session_id,
        "agent": record.agent,
        "truncated": record.doc_item.truncated,
        "snippet": snippet,
    }


def _item_payload(item: Item, snippet: str | None) -> dict:
    return {
        "kind": item.kind,
        "ext": item.ext,
        "title": item.title,
        "path": item.path,
        "url": item.url,
        "truncated": item.truncated,
        "snippet": snippet,
    }


class SearchIndex:
    """In-memory index over one data dir. Thread-safe: one writer at a time, readers lock-free."""

    def __init__(self, data_dir: Path, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._data_dir = data_dir
        self._clock = clock
        self._docs: dict[str, DocRecord] = {}
        self._skipped: dict[str, tuple] = {}
        self._sync_lock = threading.Lock()
        self._last_sync: float | None = None
        self._progress: tuple[int, int] = (0, 0)

    def sync(self) -> None:
        """Reconcile with the store now. Blocks if another sync is running."""
        with self._sync_lock:
            self._sync_locked()

    def maybe_sync(self) -> None:
        """Sync if due (throttled). Returns at once when a sync is already running."""
        last = self._last_sync
        if last is not None and self._clock() - last < SYNC_INTERVAL_S:
            return
        if not self._sync_lock.acquire(blocking=False):
            return
        try:
            self._sync_locked()
        finally:
            self._sync_lock.release()

    def _sync_locked(self) -> None:
        base = store.rendered_dir(self._data_dir)
        try:
            names = _doc_dir_names(base)
        except OSError as exc:
            sys.stderr.write(f"[md-review] search: cannot list {base}: {exc}; keeping the last index\n")
            self._last_sync = self._clock()
            return
        total = len(names)
        updated = dict(self._docs)
        skipped: dict[str, tuple] = {}
        changed_since_publish = 0
        for done, name in enumerate(names, start=1):
            doc_dir = base / name
            signature = _signature(doc_dir)
            known = updated.get(name)
            if known is None and self._skipped.get(name) == signature:
                skipped[name] = signature
            elif known is None or known.signature != signature:
                try:
                    record = _build_record(doc_dir, name, signature)
                except OSError as exc:
                    # One bad dir must not wedge the index. The signature is cached below, so this is logged once per change.
                    sys.stderr.write(f"[md-review] search: skipped {name}: {exc}\n")
                    record = None
                if record is None:
                    updated.pop(name, None)
                    skipped[name] = signature
                else:
                    updated[name] = record
                changed_since_publish += 1
                if changed_since_publish >= PUBLISH_EVERY:
                    self._docs = dict(updated)
                    changed_since_publish = 0
            self._progress = (done, total)
        for gone in set(updated) - set(names):
            del updated[gone]
        self._docs = updated
        self._skipped = skipped
        self._progress = (total, total)
        self._last_sync = self._clock()

    def search(
        self,
        *,
        terms: Iterable[str] = (),
        repos: Iterable[str] | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
        sort: str = "modified",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict:
        if sort not in SORT_FIELDS:
            raise QueryError(f"sort must be one of: {', '.join(SORT_FIELDS)}")
        if not 1 <= limit <= MAX_LIMIT:
            raise QueryError(f"limit must be between 1 and {MAX_LIMIT}")
        if not 0 <= offset <= MAX_OFFSET:
            raise QueryError(f"offset must be between 0 and {MAX_OFFSET}")
        term_list = [term.casefold() for term in terms]
        selected = set(repos) if repos is not None else None
        snapshot = self._docs
        progress = self._progress  # one read: a concurrent sync replaces the whole tuple
        names = {record.repo_key: record.repo_name for record in snapshot.values()}
        for key in selected or ():
            names.setdefault(key, "")
        labels = repo_labels(names)

        facet_counts: dict[str, int] = {}
        truncated_items = 0
        hits: list[tuple[DocRecord, bool, list[Item]]] = []
        for record in snapshot.values():
            truncated_items += record.truncated_items
            if not _in_date_range(record, sort, date_from, date_to):
                continue
            if term_list:
                doc_hit = _matches(record.doc_item, term_list)
                children = [child for child in record.children if _matches(child, term_list)]
                if not doc_hit and not children:
                    continue
            else:
                doc_hit, children = True, []
            facet_counts[record.repo_key] = facet_counts.get(record.repo_key, 0) + 1
            if selected is not None and record.repo_key not in selected:
                continue
            hits.append((record, doc_hit, children))

        for key in selected or ():
            facet_counts.setdefault(key, 0)

        hits.sort(key=lambda hit: (hit[0].title.casefold(), hit[0].doc_id))
        hits.sort(key=lambda hit: _date_sort_key(_sort_date(hit[0], sort)), reverse=True)

        groups = []
        for record, doc_hit, children in hits[offset : offset + limit]:
            doc_snippet = _snippet(record.doc_item, term_list) if doc_hit and term_list else None
            matches = [
                _item_payload(child, _snippet(child, term_list)) for child in children[:MAX_MATCHES_PER_GROUP]
            ]
            group = {"doc": _doc_payload(record, labels, doc_snippet), "matches": matches, "matchCount": len(children)}
            groups.append(group)

        facets = sorted(facet_counts.items(), key=lambda kv: (-kv[1], labels[kv[0]].casefold()))
        return {
            "total": len(hits),
            "offset": offset,
            "limit": limit,
            "groups": groups,
            "facets": {
                "repos": [{"key": key, "label": labels[key], "count": count} for key, count in facets],
            },
            "indexing": {"done": progress[0], "total": progress[1]},
            "truncatedItems": truncated_items,
        }


def _date_sort_key(moment: datetime | None) -> tuple[int, datetime]:
    # Unknown dates rank below every known one, so reverse=True puts them last.
    if moment is None:
        return (0, datetime.min.replace(tzinfo=_UTC))
    return (1, moment)
