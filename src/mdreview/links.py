"""Relative links: target resolution, identity keys, and publish-time capture.

A rendered page lives at ``/rendered/<docId>/``, so a link written relative to
the source file (``reports/a.md``) has to be resolved against the SOURCE
path, not the page URL. Two halves:

- Resolution (pure string work, used by the server's render): the target's
  identity is its display path — repo-relative inside a repo, absolute POSIX
  outside one — exactly the form ``store.doc_id_for`` hashes, so a ``.md``
  target's doc id is computable without a lookup.
- Capture (filesystem work, ONLY on the publisher's machine): the publisher
  reads the linked files and ships their bytes with the render. The server
  never opens an identity path — provenance is client-asserted, so a
  server-side read would be arbitrary file read for any LAN client.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import stat
from pathlib import Path
from urllib.parse import unquote

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_DOC_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_TARGETS = 500

IMAGE_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}
DOC_SUFFIXES = (".md", ".markdown")

# Never captured, even inside the boundary. Matched case-insensitively against
# every path component (lexical AND symlink-resolved), because a link is weak
# evidence that the publisher meant to expose a credential.
_DENIED_DIRS = {".git", ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".azure", ".gcloud"}
_DENIED_DIR_PAIRS = {(".config", "gcloud"), (".config", "gh")}
_DENIED_NAME_RE = re.compile(
    r"^(?:\.env(?:\..*)?|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.htpasswd"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)(?:\..*)?|credentials.*|secrets?(?:\..*)?"
    r"|.*\.(?:pem|key|p12|pfx|kdbx|jks|keystore|tfstate))$"
)
_SECRET_CONTENT_RE = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    rb"|\bgh[pousr]_[A-Za-z0-9]{36}"
    rb"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    rb"|\bAKIA[0-9A-Z]{16}\b"
    rb"|\bsk-[A-Za-z0-9_-]{20,}"
    rb"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    rb"|\bhf_[A-Za-z0-9]{30,}"
)


class Unavailable(Exception):
    """A link target that cannot be shown; the message is the reader-facing reason."""


def split_relative_href(href: str) -> tuple[str, str] | None:
    """``(decoded path, fragment)`` for a relative file link, else None.

    Fragments, absolute paths, protocol-relative and scheme URLs are not
    relative file links and keep their existing rendering.
    """
    href = href.strip()
    if not href or href.startswith(("#", "/")):
        return None
    if ":" in href.split("/", 1)[0].split("#", 1)[0].split("?", 1)[0]:
        return None  # a scheme (or something the scheme allowlist must judge)
    path, _, fragment = href.partition("#")
    path = path.partition("?")[0]
    path = unquote(path)
    if not path:
        return None
    return path, fragment


def resolve_target(source_display_path: str, link_path: str, *, in_repo: bool) -> str:
    """Identity (display path) of ``link_path`` written inside ``source_display_path``."""
    if any(ch in link_path for ch in ("\x00", "\\", ":")):
        raise Unavailable("unsupported characters in the link path")
    base = posixpath.dirname(source_display_path)
    joined = posixpath.normpath(posixpath.join(base, link_path)) if base else posixpath.normpath(link_path)
    if in_repo:
        if joined == ".." or joined.startswith(("../", "/")):
            raise Unavailable("outside the repository")
        return joined
    if not joined.startswith(base.rstrip("/") + "/"):
        raise Unavailable("outside the document's folder")
    return joined


def is_repo_relative(display_path: str) -> bool:
    """Display paths are repo-relative inside a repo, absolute POSIX outside."""
    return not (display_path.startswith("/") or re.match(r"^[A-Za-z]:/", display_path))


def link_key(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def kind_for(identity: str) -> str:
    """``doc`` (a markdown page), ``image``, or ``text`` — from a closed map.
    Anything that is not a doc or a known image is only ever served as text."""
    suffix = posixpath.splitext(identity)[1].lower()
    if suffix in DOC_SUFFIXES:
        return "doc"
    if suffix in IMAGE_MIME:
        return "image"
    return "text"


def image_mime(identity: str) -> str:
    return IMAGE_MIME[posixpath.splitext(identity)[1].lower()]


def denied_reason(relative_posix_path: str) -> str | None:
    parts = [p.lower() for p in relative_posix_path.split("/") if p not in ("", ".")]
    for i, part in enumerate(parts):
        if part in _DENIED_DIRS and i < len(parts) - 1:
            return "not captured (inside a credentials folder)"
        if i < len(parts) - 1 and (part, parts[i + 1]) in _DENIED_DIR_PAIRS:
            return "not captured (inside a credentials folder)"
    if parts and _DENIED_NAME_RE.match(parts[-1]):
        return "not captured (looks like a secret)"
    return None


def secret_content_reason(data: bytes) -> str | None:
    if _SECRET_CONTENT_RE.search(data):
        return "not captured (contents look like a secret)"
    return None


def capture_file(path: Path, boundary: Path, identity: str) -> bytes:
    """Read one link target for shipping, or raise Unavailable with the reason.

    ``boundary`` is the repo root (or the doc's own folder outside a repo).
    The checks run on the lexical path AND the symlink-resolved one, the read
    is bounded at cap+1 bytes, and the opened handle must be the regular file
    that was checked (no FIFO hangs, no swap between check and open).
    """
    reason = denied_reason(identity)
    if reason:
        raise Unavailable(reason)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):  # symlink loop (RuntimeError before Python 3.13)
        raise Unavailable("symlink loop or unreadable path") from None
    try:
        inside = resolved.relative_to(boundary).as_posix()
    except ValueError:
        raise Unavailable("resolves outside the repository") from None
    reason = denied_reason(inside)
    if reason:
        raise Unavailable(reason)
    try:
        fd = _open_beneath(boundary, inside)
    except FileNotFoundError:
        raise Unavailable("file not found") from None
    except OSError:
        # ELOOP/ENOTDIR here means a component became a symlink after it was
        # resolved — capture refuses rather than following it anywhere.
        raise Unavailable("file could not be opened safely") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):  # before fdopen, which refuses directories itself
        os.close(fd)
        raise Unavailable("not a regular file")
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise Unavailable(f"too large (over {MAX_FILE_BYTES // (1024 * 1024)} MiB)")
    reason = secret_content_reason(data)  # images too: SVG is text, and metadata can carry tokens
    if reason:
        raise Unavailable(reason)
    if kind_for(identity) == "image":
        return data
    if b"\x00" in data:
        raise Unavailable("binary file")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unavailable("binary file") from None
    return data


_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_CAN_WALK = os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")


def _open_beneath(boundary: Path, inside: str) -> int:
    """Open ``boundary/inside`` without following a symlink at ANY level below
    ``boundary``: each directory is opened relative to its parent's descriptor
    with O_NOFOLLOW, so swapping an ancestor for a symlink after ``resolve()``
    cannot redirect the read. ``inside`` is already symlink-free (resolved).
    O_NONBLOCK keeps a FIFO from hanging the open; the caller rejects it.
    Platforms without dir_fd support (Windows) fall back to one plain open."""
    if not _CAN_WALK:
        return os.open(boundary / inside, _FILE_FLAGS)
    parts = [part for part in inside.split("/") if part]
    if not parts:
        raise IsADirectoryError(inside)
    dir_fd = os.open(boundary, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
