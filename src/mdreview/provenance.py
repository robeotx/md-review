"""Provenance collection for rendered documents.

Every render records where the markdown came from: the file's git repo (root,
name, branch, remote), the working directory of the process that rendered it
("agent cwd" — an agent's cwd and the document's repo can genuinely differ),
the agent harness that invoked it, and the agent session id when the harness
exposes one.

Everything is best-effort with explicit ``None`` for unknowns: a missing git
repo or an unrecognized harness must never fail a render. Fail-loud applies
to the review surface, not to metadata collection.

Precedence for the two operator-supplied fields:

- session id: explicit ``session_id`` argument > ``MD_REVIEW_SESSION_ID`` >
  the first set of the known harness env vars (``CLAUDE_CODE_SESSION_ID``,
  ``CODEX_SESSION_ID``, ``AGENT_SESSION_ID``, ``KIMI_SESSION_ID``).
- agent name: explicit ``agent`` argument > ``AI_AGENT`` env > ``None``.
"""

from __future__ import annotations

import getpass
import os
import shutil
import socket
import subprocess
from pathlib import Path

# Harness env vars known to carry a session identifier, in priority order.
# Extending this list is the supported way to teach md-review about a new
# agent harness — no other code changes needed.
SESSION_ID_ENV_VARS = (
    "MD_REVIEW_SESSION_ID",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_SESSION_ID",
    "AGENT_SESSION_ID",
    "KIMI_SESSION_ID",
)

_GIT_TIMEOUT_SECONDS = 5

# Resolved once at import: on Windows, CreateProcess searches the calling
# process's CURRENT directory before PATH, so a bare "git" could execute an
# untrusted git.exe/git.bat from the directory being reviewed.
_GIT = shutil.which("git")

# Every provenance field and its expected scalar type. normalize_provenance()
# uses this table both for local collection and for sanitizing client-
# supplied provenance at the /api/render boundary — an int sessionId or a
# nested object must never reach the index renderer.
PROVENANCE_FIELDS: tuple[str, ...] = (
    "sourceAbsPath",
    "sourceRepoRelPath",
    "sourceRepoRoot",
    "sourceRepoName",
    "sourceRepoBranch",
    "sourceRepoRemote",
    "agentCwd",
    "agent",
    "sessionId",
    "hostname",
    "user",
)


def sanitize_remote_url(url: str | None) -> str | None:
    """Strip credentials from a git remote URL before it is persisted.

    HTTPS remotes commonly embed userinfo — ``https://alice:ghp_SECRET@host/…``
    — and provenance is written to manifest.json, embedded in pages, and
    served back over the LAN. Publishing tokens is never the intent.
    SCP-like SSH syntax (``git@host:org/repo.git``) has no
    userinfo concept and is returned unchanged; the ``git`` username there is
    not a secret.
    """
    if not url:
        return url
    if "://" not in url:
        return url  # scp-like ssh or a plain path: nothing to strip
    scheme, rest = url.split("://", 1)
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]  # drop everything up to the last '@' (userinfo)
    return f"{scheme}://{rest}"


def _coerce_str(value: object) -> str | None:
    """Accept only plain strings (or stringifiable scalars) — anything richer
    (dict, list, bool-as-int tricks) becomes None rather than a later crash."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def normalize_provenance(raw: object, keep: tuple[str, ...] = ()) -> dict:
    """Reduce an arbitrary provenance payload to the fixed schema with
    explicit nulls. Applied at every ingress point (local collection,
    /api/render) so downstream readers can trust the shape unconditionally.
    ``keep`` names additional fields (e.g. the server's receipt stamps) to
    carry through with the same string-only coercion."""
    source = raw if isinstance(raw, dict) else {}
    normalized = {field: _coerce_str(source.get(field)) for field in PROVENANCE_FIELDS}
    for field in keep:
        if field not in normalized:
            normalized[field] = _coerce_str(source.get(field))
    return normalized


def _git(args: list[str], cwd: Path) -> str | None:
    """Run a read-only git command; return stripped stdout or None on any failure."""
    if _GIT is None:
        return None
    try:
        result = subprocess.run(
            [_GIT, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def git_root_for(path: Path) -> Path | None:
    """Git toplevel for the file or directory at ``path``, or None outside a repo."""
    anchor = path if path.is_dir() else path.parent
    top = _git(["rev-parse", "--show-toplevel"], anchor)
    return Path(top) if top else None


def detect_session_id(explicit: str | None = None) -> str | None:
    """Resolve the session id: explicit argument first, then known env vars."""
    if explicit and explicit.strip():
        return explicit.strip()
    for var in SESSION_ID_ENV_VARS:
        value = os.environ.get(var, "").strip()
        if value:
            return value
    return None


def detect_agent(explicit: str | None = None) -> str | None:
    """Resolve the agent harness name: explicit argument first, then AI_AGENT."""
    if explicit and explicit.strip():
        return explicit.strip()
    value = os.environ.get("AI_AGENT", "").strip()
    return value or None


def collect_provenance(
    input_path: Path,
    *,
    agent: str | None = None,
    session_id: str | None = None,
    agent_cwd: str | None = None,
) -> dict:
    """Build the provenance record for a render of ``input_path``.

    ``agent_cwd`` defaults to the current process cwd, which IS the agent's
    cwd whenever an agent harness invokes the CLI — the common case. The
    override exists for wrappers that spawn md-review from a different
    directory than the agent's own working directory.
    """
    resolved = input_path.resolve()
    cwd = Path(agent_cwd).resolve() if agent_cwd else Path.cwd().resolve()

    repo_root = git_root_for(resolved)
    source_repo_name: str | None = None
    source_repo_branch: str | None = None
    source_repo_remote: str | None = None
    if repo_root is not None:
        source_repo_name = repo_root.name
        # rev-parse works once commits exist; symbolic-ref also resolves the
        # branch of a freshly-initialized repo whose HEAD is still unborn.
        source_repo_branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo_root) or _git(
            ["symbolic-ref", "--short", "HEAD"], repo_root
        )
        source_repo_remote = sanitize_remote_url(_git(["config", "--get", "remote.origin.url"], repo_root))

    try:
        # POSIX separators: sourcePath is the cross-OS identity surface and
        # this field is displayed right next to it in the Source panel —
        # backslashes on Windows would look like a different document.
        source_rel = resolved.relative_to(repo_root).as_posix() if repo_root else None
    except (ValueError, TypeError):
        source_rel = None

    try:
        user: str | None = getpass.getuser()
    except (OSError, KeyError):
        user = None

    try:
        hostname = socket.gethostname() or None
    except OSError:
        hostname = None

    return {
        "sourceAbsPath": str(resolved),
        "sourceRepoRelPath": source_rel,
        "sourceRepoRoot": str(repo_root) if repo_root else None,
        "sourceRepoName": source_repo_name,
        "sourceRepoBranch": source_repo_branch,
        "sourceRepoRemote": source_repo_remote,
        "agentCwd": str(cwd),
        "agent": detect_agent(agent),
        "sessionId": detect_session_id(session_id),
        "hostname": hostname,
        "user": user,
    }
