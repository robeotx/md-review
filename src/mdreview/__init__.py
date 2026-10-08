"""md-review — LAN-only markdown review server.

Renders markdown into commentable review pages and serves them (plus a
persistent per-document comment channel) to any device on the local
network. The server is LAN-only by construction: clients outside the
explicit loopback/private/link-local/ULA allowlist are refused, with no
opt-out flag.
"""

from importlib import metadata

try:
    # Single source of truth: pyproject.toml [project] version.
    __version__ = metadata.version("md-review")
except metadata.PackageNotFoundError:
    # Running from a bare source tree (no install). Keep this in sync with
    # pyproject.toml if you ever bump without reinstalling.
    __version__ = "0.4.3"
