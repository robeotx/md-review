"""HTTP server: review pages, comment API, and the LAN-only access guard.

LAN-only by construction
------------------------
The guard is a property of the *server*, not a deployment suggestion:

- ``is_lan_client()`` admits exactly: loopback (127/8, ::1), RFC-1918 private
  (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10), IPv6
  ULA (fc00::/7), and RFC 6598 shared space (100.64.0.0/10 — the CGNAT range
  overlay VPNs like Tailscale use) — an explicit, version-stable network
  list (NOT ``ipaddress.is_private``, whose meaning has shifted across
  Python releases). IPv4-mapped IPv6 forms are normalized before
  classification. Any other client address is refused.
- The refusal happens twice: in ``verify_request`` (before the request line
  is even parsed — zero application surface exposed) and again at the top of
  every handler (defense in depth, with a chatty 403 JSON body).
- ``Host`` is validated on every request: IP literals must themselves be
  LAN addresses; names must be localhost, this machine's hostname, or an
  operator allowlist (``MD_REVIEW_EXTRA_HOSTS``). Arbitrary names are never
  resolved — resolving them would BE the DNS-rebinding hole this check
  closes.
- POSTs additionally require ``Content-Type: application/json`` (forces a
  CORS preflight browsers will never get approved), reject cross-site
  ``Origin``/``Sec-Fetch-Site`` headers, and require a well-formed
  ``Content-Length`` (no chunked bodies). Together these kill drive-by
  writes and rebinding reads from internet web pages open in a LAN browser.
- There is deliberately **no flag to disable the IP guard**.

Residual boundary (documented honestly): a reverse proxy, load balancer, or
source-NAT in front of md-review makes remote clients arrive AS loopback/
private peers, and no source-address check can detect that. Do not proxy
this server publicly — for remote access use a VPN (Tailscale, WireGuard);
VPN clients arrive from VPN-private addresses and pass the guard naturally.

Routes
------
- ``GET  /``                              rendered-doc index (HTML)
- ``GET  /health``                        liveness + version (JSON)
- ``GET  /api/docs``                      all docs: manifest + comment counts (JSON)
- ``POST /api/render``                    render markdown shipped by a remote CLI
- ``GET  /comments?doc=<id>``             comment array for one doc
- ``POST /comments``                      append a comment
- ``POST /comments/resolve``              set resolved on one comment
- ``GET  /ds/<path>``                     read-only design-system assets (css/fonts/svg)
- ``GET  /rendered/<doc-id>/<file>``      allowlisted per-doc files only
"""

from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__, links, store
from .provenance import normalize_provenance
from .store import (
    DOC_ID_RE,
    add_comment,
    doc_id_for,
    doc_namespace,
    list_documents,
    load_comments,
    render_payload,
    set_comment_resolved,
    validate_author,
    validate_comment_body,
    validate_doc_path,
)

DS_ALLOWED_SUFFIXES = {".css", ".svg", ".ttf", ".otf", ".woff", ".woff2"}
DS_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}

# Per-doc files a browser is allowed to fetch verbatim. comments.json is
# included: agents (and the page itself, conceptually) may read the channel
# directly, and the LAN guard is the boundary that keeps this acceptable.
RENDERED_FILE_ALLOWLIST = {"index.html", "anchors.json", "manifest.json", "comments.json"}

MAX_BODY_BYTES = 4 * 1024 * 1024  # ceiling on any JSON request body (markdown is capped lower, below)
REQUEST_TIMEOUT_SECONDS = 30  # read deadline per connection (slow-loris bound)
MAX_CONCURRENT_CONNECTIONS = 64  # thread-explosion bound

# /api/render ingress caps. Each render roughly triples its input on disk
# (page embeds both anchors and rendered body), and every distinct
# sourcePath mints a new doc dir — without these, the endpoint is an
# unauthenticated disk-flood primitive.
MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
MAX_SOURCE_PATH_LENGTH = 1_024
MAX_TITLE_LENGTH = 300
# Document-count ceiling: the per-render byte caps alone still allow death
# by a thousand cuts.
MAX_DOCUMENTS = 2_000
# /api/render alone may carry the publisher's captured linked files (base64),
# so its body ceiling is higher than MAX_BODY_BYTES. Only ONE render over the
# general ceiling runs at a time, so concurrent uploads cannot multiply into
# a memory flood (64 connections x 16 MiB would otherwise be 1 GiB).
MAX_RENDER_BODY_BYTES = 16 * 1024 * 1024
LINK_ROUTE_RE = re.compile(r"^/link/([^/]+)/([0-9a-f]{16})$")
# A captured SVG opened directly is a document of its own: no script, no
# network, no forms — only its inline styles and embedded data images.
SVG_SANDBOX_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"

# The explicit LAN allowlist. Deliberately NOT ipaddress.is_private: that
# predicate's meaning has changed across CPython releases (TEST-NETs,
# benchmarking and reserved ranges have moved in and out), and a security
# boundary must not silently shift with an interpreter upgrade.
# 100.64.0.0/10 is RFC 6598 *shared* address space (carrier-grade NAT): not
# Internet-routable, and the range overlay VPNs (Tailscale) assign from —
# it's what makes the documented "remote access via VPN" story work at all.
LAN_NETWORKS_V4 = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
    )
)
LAN_NETWORKS_V6 = tuple(ipaddress.ip_network(cidr) for cidr in ("::1/128", "fe80::/10", "fc00::/7"))


def is_lan_client(ip_text: str) -> bool:
    """True only for clients on the local network or this machine.

    Admits exactly the explicit allowlist above — nothing else. IPv4-mapped
    IPv6 addresses (``::ffff:10.0.0.1``) are normalized to their IPv4 form
    first, so the mapping can't launder a public address through the v6 list
    or smuggle a private one past the v4 list.
    """
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip_text.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    networks = LAN_NETWORKS_V4 if isinstance(ip, ipaddress.IPv4Address) else LAN_NETWORKS_V6
    return any(ip in net for net in networks)


def host_allowed(host_header: str | None, extra_names: frozenset[str] = frozenset()) -> bool:
    """Validate the Host header without EVER resolving it through DNS.

    Allowed: LAN IP literals (any of this machine's plausible bind targets),
    localhost names, this machine's own hostname (+ .local), names advertised
    by the built-in mDNS responder (``extra_names``), and an operator
    allowlist via MD_REVIEW_EXTRA_HOSTS. A DNS-rebinding attack sends the
    attacker's domain as Host — it is neither an IP literal nor a known local
    name, so it dies here. A non-numeric port suffix makes the whole header
    garbage.
    """
    if not host_header:
        return False
    host = host_header.strip().lower()
    if host.startswith("[") and "]" in host:  # bracketed IPv6 literal: [::1]:8779
        host = host[1 : host.index("]")]
    elif ":" in host:  # strip :port — but only if it really is one
        name, _, port = host.rpartition(":")
        # isdecimal(), not isdigit(): '\xb2' (superscript two) passes isdigit
        # but explodes int() — a malformed Host must be refused, never crash
        # the handler.
        if not port.isdecimal() or not (0 < int(port) <= 65535):
            return False
        host = name
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return is_lan_client(host)  # IP literals must be LAN addresses themselves
    except ValueError:
        pass
    names = {"localhost", "localhost.localdomain", "ip6-localhost"}
    try:
        hostname = socket.gethostname().lower()
        names.add(hostname)
        names.add(f"{hostname}.local")
    except OSError:
        pass
    extra = os.environ.get("MD_REVIEW_EXTRA_HOSTS", "")
    names.update(part.strip().lower() for part in extra.split(",") if part.strip())
    names.update(extra_names)
    return host in names


def vendored_ds_dir() -> Path:
    return Path(str(resources.files("mdreview") / "assets" / "ds"))


def resolve_ds_dir(explicit: Path | None = None) -> Path:
    """Design-system dir precedence: --ds-dir flag > $MD_REVIEW_DS_DIR > vendored."""
    if explicit is not None:
        return explicit.expanduser().resolve()
    env = os.environ.get("MD_REVIEW_DS_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return vendored_ds_dir()


# The palettes the vendored design system ships (themes.css): light is the
# :root default, "dusk" is Dusk Slate, "dark" is Warm Chalkboard. "system" is
# the follow-the-OS sentinel: no attribute is stamped and the page's inline
# bootstrap resolves the device's prefers-color-scheme client-side.
THEMES = ("light", "dusk", "dark", "system")


def resolve_theme(explicit: str | None = None) -> str:
    """Default-theme precedence: --theme flag > $MD_REVIEW_THEME > 'system'.

    Chatty-fails on an unknown value: a typo'd theme must never silently
    fall back to system — the operator would think the flag was ignored.
    """
    value = (explicit or "").strip().lower() or os.environ.get("MD_REVIEW_THEME", "").strip().lower() or "system"
    if value not in THEMES:
        raise SystemExit(f"ERROR: unknown theme '{value}' — expected one of: {', '.join(THEMES)}")
    return value


# Theme bootstrap shared by every server-built page (the index and the /link
# pages); rendered doc pages carry their own copy (renderer.py) — keep in sync.
_THEME_BOOTSTRAP_JS = """// ---- theme bootstrap (FOUC guard) --------------------------------------
// Same script the doc pages carry — keep the two in sync. Runs BEFORE the
// stylesheet below is fetched, so data-theme is settled before first paint
// (no light-flash on dark setups). Precedence: per-device override
// (localStorage mdReviewTheme) > server default (data-theme on <html>) >
// OS preference (prefers-color-scheme is binary, so OS dark maps to "dark"
// — Warm Chalkboard; "dusk" is a mid-tone opt-in via the toggle or
// --theme dusk).
(() => {
  const root = document.documentElement;
  let stored = null;
  try { stored = localStorage.getItem('mdReviewTheme'); } catch (err) { stored = null; }
  if (stored === 'light' || stored === 'dusk' || stored === 'dark') {
    root.setAttribute('data-theme', stored);
    return;
  }
  if (root.hasAttribute('data-theme')) return;  // server pinned a default
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    root.setAttribute('data-theme', 'dark');
  }
})();"""


class ReviewServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address,
        handler_class,
        *,
        data_dir: Path,
        ds_dir: Path,
        default_author: str,
        extra_host_names: frozenset[str] = frozenset(),
        theme: str = "system",
    ):
        super().__init__(server_address, handler_class)
        self.data_dir = data_dir
        self.ds_dir = ds_dir
        self.default_author = default_author
        self.extra_host_names = extra_host_names
        self.theme = theme
        self._connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)
        self.large_render_slot = threading.BoundedSemaphore(1)

    def verify_request(self, request, client_address) -> bool:
        # First and strongest gate: drop non-LAN peers before a single byte of
        # their request line is parsed. The handler-level check below stays as
        # the chatty second layer.
        if not is_lan_client(client_address[0]):
            sys.stderr.write(f"[md-review] REFUSED non-LAN client {client_address[0]} (connection closed pre-parse)\n")
            return False
        return True

    def process_request_thread(self, request, client_address) -> None:
        # Bound concurrent handlers: without a cap, N idle LAN sockets pin N
        # threads forever (the read timeout bounds each connection's lifetime,
        # this bounds how many may exist at once).
        if not self._connection_slots.acquire(blocking=False):
            sys.stderr.write(f"[md-review] connection limit reached; dropping {client_address[0]}\n")
            self.shutdown_request(request)
            return
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer  # narrow the type for attribute access

    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        # Read deadline: a client may trickle headers or a declared-16 MiB
        # body, but not forever. 30 s is generous for any real LAN device and
        # fatal to slow-loris-style thread pinning.
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    # -- plumbing ---------------------------------------------------------

    @property
    def data_dir(self) -> Path:
        return self.server.data_dir

    def _client_permitted(self) -> bool:
        """Second-layer LAN check; sends a chatty 403 instead of a silent close."""
        if is_lan_client(self.client_address[0]):
            return True
        self._reject(403, "md-review is LAN-only; non-local clients are refused")
        return False

    def _host_permitted(self) -> bool:
        if host_allowed(self.headers.get("Host"), self.server.extra_host_names):
            return True
        self._reject(
            403,
            "unrecognized Host header — access md-review by LAN IP, localhost, or the "
            "server's hostname (custom names: set MD_REVIEW_EXTRA_HOSTS on the server)",
        )
        return False

    def _request_permitted(self) -> bool:
        return self._client_permitted() and self._host_permitted()

    def _json(self, payload: object, code: int = 200, *, no_store: bool = False) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if no_store:
            self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            # Advertise what the socket is about to do (rejects, framing
            # errors) so clients don't pipeline into a closing stream.
            self.send_header("Connection", "close")
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(raw)

    def _html(self, markup: str, code: int = 200) -> None:
        raw = markup.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # The only page _html serves is the index, which changes whenever a
        # doc is rendered or a comment lands — a cached copy actively lies.
        self.send_header("Cache-Control", "no-store")
        self._security_headers(page=True)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(raw)

    def _error(self, code: int, message: str) -> None:
        self._json({"error": message}, code)

    def _reject(self, code: int, message: str) -> None:
        """Reject a request BEFORE its body is read.

        Every pre-body rejection must close the connection: with keep-alive
        the undrained body bytes would otherwise be parsed as the NEXT
        request on this socket — and a request smuggled in this way carries
        none of the headers the CSRF/Host gates inspect.
        Never return from a handler with bytes still owed.
        """
        self.close_connection = True
        self._error(code, message)

    def _body_present_on_bodyless_verb(self) -> bool:
        """GET/HEAD with a body: reject + close (same smuggling shape)."""
        has_length = (self.headers.get("Content-Length") or "0") not in ("", "0")
        has_te = bool((self.headers.get("Transfer-Encoding") or "").strip())
        if has_length or has_te:
            self._reject(400, "GET/HEAD requests must not carry a body")
            return True
        return False

    def _read_json_body(self, max_bytes: int = MAX_BODY_BYTES) -> object | None:
        """Parse the JSON body. Framing rules (chatty, and fatal to the
        connection so undrained bytes can never poison the NEXT request on a
        keep-alive socket):

        - Missing/invalid Content-Length → 411.
        - Oversized Content-Length → 413.
        - Unparseable body → None (caller sends 400); connection closed either way.
        """
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self.close_connection = True
            raise FramingError("invalid Content-Length header") from None
        if length <= 0:
            self.close_connection = True
            raise FramingError("POST requires a Content-Length header")
        if length > max_bytes:
            self.close_connection = True
            raise PayloadTooLargeError(f"request body exceeds {max_bytes} bytes")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.close_connection = True
            return None

    def _store_error_code(self, exc: Exception) -> int:
        return 400 if isinstance(exc, ValueError) else 500 if isinstance(exc, RuntimeError) else 404

    def _safe_store_error(self, exc: Exception, doc_id: str) -> None:
        """Store errors can carry absolute paths (the operator needs them);
        clients get a generic pointer instead."""
        code = self._store_error_code(exc)
        if isinstance(exc, RuntimeError):
            sys.stderr.write(f"[md-review] {exc}\n")
            self._error(code, f"comments store error for doc '{doc_id}'; see the server log for detail")
        else:
            self._error(code, str(exc))

    # -- GET routes ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if not self._request_permitted():
            return
        if self._body_present_on_bodyless_verb():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._json({"ok": True, "version": __version__, "docs": len(list_documents(self.data_dir))}, no_store=True)
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/":
            self._render_index()
            return
        if path == "/api/docs":
            self._json({"docs": list_documents(self.data_dir)}, no_store=True)
            return
        if path == "/comments":
            doc_id = (parse_qs(parsed.query).get("doc") or [""])[0]
            try:
                self._json(load_comments(doc_id, self.data_dir), no_store=True)
            except (FileNotFoundError, RuntimeError, ValueError) as exc:
                self._safe_store_error(exc, doc_id)
            return
        if path.startswith("/ds/"):
            self._serve_ds_asset(path)
            return
        if path.startswith("/rendered/"):
            self._serve_rendered_file(path)
            return
        if path.startswith("/link/"):
            self._serve_link(path, parsed.query)
            return
        self._error(404, f"unknown route: {path}")

    def do_HEAD(self) -> None:  # noqa: N802
        # HEAD must agree with GET on every route. Run the real
        # GET logic with body output suppressed.
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _serve_ds_asset(self, path: str) -> None:
        rel = unquote(path.removeprefix("/ds/"))
        if "\x00" in rel:
            self._error(400, "NUL bytes are not valid in asset paths")
            return
        try:
            target = (self.server.ds_dir / rel).resolve()
        except (ValueError, OSError):
            self._error(400, "unresolvable asset path")
            return
        try:
            target.relative_to(self.server.ds_dir.resolve())
        except ValueError:
            self._error(403, "path escapes design-system directory")
            return
        if target.suffix.lower() not in DS_ALLOWED_SUFFIXES:
            self._error(403, "design-system route serves css/font/svg assets only")
            return
        if not target.is_file():
            self._error(404, f"design-system asset not found: {rel}")
            return
        self._send_file(target, DS_CONTENT_TYPES[target.suffix.lower()])

    def _serve_rendered_file(self, path: str) -> None:
        parts = path.removeprefix("/rendered/").split("/")
        if len(parts) != 2:
            self._error(404, "rendered docs serve exactly /rendered/<doc-id>/<file>")
            return
        doc_id, filename = parts
        doc_id = unquote(doc_id)
        filename = unquote(filename)
        if not DOC_ID_RE.match(doc_id):
            self._error(400, "invalid doc id")
            return
        if filename not in RENDERED_FILE_ALLOWLIST:
            self._error(403, f"file not served: {filename}")
            return
        try:
            doc_dir = store.doc_dir_for_id(doc_id, self.data_dir)
        except (ValueError, FileNotFoundError) as exc:
            self._error(self._store_error_code(exc), str(exc))
            return
        target = doc_dir / filename
        if not target.is_file():
            self._error(404, f"no {filename} for doc {doc_id}")
            return
        if filename == "manifest.json":
            self._serve_manifest(target, doc_id)
            return
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".json": "application/json; charset=utf-8",
        }
        if filename == "index.html":
            # Doc pages are static files — written at render time, possibly
            # before this server (and its --theme) even existed. An explicit
            # server default is therefore stamped onto the <html> tag at
            # SERVE time, so every doc this server serves carries the same
            # default regardless of when/where it was rendered; `system`
            # serves the bytes untouched. The page's inline bootstrap reads
            # localStorage BEFORE honoring this attribute, so a per-device
            # override still wins.
            self._send_content(self._themed_doc_html(target.read_bytes()), content_types[".html"], no_store=True)
            return
        # Every doc-dir file is mutable in place: a re-render overwrites the
        # SAME doc dir (same urls) and comments.json grows with each post —
        # so all of it is no-store, not just the comments channel.
        self._send_file(target, content_types[target.suffix], no_store=True)

    def _themed_doc_html(self, content: bytes) -> bytes:
        """Stamp the server's default theme onto a rendered doc page.

        `system` returns the bytes untouched; an explicit theme rewrites the
        renderer's fixed ``<html lang="en">`` opening tag to carry
        ``data-theme``. Light gets the attribute too even though no
        ``[data-theme="light"]`` palette block exists (light IS the :root
        default): the attribute is what tells the page's bootstrap "pinned —
        do not follow the OS dark preference".
        """
        if self.server.theme not in ("light", "dusk", "dark"):
            return content
        stamped = f'<html lang="en" data-theme="{self.server.theme}">'.encode()
        return content.replace(b'<html lang="en">', stamped, 1)

    def _serve_manifest(self, target: Path, doc_id: str) -> None:
        """Serve manifest.json with legacy absolute commentsPath redacted.

        Manifests written before the relative-path fix (and migrated legacy
        stores) carry the server's absolute data dir in commentsPath. New
        manifests are relative; old ones are rewritten on the way out —
        the on-disk file is left untouched.
        """
        try:
            manifest = json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            self._error(500, f"manifest for doc '{doc_id}' is unreadable; see the server log")
            sys.stderr.write(f"[md-review] unreadable manifest {target}: {exc}\n")
            return
        if isinstance(manifest, dict):
            comments_path = manifest.get("commentsPath")
            if isinstance(comments_path, str) and Path(comments_path).is_absolute():
                manifest["commentsPath"] = f"rendered/{doc_id}/comments.json"
        self._json(manifest, no_store=True)

    def _send_file(self, target: Path, content_type: str, *, no_store: bool = False) -> None:
        # Read fully BEFORE responding: on Windows, os.replace() over a file
        # another handle still holds open fails — so streaming from the open
        # handle would make every concurrent re-render a 500. Reading first also fixes the stat-then-open size race
        # (a re-render landing between the two used to desync keep-alive).
        self._send_content(target.read_bytes(), content_type, no_store=no_store)

    def _send_content(
        self, content: bytes, content_type: str, *, no_store: bool = False, csp: str | None = None
    ) -> None:
        # Split from _send_file so callers that transform bytes on the way
        # out (the doc-page theme stamp) share one response path — headers,
        # HEAD suppression, and framing stay identical.
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self._security_headers(page=content_type.startswith("text/html"))
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        self.wfile.write(content)

    def _security_headers(self, *, page: bool) -> None:
        # CSP is deliberately not a script-execution barrier here (the review
        # page NEEDS its inline script) — its value is connect-src 'self',
        # which cuts exfiltration channels if any XSS ever lands, plus
        # frame-ancestors against clickjacking ("Resolve" buttons framed by an
        # internet page would POST same-origin and pass every tripwire).
        # style-src MUST name 'self' alongside 'unsafe-inline': a specific
        # directive replaces default-src entirely, so 'unsafe-inline' alone
        # would block the external /ds/ stylesheets the whole UI depends on.
        if page:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")

    # -- POST routes --------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        if not self._request_permitted():
            return
        # Browser-attack tripwires. A "simple request" (form post or
        # text/plain fetch) crosses origins without a CORS preflight, so any
        # internet page could otherwise blind-write to this server through a
        # LAN browser. Requiring application/json forces a preflight we never
        # approve; Origin/Sec-Fetch-Site checks catch the rest.
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self._reject(415, "POSTs require Content-Type: application/json")
            return
        if not self._browser_headers_permitted():
            return
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            self._reject(501, "Transfer-Encoding is not supported; send a plain Content-Length body")
            return
        path = self.path.split("?", 1)[0]
        if path == "/comments":
            self._post_comment()
            return
        if path == "/comments/resolve":
            self._post_resolve()
            return
        if path == "/api/render":
            self._post_render()
            return
        self._reject(404, f"unknown POST route: {path}")

    def _browser_headers_permitted(self) -> bool:
        """Origin / Sec-Fetch-Site cross-site rejection for state-changing
        routes. Absent headers are fine (curl, agents, non-browser clients)."""
        origin = self.headers.get("Origin")
        if origin:
            origin_host = urlparse(origin).netloc.lower()
            host = (self.headers.get("Host") or "").lower()
            if not origin_host or origin_host != host:
                self._reject(403, "cross-origin POST refused")
                return False
        sec_fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "same-site", "none"):
            self._reject(403, f"cross-site request refused (Sec-Fetch-Site: {sec_fetch_site})")
            return False
        return True

    def _post_comment(self) -> None:
        try:
            body = self._read_json_body()
        except FramingError as exc:
            self._error(411, str(exc))
            return
        except PayloadTooLargeError as exc:
            self._error(413, str(exc))
            return
        if not isinstance(body, dict):
            self._error(400, "request body must be valid JSON object")
            return
        try:
            doc_id, anchor, text, quote = validate_comment_body(body)
            comment = {
                "id": uuid.uuid4().hex[:12],
                "doc_id": doc_id,
                "doc_path": validate_doc_path(body.get("docPath")) or validate_doc_path(anchor.get("docPath")),
                "anchor": anchor,
                "quote": quote,
                "text": text,
                "author": validate_author(body.get("author")) or self.server.default_author,
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "resolved": False,
            }
            add_comment(doc_id, comment, self.data_dir)
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            # doc_id binds inside the try — a validation failure must not
            # become an UnboundLocalError here.
            self._safe_store_error(exc, str(body.get("docId") or "?"))
            return
        self._json(comment, 201)

    def _post_resolve(self) -> None:
        try:
            body = self._read_json_body()
        except FramingError as exc:
            self._error(411, str(exc))
            return
        except PayloadTooLargeError as exc:
            self._error(413, str(exc))
            return
        if not isinstance(body, dict):
            self._error(400, "request body must be valid JSON object")
            return
        doc_id = body.get("docId")
        comment_id = body.get("id")
        resolved = body.get("resolved")
        if not isinstance(doc_id, str) or not isinstance(comment_id, str) or not isinstance(resolved, bool):
            self._error(400, "resolve requires {docId, id, resolved}")
            return
        try:
            self._json(set_comment_resolved(doc_id, comment_id, resolved, self.data_dir))
        except LookupError as exc:
            self._error(404, str(exc))
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            self._safe_store_error(exc, doc_id)

    def _post_render(self) -> None:
        """Render markdown shipped by a remote `md-review render --server`.

        Provenance arrives from the client — it was collected on the machine
        where the document actually lives, which is the whole point. It is
        normalized to the fixed schema (explicit nulls, strings only) before
        storage, and the server adds its own receipt stamp without
        overwriting the client's fields.

        A body over the general ceiling (captured linked files) needs the
        single large-render slot, taken BEFORE the body is read.
        """
        try:
            declared = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            declared = 0  # _read_json_body rejects it with the precise error
        if declared <= MAX_BODY_BYTES:
            self._post_render_body()
            return
        if not self.server.large_render_slot.acquire(blocking=False):
            self._reject(503, "another large render is in progress; retry shortly")
            return
        try:
            self._post_render_body()
        finally:
            self.server.large_render_slot.release()

    def _post_render_body(self) -> None:
        try:
            body = self._read_json_body(MAX_RENDER_BODY_BYTES)
        except FramingError as exc:
            self._error(411, str(exc))
            return
        except PayloadTooLargeError as exc:
            self._error(413, str(exc))
            return
        if not isinstance(body, dict):
            self._error(400, "request body must be valid JSON object")
            return
        markdown = body.get("markdown")
        if not isinstance(markdown, str) or not markdown.strip():
            self._error(400, "render requires non-empty markdown")
            return
        if len(markdown.encode("utf-8")) > MAX_MARKDOWN_BYTES:
            self._error(413, f"markdown exceeds {MAX_MARKDOWN_BYTES} bytes; split the document or render locally")
            return
        source_path = body.get("sourcePath")
        if not isinstance(source_path, str) or not source_path.strip():
            self._error(400, "render requires sourcePath (repo-relative or absolute display path)")
            return
        source_path = source_path.strip()
        if len(source_path) > MAX_SOURCE_PATH_LENGTH:
            self._error(400, f"sourcePath exceeds {MAX_SOURCE_PATH_LENGTH} characters")
            return
        filename = body.get("filename")
        if not isinstance(filename, str) or not filename.strip():
            filename = Path(source_path).name or "document.md"
        title = body.get("title")
        if not isinstance(title, str) or not title.strip():
            title = re.sub(r"\.md$", "", filename, flags=re.IGNORECASE).replace("-", " ")
        title = title.strip()[:MAX_TITLE_LENGTH]
        try:
            captures = parse_links_field(body.get("links"))
        except ValueError as exc:
            self._error(400, str(exc))
            return
        provenance = normalize_provenance(body.get("provenance"))
        provenance["receivedFrom"] = self.client_address[0]
        provenance["receivedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        doc_id = doc_id_for(source_path, doc_namespace(provenance))
        if not (store.rendered_dir(self.data_dir) / doc_id).exists():
            doc_count = len(list(store.rendered_dir(self.data_dir).glob("*/")))
            if doc_count >= MAX_DOCUMENTS:
                self._error(429, f"document ceiling reached ({MAX_DOCUMENTS}); prune old docs before rendering new ones")
                return
        try:
            render_payload(
                markdown=markdown,
                source_path=source_path,
                doc_id=doc_id,
                title=title,
                data_dir=self.data_dir,
                provenance=provenance,
                captures=captures,
            )
        except (OSError, ValueError) as exc:
            # Full detail (which contains server-local paths) goes to the
            # operator's log; the client gets the doc id and a generic cause.
            sys.stderr.write(f"[md-review] render of {source_path!r} failed: {exc}\n")
            self._error(500, f"render failed for docId '{doc_id}'; see the server log for detail")
            return
        self._json({"docId": doc_id, "url": f"/rendered/{doc_id}/index.html", "title": title}, 201)

    # -- relative links (see links.py) ---------------------------------------

    def _serve_link(self, path: str, query: str) -> None:
        """Follow a rewritten relative link. Decided at CLICK time, so a target
        published after the linking doc still opens its review page. Every
        byte served comes from the store (published pages, or files the
        publisher captured) — never from a path on this machine."""
        match = LINK_ROUTE_RE.match(path)
        if not match:
            self._link_page(404, "No such link", "<p>This link address is malformed.</p>")
            return
        doc_id, key = unquote(match.group(1)), match.group(2)
        if not DOC_ID_RE.match(doc_id):
            self._link_page(400, "No such link", "<p>Invalid document id.</p>")
            return
        found = store.load_link(doc_id, key, self.data_dir)
        if found is None:
            self._link_page(404, "No such link", "<p>There is no such link in this document.</p>")
            return
        entry, blob = found
        target = entry.get("target") or ""
        if entry.get("kind") == "doc":
            published = store.find_published_doc(entry, doc_id, self.data_dir)
            if published:
                self._redirect(f"/rendered/{published}/index.html")
                return
        if blob is not None:
            # Re-derived from the target here rather than trusting the stored kind.
            if links.kind_for(target) == "image":
                mime = links.image_mime(target)
                self._send_content(blob, mime, no_store=True, csp=SVG_SANDBOX_CSP if mime == "image/svg+xml" else None)
            elif "raw=1" in query.split("&"):
                self._send_content(blob, "text/plain; charset=utf-8", no_store=True)
            else:
                self._snapshot_page(doc_id, entry, blob)
            return
        reason = entry.get("reason") or store.NO_CAPTURE_REASON
        if entry.get("kind") == "doc":
            reason = f"it is not published for review yet, and {reason}"
        shown = html.escape(target or "This link")
        self._link_page(
            404,
            f"{target or 'Link'} isn't available",
            f"<p><code>{shown}</code> can't be shown: {html.escape(reason)}.</p>"
            f'<p><a href="/rendered/{html.escape(doc_id)}/index.html">Back to the document</a></p>',
        )

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _snapshot_page(self, doc_id: str, entry: dict, blob: bytes) -> None:
        """Read-only, escaped view of a captured file (Markdown included):
        rendering it again on every GET would be a CPU-cost path for any LAN
        client, and an escaped <pre> is linear and cannot carry markup."""
        target = str(entry.get("target") or "")
        text = blob.decode("utf-8", errors="replace")
        source_title = doc_id
        manifest = store.load_manifest(doc_id, self.data_dir)
        if manifest:
            source_title = str(manifest.get("title") or doc_id)
        publish_hint = ""
        if entry.get("kind") == "doc":
            publish_hint = (
                f" To review and comment on it, publish it: <code>md-review render {html.escape(target)}</code>."
            )
        raw_href = html.escape(f"/link/{doc_id}/{links.link_key(target)}?raw=1", quote=True)
        body = (
            f'<p class="note">Read-only copy of <code>{html.escape(target)}</code>, captured when '
            f'<a href="/rendered/{html.escape(doc_id)}/index.html">{html.escape(source_title)}</a> was published. '
            f"It is not published for review.{publish_hint} "
            f'<a href="{raw_href}">Raw</a></p>'
            f'<pre class="snapshot">{html.escape(text)}</pre>'
        )
        self._link_page(200, target, body)

    def _link_page(self, code: int, title: str, body_html: str) -> None:
        """Small server-built page for /link: everything interpolated into
        ``body_html`` must already be escaped by the caller; ``title`` is
        escaped here."""
        markup = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · md-review</title>
<link rel="icon" href="data:,">
<script>
{_THEME_BOOTSTRAP_JS}
</script>
<link rel="stylesheet" href="/ds/design-app/tokens.css">
<style>
body {{ margin: 0; padding: 24px 16px 60px; font-family: var(--rds-font-sans); background: var(--rds-surface); color: var(--rds-ink); }}
.wrap {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 18px; margin: 0 0 10px; overflow-wrap: anywhere; }}
.note {{ color: var(--rds-ink-5); font-size: 13px; }}
a {{ color: var(--rds-accent-strong); }}
pre.snapshot {{ white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--rds-font-mono); font-size: 13px; line-height: 1.5; background: var(--rds-surface-card); border: 1px solid var(--rds-line); border-radius: 8px; padding: 14px; }}
</style>
</head>
<body><div class="wrap"><h1>{html.escape(title)}</h1>{body_html}</div></body>
</html>
"""
        self._html(self._themed_doc_html(markup.encode("utf-8")).decode("utf-8"), code)

    # -- index page ---------------------------------------------------------

    def _render_index(self) -> None:
        entries = list_documents(self.data_dir)
        cards: list[str] = []
        for entry in entries:
            prov = entry["provenance"]
            repo = prov.get("sourceRepoName") or ""
            branch = prov.get("sourceRepoBranch") or ""
            session = prov.get("sessionId") or ""
            session_short = session[:8] if session else ""
            created = (entry["createdAt"] or "")[:16].replace("T", " ")
            open_count = entry["openComments"]
            total_count = entry["totalComments"]
            if open_count is None:
                count_label = "comments unreadable"
            elif total_count == 0:
                count_label = "no comments"
            else:
                count_label = f"{open_count} open · {total_count} total"
            repo_bits = []
            if repo:
                repo_bits.append(f"<span class='chip repo'>{html.escape(repo)}{(':' + html.escape(branch)) if branch else ''}</span>")
            if session_short:
                repo_bits.append(f"<span class='chip session' title='agent session id: {html.escape(session)}'>session {html.escape(session_short)}</span>")
            if prov.get("agent"):
                repo_bits.append(f"<span class='chip agent'>{html.escape(str(prov['agent']))}</span>")
            chips = "".join(repo_bits)
            cards.append(
                f"""<li class="card">
  <a class="title" href="/rendered/{html.escape(entry['docId'])}/index.html">{html.escape(entry["title"])}</a>
  <div class="meta"><span>{html.escape(created)}</span><span class="path">{html.escape(entry["sourcePath"])}</span></div>
  <div class="chips">{chips}<span class="chip count">{html.escape(count_label)}</span></div>
</li>"""
            )
        listing = "\n".join(cards) if cards else "<p class='empty'>No documents rendered yet. Run <code>md-review render your-doc.md</code>.</p>"
        host_label = html.escape(f"{self.server.server_address[0]}:{self.server.server_address[1]}")
        # Server-level default theme (see --theme / MD_REVIEW_THEME). Explicit
        # themes stamp data-theme on <html> — light included, even though no
        # [data-theme="light"] palette block exists (light IS the :root
        # default): the attribute is how the bootstrap below knows "pinned —
        # do not follow the OS dark preference". `system` stamps nothing and
        # lets the bootstrap resolve the device.
        theme = self.server.theme
        theme_attr = f' data-theme="{theme}"' if theme in ("light", "dusk", "dark") else ""
        body = f"""<!doctype html>
<html lang="en"{theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>md-review</title>
<link rel="icon" href="data:,">
<script>
{_THEME_BOOTSTRAP_JS}
</script>
<link rel="stylesheet" href="/ds/design-app/tokens.css">
<style>
body {{ margin: 0; padding: 28px 20px 60px; font-family: var(--rds-font-sans); background: var(--rds-surface); color: var(--rds-ink); }}
.wrap {{ max-width: 860px; margin: 0 auto; }}
.headrow {{ display: flex; align-items: center; gap: 12px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
.theme-picker {{ display: inline-flex; align-items: center; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); overflow: hidden; background: var(--rds-surface); }}
.theme-glyph {{ appearance: none; border: 0; background: transparent; color: var(--rds-ink-5); width: 30px; height: 26px; display: inline-grid; place-items: center; font-size: 13px; line-height: 1; cursor: pointer; }}
.theme-glyph + .theme-glyph {{ border-left: 1px solid var(--rds-line); }}
.theme-glyph:hover {{ background: var(--rds-surface-rail); color: var(--rds-ink-2); }}
.theme-glyph.active {{ background: var(--rds-accent-wash); color: var(--rds-accent-strong); }}
.sub {{ color: var(--rds-ink-5); font-size: 12px; margin-bottom: 22px; }}
ul {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }}
.card {{ background: var(--rds-surface-card); border: 1px solid var(--rds-line); border-radius: 10px; padding: 12px 14px; }}
.card:hover {{ border-color: var(--rds-line-strong); }}
a.title {{ color: var(--rds-ink); font-weight: 600; font-size: 14px; text-decoration: none; }}
a.title:hover {{ color: var(--rds-accent-strong); text-decoration: underline; text-underline-offset: 2px; }}
.meta {{ display: flex; flex-wrap: wrap; gap: 4px 12px; color: var(--rds-ink-5); font-size: 11px; margin-top: 4px; }}
.meta .path {{ font-family: var(--rds-font-mono); font-size: 10.5px; overflow-wrap: anywhere; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
.chip {{ font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--rds-line); color: var(--rds-ink-2); background: var(--rds-surface); }}
.chip.repo {{ border-color: var(--rds-accent); color: var(--rds-accent-strong); background: var(--rds-accent-wash); }}
.chip.session {{ font-family: var(--rds-font-mono); }}
.chip.count {{ margin-left: auto; }}
.empty {{ color: var(--rds-ink-5); font-size: 13px; }}
code {{ font-family: var(--rds-font-mono); background: var(--rds-surface-rail); border: 1px solid var(--rds-line); border-radius: 4px; padding: 1px 5px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="headrow">
    <h1>md-review</h1>
    <span class="theme-picker" role="group" aria-label="Theme for this device only (stored in localStorage, beats the server default)">
      <button class="theme-glyph" data-theme-set="light" type="button" title="Light" aria-label="Light theme">☼</button><button class="theme-glyph" data-theme-set="dusk" type="button" title="Dusk" aria-label="Dusk theme">◐</button><button class="theme-glyph" data-theme-set="dark" type="button" title="Dark" aria-label="Dark theme">☾</button>
    </span>
  </div>
  <div class="sub">{len(entries)} document{"s" if len(entries) != 1 else ""} · bound {host_label} · LAN-only · <a href="/api/docs" style="color:inherit">/api/docs</a></div>
  <ul>
{listing}
  </ul>
</div>
<script>
// Same per-device glyph picker the doc page offers, on the same localStorage
// key — see the doc page for the full rationale. The active glyph is read
// back off the <html> attribute (the <head> bootstrap already applied
// override/server/OS state), so the picker matches what is painted.
(() => {{
  const glyphs = [...document.querySelectorAll('[data-theme-set]')];
  const current = () => document.documentElement.getAttribute('data-theme') || 'light';
  const paint = () => {{ for (const g of glyphs) g.classList.toggle('active', g.dataset.themeSet === current()); }};
  for (const g of glyphs) {{
    g.addEventListener('click', () => {{
      document.documentElement.setAttribute('data-theme', g.dataset.themeSet);
      try {{ localStorage.setItem('mdReviewTheme', g.dataset.themeSet); }} catch (err) {{ /* storage unavailable: this page view only */ }}
      paint();
    }});
  }}
  paint();
}})();
</script>
</body>
</html>
"""
        self._html(body)

    def log_message(self, format, *args):  # quieter default log line
        # The request line is client-controlled: a LAN peer embedding ANSI
        # escapes must not be able to manipulate the operator's terminal.
        # Strip C0/C1 controls (keeping \n\t out too — one
        # request, one log line).
        message = format % args
        safe = "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in message)
        sys.stderr.write(f"[md-review] {safe}\n")


def parse_links_field(raw: object) -> store.Captures | None:
    """Validate the optional ``links`` field of /api/render.

    Shape: ``{"files": {target: base64}, "reasons": {target: str}}`` or
    ``{"disabled": true}``. Absent (an older client) → None. Only shapes and
    encodings are checked here; which targets count, and every size limit,
    is enforced by the store against the links its own render pass finds.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("links must be a JSON object")
    if raw.get("disabled") is True:
        return store.Captures(disabled=True)
    files_raw, reasons_raw = raw.get("files", {}), raw.get("reasons", {})
    if not isinstance(files_raw, dict) or not isinstance(reasons_raw, dict):
        raise ValueError("links.files and links.reasons must be JSON objects")
    if len(files_raw) > links.MAX_TARGETS or len(reasons_raw) > links.MAX_TARGETS:
        raise ValueError(f"links may describe at most {links.MAX_TARGETS} targets")
    captures = store.Captures()
    for target, encoded in files_raw.items():
        if len(target) > MAX_SOURCE_PATH_LENGTH or not isinstance(encoded, str):
            raise ValueError("links.files maps a target path to base64 file content")
        try:
            captures.files[target] = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f"links.files[{target[:80]!r}] is not valid base64") from None
    for target, reason in reasons_raw.items():
        if len(target) > MAX_SOURCE_PATH_LENGTH or not isinstance(reason, str):
            raise ValueError("links.reasons maps a target path to a reason string")
        captures.reasons[target] = reason[: store.MAX_LINK_REASON_LENGTH]
    return captures


class FramingError(Exception):
    """Request framing (Content-Length) was missing or invalid."""


class PayloadTooLargeError(Exception):
    pass


def lan_addresses() -> list[str]:
    """Best-effort list of this host's LAN IPv4 addresses for the startup banner.

    Two sources: a UDP "connect" to a TEST-NET address (no packets are sent —
    it only asks the routing table which local address WOULD be used, which
    finds the primary NIC even when the hostname doesn't map to it, common on
    laptops), plus the classic getaddrinfo(hostname) sweep.
    """
    addresses: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sock:
            probe_sock.connect(("192.0.2.1", 80))  # TEST-NET-1; routing lookup only
            addr = str(probe_sock.getsockname()[0])
            if is_lan_client(addr) and not addr.startswith("127."):
                addresses.append(addr)
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = str(info[4][0])
            if is_lan_client(addr) and not addr.startswith("127.") and addr not in addresses:
                addresses.append(addr)
    except OSError:
        pass
    return addresses


def serve(
    host: str,
    port: int,
    *,
    data_dir: Path,
    ds_dir: Path,
    default_author: str,
    mdns: bool = False,
    mdns_name: str = "md-review",
    theme: str = "system",
) -> None:
    if not ds_dir.is_dir():
        raise SystemExit(f"ERROR: design-system assets not found at {ds_dir}")
    if not (1 <= port <= 65535):
        raise SystemExit(f"ERROR: port must be between 1 and 65535, got {port}")
    if theme not in THEMES:
        raise SystemExit(f"ERROR: unknown theme '{theme}' — expected one of: {', '.join(THEMES)}")
    store.ensure_data_dir(data_dir)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((host, port))
    except socket.gaierror as exc:
        raise SystemExit(f"ERROR: cannot resolve bind host '{host}': {exc}") from None
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot bind {host}:{port} ({exc}). Already in use? Pass --port <free-port>") from None
    finally:
        probe.close()

    responder = None
    advertised: str | None = None
    extra_names: frozenset[str] = frozenset()
    if mdns:
        from . import mdns as mdns_mod

        try:
            clean_name = mdns_mod.validate_mdns_name(mdns_name)
        except ValueError as exc:
            raise SystemExit(f"ERROR: {exc}") from None
        addresses = lan_addresses()
        if not addresses:
            raise SystemExit(
                "ERROR: --mdns needs at least one LAN IPv4 address to advertise, none found. "
                "Run without --mdns, or fix this machine's network config."
            )
        try:
            responder, advertised = mdns_mod.advertise(clean_name, addresses)
            extra_names = frozenset({advertised.lower()})
        except OSError as exc:
            raise SystemExit(f"ERROR: cannot start mDNS responder (multicast unavailable on this host?): {exc}") from None

    server = ReviewServer(
        (host, port),
        ReviewHandler,
        data_dir=data_dir,
        ds_dir=ds_dir,
        default_author=default_author,
        extra_host_names=extra_names,
        theme=theme,
    )
    print(f"md-review {__version__} -> http://{host}:{port}/")
    for addr in lan_addresses():
        print(f"  LAN URL  : http://{addr}:{port}/")
    if advertised:
        print(f"  NAME     : http://{advertised}:{port}/  (mDNS — use this from any device)")
    print(f"  data dir : {data_dir}")
    print(f"  ds assets: {ds_dir}{' (vendored snapshot)' if ds_dir == vendored_ds_dir() else ' (external)'}")
    theme_note = "follows each device's OS light/dark preference" if theme == "system" else "server default; viewers can override per device"
    print(f"  theme    : {theme} ({theme_note})")
    print("  guard    : LAN-only — non-local clients refused (no opt-out)")
    if host not in ("127.0.0.1", "::1"):
        print("  WARNING  : reachable by your whole LAN. Do NOT put a public reverse proxy in front of md-review —")
        print("             proxied clients arrive as loopback/private and the guard cannot detect that.")
        print("             For remote access use a VPN (Tailscale/WireGuard), which passes the guard naturally.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nmd-review stopped")
    finally:
        if responder is not None:
            responder.stop()
