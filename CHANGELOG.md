# Changelog

All notable changes to md-review. Format loosely follows Keep a Changelog;
the project is pre-1.0, so minor bumps may include breaking changes (each
called out explicitly).

## [Unreleased]

### Added

- **Search on the index page.** A search box finds text across rendered
  docs, standalone HTML pages in the store, captured text files and
  comments. Sort by last modified (default) or created; filter by repo
  (multi-select) and date range (UTC days). Results are grouped by doc, the
  search state lives in the URL, and the type pill tints each file kind
  (md, html, code, data, image, comment). Served by the new
  `GET /api/search`. The index is in memory and built from the store on
  start; it syncs at most every 2 s on the query path, so a fresh render can
  take up to one sync to appear. Searching is substring-based (no stemming,
  no OR or phrases); text past 2 MB per item is searchable up to that cap
  and marked partial.
- A doc whose `createdAt` is more than a day in the future stays above all
  others in every search and listing. The margin keeps clock skew from
  pinning anything.

## [0.5.0] — 2026-10-07

### Added

- **Relative links work on rendered pages.** A rendered page lives at
  `/rendered/<doc-id>/`, so every repo-relative link used to 404. Links and
  images are now resolved against the source file. Published docs open their
  review page, decided at click time so later publishes count.
  Unpublished files open a read-only copy captured at render time.
  Targets that can't be shown are marked ⊘ and explain why. Served through
  the new `GET /link/<doc-id>/<key>`.
- **Publish-time capture.** `md-review render` (local or `--server`) copies
  linked files on the publishing machine and prints what it captured and
  skipped to stderr. Credential-like paths and contents are never captured.
  New `--no-capture` flag. Limits: 2 MiB per file, 8 MiB per document,
  500 targets, and a 2 GiB store-wide quota that degrades to "unavailable"
  rather than failing the render.
- **Relative images render inline** when captured (SVG is served sandboxed).
- **GitHub-style `#fragments` resolve.** Heading ids slug the whole heading
  path, so `#install` used to miss. Each heading now also carries its
  GitHub-style slug, and the page falls back to it.

### Changed

- `/api/render` accepts an optional `links` field and has its own 16 MiB
  body cap. Every other route keeps 4 MiB. Only one render over 4 MiB runs at
  a time; others get 503 before their body is read. Older clients that send
  no `links` still get working links to published docs.

## [0.4.3] — 2026-08-17

### Fixed

- **Comments no longer re-attach to text they were not written about**
  (orphan-on-mismatch). `semanticKey` — heading path + element kind +
  ordinal — is a POSITION key, so after a rewrite it resolved to whatever
  now occupied that slot regardless of what the slot said, and the stored
  `contentHash` was never checked. Reported in live use: a full document
  rewrite left old comments visually attached to brand-new, unrelated
  paragraphs. The stored `contentHash` is now a precondition of any
  positional re-bind, so a comment whose anchor text changed **detaches**
  instead of misattributing: it shows in the Comments drawer under a new
  **Detached** filter (plus a topbar count) carrying its original quote, and
  stays in `comments.json` untouched. Read/display-side only — the anchor
  write format is unchanged, existing stores keep working, and anchors
  predating `contentHash` are exempt.
- Consequence worth knowing: editing the prose of a commented element now
  detaches its comments (previously they silently followed the slot).
  Already-rendered pages keep the old behavior until re-rendered.

## [0.4.2] — 2026-08-01

### Fixed

- **Mutable routes are now `Cache-Control: no-store`.** A re-render
  overwrites a doc's files at the SAME url, and the index, `/api/docs`,
  `/health`, and each doc's manifest/anchors change whenever anything is
  rendered or commented on — but none of them sent cache directives, so a
  browser was free to serve a stale cached copy that actively lied (missing
  docs, pre-fix pages). Only `/ds/` assets stay cacheable (vendored,
  content-stable; re-downloading fonts on every page view would be waste).
  `/comments` and `/rendered/*/comments.json` were already no-store.

## [0.4.1] — 2026-08-01

### Changed

- **Theme picker is now glyphs, not text** — the toggle became a segmented
  ☼ ◐ ☾ picker (same vocabulary as the bundled design system's Day/Dusk/Night
  picker), on both the doc page topbar and the index header. Direct-set
  instead of cycle-through; active glyph follows whatever theme is actually
  painted.

## [0.4.0] — 2026-08-01

### Added

- **Dusk + dark themes.** The vendored design system already shipped three
  token-driven palettes (light, Dusk Slate, Warm Chalkboard); md-review now
  exposes them. `md-review serve --theme light|dusk|dark|system` (env
  `MD_REVIEW_THEME`, default `system`) sets the server-wide default.
  Explicit themes are stamped as `data-theme` on `<html>` on every page the
  server serves — doc pages included, stamped at SERVE time, so docs
  rendered before the flag existed pick it up. Under `system` nothing is
  stamped and a tiny inline `<head>` bootstrap follows the device's
  `prefers-color-scheme`; an OS dark preference maps to **dark** (Warm
  Chalkboard) — `prefers-color-scheme` is binary and dusk is a mid-tone
  opt-in, reachable via the toggle or `--theme dusk`.
- **Per-device theme override.** A topbar toggle on the doc page (and a
  matching text button on the index) cycles light → dusk → dark, persists
  to localStorage (`mdReviewTheme`), and beats the server default on that
  device only. The bootstrap runs before the stylesheets load, so overrides
  and system resolution apply with no flash of the wrong theme.
- **Token-coverage regression test**: every `var(--*)` in the tool's own
  CSS is asserted to be defined for all three palettes (at `:root` or in
  the theme's `[data-theme]` block).

### Fixed

- Dark-theme readability in the tool's own CSS: the highlight-peek button's
  foreground was hard-coded `#fff` on an accent that becomes light salmon
  under dusk/dark (now the themed surface token); the provenance panel
  shadow uses the themed `--shadow-pop` instead of a paper-tuned rgba; the
  comment error text switches from paper-only `--danger-mark` to the themed
  `--danger` on the dark palettes.

## [0.3.2] — 2026-08-01

### Fixed

- **VPN clients (Tailscale) were refused by the LAN guard** despite the
  docs promising VPN remote access "passes the guard naturally": the
  allowlist now includes RFC 6598 shared address space (`100.64.0.0/10`,
  the CGNAT range overlay VPNs assign from — not Internet-routable).
  Boundary tested: `100.128.0.1` (outside /10) remains refused.

## [0.3.1] — 2026-08-01

### Fixed

- **`.local` names didn't resolve for real resolvers** (found via a
  phone): the responder answered every query by multicast, but RFC 6762
  §5.4 requires a UNICAST answer for "legacy unicast queries" (any source
  port other than 5353 — what systemd-resolved, Windows' mDNS client, and
  Android's Network Service Discovery send) and for QU-bit questions.
  Multicast answers to those queriers are silently discarded. Verified
  live: an ephemeral-port query for md-review.local now gets its answer
  back at that exact port.

## [0.3.0] — 2026-08-01

### Added

- **Friendly LAN names via built-in mDNS** — `md-review serve --mdns` runs
  a pure-Python RFC 6762 responder (no Avahi/Bonjour/platform service;
  zero new dependencies, works on Windows/macOS/Linux), so LAN devices use
  `http://md-review.local:8779/` instead of an IP. `--mdns-name` /
  `MD_REVIEW_MDNS_NAME` to customize; collision on the LAN falls back to
  `<name>-<hostname>.local` with a loud warning; the advertised name is
  automatically accepted by Host validation. (Stock Android still needs the
  IP or a router DNS entry — documented.)

### Fixed

- A ≥4301-digit ordered-list marker no longer crashes the renderer
  (CPython `int()` digit cap; server returned a clean 500,
  CLI showed a raw traceback).

## [0.2.1] — 2026-08-01

Independent deep review against 0.2.0 found a fast path to a ship-ready
state. All its findings are fixed here.

### Security

- **P0 — request smuggling past the CSRF tripwires**: pre-body rejections
  (415 Content-Type, 403 Origin/Sec-Fetch-Site/Host, 404 unknown route) now
  close the connection. Previously the undrained body was parsed as the next
  request on the keep-alive socket, bypassing every header gate from any
  internet page. GET/HEAD with a body is now rejected (400 + close).
- **P1 — comment caps bypassed via `anchor`**: the anchor object is now
  whitelisted (10 known fields), each string capped, `headingPath` bounded,
  `quote` capped; unknown keys dropped. Per-document comment ceiling
  (5,000).
- **P1 — unbounded `/api/render`**: markdown capped at 2 MiB (413),
  sourcePath at 1,024 chars (400), title truncated at 300 chars, doc-id
  slug clamped; request body ceiling lowered 16 MiB → 4 MiB.
- Link hrefs are unescaped before the scheme check and escaped exactly once
  on emission — `[x](javascript&#58;…)` is inert, and multi-parameter URLs
  (`?a=1&b=2`) work again (they were double-escaped and broken).
- Backslash URLs (`\\host`) classify like `//host` (the browser's own rule).
- `/ds/` NUL bytes rejected (400) instead of dropping the connection with a
  traceback.
- Error bodies no longer disclose server-absolute paths; details go to the
  server log.
- Host headers with non-numeric port suffixes refused.
- `comments.json` keeps its 0600 mode across writes (chmod moved to the
  atomic tmp file); per-doc dirs are 0700.
- Response hardening headers on pages: CSP (with `connect-src 'self'` as
  the exfiltration barrier), X-Frame-Options DENY, Referrer-Policy;
  `Cache-Control: no-store` on the comments API.
- Operator log sanitizes control characters from client-controlled request
  lines.
- Provenance git invocations resolve `git` via `shutil.which` at import
  (Windows current-directory search-order hijack).
- `_send_file` reads fully before responding (Windows `os.replace`-over-
  open-file race; also fixes a stat-then-open size desync).

### Cross-OS

- `sourceRepoRelPath` is POSIX-normalized like `sourcePath` (Windows CI
  was red on first push; the test asserting a native `agentCwd` was fixed
  to assert the resolved form).
- UTF-8 BOM silently stripped on render (`utf-8-sig`) — the documented
  footgun is gone.
- Store writes use `newline=""` (byte-identical across OSs).

### OSS readiness

- CI: syntax-warning gate now force-recompiles (the old `-W error` test run
  was a no-op against pip's byte-compiled install), pyright step added,
  ruff pinned, OS matrix (ubuntu × py3.10–3.13, windows/macos × py3.10 &
  3.13).
- Added `SECURITY.md` (threat model + reporting) and this changelog.
- `.gitignore` covers `.DS_Store`/`Thumbs.db`/`.idea`/`.vscode`; `__init__` docstring no
  longer claims "self-contained" pages.
- UI robustness: legacy/hand-edited comments can't break the drawer;
  long unbroken comment text wraps in the popover.

## [0.2.0] — 2026-07-31

Independent dual deep review → full remediation:
script-embed XSS escaping, link scheme allowlist, CSRF defenses (415 /
Origin / Sec-Fetch-Site / Host validation), explicit-CIDR LAN guard with
IPv4-mapped normalization, git-remote credential stripping, repo-namespaced
doc ids (**breaking**: repo docs get new ids),
single-element anchor resolution, store global-lock/atomic/fsync writes,
provenance schema normalization, validation caps, read timeout + connection
semaphore, HEAD=GET parity, framing rules, NUL stripping, heading-level
ancestry, `<ol start>`, OFL license vendoring, CI, cross-OS fixes (cp1252
console guard, POSIX display paths).

## [0.1.0] — 2026-07-31

Initial standalone packaging of md-review: zero-dependency renderer + comment channel + LAN-only server,
provenance tracking, vendored design system, 56 tests.
