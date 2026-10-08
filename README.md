# md-review

**Review markdown documents from any device on your network.** Point
md-review at a `.md` file and it renders a clean reading page where every
paragraph, heading, list item, table row, and code block is commentable —
highlight any text to comment on exactly that span. Comments are stored as
plain JSON on the server, so teammates (or your AI agents) can read them
back programmatically. Built for reviewing design docs, specs, and
agent-written documents from your phone or laptop.

Zero dependencies. Python 3.10+. Windows, macOS, Linux.

## Install

```bash
uv tool install git+https://github.com/robeotx/md-review
```

(No `uv`? `pipx install git+https://github.com/robeotx/md-review` or
`pip install git+https://github.com/robeotx/md-review` work too.)

## Get reviewing in 60 seconds

```bash
# 1. Start the server on your LAN (with a friendly name)
md-review serve --host 0.0.0.0 --mdns

# 2. Render any markdown file
md-review render README.md

# 3. Open from any device on the network
#    → http://md-review.local:8779/   (or the LAN IP printed at startup)
```

Click the 💬 button on any block — or highlight text — and write. Comments
persist across re-renders and land in
`~/.local/share/md-review/rendered/<doc-id>/comments.json`, a plain JSON
array anything can read.

That's the whole core loop. Everything below is detail.

---

## Why you might want this

- **Comment on anything, persistently.** Dual-key anchors (content hash +
  position) keep comments attached to the right element across edits;
  orphaned comments are never deleted, just marked.
- **Provenance on every render.** Each document records which git repo,
  branch, and path it came from, the working directory of whoever rendered
  it, and the agent session id when rendered by an AI agent (Claude Code,
  Codex, and friends auto-detect). Invaluable when your document flow spans
  many repos.
- **LAN-only by construction.** No accounts, no cloud, no tracking — and no
  accidental exposure: the server refuses non-local clients in code, with
  no opt-out. See the security model below.
- **Agent-native.** `POST /api/render` lets agents on other machines render
  into one central server; the comment channel is plain JSON agents already
  know how to read.
- **Pleasant to read.** A real design system with light, dusk, and dark
  themes (per-device toggle, no flash-of-wrong-theme), and a friendly
  `http://md-review.local` name via built-in mDNS.

## How it works

```
md-review render design.md ──► <data-dir>/rendered/design-<hash>/
                                 ├── index.html      ← the review page
                                 ├── manifest.json   ← title, provenance, times
                                 ├── anchors.json    ← every commentable element
                                 ├── comments.json   ← the comment channel
                                 ├── links.json      ← where each relative link points
                                 └── files/          ← linked files captured at render

md-review serve ──► review pages + JSON API, LAN-only
```

One server holds your whole review library; the index page lists every
rendered document with its repo, session, and open-comment count.

### Rendering from other machines

Agents (or you) on another machine render straight into the server — no
shared filesystem needed:

```bash
md-review render design.md --server http://md-review.local:8779
```

Provenance is collected on the machine where the document lives and shipped
with the render.

### Relative links

Links written relative to the source file (`[report](reports/run.md)`,
`![chart](img/chart.png)`) work on the rendered page:

- **A linked doc that is published** opens its review page, `#section`
  included. This is decided when the link is clicked, so a doc published
  later still works.
- **A linked file that isn't published** opens a read-only copy captured at
  render time (Markdown and text are shown as plain text; images display
  inline). Re-render to refresh the copy.
- **A target that can't be shown** is marked ⊘ on the page; clicking it says
  why (outside the repo, too large, binary, or looks like a credential).

Capture happens on the machine where the document lives, including with
`--server`; the server never reads files from its own disk. `render` prints
what it captured and what it skipped to stderr. Credential-like files
(`.env`, keys, `.aws/`, `.ssh/`, `.kube/`, token-shaped contents, …) are
never captured; pass `--no-capture` to capture nothing. Limits: 2 MiB per
file, 8 MiB per document, 500 targets, 2 GiB across the store.

GitHub-style heading fragments (`#install`) resolve too, within a doc and
across docs.

Known edges:

- A fragment that is ALSO md-review's own id for a different heading goes
  to md-review's heading. The outline links depend on those ids.
- A link through a symlinked `.md` alias opens the captured copy, not the
  real file's review page.
- Capture never follows a symlink that appears mid-capture on POSIX.
  Windows lacks the needed directory-handle API, so it falls back to a
  single resolved open.
- The render lock that keeps a local render and the server from clobbering
  each other's captured files is POSIX-only.

### Commenting

- **Block comments**: every block has a 💬 button on hover.
- **Span comments**: highlight text → Comment. The span is highlighted and
  linked to the thread.
- **Threads**: draggable, resizable popovers; resolve/reopen; an inbox
  drawer with open/resolved/all filters.
- **Author names**: a small name field per device (stored in localStorage);
  the server's `--default-author` applies when empty.

## LAN-only security model

md-review has **no authentication** — it's a personal/small-team tool. Its
safety is a hard network boundary enforced in code:

- **Explicit client-IP allowlist**: loopback, RFC-1918 private, link-local,
  IPv6 ULA, and RFC 6598 shared space (Tailscale) — nothing else, with
  IPv4-mapped normalization. Refused pre-parse *and* per-handler.
  **There is no flag to disable this.**
- **Host-header validation** (DNS-rebinding defense): IP-literal Hosts must
  be LAN addresses; names must be localhost, the machine hostname, an
  mDNS-advertised name, or `MD_REVIEW_EXTRA_HOSTS`.
- **Browser-attack tripwires**: POSTs require `application/json` (forces a
  CORS preflight that never succeeds cross-origin), cross-site
  `Origin`/`Sec-Fetch-Site` rejected, pre-body rejections close the
  connection (no request smuggling), framing strictly enforced.
- **Page hygiene**: HTML escaped everywhere, embedded JSON `<`-escaped,
  link schemes allowlisted (`javascript:` etc. render inert), CSP with
  `connect-src 'self'`, `X-Frame-Options: DENY`.
- **Resource bounds**: request bodies capped, markdown/sourcePath/title
  capped, per-connection read timeout, connection concurrency cap,
  document and comment ceilings.

**The honest residual boundary**: a reverse proxy, load balancer, or
source-NAT makes remote clients arrive *as* loopback/private — no
source-address check can detect that. **Do not proxy md-review publicly.**
For remote access use a VPN (Tailscale works out of the box; its
`100.64.0.0/10` range is in the allowlist).

**Trust model**: anyone who can reach the server can read every document
and post/resolve comments, and provenance (which namespaces doc ids) is
client-asserted, so a LAN peer can re-render over an existing document.
Only share it on networks whose members you trust with your documents.

## Friendly LAN names (mDNS)

`--mdns` runs a tiny built-in mDNS responder (pure Python — no Avahi or
Bonjour to install) so devices use `http://md-review.local:8779/` instead
of an IP. Customize with `--mdns-name review` (→ `review.local`); a name
collision falls back to `md-review-<hostname>.local` with a loud notice.

Client support: macOS/iOS/Windows 10+/most Linux desktops resolve `.local`
natively. **Stock Android does not** — use the printed LAN IP, Tailscale,
or a DNS entry on your router.

## Provenance

Every render stamps the manifest (and the page's **Source** panel) with:

| field | meaning |
|---|---|
| `sourceAbsPath` / `sourceRepoRelPath` | where the markdown lives |
| `sourceRepoRoot` / `Name` / `Branch` / `Remote` | its git repo (auto-detected; remotes credential-stripped) |
| `agentCwd` | cwd of the rendering process (an agent's cwd can differ from the doc's repo) |
| `agent` | agent harness (`$AI_AGENT`, or `--agent`) |
| `sessionId` | agent session id — `--session-id` > `$MD_REVIEW_SESSION_ID` > `$CLAUDE_CODE_SESSION_ID` / `$CODEX_SESSION_ID` / `$AGENT_SESSION_ID` / `$KIMI_SESSION_ID` |
| `hostname` / `user` | machine + OS user |
| `receivedFrom` / `receivedAt` | server receipt stamp (remote renders) |

## Themes

Three palettes: **light**, **dusk** (Dusk Slate), **dark** (Warm
Chalkboard). The glyph picker (☼ ◐ ☾) in the topbar sets your device only
(localStorage). Server-wide default: `md-review serve --theme dark`
(or `MD_REVIEW_THEME`). Default `system` follows each device's
`prefers-color-scheme` (OS dark → dark).

## Configuration

Everything is flag > env > default; nothing is hardcoded:

| flag | env | default |
|---|---|---|
| `--data-dir` | `MD_REVIEW_DATA_DIR` | `~/.local/share/md-review` |
| `--ds-dir` | `MD_REVIEW_DS_DIR` | vendored design-system snapshot |
| `--default-author` | `MD_REVIEW_AUTHOR` | your OS username |
| `--server` | `MD_REVIEW_SERVER` | render locally |
| `--host` / `--port` | — | `127.0.0.1` / `8779` |
| `--mdns` / `--mdns-name` | `MD_REVIEW_MDNS` / `MD_REVIEW_MDNS_NAME` | off / `md-review` |
| `--theme` | `MD_REVIEW_THEME` | `system` |
| — | `MD_REVIEW_EXTRA_HOSTS` | extra Host names the server accepts |

**One server per data dir.** Writes are serialized and every store file is
written atomically, but two servers pointed at one store can lose each
other's updates.

## HTTP API

| route | method | purpose |
|---|---|---|
| `/` | GET | document index (HTML) |
| `/health` | GET | liveness, version, doc count |
| `/api/docs` | GET | all manifests + comment counts |
| `/api/render` | POST | render `{markdown, sourcePath, title?, provenance?, links?}` (`links`: `{files: {path: base64}, reasons: {path: why}}` or `{disabled: true}`) |
| `/link/<doc-id>/<key>` | GET | follow a relative link: redirect to a published doc, show a captured copy (`?raw=1` for raw text), or explain why it's unavailable |
| `/comments?doc=<id>` | GET | comment array for one doc |
| `/comments` | POST | append `{docId, anchor, text, quote?, author?}` |
| `/comments/resolve` | POST | `{docId, id, resolved}` |
| `/rendered/<doc-id>/<file>` | GET | `index.html`, `anchors.json`, `manifest.json`, `comments.json` |
| `/ds/<path>` | GET | read-only design-system assets (css/fonts/svg) |

A comment record: `{id, doc_id, doc_path, anchor, quote, text, author,
created_at, resolved}`.

## Markdown subset

ATX headings, paragraphs, fenced code, blockquotes, ordered/unordered lists
(including loose lists and wrapped continuations), GFM tables (with
`\|`-escaped and code-span pipes), horizontal rules; inline `**bold**`,
`*italic*`, `` `code` ``, `[links](...)`, and relative `![images](...)`
(see [Relative links](#relative-links)). Known edges: no setext headings,
nested lists flatten, external images render as `!`-prefixed links (the page
loads no third-party content), `)` truncates link URLs, no
autolink/strikethrough/task lists, non-allowlisted link schemes render inert.

## Running as a service

Linux (systemd user unit + linger = starts at boot):

```ini
# ~/.config/systemd/user/md-review.service
[Unit]
Description=md-review LAN markdown review server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/md-review serve --host 0.0.0.0 --port 8779 --mdns
Restart=on-failure
RestartSec=3
Environment=MD_REVIEW_AUTHOR=YourName

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now md-review.service
loginctl enable-linger "$USER"
```

On Windows use Task Scheduler, on macOS a LaunchAgent.

## Development

```bash
git clone https://github.com/robeotx/md-review
cd md-review
uv venv && uv pip install -e ".[dev]"
python -m unittest discover -s tests -v
ruff check src tests
```

CI runs the suite on ubuntu/windows/macos across Python 3.10–3.13, plus
ruff, pyright, and a wheel asset check. See `CHANGELOG.md` for history and
`SECURITY.md` for the threat model and how to report issues.

The vendored design system in `src/mdreview/assets/ds/` (see `NOTICE`) is a
snapshot of a design system; `--ds-dir` points the server at a
live checkout instead. Fonts are OFL-licensed (Atkinson Hyperlegible Next,
JetBrains Mono).

## License

MIT — see `LICENSE`.
