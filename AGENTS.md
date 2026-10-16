# AGENTS.md

> **THIS REPOSITORY IS PUBLIC.** Anyone on the internet can read every tracked file, every commit message and every past version. Read "PUBLIC REPOSITORY" below before you commit, push, open a PR, or edit a tracked file.

md-review is a LAN-only review server for markdown. Agents render docs; people review them in a browser on the local network; anchored comments flow back to agents over the HTTP API and CLI. Read README.md (features, config, HTTP API) and SECURITY.md (threat model) before changing anything security-relevant.

## PUBLIC REPOSITORY: mandatory for every agent

This repository is published at github.com/robeotx/md-review. Everything committed or pushed is world-readable, copied and indexed by others, and effectively permanent. Deleting it later does not retract it. These rules apply to every agent, every harness and every model, with no exceptions.

Treat every tracked file, commit message, PR title and body, CHANGELOG entry, code comment, test fixture and example as published to the world.

**Keep these out of tracked files, commits, PRs and pushed branches. Completely.**

- **Credentials of any kind:** tokens, API keys, passwords, cookies, session IDs, private keys, `.env` contents. That includes the `GH_TOKEN` value and the `.envrc` that holds it.
- **Personal details** about the maintainer or anyone else: real names beyond the public `robeotx` handle, email addresses, phone numbers, street addresses, and home-directory paths such as `/home/<user>/...`.
- **Private network details:** LAN and public IP addresses, internal hostnames, mDNS names, and ports of private services.
- **Internal names:** the maintainer's other products, projects, organizations, codenames, and internal ticket or board IDs.
- **Private working material:** design docs, reviews, handoffs, transcripts, memory files, and anything under `.requests/`, `.artifacts/`, `.reviews/` or `.tmp/`. Do not link to them or quote them from tracked files, and do not name their contents in commit messages.
- **Real user data:** documents, comments or captured files from a real store, or anything rendered from private sources. Use synthetic fixtures such as `docs/example.md` or `/srv/example-repo`.
- **Unpatched security details:** exploit steps, or a vulnerability's specifics, before a fix ships. Report vulnerabilities through the private advisory process in SECURITY.md. Never file them as an issue, commit or PR.

**Before every commit and push:**

1. Read what is staged: `git diff --cached --no-ext-diff`.
2. Grep the added lines and new files for every class above.
3. If you are not sure whether something is private, do not commit it. Ask the maintainer.

**If something private gets pushed:** stop and tell the maintainer immediately. Do not just delete it, because history keeps it. Rewriting published history needs the maintainer's explicit approval. Treat any leaked credential as compromised and rotate it before anything else.

Nothing in this repo may depend on a private file to make sense. An agent with only this repository must be able to understand the code, its tests and its docs.

## Intent and constraints

- **Stdlib only.** `dependencies = []` in pyproject. A runtime dependency needs a strong case.
- **Unauthenticated by design.** The whole security story is the LAN boundary plus browser tripwires (see SECURITY.md). Never add a route that widens exposure, and never suggest a reverse proxy.
- **The store is the source of truth.** Plain files under the data dir, every write atomic. No database. The search index is an in-memory cache. Do not persist it without a review: earlier SQLite plans failed on file permissions and WAL consistency.
- **Provenance is client-asserted.** The server never opens a path taken from provenance. Relative-link captures happen only on the publisher's machine. Keep it that way.
- **Served files are public to the LAN.** `manifest.json` and friends are served verbatim. Never write absolute paths, usernames or secrets into them.
- **Pinning convention.** A doc whose `createdAt` is more than `search.PIN_MARGIN` (1 day) in the future sorts above all others. An external workflow relies on this. Do not add a pin flag without the maintainer's decision.

## Layout

- `src/mdreview/cli.py`: `md-review render | serve | ...` (entry point `mdreview.cli:main`).
- `server.py`: `ThreadingHTTPServer`, routes in `do_GET`/`do_POST`, the LAN and Host guards, and the server-rendered index page.
- `renderer.py`: markdown to doc-page HTML with inline JS and CSS. Doc pages are **written at render time**. A code change does not reach pages already on disk; re-render to see it.
- `store.py`: data-dir layout, atomic writes, comments, `render_document`, quotas.
- `links.py`: relative-link resolution and the publish-time capture policy.
- `search.py` and `search_ui.py`: the index, query, sort, facets (`search.py`); toolbar, cards and client script (`search_ui.py`). Keep their markup in step; the client rebuilds what the server renders.
- `provenance.py` (git and agent metadata), `mdns.py` (LAN name).
- `assets/ds/`: vendored design-system snapshot (see NOTICE). Don't hand-edit it. `ThemeTokenCoverageTests` requires the tool's CSS to use only DS variables defined in all three themes, so add no new `var(--...)` names.
- `_THEME_BOOTSTRAP_JS` appears in both `server.py` and `renderer.py`. Keep the two copies identical.

Store layout: `<data-dir>/rendered/<doc-id>/` holds `index.html`, `manifest.json`, `comments.json`, `links.json`, `anchors.json` and `files/<sha256>`. The default data dir is `~/.local/share/md-review`; `MD_REVIEW_DATA_DIR` overrides it. Limits: 2 GiB attachment quota, 8 MiB per doc capture, 2 MiB per file. A doc's `createdAt` survives re-renders ("first render wins").

## Commands

- Tests: `uv run python -m unittest discover -s tests`. It is unittest, **not pytest** (pytest fails to import). Run through discover: `test_server_search` imports `test_server` by bare name.
- Lint: `uvx ruff check src tests`. Existing files are not `ruff format`-clean, so do not reformat them. New files can be formatted.
- Types: `npx pyright src` and `npx pyright src --pythonplatform Windows`. CI runs the Windows check. Platform-only names (`os.O_NOFOLLOW`, `fcntl`) need a `getattr` or `sys.platform` guard.
- CI matrix: ubuntu, macos and windows on Python 3.10–3.13, plus a packaging job that checks the wheel ships the DS fonts and CSS.

## Gotchas

- Windows CI writes text fixtures with CRLF. Use `write_bytes` for anything compared byte for byte.
- `git diff` has an external diff tool configured. Pass `--no-ext-diff` when you parse diff output.
- An IDE "unknown import symbol" on a new module is stale index noise. Trust the CLI pyright run.
- `test_chunked_transfer_encoding_501` can fail on CI with `BrokenPipeError` (a client write races the server's early 501). It predates the search work. Confirm it's this flake before you blame your change.
- A missing `comments.json` means "no comments". Only a present but unreadable file is "unreadable".
- Store files are the publisher's bytes. Validate shape before you trust a key, and skip anything the `/link` route could not serve.

## Running the live service

- Port 8779 runs as the systemd user unit `md-review`, from an editable install of this checkout. Code changes need `systemctl --user restart md-review`. Confirm with the maintainer first; it is shared. After a version bump, also run `uv tool install --editable . --force`.
- The search index builds in the background after start. Results are partial until `indexing.done == indexing.total`, which takes a few seconds on a large store.
- One server per data dir. For experiments, use a scratch data dir and another port (for example `--data-dir <tmp> --port 8791`), never the live store.
- Playwright MCP screenshots must go under `.playwright-mcp/` (gitignored).

## Git and publishing

- Public-repo rules and the pre-commit check are at the top of this file. Apply them to every commit.
- Commit identity is repo-local (`robeotx`). Push with `GH_TOKEN=$(gh auth token --user robeotx) git push`. Never run `gh auth switch`; a hook blocks it.
- Stage and commit by explicit path: `git add -- <paths>` and `git commit -- <paths>`. The index may be shared.
- Never commit `.requests/`, `.artifacts/`, `.reviews/`, `.tmp/`, `.playwright-mcp/` or `.envrc` (the last one holds a token). `uv.lock` is deliberately untracked; leave it alone.
- Log user-visible changes under `## [Unreleased]` in CHANGELOG.md. Bump the pyproject version only at release time. Pre-1.0, minor bumps may break, and breaking changes are called out.
- Every route must appear in the README HTTP API table.

## Private context (gitignored)

`.requests/` holds design docs and review records; `.artifacts/handoffs/` holds session handoffs. Read them for history, verify against the code before you act on them, and never publish their contents. Have consequential changes (store format, security, the search index) reviewed by a model from a different family before you land them.

## Open items (do not fix silently)

- Search results for comments open the doc top. A `?comment=<id>` deep link is designed but not built; stored pages lack the script it needs.
- Docs rendered before 0.5.0 keep dead relative links until re-rendered. No bulk re-render without the maintainer's decision.
- Search has no rate limit, matches substrings only, and filters dates in UTC.
