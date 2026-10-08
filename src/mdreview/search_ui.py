"""Index-page markup for search: toolbar, result cards, pager, and the client script.

The server renders the page for whatever URL state it was given (q, repo,
sort, from, to, offset), so a search survives reload and works without JS.
The client script re-renders the SAME markup from ``/api/search`` on each
change. Keep the two in step: a class or structure change goes in both.

Tones (the faint type pill) live in one table here and are injected into the
client script, so Python and JS cannot disagree about a file's colour.
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urlencode

from mdreview import search

TONE_BY_EXT: dict[str, str] = {
    "md": "md",
    "markdown": "md",
    "html": "html",
    "htm": "html",
    "py": "code",
    "js": "code",
    "mjs": "code",
    "ts": "code",
    "tsx": "code",
    "jsx": "code",
    "sh": "code",
    "bash": "code",
    "go": "code",
    "rs": "code",
    "rb": "code",
    "java": "code",
    "c": "code",
    "h": "code",
    "cc": "code",
    "cpp": "code",
    "hpp": "code",
    "cs": "code",
    "swift": "code",
    "kt": "code",
    "sql": "code",
    "css": "code",
    "json": "data",
    "jsonl": "data",
    "csv": "data",
    "tsv": "data",
    "yaml": "data",
    "yml": "data",
    "toml": "data",
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "webp": "image",
    "svg": "image",
    "comment": "comment",
}
DEFAULT_TONE = "text"


def tone_for(ext: str) -> str:
    return TONE_BY_EXT.get(ext, DEFAULT_TONE)


def _short_ts(iso: str | None) -> str:
    return iso[:16].replace("T", " ") if iso else "unknown"


def _mark(snippet: str | None, terms: list[str]) -> str:
    """Escaped snippet with each term wrapped in <mark>. Every part is escaped."""
    if not snippet:
        return ""
    if not terms:
        return f"<span class='snip'>{html.escape(snippet)}</span>"
    pattern = re.compile("(" + "|".join(re.escape(term) for term in terms) + ")", re.IGNORECASE)
    pieces: list[str] = []
    last = 0
    for found in pattern.finditer(snippet):
        pieces.append(html.escape(snippet[last : found.start()]))
        pieces.append(f"<mark>{html.escape(found.group(0))}</mark>")
        last = found.end()
    pieces.append(html.escape(snippet[last:]))
    return f"<span class='snip'>{''.join(pieces)}</span>"


def _repo_chip(doc: dict) -> str:
    repo = doc["repo"]
    if repo["key"] == search.STANDALONE_KEY:
        return "<span class='chip standalone'>standalone page</span>"
    if repo["key"] == search.UNKNOWN_KEY:
        return "<span class='chip'>Unknown repo</span>"
    branch = f":{html.escape(doc['branch'])}" if doc["branch"] else ""
    return f"<span class='chip repo'>{html.escape(repo['label'])}{branch}</span>"


def _count_chip(doc: dict) -> str:
    open_count = doc["openComments"]
    total = doc["totalComments"]
    if open_count is None:
        label = "comments unreadable"
    elif not total:
        label = "no comments"
    else:
        label = f"{open_count} open · {total} total"
    return f"<span class='chip count'>{html.escape(label)}</span>"


def render_card(group: dict, terms: list[str]) -> str:
    doc = group["doc"]
    tone = tone_for(doc["ext"])
    partial = (
        "<span class='chip partial' title='Only the first 2 MB of this item is searchable'>partial</span>"
        if doc["truncated"]
        else ""
    )
    session = doc["sessionId"]
    session_chip = (
        f"<span class='chip session' title='agent session id: {html.escape(session)}'>session {html.escape(session[:8])}</span>"
        if session
        else ""
    )
    agent_chip = f"<span class='chip agent'>{html.escape(doc['agent'])}</span>" if doc["agent"] else ""
    matches = ""
    if group["matches"]:
        rows = []
        for match in group["matches"]:
            rows.append(
                f"<li><span class='pill tone-{tone_for(match['ext'])}'>{html.escape(match['ext'])}</span> "
                f"<a href='{html.escape(match['url'])}'>{html.escape(match['title'])}</a> "
                f"{_mark(match['snippet'], terms)}</li>"
            )
        hidden = group["matchCount"] - len(group["matches"])
        if hidden > 0:
            rows.append(f"<li class='more'>+{hidden} more matches</li>")
        matches = f"<ul class='matches'>{''.join(rows)}</ul>"
    return (
        f"<li class='card'>"
        f"<div class='head'><span class='pill tone-{tone}'>{html.escape(doc['ext'])}</span>"
        f"<a class='title' href='{html.escape(doc['url'])}'>{html.escape(doc['title'])}</a>{partial}</div>"
        f"<div class='meta'><span>created {html.escape(_short_ts(doc['created']))}</span>"
        f"<span>modified {html.escape(_short_ts(doc['modified']))}</span>"
        f"<span class='path'>{html.escape(doc['sourcePath'])}</span></div>"
        f"<div class='chips'>{_repo_chip(doc)}{session_chip}{agent_chip}{_count_chip(doc)}</div>"
        f"{_mark(doc['snippet'], terms)}{matches}"
        f"</li>"
    )


def render_list(result: dict, terms: list[str], *, filtered: bool) -> str:
    if not result["groups"]:
        if not filtered:
            return "<li class='empty'>No documents rendered yet. Run <code>md-review render your-doc.md</code>.</li>"
        return "<li class='empty'>No matches. Try fewer terms or clear the filters.</li>"
    return "".join(render_card(group, terms) for group in result["groups"])


def render_repo_options(repos: list[dict], selected: set[str]) -> str:
    options = []
    for repo in repos:
        checked = " checked" if repo["key"] in selected else ""
        options.append(
            f"<label class='repo-option'><input type='checkbox' name='repo' value='{html.escape(repo['key'])}'{checked}> "
            f"{html.escape(repo['label'])} <span class='n'>{repo['count']}</span></label>"
        )
    return "".join(options)


def render_toolbar(state: dict, repos: list[dict], selected: set[str]) -> str:
    """The search form. ``state`` holds the raw q/sort/from/to the request carried."""
    sort_options = "".join(
        f"<option value='{value}'{' selected' if value == state['sort'] else ''}>{label}</option>"
        for value, label in (("modified", "Last modified"), ("created", "Created"))
    )
    summary = f"Repo ({len(selected)})" if selected else "Repo"
    return (
        "<form id='search-form' class='toolbar' role='search' method='get' action='/'>"
        f"<input id='search' name='q' type='search' value='{html.escape(state['q'])}' "
        "placeholder='Search docs, comments, files  ( / )' autocomplete='off' aria-label='Search'>"
        f"<select id='sort' name='sort' aria-label='Sort'>{sort_options}</select>"
        f"<details class='repo-filter'><summary id='repo-summary'>{summary}</summary>"
        f"<div id='repo-list' class='repo-list'>{render_repo_options(repos, selected)}</div></details>"
        f"<label>From <input id='from' type='date' name='from' value='{html.escape(state['from'])}'></label>"
        f"<label>To <input id='to' type='date' name='to' value='{html.escape(state['to'])}'></label>"
        "<a id='clear' href='/'>Clear</a>"
        "<noscript><button type='submit'>Search</button></noscript>"
        "</form>"
    )


def _page_url(state: dict, offset: int) -> str:
    params = {key: value for key, value in state.items() if value not in ("", None, [])}
    if offset:
        params["offset"] = str(offset)
    query = urlencode(params, doseq=True)
    return "/?" + query if query else "/"


def render_pager(result: dict, state: dict) -> str:
    total = result["total"]
    limit = result["limit"]
    offset = result["offset"]
    if total == 0:
        return ""
    first = offset + 1 if total else 0
    last = min(offset + limit, total)
    links = []
    if offset > 0:
        links.append(
            f"<a href='{_page_url(state, max(0, offset - limit))}' data-offset='{max(0, offset - limit)}'>Prev</a>"
        )
    if offset + limit < total:
        links.append(f"<a href='{_page_url(state, offset + limit)}' data-offset='{offset + limit}'>Next</a>")
    noun = "doc" if total == 1 else "docs"
    return (
        f"<span class='range'>{first}–{last} of {total} {noun}</span><span class='pager-links'>{' '.join(links)}</span>"
    )


def client_script() -> str:
    return _CLIENT_JS.replace("__TONE_BY_EXT__", json.dumps(TONE_BY_EXT, sort_keys=True))


INDEX_CSS = """
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 0 0 12px; }
.toolbar input[type=search] { flex: 1 1 240px; min-width: 0; font: inherit; font-size: 14px; padding: 6px 10px; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); background: var(--rds-surface-card); color: var(--rds-ink); }
.toolbar select, .toolbar input[type=date] { font: inherit; font-size: 12px; padding: 4px 6px; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); background: var(--rds-surface-card); color: var(--rds-ink-2); }
.toolbar label { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; color: var(--rds-ink-5); }
.toolbar a { font-size: 12px; color: var(--rds-ink-5); }
details.repo-filter { position: relative; }
details.repo-filter > summary { list-style: none; cursor: pointer; font-size: 12px; padding: 4px 8px; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); background: var(--rds-surface-card); color: var(--rds-ink-2); }
.repo-list { position: absolute; z-index: 5; top: 110%; left: 0; min-width: 240px; max-height: 280px; overflow: auto; display: grid; gap: 4px; padding: 8px; border: 1px solid var(--rds-line-strong); border-radius: 8px; background: var(--rds-surface-card); }
.repo-option { display: flex; gap: 6px; align-items: center; font-size: 12px; color: var(--rds-ink-2); }
.repo-option .n { margin-left: auto; color: var(--rds-ink-5); font-size: 11px; }
.pagerbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; margin: 14px 0 0; font-size: 12px; color: var(--rds-ink-5); }
.pagerbar a { color: var(--rds-accent-strong); }
.card .head { display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; }
.pill { font-size: 10px; font-weight: 600; padding: 1px 7px; border-radius: 4px; color: var(--rds-ink-5); background: color-mix(in oklab, var(--rds-ink) 6%, var(--rds-surface)); }
.pill.tone-md { background: color-mix(in oklab, var(--rds-ink) 7%, var(--rds-surface)); }
.pill.tone-text { background: color-mix(in oklab, var(--rds-ink) 5%, var(--rds-surface)); }
.pill.tone-html { background: color-mix(in oklab, oklch(0.78 0.12 75) 16%, var(--rds-surface)); }
.pill.tone-code { background: color-mix(in oklab, oklch(0.72 0.10 250) 16%, var(--rds-surface)); }
.pill.tone-data { background: color-mix(in oklab, oklch(0.74 0.10 150) 16%, var(--rds-surface)); }
.pill.tone-image { background: color-mix(in oklab, oklch(0.70 0.12 300) 16%, var(--rds-surface)); }
.pill.tone-comment { background: color-mix(in oklab, oklch(0.72 0.11 10) 16%, var(--rds-surface)); }
.chip.standalone { border-style: dashed; }
.chip.partial { color: var(--rds-ink-5); }
.snip { display: block; margin-top: 6px; font-size: 12px; color: var(--rds-ink-2); overflow-wrap: anywhere; }
.snip mark { background: var(--rds-accent-wash); color: var(--rds-accent-strong); border-radius: 2px; padding: 0 1px; }
.matches { margin-top: 8px; padding-left: 12px; border-left: 2px solid var(--rds-line); display: grid; gap: 4px; font-size: 12px; }
.matches li { display: block; }
.matches .more { color: var(--rds-ink-5); }
.card .head .title { overflow-wrap: anywhere; }
.status.indexing { color: var(--rds-accent-strong); }
"""

_CLIENT_JS = r"""
(() => {
  const TONE_BY_EXT = __TONE_BY_EXT__;
  const form = document.getElementById('search-form');
  if (!form) return;
  const input = document.getElementById('search');
  const sort = document.getElementById('sort');
  const from = document.getElementById('from');
  const to = document.getElementById('to');
  const list = document.getElementById('results');
  const status = document.getElementById('status');
  const pager = document.getElementById('pager');
  const repoBox = document.getElementById('repo-list');
  const repoSummary = document.getElementById('repo-summary');
  let seq = 0;
  let timer = 0;
  const limit = Number(list.dataset.limit) || 50;

  const selectedRepos = () => [...repoBox.querySelectorAll('input[type=checkbox]:checked')].map((box) => box.value);
  const termsOf = (q) => q.trim().split(/\s+/).filter(Boolean);
  const toneOf = (ext) => TONE_BY_EXT[ext] || 'text';
  const shortTs = (iso) => (iso ? iso.slice(0, 16).replace('T', ' ') : 'unknown');
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === false || value === null || value === undefined) continue;
      node.setAttribute(name, value);
    }
    node.append(...children);
    return node;
  }

  function snippetNode(text, terms) {
    if (!text) return null;
    const span = el('span', { class: 'snip' });
    if (!terms.length) {
      span.append(text);
      return span;
    }
    const pattern = new RegExp('(' + terms.map(escapeRe).join('|') + ')', 'gi');
    let last = 0;
    for (const found of text.matchAll(pattern)) {
      span.append(text.slice(last, found.index), el('mark', {}, found[0]));
      last = found.index + found[0].length;
    }
    span.append(text.slice(last));
    return span;
  }

  function repoChip(doc) {
    const key = doc.repo.key;
    if (key === 'standalone') return el('span', { class: 'chip standalone' }, 'standalone page');
    if (key === '') return el('span', { class: 'chip' }, 'Unknown repo');
    return el('span', { class: 'chip repo' }, doc.repo.label + (doc.branch ? ':' + doc.branch : ''));
  }

  function countChip(doc) {
    let label;
    if (doc.openComments === null) label = 'comments unreadable';
    else if (!doc.totalComments) label = 'no comments';
    else label = `${doc.openComments} open · ${doc.totalComments} total`;
    return el('span', { class: 'chip count' }, label);
  }

  function matchRow(match, terms) {
    return el('li', {},
      el('span', { class: 'pill tone-' + toneOf(match.ext) }, match.ext), ' ',
      el('a', { href: match.url }, match.title), ' ',
      snippetNode(match.snippet, terms));
  }

  function card(group, terms) {
    const doc = group.doc;
    const head = el('div', { class: 'head' },
      el('span', { class: 'pill tone-' + toneOf(doc.ext) }, doc.ext),
      el('a', { class: 'title', href: doc.url }, doc.title),
      doc.truncated ? el('span', { class: 'chip partial', title: 'Only the first 2 MB of this item is searchable' }, 'partial') : null);
    const meta = el('div', { class: 'meta' },
      el('span', {}, 'created ' + shortTs(doc.created)),
      el('span', {}, 'modified ' + shortTs(doc.modified)),
      el('span', { class: 'path' }, doc.sourcePath));
    const chips = el('div', { class: 'chips' }, repoChip(doc),
      doc.sessionId ? el('span', { class: 'chip session', title: 'agent session id: ' + doc.sessionId }, 'session ' + doc.sessionId.slice(0, 8)) : null,
      doc.agent ? el('span', { class: 'chip agent' }, doc.agent) : null,
      countChip(doc));
    const node = el('li', { class: 'card' }, head, meta, chips);
    const snippet = snippetNode(doc.snippet, terms);
    if (snippet) node.append(snippet);
    if (group.matches.length) {
      const rows = el('ul', { class: 'matches' });
      rows.append(...group.matches.map((match) => matchRow(match, terms)));
      const hidden = group.matchCount - group.matches.length;
      if (hidden > 0) rows.append(el('li', { class: 'more' }, `+${hidden} more matches`));
      node.append(rows);
    }
    return node;
  }

  function renderFacets(repos) {
    const checked = new Set(selectedRepos());
    repoBox.replaceChildren(...repos.map((repo) =>
      el('label', { class: 'repo-option' },
        el('input', { type: 'checkbox', name: 'repo', value: repo.key, checked: checked.has(repo.key) ? '' : false }),
        ' ' + repo.label + ' ',
        el('span', { class: 'n' }, String(repo.count)))));
    const count = checked.size;
    repoSummary.textContent = count ? `Repo (${count})` : 'Repo';
  }

  function renderPager(data) {
    const { total, offset, limit } = data;
    pager.replaceChildren();
    if (!total) return;
    const first = offset + 1;
    const last = Math.min(offset + limit, total);
    pager.append(el('span', { class: 'range' }, `${first}–${last} of ${total} ${total === 1 ? 'doc' : 'docs'}`));
    const links = el('span', { class: 'pager-links' });
    if (offset > 0) links.append(el('a', { href: '#', 'data-offset': String(Math.max(0, offset - limit)) }, 'Prev'), ' ');
    if (offset + limit < total) links.append(el('a', { href: '#', 'data-offset': String(offset + limit) }, 'Next'));
    pager.append(links);
  }

  function render(data) {
    const terms = termsOf(input.value);
    list.replaceChildren(...(data.groups.length
      ? data.groups.map((group) => card(group, terms))
      : [el('li', { class: 'empty' }, 'No matches. Try fewer terms or clear the filters.')]));
    const indexing = data.indexing.done < data.indexing.total;
    status.textContent = `${data.total} ${data.total === 1 ? 'document' : 'documents'}` + (indexing ? ` · indexing ${data.indexing.done}/${data.indexing.total}, results are partial` : '');
    status.classList.toggle('indexing', indexing);
    renderFacets(data.facets.repos);
    renderPager(data);
  }

  function params(offset) {
    const p = new URLSearchParams();
    const q = input.value.trim();
    if (q) p.set('q', q);
    for (const repo of selectedRepos()) p.append('repo', repo);
    if (sort.value !== 'modified') p.set('sort', sort.value);
    if (from.value) p.set('from', from.value);
    if (to.value) p.set('to', to.value);
    if (limit !== 50) p.set('limit', String(limit));
    if (offset) p.set('offset', String(offset));
    return p;
  }

  async function load(offset = 0) {
    const mine = ++seq;
    const p = params(offset);
    try { history.replaceState(null, '', p.toString() ? '/?' + p : '/'); } catch (err) { /* URL state is best-effort */ }
    try {
      const res = await fetch('/api/search?' + p, { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const data = await res.json();
      if (mine !== seq) return;
      if (!res.ok) { status.textContent = data.error || `search failed (${res.status})`; return; }
      render(data);
    } catch (err) {
      if (mine === seq) status.textContent = 'search request failed: ' + err.message;
    }
  }

  const later = (offset) => { clearTimeout(timer); timer = setTimeout(() => load(offset), 150); };
  input.addEventListener('input', () => later(0));
  for (const control of [sort, from, to]) control.addEventListener('change', () => load(0));
  repoBox.addEventListener('change', () => load(0));
  form.addEventListener('submit', (event) => { event.preventDefault(); load(0); });
  pager.addEventListener('click', (event) => {
    const link = event.target.closest('a[data-offset]');
    if (!link) return;
    event.preventDefault();
    load(Number(link.dataset.offset));
  });
  document.getElementById('clear').addEventListener('click', (event) => {
    event.preventDefault();
    input.value = '';
    sort.value = 'modified';
    from.value = '';
    to.value = '';
    for (const box of repoBox.querySelectorAll('input[type=checkbox]')) box.checked = false;
    load(0);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    const tag = (event.target && event.target.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (event.target && event.target.isContentEditable)) return;
    event.preventDefault();
    input.focus();
  });
})();
"""
