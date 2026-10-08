"""Markdown → commentable review-page renderer.

The markdown subset and the dual-key anchor policy are stable; this module
also adds provenance plumbing (embedded into the page config and shown in
the topbar "Source" panel) and a per-comment author field
(localStorage-backed, sent as `author` on POST /comments).

Anchor policy
-------------
Every rendered heading, paragraph, list item, table row, blockquote, and code
block gets two keys:

- ``anchorId``: content-derived from heading path + element kind + normalized
  content hash. Survives insertions and reorderings when the target text
  itself did not change.
- ``semanticKey``: position-derived from heading path + element kind +
  ordinal. Survives ordinary in-place wording edits when the target element
  stayed in the same slot.

The page resolves comments by ``anchorId`` first, then ``semanticKey``, then
content hash — and every one of those paths requires the stored
``contentHash`` to equal the candidate element's (orphan-on-mismatch,
2026-08-17). ``anchorId`` and the content-hash lookup satisfy that by
construction; the ``semanticKey`` fallback is the one that had to be gated,
because it is a pure POSITION match and was silently re-binding old comments
to whatever new text landed in that slot after a rewrite.

A comment therefore becomes DETACHED as soon as the text under its anchor
changes. It never attaches to an element it does not match: it renders in the
Comments drawer under a "Detached" filter (and a topbar count) carrying its
original quote, and it remains in ``comments.json`` untouched. This is a
read/display-side rule only — the anchor write format is unchanged and older
stores (including anchors with no ``contentHash``, which are exempt) keep
working.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha1

from .links import split_relative_href


def short_hash(text: str, n: int = 12) -> str:
    return sha1(text.encode("utf-8")).hexdigest()[:n]


def norm_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def slugify(text: str, fallback: str = "x") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or fallback


def github_slug(text: str) -> str:
    """GitHub-style heading slug of a heading's OWN text (link label kept,
    punctuation dropped, each space a hyphen), so `## Install & Run` slugs to
    `install--run` exactly as the fragment an author would write for it."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")


def escape_attr(value: object) -> str:
    return html.escape(str(value), quote=True)


def _safe_href(href: str) -> str | None:
    """Return ``href`` if it is safe to emit as a link target, else None.

    The threat model is prompt-injection → stored XSS: an agent renders a doc
    containing attacker-influenced markdown and the reviewer taps a normal-
    looking link. HTML-escaping the attribute is NOT enough — a
    ``javascript:`` URL escapes cleanly and still executes. So the scheme is
    allowlisted instead: fragments, same-origin absolute/relative paths,
    protocol-relative URLs, and http/https/mailto. Everything else
    (``javascript:``, ``data:``, ``vbscript:``, ``file:``, ...) renders the
    label as inert text. Whitespace/control characters are stripped and
    backslashes normalized to forward slashes before the check — browsers
    treat ``\\host`` as ``//host`` for special schemes, so the classifier
    must see the same URL the browser will.
    """
    probe = re.sub(r"[\s\x00-\x1f]+", "", href).replace("\\", "/")
    if not probe:
        return None
    if probe.startswith("#"):
        return href
    if probe.startswith("//"):
        return href  # protocol-relative external link; same risk class as https
    if probe.startswith("/"):
        return href
    if re.match(r"^(?:https?|mailto):", probe, re.IGNORECASE):
        return href
    first_segment = probe.split("/", 1)[0]
    if ":" not in first_segment:
        return href  # relative path like docs/other.md
    return None


@dataclass(frozen=True)
class LinkRendering:
    """How a relative link renders, as decided by the caller's resolver.

    ``css_class`` is ``md-link-local`` (a viewable target) or
    ``md-link-unavailable`` (gets a visible mark; its href still explains why).
    ``image`` is True only for a captured image the page may embed.
    """

    href: str
    css_class: str
    title: str = ""
    image: bool = False


# (raw relative href, written as an image?) -> rendering, or None for the
# default treatment. Set for the duration of MarkdownRenderer.render, so the
# many render_inline call sites need no plumbing (and threads don't share it).
LinkResolver = Callable[[str, bool], "LinkRendering | None"]
_LINK_RESOLVER: ContextVar[LinkResolver | None] = ContextVar("md_link_resolver", default=None)


def _attr(value: str) -> str:
    # Attribute values are emitted BEFORE the emphasis regexes run over the
    # line, so a literal `*` would let `*x*` grow <em> tags inside the value.
    # NULs are dropped: \x00N\x00 is render_inline's code-span placeholder,
    # and a resolver value must never be read back as one.
    return html.escape(value.replace("\x00", ""), quote=True).replace("*", "&#42;")


def render_inline_unlinked(text: str) -> str:
    """render_inline with every generated <a> tag removed, keeping its label:
    for outline entries, which are links themselves (nesting <a> is invalid)
    and render outside any resolver. Stripping the OUTPUT keeps code spans
    intact, and is exact: user text is escaped, so every `<a` here is ours."""
    # `!?`: with no resolver an image renders as `!<a …>alt</a>`; its `!` goes
    # too — unless the author escaped it (`\!`), in which case it is text.
    return re.sub(r"(?:(?<!\\)!)?<a\b[^>]*>|</a>", "", render_inline(text))


def render_inline(text: str) -> str:
    # Code spans are pulled out FIRST and swapped for a punctuation-free
    # placeholder before bold/italic/link markup is processed. This matters for
    # constructs like **`rqfp_id`** (bold wrapping inline code): the previous
    # approach split the text into code vs. non-code chunks and ran the bold
    # regex on each chunk independently, so the "**" before the span and the
    # "**" after it landed in two different chunks. Neither chunk alone matches
    # \*\*([^*]+)\*\*, so the emphasis silently failed to apply and raw
    # asterisks leaked into the rendered page. Stashing the span behind a
    # placeholder lets the bold/italic/link regexes see straight through it, so
    # a bold run (or a link, in principle) can span across a code span exactly
    # as GFM treats the span as one opaque inline atom.
    code_spans: list[str] = []
    code_text: list[str] = []  # the same spans as plain text, for attribute values

    def stash_code(match: re.Match[str]) -> str:
        # Strict CommonMark leaves backslashes literal inside code spans (escape
        # processing is a plain-text-only rule there). This renderer
        # deliberately does NOT follow that: table cells escape a literal pipe
        # as `\|` specifically so it survives inside an inline code span
        # (`` `draft\|final` ``) without splitting the column, and the
        # requirement is that it renders as a plain `|` with no visible
        # backslash. Unescaping here too keeps that one rule uniform instead of
        # carving out a code-span exception.
        content = match.group(1).replace("\\|", "|")
        code_spans.append(f'<code class="md-inline-code">{html.escape(content)}</code>')
        code_text.append(content)
        return f"\x00{len(code_spans) - 1}\x00"

    placeheld = re.sub(r"`([^`]*)`", stash_code, text)
    escaped = html.escape(placeheld)

    # Standard GFM backslash escape: `\|` renders as a literal pipe. Table
    # cells rely on this to hold a literal `|` without it being read as a
    # column separator (see MarkdownRenderer._scan_table_cells), but the escape
    # itself is a general inline rule, not a table-only one, so it is honored
    # here for every render_inline caller (headings, list items, paragraphs,
    # table cells, ...). Fenced code BLOCKS (```...```) never reach
    # render_inline at all (see MarkdownRenderer.render's fence branch), so
    # genuine backslashes in real code snippets are unaffected by this rule.
    escaped = escaped.replace("\\|", "|")

    def link_repl(match: re.Match[str]) -> str:
        bang, label = match.group(1), match.group(2)
        if not label and not bang:
            return match.group(0)  # `[](x)` was never a link here; leave it as text
        # match.group(2) comes from the ALREADY-escaped text. Two unescape
        # levels matter for TWO different reasons:
        #   - CLASSIFY on the double-unescaped form: `[x](javascript&#58;…)`
        #     unescapes once to `javascript&#58;…` (no colon — looks like a
        #     relative path) and only twice to the literal `javascript:` the
        #     scheme check must see to kill it. Checking any shallower form
        #     waves the entity-obfuscated schemes through.
        #   - EMIT the single-unescaped form, escaped exactly once. That
        #      round-trips author intent (`?a=1&b=2` works again — the old
        #      double-escape broke every multi-parameter URL) while the DOM
        #      never receives a decodable colon-entity (browsers decode
        #      attributes once), so even the "allowed but weird" forms can't
        #      spring back to life as a scheme.
        raw_href = html.unescape(match.group(3))
        if _safe_href(html.unescape(raw_href)) is None:
            # Inert: label stays readable, the link cannot execute or navigate.
            return f'{bang}<span class="md-link-inert" title="link target blocked (scheme not allowed)">{label}</span>'
        resolver = _LINK_RESOLVER.get()
        rendering = resolver(raw_href, bool(bang)) if resolver and split_relative_href(raw_href) else None
        if rendering is None:
            return f'{bang}<a href="{html.escape(raw_href, quote=True)}">{label}</a>'
        opening = f'<a class="{_attr(rendering.css_class)}" href="{_attr(rendering.href)}" title="{_attr(rendering.title)}">'
        if bang and rendering.image:
            # A code span in alt text must become its plain text here: restored
            # later as <code class="…">, its quotes would break the attribute.
            alt_text = re.sub(r"\x00(\d+)\x00", lambda m: code_text[int(m.group(1))], html.unescape(label))
            alt = _attr(alt_text)
            return f'{opening}<img src="{_attr(rendering.href.partition("#")[0])}" alt="{alt}" loading="lazy"></a>'
        mark = ""
        if rendering.css_class == "md-link-unavailable":
            mark = '<span class="md-link-unavailable-mark" aria-hidden="true">⊘</span>'
        return f"{opening}{label or 'image'}{mark}</a>"

    escaped = re.sub(r"(!?)\[([^\]]*)\]\(([^)]+)\)", link_repl, escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", escaped)

    def restore_code(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return code_spans[index] if index < len(code_spans) else ""

    return re.sub(r"\x00(\d+)\x00", restore_code, escaped)


@dataclass
class Anchor:
    anchor_id: str
    semantic_key: str
    element_kind: str
    heading_path: list[str]
    label: str
    content_hash: str
    quote: str

    def attrs(self) -> str:
        return (
            f' data-cmt-anchor="{escape_attr(self.anchor_id)}"'
            f' data-cmt-semantic-key="{escape_attr(self.semantic_key)}"'
            f' data-cmt-kind="{escape_attr(self.element_kind)}"'
            f' data-cmt-label="{escape_attr(self.label)}"'
            f' data-cmt-heading-path="{escape_attr(" > ".join(self.heading_path))}"'
            f' data-cmt-content-hash="{escape_attr(self.content_hash)}"'
            f' data-cmt-quote="{escape_attr(self.quote)}"'
        )

    def as_json(self) -> dict:
        return {
            "anchorId": self.anchor_id,
            "semanticKey": self.semantic_key,
            "elementKind": self.element_kind,
            "headingPath": self.heading_path,
            "label": self.label,
            "contentHash": self.content_hash,
            "quote": self.quote,
        }


class MarkdownRenderer:
    def __init__(self, link_resolver: LinkResolver | None = None) -> None:
        self.link_resolver = link_resolver
        self.heading_path: list[str] = []
        # Levels are tracked alongside the path because ancestry is defined by
        # heading LEVEL, not list position: a doc that opens at ### then moves
        # to ## must not treat the h3 as the h2's parent (the old
        # `path[:level-1]` slicing did exactly that, corrupting every
        # downstream anchor scope).
        self.heading_levels: list[int] = []
        self.ordinals: dict[str, int] = {}
        self.anchor_dupes: dict[str, int] = {}
        self.heading_slugs: dict[str, int] = {}
        self.github_slugs: dict[str, int] = {}
        self.anchors: list[Anchor] = []
        self.toc: list[dict] = []

    def make_anchor(self, kind: str, text: str) -> Anchor:
        normalized = norm_text(text)
        content_hash = short_hash(normalized or kind)
        heading_key = "/".join(slugify(h, "section") for h in self.heading_path) or "root"
        ordinal_key = f"{heading_key}::{kind}"
        self.ordinals[ordinal_key] = self.ordinals.get(ordinal_key, 0) + 1
        semantic_key = f"{ordinal_key}::{self.ordinals[ordinal_key]}"
        base_id = f"a-{short_hash(f'{heading_key}|{kind}|{content_hash}')}"
        self.anchor_dupes[base_id] = self.anchor_dupes.get(base_id, 0) + 1
        anchor_id = base_id if self.anchor_dupes[base_id] == 1 else f"{base_id}-{self.anchor_dupes[base_id]}"
        scope = " > ".join(self.heading_path[-2:]) if self.heading_path else "Document"
        label = f"{kind} · {scope}"
        quote = normalized[:420]
        anchor = Anchor(anchor_id, semantic_key, kind, list(self.heading_path), label, content_hash, quote)
        self.anchors.append(anchor)
        return anchor

    def heading_id(self, text: str) -> str:
        base = slugify(" ".join(self.heading_path) or text, "section")
        self.heading_slugs[base] = self.heading_slugs.get(base, 0) + 1
        return base if self.heading_slugs[base] == 1 else f"{base}-{self.heading_slugs[base]}"

    def github_heading_slug(self, text: str) -> str:
        # github-slugger's algorithm: repeats get -1, -2, … and a generated
        # suffix that collides with a real heading's slug keeps counting, so
        # `Notes`, `Notes-1`, `Notes` yield notes, notes-1, notes-2.
        base = github_slug(text)
        slug = base
        while slug in self.github_slugs:
            self.github_slugs[base] += 1
            slug = f"{base}-{self.github_slugs[base]}"
        self.github_slugs[slug] = 0
        return slug

    def render(self, markdown: str) -> str:
        token = _LINK_RESOLVER.set(self.link_resolver)
        try:
            return self._render(markdown)
        finally:
            _LINK_RESOLVER.reset(token)

    def _render(self, markdown: str) -> str:
        # NUL is never legitimate in markdown and is actively dangerous here:
        # render_inline uses \x00{n}\x00 as the code-span placeholder, so a
        # source-provided NUL could collide with the placeholder format and
        # either crash the restore step or silently swap in an unrelated code
        # span. Strip it at the door — one rule, all callers.
        markdown = markdown.replace("\x00", "")
        lines = markdown.splitlines()
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue

            fence = re.match(r"^```([A-Za-z0-9_-]*)\s*$", line)
            if fence:
                lang = fence.group(1)
                code_lines: list[str] = []
                i += 1
                while i < len(lines) and not re.match(r"^```\s*$", lines[i]):
                    code_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    i += 1
                code = "\n".join(code_lines)
                anchor = self.make_anchor("code", code)
                lang_class = f' class="language-{escape_attr(lang)}"' if lang else ""
                out.append(
                    f'<pre class="md-code md-block"{anchor.attrs()}><code{lang_class}>'
                    f"{html.escape(code)}</code></pre>"
                )
                continue

            heading = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
            if heading:
                level = len(heading.group(1))
                text = heading.group(2).strip()
                while self.heading_levels and self.heading_levels[-1] >= level:
                    self.heading_levels.pop()
                    self.heading_path.pop()
                self.heading_levels.append(level)
                self.heading_path.append(text)
                hid = self.heading_id(text)
                anchor = self.make_anchor("heading", text)
                self.toc.append({"level": level, "id": hid, "text": text})
                out.append(
                    f'<h{level} id="{escape_attr(hid)}" data-slug="{escape_attr(self.github_heading_slug(text))}" '
                    f'class="md-heading md-block"{anchor.attrs()}>'
                    f'<a class="md-heading-link" href="#{escape_attr(hid)}">#</a>{render_inline(text)}</h{level}>'
                )
                i += 1
                continue

            if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
                out.append('<hr class="md-rule">')
                i += 1
                continue

            if line.lstrip().startswith(">"):
                quote_lines: list[str] = []
                while i < len(lines) and lines[i].lstrip().startswith(">"):
                    quote_lines.append(re.sub(r"^\s*>\s?", "", lines[i]))
                    i += 1
                text = "\n".join(quote_lines)
                anchor = self.make_anchor("blockquote", text)
                body = "<br>".join(render_inline(q) for q in quote_lines)
                out.append(f'<blockquote class="md-blockquote md-block"{anchor.attrs()}>{body}</blockquote>')
                continue

            if self._is_table_start(lines, i):
                html_table, i = self._render_table(lines, i)
                out.append(html_table)
                continue

            list_match = re.match(r"^\s*((?:[-*+])|(?:\d+[.)]))\s+(.+)$", line)
            if list_match:
                ordered = bool(re.match(r"\d", list_match.group(1)))
                tag = "ol" if ordered else "ul"
                # A numbered list that resumes mid-sequence (`7. Item`) must
                # render from 7 — without a start attribute the browser always
                # opens at 1 and silently renumbers the author's procedure.
                # The digit string is length-guarded: CPython caps int() at
                # 4300 digits, and a 5000-digit "marker" is pathological input,
                # not a list number.
                start_match = re.match(r"\d{1,9}", list_match.group(1)) if ordered else None
                start_num = int(start_match.group(0)) if start_match else 1
                items: list[str] = []
                while i < len(lines):
                    m = re.match(r"^\s*((?:[-*+])|(?:\d+[.)]))\s+(.+)$", lines[i])
                    if m:
                        is_ordered = bool(re.match(r"\d", m.group(1)))
                        if is_ordered != ordered:
                            break
                        items.append(m.group(2).strip())
                        i += 1
                        continue
                    if not lines[i].strip():
                        # A blank line (or a run of them) does not by itself
                        # end the list. CommonMark's "loose list" rule keeps
                        # items that are merely separated by blank lines in
                        # the SAME list — one <ol>, not a fresh one restarting
                        # at 1 for every item. Real design docs use this style
                        # (e.g. a glossary of field names, each
                        # set off by a blank line):
                        # without this peek-ahead, blank-line spacing between
                        # items reproduced the exact same "every item renders
                        # as 1." symptom as the wrapped-continuation case, just
                        # via a different trigger. Peek past the blank run: if
                        # a marker of the SAME type follows, the list continues
                        # from there; otherwise this genuinely ends the list (a
                        # paragraph, heading, EOF, or a different marker type
                        # follows), and the blank line is left untouched for
                        # the outer render() loop to skip as it already does.
                        j = i
                        while j < len(lines) and not lines[j].strip():
                            j += 1
                        if j < len(lines):
                            m2 = re.match(r"^\s*((?:[-*+])|(?:\d+[.)]))\s+(.+)$", lines[j])
                            if m2 and bool(re.match(r"\d", m2.group(1))) == ordered:
                                i = j
                                continue
                        break
                    # Lazy continuation: a hand-wrapped source line that keeps
                    # writing the current item's sentence (no marker prefix)
                    # is folded onto that item instead of closing the list.
                    # Without this, EVERY wrapped line ended the <ol>/<ul>
                    # right here, the wrapped text fell through to the
                    # paragraph branch below as its own <p> ("awkward hard line
                    # break after roughly the first column-width"), and each
                    # subsequent numbered source line then opened a BRAND NEW
                    # <ol> — which the browser numbers from 1 by default
                    # regardless of the source's own digits ("every item
                    # renders as 1."). A line that starts some OTHER block
                    # (heading/fence/blockquote/hr/table/opposite-type marker)
                    # still closes the list here, mirroring how the paragraph
                    # branch below already treats lazy continuation for prose
                    # outside of lists.
                    if items and not self._starts_block(lines, i):
                        items[-1] = f"{items[-1]} {lines[i].strip()}"
                        i += 1
                        continue
                    break
                rendered_items: list[str] = []
                for item in items:
                    anchor = self.make_anchor("list-item", item)
                    rendered_items.append(f'<li class="md-block"{anchor.attrs()}>{render_inline(item)}</li>')
                start_attr = f' start="{start_num}"' if ordered and start_num != 1 else ""
                out.append(f'<{tag} class="md-list"{start_attr}>{"".join(rendered_items)}</{tag}>')
                continue

            para_lines: list[str] = []
            while i < len(lines) and lines[i].strip() and not self._starts_block(lines, i):
                para_lines.append(lines[i].strip())
                i += 1
            text = " ".join(para_lines)
            anchor = self.make_anchor("paragraph", text)
            out.append(f'<p class="md-para md-block"{anchor.attrs()}>{render_inline(text)}</p>')
        return "\n".join(out)

    def _starts_block(self, lines: list[str], i: int) -> bool:
        line = lines[i]
        if re.match(r"^```", line):
            return True
        if re.match(r"^#{1,6}\s+", line):
            return True
        if line.lstrip().startswith(">"):
            return True
        if re.match(r"^\s*((?:[-*+])|(?:\d+[.)]))\s+", line):
            return True
        if self._is_table_start(lines, i):
            return True
        return re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line) is not None

    def _is_table_start(self, lines: list[str], i: int) -> bool:
        if i + 1 >= len(lines):
            return False
        if "|" not in lines[i] or "|" not in lines[i + 1]:
            return False
        cells = self._split_table_row(lines[i + 1])
        if not cells:
            return False
        return all(re.match(r"^:?-{3,}:?$", cell.strip()) for cell in cells)

    def _split_table_row(self, line: str) -> list[str]:
        row = line.strip()
        cells = self._scan_table_cells(row)
        # A row conventionally opens/closes with a pipe (`| a | b |`); GFM makes
        # both optional. Drop the one leading/trailing empty cell a real
        # boundary pipe produces. This stays safe even when the row's actual
        # first/last character is a backslash-escaped or code-span pipe,
        # because _scan_table_cells never treats those as separators — cells[0]
        # /cells[-1] can only be empty here when a genuine splitting pipe was
        # the first/last character consumed by the scan.
        if cells and cells[0] == "" and row.startswith("|"):
            cells = cells[1:]
        if cells and cells[-1] == "" and row.endswith("|"):
            cells = cells[:-1]
        return [cell.strip() for cell in cells]

    @staticmethod
    def _scan_table_cells(row: str) -> list[str]:
        """Split a table row on column-separator pipes only.

        A naive ``row.split("|")`` breaks on every pipe, including two standard
        GFM escapes that must NOT split a cell in two:

          1. a backslash-escaped pipe, e.g. ``draft\\|final`` — the
             documented way to put a literal ``|`` inside a cell.
          2. a pipe inside a single-backtick code span, e.g. `` `0|1|2|3` `` —
             the span is one opaque inline unit, matching how render_inline
             later treats it.

        Both were observed together in real table cells (`` `draft\\|final` ``,
        `` `0\\|1\\|2\\|3` ``): the previous splitter turned one cell into several,
        silently dropping any trailing cell text once a row produced more raw
        pieces than the table's declared column count.
        """
        cells: list[str] = []
        current: list[str] = []
        in_code_span = False
        i = 0
        n = len(row)
        while i < n:
            ch = row[i]
            if ch == "\\" and i + 1 < n:
                # Keep the escape pair intact — render_inline unescapes `\|` to
                # `|` later. Consuming both characters here also stops
                # something like ``\` `` from being mistaken for a code-span
                # delimiter.
                current.append(ch)
                current.append(row[i + 1])
                i += 2
                continue
            if ch == "`":
                in_code_span = not in_code_span
                current.append(ch)
                i += 1
                continue
            if ch == "|" and not in_code_span:
                cells.append("".join(current))
                current = []
                i += 1
                continue
            current.append(ch)
            i += 1
        cells.append("".join(current))
        return cells

    def _render_table(self, lines: list[str], i: int) -> tuple[str, int]:
        header = self._split_table_row(lines[i])
        i += 2
        rows: list[list[str]] = []
        while i < len(lines) and lines[i].strip() and "|" in lines[i]:
            rows.append(self._split_table_row(lines[i]))
            i += 1
        width = len(header)
        head_text = " | ".join(header)
        head_anchor = self.make_anchor("table-row", head_text)
        head_cells = "".join(f"<th>{render_inline(cell)}</th>" for cell in header)
        rendered = [
            '<table class="md-table">',
            f'<thead><tr class="md-table-row md-block"{head_anchor.attrs()}>{head_cells}<th class="md-cmt-col"></th></tr></thead>',
            "<tbody>",
        ]
        for row in rows:
            padded = row + [""] * max(0, width - len(row))
            text = " | ".join(padded[:width])
            anchor = self.make_anchor("table-row", text)
            cells = "".join(f"<td>{render_inline(cell)}</td>" for cell in padded[:width])
            rendered.append(
                f'<tr class="md-table-row md-block"{anchor.attrs()}>{cells}<td class="md-cmt-col"></td></tr>'
            )
        rendered.append("</tbody></table>")
        return "\n".join(rendered), i


def page_html(
    title: str,
    source_path: str,
    doc_id: str,
    body: str,
    anchors: list[dict],
    toc: list[dict],
    provenance: dict | None = None,
) -> str:
    config = {
        "docId": doc_id,
        "title": title,
        "sourcePath": source_path,
        "anchors": anchors,
        "provenance": provenance or {},
    }
    prov = provenance or {}
    repo_name = prov.get("sourceRepoName") or ""
    repo_branch = prov.get("sourceRepoBranch") or ""
    if repo_name and repo_branch:
        subtitle = f"{repo_name}:{repo_branch} · {source_path}"
    elif repo_name:
        subtitle = f"{repo_name} · {source_path}"
    else:
        subtitle = source_path
    toc_html = "\n".join(
        f'<a class="toc-l{int(item["level"])}" href="#{escape_attr(item["id"])}">{render_inline_unlinked(item["text"])}</a>'
        for item in toc
    )
    # json.dumps output is valid JSON but NOT safe <script>-element text: a
    # "</script>" inside any config string (title, sourcePath, branch name,
    # anchor quote, session id — all attacker-influencable) closes the element
    # early and executes. Escape the three characters that can break out of
    # the element/comment context to their JSON unicode escapes; the JS side
    # receives byte-identical strings after JSON parsing
    # (demonstrated with a crafted sourceRepoBranch).
    config_json = (
        json.dumps(config, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<link rel="icon" href="data:,">
<script>
// ---- theme bootstrap (FOUC guard) --------------------------------------
// Runs BEFORE the stylesheets below are fetched, so data-theme is settled
// before first paint — no light-flash on dark setups. Precedence:
//   1. per-device override (localStorage mdReviewTheme, set by the topbar
//      toggle) — beats everything, on this device only;
//   2. server default (the server stamps data-theme on <html> at serve
//      time for --theme light|dusk|dark; absent under --theme system);
//   3. OS preference — prefers-color-scheme is binary, so OS dark maps to
//      "dark" (Warm Chalkboard); "dusk" is a mid-tone opt-in reachable via
//      the toggle or --theme dusk. Light needs no palette block (it IS the
//      :root default), but a pinned/override light still sets the
//      attribute so this script and the toggle read one uniform signal.
(() => {{
  const root = document.documentElement;
  let stored = null;
  try {{ stored = localStorage.getItem('mdReviewTheme'); }} catch (err) {{ stored = null; }}
  if (stored === 'light' || stored === 'dusk' || stored === 'dark') {{
    root.setAttribute('data-theme', stored);
    return;
  }}
  if (root.hasAttribute('data-theme')) return;  // server pinned a default
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {{
    root.setAttribute('data-theme', 'dark');
  }}
}})();
</script>
<link rel="stylesheet" href="/ds/design-app/tokens.css">
<link rel="stylesheet" href="/ds/components/components.css">
<style>
:root {{ --accent-sage: var(--confirm); }}
body {{ min-height: 100vh; background: var(--rds-surface); color: var(--rds-ink); }}
a {{ color: var(--rds-accent-strong); text-decoration-thickness: 1px; text-underline-offset: 2px; }}
.topbar {{ position: sticky; top: 0; z-index: 50; height: 48px; display: flex; align-items: center; gap: 14px; padding: 0 18px; background: color-mix(in srgb, var(--rds-surface-card) 92%, transparent); border-bottom: 1px solid var(--rds-line); backdrop-filter: blur(10px); }}
.brand {{ display: flex; min-width: 0; flex-direction: column; gap: 1px; }}
.brand b {{ font-size: 13px; font-weight: 600; color: var(--rds-ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.brand span {{ font-size: 10px; color: var(--rds-ink-5); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.spacer {{ flex: 1; }}
.topbtn {{ appearance: none; border: 1px solid var(--rds-line); background: var(--rds-surface); color: var(--rds-ink-2); border-radius: var(--radius-sharp); height: 28px; padding: 0 10px; display: inline-flex; align-items: center; gap: 7px; font-family: var(--rds-font-sans); font-size: 11px; font-weight: 600; cursor: pointer; }}
.topbtn:hover {{ border-color: var(--rds-line-strong); background: var(--rds-surface-rail); }}
.topbtn[aria-expanded="true"] {{ border-color: var(--rds-accent); color: var(--rds-accent-strong); }}
/* Theme glyph picker: same ☼ ◐ ☾ vocabulary as the bundled design system's
   theme-picker (Day/Dusk/Night) — a segmented three-way, not a cycle
   button. */
.theme-picker {{ display: inline-flex; align-items: center; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); overflow: hidden; background: var(--rds-surface); }}
.theme-glyph {{ appearance: none; border: 0; background: transparent; color: var(--rds-ink-5); width: 30px; height: 28px; display: inline-grid; place-items: center; font-size: 14px; line-height: 1; cursor: pointer; }}
.theme-glyph + .theme-glyph {{ border-left: 1px solid var(--rds-line); }}
.theme-glyph:hover {{ background: var(--rds-surface-rail); color: var(--rds-ink-2); }}
.theme-glyph.active {{ background: var(--rds-accent-wash); color: var(--rds-accent-strong); }}
/* The shadow uses the design system's ONE themed shadow token instead of a
   hard-coded rgba: the warm-brown 0.16-alpha it replaces was tuned for
   paper and all but vanishes on the dusk/dark palettes, where --shadow-pop
   switches to a deeper black. */
.md-prov-panel {{ position: fixed; top: 54px; right: 14px; z-index: 60; width: min(92vw, 430px); max-height: min(70vh, 560px); overflow-y: auto; background: var(--rds-surface-card); border: 1px solid var(--rds-line); border-radius: 10px; box-shadow: var(--shadow-pop); padding: 12px 14px; font-family: var(--rds-font-sans); }}
.md-prov-panel h2 {{ font-size: 11px; text-transform: uppercase; letter-spacing: var(--track-eyebrow); color: var(--rds-ink-5); margin: 0 0 8px; font-weight: 600; }}
.md-prov-row {{ display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 4px 10px; padding: 3px 0; font-size: 11px; line-height: 1.45; }}
.md-prov-row dt {{ color: var(--rds-ink-5); font-weight: 600; }}
.md-prov-row dd {{ margin: 0; color: var(--rds-ink-2); overflow-wrap: anywhere; font-family: var(--rds-font-mono); font-size: 10.5px; }}
.shell {{ display: grid; grid-template-columns: minmax(168px, 236px) minmax(0, 760px) minmax(48px, 1fr); gap: 28px; align-items: start; max-width: 1240px; margin: 0 auto; padding: 30px 24px 80px; }}
.toc {{ position: sticky; top: 74px; max-height: calc(100vh - 92px); overflow: auto; padding-right: 8px; border-right: 1px solid var(--rds-line); }}
.toc-title {{ font-size: 10px; color: var(--rds-ink-5); text-transform: uppercase; letter-spacing: var(--track-eyebrow); font-weight: 600; margin-bottom: 10px; }}
.toc a {{ display: block; color: var(--rds-text-faint); text-decoration: none; font-size: 11px; line-height: 1.35; padding: 4px 0; overflow-wrap: anywhere; }}
.toc a:hover {{ color: var(--rds-accent-strong); }}
.toc-l1 {{ font-weight: 600; color: var(--rds-ink-2) !important; }}
.toc-l2 {{ padding-left: 8px !important; }}
.toc-l3, .toc-l4, .toc-l5, .toc-l6 {{ padding-left: 16px !important; }}
.doc {{ min-width: 0; }}
/* Native text selection (pre-comment, before the highlight-to-comment flow
   commits a span) reads as coral, not the browser's default blue — reuses the
   same --rds-accent-wash soft/translucent coral token the design system
   applies to ::selection inside its own .editor surface
   (design-app/tokens.css), scoped to .doc since that's this tool's content
   container. */
.doc ::selection {{ background: var(--rds-accent-wash); color: var(--rds-accent-strong); }}
.doc h1, .doc h2, .doc h3, .doc h4, .doc h5, .doc h6 {{ position: relative; color: var(--rds-ink); letter-spacing: 0; line-height: 1.18; margin: 1.35em 0 0.55em; font-weight: 600; }}
.doc h1 {{ font-size: 30px; margin-top: 0; }}
.doc h2 {{ font-size: 22px; border-top: 1px solid var(--rds-line); padding-top: 22px; }}
.doc h3 {{ font-size: 17px; }}
.doc h4 {{ font-size: 14px; }}
.md-heading-link {{ opacity: 0; position: absolute; left: -22px; color: var(--rds-ink-5); text-decoration: none; }}
.md-heading:hover .md-heading-link {{ opacity: 1; }}
.doc p, .doc li, .doc blockquote, .doc td, .doc th {{ font-size: 14px; line-height: 1.62; }}
.md-para {{ margin: 0 0 16px; }}
.md-list {{ margin: 0 0 16px 0; padding-left: 24px; }}
.md-list li {{ margin: 5px 0; padding-left: 2px; }}
.md-blockquote {{ margin: 18px 0; padding: 8px 14px; color: var(--rds-text-faint); background: var(--rds-surface-rail-soft); border-left: 2px solid var(--rds-accent); }}
.md-code {{ margin: 18px 0; padding: 14px 16px; overflow: auto; background: var(--rds-surface-rail); border: 1px solid var(--rds-line); border-radius: 8px; font-size: 12px; line-height: 1.55; }}
.md-inline-code {{ padding: 0.15em 0.4em; margin: 0 1px; border-radius: 4px; background: var(--rds-surface-rail); border: 1px solid var(--rds-line); font-size: 0.9em; }}
.md-link-inert {{ color: var(--rds-text-faint); text-decoration: underline dashed; text-decoration-color: var(--caution-edge); cursor: not-allowed; }}
.md-link-unavailable {{ color: var(--rds-text-faint); text-decoration: underline dotted; text-decoration-color: var(--caution); }}
.md-link-unavailable-mark {{ margin-left: 3px; font-weight: 600; color: var(--caution); }}
.md-link-local img {{ max-width: 100%; height: auto; border-radius: 6px; }}
.md-rule {{ border: 0; border-top: 1px solid var(--rds-line); margin: 24px 0; }}
.md-table {{ width: 100%; border-collapse: collapse; margin: 18px 0 24px; font-size: 13px; }}
.md-table th, .md-table td {{ border: 1px solid var(--rds-line); padding: 7px 9px; vertical-align: top; }}
.md-table th {{ background: var(--rds-surface-rail); color: var(--rds-ink-2); font-weight: 600; }}
.md-cmt-col {{ width: 34px; min-width: 34px; padding: 3px !important; text-align: center; }}
.md-block {{ position: relative; scroll-margin-top: 70px; }}
.md-cmt-btn {{ appearance: none; border: 1px solid var(--rds-line); background: var(--rds-surface-card); color: var(--rds-ink-5); border-radius: 999px; width: 26px; height: 26px; display: inline-grid; place-items: center; cursor: pointer; opacity: 0; transition: opacity 90ms ease, border-color 90ms ease, color 90ms ease, background 90ms ease; }}
.md-block:hover > .md-cmt-btn, .md-block:focus-within > .md-cmt-btn, .md-cmt-btn.has-comments {{ opacity: 1; }}
.doc :not(tr).md-block > .md-cmt-btn {{ position: absolute; right: -38px; top: 0; }}
.md-cmt-cell .md-cmt-btn {{ opacity: 0.45; }}
tr:hover .md-cmt-cell .md-cmt-btn, .md-cmt-cell .md-cmt-btn.has-comments {{ opacity: 1; }}
.md-cmt-btn:hover {{ color: var(--rds-accent-strong); border-color: var(--rds-accent); background: var(--rds-surface); }}
.md-cmt-btn .rds-cbadge {{ position: absolute; transform: translate(9px, -9px); }}
.md-orphan {{ outline: 2px solid var(--caution-edge); outline-offset: 4px; }}
/* Detached comments (orphan-on-mismatch). --caution is the themed token; the
   -mark/-wash/-edge trio is deliberately left un-rethemed (see the
   .rds-cmt-error note below), so it would vanish on dusk/dark. */
.md-detached-btn {{ border-color: var(--caution); color: var(--caution); }}
.md-detached-btn:hover {{ border-color: var(--caution); color: var(--caution); }}
.rds-cmt-item.md-detached-item {{ border-left: 3px solid var(--caution); }}
.md-detached-tag {{ margin: 2px 0 4px; color: var(--caution); font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; }}
/* Bug: the base .rds-cmt-pop rule in the design system
   (components.css) is `position: fixed` with a fixed width but NO
   max-height/overflow, and it isn't a flex container. Its children (head,
   quote, existing-comment thread, the compose textarea, then the Cancel/
   Comment footer) just stack in normal flow, so the box's height is purely
   content-driven. Once a long in-progress comment or thread pushed that
   content taller than the viewport, there was nothing to scroll (a `position:
   fixed` element does not move when the page scrolls) and no cap on the
   textarea itself (only `resize: vertical` from the base rule, which lets a
   user drag it arbitrarily tall) — so the footer with Cancel/Comment simply
   rendered off-screen with no way to reach it. Turning the popup into a
   height-capped flex column, with the existing-comment thread and the
   textarea as the only two internally-scrolling regions, guarantees the
   header/quote/footer always stay on-screen and reachable regardless of
   comment length.
*/
/* Follow-up (live review): the popover used to let the *textarea* resize
   itself natively (resize: both on the input), with a separate function
   (growPopToFitTextarea, since removed) trying to widen the card to match —
   width-only, and only grows, never shrinks. Worse, [data-existing] held the
   flex-grow (flex: 1 1 auto) while the textarea was flex: 0 0 auto (fixed to
   its own dragged height), so growing the textarea taller — with the card's
   max-height capped and overflow: hidden — forced [data-existing] to shrink
   to compensate, i.e. the textarea visibly grew *upward* into the existing
   comment thread. Fix: resize the CARD itself (native `resize: both` on
   .rds-cmt-pop, min/max-width/height as browser-enforced clamps — no JS math
   needed), and swap the flex roles so the textarea (flex: 1 1 auto) absorbs
   all extra vertical space while [data-existing] (flex: 0 1 auto, no grow)
   only ever sizes up to its own content height — it stops "expanding" the
   moment it no longer needs a scrollbar, and any further card growth flows
   entirely into the textarea instead of stretching blank space under a short
   comment thread.

   min-height is deliberately generous (280px), not a round guess: with
   [data-existing] free to shrink all the way to 0 (by design, so a small
   card doesn't force it to stay artificially tall), the footer's Cancel/
   Comment buttons are the thing standing between "reachable" and exactly the
   bug described above. Measured floor at the resize handle's min drag size:
   head ~48px + quote ~84px (3-line clamp, its worst case) + textarea's own
   44px min-height + foot ~26px + 24px pop padding + ~27px inter-element
   margins == ~253px. 280px keeps a real margin above that measured floor
   rather than shipping a value pixel-tight enough that a font/zoom-level
   difference could clip the footer again.
*/
.rds-cmt-pop {{ display: flex; flex-direction: column; min-width: 260px; max-width: min(90vw, 640px); min-height: 280px; max-height: min(72vh, 520px); overflow: hidden; resize: both; }}
.rds-cmt-pop-head {{ flex: 0 0 auto; }}
.rds-cmt-pop .rds-cmt-quote {{ flex: 0 0 auto; }}
.rds-cmt-pop [data-existing] {{ flex: 0 1 auto; min-height: 0; overflow-y: auto; }}
.rds-cmt-pop textarea {{ width: 100%; min-height: 44px; flex: 1 1 auto; overflow-y: auto; resize: none; }}
.rds-cmt-foot {{ flex: 0 0 auto; }}
/* components.css styles .rds-cmt-row and .rds-cmt-av but has no .rds-cmt-cbody
   rule: without min-width: 0 the text column can overflow the popover instead
   of wrapping on long unbroken comment text. */
.rds-cmt-pop .rds-cmt-cbody {{ min-width: 0; }}
.md-cmt-author {{ flex: 0 1 110px; min-width: 64px; height: 24px; padding: 0 8px; margin-left: 8px; border: 1px solid var(--rds-line); border-radius: var(--radius-sharp); background: var(--rds-surface); color: var(--rds-ink-2); font-family: var(--rds-font-sans); font-size: 11px; }}
.md-cmt-author:focus {{ outline: none; border-color: var(--rds-accent); }}
.md-cmt-author::placeholder {{ color: var(--rds-ink-5); }}
.rds-cmt-error {{ margin-left: 10px; color: var(--danger-mark); font-size: 11px; }}
/* --danger-mark (dark clay) is tuned for paper, and the design system
   deliberately leaves the pastel -mark/-wash/-edge trio un-rethemed — so on
   dusk/dark it renders ~1.3:1 on the card and the error text effectively
   vanishes. --danger IS themed (brightened clay on dusk/dark), so swap to
   it on the dark palettes only. */
[data-theme="dusk"] .rds-cmt-error, [data-theme="dark"] .rds-cmt-error {{ color: var(--danger); }}
.rds-cmt-pop-head {{ cursor: grab; user-select: none; }}
.rds-cmt-pop-head:active {{ cursor: grabbing; }}
@keyframes md-flash-block {{ 0% {{ background: color-mix(in srgb, var(--rds-accent) 30%, transparent); }} 100% {{ background: transparent; }} }}
.md-flash-block {{ animation: md-flash-block 1.2s ease; }}
/* Foreground was hard-coded #fff: readable on the light palette's mid coral
   (--rds-accent #C07C74), but on dusk/dark the accent flips to a LIGHT
   salmon and white-on-salmon sits ~2:1 — the icon (currentColor, per
   .rds-icon-smart-comment in components.css) all but disappears. The surface
   token is the semantic "what sits under the accent": near-white paper on
   light, dark slate/graphite on dusk/dark — high contrast on all three. */
.md-hl-peek {{
  position: fixed; z-index: 2147483600; display: inline-grid; place-items: center;
  width: 26px; height: 26px; background: var(--rds-accent); color: var(--rds-surface); border: 0; border-radius: 999px; cursor: pointer;
  box-shadow: 0 4px 14px rgba(40,35,25,0.18); transform: translate(-50%, -130%); opacity: 0; pointer-events: none;
  transition: opacity 90ms ease;
}}
.md-hl-peek.show {{ opacity: 1; pointer-events: auto; }}
.md-hl-peek:hover {{ background: var(--rds-accent-strong); }}
.md-hl-peek svg {{ width: 13px; height: 13px; }}
@media (max-width: 860px) {{
  .shell {{ display: block; padding: 22px 18px 72px; }}
  .toc {{ position: static; max-height: none; border-right: 0; border-bottom: 1px solid var(--rds-line); padding: 0 0 16px; margin-bottom: 22px; }}
  .doc :not(tr).md-block > .md-cmt-btn {{ right: 0; top: -4px; }}
  .md-prov-panel {{ right: 8px; left: 8px; width: auto; }}
}}
</style>
</head>
<body>
<header class="topbar">
  <a class="topbtn" href="/" data-home-btn title="Back to md-review list"><span aria-hidden="true">&larr;</span><span>All docs</span></a>
  <div class="brand">
    <b>{html.escape(title)}</b>
    <span>{html.escape(subtitle)}</span>
  </div>
  <div class="spacer"></div>
  <button class="topbtn" data-prov-toggle aria-expanded="false" title="Where this document came from"><span>Source</span></button>
  <span class="theme-picker" role="group" aria-label="Theme for this device only (stored in localStorage, beats the server default)">
    <button class="theme-glyph" data-theme-set="light" type="button" title="Light" aria-label="Light theme">☼</button><button class="theme-glyph" data-theme-set="dusk" type="button" title="Dusk" aria-label="Dusk theme">◐</button><button class="theme-glyph" data-theme-set="dark" type="button" title="Dark" aria-label="Dark theme">☾</button>
  </span>
  <span class="rds-cmt-open" data-open-count>0 open</span>
  <button class="topbtn md-detached-btn" data-detached-btn style="display:none" title="Comments written against earlier revisions of this document — they no longer match any text here">0 detached</button>
  <button class="topbtn" data-open-drawer><span class="rds-icon-smart-comment" aria-hidden="true"></span><span>Comments</span></button>
</header>
<main class="shell">
  <nav class="toc" aria-label="Document outline">
    <div class="toc-title">Outline</div>
    {toc_html or '<span class="rds-cmt-empty">No headings</span>'}
  </nav>
  <article class="doc" data-doc-root data-cmt-scope="doc:{escape_attr(doc_id)}">
    {body}
  </article>
  <div aria-hidden="true"></div>
</main>
<script>
window.MD_REVIEW = {config_json};
</script>
<script>
(() => {{
  const CFG = window.MD_REVIEW;
  const root = document.querySelector('[data-doc-root]');
  const openCount = document.querySelector('[data-open-count]');
  const detachedBtn = document.querySelector('[data-detached-btn]');
  const ICON = '<span class="rds-icon-smart-comment" aria-hidden="true"></span>';
  let comments = [];
  let pop = null;
  let drawer = null;
  let selectionInfo = null;
  let trigger = null;

  let popOffset = {{ dx: 0, dy: 0 }};
  try {{ popOffset = JSON.parse(localStorage.getItem('mdReviewPopOffset') || '') || popOffset; }} catch (err) {{ /* corrupt storage, use default */ }}
  let popSize = null;
  try {{ popSize = JSON.parse(localStorage.getItem('mdReviewPopSize') || 'null'); }} catch (err) {{ popSize = null; }}
  let authorName = '';
  try {{ authorName = localStorage.getItem('mdReviewAuthor') || ''; }} catch (err) {{ authorName = ''; }}
  let activePopObserver = null;
  let peekEl = null;
  let peekHover = false;
  let peekThreadId = null;
  let peekHideTimer = null;

  const esc = (s) => String(s || '').replace(/[&<>"']/g, (ch) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
  const nowLabel = (iso) => {{
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso || '';
    const mins = Math.round((Date.now() - t) / 60000);
    if (mins < 1) return 'now';
    if (mins < 60) return `${{mins}}m ago`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return `${{hours}}h ago`;
    const days = Math.round(hours / 24);
    return days < 30 ? `${{days}}d ago` : new Date(iso).toISOString().slice(0, 10);
  }};
  const initials = (name) => String(name || '?').trim().split(/\\s+/).map((w) => w[0]).join('').slice(0,2).toUpperCase();

  // ---- theme glyph picker ----------------------------------------------
  // The picked theme persists to localStorage (mdReviewTheme), overrides
  // the server default on THIS device only, and applies with no flash on
  // the next load. The active glyph is always painted from the <html>
  // attribute (the bootstrap has already resolved override/server/OS state
  // by the time this runs), so the picker can never lie about what is
  // actually painted. 'light' sets the attribute too (no palette block
  // exists for it — it falls through to :root) so the read-back is uniform.
  const themeGlyphs = [...document.querySelectorAll('[data-theme-set]')];
  const currentTheme = () => document.documentElement.getAttribute('data-theme') || 'light';
  const paintThemeGlyphs = () => {{
    for (const g of themeGlyphs) g.classList.toggle('active', g.dataset.themeSet === currentTheme());
  }};
  for (const g of themeGlyphs) {{
    g.addEventListener('click', () => {{
      const next = g.dataset.themeSet;
      document.documentElement.setAttribute('data-theme', next);
      try {{ localStorage.setItem('mdReviewTheme', next); }} catch (err) {{ /* storage unavailable: apply for this page view only */ }}
      paintThemeGlyphs();
    }});
  }}
  paintThemeGlyphs();

  // ---- provenance panel ------------------------------------------------
  const PROV_FIELDS = [
    ['sourcePath', 'Source path'],
    ['sourceAbsPath', 'Absolute path'],
    ['sourceRepoName', 'Repo'],
    ['sourceRepoRoot', 'Repo root'],
    ['sourceRepoBranch', 'Branch'],
    ['sourceRepoRemote', 'Remote'],
    ['agent', 'Agent'],
    ['agentCwd', 'Agent cwd'],
    ['sessionId', 'Session ID'],
    ['hostname', 'Host'],
    ['user', 'Rendered by'],
    ['createdAt', 'First rendered'],
    ['renderedAt', 'Last rendered'],
  ];
  let provPanel = null;
  function ensureProvPanel() {{
    if (provPanel) return provPanel;
    provPanel = document.createElement('div');
    provPanel.className = 'md-prov-panel';
    provPanel.setAttribute('role', 'dialog');
    provPanel.setAttribute('aria-label', 'Document provenance');
    const prov = CFG.provenance || {{}};
    const rows = PROV_FIELDS.map(([key, label]) => {{
      const value = prov[key] || CFG[key] || '';
      return `<div class="md-prov-row"><dt>${{esc(label)}}</dt><dd>${{esc(value) || '&mdash; unknown &mdash;'}}</dd></div>`;
    }}).join('');
    provPanel.innerHTML = `<h2>Document provenance</h2><dl>${{rows}}</dl>`;
    provPanel.style.display = 'none';
    document.body.appendChild(provPanel);
    return provPanel;
  }}
  const provToggle = document.querySelector('[data-prov-toggle]');
  provToggle.addEventListener('click', (event) => {{
    event.stopPropagation();
    const panel = ensureProvPanel();
    const open = panel.style.display !== 'none';
    panel.style.display = open ? 'none' : 'block';
    provToggle.setAttribute('aria-expanded', String(!open));
  }});
  document.addEventListener('click', (event) => {{
    if (!provPanel || provPanel.style.display === 'none') return;
    if (event.target.closest('.md-prov-panel') || event.target.closest('[data-prov-toggle]')) return;
    provPanel.style.display = 'none';
    provToggle.setAttribute('aria-expanded', 'false');
  }});

  function anchorFromElement(el, quoteOverride) {{
    return {{
      type: 'md-element',
      docId: CFG.docId,
      docPath: CFG.sourcePath,
      anchorId: el.dataset.cmtAnchor,
      semanticKey: el.dataset.cmtSemanticKey,
      elementKind: el.dataset.cmtKind,
      headingPath: (el.dataset.cmtHeadingPath || '').split(' > ').filter(Boolean),
      label: el.dataset.cmtLabel || 'Document element',
      contentHash: el.dataset.cmtContentHash,
      quote: quoteOverride || el.dataset.cmtQuote || el.textContent.trim().slice(0, 420),
    }};
  }}
  const exactKey = (anchor) => anchor && anchor.anchorId ? `id:${{anchor.anchorId}}` : '';
  const semanticKey = (anchor) => anchor && anchor.semanticKey ? `sem:${{anchor.semanticKey}}` : '';
  // Orphan-on-mismatch. semanticKey is a
  // POSITION key — heading path + element kind + ordinal — so it resolves to
  // whatever element now occupies that slot, no matter what the slot now
  // SAYS. After a full rewrite of a document, old comments stayed visually attached
  // to brand-new, unrelated paragraphs: the stored contentHash disagreed and
  // nothing checked it. A comment re-bound to text it was never written about
  // is silent misattribution, which is worse than a lost anchor — so the
  // stored contentHash is now a precondition of any positional re-bind.
  // Anchors written before contentHash existed (no field) are exempt; the
  // anchorId path is hash-derived and the contentHash path is hash-exact, so
  // this only ever gates the semanticKey fallback. Read-side only: the write
  // format is untouched and existing stores keep working.
  function hashMatches(anchor, el) {{
    if (!anchor || !el) return false;
    if (!anchor.contentHash) return true;
    return el.dataset.cmtContentHash === anchor.contentHash;
  }}
  function elementFor(anchor) {{
    if (!anchor) return null;
    if (anchor.anchorId) {{
      const el = root.querySelector(`[data-cmt-anchor="${{CSS.escape(anchor.anchorId)}}"]`);
      if (el) return el;
    }}
    if (anchor.semanticKey) {{
      const el = root.querySelector(`[data-cmt-semantic-key="${{CSS.escape(anchor.semanticKey)}}"]`);
      if (el && hashMatches(anchor, el)) return el;
    }}
    if (anchor.contentHash) {{
      return root.querySelector(`[data-cmt-content-hash="${{CSS.escape(anchor.contentHash)}}"]`);
    }}
    return null;
  }}
  // Single-resolution rule: a stored comment belongs to
  // EXACTLY ONE element, chosen by ordered fallback — anchorId first (the
  // content survived), semanticKey only when no element claims the anchorId
  // (same slot, edited text), and contentHash only when it matches UNIQUELY
  // (a first-match-any-twin rule could hand the comment to the wrong
  // duplicate). The previous OR-match (sameAnchor) let one comment badge two
  // elements at once after an insertion: its anchorId still matched the
  // original paragraph while its stale semanticKey matched the inserted one.
  function elementForComment(c) {{
    const a = (c && c.anchor) || {{}};
    if (a.anchorId) {{
      const el = root.querySelector(`[data-cmt-anchor="${{CSS.escape(a.anchorId)}}"]`);
      if (el) return el;
    }}
    if (a.semanticKey) {{
      const el = root.querySelector(`[data-cmt-semantic-key="${{CSS.escape(a.semanticKey)}}"]`);
      if (el && hashMatches(a, el)) return el;
    }}
    if (a.contentHash) {{
      const els = root.querySelectorAll(`[data-cmt-content-hash="${{CSS.escape(a.contentHash)}}"]`);
      if (els.length === 1) return els[0];
    }}
    return null;
  }}
  // A comment nothing in THIS render can carry: its element is gone or the
  // text under its anchor changed. It never attaches; it shows detached, with
  // its original quote, in the Comments drawer.
  function isDetached(c) {{ return !elementForComment(c); }}
  function commentsForElement(el) {{
    if (!el) return [];
    return comments.filter((c) => elementForComment(c) === el);
  }}
  function spanForComment(id) {{
    return root.querySelector(`.rds-cmt-hl[data-thread="${{CSS.escape(id)}}"]`);
  }}

  function offsetToPoint(segments, offset) {{
    for (const seg of segments) {{
      if (offset >= seg.start && offset <= seg.end) return {{ node: seg.node, offset: offset - seg.start }};
    }}
    return null;
  }}
  function findRangeForText(container, needle) {{
    const cleanNeedle = String(needle || '').replace(/\\s+/g, ' ').trim();
    if (!cleanNeedle) return null;
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
    let fullText = '';
    const segments = [];
    let node;
    while ((node = walker.nextNode())) {{
      const raw = node.nodeValue;
      segments.push({{ node, start: fullText.length, end: fullText.length + raw.length }});
      fullText += raw;
    }}
    let idx = fullText.indexOf(cleanNeedle);
    if (idx === -1) {{
      const normFull = fullText.replace(/\\s+/g, ' ');
      if (normFull === fullText) return null;
      idx = normFull.indexOf(cleanNeedle);
      if (idx === -1) return null;
    }}
    const start = offsetToPoint(segments, idx);
    const end = offsetToPoint(segments, idx + cleanNeedle.length);
    if (!start || !end) return null;
    const range = document.createRange();
    range.setStart(start.node, start.offset);
    range.setEnd(end.node, end.offset);
    return range;
  }}
  function wrapRangeAsHighlight(range, commentId) {{
    const nodes = [];
    const walker = document.createTreeWalker(range.commonAncestorContainer, NodeFilter.SHOW_TEXT, null);
    let n;
    while ((n = walker.nextNode())) {{ if (range.intersectsNode(n)) nodes.push(n); }}
    if (range.commonAncestorContainer.nodeType === 3) nodes.push(range.commonAncestorContainer);
    for (let i = nodes.length - 1; i >= 0; i--) {{
      const node = nodes[i];
      if (!node.parentNode || !node.textContent) continue;
      let s = 0;
      let e = node.length;
      if (node === range.startContainer) s = range.startOffset;
      if (node === range.endContainer) e = range.endOffset;
      if (s >= e) continue;
      const r = document.createRange();
      r.setStart(node, s);
      r.setEnd(node, e);
      const span = document.createElement('span');
      span.className = 'rds-cmt-hl';
      span.dataset.thread = commentId;
      try {{ r.surroundContents(span); }} catch (err) {{ continue; }}
    }}
    const sel = window.getSelection();
    if (sel) sel.removeAllRanges();
  }}
  function restoreHighlights() {{
    for (const c of comments) {{
      if (spanForComment(c.id)) continue;
      const quote = (c.quote || '').trim();
      if (!quote) continue;
      const block = elementForComment(c);
      if (!block) continue;
      const normQuote = quote.replace(/\\s+/g, ' ').trim();
      const normBlock = block.textContent.replace(/\\s+/g, ' ').trim();
      if (!normQuote || normQuote === normBlock) continue;
      const range = findRangeForText(block, quote);
      if (!range) continue;
      try {{ wrapRangeAsHighlight(range, c.id); }} catch (err) {{ /* best-effort restore, skip on failure */ }}
    }}
  }}

  function ensurePeek() {{
    if (peekEl) return peekEl;
    peekEl = document.createElement('button');
    peekEl.type = 'button';
    peekEl.className = 'md-hl-peek';
    peekEl.innerHTML = ICON;
    peekEl.setAttribute('aria-label', 'View comment');
    peekEl.addEventListener('mouseenter', () => {{ peekHover = true; }});
    peekEl.addEventListener('mouseleave', () => {{ peekHover = false; hidePeekSoon(); }});
    peekEl.addEventListener('click', () => {{
      const c = comments.find((x) => x.id === peekThreadId);
      if (c) openThread(c.anchor, peekEl.getBoundingClientRect());
    }});
    document.body.appendChild(peekEl);
    return peekEl;
  }}
  function showPeek(span) {{
    clearTimeout(peekHideTimer);
    const p = ensurePeek();
    peekThreadId = span.dataset.thread;
    const rect = span.getBoundingClientRect();
    p.style.left = `${{rect.left + rect.width / 2}}px`;
    p.style.top = `${{rect.top}}px`;
    p.classList.add('show');
  }}
  function hidePeekSoon() {{
    clearTimeout(peekHideTimer);
    peekHideTimer = setTimeout(() => {{
      if (peekHover) return;
      if (peekEl) peekEl.classList.remove('show');
    }}, 150);
  }}
  root.addEventListener('mouseover', (event) => {{
    const hl = event.target.closest('.rds-cmt-hl[data-thread]');
    if (!hl) return;
    showPeek(hl);
  }});
  root.addEventListener('mouseout', (event) => {{
    const hl = event.target.closest('.rds-cmt-hl[data-thread]');
    if (!hl) return;
    const to = event.relatedTarget;
    if (to && to.closest && to.closest('.rds-cmt-hl[data-thread]') === hl) return;
    hidePeekSoon();
  }});
  root.addEventListener('click', (event) => {{
    const hl = event.target.closest('.rds-cmt-hl[data-thread]');
    if (!hl) return;
    const sel = window.getSelection();
    if (sel && !sel.isCollapsed) return;
    const c = comments.find((x) => x.id === hl.dataset.thread);
    if (!c) return;
    openThread(c.anchor, hl.getBoundingClientRect());
  }});

  async function loadComments() {{
    const res = await fetch(`/comments?doc=${{encodeURIComponent(CFG.docId)}}`);
    if (!res.ok) throw new Error(`GET /comments failed: ${{res.status}}`);
    comments = await res.json();
    restoreHighlights();
    repaint();
  }}
  async function postComment(anchor, text) {{
    const body = {{ docId: CFG.docId, docPath: CFG.sourcePath, anchor, quote: anchor.quote, text }};
    if (authorName) body.author = authorName;
    const res = await fetch('/comments', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(body),
    }});
    if (!res.ok) {{
      const err = await res.json().catch(() => ({{}}));
      throw new Error(err.error || `POST /comments failed: ${{res.status}}`);
    }}
    const created = await res.json();
    comments.push(created);
    repaint();
    return created;
  }}
  async function setResolved(id, resolved) {{
    const res = await fetch('/comments/resolve', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ docId: CFG.docId, id, resolved }}),
    }});
    if (!res.ok) {{
      const err = await res.json().catch(() => ({{}}));
      throw new Error(err.error || `resolve failed: ${{res.status}}`);
    }}
    const updated = await res.json();
    const local = comments.find((c) => c.id === id);
    if (local) local.resolved = updated.resolved;
    repaint();
  }}

  function decorate() {{
    for (const el of root.querySelectorAll('[data-cmt-anchor]')) {{
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'md-cmt-btn';
      btn.title = 'Comment';
      btn.setAttribute('aria-label', 'Comment');
      btn.innerHTML = ICON;
      btn.addEventListener('click', (event) => {{
        event.preventDefault();
        event.stopPropagation();
        openThread(anchorFromElement(el), btn.getBoundingClientRect());
      }});
      if (el.tagName === 'TR') {{
        const cell = el.querySelector('.md-cmt-col');
        if (cell) {{
          cell.classList.add('md-cmt-cell');
          cell.appendChild(btn);
        }}
      }} else {{
        el.appendChild(btn);
      }}
    }}
  }}

  function repaint() {{
    const total = comments.filter((c) => !c.resolved).length;
    openCount.textContent = `${{total}} open`;
    const detachedCount = comments.filter((c) => !c.resolved && isDetached(c)).length;
    if (detachedBtn) {{
      detachedBtn.textContent = `${{detachedCount}} detached`;
      detachedBtn.style.display = detachedCount ? '' : 'none';
    }}
    for (const el of root.querySelectorAll('[data-cmt-anchor]')) {{
      const count = commentsForElement(el).filter((c) => !c.resolved).length;
      const btn = el.tagName === 'TR' ? el.querySelector('.md-cmt-cell .md-cmt-btn') : el.querySelector(':scope > .md-cmt-btn');
      if (btn) {{
        btn.classList.toggle('has-comments', count > 0);
        btn.innerHTML = `${{ICON}}${{count ? `<span class="rds-cbadge rds-cbadge--sm rds-cbadge--soft">${{count}}</span>` : ''}}`;
      }}
      el.classList.toggle('md-orphan', false);
    }}
    for (const c of comments) {{
      for (const span of root.querySelectorAll(`.rds-cmt-hl[data-thread="${{CSS.escape(c.id)}}"]`)) {{
        span.classList.toggle('resolved', !!c.resolved);
      }}
    }}
    if (drawer && drawer.classList.contains('open')) renderDrawer();
  }}

  function closePop() {{
    if (activePopObserver) {{ activePopObserver.disconnect(); activePopObserver = null; }}
    if (pop) pop.remove();
    pop = null;
    root.querySelectorAll('.rds-cmt-hl.is-active').forEach((n) => n.classList.remove('is-active'));
  }}
  function placePop(el, rect) {{
    const width = el.offsetWidth || 328;
    let left = rect.left + rect.width / 2 - width / 2 + popOffset.dx;
    left = Math.max(12, Math.min(left, window.innerWidth - width - 12));
    let top = rect.bottom + 8 + popOffset.dy;
    const h = el.offsetHeight || 240;
    if (top + h > window.innerHeight - 12) top = Math.max(12, rect.top - h - 8);
    top = Math.max(12, Math.min(top, window.innerHeight - 12));
    el.style.left = `${{left}}px`;
    el.style.top = `${{top}}px`;
    el.classList.add('show');
    pop = el;
    wireDrag(el);
  }}
  function wireDrag(el) {{
    const head = el.querySelector('.rds-cmt-pop-head');
    if (!head) return;
    head.addEventListener('mousedown', (event) => {{
      if (event.target.closest('[data-x]')) return;
      event.preventDefault();
      const startX = event.clientX;
      const startY = event.clientY;
      const startLeft = parseFloat(el.style.left) || 0;
      const startTop = parseFloat(el.style.top) || 0;
      let dx = 0;
      let dy = 0;
      const onMove = (moveEvent) => {{
        dx = moveEvent.clientX - startX;
        dy = moveEvent.clientY - startY;
        el.style.left = `${{startLeft + dx}}px`;
        el.style.top = `${{startTop + dy}}px`;
      }};
      const onUp = () => {{
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        if (dx || dy) {{
          popOffset = {{ dx: popOffset.dx + dx, dy: popOffset.dy + dy }};
          localStorage.setItem('mdReviewPopOffset', JSON.stringify(popOffset));
        }}
      }};
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    }});
  }}
  function wirePopResize(el) {{
    if (popSize) {{
      el.style.width = `${{popSize.w}}px`;
      el.style.height = `${{popSize.h}}px`;
    }}
    if (typeof ResizeObserver === 'undefined') return;
    if (activePopObserver) activePopObserver.disconnect();
    // ResizeObserver fires once immediately on observe() with whatever size
    // the card happens to auto-lay-out at (content-driven — e.g. a thread
    // with no existing comments naturally renders shorter than one with
    // three). That mount-time callback is not a user resize; persisting it
    // would silently pin that thread's incidental size as the sticky default
    // for every future popover. Skip it — only a real post-mount size
    // change (an actual drag on the native resize handle) should persist.
    let mounted = false;
    activePopObserver = new ResizeObserver(() => {{
      if (!mounted) {{ mounted = true; return; }}
      // Read el.offsetWidth/offsetHeight (border-box, matches the inline width/
      // height we set) rather than entry.contentRect (content-box-only) so
      // persisted size reapplies to the exact same rendered box next time.
      const w = Math.round(el.offsetWidth);
      const h = Math.round(el.offsetHeight);
      if (w > 40 && h > 40) {{
        popSize = {{ w, h }};
        localStorage.setItem('mdReviewPopSize', JSON.stringify(popSize));
      }}
    }});
    activePopObserver.observe(el);
  }}
  function commentRow(c) {{
    return `<div class="rds-cmt-row">
      <div class="rds-cmt-av">${{esc(initials(c.author))}}</div>
      <div class="rds-cmt-cbody">
        <div><span class="rds-cmt-who">${{esc(c.author)}}</span><span class="rds-cmt-when">${{esc(nowLabel(c.created_at))}}</span></div>
        <div class="rds-cmt-text">${{esc(c.text)}}</div>
        <div class="rds-cmt-imeta">
          ${{c.resolved ? '<span class="rds-cmt-resolved"><span class="d"></span>resolved</span>' : '<span class="rds-cmt-open">open</span>'}}
          <button class="rds-cmt-btn ghost" data-resolve="${{esc(c.id)}}" data-state="${{c.resolved ? '1' : '0'}}">${{c.resolved ? 'Reopen' : 'Resolve'}}</button>
        </div>
      </div>
    </div>`;
  }}
  function openThread(anchor, rect, range) {{
    closePop();
    const anchorEl = elementFor(anchor);
    const existing = commentsForElement(anchorEl).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''));
    const el = document.createElement('div');
    el.className = 'rds-cmt-pop';
    el.innerHTML = `<div class="rds-cmt-pop-head">
      <span class="rds-cmt-ttl">${{existing.length ? `${{existing.length}} comment${{existing.length === 1 ? '' : 's'}}` : 'New comment'}}</span>
      <span class="rds-cmt-crumb">· ${{esc(anchor.label)}}</span>
      <span class="rds-cmt-x" data-x>×</span>
    </div>
    <div class="rds-cmt-quote">${{esc(anchor.quote || '')}}</div>
    <div data-existing>${{existing.map(commentRow).join('')}}</div>
    <textarea class="rds-cmt-input" placeholder="Add your comment..."></textarea>
    <div class="rds-cmt-foot">
      <span class="rds-cmt-anchored"><span class="rds-icon-smart-comment" aria-hidden="true"></span><span>anchored</span></span>
      <input class="md-cmt-author" data-author type="text" maxlength="60" placeholder="name (optional)" aria-label="Comment author name">
      <span class="rds-cmt-error" data-error></span>
      <div class="rds-cmt-acts"><button class="rds-cmt-btn ghost" data-cancel>Cancel</button><button class="rds-cmt-btn primary" data-post disabled>Comment</button></div>
    </div>`;
    el.querySelector('[data-x]').addEventListener('click', closePop);
    el.querySelector('[data-cancel]').addEventListener('click', closePop);
    const input = el.querySelector('textarea');
    const post = el.querySelector('[data-post]');
    const error = el.querySelector('[data-error]');
    const authorInput = el.querySelector('[data-author]');
    authorInput.value = authorName;
    authorInput.addEventListener('input', () => {{
      authorName = authorInput.value.trim();
      try {{ localStorage.setItem('mdReviewAuthor', authorName); }} catch (err) {{ /* storage unavailable, keep in-memory only */ }}
    }});
    input.addEventListener('input', () => {{ post.disabled = !input.value.trim(); error.textContent = ''; }});
    const send = async () => {{
      const text = input.value.trim();
      if (!text) return;
      post.disabled = true;
      try {{
        const created = await postComment(anchor, text);
        closePop();
        if (range) {{
          try {{ wrapRangeAsHighlight(range, created.id); }} catch (err) {{ /* selection spanned an unwrappable range, skip inline highlight */ }}
        }}
        const target = spanForComment(created.id) || elementFor(anchor);
        if (target) flashTarget(target);
      }} catch (err) {{
        error.textContent = err.message;
        post.disabled = false;
      }}
    }};
    post.addEventListener('click', send);
    input.addEventListener('keydown', (event) => {{
      if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {{ event.preventDefault(); send(); }}
      if (event.key === 'Escape') {{ event.preventDefault(); closePop(); }}
    }});
    for (const btn of el.querySelectorAll('[data-resolve]')) {{
      btn.addEventListener('click', async () => {{
        try {{
          await setResolved(btn.dataset.resolve, btn.dataset.state !== '1');
          openThread(anchor, rect);
        }} catch (err) {{
          error.textContent = err.message;
        }}
      }});
    }}
    document.body.appendChild(el);
    wirePopResize(el);
    placePop(el, rect);
    setTimeout(() => input.focus(), 40);
  }}
  function flashTarget(el) {{
    el.scrollIntoView({{ block: 'center' }});
    const isHighlightSpan = el.classList.contains('rds-cmt-hl');
    el.classList.remove('flash', 'md-flash-block');
    void el.offsetWidth;
    el.classList.add(isHighlightSpan ? 'flash' : 'md-flash-block');
    setTimeout(() => el.classList.remove('flash', 'md-flash-block'), 1250);
  }}

  function ensureTrigger() {{
    if (trigger) return trigger;
    trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'rds-cmt-trigger';
    trigger.innerHTML = `${{ICON}}<span>Comment</span>`;
    trigger.addEventListener('mousedown', (event) => event.preventDefault());
    trigger.addEventListener('click', () => {{
      if (!selectionInfo) return;
      const info = selectionInfo;
      hideTrigger();
      openThread(info.anchor, info.rect, info.range);
    }});
    document.body.appendChild(trigger);
    return trigger;
  }}
  function hideTrigger() {{
    if (trigger) trigger.classList.remove('show');
    selectionInfo = null;
  }}
  document.addEventListener('mouseup', (event) => {{
    if (event.target.closest('.rds-cmt-pop') || event.target.closest('.rds-cmt-inbox') || event.target.closest('.md-cmt-btn')) return;
    setTimeout(() => {{
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed || !sel.rangeCount) {{ hideTrigger(); return; }}
      const text = sel.toString().trim();
      if (!text) {{ hideTrigger(); return; }}
      const range = sel.getRangeAt(0);
      if (!root.contains(range.commonAncestorContainer)) {{ hideTrigger(); return; }}
      const block = (range.startContainer.nodeType === 1 ? range.startContainer : range.startContainer.parentElement).closest('[data-cmt-anchor]');
      if (!block) {{ hideTrigger(); return; }}
      const rect = range.getBoundingClientRect();
      const trig = ensureTrigger();
      selectionInfo = {{ anchor: anchorFromElement(block, text), rect, range: range.cloneRange() }};
      trig.style.left = `${{rect.left + rect.width / 2}}px`;
      // The trigger used to sit ON the highlighted text, not above it. The
      // design system's own .rds-cmt-trigger rule (components.css) applies
      // `transform: translate(-50%, -10px)` on top of whatever `top` we set —
      // so `top: rect.top` renders the button's bottom edge at
      // rect.top - 10 + trig.offsetHeight, i.e. ~20px *into* the selection.
      // Solve for the `top` that instead lands the button's bottom edge
      // TRIGGER_GAP px above the selection: top = rect.top - gap - height + 10
      // (the +10 undoes the shared rule's own upward shift so it isn't
      // double-applied). Reads trig.offsetHeight live rather than hardcoding
      // the design system's 30px so this can't silently drift out of sync.
      const TRIGGER_GAP = 8;
      trig.style.top = `${{rect.top - TRIGGER_GAP - trig.offsetHeight + 10}}px`;
      trig.classList.add('show');
    }}, 0);
  }});

  function ensureDrawer() {{
    if (drawer) return drawer;
    drawer = document.createElement('aside');
    drawer.className = 'rds-cmt-inbox';
    drawer.setAttribute('aria-label', 'Comments');
    drawer.innerHTML = `<div class="rds-cmt-inbox-head"><b>Comments</b><span class="rds-cmt-open" data-drawer-count></span><span class="rds-cmt-x" data-close style="margin-left:auto">×</span></div>
      <div class="rds-cmt-inbox-filter"><span class="rds-cmt-seg"><button data-filter="open" aria-pressed="true">Open</button><button data-filter="resolved" aria-pressed="false">Resolved</button><button data-filter="detached" aria-pressed="false">Detached</button><button data-filter="all" aria-pressed="false">All</button></span></div>
      <div class="rds-cmt-inbox-list"></div>`;
    drawer.dataset.filter = 'open';
    document.body.appendChild(drawer);
    drawer.querySelector('[data-close]').addEventListener('click', () => drawer.classList.remove('open'));
    for (const btn of drawer.querySelectorAll('[data-filter]')) {{
      btn.addEventListener('click', () => {{
        drawer.dataset.filter = btn.dataset.filter;
        for (const b of drawer.querySelectorAll('[data-filter]')) b.setAttribute('aria-pressed', String(b === btn));
        renderDrawer();
      }});
    }}
    return drawer;
  }}
  function renderDrawer() {{
    const d = ensureDrawer();
    d.querySelector('[data-drawer-count]').textContent = `${{comments.filter((c) => !c.resolved).length}} open`;
    let items = [...comments].sort((a,b) => (b.created_at || '').localeCompare(a.created_at || ''));
    if (d.dataset.filter === 'open') items = items.filter((c) => !c.resolved);
    if (d.dataset.filter === 'resolved') items = items.filter((c) => c.resolved);
    if (d.dataset.filter === 'detached') items = items.filter((c) => isDetached(c));
    const list = d.querySelector('.rds-cmt-inbox-list');
    if (!items.length) {{
      list.innerHTML = d.dataset.filter === 'detached'
        ? '<div class="rds-cmt-empty">No detached comments — every comment still matches the text it was written on.</div>'
        : '<div class="rds-cmt-empty">No comments.</div>';
      return;
    }}
    list.innerHTML = items.map((c) => `<div class="rds-cmt-item${{c.resolved ? ' resolved' : ''}}${{isDetached(c) ? ' md-detached-item' : ''}}" data-comment-id="${{esc(c.id)}}">
      <div class="rds-cmt-icrumb">${{esc((c.anchor && (c.anchor.label || c.anchor.elementKind)) || 'Document element')}}</div>
      ${{isDetached(c) ? '<div class="md-detached-tag">detached &middot; written on an earlier revision; the text below is the original quote</div>' : ''}}
      <div class="rds-cmt-iquote">${{esc(c.quote || (c.anchor && c.anchor.quote) || '')}}</div>
      <div class="rds-cmt-ilast"><span class="rds-cmt-who">${{esc(c.author)}}</span><span class="rds-cmt-itxt">${{esc(c.text)}}</span></div>
      <div class="rds-cmt-imeta"><span>${{esc(nowLabel(c.created_at))}}</span>${{c.resolved ? '·<span>resolved</span>' : ''}}</div>
    </div>`).join('');
    for (const item of list.querySelectorAll('.rds-cmt-item')) {{
      item.addEventListener('click', () => {{
        const c = comments.find((x) => x.id === item.dataset.commentId);
        const el = c && (spanForComment(c.id) || elementForComment(c));
        if (el) {{
          d.classList.remove('open');
          flashTarget(el);
          openThread(c.anchor, el.getBoundingClientRect());
        }} else if (c) {{
          alert('Detached comment — the text it was written on has changed or is gone in this render, so it is deliberately not attached to any element. Its original quote is shown above and it remains in comments.json.');
        }}
      }});
    }}
  }}
  document.querySelector('[data-open-drawer]').addEventListener('click', () => {{
    const d = ensureDrawer();
    renderDrawer();
    d.classList.toggle('open');
  }});
  if (detachedBtn) {{
    detachedBtn.addEventListener('click', () => {{
      const d = ensureDrawer();
      d.dataset.filter = 'detached';
      for (const b of d.querySelectorAll('[data-filter]')) b.setAttribute('aria-pressed', String(b.dataset.filter === 'detached'));
      renderDrawer();
      d.classList.add('open');
    }});
  }}

  // Authors write GitHub-style fragments (#install), but heading ids here are
  // heading-PATH slugs (guide-install). When the fragment names no element,
  // fall back to the heading whose data-slug (its own-text slug) matches.
  function resolveFragment() {{
    let slug;
    try {{ slug = decodeURIComponent(location.hash.slice(1)); }} catch (err) {{ return; }}
    if (!slug || document.getElementById(slug)) return;
    const el = document.querySelector('[data-slug="' + CSS.escape(slug) + '"]')
      || document.querySelector('[data-slug="' + CSS.escape(slug.toLowerCase()) + '"]');
    if (el) el.scrollIntoView();
  }}
  window.addEventListener('hashchange', resolveFragment);
  resolveFragment();

  decorate();
  loadComments().catch((err) => {{
    openCount.textContent = 'comments unavailable';
    console.error(err);
  }});
}})();
</script>
</body>
</html>
"""
