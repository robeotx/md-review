"""Renderer regression tests."""

from __future__ import annotations

import unittest

from mdreview.renderer import LinkRendering, MarkdownRenderer, page_html


class MarkdownRendererTests(unittest.TestCase):
    def test_table_cell_escaped_pipe_inside_code_span_does_not_split_column(self) -> None:
        # Regression for the `draft\|final` report: the naive
        # `row.split("|")` used to break this single 2-column data row into
        # extra pieces and silently drop everything past the declared width.
        renderer = MarkdownRenderer()
        body = renderer.render(
            "| field | meaning |\n"
            "|---|---|\n"
            "| `doc.state` | enum(2) `draft\\|final` — the seam |\n"
        )
        # NOTE: a raw `<td>` COUNT check is not a useful assertion here —
        # _render_table always pads/truncates a parsed row to exactly the
        # header's declared width (see `padded = row + [""] * ...` /
        # `padded[:width]`), so the count is forced to 2 regardless of whether
        # the split above it was correct. The only real signal is the content:
        # the rendered <td> must show a plain pipe with no backslash and must
        # still carry the trailing " — the seam" text that a mis-split row
        # would push into a truncated, dropped 3rd piece.
        # (data-cmt-quote deliberately keeps the raw "draft\|final"
        # source for anchor-matching metadata — that copy is not a bug.)
        self.assertIn(
            '<td>enum(2) <code class="md-inline-code">draft|final</code> — the seam</td>', body
        )

    def test_table_cell_multiple_escaped_pipes_one_cell(self) -> None:
        renderer = MarkdownRenderer()
        body = renderer.render(
            "| field | meaning |\n"
            "|---|---|\n"
            "| `doc.tier` | enum(4) `0\\|1\\|2\\|3` | which ring |\n"
        )
        # Row only declares 2 columns; a 3rd literal pipe-delimited pseudo-cell
        # ("which ring") is intentionally beyond width and gets dropped by
        # existing design (_render_table's width-truncation contract) — what
        # must NOT happen is the 3 escaped pipes inside the code span each
        # causing a split.
        self.assertIn('<code class="md-inline-code">0|1|2|3</code>', body)

    def test_table_cell_escaped_pipe_at_both_ends_of_code_span(self) -> None:
        renderer = MarkdownRenderer()
        body = renderer.render(
            "| field | meaning |\n"
            "|---|---|\n"
            "| edge | surprise = `\\|graph_proximity - embedding_similarity\\|` |\n"
        )
        self.assertIn('<code class="md-inline-code">|graph_proximity - embedding_similarity|</code>', body)

    def test_table_cell_bare_escaped_pipe_without_code_span(self) -> None:
        renderer = MarkdownRenderer()
        body = renderer.render(
            "| field | meaning |\n"
            "|---|---|\n"
            "| bare | literal a\\|b without backticks |\n"
        )
        self.assertIn("<td>literal a|b without backticks</td>", body)

    def test_table_cell_unescaped_pipe_inside_code_span_does_not_split(self) -> None:
        # A raw (non-backslash-escaped) pipe inside a code span is also a
        # column-separator false positive: the span is one opaque inline unit,
        # same as render_inline's own code-span handling.
        renderer = MarkdownRenderer()
        body = renderer.render(
            "| field | meaning |\n"
            "|---|---|\n"
            "| raw | `a|b` unescaped |\n"
        )
        self.assertIn('<td><code class="md-inline-code">a|b</code> unescaped</td>', body)

    def test_bold_wrapping_inline_code_in_list_item(self) -> None:
        # Regression: a numbered-list line starting with **`field_id`**
        # rendered literal asterisks instead of <strong>, because splitting on
        # code spans before scanning for ** broke the pair across two
        # independently-processed chunks.
        renderer = MarkdownRenderer()
        body = renderer.render("1. **`field_id`** — unique identifier.\n")
        # Anchor on '">' (end of the <li>'s data-cmt-* attributes) so this only
        # checks the RENDERED content, not the data-cmt-quote/label metadata,
        # which deliberately retains the raw "**`field_id`**" source text.
        self.assertIn(
            '"><strong><code class="md-inline-code">field_id</code></strong> — unique identifier.</li>', body
        )

    def test_bold_wrapping_inline_code_in_paragraph_and_heading(self) -> None:
        renderer = MarkdownRenderer()
        body = renderer.render(
            "### Heading with **`heading_variant`** bolded\n\n"
            "Paragraph with **`inline_variant`** in the middle.\n"
        )
        # Anchor past each element's boilerplate prefix ('>#</a>' for the
        # heading permalink, '">' for the paragraph's attrs) so these checks
        # cover only RENDERED content, not the data-cmt-* raw-source metadata.
        self.assertIn(
            '>#</a>Heading with <strong><code class="md-inline-code">heading_variant</code></strong> bolded</h3>',
            body,
        )
        self.assertIn(
            '">Paragraph with <strong><code class="md-inline-code">inline_variant</code></strong> in the middle.</p>',
            body,
        )

    def test_inline_code_gets_spacing_class_distinct_from_block_code(self) -> None:
        # Bare inline <code> had no class/styling hook at all, so code
        # immediately followed by text (no source whitespace) visually ran
        # together. Inline spans get md-inline-code; fenced code BLOCKS keep
        # their own md-code/pre styling untouched (no md-inline-code leakage).
        renderer = MarkdownRenderer()
        body = renderer.render("A paragraph with `token`immediately touching text.\n\n```\nblock code\n```\n")
        self.assertIn('<code class="md-inline-code">token</code>', body)
        self.assertIn('<pre class="md-code md-block"', body)
        pre_start = body.index('<pre class="md-code')
        pre_block = body[pre_start:]
        self.assertNotIn("md-inline-code", pre_block)

    def test_ordered_list_wrapped_continuation_stays_single_ol(self) -> None:
        # Regression (hand-wrapped prose with each
        # continuation line indented under its marker): the list-item scan
        # only continued while a line itself started with a fresh `-`/`digit.`
        # marker. A wrapped continuation line has no marker, so it broke the
        # scan immediately, fell through to the paragraph branch as its own
        # stray <p> ("awkward hard line break after roughly the first
        # column-width of text"), and the NEXT numbered source line then
        # opened a BRAND NEW <ol> — which a browser numbers from 1 regardless
        # of the source digit ("every item renders as 1.").
        renderer = MarkdownRenderer()
        body = renderer.render(
            "1. **Keep the cache warm** (R1). A Worker holds a queue + a config + a retry budget, addressed by a stable name.\n"
            "   A *Lane* is a read-only view of it; closing a Lane never stops the Worker. The naming is final\n"
            "   (see `notes/naming.md` and `notes/glossary.md`).\n"
            "2. **Bounded, ordered, restartable.** One job belongs to exactly one Worker; one Worker drains many\n"
            "   jobs in order; flat namespace.\n"
            "3. **Every entry is checked, never assumed** (R2). Every cache row carries `(name, size, mtime,\n"
            "   checksum)`. A hit *suggests* freshness; only a matching checksum proves it.\n"
        )
        self.assertEqual(
            body.count("<ol"),
            1,
            "all three items must render inside ONE <ol> so the browser numbers them 1/2/3 — "
            "each wrapped item instead opening its own <ol> is exactly what made every item show '1.'",
        )
        self.assertEqual(body.count("<li"), 3)
        self.assertEqual(
            body.count("<p "),
            0,
            "a wrapped continuation line must fold onto its list item, not become a stray paragraph",
        )
        # The wrapped continuation text must flow into the SAME <li> as
        # continuous text (space-joined), not get orphaned into a separate
        # block — this is the "flow as continuous text" half of the fix.
        self.assertIn(
            "A <em>Lane</em> is a read-only view of it; closing a Lane never stops the Worker. "
            "The naming is final",
            body,
        )
        # The inline code span that itself straddled the wrapped-line boundary
        # (`(name, size, mtime, checksum)`) now
        # closes correctly once the raw lines are folded back together before
        # inline parsing runs — a second, independent signal that the fold
        # happens on the source text rather than on some already-rendered
        # fragment.
        self.assertIn(
            '<code class="md-inline-code">(name, size, mtime, checksum)</code>',
            body,
        )

    def test_ordered_list_simple_no_wrap_renders_one_ol_three_items(self) -> None:
        # Baseline (not a regression by itself — this already worked pre-fix):
        # a plain, non-wrapped numbered list must keep rendering as one <ol>
        # with three <li>. Guards the common case while the scan loop above is
        # restructured for lazy continuation.
        renderer = MarkdownRenderer()
        body = renderer.render("1. Alpha\n2. Beta\n3. Gamma\n")
        self.assertEqual(body.count("<ol"), 1)
        self.assertEqual(body.count("<li"), 3)

    def test_ordered_list_blank_line_between_same_type_items_stays_one_list(self) -> None:
        # Regression for a second real instance of the bug: a "loose"
        # list of field definitions (each item set off by a blank line). CommonMark's loose-list
        # rule keeps items merely separated by blank lines in the SAME list
        # (one <ol>, still numbered 1/2/3/4) — an EARLIER version of this test
        # asserted the opposite (that a blank line always splits the list)
        # before a real document exposed that as just the "every item
        # renders as 1." bug again, via a different trigger than the
        # wrapped-continuation case.
        renderer = MarkdownRenderer()
        body = renderer.render("1. First item.\n\n2. Second item, blank-line separated.\n\n3. Third item.\n")
        self.assertEqual(body.count("<ol"), 1)
        self.assertEqual(body.count("<li"), 3)

    def test_ordered_list_blank_line_then_unrelated_content_still_ends_list(self) -> None:
        # A blank line only keeps the list open when a marker of the SAME
        # type is what follows it. A blank line followed by an ordinary
        # paragraph (real intervening content, not just list spacing) must
        # still end the list there — the peek-ahead must not swallow
        # unrelated prose or a later, genuinely separate list.
        renderer = MarkdownRenderer()
        body = renderer.render(
            "1. First list, one item.\n"
            "\n"
            "An unrelated paragraph in between.\n"
            "\n"
            "2. A different, later list, unrelated to the first.\n"
        )
        self.assertEqual(body.count("<ol"), 2)
        self.assertEqual(body.count("<li"), 2)
        self.assertEqual(body.count("<p "), 1)

    def test_ordered_list_blank_line_then_opposite_marker_type_ends_list(self) -> None:
        # A blank line followed by the OTHER marker type (bullet vs. number)
        # must still end the current list rather than being folded in.
        renderer = MarkdownRenderer()
        body = renderer.render("1. Numbered item.\n\n- Bullet item, different list.\n")
        self.assertEqual(body.count("<ol"), 1)
        self.assertEqual(body.count("<ul"), 1)

    def test_ordered_list_continuation_fold_stops_at_next_block(self) -> None:
        # A wrapped continuation line folds into the current item, but a line
        # that itself opens a new block (a heading here, with no blank line
        # separating it from the list) must still close the list — lazy
        # continuation folds prose it owns, not content that starts something
        # else. Pre-fix this already produced one <li> (there is only one
        # source item), but the continuation line still leaked out as its own
        # stray <p> between the list and the heading; post-fix it must fold
        # into the <li> with zero stray paragraphs.
        renderer = MarkdownRenderer()
        body = renderer.render("1. Item one wraps here\nonto a continuation line.\n## Next heading\n")
        self.assertEqual(body.count("<ol"), 1)
        self.assertEqual(body.count("<li"), 1)
        self.assertEqual(body.count("<p "), 0)
        self.assertIn("Item one wraps here onto a continuation line.", body)
        self.assertIn('<h2 id="next-heading"', body)


class PageHtmlTests(unittest.TestCase):
    def test_semantic_key_rebind_is_gated_by_content_hash(self) -> None:
        # Regression: after a full document rewrite, old comments visually re-attached to brand-new
        # unrelated paragraphs. semanticKey is a POSITION key (heading path +
        # element kind + ordinal), so it resolved to whatever now occupied the
        # slot; the stored contentHash disagreed and nothing checked it. Both
        # resolvers must now require hashMatches() before honoring a semanticKey
        # hit — otherwise the page misattributes a reviewer's comments.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn("function hashMatches(anchor, el)", html_out)
        self.assertIn("return el.dataset.cmtContentHash === anchor.contentHash;", html_out)
        # elementFor(anchor) and elementForComment(c) are the only two
        # resolvers; each has exactly one semanticKey branch and both are gated.
        self.assertIn("if (el && hashMatches(anchor, el)) return el;", html_out)
        self.assertIn("if (el && hashMatches(a, el)) return el;", html_out)
        # No ungated semanticKey return survives: the only bare `if (el) return
        # el;` lines left belong to the hash-derived anchorId branches.
        self.assertEqual(2, html_out.count("      if (el) return el;"))

    def test_detached_comments_get_a_labeled_surface_with_the_original_quote(self) -> None:
        # A comment that can no longer attach must stay VISIBLE and carry its
        # stored quote — silently hiding it is the other half of the same bug.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn("function isDetached(c) { return !elementForComment(c); }", html_out)
        self.assertIn('data-detached-btn', html_out)
        self.assertIn('data-filter="detached"', html_out)
        self.assertIn("md-detached-tag", html_out)
        self.assertIn("written on an earlier revision", html_out)

    def test_comment_popup_capped_height_with_internal_scroll_regions(self) -> None:
        # Regression: a long in-progress comment (or a
        # long existing thread) made the popup grow past the viewport with no
        # scroll and no cap — `.rds-cmt-pop` in the design system is
        # `position: fixed` with a fixed width but no max-height/overflow and
        # isn't a flex container, so its height was purely content-driven, and
        # a `position: fixed` element does not move when the page scrolls. The
        # Cancel/Comment footer buttons ended up rendered off-screen with
        # nothing able to bring them back into view.
        #
        # Follow-up: the popup used to let only the
        # *textarea* natively resize (resize: both on the input) while
        # [data-existing] held the sole flex-grow — so growing the textarea's
        # own height, capped by the popup's max-height + overflow: hidden,
        # forced [data-existing] to shrink to compensate, i.e. the textarea
        # visibly grew *upward* into the existing comment thread. Fixed by
        # resizing the CARD itself (native `resize: both` on .rds-cmt-pop,
        # browser-enforced min/max-width/height, no JS math) and swapping the
        # flex roles: textarea (flex: 1 1 auto) now absorbs all extra vertical
        # space, while [data-existing] (flex: 0 1 auto, no grow) only ever
        # sizes up to its own content height.
        #
        # This only confirms the CSS rules are PRESENT in the emitted page —
        # a plain unit test has no browser layout engine to actually exercise
        # scrolling/visibility/dragging. The real on-screen behavior was
        # verified separately with a live before/after browser session.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn(
            ".rds-cmt-pop { display: flex; flex-direction: column; min-width: 260px; max-width: min(90vw, 640px); "
            "min-height: 280px; max-height: min(72vh, 520px); overflow: hidden; resize: both; }",
            html_out,
        )
        self.assertIn(
            ".rds-cmt-pop [data-existing] { flex: 0 1 auto; min-height: 0; overflow-y: auto; }", html_out
        )
        self.assertIn(
            ".rds-cmt-pop textarea { width: 100%; min-height: 44px; flex: 1 1 auto; overflow-y: auto; resize: none; }",
            html_out,
        )
        self.assertIn(".rds-cmt-foot { flex: 0 0 auto; }", html_out)

    def test_page_embeds_provenance_and_source_chip(self) -> None:
        html_out = page_html(
            "T",
            "docs/thing.md",
            "doc-1",
            "<p>body</p>",
            [],
            [],
            provenance={
                "sourceRepoName": "example-repo",
                "sourceRepoBranch": "main",
                "sessionId": "abc123",
                "agentCwd": "/home/user/projects/example-repo",
            },
        )
        self.assertIn("data-prov-toggle", html_out)
        self.assertIn("example-repo:main · docs/thing.md", html_out)
        # Provenance must reach the page config so the Source panel can render it.
        self.assertIn('"sessionId": "abc123"', html_out)
        self.assertIn('"agentCwd": "/home/user/projects/example-repo"', html_out)

    def test_page_without_provenance_still_renders(self) -> None:
        # Docs rendered before provenance existed (migrated stores) must not break.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn("src.md", html_out)
        self.assertIn("data-prov-toggle", html_out)

    def test_page_includes_author_input(self) -> None:
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn('class="md-cmt-author"', html_out)
        self.assertIn("mdReviewAuthor", html_out)

    def test_theme_bootstrap_guard_runs_before_stylesheets(self) -> None:
        # The FOUC guard must settle data-theme BEFORE the design-system
        # stylesheets are processed, or dark-mode users get a light flash on
        # every load. Statically: the bootstrap script's position in the
        # emitted <head> precedes the first stylesheet link.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        bootstrap = html_out.index("localStorage.getItem('mdReviewTheme')")
        first_stylesheet = html_out.index('<link rel="stylesheet"')
        self.assertLess(bootstrap, first_stylesheet)
        # System fallback: an OS dark preference maps to the "dark" palette,
        # and a server-stamped attribute is respected (not overwritten).
        self.assertIn("prefers-color-scheme: dark", html_out)
        self.assertIn("hasAttribute('data-theme')", html_out)

    def test_theme_glyph_picker_and_persistence_js(self) -> None:
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        # The glyph picker (☼ ◐ ☾, same vocabulary as the bundled design system)
        # with all three set-buttons and the persistence key the bootstrap
        # reads back.
        self.assertIn('data-theme-set="light"', html_out)
        self.assertIn('data-theme-set="dusk"', html_out)
        self.assertIn('data-theme-set="dark"', html_out)
        self.assertIn("☼", html_out)
        self.assertIn("◐", html_out)
        self.assertIn("☾", html_out)
        self.assertIn("localStorage.setItem('mdReviewTheme'", html_out)

    def test_static_page_carries_no_data_theme_attribute(self) -> None:
        # Rendered pages are theme-agnostic static files: the server stamps
        # its default theme at SERVE time (see server._themed_doc_html), so
        # docs rendered before a --theme existed still pick it up, and a
        # file opened without the server resolves system/localStorage via
        # the bootstrap.
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn('<html lang="en">', html_out)
        self.assertNotIn('<html lang="en" data-theme', html_out)

    def test_script_embed_escaped_against_breakout(self) -> None:
        # a "</script>" in any config string used to close the element early → stored XSS.
        payload = "</script><script>alert(1)</script>"
        html_out = page_html(
            payload,
            "src.md",
            "doc-1",
            "<p>body</p>",
            [],
            [],
            provenance={"sourceRepoBranch": f"x{payload}", "sessionId": "s"},
        )
        self.assertNotIn(payload, html_out)
        # The escaped form is what must appear instead.
        self.assertIn("\\u003c/script\\u003e", html_out)
        # And the surrounding config must still be valid embeddable JSON text.
        self.assertIn("window.MD_REVIEW = {", html_out)

    def test_ampersand_escaped_in_embed(self) -> None:
        html_out = page_html("A&B", "src.md", "doc-1", "<p>x</p>", [], [])
        self.assertIn("A\\u0026B", html_out)


class LinkSchemeTests(unittest.TestCase):
    def test_javascript_links_render_inert(self) -> None:
        from mdreview.renderer import render_inline

        for payload in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "java\tscript:alert(1)",
            "  javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
        ]:
            out = render_inline(f"[click]({payload})")
            self.assertNotIn("<a href", out, payload)
            self.assertIn("md-link-inert", out, payload)
            self.assertIn("click", out)

    def test_safe_links_pass(self) -> None:
        from mdreview.renderer import render_inline

        for href in [
            "https://example.com/x",
            "http://192.168.1.10:8779/docs",
            "mailto:reviewer@example.com",
            "#section",
            "/rendered/doc/index.html",
            "docs/other.md",
            "../relative/path.md",
            "//cdn.example.com/lib.js",
        ]:
            out = render_inline(f"[go]({href})")
            self.assertIn(f'<a href="{href}">go</a>', out, href)

    def test_query_string_urls_escape_exactly_once(self) -> None:
        # the href was previously HTML-escaped TWICE, so the
        # browser decoded one layer and navigated to ?a=1&amp;b=2 — every
        # multi-parameter URL silently broken.
        from mdreview.renderer import render_inline

        out = render_inline("[a](https://x.com/?a=1&b=2)")
        self.assertIn('<a href="https://x.com/?a=1&amp;b=2">a</a>', out)
        self.assertNotIn("&amp;amp;", out)
        out2 = render_inline("[a](mailto:x@y.com?subject=a&b=c)")
        self.assertIn('<a href="mailto:x@y.com?subject=a&amp;b=c">a</a>', out2)

    def test_entity_obfuscated_javascript_is_inert(self) -> None:
        # the scheme check must run on the DECODED href —
        # checking the escaped form sees no colon and waves these through.
        from mdreview.renderer import render_inline

        for payload in [
            "javascript&#58;alert(1)",
            "javascript&#x3A;alert(1)",
            "javascript&colon;alert(1)",
            "&#106;avascript:alert(1)",
        ]:
            out = render_inline(f"[x]({payload})")
            self.assertNotIn("<a href", out, payload)
            self.assertIn("md-link-inert", out, payload)

    def test_backslash_urls_classify_like_their_forward_forms(self) -> None:
        # Browsers treat \\host as //host for special schemes; the classifier
        # must see the same URL the browser will (both land in the allowed
        # protocol-relative class, so this asserts consistency, not blocking).
        from mdreview.renderer import render_inline

        out = render_inline("[a](\\\\evil.com/x)")
        self.assertIn("<a href", out)  # same risk class as //evil.com (allowed)


class StructureFixTests(unittest.TestCase):
    def test_nul_bytes_stripped_before_render(self) -> None:
        # a literal NUL could collide with the \x00{n}\x00
        # code-span placeholder and crash or corrupt the render.
        renderer = MarkdownRenderer()
        body = renderer.render("para with \x00 NUL and `code`\x005\x00 tail\n")
        self.assertNotIn("\x00", body)
        self.assertIn('<code class="md-inline-code">code</code>', body)

    def test_skipped_heading_levels_have_true_ancestry(self) -> None:
        # ancestry was list-LENGTH, so a doc opening at ###
        # then moving to ## treated the h3 as the h2's parent.
        renderer = MarkdownRenderer()
        renderer.render("### Deep first\n\npara under deep\n\n## Shallower\n\npara under shallow\n")
        deep_para = [a for a in renderer.anchors if a.element_kind == "paragraph"][0]
        shallow_para = [a for a in renderer.anchors if a.element_kind == "paragraph"][1]
        self.assertEqual(deep_para.heading_path, ["Deep first"])
        self.assertEqual(shallow_para.heading_path, ["Shallower"])

    def test_ordered_list_start_attribute(self) -> None:
        renderer = MarkdownRenderer()
        body = renderer.render("7. Resumed step\n8. Next step\n")
        self.assertIn('<ol class="md-list" start="7">', body)
        renderer2 = MarkdownRenderer()
        body2 = renderer2.render("1. First\n2. Second\n")
        self.assertIn('<ol class="md-list">', body2)
        self.assertNotIn("start=", body2)

    def test_absurd_digit_marker_does_not_crash(self) -> None:
        # a ≥4301-digit marker raised in int() (CPython's
        # int_max_str_digits). Now length-guarded — renders as an ordinary
        # list opening at 1.
        renderer = MarkdownRenderer()
        body = renderer.render("9" * 5000 + ". pathological\n")
        self.assertIn("<ol", body)


class FragmentTests(unittest.TestCase):
    """Heading ids are slugs of the whole heading PATH (`guide-install`), but
    authors write GitHub-style fragments (`#install`), which slug the heading's
    own text. Each heading carries that GitHub slug as data-slug so the page can
    resolve such fragments."""

    def test_heading_carries_github_style_slug_of_its_own_text(self) -> None:
        body = MarkdownRenderer().render("# Guide\n\n## Install & Run\n")
        self.assertIn('id="guide-install-run"', body)
        self.assertIn('data-slug="install--run"', body)

    def test_github_slug_keeps_code_and_link_text(self) -> None:
        from mdreview.renderer import github_slug

        self.assertEqual("code-span", github_slug("`code` span"))
        self.assertEqual("see-the-docs-now", github_slug("See [the docs](a.md) now"))

    def test_duplicate_heading_slugs_get_github_numeric_suffixes(self) -> None:
        body = MarkdownRenderer().render("# A\n\n## Notes\n\n# B\n\n## Notes\n")
        self.assertIn('data-slug="notes"', body)
        self.assertIn('data-slug="notes-1"', body)

    def test_page_resolves_unmatched_fragment_via_data_slug(self) -> None:
        html_out = page_html("T", "src.md", "doc-1", "<p>body</p>", [], [])
        self.assertIn("function resolveFragment()", html_out)
        self.assertIn("window.addEventListener('hashchange', resolveFragment)", html_out)
        self.assertIn("document.querySelector('[data-slug=\"' + CSS.escape(slug) + '\"]')", html_out)


class LinkResolverTests(unittest.TestCase):
    """The renderer exposes relative links to a resolver hook; it never decides
    file policy itself."""

    def render(self, markdown: str, resolver) -> str:
        return MarkdownRenderer(link_resolver=resolver).render(markdown)

    @staticmethod
    def always(rendering: LinkRendering):
        def resolver(href: str, is_image: bool) -> LinkRendering:
            return rendering

        return resolver

    def test_without_a_resolver_links_and_images_render_as_before(self) -> None:
        body = MarkdownRenderer().render("See [r](reports/a.md) and ![d](d.png).\n")
        self.assertIn('<a href="reports/a.md">r</a>', body)
        self.assertIn('!<a href="d.png">d</a>', body)

    def test_resolver_rewrites_relative_links_and_sees_raw_href(self) -> None:
        seen = []

        def resolver(href, is_image):
            seen.append((href, is_image))
            return LinkRendering(href="/link/doc-1/abc#sec", css_class="md-link-local", title="reports/a.md")

        body = self.render("See [r](reports/a.md#sec) and [w](https://e.com/x).\n", resolver)
        self.assertIn('<a class="md-link-local" href="/link/doc-1/abc#sec" title="reports/a.md">r</a>', body)
        self.assertIn('href="https://e.com/x"', body)  # non-relative: resolver not consulted
        self.assertEqual([("reports/a.md#sec", False)], seen)

    def test_captured_image_renders_as_img_wrapped_in_its_link(self) -> None:
        resolver = self.always(LinkRendering(href="/link/d/k", css_class="md-link-local", title="d.png", image=True))
        body = self.render("![A diagram](img/d.png)\n", resolver)
        self.assertIn('<a class="md-link-local" href="/link/d/k" title="d.png"><img src="/link/d/k" alt="A diagram" loading="lazy"></a>', body)

    def test_unavailable_link_is_marked_visibly(self) -> None:
        resolver = self.always(LinkRendering(href="/link/d/k", css_class="md-link-unavailable", title="too large"))
        body = self.render("[big](big.bin) and ![](gone.png)\n", resolver)
        self.assertIn('class="md-link-unavailable"', body)
        self.assertEqual(2, body.count('<span class="md-link-unavailable-mark" aria-hidden="true">⊘</span>'))
        self.assertNotIn("<img", body)

    def test_hostile_resolver_output_and_alt_text_are_escaped(self) -> None:
        resolver = self.always(LinkRendering(
            href='/link/d/k#"><script>x</script>', css_class="md-link-local", title='"><script>t</script>', image=True
        ))
        body = self.render('![a"><script>alt</script>](x.png) [l](y.md)\n', resolver)
        self.assertNotIn("<script>", body)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
