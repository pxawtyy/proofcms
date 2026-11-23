# WPVDB-aa354358 — source and lab analysis (2026-11-23)

## Source difference (verified)

Comparing WordPress 7.1.0 and 7.1.1, one change in `wp-includes/formatting.php`
is relevant to comment rendering. `wpautop()` rewrites a paragraph-wrapped
blockquote:

- 7.1.0: `|<p><blockquote([^>]*)>|i`
- 7.1.1: `!<p><blockquote((?:[^>"\']|"[^"]*"|\'[^\']*\')*)>!i`

The old pattern stops at the first `>` even when it is inside a quoted
attribute value, so a blockquote whose attribute contains `>` can be split and
the remainder reinterpreted as attributes of the generated `<p>` tag.

## Lab attempt (negative)

A paired lab was built with the official 7.1.0 and 7.1.1 images, comments set
to auto-approve, and a published post. Unauthenticated comments were posted
with payloads of the form:

```
<blockquote cite="> data-proofcms=MARKER">hello</blockquote>
```

Both builds rendered the comment identically. Reading `wp_comments` showed why:

```
<blockquote> data-proofcms=MARKER"&gt;hello</blockquote>
```

WordPress comment KSES strips the `cite` attribute and escapes the `>` before
`wpautop()` runs, so the quote-aware regex change is not observable through the
stock comment path. No HTTP differential was produced.

The WPScan advisory for this ID does not publish a Proof of Concept, and the
source-derived path above is neutralised by KSES in the tested configuration.
A reliable probe cannot be built from the available material.

## Disposition

The check remains passive. The lab is retained as a reproducible negative
attempt and as a paired WordPress 7.1.0/7.1.1 fixture for future work if a PoC
becomes available.
