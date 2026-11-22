# Document rendering and annotation — plan (draft)
Working name `bae6-annotate` (needs a product-name ADR; the five existing names are fixed by AGENTS.md). Purpose: render large text/markdown documents instantly and overlay annotations so people can check work (agent outputs, eval cases, retrieved context, drafts).

## Decision: Rust core compiled to WASM, thin TS shell
- One engine for browser and server. Browser runs it as WASM; a Node/Python binding (napi-rs / PyO3) runs the same code for headless checks and tests. Go would only help the server half, and a server render means a network hop per scroll, which loses on "lightning fast".
- Pure browser/DOM rendering is the fallback, not the base: DOM cost grows with document size, and annotation anchoring across reflow is where it gets slow and wrong.

## Core (Rust, no UI dependencies)
- Text storage: rope (or piece table) of UTF-8, with a line index; indexes are code points internally, UTF-16 only at the JS boundary.
- Layout: incremental line breaking and measurement only for the visible window plus overscan; cached per paragraph, invalidated by edit range. Fixed-width and proportional fonts; bidi and complex scripts deferred.
- Annotation model follows the W3C Web Annotation selectors: `TextPositionSelector` for speed, `TextQuoteSelector` (exact + prefix/suffix) as the re-anchor fallback when the text changed. Annotations are data, never executed; body text is escaped on output.
- Re-anchoring: position first; if the quoted text no longer matches there, fuzzy search near the old position with a bounded window; if none, mark the annotation orphaned rather than guessing.
- Bounds: max document size, max annotations per document, max annotation body size, all enforced at load.

## Rendering (TS shell)
- Canvas 2D first (glyph/line cache, draw only visible lines, annotation highlights as rects). WebGPU atlas is an upgrade if profiling shows canvas draw as the bottleneck.
- Accessibility is a requirement, not a stretch goal: a visually hidden DOM mirror of the visible lines for screen readers and find-in-page, keyboard navigation between annotations, selection and copy.
- Input: select text to create an annotation; annotations list is a plain event stream the host app stores (this repo holds no database).

## Slices
1. Core: rope, line index, layout window, selectors + re-anchor, with property tests (random edits keep anchors valid or orphaned, never wrong).
2. WASM build + canvas viewer for plain text; benchmark.
3. Markdown (CommonMark subset via an existing Rust parser, not hand-written), annotations UI, a11y mirror.
4. Console integration (agent outputs, eval cases, retrieved chunks); Node/Python bindings.

## Gates
- Open a 10 MB text file to first paint under 100 ms and hold 60 fps scrolling on a mid laptop; 10k annotations without frame drops. Numbers recorded, not assumed.
- No document or annotation content in logs; sizes and counts bounded; fuzz target on the selector parser.

## Open
- Name and repo ADR. Editing (vs. read-only plus annotation) is out of v1. PDF and rich formats are out of v1.
- Dependencies to measure before adopting: markdown parser crate, a text-shaping crate (rustybuzz) only if proportional-font layout needs it.
