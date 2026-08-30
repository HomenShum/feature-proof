# Capture and narration contract

A feature user needs to see the whole journey, including the baseline, wait,
refusal, or recovery state. Showing only the final screen can conceal the very
failure the feature claims to solve.

## Reuse the working media stack

Prefer an existing semantic Playwright journey. Capture the real interface at
one stable route, viewport, theme, session, and fixture. Record console/network
errors and assert the semantic states before treating pixels as evidence.

Use the repository's installed capture and media stack first. Prefer commands
that already drive the product's semantic browser journey, FFmpeg/FFprobe,
console and network assertions, and hash receipts. For example:

```bash
npm run test:e2e
npm run capture:feature-proof
npm run verify:feature-proof-media
```

When no publisher exists, add one that stages the WebM, MP4, poster, contact
sheet, semantic receipt, media receipt, and FFprobe metadata, then publishes
receipts last. Build product and engineering narration from the packet's
structured narration files and keep captions on the same segment data. If an
external studio is available, use it only after verifying its command exists;
this skill embeds no voice or video model. Narration owns pacing—hold a still
longer rather than rushing speech. Video-model review is advisory and
conditional, never a gate unless the manifest explicitly names its receipt.

## Seven beats

Capture premise, viewer question, comparison axis, conflict, evidence, verdict,
and exit decision. Show loading and intermediate states when they carry truth.
Captions state receipt-bound outcomes, not mouse instructions.

Product mode says who was helped, what went wrong, and what decision is now
possible, without code terms. Engineering mode explains authority, flow,
measured latency/tokens/cost, and ends with the run's own trace waterfall.

## Atomic media receipt

Stage source WebM, product/engineering MP4s, captions, poster, contact sheet,
semantic browser receipt, and FFprobe metadata in a temporary directory.
Compute byte sizes and SHA-256 hashes. Publish artifacts first, their media
receipt next, and `artifact-manifest.json` last. A failed take must leave the
previous coherent packet intact.

UI packets require product/engineering clips, a reduced-motion poster, contact
sheet, captions, and the media receipt declared by the manifest. Server-only
packets set `ui_applicable=false` and require none of these.
