# Manifest and claim contract

A product owner needs to know whether a feature is safe to demonstrate. A clip
can look convincing while a retry created two jobs or a reviewer receipt named
the wrong version. The manifest makes each statement point to the exact receipt
that would expose that failure.

The single source is `feature-manifest.json` with schema
`feature-proof/v1`. Keep business intent and the authority split handwritten.
Point inputs, outputs, and contract facts at source symbols instead of copying
their definitions.

## Required sections

- `business`: persona, decision, problem, concrete failure, success measure.
- `source`: `identity_status`, base/implementation commits, and every
  implementation path, including the verifier scripts and exact contract/schema
  assets that decide whether evidence passes. Use `pending_clean_commit` with a
  JSON `null` implementation commit while the working bytes are not frozen.
  New packets use `integrity_contract: git-seal-main-portable/v1`: the frozen
  implementation commit must be an ancestor of the executing `HEAD`. That is a
  local ancestry proof, not proof that a hosting service will retain the
  source. Before freezing a Graphite stack, the host workflow must also run
  `git merge-base --is-ancestor "$Source" origin/main` and require exit zero.
  The first committed artifact-manifest add permanently owns that packet path,
  complete tree and modes, `feature_id`, and implementation commit. `finalize`
  may self-verify the uncommitted artifact, but an ordinary `check` reports
  `PENDING` until that first add is committed; it reports `PASS` only afterward.
  A later release uses a successor directory instead of deleting or resealing
  the old one. Preserve full, protected Git history so the first add remains
  provable after stacked branches are removed.
  `init` uses its commit argument as the clean base but emits this pending/null
  state. Commit implementation plus packet policy before generating receipts.
  Afterward, the manifest may change only from `pending_clean_commit`/`null` to
  `frozen`/that new source commit, while each claim stays `pending` or advances
  from committed `pending` to `verified`. Gate commands, claim text, paths,
  schemas, capture policy, authority, and every other field stay exact.
  Before first seal, and for every command that executes or publishes new
  evidence, all tracked bytes outside the packet must match the source commit
  and no non-ignored untracked path may exist. After a portable first seal,
  read-only `check` resolves implementation paths and anchors from the source
  commit's Git blobs and validates the immutable packet tree; that archival
  PASS does not certify the current checkout.
- `authority`: deterministic, model, human, and forbidden responsibilities.
- `contracts`: inputs, outputs, and resolvable `{id,path,symbol}` anchors.
- `attacks`: persona, realistic scenario, and expected receipt.
- `verification_matrix`: happy, sad, adversarial, degraded, burst, sustained,
  and restore scenarios, each pointing at a receipt or gate.
- `claims`: narration-safe text, receipt type/reference, modes, required flag,
  `pending|verified|failed` status, and an exact `evidence_schema` for every
  non-trace claim. Object keys are closed; use the documented scalar tokens or
  `{"$const": ...}` / `{"$enum": [...]}` leaves.
- `gates`: argv array, literal success output, receipt path, and condition.
- `capture`: whether UI evidence applies and its stable route, viewport, theme,
  motion preference, fixture, and required media.

`verified` is not evidence by itself. The checker also validates the receipt,
source commit, privacy boundary, and receipt-type invariants.

The packet itself is closed at the source commit. Contracts, storyboard,
narrations, BEFORE evidence, and other committed policy stay byte-exact.
For `git-seal-main-portable/v1`, artifact rows canonicalize `.ffconcat`,
`.json`, `.jsonl`, `.md`, `.svg`, `.txt`, and `.vtt` line endings to LF while
all other suffixes remain raw. Declare those text suffixes as `text eol=lf` in
`.gitattributes` before source freeze so a Git-smudged Windows checkout stays
clean against the sealed Git tree.
`HANDOFF.md` may be updated for the final reviewer, and
`decision-log.jsonl` may append only after preserving the committed prefix.
The prefix comparison canonicalizes only CRLF and bare CR to LF for
Git-smudged Windows worktrees; it does not normalize any non-newline byte.
Generated files may appear only at exact paths declared by committed gate
receipt/scenario refs, claim receipt refs, capture media/media-receipt refs, or
engineering narration `visual_receipt_ref` SVGs, plus exact
`artifact-manifest.json`. A declared output may not collide with any file
tracked at the source commit. Any other packet file, including an undeclared
waterfall HTML file, fails the checkout guard.

## Claim receipts

Every non-trace receipt uses `feature-proof-receipt/v1`, repeats the claim ID
and type, binds both `source_commit` and `source_identity_sha256`, sets
`passed: true`, and supplies typed `evidence`. Receipt, derivation, gate, trace,
span, and score objects are closed schemas; extra fields fail validation:
Every receipt also embeds the canonical claim definition and its SHA-256. A
later edit to claim text, narration modes, required flag, or receipt rule makes
the old receipt invalid instead of silently authorizing new narration.

| Type | Receipt invariant |
|---|---|
| `idempotent` | Same durable identity twice; second creates nothing; count unchanged |
| `versioned` | The current version advances; the old version remains recoverable from immutable receipt/snapshot coordinates |
| `parallel` | Named sibling spans have strictly positive measured overlap |
| `fail_closed` | Exact 4xx/code/body digest and zero forbidden side effects |
| `citation_grounded` | Source, revision, and excerpt digest resolve exactly |
| `human_reviewed` | Distinct actor/owner digests, bounded role, positive version, disposition, persistence |
| `no_duplicate_job` | Same key and job ID; second reuses; job count unchanged |
| `trace_contract` | The receipt itself is a normalized trace |
| `gate` | Command exits zero and emits the manifest's literal |

Narration segments carry `claim_ids`. All spoken/captioned segments require at
least one claim. A failed claim may never appear in narration.

## Execution-derived receipts

Do not hand-write passing gate or claim JSON. `run-gate` executes the
manifest's argv without a shell, caps each output stream at 1 MiB, enforces a
timeout, rejects private output, and binds exit code, expected literal, exact
argv, complete source identity, and output digests. If the portable first token
is `npm`, for example, a Windows host may resolve it
to an absolute regular `npm.cmd` through `PATH`/`PATHEXT` for process creation
only. Missing, relative, or non-file resolutions fail before spawn; the
manifest argv and its canonical digest do not change. When
`--expect-scenario-output` is set, the command must write a fresh
`feature-proof-scenario-output/v1` object to the path in
`FEATURE_PROOF_SCENARIO_OUTPUT`; the runner injects the gate ID and source
identity in adjacent environment variables.

`compile-claim` accepts only one passing typed claim from that scenario file.
It verifies the gate receipt and both file hashes, generates the claim receipt,
then atomically promotes the manifest claim to `verified`. A pytest PASS line
cannot establish versioning, idempotency, review, citation, or fail-closed
behavior unless the structured scenario row carries that type's evidence.

Trace-contract claims use the telemetry receipt lane. `normalize` may create a
privacy-reduced diagnostic staging artifact, but it is never promotion input.
`verify-trace-claim` performs an authenticated Langfuse read by immutable trace
ID, scans the complete raw response before normalization, then validates release, source identity, topology,
semantic metric values, finite unique scores, bounds, and privacy. It stamps the
canonical claim definition, raw response, contract, and complete source-identity hashes before writing
the receipt and promotes the feature manifest last. There is no hand-edited
trace status transition.

## Append-only decision log

Use one JSON object per line in chronological append order:

```json
{"id":"decision-0001","timestamp":"...Z","decision":"...","why":"...","rejected_alternative":"...","evidence":[],"trigger_to_revisit":"...","supersedes":null}
```

Never delete or edit an earlier line. Record a reversal as a new line whose
`supersedes` names the prior decision.
