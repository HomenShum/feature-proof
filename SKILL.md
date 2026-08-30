---
name: feature-proof
description: Take a meaningful software feature from business problem to receipt-bound handoff, including typed contracts, Langfuse trace validation, adversarial tests, browser evidence, narrated clips, hashes, and an append-only decision log. Use for feature implementation or handoff work that must not claim DONE without reproducible proof.
---

# Feature Proof

Produce a handoff another worker can verify without trusting the narration.

The governing rule is absolute: **no receipt, no narration claim**. In
particular, say work ran in parallel only when sibling spans in the run's own
normalized trace have strictly positive timestamp overlap.

## Run the chain

1. Read existing manifests, evidence, decisions, and capture scripts first.
2. Write the business problem, authority split, code anchors, attacks, claims,
   and gates into one feature manifest. Read
   [references/manifest-contract.md](references/manifest-contract.md).
3. Capture the BEFORE state before implementation. Make the smallest current
   change; do not redesign adjacent systems.
4. Instrument one user action as one parent trace with honest nested spans.
   Read [references/trace-contract.md](references/trace-contract.md).
5. Run deterministic, adversarial, degraded, burst, and sustained scenarios.
   A model or hosted trace is conditional evidence: if no model ran, neither is
   required. Read
   [references/forward-test-matrix.md](references/forward-test-matrix.md).
   Generate gate and typed claim receipts through
   [references/receipt-generation.md](references/receipt-generation.md), never
   by editing passing JSON.
6. Drive the real UI when the feature has a UI. A take whose narration would
   make a false claim dies in staging instead of being published. Read
   [references/capture-contract.md](references/capture-contract.md).
7. Bind every product and engineering narration segment to claim IDs. Product
   mode explains the human problem without code terms. Engineering mode ends
   at Scene 7 on the run's own hash-bound trace waterfall.
8. Append a decision-log entry. Never rewrite an older entry; a reversal names
   what it supersedes.
9. Finalize only after every applicable gate passes. The artifact manifest is
   written atomically and last.

## Tooling

Set `SKILL` to this directory, then use the stdlib-only tool:

```bash
python "$SKILL/scripts/feature_proof.py" init <packet> \
  --feature-id <id> --title <title> \
  --implementation-commit <sha> --implementation-path <path> \
  --anchor-symbol <symbol>

python "$SKILL/scripts/feature_proof.py" normalize <langfuse-export.json> \
  <staging>/run.normalized.json

python "$SKILL/scripts/feature_proof.py" verify-trace-claim <packet> \
  --claim-id <trace-claim> --trace-id <immutable-langfuse-trace-id> \
  --repo-root <repo>

python "$SKILL/scripts/feature_proof.py" render-waterfall \
  <packet>/receipts/traces/run.json \
  --svg <packet>/receipts/traces/trace-waterfall.svg \
  --html <temporary-staging>/trace-waterfall.html

python "$SKILL/scripts/feature_proof.py" run-gate <packet> \
  --gate-id <manifest-gate> --repo-root <repo> \
  --expect-scenario-output

python "$SKILL/scripts/feature_proof.py" compile-claim <packet> \
  --claim-id <claim> --scenario-output receipts/scenarios/<gate>.json \
  --repo-root <repo>

python "$SKILL/scripts/feature_proof.py" check <packet> --repo-root <repo>
python "$SKILL/scripts/feature_proof.py" check <packet> --repo-root <repo> --allow-pending
python "$SKILL/scripts/feature_proof.py" finalize <packet> --repo-root <repo>
```

`--allow-pending` permits an honest skeleton, not a failed or malformed packet.
`init` treats `--implementation-commit` as the clean base revision and writes
`source.identity_status=pending_clean_commit` with a JSON `null`
`implementation_commit`. Commit the packet policy in that pending state, then
freeze the manifest to the new source commit before generating evidence.
New packets also declare `source.integrity_contract=git-seal-main-portable/v1`.
The public checker proves that the frozen source is an ancestor of the
executing `HEAD`; it cannot infer which branch the hosting service will retain.
Before freezing a stacked-branch release, the host workflow must separately
run `git merge-base --is-ancestor "$Source" origin/main` and require exit zero.
That host check is what prevents a Graphite-only commit from becoming the sole
source before branch cleanup.
`finalize` refuses pending claims and publishes `artifact-manifest.json` only
after the complete packet passes. For the portable contract it self-verifies
that new file locally, while an ordinary `check` remains honestly `PENDING`
until the artifact manifest is committed for the first time. The first add
commit seals the packet path, complete tree and file modes, `feature_id`, and
implementation commit. Commit the complete packet, then rerun `check` for
`PASS`. Publish a later release under a new packet path; never delete and
reseal an artifact manifest in an already finalized directory. Preserve full,
protected Git history or the public checker cannot prove an earlier first add.
Artifact rows canonicalize `.ffconcat`, `.json`, `.jsonl`, `.md`, `.svg`,
`.txt`, and `.vtt` line endings to LF; every other suffix remains raw bytes.
Declare those text suffixes as `text eol=lf` in `.gitattributes` before source
freeze so Git-smudged Windows worktrees remain clean against the sealed tree.
`run-gate` refuses an unfrozen source identity, caps stdout and stderr, and
publishes only hashes—not raw command output. `compile-claim` refuses hand-made
evidence that is not bound to the executed gate's structured scenario output.
On Windows, a release owner may declare portable `npm` even when the installed
launcher is `npm.cmd`: `run-gate` resolves only the first argv token through
the execution environment's `PATH`/`PATHEXT`, requires an absolute regular
file, and still spawns with no shell. The receipt and command digest remain
bound to the exact declared argv, never the host-specific resolved path.
Before a first seal, `check` and every source-bound gate, claim, trace, and
finalization verify that the declared commit exists, each implementation path
has the same Git-canonical bytes, and the whole checkout is closed against that
commit. Outside the feature packet, no tracked drift or non-ignored untracked
path is allowed. After a portable artifact seal is committed, `check` is an
archival operation: it reads implementation paths and anchor symbols from the
declared source commit and verifies the packet against its first-add Git tree;
it does not certify today's checkout. Any command that executes or publishes
new evidence keeps the strict current-checkout guard. Inside an unsealed packet,
committed policy, contracts, storyboard, narrations, and BEFORE evidence remain
source-exact. A trace contract receipt hashes the
immutable Git blob named by the frozen source commit, so LF, CRLF, and bare-CR
worktree spellings produce one digest; the current contract must match that
blob after newline normalization, and every non-newline byte remains exact.
The only manifest edits are the pending/null
source pointer becoming frozen/the source commit and individual claim statuses
remaining pending or becoming verified. `HANDOFF.md` may change, while
`decision-log.jsonl` may only append to its exact committed byte prefix.
For that prefix comparison only, CRLF and bare CR are normalized to LF so a
Git-smudged Windows checkout remains equivalent; every non-newline byte stays
exact.
Generated paths are limited to the committed manifest's gate/scenario/claim
receipt refs, capture media and media-receipt refs, engineering narration SVG
refs, and exact `artifact-manifest.json`; every other untracked packet file
fails. Keep the waterfall HTML outside the packet and discard it unless a
future closed contract explicitly declares it. `run-gate` repeats the guard
after its child exits and before publication. `verify-trace-claim`
requires Langfuse credentials, fetches the trace,
observations, and scores itself by immutable trace ID, scans the complete raw
response before normalization, and binds claim-definition, raw, contract, and
source hashes. An optional `--langfuse-export-cache` is accepted only when its
bytes equal the verifier's canonical authenticated response. Packet mutations use a process-safe
lock; identical retries recover, while conflicting inputs fail closed.

## Completion boundary

The packet state is derived, never declared:

```text
problem -> contract -> implementation -> trace -> verification
        -> capture -> two narrations -> handoff -> append
```

Skip only inapplicable evidence. Server-only work needs no UI clip. A workflow
with no model call needs no model span. Everything else needs the receipt named
by its manifest.
