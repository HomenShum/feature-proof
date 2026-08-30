# Trace and waterfall contract

An engineer needs to know what the software actually did for one user action.
Source code may contain concurrent syntax while the live work still ran one
step at a time. Only the run's timestamps decide whether work overlapped.

## Acquire and normalize

Promotion uses the official authenticated Langfuse client to fetch the immutable
trace ID and its observations/scores. A configured client or provider-shaped
local JSON file is not delivery proof.

```python
client.api.observations.get_many(trace_id=trace_id, fields="core,basic,metadata,model,usage,prompt,metrics,trace_context", limit=257)
client.api.scores_v3.get_many_v3(trace_id=trace_id, fields="details,subject,annotation", limit=100)
```

Langfuse v4 defaults to observations-only storage, so the verifier reconstructs
the trace envelope from the single root observation's authenticated
`trace_context` fields. It never calls the legacy trace endpoint and does not
request observation input/output.

Poll for at least 45 seconds when delivery is asynchronous. Serialize the
selected trace locally, then run `feature_proof.py normalize`. Normalization
rejects raw email/credential-like content and drops inputs, outputs, comments,
documents, and prompt text. It retains only topology, timestamps, closed
metrics, score values, trace/release identity, and a digest of the raw export.
Keep that normalized file only for diagnostics. Publish with
`verify-trace-claim --trace-id ...`, which fetches the hosted run itself, scans
the entire raw payload against privacy keys/patterns, derives normalization, rejects
a stale release or source binding, validates the claim-specific contract,
stamps raw-export, contract, claim, and source-identity digests, writes the
declared receipt path, and promotes the manifest last.
The contract digest is the SHA-256 of the contract blob at the frozen source
commit, not the platform-specific worktree bytes. The verifier accepts LF,
CRLF, or bare-CR spelling only when newline normalization leaves every other
source byte unchanged, then validates the parsed contract semantics as usual.
Provider placeholder privacy keys are accepted only when their value is exactly
`null`, `""`, `[]`, or `{}`; any nonempty input, output, user ID, status message,
or other forbidden field fails before normalization.

## Validate

`trace-contract.json` names the root, required spans, optional spans whose
parent/kind is checked when present, ordered pairs, any parallel groups,
conditional metrics, required scores, privacy denylist, and bounds. The checker enforces:

- one root, unique span IDs, existing parents, and children contained within
  parent intervals;
- `start <= end` for every span; provider-resolution zero-duration spans are
  honest sequential work, but they never prove overlap or parallelism;
- required names, parents, kinds, metrics, and score thresholds;
- exactly one runtime span for every contract-addressable name;
- exact closed receipt/span/score schemas, finite unique score values, and
  explicit `required_values` for every runtime status and authority-bearing
  field such as authenticated, persisted, checkpointed, resumed, and review decision;
- ordered spans that do not overlap or reverse;
- positive overlap for every declared parallel group:
  `max(starts) < min(ends)`;
- model, prompt version, input/output/total tokens, cost, and latency when
  `model_attempted=true`;
- every observed interval and `latency_ms` stays within the contract's
  `max_latency_ms` when that bound is declared;
- no model/version/token/cost metrics required when `model_attempted=false`;
  a generation-kind fallback span may still describe deterministic work.

Touching endpoints are sequential, not parallel. Parent-child containment is
nesting, not parallel evidence.

## Render Scene 7

`render-waterfall` accepts only the normalized receipt. Bar positions and
widths come from its timestamps. It calculates sibling overlap, explicitly
labels `none` for a sequential run, embeds the normalized receipt SHA-256 in
both SVG and HTML, and uses no wall-clock generation data. The engineering
narration must reference a `trace_contract` claim and a waterfall whose embedded
digest matches that claim's receipt. Finalization hashes the rendered files.
