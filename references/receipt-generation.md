# Receipt generation

A release owner needs to know that a PASS receipt came from the command that
actually ran. Copying a green test line into JSON loses the command, source,
and output boundary. `run-gate` therefore executes the manifest argv without a
shell and publishes the gate receipt atomically only after exit 0 and the exact
literal are observed.

A release owner can keep a gate portable as `npm ...` on every host even when
Windows exposes the launcher as `npm.cmd`. The runner resolves only argv[0]
through the execution environment's `PATH`/`PATHEXT`, accepts only an absolute
regular file, and uses that path for shell-free process creation. The receipt
continues to record and hash the exact declared argv, so a host installation
path cannot silently change the command identity.

```bash
python "$SKILL/scripts/feature_proof.py" run-gate "$PACKET" \
  --gate-id feature-scenarios --repo-root .
```

The receipt binds exact argv and its canonical digest, exit code, expected and
observed literal, full manifest-source identity, stdout/stderr byte counts and
digests, a combined output digest, and capture time. Each stream is capped at
1 MiB; timeout defaults to 900 seconds and can never exceed 3600. Raw output is
privacy-scanned but is not copied into the packet.

Before execution, the runner proves the implementation commit exists, every
declared implementation path is a tracked blob with matching Git-canonical
bytes, and the entire tracked checkout outside the feature packet matches that
commit. Non-ignored untracked paths outside the packet also fail, so an omitted
import shadow cannot influence a receipt. Inside the packet, source-committed
policy stays exact. Only the frozen source pointer, pending-to-verified claim
statuses, mutable `HANDOFF.md`, byte-prefix-preserving decision-log appends, and
generated outputs at committed gate/scenario/claim/media/SVG refs or exact
`artifact-manifest.json` are allowed. Generated refs may not alias a
source-tracked policy file, and any undeclared packet output fails. The
checkout guard canonicalizes only CRLF and bare CR to LF when comparing the
committed decision-log prefix; every non-newline byte remains exact. The gate
repeats this checkout guard after its child exits and before it publishes a
scenario or receipt. The child environment removes inherited
`PYTHONOPTIMIZE` and `PYTEST_ADDOPTS` so a caller cannot silently skip asserts
or change test selection. Packet publication is serialized with an OS-process
lock. Scenario/receipt bytes are written first and the feature manifest last;
an identical retry recovers an orphan, while a conflicting retry is refused.

## Typed scenario claims

Idempotency, versioning, review, citation, and refusal claims need values a
PASS line does not contain. The scenario command must write this bounded object
to the fresh path injected as `FEATURE_PROOF_SCENARIO_OUTPUT`:

```json
{
  "schema_version": "feature-proof-scenario-output/v1",
  "gate_id": "feature-scenarios",
  "source_identity_sha256": "value from FEATURE_PROOF_SOURCE_IDENTITY_SHA256",
  "claims": [
    {
      "claim_id": "claim-review-versioned",
      "receipt_type": "versioned",
      "passed": true,
      "evidence": {
        "previous": {
          "version": 1,
          "retrievable": true,
          "retrieval": {
            "authority": "immutable_evidence_snapshot",
            "receipt_sha256": "64 lowercase hex",
            "snapshot_sha256": "64 lowercase hex"
          }
        },
        "current": {
          "version": 2,
          "retrievable": true,
          "retrieval": {"authority": "current_authoritative_read"}
        }
      }
    }
  ]
}
```

Run and compile with exact packet-relative coordinates:

```bash
python "$SKILL/scripts/feature_proof.py" run-gate "$PACKET" \
  --gate-id feature-scenarios --repo-root . \
  --expect-scenario-output

python "$SKILL/scripts/feature_proof.py" compile-claim "$PACKET" \
  --claim-id claim-review-versioned \
  --scenario-output receipts/scenarios/feature-scenarios.json \
  --repo-root .
```

`compile-claim` compares the structured row byte-for-byte with the generated
receipt, verifies the deriving gate and hashes, then atomically changes only
that claim to `verified`. Trace and parallel claims cannot be compiled from
scenario JSON; trace claims use the verifier below.
Before `run-gate` publishes either scenario or gate receipt, every scenario row
must match one declared manifest claim and its exact closed `evidence_schema`.

## Authenticated trace claims

A normalized trace is diagnostic staging data, not a verified claim and not a
promotion input. Give the verifier an immutable trace ID; it performs the
authenticated Langfuse reads itself. A stale release, dirty source,
wrong contract, privacy leak, non-finite or duplicate score, latency violation,
or broken topology fails before the manifest changes:

```bash
python "$SKILL/scripts/feature_proof.py" normalize langfuse-export.json \
  staged-assessment.json
python "$SKILL/scripts/feature_proof.py" verify-trace-claim "$PACKET" \
  --claim-id claim-assessment-trace \
  --trace-id <immutable-langfuse-trace-id> --repo-root .
```

Set `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY`; set a bounded HTTPS
`LANGFUSE_BASE_URL` only for a non-default host. An optional canonical export
cache may be supplied with `--langfuse-export-cache`, but promotion rejects it
unless its bytes equal the verifier's authenticated response.
At this environment boundary, surrounding whitespace and leading UTF-8 BOM
characters are removed from credentials. Empty, oversized, or control-bearing
results fail without including credential bytes in an error.

The verifier writes the claim's declared `receipt_ref` atomically, stamps
`claim_id`, the canonical claim definition and digest,
`trace_contract_sha256`, `source_identity_sha256`, and the raw Langfuse
response digest, then changes only the selected pending trace claim to
`verified`. A process-safe packet lock serializes promotion. An identical
orphan receipt is recoverable after interruption; a conflicting retry is
rejected. Do not copy normalized staging into the receipt path or hand-edit the
claim status.

`trace_contract_sha256` hashes the immutable Git blob at the manifest's frozen
source commit. It never hashes platform-smudged worktree bytes. LF, CRLF, and
bare-CR spellings are accepted only when normalizing line endings makes the
current contract byte-identical to that blob; any non-newline mutation fails
before receipt publication, and the parsed contract still passes the complete
semantic validator.
