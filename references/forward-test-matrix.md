# Forward-test matrix

A feature owner needs proof that a workflow survives real use, not only one
clean example. A passing happy path can conceal a fail-open refusal, duplicate
retry, unavailable dependency, burst race, or state that decays after many
turns. The manifest therefore names every forward scenario and its receipt.

Every feature manifest covers these categories:

| Category | Required observation |
|---|---|
| `happy` | The named persona reaches the business decision through the real path |
| `sad` | A realistic incomplete or invalid request produces the honest state |
| `adversarial` | Authority, privacy, citation, or idempotency abuse fails closed |
| `degraded` | A dependency timeout/unavailability has bounded, honest recovery |
| `burst` | Concurrent or rapid repeated work stays bounded and deduplicated |
| `sustained` | Long-running use stays within latency, memory, and state bounds |
| `restore` | Durable state restores deterministically after reload/restart |

Each `verification_matrix` row carries a stable ID, one category, a persona,
goal, behavior, and either an `expected_receipt` or `gate_id`. UI applicability
is explicit. A row is a contract pointer, not proof; the referenced current-
release receipt or gate is still required before the related claim is verified.

Use representative scale. The default burst is 100 immediate attempts. The
default sustained case is 100 sequential turns or the product's lower declared
capacity bound. Record the exact count, elapsed time, maximum resident state,
eviction/deduplication result, and final restore identity where applicable.
