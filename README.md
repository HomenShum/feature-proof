# Feature Proof

A workflow for developers and coding agents who need another person to verify a feature handoff. It connects the business problem, typed contracts, scenario results, traces and applicable UI evidence in a packet of recorded results and file hashes.

For example, a recovery flow can look correct in a final screenshot while losing work during a retry. The workflow asks for the before state and the actual journey so a reviewer can see what was checked and what the evidence supports.

## Start here

1. Read the [workflow](SKILL.md) and its [completion boundary](SKILL.md#completion-boundary). Define the feature and its acceptance criteria before implementation.
2. Use the [feature manifest template](assets/feature-manifest.template.json) with the [manifest contract](references/manifest-contract.md) to name the code, claims, scenarios and required evidence.
3. Follow the [tooling reference](SKILL.md#tooling) and [receipt-generation guide](references/receipt-generation.md) to produce and check the packet.

Use the workflow with the repository containing the feature you are changing. This repository supplies the workflow, templates and Python helpers; build, test and capture commands belong to that target project. The npm commands in the capture guide are examples to adapt to its existing scripts.

## Find the right reference

| Decision | Reference |
| --- | --- |
| What must the handoff prove? | [Manifest contract](references/manifest-contract.md) |
| Which failure and load scenarios apply? | [Forward-test matrix](references/forward-test-matrix.md) |
| How should one user action be traced? | [Trace contract](references/trace-contract.md) |
| What should the browser and video evidence show? | [Capture contract](references/capture-contract.md) |
| How are results turned into verifiable records? | [Receipt generation](references/receipt-generation.md) |
| Where are the packet templates? | [Templates](assets/) |
| Where is the main Python helper? | [feature_proof.py](scripts/feature_proof.py) |
| Where is the agent adapter metadata? | [openai.yaml](agents/openai.yaml) |

## Readiness and completion

Reading or installing this workflow does not produce a completed feature. Run the target project's applicable checks and collect the evidence named by its manifest. UI work needs its real journey and media evidence; server-only work can mark UI evidence inapplicable. Model and hosted-trace evidence depend on what actually ran. The [workflow](SKILL.md) defines those boundaries and the order for finalizing the packet.

[Change history](CHANGELOG/docs/readme.md) · [License](LICENSE)
