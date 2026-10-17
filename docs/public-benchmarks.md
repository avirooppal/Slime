# Public benchmark evaluation

Slime has **no measured public benchmark result**. `selfheal bench` runs a built-in **7-case smoke test** (5 synthetic fault scenarios + 2 adversarial non-incident log scenarios, scoring detection on the 5 fault cases, root-cause match, proposed fix or abstention match, and a separate false-incident metric on the 2 non-incident cases); because the scenarios and runbooks were written together in this repository, its scores are a local smoke test and not an accuracy measurement. The named Train-Ticket and AIOps Challenge adapters deliberately report unavailable because their trace parsers and ground-truth mappings are not implemented. A file extension alone is not a validated dataset.

For an external evaluation, obtain each benchmark from its maintainers, check the license of the exact dataset release (code and telemetry can differ), preserve the official train/test split, and map timestamps, service identity and ground-truth root causes into Slime's `Event` and `Incident` contracts. Score diagnosis before any remediation; the public telemetry alone does not establish that a proposed repair would succeed. Do not enter a score in README until the parser, mapping, split and scorer are versioned and tested.

| Benchmark | Maintainer instructions | Current integration |
|---|---|---|
| AIOpsLab | [Microsoft repository](https://github.com/microsoft/AIOpsLab) and its `LICENSE.txt` | External environment setup and scoring required |
| OpenRCA | [Microsoft repository](https://github.com/microsoft/OpenRCA) and its `LICENSE` | External telemetry download and RCA schema mapping required |
| RCAEval | [Maintainer repository](https://github.com/phamquiluan/RCAEval); review per-component licenses in `LICENSES` | Dataset-specific license and schema mapping required |
| ITBench | [ITBench repository](https://github.com/itbench-hub/ITBench) and [evaluation instructions](https://github.com/itbench-hub/ITBench-Evaluations) | Scenario runtime and scorer integration required |
| LogHub | [Maintainer repository](https://github.com/logpai/loghub) | Log parsing evaluation only; not root-cause or repair ground truth |
| Train-Ticket | [Benchmark service repository](https://github.com/FudanSELab/train-ticket) | An application, not an automatically scored trace dataset |

RCAEval combines material with different license terms, including components without a stated license. OpenRCA's large telemetry is downloaded separately from its code. This project does not fetch, redistribute or claim permission for those datasets. Verify upstream terms before use.
