# AgentSec-Bench

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23734796.svg)](https://doi.org/10.5281/zenodo.23734796)
[![ci](https://github.com/drsafavi/agentsec-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/drsafavi/agentsec-bench/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

An open benchmark for indirect prompt injection in tool-augmented LLM agents.

AgentSec-Bench measures how a tool-using agent behaves when untrusted content
returned by a tool contains instructions aimed at the agent. The payload is
always placed in a tool output, never in the user prompt, so the benchmark
isolates the indirect channel.

- **240 tasks**, each pairing one benign user goal with one injected payload.
- **6 tool environments:** email, calendar, file system, web browsing, code
  execution and a synthetic electronic health record (40 tasks each).
- **6 attack classes:** goal hijacking, data exfiltration, unauthorised tool
  invocation, privilege escalation through tool chaining, cross-session memory
  poisoning and multi-agent relay (40 tasks each).
- **3 obfuscation levels:** plain, encoded or formatted, and split across
  several tool outputs (80 tasks each).
- **4 measures:** benign task success, attack success rate, targeted harm rate
  and utility under attack, each reported per environment, attack class and
  obfuscation level.

Environment, attack class and obfuscation level are assigned independently, so
results can be read along any one axis without the others being confounded.

## Status

This is the benchmark, its reference agents and its harness. The repository
ships **no language-model results**. The numbers in [`RESULTS.md`](RESULTS.md)
are reference-agent validation runs that exercise the harness end to end.
Language-model results are produced by the user with their own API keys and are
reported separately, as described in the accompanying paper.

## Install

```bash
pip install -e ".[dev]"
```

The core package has no third-party runtime dependencies (standard library
only). Model providers are optional extras (`.[openai]`, `.[anthropic]`).

## Quickstart

```bash
# build the task suite (deterministic)
python -m agentsec_bench.generate --out data/tasks

# run the three reference agents and write results + summaries
python -m agentsec_bench.cli run --agent all --out results

# or reproduce everything, including the suite checksum
bash scripts/reproduce.sh
```

Reference-agent summary (see [`RESULTS.md`](RESULTS.md) for the full breakdown):

| Reference agent | Benign | Attack success | Harm | Utility under attack |
|---|---|---|---|---|
| Naive | 100.0 | 100.0 | 100.0 | 0.0 |
| Keyword-filter defence | 100.0 | 66.7 | 44.2 | 33.3 |
| Provenance defence | 100.0 | 0.0 | 0.0 | 100.0 |

The naive agent follows every readable injection; the provenance defence treats
tool output as data and follows none; the keyword filter blocks plain payloads
but is defeated by encoded and split ones (plain 0.0, encoded 100.0, split
100.0). This is the behaviour the measures are designed to separate.

## Running a language model

A model agent is driven by a provider through a tool-calling loop. Set the
provider's API key and run:

```python
from agentsec_bench.agents.model import build_provider
from agentsec_bench.generate import generate
from agentsec_bench.model_harness import run_model_task

provider = build_provider("openai:gpt-4o")      # or "anthropic:<model>", "hf:<org/model>"
rows = [run_model_task(t, provider) for t in generate()]
```

Providers raise a clear error if the SDK or API key is missing, so no network
call happens by accident. The tool-calling loop is covered by tests using a
scripted fake provider (`tests/test_model_path.py`).

## Task format

Each task is a JSON file in `data/tasks/`. The fields and the declarative check
language are documented in [`docs/task_schema.md`](docs/task_schema.md); the
machine schema is [`docs/task_schema.json`](docs/task_schema.json). Success and
harm are judged from the agent's tool calls and the resulting environment
state, not only from its text.

## Safety and responsible use

This is defensive security research. Every record, person, organisation,
credential and address in the task data is synthetic. Attacker destinations use
the reserved `.example` top-level domain and do not resolve to any real system.
Tools are deterministic mocks; nothing is sent, deleted or executed outside the
process. The optional Docker sandbox for the code and file-system environments
runs with no network, a read-only root file system and strict limits. The
benchmark is intended for measuring and improving agent defences, not for
attacking live systems.

## Licence

Code: MIT (see [`LICENSE`](LICENSE)). Task data and results: CC BY 4.0 (see
[`data/LICENSE-DATA.md`](data/LICENSE-DATA.md)).

## Citation

If you use AgentSec-Bench, please cite the archived software. The DOI below
always resolves to the latest version; version 0.1.0 is
[10.5281/zenodo.23734797](https://doi.org/10.5281/zenodo.23734797).

```bibtex
@software{safavi_agentsec_bench,
  author    = {Safavi, Seyedmostafa},
  title     = {{AgentSec-Bench: An Open Benchmark for Indirect Prompt
               Injection in Tool-Augmented Agents}},
  year      = {2026},
  publisher = {Zenodo},
  version   = {0.1.0},
  doi       = {10.5281/zenodo.23734796},
  url       = {https://doi.org/10.5281/zenodo.23734796}
}
```

Machine-readable metadata is in [`CITATION.cff`](CITATION.cff); GitHub's
"Cite this repository" button uses it.
