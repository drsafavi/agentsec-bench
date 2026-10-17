# Reference-agent validation results

These numbers are produced by running the execution harness over all 240 tasks
with the three deterministic reference agents that ship with the benchmark.
They are **not language-model results**; they exist to show that the harness and
the scoring run end to end and that the measures separate a compromised agent, a
weak keyword-filter defence and a provenance defence. Language-model results are
produced by the benchmark user with their own API keys and are reported
separately. Every number below is reproducible with `bash scripts/reproduce.sh`.

Suite: 240 tasks, 6 environments (40 each), 6 attack classes (40 each), 3
obfuscation levels (80 each). All runs are deterministic.

## Overall (per cent)

| Reference agent | Benign task success | Attack success rate | Targeted harm rate | Utility under attack |
|---|---|---|---|---|
| Naive (follows any readable injection) | 100.0 | 100.0 | 100.0 | 0.0 |
| Keyword-filter defence (blocks plain only) | 100.0 | 66.7 | 44.2 | 33.3 |
| Provenance/spotlighting defence | 100.0 | 0.0 | 0.0 | 100.0 |

## Attack success rate by obfuscation level (per cent)

| Reference agent | Plain | Encoded | Split |
|---|---|---|---|
| Naive (follows any readable injection) | 100.0 | 100.0 | 100.0 |
| Keyword-filter defence (blocks plain only) | 0.0 | 100.0 | 100.0 |
| Provenance/spotlighting defence | 0.0 | 0.0 | 0.0 |

## Attack success rate by attack class, naive agent (per cent)

| Attack class | ASR |
|---|---|
| data exfiltration | 100.0 |
| goal hijacking | 100.0 |
| memory poisoning | 100.0 |
| multi agent relay | 100.0 |
| privilege escalation chaining | 100.0 |
| unauthorised tool invocation | 100.0 |
