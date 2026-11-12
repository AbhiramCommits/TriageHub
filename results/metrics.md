# TriageHub metrics

Generated 2026-11-12T15:41:37.977937+00:00 from 132 findings, 367 events (103 terminal transitions), 15 rules and 4 repositories.

## Time to triage

| Scope | n | Median (s) | Median | p90 (s) | p90 |
|---|---:|---:|---|---:|---|
| overall | 103 | 20303.95 | 5h 38m | 118519.73 | 32h 55m |
| critical | 19 | 6011.69 | 1h 40m | 11926.78 | 3h 18m |
| high | 42 | 17401.63 | 4h 50m | 53945.84 | 14h 59m |
| medium | 26 | 39864.33 | 11h 04m | 120456.06 | 33h 27m |
| low | 16 | 69344.86 | 19h 15m | 131612.64 | 36h 33m |

## False-positive rate by rule (n >= 5 accepted or muted)

| Rule | Muted | Accepted | n | FP rate |
|---|---:|---:|---:|---:|
| `python.lang.correctness.useless-comparison` | 7 | 0 | 7 | 100.00% |
| `javascript.lang.security.audit.prototype-pollution` | 6 | 0 | 6 | 100.00% |
| `python.flask.security.audit.debug-enabled` | 8 | 1 | 9 | 88.89% |
| `python.lang.security.audit.weak-hash` | 8 | 2 | 10 | 80.00% |
| `javascript.lang.security.audit.innerhtml` | 6 | 3 | 9 | 66.67% |
| `python.cryptography.security.insufficient-key-size` | 4 | 3 | 7 | 57.14% |
| `python.lang.security.audit.hardcoded-password` | 4 | 4 | 8 | 50.00% |
| `python.lang.security.audit.subprocess-shell-true` | 1 | 12 | 13 | 7.69% |
| `python.lang.security.audit.eval-detected` | 0 | 6 | 6 | 0.00% |

## A/B notification experiment

| Variant | n | Triaged | Triage rate | Median time to triage (s) | Median |
|---|---:|---:|---:|---:|---|
| A | 77 | 64 | 83.12% | 18002.71 | 5h 00m |
| B | 55 | 39 | 70.91% | 41500.01 | 11h 31m |

Absolute difference in triage rate: 0.1221
Two-proportion z-test: z = -1.6701, two-sided p = 0.094907
Verdict: **Not statistically significant at p<0.05; do not pick a winner from this sample.**
