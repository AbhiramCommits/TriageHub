# TriageHub

TriageHub is a triage surface for static-analysis security findings. Semgrep-style findings land in
Postgres, and reviewers act on them where they already work — a Slack message or an inline GitHub
pull-request review comment — instead of opening yet another dashboard. A React console handles
bulk triage, SSO-only onboarding scopes every session to one workspace, and an append-only events
table answers how fast findings get triaged, which rules are noisy, and whether notification format
A or B gets triaged faster.

Capabilities:

- **OAuth install handshake** for Slack and GitHub App, with signed, TTL-stamped, single-use state.
- **Slack triage actions** from `/triage` slash commands and Block Kit Accept / Mute / Assign buttons.
- **GitHub inline PR comments** grouped into one review, plus fingerprint-based auto-resolution on push.
- **React triage console** with URL-backed filters, bulk actions, keyboard navigation and optimistic updates.
- **SSO-only onboarding** through OIDC with PKCE, ID-token validation and JIT user provisioning.
- **Metrics + A/B experiment** over an append-only events table, including a two-proportion z-test.

## Architecture

```
 Slack events ─┐
 GitHub hooks ─┼─> FastAPI routers ──> services/triage.apply_transition ──> PostgreSQL
 OIDC IdP ─────┘   (verify first)              │                          findings
                                               │                          events (append-only)
 Browser console ──> /api/findings,             └──> analytics/metrics
                     /api/findings/bulk-transition,     (pure functions over events)
                     /api/metrics/summary
```

| Directory | What lives there |
|---|---|
| `backend/app` | FastAPI app, SQLAlchemy models, auth, Slack/GitHub integrations, metrics |
| `backend/alembic` | Initial schema and OAuth nonce migrations |
| `backend/tests` | 85 pytest tests over a real Postgres test database |
| `frontend/src` | React 18 + TypeScript console, components, hooks and vitest tests |
| `scripts` | Idempotent seed, deterministic simulation and metrics analysis |
| `data` | 132 realistic Semgrep-style sample findings |
| `results` | Generated `metrics.json` and `metrics.md` |
| `.github/workflows` | Backend and frontend CI jobs |

Two design decisions carry the system:

1. **One transition chokepoint.** Slack, GitHub and the console all call
   `services/triage.py::apply_transition`. State legality, first-terminal `triaged_at`, idempotent
   replays and event emission are implemented once, so surfaces cannot drift apart.
2. **The events table is append-only.** A finding's current state is a column, but every meaningful
   act is an event row. Metrics are pure functions over those rows, so time-to-triage, rule noise and
   experiment results are auditable and reproducible instead of being computed from mutable counters.

**Tradeoff accepted:** metrics are computed in Python from raw JSONB events rather than maintained as
materialized aggregates. That keeps writes simple and the audit trail exact, at the cost of recomputing
over the whole event set as volume grows.

## Security notes

- **OAuth state** is HMAC-SHA256 signed, TTL-stamped (10 minutes by default) and single-use. Nonces are
  checked in a process-local store for unit tests and persisted in `consumed_nonces` for multi-worker
  replay protection. Bad signature, expiry and replay all fail before any token exchange.
- **Provider tokens** are encrypted at rest with Fernet (`TOKEN_ENCRYPTION_KEY`). Access and refresh
  tokens are never stored or logged in plaintext; refresh happens inside 60 seconds of expiry and a
  rotated refresh token replaces the old one.
- **Slack requests** verify the `v0` signing secret over `v0:{timestamp}:{body}` with a five-minute
  timestamp window and a constant-time comparison. Button payloads carry their own signed
  finding/workspace pair, verified before any transition.
- **GitHub webhooks** verify `X-Hub-Signature-256` with HMAC-SHA256 before parsing the body.
  Installation tokens are minted from an RS256 app JWT and cached until expiry.
- **Workspace scoping:** sessions bind a user to one workspace. `require_workspace` and the workspace
  resolver reject cross-workspace reads and writes with 403.
- **SSO-only enforcement:** `workspace.sso_only = true` makes the password/dev-login path return 403;
  only the OIDC callback can create a session for that workspace. Production also disables anonymous
  dev reads.

## How to run

Prerequisites: Docker, Python 3.11, Node 20.

```bash
cp .env.example .env
docker compose up --build -d
```

The API is at `http://localhost:8000`, the console at `http://localhost:5173`. The API container runs
`alembic upgrade head` on start. To load the demo data, install the backend locally (the scripts use
the host `DATABASE_URL` from `.env`):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e "backend[dev]"

python scripts/seed.py
python scripts/simulate.py
python scripts/analyze.py
```

`seed.py` is idempotent and loads 132 findings into two workspaces. `simulate.py` writes a deterministic
triage history through `apply_transition`; it is a no-op if a simulation is already present. `analyze.py`
regenerates `results/metrics.json` and `results/metrics.md`.

Quick check:

```bash
curl "http://localhost:8000/api/findings?severity=high"
curl "http://localhost:8000/api/metrics/summary"
```

### Tests

Backend (needs the Postgres container; the suite creates and drops `triagehub_test`):

```bash
docker compose up -d db
cd backend
alembic upgrade head
ruff check . && ruff format --check . && mypy app
pytest --cov=app --cov-fail-under=80
```

Frontend:

```bash
cd frontend
npm ci
npx tsc --noEmit
npm run test -- --run
npm run build
```

For live development, run Postgres only (`docker compose up -d db`), then
`cd backend && uvicorn app.main:app --reload` and `cd frontend && npm run dev`.

## Results

All figures below were produced by running the pipeline in this repository (`seed.py` → `simulate.py`
→ `analyze.py`) and the test suites. `analyze.py` aggregates events across both seeded workspaces;
the per-workspace API returns the same metrics scoped to the signed-in workspace.

**Dataset:** 132 findings, 367 events (103 terminal transitions, 8 auto-resolved), 15 rule IDs,
4 repositories, 2 workspaces.

### Time to triage

| Scope | n | Median | p90 |
|---|---:|---:|---:|
| overall | 103 | 20,303.95 s (5h 38m) | 118,519.73 s (32h 55m) |
| critical | 19 | 6,011.69 s (1h 40m) | 11,926.78 s (3h 18m) |
| high | 42 | 17,401.63 s (4h 50m) | 53,945.84 s (14h 59m) |
| medium | 26 | 39,864.33 s (11h 04m) | 120,456.06 s (33h 27m) |
| low | 16 | 69,344.86 s (19h 15m) | 131,612.64 s (36h 33m) |

### Noisiest rules (n >= 5 accepted or muted)

| Rule | Muted | Accepted | n | FP rate |
|---|---:|---:|---:|---:|
| `python.lang.correctness.useless-comparison` | 7 | 0 | 7 | 100.00% |
| `javascript.lang.security.audit.prototype-pollution` | 6 | 0 | 6 | 100.00% |
| `python.flask.security.audit.debug-enabled` | 8 | 1 | 9 | 88.89% |
| `python.lang.security.audit.weak-hash` | 8 | 2 | 10 | 80.00% |
| `javascript.lang.security.audit.innerhtml` | 6 | 3 | 9 | 66.67% |

### Notification variant A/B

| Variant | n | Triaged | Triage rate | Median time to triage |
|---|---:|---:|---:|---:|
| A (compact one-liner) | 77 | 64 | 83.12% | 18,002.71 s (5h 00m) |
| B (expanded + snippet) | 55 | 39 | 70.91% | 41,500.01 s (11h 31m) |

Absolute difference in triage rate: 0.1221 (12.21 percentage points). Two-proportion z-test:
**z = -1.6701, two-sided p = 0.094907**. With p >= 0.05 the result is **not statistically significant**;
this sample does not justify picking a winner, even though variant A looks faster.

### Build health

| Measure | Result |
|---|---|
| Backend tests | 85 passing |
| Backend coverage (`--cov=app`) | 89.70% |
| Frontend tests | 8 passing (2 files) |
| TypeScript | `tsc --noEmit` clean under `strict` |
| Frontend build | Vite production build succeeds |

## Limitations and what I'd do next

- **The triage history is simulated.** Findings are realistic, but the 103 triage decisions and their
  timings come from a fixed-seed simulation, not production reviewers. The metrics pipeline is real;
  the behaviour it measures is not. Next: ship the events table behind an actual Slack workspace and
  compare against observed traffic.
- **The A/B split is 77/55, not exactly 50/50.** Assignment is a deterministic hash of the finding UUID;
  uniform over random UUIDs, but this sample drew an uneven split. Next: stratify assignment at the
  workspace/rule level and pre-register a minimum sample size, since the current experiment is
  underpowered at p = 0.0949.
- **SAML is not implemented.** SSO is OIDC only. Next: add a SAML broker or accept an OIDC bridge for
  enterprise IdPs.
- **No retry/backoff queue for provider rate limits.** Provider calls are synchronous; a Slack or GitHub
  429 surfaces as an error. Next: move notifications and review posting onto a durable queue with
  exponential backoff and dead-lettering.
- **Review thread resolution needs stored thread IDs.** GitHub's REST review API does not return GraphQL
  thread IDs, so auto-resolution resolves a thread only when a prior `review.posted` event recorded one.
  Next: after posting a review, query GraphQL for the created threads and persist them.
- **Replay protection is split.** Tests use the in-memory nonce store; the API persists nonces in
  Postgres. A multi-region deployment would want a shared cache with TTL for the same guarantee at lower
  write cost.
- **No secret scanning of provider payloads.** Findings, event payloads and Slack confirmations can
  include code snippets. Next: redact matched secrets before persisting snippets, and add retention
  controls for the events table.
