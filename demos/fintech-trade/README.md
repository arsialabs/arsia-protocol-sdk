# Fintech Trade Demo — ARSIA Protocol

A live demonstration of three autonomous AI agents executing a regulated
securities trade under MiFID-II compliance, communicating exclusively via
the ARSIA Protocol.

## What this demo shows

- **3 autonomous AI agents** communicating through signed ARSIA Protocol
  envelopes — no shared memory, no shared database, no direct function
  calls.
- **MiFID-II regulatory compliance** — suitability assessment (Art. 25),
  best execution (Art. 27), human oversight, and mandatory audit trail.
- **Structural data isolation** — each agent sees only the data it needs.
  Agent B never learns the client's name. Agent C never sees the risk
  profile.
- **Human-in-the-loop oversight** — a compliance officer must approve or
  deny the trade with a written justification before execution proceeds.
- **Complete audit trail** — every envelope is recorded with SHA-256
  payload hashes, MiFID-II compliance profile, and 5-year retention
  metadata.
- **LLM-powered decision-making** — Agent B uses an LLM for suitability
  analysis; Agent C uses an LLM for trade execution splitting. The LLM is
  your choice — the Ollama on your machine, OpenAI, Anthropic or Gemini
  with your own key, or none (see [Choosing the LLM](#choosing-the-llm)).
  Both agents fall back to deterministic results if the LLM is
  unavailable.
- **Real-time LLM streaming** — the dashboard shows LLM output
  token-by-token as each agent generates its response, with a live
  cursor and agent identification.

## Architecture

```
                     ┌─────────────────────────────────────────────────┐
                     │              Compliance Dashboard               │
                     │                 :3000 (FastAPI)                  │
                     │          SSE stream · approve/deny              │
                     └──────────────────────┬──────────────────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────────┐
                     │           Agent A — Client Advisor              │
                     │             :8001 (FastAPI)                     │
                     │    Orchestrates pipeline · holds client PII     │
                     └──────┬─────────────────────────────┬────────────┘
                            │                             │
              Envelope ②    │                             │    Envelope ⑤
           (no client PII)  │                             │  (no identity,
                            │                             │   no risk data)
                            ▼                             ▼
              ┌─────────────────────┐       ┌─────────────────────────┐
              │ Agent B — Risk      │       │ Agent C — Trade         │
              │ Assessor :8002      │       │ Executor :8003          │
              │ MiFID-II suitability│       │ Order splitting (TWAP)  │
              └────────┬────────────┘       └────────────┬────────────┘
                       │                                 │
              Envelope ③                        Envelope ⑥
          (suitability result)              (execution report)
                       │                                 │
                       ▼                                 ▼
              ┌──────────────┐              ┌──────────────────┐
              │     LLM      │              │       LLM        │
              └──────────────┘              └──────────────────┘

  One LLM for the whole demo: the Ollama on your machine (default,
  gemma4:e2b), OpenAI, Anthropic or Gemini with your own key, or none.
```

### Data isolation — who sees what

The key principle: **each agent only receives the data it needs for its
specific function.** Agent A enforces this by constructing separate
envelopes with different payloads for each peer.

| Data field                  | Agent A | Agent B | Agent C |
|-----------------------------|:-------:|:-------:|:-------:|
| Client name & account       |    Y    |    -    |    -    |
| Risk tolerance              |    Y    |    Y    |    -    |
| Portfolio composition       |    Y    |    Y    |    -    |
| Trade parameters            |    Y    |    Y    |    Y    |
| Suitability assessment      |    Y    |    -    |    -    |
| Execution report            |    Y    |    -    |    -    |
| Full audit trail            |    Y    |    -    |    -    |

The "fields not sent to this agent" notes in the Envelope Inspector
refer to fields that were present in the original client request but
**excluded** from the envelope sent to that particular agent. Agent A
always has the complete picture.

### Pipeline steps

| Step | What happens | Envelope |
|------|-------------|----------|
| 1 | Client request recorded by Agent A | Client → A |
| 2 | Agent A sends risk profile to Agent B (no client PII) | A → B |
| 3 | Agent B returns suitability assessment (LLM) | B → A |
| 4 | Agent A creates pending approval — pipeline stops | A (internal) |
| 5 | On approval: Agent A sends trade to Agent C (no identity, no risk) | A → C |
| 6 | Agent C returns execution report (LLM, 4×€50K TWAP split) | C → A |
| 7 | Audit trail finalized — all records sealed | — |

## Understanding the flow

This section explains what actually happens at each step, what data each
agent sees, and why the pipeline stops where it does. For the full
protocol specification, see the
[ARSIA Protocol spec](https://github.com/arsialabs/arsia-protocol).

### The big picture

```
Client ──[full PII]──→ Agent A ──[no PII]──→ Agent B (risk)
                          │                      │
                          │←──[suitability]──────┘
                          │
                      [STOP: awaiting human approval]
                          │
                          │──[trade params only]──→ Agent C (execution)
                          │                            │
                          │←──[execution report]───────┘
                          │
                      [Audit trail sealed]
```

Every arrow is a signed ARSIA Protocol
[envelope](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Core.md) —
Ed25519 signature, MiFID-II compliance profile, 5-year retention
metadata. No shared databases, no shared memory. Agents communicate
exclusively through envelopes.

### Step by step

**Step 1 — Client request recorded.**
The dashboard sends a trade request to Agent A with full client data:
name, account, risk tolerance, portfolio, proposed trade. Agent A records
this as an internal envelope (`from` and `to` are both Agent A) and
stores all client data in memory. This is the only place where the
complete picture exists.

**Step 2 — Agent A sends a risk profile to Agent B.**
Agent A constructs a **new** envelope for Agent B. Critically, this
envelope does not contain `client_name` or `client_account`. Agent B
receives an opaque `client_ref` identifier ("CLT-2026-4471"), the risk
tolerance, portfolio composition, and proposed trade — enough to assess
suitability, but not enough to identify the person. This is not redaction
(replacing values with `[REDACTED]`). The fields are simply never
included in the envelope — structural data isolation by construction.

**Step 3 — Agent B returns the suitability assessment.**
Agent B calls an LLM (or uses a deterministic fallback) to produce a
MiFID-II Art. 25(2) suitability analysis. The response includes a score
(0.0-1.0), a classification (suitable / suitable_with_warnings /
unsuitable), warnings, and the regulatory basis. Agent B signs the
response envelope and sends it back to Agent A. Agent A validates the
[correlation and explainability](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Actions.md)
of the response.

**Step 4 — Pipeline stops for human oversight.**
Agent A creates a `pending_approval`
[oversight envelope](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Actions.md).
This is not the approval itself — it is the **request** for approval. The envelope contains a
summary (amount, suitability score, warning count) and an expiry time
(1 hour). The pipeline halts here. The dashboard shows the approval form
with a countdown timer. Nothing proceeds until a human compliance officer
types a justification and clicks Approve or Deny.

**Step 5 — On approval, Agent A sends trade parameters to Agent C.**
After approval, Agent A constructs another new envelope — this time for
Agent C. This envelope contains only trade execution parameters:
instrument, amount, currency, venue, limit price, execution strategy.
The instrument, venue and limit price come from the client request; a
request without them gets UCITS-EU-BLEND-50 on XETRA at €50. It does **not**
contain the client name, account, risk tolerance, investment horizon,
portfolio composition, suitability score, or warnings. Agent C knows
**what** to trade but not **who** is trading or **why**.

**Step 6 — Agent C returns the execution report.**
Agent C calls an LLM (or falls back to deterministic logic) to split the
[trade](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Assets.md)
into orders of up to €50,000 each using a TWAP (Time-Weighted Average
Price) strategy. The response includes individual orders with fill
times, quantities, and prices. Every order buys whole units at the limit
price, and its amount is quantity × price; Agent C's code computes the
orders and their dates, whatever the LLM replies. Agent C signs the
response and sends it back to Agent A.

**Step 7 — Audit trail finalized.**
All envelopes have been recorded in the
[audit store](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-State.md).
Each audit record includes a SHA-256 payload hash, the compliance
profile (MIFID-II), and a 5-year (1,827 days) retention period. The
pipeline is marked complete.

### If approval is denied

When the compliance officer denies the trade, Agent A builds an oversight
denial error envelope with the approver ID and reason, records it in the
audit trail, and terminates the pipeline. Steps 5-7 never execute.

### Capability denial demo

The demo includes a capability denial scenario that proves Agent C
cannot perform risk assessments — only trade execution.

Agent A sends a request to Agent C asking for `risk.assess` — a
capability Agent C does not have. Agent C responds with a 403 Forbidden
and an ARSIA error envelope listing the required vs. provided
capabilities.

## Prerequisites

- **Python 3.12+**
- **An LLM, or none** — the [Ollama](https://ollama.com) on your machine
  (the default), OpenAI, Anthropic or Gemini with your own API key, or no
  LLM at all, in which case the agents use deterministic fallback
  responses. See [Choosing the LLM](#choosing-the-llm).
- **Docker** — only for [Docker mode](#running-with-docker).

## Quick start

### 1. Install dependencies

```bash
cd demos/fintech-trade
pip install -r requirements.txt
```

This installs the published `arsia-protocol` SDK and the demo's other
dependencies, at the versions the demo is tested with.

<details>
<summary>Optional: use a local SDK checkout</summary>

To run the demo against your own copy of the SDK, install it after the
requirements:

```bash
pip install -e ../../python
```

Docker mode always installs the published SDK.

</details>

### 2. Run

```bash
./run.sh                    # the Ollama on this machine (default)
./run.sh --llm openai       # or anthropic, gemini: needs your API key
./run.sh --no-llm           # no LLM: deterministic fallback responses
```

The script checks the LLM settings before starting anything, starts the
four services, waits until every agent holds its peers' public keys, and
prints a summary. With the default mode it also checks that Ollama is
running and pulls `gemma4:e2b` if it is missing. Press Ctrl+C to stop
everything.

<details>
<summary>Manual startup (four separate terminals)</summary>

Every agent fetches its peers' public keys at start-up and retries for
about 60 seconds, so start all three within that time. The terminals read
the LLM settings from the environment or from `.env`, as `run.sh` does.

```bash
# Terminal 1 — Agent B (Risk Assessor)
cd demos/fintech-trade
python -m uvicorn agents.risk_assessor:app --host 127.0.0.1 --port 8002

# Terminal 2 — Agent C (Trade Executor)
cd demos/fintech-trade
python -m uvicorn agents.trade_executor:app --host 127.0.0.1 --port 8003

# Terminal 3 — Agent A (Client Advisor)
cd demos/fintech-trade
python -m uvicorn agents.advisor:app --host 127.0.0.1 --port 8001

# Terminal 4 — Dashboard
cd demos/fintech-trade
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 3000
```

</details>

### 3. Open the dashboard

Navigate to **http://localhost:3000** in your browser.

## Demo walkthrough

### Starting the pipeline

1. Open **http://localhost:3000**.
2. The SSE connection indicator (top-right) should show **Connected**.
3. Click **Start Pipeline**. The demo sends a pre-filled trade request:
   - Client: Maria Torres, CLT-2026-4471
   - Amount: €200,000 in EU equities (UCITS-EU-BLEND-50 on XETRA, €50 limit price)
   - Risk tolerance: moderate, 5-10 year horizon

   Each **Reset** moves the dashboard to the next of its five client
   profiles, each with its own instrument, amount, limit price and venue.
   The prices and venues are illustrative, not market quotes.

### Watching the pipeline progress

- **Steps 1-3** execute automatically. On our test machine (an Apple
  silicon laptop) they took 11–13 s across our runs with `gemma4:e2b` on the host
  Ollama, and under a second without an LLM; the time depends on your
  machine and on the LLM you choose.
- The **Pipeline Status** bar shows each step lighting up in sequence.
- The **LLM Streaming** panel appears during step 2, showing Agent B's
  response being generated token-by-token in real time.
- At step 3, the **Suitability Assessment** panel appears with the LLM's
  analysis: score, classification, warnings, regulatory basis.

### Approving or denying

- At step 4, the pipeline **stops** and waits for human approval.
- The **Human Oversight** panel shows a summary (amount, suitability
  score, warning count) and a countdown timer.
- Type a justification in the text field (required).
- Click **Approve** (green) or **Deny** (red).
- On approval: steps 5-7 execute automatically. The **LLM Streaming**
  panel reappears showing Agent C generating the execution plan.
- On denial: the pipeline terminates and the denial is recorded.

### Inspecting the audit trail

- The **Audit Trail** table populates progressively as steps complete.
- Click any row to expand it and see: record ID, envelope ID, payload
  hash (SHA-256), correlation ID, compliance profile, retention period.
- After an approved run you should see 7 audit records; after a denied
  run, 6.

### Inspecting envelopes

- The **Envelope Inspector** shows the raw ARSIA envelope at each step.
- Click a step header to expand and see the full JSON.
- Steps 2 and 5 show **data isolation notes** listing which fields were
  excluded from the envelope sent to that agent.

### Triggering capability denial

The dashboard has no button for this; use the trigger endpoint with
`?demo_denial=true`:

```bash
curl -X POST http://localhost:8001/trigger?demo_denial=true \
  -H "Content-Type: application/json" \
  -d '{"client_ref":"CLT-TEST","proposed_trade":{"amount_eur":100000,"instrument":"UCITS-EU-BLEND-50","limit_price":50.00,"venue":"XETRA"}}'
```

The command answers `{"status": "started", "message": "Pipeline
triggered"}` (HTTP 200): it starts a normal pipeline run. When that run
reaches the approval step, Agent A also asks Agent C for `risk.assess`,
which Agent C does not have. Agent C refuses with 403 Forbidden and a
signed ARSIA error envelope. You can see the refusal:

- in Agent C's log: `"POST /envelope HTTP/1.1" 403 Forbidden`;
- in Agent C's audit trail (`curl http://localhost:8003/audit`): an
  `error` record from Agent C to Agent A, carrying the envelope's SHA-256
  payload hash (not its content).

The dashboard does not show this refusal; the pipeline waits for approval
as usual.

## Running with Docker

Docker mode runs the three agents and the dashboard in containers. The
LLM runs outside Docker: the Ollama on your machine, or a provider.

**Requirements:** Docker Engine 25.0 or later and Docker Compose 2.20.2 or
later. The health checks use `start_interval`, which Docker documents as
introduced in Compose 2.20.2 and as needing Engine API 1.44 (Engine 25.0).

```bash
cd demos/fintech-trade

# The Ollama on this machine (pull the model first: ollama pull gemma4:e2b)
docker compose up --build -d --wait

# Or OpenAI, Anthropic or Gemini with your key, or no LLM:
docker compose -f docker-compose.yml -f docker-compose.openai.yml up --build -d --wait
docker compose -f docker-compose.yml -f docker-compose.anthropic.yml up --build -d --wait
docker compose -f docker-compose.yml -f docker-compose.gemini.yml up --build -d --wait
docker compose -f docker-compose.yml -f docker-compose.no-llm.yml up --build -d --wait
```

`--wait` returns once every agent holds its peers' public keys and the
dashboard is up; then open **http://localhost:3000**. On our test machine
this took 7–20 s, with the Python base image already downloaded. To stop,
run the same command with `down` in place of `up --build -d --wait`.

- **Provider keys** — the provider files read `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` from your environment or from
  the demo's `.env`. Without it, Compose stops before building or
  starting anything. The key is passed only to the agents that call the
  LLM; like any container setting, `docker inspect` and
  `docker compose config` show it on your machine.
- **The host's Ollama** — the agents reach it at
  `http://host.docker.internal:11434` (set `DEMO_OLLAMA_URL` to change
  it). Docker Desktop resolves that name; we tested it on macOS with
  Ollama's default settings. Nothing is pulled in Docker mode.
- **Linux** (from Docker's and Ollama's documentation; not tested here) —
  the compose file maps `host.docker.internal` to the host with
  `extra_hosts: host-gateway`. Ollama "binds 127.0.0.1 port 11434 by
  default. Change the bind address with the `OLLAMA_HOST` environment
  variable" (Ollama FAQ), so on Linux it must listen on an address the
  containers can reach, for example `OLLAMA_HOST=0.0.0.0:11434`. That
  also exposes Ollama to your network; restrict access with a firewall.
- **The demo's `.env` is read by both `run.sh` and Docker Compose.** Keys
  and `DEMO_LLM_MODEL` set there apply to both. Do not put
  `DEMO_OLLAMA_URL=http://localhost:11434` there when you use Docker
  mode: inside a container, `localhost` is the container itself, so the
  agents cannot reach Ollama and fall back. `.env.example` keeps that
  line commented for this reason. In Docker mode the `-f` file chooses
  the LLM; `DEMO_LLM` in `.env` is used by `run.sh` only. The `.env` file
  is never copied into the images.

## Choosing the LLM

The demo uses one LLM for all its agents. The same choice works with
`./run.sh` and with Docker Compose.

| LLM | `run.sh` | Docker Compose file | Default model |
|-----|----------|---------------------|---------------|
| The Ollama on your machine (default) | `./run.sh` | `docker-compose.yml` alone | `gemma4:e2b` |
| OpenAI, your key | `./run.sh --llm openai` | `docker-compose.openai.yml` | `gpt-5.6-luna` |
| Anthropic, your key | `./run.sh --llm anthropic` | `docker-compose.anthropic.yml` | `claude-haiku-5-5` |
| Gemini, your key | `./run.sh --llm gemini` | `docker-compose.gemini.yml` | `gemini-3.5-flash-lite` |
| No LLM | `./run.sh --no-llm` | `docker-compose.no-llm.yml` | — |

- **API keys** — set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or
  `GEMINI_API_KEY` in your environment or in the demo's `.env`. Without
  the key for the chosen provider, `run.sh` and Docker Compose stop
  before starting anything and name the missing variable. The key is
  sent only in the request header the provider documents, never in a
  URL, and is never written to logs, health responses, the dashboard or
  the audit trail.
- **Each provider is called through its own API** — OpenAI and Ollama
  through chat completions, Anthropic through its Messages API (each
  agent asks for its reply as a JSON schema), Gemini through
  `streamGenerateContent`.
- **If an LLM call fails** (wrong key, rate limit, timeout), the agent
  logs `LLM call failed (openai returned HTTP 401), using fallback
  result` (or similar, without the key or the address) and uses its
  deterministic result; the pipeline still completes.
- **No LLM** — `--no-llm` (or `DEMO_LLM=none`) makes no LLM call at all.
  `--no-ollama` still works the same way and points to `--no-llm`.

## Configuration

All configuration is via environment variables, read from your
environment first and then from the demo's `.env`. See `.env.example`
for the full list; copy it to `.env` to customize:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_LLM` | `ollama` | The LLM for all agents: `ollama`, `openai`, `anthropic`, `gemini` or `none` (`run.sh`; `--llm` overrides it) |
| `DEMO_LLM_MODEL` | per LLM, see above | The model to use |
| `DEMO_OLLAMA_URL` | `http://localhost:11434` (Docker: `http://host.docker.internal:11434`) | Where the host's Ollama listens |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | — | Your key for the chosen provider |
| `DEMO_LLM_BASE_URL` | — | Advanced, for testing only: sends the provider's requests to another address; `run.sh` says when it is set, without showing it |
| `AGENT_A_PORT` | `8001` | Agent A listen port |
| `AGENT_B_PORT` | `8002` | Agent B listen port |
| `AGENT_C_PORT` | `8003` | Agent C listen port |
| `DASHBOARD_PORT` | `3000` | Dashboard listen port |
| `DASHBOARD_AGENT_A_URL` | `http://localhost:8001` | How the dashboard reaches Agent A |

**Removed variables.** The per-agent `AGENT_A_OLLAMA_URL`,
`AGENT_B_OLLAMA_URL`, `AGENT_C_OLLAMA_URL` and `AGENT_A/B/C_OLLAMA_MODEL`
are no longer read. One setting now covers all agents: `DEMO_OLLAMA_URL`
for the Ollama address and `DEMO_LLM_MODEL` for the model.

For example, to use another Ollama model:

```bash
DEMO_LLM_MODEL=llama3.2:3b ./run.sh
```

## Compliance

### MIFID-II profile

Used for all envelopes in the pipeline. Applied with:

```json
{
  "profile": "MIFID-II",
  "audit_required": true,
  "retention_days": 1827,
  "data_residency": "EU"
}
```

- `retention_days: 1827` — 5-year retention for investment services
  records (MiFID-II Art. 16(7)).
- `data_residency: EU` — data must remain in the European Union.

### Per-message overrides

Each envelope carries its own compliance block. The A → B envelope
excludes client PII fields; the A → C envelope further excludes risk
data. The compliance profile is consistent (MIFID-II) but the data
included in each envelope varies by recipient.

### What a regulator can verify

**Audit trail (7 records per approved pipeline):**

| # | Event type | From → To | What it proves |
|---|-----------|-----------|----------------|
| 1 | `request` | client → A | Trade request received |
| 2 | `request` | A → B | Suitability assessment requested (no client PII) |
| 3 | `response` | B → A | MiFID-II Art. 25(2) suitability result |
| 4 | `pending_approval` | A → officer | Human oversight gate created |
| 5 | `approval_decision` | officer → A | Compliance officer approved/denied with reason |
| 6 | `request` | A → C | Trade execution requested (no identity, no risk) |
| 7 | `response` | C → A | Execution report with TWAP order splitting |

If the officer denies the trade, record 5 records the denial and a sixth
record (`error`, officer → A) closes the pipeline; rows 6 and 7 never
occur.

Each record includes: SHA-256 payload hash, correlation ID, compliance
profile, retention period, data residency, and processing timestamp.

**MiFID-II compliance points:**

- **Art. 25 (suitability)** — Agent B performs suitability assessment
  before any trade execution. Assessment includes score, classification,
  warnings, and regulatory basis.
- **Art. 27 (best execution)** — Agent C splits large orders into
  smaller tranches using TWAP strategy to minimize market impact.
- **Art. 16(7) (record-keeping)** — 5-year retention period (1,827
  days) on all audit records with SHA-256 payload hashes.
- **Human oversight** — pipeline stops for compliance officer approval
  with expiry timer. Decision recorded with approver ID and written
  justification.

## The ARSIA Protocol in action

This demo builds on the **ARSIA Protocol SDK** — the open-source
reference implementation of the ARSIA Protocol specification.

**What the SDK provides** (used in this demo):
- Envelope construction (`create_request`, `create_response`,
  `create_pending_approval`, `create_approval_decision`)
- Ed25519 signing and verification (`sign_message`, `verify_message`)
- Compliance profile application (`apply_profile` — MiFID-II)
- Audit record building (`build_audit_record`)
- Capability matching (`match_capabilities`)
- Correlation and explainability validation

**What this demo builds** (not in the SDK):
- Agent logic (LLM integration, pipeline orchestration)
- HTTP transport (FastAPI endpoints, envelope delivery)
- Dashboard (SSE, approval UI, audit viewer)
- Key exchange (runtime public key distribution)

The SDK is transport-agnostic — it builds and validates envelopes. This
demo adds HTTP transport, but the same envelopes could travel over
WebSocket, gRPC, message queues, or any other transport.

## Project structure

```
demos/fintech-trade/
├── agents/
│   ├── __init__.py               # Package marker
│   ├── advisor.py                # Agent A — pipeline orchestrator (holds client PII)
│   ├── risk_assessor.py          # Agent B — MiFID-II suitability assessment
│   └── trade_executor.py         # Agent C — TWAP order splitting (no PII)
├── dashboard/
│   ├── __init__.py               # Package marker
│   ├── app.py                    # FastAPI proxy to Agent A + static serving
│   └── static/
│       ├── index.html            # Single-page dashboard (SSE, approval UI)
│       └── style.css             # Dashboard styles
├── run.sh                        # One-command local startup (./run.sh)
├── config.py                     # Agent/demo configuration from env vars
├── keys.py                       # Ed25519 key generation and peer exchange
├── transport.py                  # HTTP envelope sending and validation
├── llm_client.py                 # LLM client: host Ollama, OpenAI, Anthropic, Gemini
├── audit_store.py                # In-memory audit record store
├── flow_state.py                 # Pipeline state tracking with SSE broadcast
├── docker-compose.yml            # 3 agents + dashboard (host Ollama by default)
├── docker-compose.openai.yml     # Docker: OpenAI with your key
├── docker-compose.anthropic.yml  # Docker: Anthropic with your key
├── docker-compose.gemini.yml     # Docker: Gemini with your key
├── docker-compose.no-llm.yml     # Docker: no LLM
├── Dockerfile                    # Python 3.12.15 slim; installs requirements.txt
├── .dockerignore                 # Keeps .env and local files out of the images
├── requirements.txt              # Pinned Python dependencies (published SDK)
├── .env.example                  # Environment variable reference
└── README.md                     # This file
```

## Troubleshooting

### Ollama not running

```
[warn]  Ollama not running at http://localhost:11434
```

Start Ollama (`ollama serve`), choose another LLM (`./run.sh --llm
openai`, …), or run without one: `./run.sh --no-llm`. The agents use
deterministic fallback responses when Ollama is unreachable.

### Model not pulled

```
[warn]  Failed to pull gemma4:e2b — agents will use fallback
```

Pull manually: `ollama pull gemma4:e2b`. Check available models with
`ollama list`. In Docker mode nothing is pulled: pull the model on your
machine before starting.

### Missing API key

```
[fail]  DEMO_LLM=openai needs OPENAI_API_KEY to be set
```

Set the key in your environment or in `.env`. Docker Compose reports the
same as `required variable OPENAI_API_KEY is missing a value`.

### LLM call failed

```
LLM call failed (openai returned HTTP 401), using fallback result
```

401 means the provider rejected the key; 429 means a rate limit or a
spending limit. The pipeline still completes with the deterministic
result.

### Docker agents cannot reach Ollama

`curl http://localhost:8002/health` shows `"llm_reachable": false`.
Check that Ollama is running on your machine, that `DEMO_OLLAMA_URL` is
not set to a `localhost` address in `.env`, and, on Linux, that Ollama
listens on an address the containers can reach (see
[Running with Docker](#running-with-docker)).

### Port conflicts

```
[ERROR] Address already in use
```

Another process is using the port. Check with:

```bash
lsof -i :8001  # or :8002, :8003, :3000
```

Override ports via environment variables:

```bash
AGENT_A_PORT=9001 AGENT_B_PORT=9002 AGENT_C_PORT=9003 DASHBOARD_PORT=9000 ./run.sh
```

### LLM timeout

Each LLM call times out after 300 seconds (requests between agents after
360 seconds). The agent then logs `LLM call failed (… request timed
out), using fallback result` and uses its deterministic result; the
pipeline completes either way.

### Key exchange timeout

Every agent fetches its peers' public keys at start-up and retries for
about 60 seconds. Until it has them, its `/health` answers 503 with
`"status": "starting"`; if it gives up, 503 with
`"status": "key_exchange_failed"` and the missing peers. `run.sh` then
stops and prints the last health response. Start the demo again.

### Checking service health

```bash
curl http://localhost:8001/health  # Agent A
curl http://localhost:8002/health  # Agent B
curl http://localhost:8003/health  # Agent C
curl http://localhost:3000/health  # Dashboard
```

### Viewing logs

Each service logs to stderr. In Docker mode:

```bash
docker compose logs -f agent-a
docker compose logs -f agent-b
docker compose logs -f dashboard
```

In local mode with `run.sh`, all logs are interleaved in the terminal.
For separate logs, use manual startup (one terminal per service).

## Links

- **ARSIA Protocol**: [arsiaprotocol.org](https://arsiaprotocol.org)
- **SDK**: [github.com/arsialabs/arsia-protocol-sdk](https://github.com/arsialabs/arsia-protocol-sdk)
- **Spec**: [github.com/arsialabs/arsia-protocol](https://github.com/arsialabs/arsia-protocol)

## License

BSL 1.1 — see [LICENSE](../../LICENSE) in the repository root.
