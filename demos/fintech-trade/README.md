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
  analysis; Agent C uses an LLM for trade execution splitting. Both fall
  back to deterministic results if the LLM is unavailable.
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
              │   Ollama     │              │     Ollama       │
              │ gemma4:e2b   │              │   gemma4:e2b     │
              └──────────────┘              └──────────────────┘

  Default model: gemma4:e2b for all agents (configurable per agent)
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
instrument, amount, currency, venue, execution strategy. It does **not**
contain the client name, account, risk tolerance, investment horizon,
portfolio composition, suitability score, or warnings. Agent C knows
**what** to trade but not **who** is trading or **why**.

**Step 6 — Agent C returns the execution report.**
Agent C calls an LLM (or falls back to deterministic logic) to split the
[trade](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Assets.md)
into orders of up to €50,000 each using a TWAP (Time-Weighted Average
Price) strategy. The response includes individual orders with fill
times, quantities, and prices. Agent C signs the response and sends it
back to Agent A.

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
- **Ollama** installed and running (optional — agents fall back to
  deterministic responses)
- **arsia-protocol SDK** installed in development mode

## Quick start

### 1. Install dependencies

```bash
# From the repo root:
cd python && pip install -e ".[dev]"
cd ../demos/fintech-trade && pip install -r requirements.txt
```

### 2. Pull Ollama model (optional)

```bash
ollama pull gemma4:e2b
```

Skip this step to run without LLM — agents use deterministic fallback
responses automatically.

### 3. Run

```bash
cd demos/fintech-trade
./run.sh
```

Or skip Ollama checks:

```bash
./run.sh --no-ollama
```

The script validates prerequisites, starts all four services in the
correct order, waits for health checks, and prints a summary. Press
Ctrl+C to stop everything.

<details>
<summary>Manual startup (four separate terminals)</summary>

Start Agent B and C before Agent A — Agent A exchanges public keys with
its peers on startup and will retry until they respond.

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

### 4. Open the dashboard

Navigate to **http://localhost:3000** in your browser.

## Demo walkthrough

### Starting the pipeline

1. Open **http://localhost:3000**.
2. The SSE connection indicator (top-right) should show **Connected**.
3. Click **Start Pipeline**. The demo sends a pre-filled trade request:
   - Client: Maria Torres, CLT-2026-4471
   - Amount: €200,000 in EU equities
   - Risk tolerance: moderate, 5-10 year horizon

### Watching the pipeline progress

- **Steps 1-3** execute automatically (~10-15s with `gemma4:e2b`,
  instant with fallback).
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
- After completion, you should see 6-8 audit records (depending on the
  path taken).

### Inspecting envelopes

- The **Envelope Inspector** shows the raw ARSIA envelope at each step.
- Click a step header to expand and see the full JSON.
- Steps 2 and 5 show **data isolation notes** listing which fields were
  excluded from the envelope sent to that agent.

### Triggering capability denial

Add `?demo_denial=true` to the trigger:

```bash
curl -X POST http://localhost:8001/trigger?demo_denial=true \
  -H "Content-Type: application/json" \
  -d '{"client_ref":"CLT-TEST","proposed_trade":{"amount_eur":100000}}'
```

This asks Agent C for `risk.assess` (which it doesn't have), triggering
a 403 Forbidden response with an ARSIA error envelope.

## Running with Docker

```bash
cd demos/fintech-trade
docker compose up --build
```

The first startup will pull Ollama images and models (this takes time).

### Single Ollama mode

For machines with limited resources, point all agents at one Ollama
instance. Create a `.env` file:

```bash
cp .env.example .env
```

Then uncomment the single-Ollama overrides:

```
AGENT_A_OLLAMA_URL=http://localhost:11434
AGENT_B_OLLAMA_URL=http://localhost:11434
AGENT_C_OLLAMA_URL=http://localhost:11434
```

### GPU passthrough (NVIDIA)

Uncomment the `deploy.resources.reservations.devices` block in
`docker-compose.yml` for each Ollama service to enable GPU acceleration.

## Configuration

All configuration is via environment variables. See `.env.example` for
the full list. Copy it to `.env` to customize:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_A_PORT` | `8001` | Agent A listen port |
| `AGENT_B_PORT` | `8002` | Agent B listen port |
| `AGENT_C_PORT` | `8003` | Agent C listen port |
| `DASHBOARD_PORT` | `3000` | Dashboard listen port |
| `AGENT_A_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint for Agent A |
| `AGENT_B_OLLAMA_URL` | `http://localhost:11435` | Ollama endpoint for Agent B |
| `AGENT_C_OLLAMA_URL` | `http://localhost:11436` | Ollama endpoint for Agent C |
| `AGENT_A_OLLAMA_MODEL` | `gemma4:e2b` | Model for Agent A |
| `AGENT_B_OLLAMA_MODEL` | `gemma4:e2b` | Model for Agent B |
| `AGENT_C_OLLAMA_MODEL` | `gemma4:e2b` | Model for Agent C |
| `DASHBOARD_AGENT_A_URL` | `http://localhost:8001` | How the dashboard reaches Agent A |

### Changing Ollama model

Set the model per agent via environment variables:

```bash
AGENT_B_OLLAMA_MODEL=llama3.2:3b ./run.sh
```

### Single Ollama instance

Point all agents at one Ollama (typical for local development):

```bash
export AGENT_A_OLLAMA_URL=http://localhost:11434
export AGENT_B_OLLAMA_URL=http://localhost:11434
export AGENT_C_OLLAMA_URL=http://localhost:11434
./run.sh
```

The run script does this automatically — in local mode, all agents
default to `http://localhost:11434`.

### Using a different LLM provider

The agents use Ollama's OpenAI-compatible endpoint
(`/v1/chat/completions`). Any provider with the same API works —
set the Ollama URL to your provider's base URL:

```bash
AGENT_B_OLLAMA_URL=http://your-openai-compatible-api:8080 ./run.sh
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

**Audit trail (6-8 records per completed pipeline):**

| # | Event type | From → To | What it proves |
|---|-----------|-----------|----------------|
| 1 | `request` | client → A | Trade request received |
| 2 | `request` | A → B | Suitability assessment requested (no client PII) |
| 3 | `response` | B → A | MiFID-II Art. 25(2) suitability result |
| 4 | `pending_approval` | A → officer | Human oversight gate created |
| 5 | `approval_decision` | officer → A | Compliance officer approved/denied with reason |
| 6 | `request` | A → C | Trade execution requested (no identity, no risk) |
| 7 | `response` | C → A | Execution report with TWAP order splitting |
| 8 | `response` | A → client | Pipeline complete — audit sealed |

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
├── ollama_client.py              # Ollama OpenAI-compatible API client
├── audit_store.py                # In-memory audit record store
├── flow_state.py                 # Pipeline state tracking with SSE broadcast
├── docker-compose.yml            # 3 Ollama + 3 agents + dashboard
├── Dockerfile                    # Python 3.12 slim with SDK volume mount
├── entrypoint.sh                 # Installs SDK from volume on first run
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variable reference
└── README.md                     # This file
```

## Troubleshooting

### Ollama not running

```
[warn] Ollama not running at http://localhost:11434
```

Start Ollama: `ollama serve`. Or run without it: `./run.sh --no-ollama`.
Agents automatically use deterministic fallback responses when Ollama is
unreachable.

### Model not pulled

```
[warn] Failed to pull gemma4:e2b
```

Pull manually: `ollama pull gemma4:e2b`. Check available models with
`ollama list`.

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

The default timeout is 120 seconds for LLM calls. If the LLM is slow,
agents automatically fall back to deterministic responses and log a
warning. The pipeline completes successfully either way.

### Key exchange timeout

```
Key exchange incomplete — missing peers: [...]
```

Agent A retries key exchange for 60 seconds. If peers don't start in
time, Agent A will log a warning and continue. Restart Agent A after the
peers are healthy.

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
