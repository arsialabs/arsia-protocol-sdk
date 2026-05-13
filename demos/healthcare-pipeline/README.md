# Healthcare Data Pipeline with PII Isolation — ARSIA Protocol

A live demonstration of three autonomous AI agents processing patient
health data through a regulated pipeline with structural PII isolation,
communicating exclusively via the ARSIA Protocol. The pipeline
anonymizes patient records, generates clinical analysis from anonymized
lab values, requires clinician approval before delivering results, and
produces a complete audit trail — demonstrating GDPR Art. 9 (special
category health data) and EU AI Act high-risk system compliance.

## What this demo shows

- **Structural PII isolation** — Agent C (Clinical Analyzer) never sees
  patient identity. This is not access control — the data is
  structurally absent from the envelope. Agent C cannot access PII even
  if compromised.
- **GDPR Art. 9 compliance** — health data processed under explicit
  legal basis (`health_medicine`), with field-level anonymization,
  opaque tokens, and per-message compliance profiles.
- **EU AI Act high-risk system compliance** — Art. 13 transparency
  (explanation objects on every clinical response) and Art. 14 human
  oversight (clinician must approve before diagnosis delivery).
- **Cryptographic envelope signing** — every message is Ed25519-signed
  and verified. Agents exchange public keys at startup via JWKS
  endpoints.
- **Human oversight gate** — the pipeline halts at step 6 until a
  clinician approves or denies the diagnosis with a written
  justification. No result is delivered without human approval.
- **Complete audit trail** — 8 signed audit records per pipeline run
  with SHA-256 payload hashes, compliance profiles, and 10-year
  retention metadata.
- **Capability-based access control** — Agent C is denied access when
  asked for `pii.read` (403 Forbidden with an ARSIA error envelope).
- **LLM-powered processing** — Agents B and C use LLMs for
  anonymization and clinical analysis. Both fall back to deterministic
  results if the LLM is unavailable.
- **Real-time LLM streaming** — the dashboard shows LLM output
  token-by-token as each agent generates its response.

## Architecture

```
                     ┌─────────────────────────────────────────────────┐
                     │             Clinician Dashboard                 │
                     │                :3000 (FastAPI)                  │
                     │         SSE stream · approve/deny              │
                     └──────────────────────┬──────────────────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────────┐
                     │          Agent A — Data Collector               │
                     │             :8001 (FastAPI)                     │
                     │   Orchestrates pipeline · holds patient PII     │
                     └──────┬─────────────────────────────┬────────────┘
                            │                             │
              Envelope ②    │                             │    Envelope ④
           (full PII +      │                             │  (no PII —
            lab values)     │                             │   anonymized
                            │                             │   lab values
                            ▼                             │   + token)
              ┌─────────────────────┐                     ▼
              │ Agent B —           │       ┌─────────────────────────┐
              │ Anonymizer :8002    │       │ Agent C — Clinical      │
              │ PII stripping       │       │ Analyzer :8003          │
              │ GDPR Art. 9         │       │ Lab interpretation      │
              └────────┬────────────┘       │ EU AI Act high-risk     │
                       │                    └────────────┬────────────┘
              Envelope ③                        Envelope ⑤
          (anonymized data                  (diagnosis +
           + opaque token,                   explanation,
           NO PII)                           NO PII)
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

| Data field               | Agent A | Agent B | Agent C |
|--------------------------|:-------:|:-------:|:-------:|
| Patient name             |    Y    | strips  |    -    |
| Date of birth            |    Y    | strips  |    -    |
| Health number            |    Y    | strips  |    -    |
| Lab values               |    Y    |    Y    |    Y    |
| Anonymization token      |    Y    |    Y    |    Y    |
| Diagnosis & report       |    Y    |    -    |    Y    |
| Full audit trail         |    Y    |    -    |    -    |

Agent B receives PII only to strip it — the token it produces cannot be
reversed to recover identity. Agent C receives only the anonymized lab
values and an opaque token. The PII fields are not redacted or masked —
they are **structurally absent** from the envelope.

### Pipeline steps

| Step | What happens | Envelope | PII present? |
|------|-------------|----------|:------------:|
| 1 | Patient record arrives at Data Collector | Intake → A | Yes |
| 2 | Agent A sends PII + lab values to Agent B for anonymization | A → B | Yes |
| 3 | Agent B returns anonymized dataset with opaque token | B → A | No |
| 4 | Agent A sends anonymized lab values to Agent C for analysis | A → C | No |
| 5 | Agent C returns diagnosis + EU AI Act explanation | C → A | No |
| 6 | Human oversight gate — clinician approves/denies | A (internal) | No |
| 7 | Agent A reassociates diagnosis with patient via token | A (internal) | Yes |

## Understanding the flow

This section explains what actually happens at each step, what data each
agent sees, and why the pipeline stops where it does. For the full
protocol specification, see the
[ARSIA Protocol spec](https://github.com/arsialabs/arsia-protocol).

### The big picture

```
Patient ──[full PII]──→ Agent A ──[PII + labs]──→ Agent B (anonymize)
                          │                           │
                          │←──[anonymized + token]────┘
                          │
                          │──[anonymized labs only]──→ Agent C (analyze)
                          │                              │
                          │←──[diagnosis + explanation]──┘
                          │
                      [STOP: awaiting clinician approval]
                          │
                      [Reassociate via token · deliver report]
```

Every arrow is a signed ARSIA Protocol
[envelope](https://github.com/arsialabs/arsia-protocol/blob/main/spec/ARSIA-Core.md) —
Ed25519 signature, GDPR/EU AI Act compliance profile, 10-year retention
metadata. No shared databases, no shared memory. Agents communicate
exclusively through envelopes.

### Step by step

**Step 1 — Patient record received.**
The dashboard sends a patient record to Agent A containing full PII
(name, date of birth, health number) and clinical lab values (LDL/HDL
cholesterol, fasting glucose, hemoglobin). Agent A stores the complete
record in memory — this is the only place where the full picture exists.

**Step 2 — Sent to Agent B for anonymization.**
Agent A sends the full patient record (PII + lab values) to Agent B.
This is the only step where PII leaves Agent A, and only because Agent B
needs to see it to strip it. The envelope uses GDPR-STANDARD profile
with `legal_basis: health_medicine` (Art. 9).

**Step 3 — Anonymized data received.**
Agent B strips all PII fields (patient_name, date_of_birth,
health_number), generates an opaque anonymization token, and returns
only the lab values and token. The LLM performs the anonymization with a
deterministic fallback that strips known fields by name. A post-LLM PII
leak check verifies no patient data leaked into the output.

**Step 4 — Sent to Agent C for clinical analysis.**
Agent A constructs a **new** envelope for Agent C containing only the
anonymization token and lab values. Patient identity fields are not
redacted — they are simply never included. Agent C receives
`pii_involved: false` in the compliance metadata. This is structural
isolation by construction.

**Step 5 — Diagnosis received.**
Agent C interprets the lab values against standard reference ranges
(ATP III for lipids, ADA 2024 for glucose, WHO for hemoglobin) and
returns a diagnosis with risk level, confidence score, per-test
findings, recommendations, and an EU AI Act Art. 13 explanation object
listing the model, reasoning, and inputs used.

**Step 6 — Human oversight gate.**
Agent A creates a `pending_approval` envelope under the
EU-AI-ACT-HIGH-RISK profile. The pipeline **halts**. The dashboard
displays the diagnosis summary (risk level, confidence, findings count)
and a countdown timer (1 hour expiry). The clinician must type a
justification and click Approve or Deny. Nothing proceeds without human
decision.

**Step 7 — Reassociation and delivery.**
On approval, Agent A reassociates the diagnosis with the patient's
identity using the anonymization token. An LLM formats the final
clinical report (with deterministic fallback). The result is signed,
audited, and the pipeline completes.

### If approval is denied

When the clinician denies the diagnosis, Agent A builds an oversight
denial error envelope with the approver ID and reason, records it in the
audit trail, and terminates the pipeline. Step 7 never executes.

### Capability denial demo

The demo includes a capability denial scenario that proves Agent C
cannot access PII even if asked.

During the pipeline run, Agent A sends an additional request to Agent C
asking for `pii.read` — a capability Agent C does not have. Agent C
responds with a 403 Forbidden and an ARSIA error envelope listing the
required vs. provided capabilities.

## Prerequisites

- **Python 3.12+**
- **Ollama** installed and running with the `gemma4:e2b` model
  (optional — agents fall back to deterministic responses)
- **arsia-protocol SDK** installed in development mode

## Quick start

### 1. Install dependencies

```bash
# From the repo root:
cd python && pip install -e ".[dev]"
cd ../demos/healthcare-pipeline && pip install -r requirements.txt
```

### 2. Pull Ollama model (optional)

```bash
ollama pull gemma4:e2b
```

Skip this step to run without LLM — agents use deterministic fallback
responses automatically.

### 3. Run

```bash
cd demos/healthcare-pipeline
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
# Terminal 1 — Agent B (Anonymizer)
cd demos/healthcare-pipeline
python -m uvicorn agents.anonymizer:app --host 127.0.0.1 --port 8002

# Terminal 2 — Agent C (Clinical Analyzer)
cd demos/healthcare-pipeline
python -m uvicorn agents.clinical_analyzer:app --host 127.0.0.1 --port 8003

# Terminal 3 — Agent A (Data Collector)
cd demos/healthcare-pipeline
python -m uvicorn agents.data_collector:app --host 127.0.0.1 --port 8001

# Terminal 4 — Dashboard
cd demos/healthcare-pipeline
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 3000
```

</details>

### 4. Open the dashboard

Navigate to **http://localhost:3000** in your browser.

## Demo walkthrough

### Starting the pipeline

1. Open **http://localhost:3000**.
2. The SSE connection indicator (top-right) should show **Connected**.
3. Click **Start Pipeline**. The demo sends a pre-filled patient record:
   - Patient: Maria Silva
   - Lab values: LDL/HDL cholesterol, fasting glucose, hemoglobin

Subsequent runs cycle through five built-in patient profiles.

### Watching the pipeline progress

- **Steps 1-5** execute automatically (~10-15s with `gemma4:e2b`,
  instant with fallback).
- The **Pipeline Status** bar shows each step lighting up in sequence.
- The **PII Isolation** grid highlights which agent is active and what
  data it can see at each step.
- The **LLM Processing** panel appears during steps 2-3 and 4-5,
  showing Agent B's anonymization and Agent C's analysis being generated
  token-by-token in real time.
- At step 3, the **Anonymization Result** panel appears with the
  stripped fields, opaque token, lab values, and PII leak check status.
- At step 5, the **Clinical Diagnosis** panel appears with risk level,
  confidence score, findings, recommendations, and the EU AI Act
  explanation.

### Approving or denying

- At step 6, the pipeline **stops** and waits for clinician approval.
- The **Human Oversight** panel shows a summary (risk level, confidence,
  findings count) and a countdown timer.
- Type a justification in the text field (required).
- Click **Approve Diagnosis** (green) or **Deny Diagnosis** (red).
- On approval: step 7 executes automatically. The **Final Clinical
  Report** appears with patient identity reassociated via the
  anonymization token.
- On denial: the pipeline terminates and the denial is recorded.

### Inspecting the audit trail

- The **Audit Trail** table populates progressively as steps complete.
- Click any row to expand it and see: record ID, message ID, payload
  hash (SHA-256), correlation ID, compliance profile, legal basis,
  retention period, data residency.
- After completion, you should see 8 audit records (one per pipeline
  step plus oversight events).

### Inspecting envelopes

- The **Envelope Inspector** shows the raw ARSIA envelope at each step.
- Click a step header to expand and see the full JSON.
- Step 2 shows a **PII present** note — Agent B needs PII to anonymize.
- Step 4 shows a **data isolation** note — PII fields are structurally
  absent from the envelope sent to Agent C.

### Triggering capability denial

Click **Demo: PII Access Denial** in the dashboard, or trigger with:

```bash
curl -X POST http://localhost:8001/trigger?demo_denial=true \
  -H "Content-Type: application/json" -d '{}'
```

Agent A sends an additional request to Agent C asking for `pii.read`.
Agent C responds with 403 Forbidden and an ARSIA error envelope.

## Running with Docker

```bash
cd demos/healthcare-pipeline
docker compose up --build
```

The first startup will pull Ollama images (~4 GB) and may take several
minutes.

### Pull models into Ollama containers

After the Ollama services are healthy, pull the model into each
container:

```bash
docker compose exec ollama-a ollama pull gemma4:e2b
docker compose exec ollama-b ollama pull gemma4:e2b
docker compose exec ollama-c ollama pull gemma4:e2b
```

Or point all agents at one Ollama by setting the environment overrides
in a `.env` file (see Configuration below).

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

### Using custom patient data

POST a patient record directly to the trigger endpoint:

```bash
curl -X POST http://localhost:3000/api/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "patient_name": "Custom Patient",
    "date_of_birth": "1995-06-15",
    "health_number": "PT-SNS-111222333",
    "lab_values": {
      "ldl_cholesterol": 200,
      "hdl_cholesterol": 35,
      "fasting_glucose": 130,
      "hemoglobin": 14.0
    }
  }'
```

### Using a different LLM provider

The agents use Ollama's OpenAI-compatible endpoint
(`/v1/chat/completions`). Any provider with the same API works —
set the Ollama URL to your provider's base URL:

```bash
AGENT_B_OLLAMA_URL=http://your-openai-compatible-api:8080 ./run.sh
```

## Compliance

### GDPR-STANDARD with Art. 9 overrides (steps 1-3, 7)

Used for messages involving patient health data (special category under
GDPR Art. 9). Applied with:

```json
{
  "profile": "GDPR-STANDARD",
  "pii_involved": true,
  "legal_basis": "health_medicine",
  "audit_required": true,
  "retention_days": 3650,
  "data_residency": "EU"
}
```

- `legal_basis: health_medicine` — GDPR Art. 9(2)(h): processing for
  health or social care purposes.
- `retention_days: 3650` — 10-year retention for clinical records.
- `data_residency: EU` — data must remain in the European Union.

### EU-AI-ACT-HIGH-RISK (steps 5-6)

Used for the clinical analysis response and the oversight gate. Applied
with:

```json
{
  "profile": "EU-AI-ACT-HIGH-RISK",
  "ai_system_classification": "high-risk",
  "audit_required": true
}
```

- Classified as high-risk under EU AI Act Annex III (health/medical).
- Requires Art. 13 transparency (explanation object) and Art. 14 human
  oversight (pending approval before delivery).

### Per-message overrides

Each envelope carries its own compliance block rather than inheriting
from a global configuration. This follows the spec's priority chain
(§4.3.7): per-message overrides take precedence over profile defaults.
The anonymized A → C envelope explicitly sets `pii_involved: false`
even though the surrounding pipeline handles PII.

### What a regulator can verify

**Audit trail (8 records per completed pipeline):**

| # | Event type | From → To | What it proves |
|---|-----------|-----------|----------------|
| 1 | `request` | intake → A | Patient data received with legal basis |
| 2 | `request` | A → B | Anonymization requested under GDPR Art. 9 |
| 3 | `response` | B → A | Anonymized result returned (PII stripped) |
| 4 | `request` | A → C | Analysis requested — `pii_involved: false` |
| 5 | `response` | C → A | Diagnosis with explanation (EU AI Act Art. 13) |
| 6 | `pending_approval` | A → clinician | Human oversight gate created (Art. 14) |
| 7 | `approval_decision` | clinician → A | Clinician approved/denied with reason |
| 8 | `response` | A → intake | Final report with reassociated identity |

Each record includes: SHA-256 payload hash, correlation ID, compliance
profile, legal basis, retention period, data residency, and processing
timestamp.

**GDPR compliance points:**

- **Art. 5 (principles)** — purpose limitation (each agent processes
  only what it needs), data minimization (PII structurally absent from
  Agent C), storage limitation (10-year retention set per-record).
- **Art. 6 (lawfulness)** — legal basis recorded on every envelope.
- **Art. 9 (special categories)** — health data processed under
  Art. 9(2)(h) with explicit `legal_basis: health_medicine`.
- **Art. 30 (records of processing)** — complete audit trail with
  payload hashes, correlation IDs, and retention metadata.

**EU AI Act compliance points:**

- **Art. 13 (transparency)** — Agent C attaches an explanation object
  to every clinical response: model used, clinical reasoning, confidence
  score, and inputs considered.
- **Art. 14 (human oversight)** — pipeline halts for clinician approval
  with expiry timer. Decision recorded with approver ID and written
  justification.

## The ARSIA Protocol in action

This demo builds on the **ARSIA Protocol SDK** — the open-source
reference implementation of the ARSIA Protocol specification.

**What the SDK provides** (used in this demo):
- Envelope construction (`create_request`, `create_response`,
  `create_pending_approval`, `create_approval_decision`)
- Ed25519 signing and verification (`sign_message`, `verify_message`)
- Compliance profile application (`apply_profile` — GDPR-STANDARD,
  EU-AI-ACT-HIGH-RISK)
- Audit record building (`build_audit_record`)
- Capability matching (`match_capabilities`)
- Correlation and explainability validation

**What this demo builds** (not in the SDK):
- Agent logic (LLM integration, PII anonymization, clinical analysis)
- HTTP transport (FastAPI endpoints, envelope delivery)
- Dashboard (SSE, clinician approval UI, audit viewer)
- Key exchange (runtime public key distribution)

The SDK is transport-agnostic — it builds and validates envelopes. This
demo adds HTTP transport, but the same envelopes could travel over
WebSocket, gRPC, message queues, or any other transport.

## Project structure

```
demos/healthcare-pipeline/
├── agents/
│   ├── __init__.py               # Package marker
│   ├── data_collector.py         # Agent A — pipeline orchestrator (holds PII)
│   ├── anonymizer.py             # Agent B — PII stripping with leak detection
│   └── clinical_analyzer.py      # Agent C — LLM lab interpretation (no PII)
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

The default timeout is 120 seconds for LLM calls (360 seconds for
pipeline-level requests to agents). If the LLM is slow, agents
automatically fall back to deterministic responses and log a warning:

```
[warn] LLM call failed (ReadTimeout), using fallback result
```

The fallback produces clinically accurate results based on hardcoded
reference ranges — the pipeline completes successfully either way.

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
