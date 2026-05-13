#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)
#
# Start the healthcare pipeline demo locally (without Docker).
# Usage: ./run.sh [--no-ollama]

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$DEMO_DIR/../../python" && pwd)"

AGENT_A_PORT="${AGENT_A_PORT:-8001}"
AGENT_B_PORT="${AGENT_B_PORT:-8002}"
AGENT_C_PORT="${AGENT_C_PORT:-8003}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"

OLLAMA_URL="${AGENT_A_OLLAMA_URL:-http://localhost:11434}"
MODEL_A="${AGENT_A_OLLAMA_MODEL:-gemma4:e2b}"
MODEL_B="${AGENT_B_OLLAMA_MODEL:-gemma4:e2b}"
MODEL_C="${AGENT_C_OLLAMA_MODEL:-gemma4:e2b}"

NO_OLLAMA=false
PIDS=()

# ── Parse arguments ───────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --no-ollama) NO_OLLAMA=true ;;
        --help|-h)
            echo "Usage: ./run.sh [--no-ollama]"
            echo ""
            echo "Starts the ARSIA healthcare pipeline demo locally."
            echo ""
            echo "Options:"
            echo "  --no-ollama   Skip Ollama checks and model pulls."
            echo "                Agents will use deterministic fallback responses."
            echo ""
            echo "Environment variables: see .env.example"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: ./run.sh [--no-ollama]"
            exit 1
            ;;
    esac
done

# ── Cleanup handler ───────────────────────────────────────
cleanup() {
    echo ""
    echo "Shutting down..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "All services stopped."
}
trap cleanup EXIT INT TERM

# ── Colour helpers ────────────────────────────────────────
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' CYAN='' BOLD='' NC=''
fi

info()  { echo -e "${CYAN}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail()  { echo -e "${RED}[fail]${NC}  $*"; }

# ── Prerequisites ─────────────────────────────────────────
info "Checking prerequisites..."

# Python 3.12+
if ! command -v python3 &>/dev/null; then
    fail "python3 not found. Install Python 3.12+."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 12 ]; }; then
    fail "Python 3.12+ required (found $PY_VERSION)."
    exit 1
fi
ok "Python $PY_VERSION"

# arsia-protocol SDK
if ! python3 -c "import arsia_protocol" 2>/dev/null; then
    fail "arsia-protocol SDK not installed."
    echo "  Run: cd $SDK_DIR && pip install -e '.[dev]'"
    exit 1
fi
ok "arsia-protocol SDK installed"

# uvicorn
if ! python3 -c "import uvicorn" 2>/dev/null; then
    fail "uvicorn not installed. Run: pip install -r $DEMO_DIR/requirements.txt"
    exit 1
fi
ok "uvicorn installed"

# Ollama (unless --no-ollama)
if [ "$NO_OLLAMA" = false ]; then
    if ! command -v ollama &>/dev/null; then
        warn "ollama command not found. Install from https://ollama.com"
        warn "Continuing anyway — agents will use deterministic fallbacks if Ollama is unreachable."
    else
        ok "ollama installed"

        # Check Ollama is running
        if curl -sf "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
            ok "Ollama reachable at $OLLAMA_URL"

            # Pull models if missing
            for model in "$MODEL_A" "$MODEL_B" "$MODEL_C"; do
                if ollama list 2>/dev/null | grep -q "^${model}"; then
                    ok "Model $model available"
                else
                    info "Pulling model $model (this may take a while)..."
                    if ollama pull "$model" 2>/dev/null; then
                        ok "Model $model pulled"
                    else
                        warn "Failed to pull $model — agent will use fallback"
                    fi
                fi
            done
        else
            warn "Ollama not running at $OLLAMA_URL"
            warn "Start it with: ollama serve"
            warn "Continuing — agents will use deterministic fallbacks."
        fi
    fi
else
    info "Skipping Ollama checks (--no-ollama)"
fi

echo ""

# ── Point all agents at one Ollama for local mode ─────────
# In local mode, there's typically one Ollama instance on :11434.
export AGENT_A_OLLAMA_URL="${AGENT_A_OLLAMA_URL:-$OLLAMA_URL}"
export AGENT_B_OLLAMA_URL="${AGENT_B_OLLAMA_URL:-$OLLAMA_URL}"
export AGENT_C_OLLAMA_URL="${AGENT_C_OLLAMA_URL:-$OLLAMA_URL}"

export AGENT_A_PORT AGENT_B_PORT AGENT_C_PORT DASHBOARD_PORT
export PEER_B_URL="http://localhost:$AGENT_B_PORT"
export PEER_C_URL="http://localhost:$AGENT_C_PORT"
export PEER_A_URL="http://localhost:$AGENT_A_PORT"
export DASHBOARD_AGENT_A_URL="http://localhost:$AGENT_A_PORT"

# ── Start services ────────────────────────────────────────
cd "$DEMO_DIR"

info "Starting Agent B (Anonymizer) on port $AGENT_B_PORT..."
python3 -m uvicorn agents.anonymizer:app \
    --host 127.0.0.1 --port "$AGENT_B_PORT" \
    --log-level info &
PIDS+=($!)

info "Starting Agent C (Clinical Analyzer) on port $AGENT_C_PORT..."
python3 -m uvicorn agents.clinical_analyzer:app \
    --host 127.0.0.1 --port "$AGENT_C_PORT" \
    --log-level info &
PIDS+=($!)

info "Starting Agent A (Data Collector) on port $AGENT_A_PORT..."
python3 -m uvicorn agents.data_collector:app \
    --host 127.0.0.1 --port "$AGENT_A_PORT" \
    --log-level info &
PIDS+=($!)

info "Starting Dashboard on port $DASHBOARD_PORT..."
python3 -m uvicorn dashboard.app:app \
    --host 127.0.0.1 --port "$DASHBOARD_PORT" \
    --log-level info &
PIDS+=($!)

# ── Wait for health ───────────────────────────────────────
info "Waiting for services to become healthy..."

wait_healthy() {
    local name="$1" url="$2" max_wait=60 elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        if curl -sf "$url/health" >/dev/null 2>&1; then
            ok "$name healthy"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    fail "$name did not become healthy within ${max_wait}s"
    return 1
}

# Agent B and C start first (no peer dependencies except A)
wait_healthy "Agent B" "http://localhost:$AGENT_B_PORT"
wait_healthy "Agent C" "http://localhost:$AGENT_C_PORT"
wait_healthy "Agent A" "http://localhost:$AGENT_A_PORT"
wait_healthy "Dashboard" "http://localhost:$DASHBOARD_PORT"

echo ""
echo -e "${BOLD}${GREEN}All services running.${NC}"
echo ""
echo -e "  Dashboard:  ${BOLD}http://localhost:$DASHBOARD_PORT${NC}"
echo -e "  Agent A:    http://localhost:$AGENT_A_PORT"
echo -e "  Agent B:    http://localhost:$AGENT_B_PORT"
echo -e "  Agent C:    http://localhost:$AGENT_C_PORT"
echo ""
echo "Press Ctrl+C to stop all services."
echo ""

# ── Keep alive ────────────────────────────────────────────
wait
