#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)
#
# Start the healthcare pipeline demo locally (without Docker).
# Usage: ./run.sh [--llm MODE | --no-llm]

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

AGENT_A_PORT="${AGENT_A_PORT:-8001}"
AGENT_B_PORT="${AGENT_B_PORT:-8002}"
AGENT_C_PORT="${AGENT_C_PORT:-8003}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"

LLM_FLAG=""
PIDS=()

usage() {
    echo "Usage: ./run.sh [--llm MODE | --no-llm]"
    echo ""
    echo "Starts the ARSIA healthcare pipeline demo locally."
    echo ""
    echo "Options:"
    echo "  --llm MODE    The LLM for all agents: ollama (default), openai, anthropic,"
    echo "                gemini or none. Overrides DEMO_LLM."
    echo "  --no-llm      Same as --llm none: no LLM calls; agents use deterministic"
    echo "                fallback responses. --no-ollama does the same."
    echo ""
    echo "Provider modes need their API key — OPENAI_API_KEY, ANTHROPIC_API_KEY or"
    echo "GEMINI_API_KEY — in the environment or in .env. Other variables: see .env.example"
}

# ── Parse arguments ───────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --llm)
            if [ $# -lt 2 ]; then
                echo "--llm needs a mode: ollama, openai, anthropic, gemini or none"
                exit 1
            fi
            LLM_FLAG="$2"
            shift
            ;;
        --llm=*) LLM_FLAG="${1#--llm=}" ;;
        --no-llm) LLM_FLAG=none ;;
        --no-ollama)
            LLM_FLAG=none
            echo "Note: --no-ollama is now --no-llm; it works the same way."
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: ./run.sh [--llm MODE | --no-llm]"
            exit 1
            ;;
    esac
    shift
done

# ── Cleanup handler ───────────────────────────────────────
# Runs once, on exit. Ctrl+C or a termination signal ends the script (and
# with it any start-up still in progress) before the cleanup runs.
cleanup() {
    trap - EXIT INT TERM
    echo ""
    echo "Shutting down..."
    # The array may still be empty when stopped during start-up; this form
    # is safe under `set -u` on every bash version.
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "All services stopped."
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
    echo "  Run: pip install -r $DEMO_DIR/requirements.txt"
    exit 1
fi
ok "arsia-protocol SDK installed"

# uvicorn
if ! python3 -c "import uvicorn" 2>/dev/null; then
    fail "uvicorn not installed. Run: pip install -r $DEMO_DIR/requirements.txt"
    exit 1
fi
ok "uvicorn installed"

# ── LLM selection ─────────────────────────────────────────
# One LLM for the whole demo, read exactly as the agents read it: the
# environment first, then .env. A --llm flag overrides DEMO_LLM. The check
# runs before any service starts; it names a missing variable and never
# prints a value.
if [ -n "$LLM_FLAG" ]; then
    export DEMO_LLM="$LLM_FLAG"
fi
if ! LLM_INFO="$(cd "$DEMO_DIR" && python3 - <<'EOF'
import sys

from config import API_KEY_VARS, LLMConfigError, load_llm_settings

try:
    s = load_llm_settings()
except LLMConfigError as exc:
    print(exc)
    sys.exit(1)
print(s.mode)
print(s.model)
print(s.base_url if s.mode == "ollama" else "")
print(API_KEY_VARS.get(s.mode, ""))
print("yes" if s.base_url_overridden else "no")
EOF
)"; then
    fail "$LLM_INFO"
    echo "  The LLM settings are read from the environment or from .env; see .env.example."
    exit 1
fi
{ read -r LLM_MODE; read -r LLM_MODEL; read -r LLM_OLLAMA_URL; read -r LLM_KEY_VAR; read -r LLM_BASE_OVERRIDDEN; } <<< "$LLM_INFO"
export DEMO_LLM="$LLM_MODE"

# Print "local:<port>" when a URL points at this machine, or "other" when
# it does not or cannot be read. With "cli", the argument is OLLAMA_HOST,
# read the way the ollama command reads it: it is the Ollama that
# `ollama list` and `ollama pull` act on.
llm_endpoint() {
    python3 - "$1" "$2" <<'EOF'
import ipaddress
import sys
from urllib.parse import urlsplit

value, kind = sys.argv[1].strip(), sys.argv[2]
scheme, sep, rest = value.partition("://")
if not sep:
    scheme, rest = "http", value
default_port = {"http": 80, "https": 443}.get(scheme)
if kind == "cli" and not sep:
    default_port = 11434
try:
    parts = urlsplit(f"{scheme}://{rest}")
    port = parts.port or default_port
    host = (parts.hostname or "").lower()
    local = host in ("", "localhost") or ipaddress.ip_address(host).is_loopback \
        or ipaddress.ip_address(host).is_unspecified
except ValueError:
    local = False
print(f"local:{port}" if local and port else "other")
EOF
}

case "$LLM_MODE" in
    none)
        info "LLM disabled — agents use deterministic fallback responses."
        ;;
    ollama)
        info "LLM: the host's Ollama, model $LLM_MODEL"
        # The model is checked and pulled only when DEMO_OLLAMA_URL is the
        # Ollama that the ollama command acts on.
        HOST_OLLAMA="$(llm_endpoint "${OLLAMA_HOST:-}" cli)"
        if [ "$HOST_OLLAMA" = other ] || [ "$(llm_endpoint "$LLM_OLLAMA_URL" url)" != "$HOST_OLLAMA" ]; then
            info "DEMO_OLLAMA_URL is not the Ollama that the ollama command uses; the model is not checked or pulled here."
        elif ! command -v ollama &>/dev/null; then
            warn "ollama command not found. Install from https://ollama.com"
            warn "Continuing anyway — agents will use deterministic fallbacks if Ollama is unreachable."
        else
            ok "ollama installed"

            # Check Ollama is running
            if curl -sf "$LLM_OLLAMA_URL/api/tags" >/dev/null 2>&1; then
                ok "Ollama reachable at $LLM_OLLAMA_URL"

                # Pull the model if missing. Read the model list once and in
                # full: stopping early on a match closes the pipe under
                # pipefail and makes a present model look absent.
                AVAILABLE_MODELS="$(ollama list 2>/dev/null | awk 'NR > 1 { print $1 }' || true)"
                # A name without a tag means ":latest", which is how
                # `ollama list` shows it.
                model_ref="$LLM_MODEL"
                case "${LLM_MODEL##*/}" in
                    *:*) ;;
                    *) model_ref="${LLM_MODEL}:latest" ;;
                esac
                if grep -qxF -- "$model_ref" <<< "$AVAILABLE_MODELS"; then
                    ok "Model $LLM_MODEL available"
                else
                    info "Pulling model $LLM_MODEL (this may take a while)..."
                    if ollama pull "$LLM_MODEL" 2>/dev/null; then
                        ok "Model $LLM_MODEL pulled"
                    else
                        warn "Failed to pull $LLM_MODEL — agents will use fallback"
                    fi
                fi
            else
                warn "Ollama not running at $LLM_OLLAMA_URL"
                warn "Start it with: ollama serve"
                warn "Continuing — agents will use deterministic fallbacks."
            fi
        fi
        ;;
    *)
        info "LLM: $LLM_MODE, model $LLM_MODEL (API key from $LLM_KEY_VAR)"
        if [ "$LLM_BASE_OVERRIDDEN" = yes ]; then
            warn "DEMO_LLM_BASE_URL is set: $LLM_MODE requests go to that address instead of the provider (for testing only)."
        fi
        ;;
esac

echo ""

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
    echo "  Last health response: $(curl -s "$url/health" 2>/dev/null || echo "no response")"
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
