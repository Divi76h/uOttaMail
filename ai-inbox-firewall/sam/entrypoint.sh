#!/bin/sh
set -eu

echo "[SAM] Booting..."

# Prefer absolute path to avoid PATH issues
SAM_CLI="/opt/venv/bin/solace-agent-mesh"
if [ ! -x "$SAM_CLI" ]; then
  SAM_CLI="$(command -v solace-agent-mesh 2>/dev/null || true)"
fi
if [ -z "${SAM_CLI:-}" ]; then
  SAM_CLI="$(command -v sam 2>/dev/null || true)"
fi
if [ -z "${SAM_CLI:-}" ]; then
  echo "[SAM] ERROR: Could not find the SAM CLI (sam / solace-agent-mesh) in the container."
  echo "[SAM] Debug: contents of /opt/venv/bin:"
  ls -la /opt/venv/bin || true
  echo "[SAM] Debug: PATH=$PATH"
  exit 1
fi

echo "[SAM] Using CLI: $SAM_CLI"

# Optional: show version
"$SAM_CLI" --version || true

# Install the Event Mesh Gateway plugin (idempotent; safe to run on every start)
# The docs install this via "sam plugin add ... --plugin sam-event-mesh-gateway"
# so we do the same at container startup.
if python -c "import sam_event_mesh_gateway" >/dev/null 2>&1; then
  echo "[SAM] sam_event_mesh_gateway already installed, skipping plugin add."
else
  echo "[SAM] Installing Event Mesh Gateway plugin..."
  "$SAM_CLI" plugin add _inbox_event_mesh_gateway --plugin sam-event-mesh-gateway
fi

# Run agents + gateway configs
# Update these paths if your configs differ.
echo "[SAM] Starting SAM run..."
exec "$SAM_CLI" run \
  configs/agents/spam_agent.yaml \
  configs/agents/priority_agent.yaml \
  configs/agents/summary_agent.yaml \
  configs/agents/action_items_agent.yaml \
  configs/agents/email_tone_analyzer.yaml \
  configs/agents/url-scanner.yaml \
  configs/gateways/inbox-event-mesh.yaml
