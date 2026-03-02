#!/bin/bash
# ============================================================
# Start n8n with environment variables loaded
# ============================================================

ENV_FILE="/home/pavan/security-pipeline/.env"

if [ -f "$ENV_FILE" ]; then
  export $(grep -v '^#' "$ENV_FILE" | xargs)
  echo "Loaded API keys from .env"
fi

echo "Starting n8n at http://localhost:5678 ..."
exec n8n start
