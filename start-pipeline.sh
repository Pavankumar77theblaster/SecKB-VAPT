#!/bin/bash
# ============================================================
# Start the Security Pipeline
# ============================================================

ENV_FILE="/home/pavan/security-pipeline/.env"

echo ""
echo "======================================================"
echo "  Starting Security Knowledge Pipeline"
echo "======================================================"
echo ""

# Load env vars
if [ -f "$ENV_FILE" ]; then
  export $(grep -v '^#' "$ENV_FILE" | grep -v '^$' | xargs)
  echo "✓ API keys loaded"
else
  echo "ERROR: No .env file. Run configure.sh first."
  exit 1
fi

# Check keys
[ -z "$GEMINI_API_KEY" ] && echo "WARNING: GEMINI_API_KEY not set"
[ -z "$GROQ_API_KEY" ] && echo "WARNING: GROQ_API_KEY not set"

# Check Obsidian vault
VAULT="${OBSIDIAN_VAULT:-/home/pavan/SecurityKB}"
if [ ! -d "$VAULT" ]; then
  echo "Creating Obsidian vault..."
  bash /home/pavan/security-pipeline/setup-obsidian.sh > /dev/null
fi
echo "✓ Obsidian vault: $VAULT"

# Check Google service account
if [ -f "/home/pavan/security-pipeline/google-sa.json" ]; then
  echo "✓ Google Sheets: service account found"
else
  echo "ℹ Google Sheets: no service account (Obsidian-only mode)"
fi

echo ""
echo "Starting n8n at http://localhost:5678 ..."
echo "Import workflow: /home/pavan/security-pipeline/workflow-sheets-obsidian.json"
echo ""
echo "After n8n opens:"
echo "  1. Click ≡ menu → Import workflow"
echo "  2. Select workflow-sheets-obsidian.json"
echo "  3. Click Activate (toggle top-right)"
echo "  4. Done — pipeline runs every 6 hours automatically"
echo ""

exec n8n start
