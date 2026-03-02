#!/bin/bash
# ============================================================
# Import workflow into n8n via API
# ============================================================

PIPELINE_DIR="/home/pavan/security-pipeline"
ENV_FILE="$PIPELINE_DIR/.env"
WORKFLOW_FILE="$PIPELINE_DIR/workflow.json"
N8N_URL="http://localhost:5678"

# Load env vars
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: No .env file found. Run ./configure.sh first."
  exit 1
fi
source "$ENV_FILE"

echo ""
echo "======================================================"
echo "  Importing Workflow into n8n"
echo "======================================================"
echo ""

# Check if n8n is running
if ! curl -s "$N8N_URL/healthz" > /dev/null 2>&1; then
  echo "n8n is not running. Starting it now..."
  nohup n8n start > /home/pavan/.n8n/n8n.log 2>&1 &
  echo "Waiting 15 seconds for n8n to start..."
  sleep 15

  if ! curl -s "$N8N_URL/healthz" > /dev/null 2>&1; then
    echo "ERROR: n8n failed to start. Check: tail -f /home/pavan/.n8n/n8n.log"
    exit 1
  fi
fi

echo "n8n is running at $N8N_URL"
echo ""

# Try to import via n8n API (n8n v1 API)
echo "Importing workflow..."
RESPONSE=$(curl -s -X POST \
  "$N8N_URL/api/v1/workflows" \
  -H "Content-Type: application/json" \
  -H "X-N8N-API-KEY: $(grep -r 'apiKey' /home/pavan/.n8n/config 2>/dev/null | head -1 | awk -F'"' '{print $4}' || echo '')" \
  -d @"$WORKFLOW_FILE" 2>/dev/null)

if echo "$RESPONSE" | grep -q '"id"'; then
  WORKFLOW_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','unknown'))" 2>/dev/null)
  echo "SUCCESS: Workflow imported with ID: $WORKFLOW_ID"
  echo ""
  echo "Open n8n at: $N8N_URL"
  echo "1. Find 'Medium Security Knowledge Pipeline' workflow"
  echo "2. Set your environment variables in n8n Settings → Environment Variables:"
  echo "   GEMINI_API_KEY  = $GEMINI_API_KEY"
  echo "   GROQ_API_KEY    = $GROQ_API_KEY"
  echo "   NOTION_TOKEN    = $NOTION_TOKEN"
  echo "   NOTION_DATABASE_ID = $NOTION_DATABASE_ID"
  echo "3. Click Activate (toggle top-right)"
else
  echo "Auto-import failed (n8n may require manual login first)."
  echo ""
  echo "MANUAL IMPORT (takes 30 seconds):"
  echo "  1. Open http://localhost:5678 in your browser"
  echo "  2. Click the hamburger menu (≡) → Import workflow"
  echo "  3. Select: $WORKFLOW_FILE"
  echo "  4. Then set these environment variables in Settings → Environment Variables:"
  echo ""
  echo "     GEMINI_API_KEY     = $GEMINI_API_KEY"
  echo "     GROQ_API_KEY       = $GROQ_API_KEY"
  echo "     NOTION_TOKEN       = $NOTION_TOKEN"
  echo "     NOTION_DATABASE_ID = $NOTION_DATABASE_ID"
  echo ""
  echo "  5. Click Save → Activate the workflow"
fi

echo ""
echo "======================================================"
echo "  Notion Database Setup Reminder"
echo "======================================================"
echo ""
echo "Make sure your Notion database has these EXACT property names:"
echo "  - Title (Title type)"
echo "  - Category (Select)"
echo "  - Vulnerability Type (Select)"
echo "  - Severity (Select)"
echo "  - Root Cause (Rich Text)"
echo "  - Exploitation Method (Rich Text)"
echo "  - Tools Used (Multi-select)"
echo "  - Source URL (URL)"
echo "  - Date Added (Date)"
echo "  - Chaining Potential (Rich Text)"
echo "  - Status (Select) with options: New, Reviewed, Practiced, Mastered"
echo ""
echo "And connect your Notion integration to the database:"
echo "  Open database page → ••• → Connections → Add your integration"
echo ""
