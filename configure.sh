#!/bin/bash
# ============================================================
# Security Pipeline - API Keys Configuration Script
# Run this ONCE to set your API keys
# ============================================================

set -e

PIPELINE_DIR="/home/pavan/security-pipeline"
ENV_FILE="$PIPELINE_DIR/.env"

echo ""
echo "======================================================"
echo "  Security Knowledge Pipeline - API Key Setup"
echo "======================================================"
echo ""
echo "You need 3 things:"
echo "  1. Gemini API Key  → https://aistudio.google.com/apikey (FREE)"
echo "  2. Groq API Key    → https://console.groq.com (FREE)"
echo "  3. Notion Token    → https://www.notion.so/my-integrations"
echo "  4. Notion DB ID    → from your Notion database URL"
echo ""
echo "------------------------------------------------------"

# Gemini API Key
read -p "Paste your GEMINI API Key: " GEMINI_KEY
if [ -z "$GEMINI_KEY" ]; then
  echo "ERROR: Gemini API key cannot be empty"
  exit 1
fi

# Groq API Key
read -p "Paste your GROQ API Key: " GROQ_KEY
if [ -z "$GROQ_KEY" ]; then
  echo "ERROR: Groq API key cannot be empty"
  exit 1
fi

# Notion Token
read -p "Paste your Notion Integration Token (secret_...): " NOTION_TOKEN
if [ -z "$NOTION_TOKEN" ]; then
  echo "ERROR: Notion token cannot be empty"
  exit 1
fi

echo ""
echo "------------------------------------------------------"
echo "Notion Database ID:"
echo "  Open your 'Security Knowledge Base — Auto' database in Notion"
echo "  Copy the URL - it looks like:"
echo "  https://www.notion.so/YOUR-DB-NAME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
echo "  The ID is the last 32 characters (with hyphens added automatically)"
echo ""
read -p "Paste your Notion Database ID: " NOTION_DB_ID
if [ -z "$NOTION_DB_ID" ]; then
  echo "ERROR: Notion database ID cannot be empty"
  exit 1
fi

# Format DB ID: remove hyphens and reformat as UUID if needed
NOTION_DB_ID_CLEAN=$(echo "$NOTION_DB_ID" | tr -d '-' | sed 's/.\{8\}/&-/' | sed 's/.\{13\}/&-/' | sed 's/.\{18\}/&-/' | sed 's/.\{23\}/&-/' | sed 's/-$//' 2>/dev/null || echo "$NOTION_DB_ID")

# Write environment file
cat > "$ENV_FILE" << ENVEOF
# Security Pipeline Environment Variables
# DO NOT share this file

GEMINI_API_KEY=$GEMINI_KEY
GROQ_API_KEY=$GROQ_KEY
NOTION_TOKEN=$NOTION_TOKEN
NOTION_DATABASE_ID=$NOTION_DB_ID
ENVEOF

chmod 600 "$ENV_FILE"

echo ""
echo "======================================================"
echo "  Configuration saved to: $ENV_FILE"
echo "======================================================"
echo ""
echo "Next step: Run ./import-workflow.sh to load the workflow into n8n"
echo ""
