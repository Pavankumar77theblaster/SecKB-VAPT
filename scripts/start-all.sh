#!/bin/bash
# ============================================================
# START EVERYTHING — Run this whenever you want to start the pipeline
# Or just run: bash ~/security-pipeline/scripts/start-all.sh
# ============================================================

ENV=/home/pavan/security-pipeline/.env
LOG=/home/pavan/security-pipeline/logs

mkdir -p $LOG

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     Security KB Pipeline — Starting Up          ║"
echo "╚══════════════════════════════════════════════════╝"

# Load API keys
export $(grep -v '^#' $ENV | grep -v '^$' | xargs)
export OBSIDIAN_VAULT=/home/pavan/SecurityKB

# 1. Web Dashboard
if lsof -ti:3000 > /dev/null 2>&1; then
  echo "  ✓ Dashboard already running on :3000"
else
  cd /home/pavan/security-pipeline/webapp
  nohup node server.js >> $LOG/dashboard.log 2>&1 &
  sleep 3s
  echo "  ✓ Dashboard started → http://localhost:3000"
fi

# 2. n8n
if lsof -ti:5678 > /dev/null 2>&1; then
  echo "  ✓ n8n already running on :5678"
else
  nohup n8n start >> $LOG/n8n.log 2>&1 &
  echo "  ✓ n8n started → http://localhost:5678"
  echo "    (takes ~15 seconds to be ready)"
fi

echo ""
echo "  Dashboard:  http://localhost:3000"
echo "  n8n:        http://localhost:5678"
echo ""
echo "  Tailscale:  run 'tailscale ip -4' to get your remote IP"
echo "              then access: http://<ts-ip>:3000 from any device"
echo ""
echo "  IMPORTANT: Open http://localhost:5678 in browser"
echo "             → Log in → Find 'Auto Pipeline v2' workflow"
echo "             → Click ACTIVATE toggle (top right)"
echo "             → Pipeline will then run every 2 hours automatically"
echo ""
