#!/bin/bash
# ============================================================
# Install n8n as systemd service (auto-start on boot)
# Run with: sudo ./setup-autostart.sh
# ============================================================

if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo: sudo ./setup-autostart.sh"
  exit 1
fi

ENV_FILE="/home/pavan/security-pipeline/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: No .env file. Run ./configure.sh first."
  exit 1
fi

echo "Installing n8n systemd service..."

cp /home/pavan/security-pipeline/n8n.service /etc/systemd/system/n8n.service

systemctl daemon-reload
systemctl enable n8n
systemctl start n8n

echo ""
echo "======================================================"
echo "  n8n auto-start installed!"
echo "======================================================"
echo ""
echo "Status: $(systemctl is-active n8n)"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status n8n     → check status"
echo "  sudo systemctl stop n8n       → stop n8n"
echo "  sudo systemctl restart n8n    → restart n8n"
echo "  tail -f /home/pavan/.n8n/n8n.log → view logs"
echo ""
echo "n8n dashboard: http://localhost:5678"
echo ""
