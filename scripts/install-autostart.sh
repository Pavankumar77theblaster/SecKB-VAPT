#!/bin/bash
# Run this once: bash install-autostart.sh
# It will ask for your sudo password ONE TIME

echo ""
echo "Installing auto-start services (needs your password)..."
echo ""

sudo cp /home/pavan/security-pipeline/systemd/n8n.service /etc/systemd/system/n8n.service
sudo cp /home/pavan/security-pipeline/systemd/security-kb.service /etc/systemd/system/security-kb.service
sudo systemctl daemon-reload
sudo systemctl enable n8n security-kb
sudo systemctl start n8n security-kb

echo ""
echo "Done! Checking status..."
echo ""
sudo systemctl status n8n --no-pager -l | head -6
echo "---"
sudo systemctl status security-kb --no-pager -l | head -6
echo ""
echo "Both services now auto-start on every boot."
echo "Dashboard: http://localhost:3000"
echo "n8n:       http://localhost:5678"
