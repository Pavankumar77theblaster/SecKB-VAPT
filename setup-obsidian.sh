#!/bin/bash
# ============================================================
# Setup Obsidian SecurityKB Vault
# ============================================================

VAULT="/home/pavan/SecurityKB"

echo "Creating SecurityKB Obsidian vault at $VAULT ..."

# Create main vault and category folders
mkdir -p "$VAULT"/{Bug-Bounty,Web-Exploitation,API-Security,Red-Teaming,Cloud-Security,Authentication,Injection,SSRF,XSS,IDOR,Misc}
mkdir -p "$VAULT/.obsidian/plugins/dataview"

# Obsidian app config
cat > "$VAULT/.obsidian/app.json" << 'EOF'
{
  "defaultViewMode": "source",
  "foldHeading": false,
  "showLineNumber": true
}
EOF

# Enable community plugins (Dataview)
cat > "$VAULT/.obsidian/community-plugins.json" << 'EOF'
["dataview"]
EOF

# Dataview plugin config
cat > "$VAULT/.obsidian/plugins/dataview/data.json" << 'EOF'
{
  "renderNullAs": "\\-",
  "taskCompletionTracking": false,
  "warnOnMissingFrontmatter": false,
  "inlineQueryPrefix": "=",
  "dataviewJsPrefix": "dataviewjs",
  "enableDataviewJs": true,
  "enableInlineDataview": true,
  "enableInlineDataviewJs": true,
  "prettyRenderInlineFields": true
}
EOF

# Obsidian hotkeys config
cat > "$VAULT/.obsidian/hotkeys.json" << 'EOF'
{}
EOF

# Create the master dashboard note
cat > "$VAULT/🛡️ Security KB Dashboard.md" << 'DASHBOARD'
---
title: Security Knowledge Base Dashboard
---

# 🛡️ Security Knowledge Base

> Auto-populated from Medium via n8n + Gemini + Groq pipeline

---

## 📊 All Articles — Quick Overview

```dataview
TABLE category, vulnerability_type, severity, quality_score, status, date_added
FROM ""
WHERE title != "Security Knowledge Base Dashboard"
SORT quality_score DESC, date_added DESC
```

---

## 🔥 Critical Articles — Unreviewed

```dataview
TABLE title, vulnerability_type, tools, source
FROM ""
WHERE severity = "Critical" AND status = "new"
SORT date_added DESC
```

---

## 🎯 High Severity — Unreviewed

```dataview
TABLE title, category, vulnerability_type, quality_score
FROM ""
WHERE severity = "High" AND status = "new"
SORT quality_score DESC
```

---

## 📂 By Category

### SSRF
```dataview
LIST title
FROM ""
WHERE category = "SSRF" OR vulnerability_type = "SSRF"
SORT quality_score DESC
```

### XSS
```dataview
LIST title
FROM ""
WHERE category = "XSS" OR vulnerability_type = "XSS"
SORT quality_score DESC
```

### Authentication / Auth Bypass
```dataview
LIST title
FROM ""
WHERE category = "Authentication" OR vulnerability_type = "Auth Bypass"
SORT quality_score DESC
```

### Bug Bounty Reports
```dataview
TABLE title, severity, quality_score, date_added
FROM "Bug-Bounty"
SORT quality_score DESC
```

---

## 🏆 Top Scoring Articles (9-10)

```dataview
TABLE title, category, vulnerability_type, severity, quality_score
FROM ""
WHERE quality_score >= 9
SORT quality_score DESC
```

---

## 📅 This Week's Additions

```dataview
TABLE title, category, severity, quality_score
FROM ""
WHERE date_added >= date(today) - dur(7 days)
SORT date_added DESC
```
DASHBOARD

echo ""
echo "======================================================"
echo "  Obsidian Vault Created: $VAULT"
echo "======================================================"
echo ""
echo "Folder structure:"
ls "$VAULT"
echo ""
echo "Next steps:"
echo "  1. Download Obsidian → https://obsidian.md"
echo "  2. Open Obsidian → Open folder as vault → select $VAULT"
echo "  3. Go to Settings → Community Plugins → install 'Dataview'"
echo "  4. Open '🛡️ Security KB Dashboard' — it shows all articles"
echo "     automatically as n8n adds them"
echo ""
echo "On Kali you can install Obsidian with:"
echo "  snap install obsidian  OR"
echo "  flatpak install flathub md.obsidian.Obsidian  OR"
echo "  Download AppImage from https://obsidian.md/download"
echo ""
