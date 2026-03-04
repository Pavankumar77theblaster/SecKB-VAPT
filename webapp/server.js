const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const fs   = require('fs');

// Load .env from project root (one level up from webapp/)
try {
  fs.readFileSync(path.join(__dirname, '../.env'), 'utf8').split('\n').forEach(l => {
    const m = l.match(/^([A-Z_]+)=(.+)$/);
    if (m) process.env[m[1]] = m[2].trim();
  });
} catch(e) {}

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'db', 'security_kb.db');

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

// WAL mode: crash-safe, allows concurrent reads, survives power-off
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS articles (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    date_added             TEXT,
    title                  TEXT NOT NULL,
    vapt_level             TEXT DEFAULT 'Medium',
    category               TEXT,
    vulnerability_type     TEXT,
    severity               TEXT,
    quality_score          INTEGER DEFAULT 0,
    tools_used             TEXT,
    source_url             TEXT UNIQUE,
    one_line_summary       TEXT,
    beginner_context       TEXT,
    what_is_it             TEXT,
    how_to_find_it         TEXT,
    root_cause             TEXT,
    exploitation_walkthrough TEXT,
    payloads_and_commands  TEXT,
    impact                 TEXT,
    chaining_opportunities TEXT,
    detection_and_hunting  TEXT,
    remediation            TEXT,
    key_takeaways          TEXT,
    difficulty_tips        TEXT,
    status                 TEXT DEFAULT 'new',
    created_at             DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_severity  ON articles(severity);
  CREATE INDEX IF NOT EXISTS idx_category  ON articles(category);
  CREATE INDEX IF NOT EXISTS idx_level     ON articles(vapt_level);
  CREATE INDEX IF NOT EXISTS idx_status    ON articles(status);
  CREATE INDEX IF NOT EXISTS idx_score     ON articles(quality_score DESC);
  CREATE INDEX IF NOT EXISTS idx_url       ON articles(source_url);
`);

// ── Migrations: safe add-column (ignores if already exists) ──────────────────
const migrations = [
  `ALTER TABLE articles ADD COLUMN vapt_level TEXT DEFAULT 'Medium'`,
  `ALTER TABLE articles ADD COLUMN beginner_context TEXT`,
  `ALTER TABLE articles ADD COLUMN what_is_it TEXT`,
  `ALTER TABLE articles ADD COLUMN how_to_find_it TEXT`,
  `ALTER TABLE articles ADD COLUMN difficulty_tips TEXT`,
  `ALTER TABLE articles ADD COLUMN mental_model TEXT`,
  `ALTER TABLE articles ADD COLUMN behavioral_indicators TEXT`,
  `ALTER TABLE articles ADD COLUMN where_to_look TEXT`,
  `ALTER TABLE articles ADD COLUMN payload_mutations TEXT`,
  `ALTER TABLE articles ADD COLUMN custom_header_guide TEXT`,
  `ALTER TABLE articles ADD COLUMN real_world_scenario TEXT`,
  `ALTER TABLE articles ADD COLUMN memory_hook TEXT`,
  `ALTER TABLE articles ADD COLUMN personal_notes TEXT`,
  `ALTER TABLE articles ADD COLUMN flashcard_status TEXT DEFAULT 'unseen'`,
  `ALTER TABLE articles ADD COLUMN lab_content TEXT`,
  `ALTER TABLE articles ADD COLUMN source_type TEXT DEFAULT 'rss'`,
  `ALTER TABLE articles ADD COLUMN image_urls TEXT DEFAULT '[]'`,
];
for (const sql of migrations) {
  try { db.exec(sql); } catch(e) { /* column already exists */ }
}

// ── Knowledge Base table ──────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS knowledge_base (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_type  TEXT NOT NULL UNIQUE,
    content    TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ── PayloadsAllTheThings cache table ─────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS patt_cache (
    vuln_type  TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

const PATT_MAP = {
  'XSS':                'XSS Injection',
  'SQLi':               'SQL Injection',
  'SSRF':               'Server Side Request Forgery',
  'Command Injection':  'Command Injection',
  'Path Traversal':     'Directory Traversal',
  'CSRF':               'Cross-Site Request Forgery',
  'IDOR':               'Insecure Direct Object References',
  'JWT Attack':         'JSON Web Token',
  'SSTI':               'Server Side Template Injection',
  'XXE':                'XXE Injection',
  'Open Redirect':      'Open Redirect',
  'File Upload':        'Upload Insecure Files',
  'Prototype Pollution':'Prototype Pollution',
  'Deserialization':    'Insecure Deserialization',
  'GraphQL':            'GraphQL Injection',
  'Business Logic':     'Business Logic Errors',
  'Race Condition':     'Race Condition',
  'CORS':               'CORS Misconfiguration',
  'Mass Assignment':    'Mass Assignment',
};

// ── API: Check URL (dedup) ────────────────────────────────────────────────────
app.get('/api/check-url', (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ exists: false });
  const row = db.prepare('SELECT id FROM articles WHERE source_url = ?').get(url);
  res.json({ exists: !!row });
});

// ── API: Add Article (called by n8n) ─────────────────────────────────────────
app.post('/api/articles', (req, res) => {
  const d = req.body;
  if (!d.title) return res.status(400).json({ error: 'title required' });

  if (d.source_url) {
    const existing = db.prepare('SELECT id FROM articles WHERE source_url = ?').get(d.source_url);
    if (existing) return res.json({ status: 'duplicate', id: existing.id });
  }

  const insert = db.prepare(`
    INSERT INTO articles (
      date_added, title, vapt_level, category, vulnerability_type, severity,
      quality_score, tools_used, source_url, one_line_summary, beginner_context,
      what_is_it, how_to_find_it, root_cause, exploitation_walkthrough,
      payloads_and_commands, impact, chaining_opportunities,
      detection_and_hunting, remediation, key_takeaways, difficulty_tips,
      mental_model, behavioral_indicators, where_to_look, payload_mutations,
      custom_header_guide, real_world_scenario, memory_hook, image_urls, status, source_type
    ) VALUES (
      @date_added, @title, @vapt_level, @category, @vulnerability_type, @severity,
      @quality_score, @tools_used, @source_url, @one_line_summary, @beginner_context,
      @what_is_it, @how_to_find_it, @root_cause, @exploitation_walkthrough,
      @payloads_and_commands, @impact, @chaining_opportunities,
      @detection_and_hunting, @remediation, @key_takeaways, @difficulty_tips,
      @mental_model, @behavioral_indicators, @where_to_look, @payload_mutations,
      @custom_header_guide, @real_world_scenario, @memory_hook, @image_urls, @status, @source_type
    )
  `);

  const result = insert.run({
    date_added:               d.date_added || new Date().toISOString().split('T')[0],
    title:                    d.title,
    vapt_level:               d.vapt_level || 'Medium',
    category:                 d.category || 'Web Fundamentals',
    vulnerability_type:       d.vulnerability_type || 'Other',
    severity:                 d.severity || 'Medium',
    quality_score:            d.quality_score || 0,
    tools_used:               Array.isArray(d.tools_used) ? d.tools_used.join(', ') : (d.tools_used || ''),
    source_url:               d.source_url || null,
    one_line_summary:         d.one_line_summary || '',
    beginner_context:         d.beginner_context || '',
    what_is_it:               d.what_is_it || '',
    how_to_find_it:           d.how_to_find_it || '',
    root_cause:               d.root_cause || '',
    exploitation_walkthrough: d.exploitation_walkthrough || '',
    payloads_and_commands:    d.payloads_and_commands || '',
    impact:                   d.impact || '',
    chaining_opportunities:   d.chaining_opportunities || '',
    detection_and_hunting:    d.detection_and_hunting || '',
    remediation:              d.remediation || '',
    key_takeaways:            d.key_takeaways || '',
    difficulty_tips:          d.difficulty_tips || '',
    mental_model:             d.mental_model || '',
    behavioral_indicators:    d.behavioral_indicators || '',
    where_to_look:            d.where_to_look || '',
    payload_mutations:        d.payload_mutations || '',
    custom_header_guide:      d.custom_header_guide || '',
    real_world_scenario:      d.real_world_scenario || '',
    memory_hook:              d.memory_hook || '',
    image_urls:               Array.isArray(d.image_urls) ? JSON.stringify(d.image_urls) : (d.image_urls || '[]'),
    status:                   d.status || 'new',
    source_type:              d.source_type || 'rss'
  });

  console.log(`[+] Saved: [${d.vapt_level}/${d.severity}] "${d.title.substring(0,50)}" (score:${d.quality_score})`);
  res.json({ status: 'saved', id: result.lastInsertRowid });
});

// ── API: List Articles ────────────────────────────────────────────────────────
app.get('/api/articles', (req, res) => {
  const { severity, category, vuln, status, level, search, score_min, source_type, limit = 150, offset = 0 } = req.query;

  let where = ['1=1'];
  const params = [];

  if (severity)    { where.push('severity = ?');           params.push(severity); }
  if (category)    { where.push('category = ?');           params.push(category); }
  if (vuln)        { where.push('vulnerability_type = ?'); params.push(vuln); }
  if (status)      { where.push('status = ?');             params.push(status); }
  if (level)       { where.push('vapt_level = ?');         params.push(level); }
  if (score_min)   { where.push('quality_score >= ?');     params.push(parseInt(score_min)); }
  if (source_type) { where.push('source_type = ?');        params.push(source_type); }
  if (search) {
    where.push('(title LIKE ? OR one_line_summary LIKE ? OR key_takeaways LIKE ? OR vulnerability_type LIKE ? OR category LIKE ? OR payloads_and_commands LIKE ? OR mental_model LIKE ? OR memory_hook LIKE ? OR what_is_it LIKE ?)');
    const q = `%${search}%`;
    params.push(q, q, q, q, q, q, q, q, q);
  }

  const sql = `
    SELECT id, date_added, title, vapt_level, category, vulnerability_type,
           severity, quality_score, tools_used, source_url, one_line_summary, status,
           CASE WHEN personal_notes IS NOT NULL AND personal_notes != '' THEN 1 ELSE 0 END as has_notes
    FROM articles
    WHERE ${where.join(' AND ')}
    ORDER BY quality_score DESC, date_added DESC
    LIMIT ? OFFSET ?
  `;
  params.push(parseInt(limit), parseInt(offset));

  const countSql = `SELECT COUNT(*) as n FROM articles WHERE ${where.join(' AND ')}`;
  const rows  = db.prepare(sql).all(...params);
  const total = db.prepare(countSql).get(...params.slice(0, -2)).n;

  res.json({ data: rows, total });
});

// ── API: Single Article ───────────────────────────────────────────────────────
app.get('/api/articles/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

// ── API: Full Update (personal articles) ─────────────────────────────────────
app.put('/api/articles/:id', (req, res) => {
  const d = req.body;
  if (!d.title) return res.status(400).json({ error: 'title required' });

  db.prepare(`
    UPDATE articles SET
      title=@title, vapt_level=@vapt_level, category=@category,
      vulnerability_type=@vulnerability_type, severity=@severity,
      quality_score=@quality_score, tools_used=@tools_used,
      source_url=@source_url, one_line_summary=@one_line_summary,
      what_is_it=@what_is_it, mental_model=@mental_model,
      memory_hook=@memory_hook, key_takeaways=@key_takeaways,
      exploitation_walkthrough=@exploitation_walkthrough,
      how_to_find_it=@how_to_find_it, chaining_opportunities=@chaining_opportunities,
      difficulty_tips=@difficulty_tips, payloads_and_commands=@payloads_and_commands,
      payload_mutations=@payload_mutations, where_to_look=@where_to_look,
      behavioral_indicators=@behavioral_indicators, root_cause=@root_cause,
      impact=@impact, detection_and_hunting=@detection_and_hunting,
      remediation=@remediation, real_world_scenario=@real_world_scenario,
      custom_header_guide=@custom_header_guide, beginner_context=@beginner_context,
      personal_notes=@personal_notes
    WHERE id=@id
  `).run({
    id: req.params.id,
    title:                    d.title,
    vapt_level:               d.vapt_level || 'Medium',
    category:                 d.category || 'Personal Notes',
    vulnerability_type:       d.vulnerability_type || 'Other',
    severity:                 d.severity || 'Medium',
    quality_score:            d.quality_score || 0,
    tools_used:               d.tools_used || '',
    source_url:               d.source_url || null,
    one_line_summary:         d.one_line_summary || '',
    what_is_it:               d.what_is_it || '',
    mental_model:             d.mental_model || '',
    memory_hook:              d.memory_hook || '',
    key_takeaways:            d.key_takeaways || '',
    exploitation_walkthrough: d.exploitation_walkthrough || '',
    how_to_find_it:           d.how_to_find_it || '',
    chaining_opportunities:   d.chaining_opportunities || '',
    difficulty_tips:          d.difficulty_tips || '',
    payloads_and_commands:    d.payloads_and_commands || '',
    payload_mutations:        d.payload_mutations || '',
    where_to_look:            d.where_to_look || '',
    behavioral_indicators:    d.behavioral_indicators || '',
    root_cause:               d.root_cause || '',
    impact:                   d.impact || '',
    detection_and_hunting:    d.detection_and_hunting || '',
    remediation:              d.remediation || '',
    real_world_scenario:      d.real_world_scenario || '',
    custom_header_guide:      d.custom_header_guide || '',
    beginner_context:         d.beginner_context || '',
    personal_notes:           d.personal_notes || ''
  });
  res.json({ ok: true });
});

// ── API: Delete Article ───────────────────────────────────────────────────────
app.delete('/api/articles/:id', (req, res) => {
  const row = db.prepare('SELECT source_type FROM articles WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (row.source_type !== 'personal') return res.status(403).json({ error: 'can only delete personal articles' });
  db.prepare('DELETE FROM articles WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── API: Update Status ────────────────────────────────────────────────────────
app.patch('/api/articles/:id/status', (req, res) => {
  const { status } = req.body;
  if (!['new','reviewed','practiced','mastered'].includes(status))
    return res.status(400).json({ error: 'invalid status' });
  db.prepare('UPDATE articles SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ ok: true });
});

// ── API: Get Personal Notes ───────────────────────────────────────────────────
app.get('/api/articles/:id/notes', (req, res) => {
  const row = db.prepare('SELECT personal_notes FROM articles WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ notes: row.personal_notes || '' });
});

// ── API: Save Personal Notes ──────────────────────────────────────────────────
app.patch('/api/articles/:id/notes', (req, res) => {
  const { notes } = req.body;
  db.prepare('UPDATE articles SET personal_notes = ? WHERE id = ?').run(notes || '', req.params.id);
  res.json({ ok: true });
});

// ── API: Flashcards ───────────────────────────────────────────────────────────
app.get('/api/flashcards', (req, res) => {
  const { level } = req.query;
  let sql = `
    SELECT id, title, vapt_level, category, vulnerability_type, severity,
           mental_model, memory_hook, key_takeaways, payloads_and_commands,
           one_line_summary, flashcard_status
    FROM articles
    WHERE flashcard_status != 'known'
  `;
  const params = [];
  if (level) { sql += ' AND vapt_level = ?'; params.push(level); }
  sql += ' ORDER BY RANDOM() LIMIT 50';

  const cards = db.prepare(sql).all(...params);
  res.json(cards);
});

// ── API: Update Flashcard Status ──────────────────────────────────────────────
app.patch('/api/articles/:id/flashcard', (req, res) => {
  const { flashcard_status } = req.body;
  if (!['unseen','known','review'].includes(flashcard_status))
    return res.status(400).json({ error: 'invalid status: use unseen|known|review' });
  db.prepare('UPDATE articles SET flashcard_status = ? WHERE id = ?').run(flashcard_status, req.params.id);
  res.json({ ok: true });
});

// ── API: Daily Challenge ──────────────────────────────────────────────────────
app.get('/api/daily-challenge', (req, res) => {
  // First prefer an unread high-quality article
  const unread = db.prepare(`
    SELECT id, title, vapt_level, category, severity, quality_score, status, one_line_summary
    FROM articles
    WHERE status = 'new'
    ORDER BY quality_score DESC
    LIMIT 1
  `).get();

  if (unread) return res.json(unread);

  // Fallback: deterministic pick by day-of-year
  const total = db.prepare('SELECT COUNT(*) as n FROM articles').get().n;
  if (!total) return res.json(null);

  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 1)) / 86400000);
  const offset = dayOfYear % total;

  const article = db.prepare(`
    SELECT id, title, vapt_level, category, severity, quality_score, status, one_line_summary
    FROM articles
    ORDER BY quality_score DESC
    LIMIT 1 OFFSET ?
  `).get(offset);

  res.json(article || null);
});

// ── API: Progress per VAPT Level ─────────────────────────────────────────────
app.get('/api/progress', (req, res) => {
  const LEVELS = ['Foundation','Recon','Low','Medium','High','Critical','Advanced','Expert'];

  const rows = db.prepare(`
    SELECT vapt_level,
           COUNT(*) as total,
           SUM(CASE WHEN status IN ('reviewed','practiced','mastered') THEN 1 ELSE 0 END) as done
    FROM articles
    GROUP BY vapt_level
  `).all();

  const map = {};
  rows.forEach(r => { map[r.vapt_level] = r; });

  const result = LEVELS.map(lv => {
    const r = map[lv] || { total: 0, done: 0 };
    return {
      level: lv,
      total: r.total,
      done:  r.done,
      pct:   r.total > 0 ? Math.round((r.done / r.total) * 100) : 0
    };
  });

  res.json(result);
});

// ── API: Stats ────────────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const total      = db.prepare('SELECT COUNT(*) as n FROM articles').get().n;
  const personal   = db.prepare("SELECT COUNT(*) as n FROM articles WHERE source_type='personal'").get().n;
  const byStatus   = db.prepare('SELECT status, COUNT(*) as n FROM articles GROUP BY status').all();
  const bySeverity = db.prepare(`SELECT severity, COUNT(*) as n FROM articles GROUP BY severity ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END`).all();
  const byLevel    = db.prepare(`SELECT vapt_level, COUNT(*) as n FROM articles GROUP BY vapt_level ORDER BY CASE vapt_level WHEN 'Foundation' THEN 1 WHEN 'Recon' THEN 2 WHEN 'Low' THEN 3 WHEN 'Medium' THEN 4 WHEN 'High' THEN 5 WHEN 'Critical' THEN 6 WHEN 'Advanced' THEN 7 WHEN 'Expert' THEN 8 ELSE 9 END`).all();
  const byCategory = db.prepare('SELECT category, COUNT(*) as n FROM articles GROUP BY category ORDER BY n DESC').all();
  const topScoring = db.prepare('SELECT id, title, quality_score, severity, vapt_level, vulnerability_type FROM articles ORDER BY quality_score DESC LIMIT 10').all();
  const recent     = db.prepare('SELECT id, title, date_added, severity, vapt_level, category FROM articles ORDER BY created_at DESC LIMIT 10').all();
  const unread     = db.prepare("SELECT COUNT(*) as n FROM articles WHERE status = 'new'").get().n;

  res.json({ total, unread, personal, byStatus, bySeverity, byLevel, byCategory, topScoring, recent });
});

// ── API: Filters (dropdown values) ───────────────────────────────────────────
app.get('/api/filters', (req, res) => {
  const levels     = db.prepare(`SELECT DISTINCT vapt_level FROM articles WHERE vapt_level IS NOT NULL ORDER BY CASE vapt_level WHEN 'Foundation' THEN 1 WHEN 'Recon' THEN 2 WHEN 'Low' THEN 3 WHEN 'Medium' THEN 4 WHEN 'High' THEN 5 WHEN 'Critical' THEN 6 WHEN 'Advanced' THEN 7 WHEN 'Expert' THEN 8 ELSE 9 END`).all().map(r => r.vapt_level);
  const categories = db.prepare('SELECT DISTINCT category FROM articles WHERE category IS NOT NULL ORDER BY category').all().map(r => r.category);
  const vulnTypes  = db.prepare('SELECT DISTINCT vulnerability_type FROM articles WHERE vulnerability_type IS NOT NULL ORDER BY vulnerability_type').all().map(r => r.vulnerability_type);
  res.json({ levels, categories, vulnTypes });
});

// ── API: Get Lab ──────────────────────────────────────────────────────────────
app.get('/api/articles/:id/lab', (req, res) => {
  const row = db.prepare('SELECT lab_content FROM articles WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!row.lab_content) return res.json({ lab: null });
  try {
    res.json({ lab: JSON.parse(row.lab_content) });
  } catch(e) {
    res.json({ lab: null });
  }
});

// ── API: Generate Lab via Gemini ──────────────────────────────────────────────
app.post('/api/articles/:id/lab/generate', async (req, res) => {
  const row = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });

  // Return cached lab if already generated
  if (row.lab_content) {
    try { return res.json({ lab: JSON.parse(row.lab_content) }); } catch(e) {}
  }

  const key = process.env.GEMINI_API_KEY;
  if (!key) return res.status(500).json({ error: 'GEMINI_API_KEY not set' });

  const prompt = `You are a cybersecurity lab instructor. Create a hands-on interactive lab for this security vulnerability.

Article Title: ${row.title}
Vulnerability Type: ${row.vulnerability_type || 'Unknown'}
VAPT Level: ${row.vapt_level || 'Medium'}
Summary: ${row.one_line_summary || ''}
Exploitation Context: ${(row.exploitation_walkthrough || '').substring(0, 500)}

Return ONLY valid JSON (no markdown, no code fences, no extra text) in this exact structure:
{
  "overview": "2-3 sentence description of what the learner will practice in this lab",
  "tools_needed": ["tool1", "tool2", "tool3"],
  "target_context": "Where to practice: e.g. DVWA, HackTheBox, local Docker, or real-world bug bounty context",
  "vulnerable_scenario": "Brief description of the vulnerable setup/application context",
  "vulnerable_code": "Code snippet, config, or request showing the exact vulnerability (use realistic examples)",
  "steps": [
    {
      "number": 1,
      "title": "Step title (action verb)",
      "goal": "What you are trying to achieve in this step",
      "command": "Exact curl command, tool command, or code to run",
      "expected_output": "What a successful output looks like",
      "tip": "A helpful hint or common pitfall to watch for"
    }
  ],
  "success_criteria": "Clear description of how to confirm the vulnerability was successfully exploited",
  "practice_variations": ["Variation 1 to try", "Variation 2 to try", "Variation 3 to try"],
  "defensive_exercise": "A specific action to take to verify the fix/patch is effective"
}

Create 4-6 detailed steps. Make commands realistic and educational. Focus on practical skills.`;

  // Try models in order — flash-latest is the reliable alias, others as fallback
  const MODELS = ['gemini-flash-latest', 'gemini-2.0-flash-lite', 'gemini-2.5-flash', 'gemini-2.0-flash'];
  let geminiRes, lastErr;

  for (const model of MODELS) {
    try {
      geminiRes = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.3, maxOutputTokens: 3000 }
          })
        }
      );
      if (geminiRes.ok) { console.log(`[lab] Using model: ${model}`); break; }
      const errJson = await geminiRes.json().catch(() => ({}));
      lastErr = errJson?.error || {};
      if (lastErr.code === 429) {
        // Extract retry delay if available
        const retryInfo = (lastErr.details || []).find(d => d['@type']?.includes('RetryInfo'));
        const delay = retryInfo?.retryDelay || '60s';
        console.warn(`[lab] ${model} quota hit (429), delay=${delay}. Trying next model...`);
        geminiRes = null;
        continue;
      }
      // Other error — stop
      console.error(`[lab] ${model} error ${lastErr.code}:`, lastErr.message);
      break;
    } catch(fetchErr) {
      lastErr = { message: fetchErr.message };
      geminiRes = null;
    }
  }

  if (!geminiRes || !geminiRes.ok) {
    const msg = lastErr?.code === 429
      ? 'Gemini free-tier quota exceeded. Wait ~1 min and try again, or add billing at https://console.cloud.google.com/billing'
      : (lastErr?.message || 'All Gemini models failed');
    console.error('[lab] Final error:', msg);
    return res.status(502).json({ error: msg });
  }

  try {

    const geminiData = await geminiRes.json();
    const rawText = geminiData?.candidates?.[0]?.content?.parts?.[0]?.text || '';

    // Strip markdown fences if Gemini wrapped it anyway
    const jsonText = rawText.replace(/^```(?:json)?\n?/,'').replace(/\n?```$/,'').trim();

    let lab;
    try {
      lab = JSON.parse(jsonText);
    } catch(parseErr) {
      console.error('[lab] JSON parse failed:', jsonText.substring(0, 200));
      return res.status(502).json({ error: 'Failed to parse Gemini response as JSON' });
    }

    db.prepare('UPDATE articles SET lab_content = ? WHERE id = ?')
      .run(JSON.stringify(lab), req.params.id);

    console.log(`[lab] Generated for article ${req.params.id}: "${row.title.substring(0,50)}"`);
    res.json({ lab });

  } catch(e) {
    console.error('[lab] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Groq helper (for import) ─────────────────────────────────────────────────
const GROQ_KEY = process.env.GROQ_API_KEY || 'xxxx';

async function groqReq(messages, maxTokens = 1500, model = 'llama-3.1-8b-instant') {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, temperature: 0.1, max_tokens: maxTokens, messages }),
    signal: AbortSignal.timeout(90000)
  });
  const d = await res.json();
  if (d.error) throw new Error(d.error.message);
  return d.choices?.[0]?.message?.content || '';
}

// ── Technical 6-section notes prompt ─────────────────────────────────────────
const NOTES_SYSTEM = `You are a senior Red Team professional (OSCP, BSCP, CPENT, eWPTX) writing structured pentest playbooks for junior practitioners.
RULES:
(1) Manual testing = Burp Suite workflow (Proxy → Intercept → Repeater → Intruder). Never use curl for manual steps. Curl is only for automation/scripting sections.
(2) For every Burp step: describe which Burp tool to use, what to modify, what to look for in the Response tab, and what it proves.
(3) Every section must teach the WHY alongside the HOW — a step without explanation of what it confirms is useless.
(4) Real tool flags, real /usr/share/seclists/ paths, real nuclei template paths.
(5) Return ONLY a raw JSON object — start with { end with }. No markdown fences. Use \\n inside strings.`;

function buildNotesPrompt(vulnType, vaptLevel, severity, title, content, beginnerCtx) {
  return `Vulnerability: ${vulnType} | VAPT Level: ${vaptLevel} | Severity: ${severity}
Article: ${title}
Content summary: ${content}

Return ONLY this JSON. Fill every field with actionable, technical, hands-on content:
{"what_is_it":"01 — TOPIC OVERVIEW\\nWhat: CWE#. OWASP Top 10 category. Trust boundary violated. Attacker primitive: read/write/execute/redirect/exfil/pivot.\\n\\nWhy: Root cause — which developer assumption fails. E.g. 'Server trusts attacker-controlled X to determine Y without validating Z.'\\n\\nWhere: Real products/frameworks/cloud services affected. Name actual CVEs if relevant. Which middleware or SDK version.\\n\\nHow: 4-step lifecycle — 1) Recon: how attacker finds target 2) Identify: signal that confirms vulnerability 3) Exploit: the exact technique 4) Impact: what attacker achieves\\n\\nWhich tech stacks most affected and why (SaaS APIs, fintech, healthcare HL7, e-commerce redirect flows, JWT-heavy SPAs)","mental_model":"02 — HOW IT WORKS\\nSimple: [one-sentence trigger: 'When app does X without Y, attacker sends Z and gains primitive']\\n\\nTechnical (HTTP/middleware level): Step-by-step — what the parser/interpreter/server does with the payload. What trust check is skipped. How the response differs from normal.\\n\\nRaw HTTP request showing the bug:\\nGET/POST [endpoint] HTTP/1.1\\nHost: target.com\\n[headers]\\n\\n[body if POST]\\n\\nVulnerable response (confirm exploit):\\n[status + header/body diff showing impact]\\n\\nPatched response:\\n[what it looks like when fixed]\\n\\nCode-level mistake (pseudocode or real framework snippet):\\n[the exact developer error]\\n\\nHow it differs from related vulns: [IDOR vs BAC vs Auth Bypass — why this is distinct]","key_takeaways":"03 — MANDATORY KEYWORDS\\n7 terms. Each on its own line:\\nTERM: [technical definition in attack context — not textbook] | Pentest relevance: [how you use this in engagement] | Connected to: [related vulns/techniques/primitives] | Exploitation implication: [what this enables for attacker]\\n\\n[Repeat for all 7 terms]","exploitation_walkthrough":"04 — PENTEST TEST CASES (Burp Suite)\\n\\nSTEP 0 — SETUP:\\n• Open Burp Suite → Proxy → Intercept ON\\n• Navigate target app in Burp's built-in browser\\n• Map the attack surface: HTTP History tab → identify [relevant endpoint patterns]\\n• Right-click interesting requests → Send to Repeater\\n\\nSTEP 1 — ESTABLISH BASELINE:\\n• In Repeater: send the original unmodified request\\n• Note: response status, body length, key response headers\\n• Why: you need a baseline to distinguish noise from signal\\n\\nSTEP 2 — PROBE FOR VULNERABILITY:\\n• Modify [parameter/header] — change [original value] to [probe payload]\\n• Send → observe Response tab\\n• Look for: [specific error / reflection / redirect / timing difference]\\n• Why this matters: [what this tells you about server-side handling]\\n\\nSTEP 3 — CONFIRM EXPLOITABILITY:\\n• Replace probe with [exploit payload]\\n• Send → confirm: [success indicator in response — status, body content, header value]\\n• Document: right-click Response → Copy as issue evidence\\n• Why this is definitive: [what the response proves]\\n\\n--- TEST CASE 1: [Name — basic exploitation] ---\\nTarget: [endpoint] | Param: [parameter name] | Method: [HTTP method]\\nBurp Repeater request:\\n[METHOD] [path?param=PAYLOAD] HTTP/1.1\\nHost: target.com\\n[any relevant headers]\\n\\n[body if POST]\\n\\nSuccess indicator: [exact string/status/header proving exploitation]\\nWhat it proves: [impact in one sentence]\\nReport evidence: [what to screenshot / copy from response]\\n\\n--- TEST CASE 2: [Name — authenticated or higher-impact] ---\\n[Same Burp-centric structure]\\n\\n--- TEST CASE 3: [Name — WAF bypass or filter evasion] ---\\n[Same Burp-centric structure]\\n\\nBurp Intruder — mass testing:\\n• Send request to Intruder → Positions tab → mark [parameter] as §payload§\\n• Payloads tab → Payload type: Simple list → Load: /usr/share/seclists/[path]\\n• Attack type: Sniper → Start Attack → sort by [Length/Status] to spot anomalies","chaining_opportunities":"05 — ATTACKER MINDSET\\nChain 1 — [Impact name]: [VulnA] → [how A enables B] → [VulnB] → [Critical result]\\nChain 2 — [Impact name]: [different path]\\nChain 3 — [Impact name]: [different path]\\n\\nEscalation path:\\n1. Initial: [low-impact find attacker starts with]\\n2. Escalate: [how to pivot using first finding]\\n3. Maximize: [full exploitation — ATO/RCE/data exfil]\\n\\nPost-exploitation priorities (first 3 things after successful exploit):\\n1. [what to enumerate/exfil first]\\n2. [what internal service/credential to target]\\n3. [how to maintain access or pivot]\\n\\nBusiness impact: [data breach notification trigger / compliance violation / customer impact]","difficulty_tips":"06 — INTERVIEW CHALLENGE\\nQ: [Scenario question — specific target type (e.g. 'You are testing a fintech SaaS on a bug bounty program'), realistic constraint, add a twist that separates juniors from seniors]\\n\\nExpected answer framework (what interviewer wants to hear):\\n• Enumeration strategy: [specific steps, not generic]\\n• Exploitation method: [exact technique + why it applies here]\\n• Vulnerability classification: [CWE + OWASP + severity + CVSS reasoning]\\n• Chaining possibilities: [what this enables]\\n• Business impact: [real-world consequence in business terms]\\n• Report writing: [what evidence + CVSS vector + remediation recommendation]\\n\\nFollow-up questions (interviewer digs into every term you mention):\\n• If you say '[technical term]': Show me the exact HTTP request you would send. What would the server response look like?\\n• If you mention '[tool]': What exact command with all flags? What does each flag do?\\n• If you claim '[action]': How do you distinguish a true positive from a false positive here?\\n\\nCommon junior mistakes:\\n[What incomplete or incorrect answers look like — the gaps that reveal lack of hands-on experience]","how_to_find_it":"RECON CHECKLIST\\n1. Passive recon: [exact tool/command to map attack surface without sending payloads]\\n2. Active fingerprint: [how to identify tech stack and version]\\n3. Endpoint discovery: ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/[path] -mc 200,301\\n4. Parameter fuzz: [arjun/ffuf command for param discovery]\\n5. Vulnerability probe: [exact first payload to confirm presence]\\n6. Confirm exploitability: [how to distinguish true positive from false positive]\\nnuclei template: nuclei -u https://TARGET -t [template-path] (if applicable)\\nBurp scan: [specific Active Scan issue name to look for]\\nWhat scanners miss: [the one manual check that catches what automation skips]","payloads_and_commands":"[BASIC]: [minimal working payload, no encoding]\\n[ENCODED]: [URL or HTML encoded variant for filter bypass]\\n[BLIND/OOB]: [payload with interactsh.com or Burp Collaborator callback]\\n[POLYGLOT]: [single payload working in HTML/JS/attr/CSS context]\\n[sqlmap]: sqlmap -u 'URL' -p param --dbs --batch --level=5 --risk=3\\n[ffuf]: ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/[path] -mc 200 -fs [size]\\n[nuclei]: nuclei -u https://TARGET -t nuclei-templates/[path]\\n[custom]: [any relevant specialized tool command]","payload_mutations":"WAF Bypass Table:\\n1. URL double-encode | %253Cscript%253E | WAF decodes once, browser decodes twice\\n2. Case variation | SeLeCt 1 | Regex WAF bypassed (case-insensitive)\\n3. Comment injection | SEL/**/ECT | Breaks keyword pattern detection\\n4. Whitespace substitution | SELECT%09FROM | Tab replaces space, rule misses\\n5. Param pollution | param=safe&param=payload | WAF sees first value, server uses last\\n6. Unicode normalization | ＜script＞ | Full-width chars normalize post-WAF\\n7. Chunked Transfer-Encoding | payload split across chunks | Body inspection bypassed\\n8. [Vuln-specific bypass] | [payload] | [why this works for this vuln type]","where_to_look":"High-probability entry points:\\nURL params: id, uid, user_id, account_id, redirect, url, next, return, file, path, cmd, template, token, ref\\nHTTP headers: Host, Origin, Referer, X-Forwarded-For, X-Forwarded-Host, X-Original-URL, Content-Type, Authorization, X-API-Key\\nBody fields: [specific JSON keys, XML nodes, multipart filename fields relevant to this vuln]\\nGraphQL: query introspection, nested resolver ID args, __typename\\nHTTP methods exposing this: [GET/POST/PUT/PATCH — which and why]\\nApp flows to test first: [file upload / password reset / profile update / export/PDF / webhook config / OAuth callback / redirect handler — whichever applies to this vuln]","behavioral_indicators":"Differential signals (capture baseline FIRST, then compare):\\n1. Time-based: inject sleep(5)/WAITFOR DELAY → response time >5s | confirms blind injection point\\n2. Error-based: send [probe] → response contains [specific error pattern] | leaks DB/framework version\\n3. Size-based: send [probe] → response body >20% larger than baseline | data being returned\\n4. Status-based: send [payload] → 500 Internal Server Error | injection point / [302 to /admin] confirms auth bypass\\n5. OOB callback: send [payload with interactsh URL] → DNS lookup in interactsh dashboard | confirms SSRF/RCE/XXE blind\\n6. Header difference: send [specific header value] → different response header in reply | confirms reflection or trust","root_cause":"CWE-[NUMBER]: [Official CWE name]\\nRoot cause: [exact developer mistake in one technical sentence]\\nVulnerable code:\\n[pseudocode or real framework snippet showing the bug]\\nMissing control: [exact validation/sanitization/encoding/ACL that was not implemented]\\nSecure equivalent:\\n[what the code should look like instead]","impact":"1) Data accessible: [PII/credentials/secrets/source code/internal IPs/tokens]\\n2) Actions possible: [ATO/file write/RCE/SSRF pivot/lateral movement]\\n3) Lateral movement: [specific next internal targets after initial compromise]\\n4) CVSS v3.1: [X.X] — [Critical/High/Medium/Low]\\n   Vector: CVSS:3.1/AV:[N/A/L/P]/AC:[L/H]/PR:[N/L/H]/UI:[N/R]/S:[U/C]/C:[N/L/H]/I:[N/L/H]/A:[N/L/H]\\n5) Compliance: [GDPR Article / PCI DSS Req / HIPAA § violated] — breach notification required if [condition]","detection_and_hunting":"Splunk: index=web_logs [SPL query finding attack pattern]\\nElastic: [KQL/DSL query]\\nKey log fields: [field_name] contains [suspicious value]\\nNetwork IOC: [pattern visible in network logs during exploitation]\\nWAF rule (ModSecurity): SecRule [target] [operator] [action]\\nAWS WAF: [managed rule group or custom rule]\\nAnomaly: [what normal traffic looks like vs attack traffic — rate, size, user-agent, timing]","remediation":"Vulnerable code:\\n[exact snippet showing the mistake]\\n\\nFixed code:\\n[same snippet with fix applied]\\n\\nSecurity framework API: [PreparedStatement / DOMPurify.sanitize() / bcrypt.hash() / etc]\\nRequired security headers: [Header: value — only if directly relevant]\\nInput validation: [allowlist regex or logic specific to this vuln type]\\nLibrary to upgrade: [if CVE-specific, name the package and safe version]","real_world_scenario":"[200+ word bug bounty or pentest story. First person, past tense. Structure: 1) target type and scope 2) initial recon — show actual tool output snippet 3) exact endpoint/parameter found 4) full exploitation chain with exact commands 5) what was exfiltrated or demonstrated as impact 6) severity rating and program response. Include 1-2 dead ends and what the key insight was.]","custom_header_guide":"Header injection cheat sheet:\\nHeader | Inject value | Success indicator | curl command\\nHost | attacker.com | Password reset link goes to attacker | curl -H 'Host: attacker.com'\\nX-Forwarded-For | 127.0.0.1 | Admin access / rate limit bypass | curl -H 'X-Forwarded-For: 127.0.0.1'\\nOrigin | https://evil.com | ACAO: evil.com in response | curl -H 'Origin: https://evil.com'\\nX-Forwarded-Host | evil.com | App trusts this as base URL | curl -H 'X-Forwarded-Host: evil.com'\\nContent-Type | application/xml | XML parsed → XXE | curl -H 'Content-Type: application/xml'\\n[3 more headers specific to this vulnerability type]","memory_hook":"If [observable condition during recon or testing] → immediately test [specific attack]. [one-liner rule the pentester burns into muscle memory]","beginner_context":"Prerequisites before testing this:\\n1. [specific technical concept to understand first]\\n2. [tool to install and basic usage]\\n3. [protocol/spec knowledge needed]\\nRead first: [specific PortSwigger Academy lab / HackTricks section / OWASP page — name exact URL path]\\nMost critical concept: [the single thing that, if misunderstood, causes all tests to fail]"}`;
}

// ── API: Import URL (SSE streaming) ──────────────────────────────────────────
app.get('/api/import-url', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url required' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  const send = (evt, data) => res.write(`event: ${evt}\ndata: ${JSON.stringify(data)}\n\n`);

  try {
    // 1. Dedup check
    const existing = db.prepare('SELECT id, title FROM articles WHERE source_url = ?').get(url);
    if (existing) {
      send('error', { message: 'Already in your knowledge base', id: existing.id });
      return res.end();
    }

    // 2. Fetch page
    send('progress', { stage: 'fetch', message: 'Fetching article from URL...' });
    const pageRes = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      },
      signal: AbortSignal.timeout(20000)
    });
    if (!pageRes.ok) throw new Error(`Could not fetch page (HTTP ${pageRes.status})`);
    const html = await pageRes.text();

    // Extract images: og:image first, then article <img> tags
    const images = [];
    const ogImg = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
                  || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    if (ogImg?.[1]) images.push(ogImg[1]);
    const imgRe = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
    let imgM;
    while ((imgM = imgRe.exec(html)) !== null && images.length < 8) {
      const src = imgM[1];
      if (src.startsWith('http') && !images.includes(src) &&
          !/(pixel|tracker|badge|avatar|icon|logo|emoji|1x1|spacer|ads|count)/i.test(src) &&
          !src.endsWith('.svg') && src.includes('.')) {
        images.push(src);
      }
    }

    // Extract title
    const titleM = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    let title = titleM ? titleM[1].replace(/&amp;/g,'&').replace(/&#39;/g,"'").replace(/&quot;/g,'"').trim() : '';
    // Strip site suffix: "XSS Bug | Medium" → "XSS Bug"
    title = title.replace(/\s*[|\-–·—]\s*(Medium|HackerNoon|HackTricks|GitHub|Substack|InfoSec\s*Write-?ups?|The Hacker News|PortSwigger|OWASP|DEV Community|dev\.to).*$/i, '').trim() || title;
    if (!title || title.length < 5) title = url;

    // Extract readable text (strip HTML, nav, scripts)
    const text = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<nav[\s\S]*?<\/nav>/gi, '')
      .replace(/<header[\s\S]*?<\/header>/gi, '')
      .replace(/<footer[\s\S]*?<\/footer>/gi, '')
      .replace(/<aside[\s\S]*?<\/aside>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 5000);

    // 3. Score with Groq
    send('progress', { stage: 'score', message: 'Analysing content with AI...' });
    const scoreRaw = await groqReq([{ role: 'user', content:
      `You are a senior penetration tester grading a security article for a VAPT curriculum.
Return ONLY valid JSON, no markdown:
{"score":8,"skip":false,"vapt_level":"Medium","category":"Client-Side Attacks","vulnerability_type":"XSS","severity":"High","tools_mentioned":["burp","xsstrike"],"one_line_summary":"One precise technical sentence","beginner_context":"2 beginner sentences"}
If NOT about security/hacking/pentesting: {"skip":true,"score":0}
vapt_level: Foundation|Recon|Low|Medium|High|Critical|Advanced|Expert
category: Recon & Enumeration|Client-Side Attacks|Injection Attacks|Broken Access Control|Authentication & Sessions|Server-Side Attacks|API & Web Services|Cloud & Infrastructure|Exploit Chaining|Web Fundamentals
vulnerability_type: XSS|CSRF|SQLi|SSRF|XXE|RCE|IDOR|Auth Bypass|SSTI|Open Redirect|Clickjacking|CORS|JWT Attack|OAuth Attack|GraphQL|Deserialization|File Upload|Path Traversal|Subdomain Takeover|Command Injection|Business Logic|Race Condition|Prototype Pollution|Misconfiguration|Info Disclosure|Other

Article Title: ${title}
Article Content: ${text.slice(0, 2500)}` }], 400);

    let score;
    try { score = JSON.parse(scoreRaw.replace(/```json\n?/g,'').replace(/```\n?/g,'').trim()); }
    catch(e) { throw new Error('AI scoring failed — please try again'); }

    if (score.skip) {
      send('error', { message: "This doesn't look like a security/pentesting article. Try a different URL." });
      return res.end();
    }

    // 4. Generate notes (inject KB + PATT context if available)
    send('progress', { stage: 'notes', message: `Generating pentest notes (${score.vulnerability_type || 'security'})...` });
    const kbEntry   = db.prepare('SELECT content FROM knowledge_base WHERE vuln_type = ?').get(score.vulnerability_type || '');
    const pattEntry = db.prepare('SELECT content FROM patt_cache WHERE vuln_type = ?').get(score.vulnerability_type || '');
    const kbContext   = kbEntry   ? `\nYOUR PREVIOUS FINDINGS FOR ${score.vulnerability_type}:\n${kbEntry.content}\n\nUse these insights to enhance and validate your analysis.\n` : '';
    const pattContext = pattEntry ? `\n=== PayloadsAllTheThings Reference (${score.vulnerability_type}) ===\n${pattEntry.content.slice(0,3000)}\n===\n` : '';
    const notesRaw = await groqReq([
      { role: 'system', content: NOTES_SYSTEM },
      { role: 'user',   content: kbContext + pattContext + buildNotesPrompt(score.vulnerability_type, score.vapt_level, score.severity, title, text.slice(0, 3000), score.beginner_context) }
    ], 5000);

    let notes;
    const nc = notesRaw.replace(/```json\n?/g,'').replace(/```\n?/g,'');
    const fi = nc.indexOf('{'), li = nc.lastIndexOf('}');
    const nclean = fi !== -1 && li !== -1 ? nc.slice(fi, li+1) : nc;
    try { notes = JSON.parse(nclean); }
    catch(e) {
      try { notes = JSON.parse(nclean.replace(/,(\s*[}\]])/g,'$1')); }
      catch(e2) { throw new Error('Failed to parse AI notes — please try again'); }
    }

    // 5. Save to DB
    send('progress', { stage: 'save', message: 'Saving to knowledge base...' });
    const str = v => v == null ? '' : Array.isArray(v) ? v.join('\n') : String(v);

    const ins = db.prepare(`
      INSERT INTO articles (
        date_added, title, vapt_level, category, vulnerability_type, severity,
        quality_score, tools_used, source_url, one_line_summary, beginner_context,
        what_is_it, how_to_find_it, root_cause, exploitation_walkthrough,
        payloads_and_commands, impact, chaining_opportunities, detection_and_hunting,
        remediation, key_takeaways, difficulty_tips, mental_model, behavioral_indicators,
        where_to_look, payload_mutations, custom_header_guide, real_world_scenario,
        memory_hook, image_urls, status
      ) VALUES (
        @date_added, @title, @vapt_level, @category, @vulnerability_type, @severity,
        @quality_score, @tools_used, @source_url, @one_line_summary, @beginner_context,
        @what_is_it, @how_to_find_it, @root_cause, @exploitation_walkthrough,
        @payloads_and_commands, @impact, @chaining_opportunities, @detection_and_hunting,
        @remediation, @key_takeaways, @difficulty_tips, @mental_model, @behavioral_indicators,
        @where_to_look, @payload_mutations, @custom_header_guide, @real_world_scenario,
        @memory_hook, @image_urls, @status
      )
    `);

    const saved = ins.run({
      date_added: new Date().toISOString().split('T')[0],
      title,
      vapt_level:               score.vapt_level || 'Medium',
      category:                 score.category || 'Web Fundamentals',
      vulnerability_type:       score.vulnerability_type || 'Other',
      severity:                 score.severity || 'Medium',
      quality_score:            score.score || 7,
      tools_used:               Array.isArray(score.tools_mentioned) ? score.tools_mentioned.join(', ') : '',
      source_url:               url,
      one_line_summary:         score.one_line_summary || '',
      beginner_context:         score.beginner_context || str(notes.beginner_context),
      what_is_it:               str(notes.what_is_it),
      how_to_find_it:           str(notes.how_to_find_it),
      root_cause:               str(notes.root_cause),
      exploitation_walkthrough: str(notes.exploitation_walkthrough),
      payloads_and_commands:    str(notes.payloads_and_commands),
      impact:                   str(notes.impact),
      chaining_opportunities:   str(notes.chaining_opportunities),
      detection_and_hunting:    str(notes.detection_and_hunting),
      remediation:              str(notes.remediation),
      key_takeaways:            str(notes.key_takeaways),
      difficulty_tips:          str(notes.difficulty_tips),
      mental_model:             str(notes.mental_model),
      behavioral_indicators:    str(notes.behavioral_indicators),
      where_to_look:            str(notes.where_to_look),
      payload_mutations:        str(notes.payload_mutations),
      custom_header_guide:      str(notes.custom_header_guide),
      real_world_scenario:      str(notes.real_world_scenario),
      memory_hook:              str(notes.memory_hook),
      image_urls:               JSON.stringify(images),
      status:                   'new'
    });

    console.log(`[import] Saved: [${score.vapt_level}/${score.severity}] "${title.slice(0,60)}" (score:${score.score})`);
    send('done', {
      id: saved.lastInsertRowid,
      title,
      score: score.score,
      vapt_level: score.vapt_level,
      severity: score.severity,
      vulnerability_type: score.vulnerability_type
    });
    res.end();

  } catch(e) {
    console.error('[import] Error:', e.message);
    send('error', { message: e.message });
    res.end();
  }
});

// ── API: Burp Request Analyzer ────────────────────────────────────────────────
app.post('/api/analyze-request', async (req, res) => {
  const { request } = req.body;
  if (!request) return res.status(400).json({ error: 'request required' });

  try {
    const raw = await groqReq([
      { role: 'system', content: 'You are a senior web application penetration tester. Analyze HTTP requests for security vulnerabilities and provide Burp Suite testing steps. Return ONLY a raw JSON object — start with { end with }. No markdown fences.' },
      { role: 'user', content: `Analyze this HTTP request for ALL possible vulnerabilities. For each vuln provide exact Burp Suite steps (Proxy→Repeater→Intruder workflow), not curl.

Return JSON exactly:
{"vulns":[{"name":"SQL Injection","confidence":"High","location":"user_id parameter in body","payload":"1 OR 1=1--","why":"Integer parameter passed directly to SQL query without parameterization","burp_steps":"1. Send to Repeater\\n2. Change user_id value from 1 to 1 OR 1=1--\\n3. Forward → check Response tab for extra data or SQL error\\n4. Confirm: response differs from baseline (more rows / error message)\\n5. Escalate: try 1 UNION SELECT null,null-- to extract columns"}],"headers_to_test":["Authorization","X-Forwarded-For","Host"],"notes":"Any patterns or context worth noting"}

HTTP Request:
${request.slice(0, 3000)}` }
    ], 2000);

    const cleaned = raw.replace(/```json\n?/g,'').replace(/```\n?/g,'').trim();
    const fi = cleaned.indexOf('{'), li = cleaned.lastIndexOf('}');
    const result = JSON.parse(fi !== -1 ? cleaned.slice(fi, li+1) : cleaned);
    res.json(result);
  } catch(e) {
    console.error('[analyze-request]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── API: AI Chat ──────────────────────────────────────────────────────────────
app.post('/api/chat', async (req, res) => {
  const { messages, model = 'groq' } = req.body;
  if (!Array.isArray(messages) || messages.length === 0)
    return res.status(400).json({ error: 'messages array required' });

  const systemPrompt = 'You are an expert Red Team pentester and security researcher. Answer questions about hacking techniques, CTF challenges, penetration testing, vulnerability research, tools (Burp Suite, nmap, sqlmap, ffuf, etc.), and defensive security. Be concise, practical, and technical. Use code blocks for commands and payloads.';

  try {
    if (model === 'gemini') {
      const key = process.env.GEMINI_API_KEY;
      if (!key) return res.json({ error: 'GEMINI_API_KEY not set. Add it to your .env file.' });

      // Convert chat history to Gemini format
      const contents = messages.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
      }));

      const geminiRes = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key=${key}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents,
            generationConfig: { temperature: 0.7, maxOutputTokens: 2048 }
          }),
          signal: AbortSignal.timeout(60000)
        }
      );

      const data = await geminiRes.json();
      if (data.error) return res.json({ error: data.error.message });
      const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      res.json({ reply });

    } else {
      // Default: Groq
      const allMessages = [
        { role: 'system', content: systemPrompt },
        ...messages
      ];
      const reply = await groqReq(allMessages, 2048);
      res.json({ reply });
    }
  } catch(e) {
    console.error('[chat] Error:', e.message);
    res.json({ error: e.message });
  }
});

// ── API: Knowledge Base ───────────────────────────────────────────────────────
app.get('/api/knowledge-base', (req, res) => {
  const rows = db.prepare('SELECT id, vuln_type, content, updated_at FROM knowledge_base ORDER BY vuln_type').all();
  res.json(rows);
});

app.get('/api/knowledge-base/types', (req, res) => {
  const existing = db.prepare('SELECT DISTINCT vuln_type FROM knowledge_base ORDER BY vuln_type').all().map(r => r.vuln_type);
  const fromArticles = db.prepare('SELECT DISTINCT vulnerability_type FROM articles WHERE vulnerability_type IS NOT NULL ORDER BY vulnerability_type').all().map(r => r.vulnerability_type);
  const all = [...new Set([...existing, ...fromArticles])].sort();
  res.json(all);
});

app.post('/api/knowledge-base', (req, res) => {
  const { vuln_type, content } = req.body;
  if (!vuln_type || !content) return res.status(400).json({ error: 'vuln_type and content required' });
  const stmt = db.prepare(`
    INSERT INTO knowledge_base (vuln_type, content, updated_at)
    VALUES (@vuln_type, @content, CURRENT_TIMESTAMP)
    ON CONFLICT(vuln_type) DO UPDATE SET content = @content, updated_at = CURRENT_TIMESTAMP
  `);
  const result = stmt.run({ vuln_type: vuln_type.trim(), content });
  const row = db.prepare('SELECT id, vuln_type, content, updated_at FROM knowledge_base WHERE vuln_type = ?').get(vuln_type.trim());
  res.json(row);
});

app.delete('/api/knowledge-base/:id', (req, res) => {
  const result = db.prepare('DELETE FROM knowledge_base WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ deleted: true });
});

// ── API: PATT Cache ───────────────────────────────────────────────────────────
app.get('/api/patt-cache', (req, res) => {
  const rows = db.prepare('SELECT vuln_type, length(content) as len, fetched_at FROM patt_cache ORDER BY vuln_type').all();
  res.json({ total: Object.keys(PATT_MAP).length, cached: rows });
});

app.post('/api/sync-patt', async (req, res) => {
  const https = require('https');
  const PATT_BASE = 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master';
  const upsert = db.prepare(`INSERT INTO patt_cache (vuln_type, content, fetched_at) VALUES (?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(vuln_type) DO UPDATE SET content=excluded.content, fetched_at=CURRENT_TIMESTAMP`);

  function fetchRaw(url) {
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { 'User-Agent': 'security-kb/1.0' } }, r => {
        if (r.statusCode === 302 || r.statusCode === 301) {
          return fetchRaw(r.headers.location).then(resolve).catch(reject);
        }
        let body = '';
        r.on('data', d => body += d);
        r.on('end', () => r.statusCode === 200 ? resolve(body) : reject(new Error(`HTTP ${r.statusCode}`)));
      }).on('error', reject).setTimeout(15000, function() { this.destroy(); reject(new Error('timeout')); });
    });
  }

  const synced = [], failed = [];
  for (const [vulnType, folder] of Object.entries(PATT_MAP)) {
    try {
      const encoded = encodeURIComponent(folder);
      const raw = await fetchRaw(`${PATT_BASE}/${encoded}/README.md`);
      // Take first 5000 chars — covers methodology + key payloads
      upsert.run(vulnType, raw.slice(0, 5000));
      synced.push(vulnType);
    } catch(e) {
      failed.push({ vuln_type: vulnType, error: e.message });
    }
  }
  res.json({ synced: synced.length, failed });
});

// ── API: System Status ────────────────────────────────────────────────────────
app.get('/api/system-status', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as n FROM articles').get().n;
  const labs  = db.prepare('SELECT COUNT(*) as n FROM articles WHERE lab_content IS NOT NULL').get().n;
  const last  = db.prepare('SELECT date_added FROM articles ORDER BY created_at DESC LIMIT 1').get();
  const unread = db.prepare("SELECT COUNT(*) as n FROM articles WHERE status = 'new'").get().n;

  res.json({
    articles: total,
    labs,
    unread,
    lastAdded: last ? last.date_added : null,
    uptime: Math.floor(process.uptime()),
    nodeVersion: process.version,
  });
});

// Catch-all → frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Graceful shutdown ─────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`[shutdown] Received ${signal}, closing DB and exiting...`);
  try { db.close(); } catch(e) {}
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║  Security KB Dashboard  :${PORT}            ║`);
  console.log(`║  Tailscale: <ts-ip>:${PORT}                 ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
});
