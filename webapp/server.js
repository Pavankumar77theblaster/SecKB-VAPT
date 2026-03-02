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
];
for (const sql of migrations) {
  try { db.exec(sql); } catch(e) { /* column already exists */ }
}

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
      custom_header_guide, real_world_scenario, memory_hook, status
    ) VALUES (
      @date_added, @title, @vapt_level, @category, @vulnerability_type, @severity,
      @quality_score, @tools_used, @source_url, @one_line_summary, @beginner_context,
      @what_is_it, @how_to_find_it, @root_cause, @exploitation_walkthrough,
      @payloads_and_commands, @impact, @chaining_opportunities,
      @detection_and_hunting, @remediation, @key_takeaways, @difficulty_tips,
      @mental_model, @behavioral_indicators, @where_to_look, @payload_mutations,
      @custom_header_guide, @real_world_scenario, @memory_hook, @status
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
    status:                   d.status || 'new'
  });

  console.log(`[+] Saved: [${d.vapt_level}/${d.severity}] "${d.title.substring(0,50)}" (score:${d.quality_score})`);
  res.json({ status: 'saved', id: result.lastInsertRowid });
});

// ── API: List Articles ────────────────────────────────────────────────────────
app.get('/api/articles', (req, res) => {
  const { severity, category, vuln, status, level, search, score_min, limit = 150, offset = 0 } = req.query;

  let where = ['1=1'];
  const params = [];

  if (severity)  { where.push('severity = ?');           params.push(severity); }
  if (category)  { where.push('category = ?');           params.push(category); }
  if (vuln)      { where.push('vulnerability_type = ?'); params.push(vuln); }
  if (status)    { where.push('status = ?');             params.push(status); }
  if (level)     { where.push('vapt_level = ?');         params.push(level); }
  if (score_min) { where.push('quality_score >= ?');     params.push(parseInt(score_min)); }
  if (search) {
    where.push('(title LIKE ? OR one_line_summary LIKE ? OR key_takeaways LIKE ? OR vulnerability_type LIKE ? OR category LIKE ? OR payloads_and_commands LIKE ? OR mental_model LIKE ? OR memory_hook LIKE ?)');
    const q = `%${search}%`;
    params.push(q, q, q, q, q, q, q, q);
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
  const byStatus   = db.prepare('SELECT status, COUNT(*) as n FROM articles GROUP BY status').all();
  const bySeverity = db.prepare(`SELECT severity, COUNT(*) as n FROM articles GROUP BY severity ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END`).all();
  const byLevel    = db.prepare(`SELECT vapt_level, COUNT(*) as n FROM articles GROUP BY vapt_level ORDER BY CASE vapt_level WHEN 'Foundation' THEN 1 WHEN 'Recon' THEN 2 WHEN 'Low' THEN 3 WHEN 'Medium' THEN 4 WHEN 'High' THEN 5 WHEN 'Critical' THEN 6 WHEN 'Advanced' THEN 7 WHEN 'Expert' THEN 8 ELSE 9 END`).all();
  const byCategory = db.prepare('SELECT category, COUNT(*) as n FROM articles GROUP BY category ORDER BY n DESC').all();
  const topScoring = db.prepare('SELECT id, title, quality_score, severity, vapt_level, vulnerability_type FROM articles ORDER BY quality_score DESC LIMIT 10').all();
  const recent     = db.prepare('SELECT id, title, date_added, severity, vapt_level, category FROM articles ORDER BY created_at DESC LIMIT 10').all();
  const unread     = db.prepare("SELECT COUNT(*) as n FROM articles WHERE status = 'new'").get().n;

  res.json({ total, unread, byStatus, bySeverity, byLevel, byCategory, topScoring, recent });
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

async function groqReq(messages, maxTokens = 1500) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'llama-3.1-8b-instant', temperature: 0.15, max_tokens: maxTokens, messages }),
    signal: AbortSignal.timeout(60000)
  });
  const d = await res.json();
  if (d.error) throw new Error(d.error.message);
  return d.choices?.[0]?.message?.content || '';
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

    // 4. Generate notes
    send('progress', { stage: 'notes', message: `Generating pentest notes (${score.vulnerability_type || 'security'})...` });
    const notesRaw = await groqReq([
      { role: 'system', content: 'You are a senior Red Team pentester. Return ONLY valid JSON, no markdown backticks. Use \\n for newlines inside strings.' },
      { role: 'user', content:
        `Article: ${title}
VAPT Level: ${score.vapt_level} | Category: ${score.category} | Vuln: ${score.vulnerability_type} | Severity: ${score.severity}
Summary: ${score.one_line_summary}
Content: ${text.slice(0, 3000)}

Return this exact JSON:
{"what_is_it":"ELI5 + analogy. 4-5 sentences.","mental_model":"'[Vuln] is like [scenario] — developer [mistake], attacker [action], result is [impact]'","memory_hook":"One punchy mnemonic.","where_to_look":"Exact app locations, HTTP methods, parameters.","behavioral_indicators":"Server behavior clues: timing, errors, status codes.","how_to_find_it":"Step-by-step with tool commands.","root_cause":"The developer mistake.","exploitation_walkthrough":"Step-by-step with commands.","payloads_and_commands":"Working payloads and curl commands.","payload_mutations":"WAF bypass and encoding tricks.","impact":"What attacker gains.","chaining_opportunities":"How to chain with other vulns.","detection_and_hunting":"Log patterns, WAF rules, SIEM queries.","remediation":"Exact code fixes and headers.","key_takeaways":"5 bullet points.","difficulty_tips":"Tips for ${score.vapt_level} level.","real_world_scenario":"Realistic engagement scenario.","custom_header_guide":"Headers to test and inject.","beginner_context":"${score.beginner_context || ''}"}` }
    ], 2000);

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
        memory_hook, status
      ) VALUES (
        @date_added, @title, @vapt_level, @category, @vulnerability_type, @severity,
        @quality_score, @tools_used, @source_url, @one_line_summary, @beginner_context,
        @what_is_it, @how_to_find_it, @root_cause, @exploitation_walkthrough,
        @payloads_and_commands, @impact, @chaining_opportunities, @detection_and_hunting,
        @remediation, @key_takeaways, @difficulty_tips, @mental_model, @behavioral_indicators,
        @where_to_look, @payload_mutations, @custom_header_guide, @real_world_scenario,
        @memory_hook, @status
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
