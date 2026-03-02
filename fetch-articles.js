#!/usr/bin/env node
// standalone pipeline: RSS → Groq score → Groq notes → dashboard
// bypasses n8n entirely; runs on demand or via cron
// Usage: node fetch-articles.js [--limit N] [--days N]

const https = require('https');
const http  = require('http');

// Load .env if present (allows running without sourcing env manually)
try { require('fs').readFileSync(require('path').join(__dirname, '.env'), 'utf8').split('\n').forEach(l => { const m = l.match(/^([A-Z_]+)=(.+)$/); if (m) process.env[m[1]] = m[2].trim(); }); } catch(e) {}

const GROQ_KEY     = process.env.GROQ_API_KEY     || 'xxxx';
const DASHBOARD    = 'http://localhost:3000/api/articles';
const MAX_ARTICLES = parseInt(process.argv[process.argv.indexOf('--limit') + 1] || '30');
const DAYS_BACK    = parseInt(process.argv[process.argv.indexOf('--days')  + 1] || '7');
const CUTOFF       = Date.now() - DAYS_BACK * 24 * 60 * 60 * 1000;

// ── RSS feed list (key sources, varied levels) ───────────────────────────────
const FEEDS = [
  { url: 'https://portswigger.net/blog/rss',                         level: 'Foundation', label: 'PortSwigger Blog' },
  { url: 'https://owasp.org/blog/feed.xml',                          level: 'Foundation', label: 'OWASP Blog' },
  { url: 'https://medium.com/feed/tag/bug-bounty',                   level: 'High',       label: 'Bug Bounty' },
  { url: 'https://medium.com/feed/tag/xss',                          level: 'Medium',     label: 'XSS' },
  { url: 'https://medium.com/feed/tag/sql-injection',                level: 'High',       label: 'SQL Injection' },
  { url: 'https://medium.com/feed/tag/ssrf',                         level: 'Critical',   label: 'SSRF' },
  { url: 'https://medium.com/feed/tag/idor',                         level: 'Medium',     label: 'IDOR' },
  { url: 'https://medium.com/feed/tag/csrf',                         level: 'Medium',     label: 'CSRF' },
  { url: 'https://medium.com/feed/tag/authentication',               level: 'High',       label: 'Auth Bypass' },
  { url: 'https://medium.com/feed/tag/jwt',                          level: 'High',       label: 'JWT Attack' },
  { url: 'https://medium.com/feed/tag/web-application-security',     level: 'Medium',     label: 'Web App Security' },
  { url: 'https://medium.com/feed/tag/penetration-testing',          level: 'Advanced',   label: 'Pentesting' },
  { url: 'https://medium.com/feed/tag/ctf',                          level: 'Medium',     label: 'CTF Writeup' },
  { url: 'https://medium.com/feed/tag/reconnaissance',               level: 'Recon',      label: 'Recon' },
  { url: 'https://medium.com/feed/tag/osint',                        level: 'Recon',      label: 'OSINT' },
  { url: 'https://medium.com/feed/tag/subdomain-takeover',           level: 'Low',        label: 'Subdomain Takeover' },
  { url: 'https://medium.com/feed/tag/command-injection',            level: 'Critical',   label: 'Command Injection' },
  { url: 'https://medium.com/feed/tag/path-traversal',               level: 'Medium',     label: 'Path Traversal' },
  { url: 'https://medium.com/feed/tag/broken-access-control',        level: 'Medium',     label: 'Broken Access Control' },
  { url: 'https://medium.com/feed/tag/prototype-pollution',          level: 'Advanced',   label: 'Prototype Pollution' },
  { url: 'https://medium.com/feed/tag/deserialization',              level: 'Expert',     label: 'Deserialization' },
  { url: 'https://medium.com/feed/tag/race-condition',               level: 'Advanced',   label: 'Race Condition' },
  { url: 'https://medium.com/feed/tag/api-security',                 level: 'High',       label: 'API Security' },
  { url: 'https://medium.com/feed/tag/cors',                         level: 'Low',        label: 'CORS Misconfig' },
];

// ── HTTP fetch ───────────────────────────────────────────────────────────────
function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const timeout = opts.timeout || 15000;
    const req = mod.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location, opts).then(resolve).catch(reject);
      }
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function post(url, data) {
  const body = JSON.stringify(data);
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const u = new URL(url);
    const req = mod.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let b = '';
      res.on('data', d => b += d);
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── RSS parser ───────────────────────────────────────────────────────────────
function parseRSS(xml, feed) {
  const items = [];
  const blocks = xml.match(/<item[\s\S]*?<\/item>/gi) || xml.match(/<entry[\s\S]*?<\/entry>/gi) || [];
  for (const block of blocks.slice(0, 10)) {
    const titleM = block.match(/<title>(?:<!\[CDATA\[)?([^\]<]+?)(?:\]\]>)?<\/title>/i);
    const linkM  = block.match(/<link>([^<]+)<\/link>/i) || block.match(/<link[^>]+href="([^"]+)"/i);
    const dateM  = block.match(/<pubDate>([^<]+)<\/pubDate>/i) ||
                   block.match(/<published>([^<]+)<\/published>/i) ||
                   block.match(/<updated>([^<]+)<\/updated>/i);
    const descM  = block.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i) ||
                   block.match(/<content:encoded>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/content:encoded>/i) ||
                   block.match(/<summary[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/summary>/i);

    const link  = linkM?.[1]?.trim();
    const title = titleM?.[1]?.trim() || 'Untitled';
    const dateStr = dateM?.[1]?.trim();
    const pubTime = dateStr ? new Date(dateStr).getTime() : Date.now();
    // strip HTML from description for context
    const rawDesc = descM?.[1] || '';
    const desc = rawDesc.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 1200);

    if (!link || !link.startsWith('http')) continue;
    if (pubTime < CUTOFF) continue;
    if (!title || title === 'Untitled' || title.length < 10) continue;

    items.push({ title, link, pub_date: dateStr || new Date().toISOString(), level: feed.level, label: feed.label, desc });
  }
  return items;
}

// ── Groq call ────────────────────────────────────────────────────────────────
async function groq(model, messages, maxTokens = 600) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, temperature: 0.15, max_tokens: maxTokens, messages }),
    timeout: 60000
  });
  const d = JSON.parse(res.body);
  if (d.error) throw new Error(d.error.message);
  return d.choices?.[0]?.message?.content || '';
}

// Override fetch to allow POST for groq
const origFetch = fetch;
async function groqRequest(messages, maxTokens, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    const body = JSON.stringify({ model: 'llama-3.3-70b-versatile', temperature: 0.15, max_tokens: maxTokens, messages });
    const result = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'api.groq.com', port: 443, path: '/openai/v1/chat/completions', method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, (res) => {
        let b = '';
        res.on('data', d => b += d);
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      });
      req.on('error', reject);
      req.setTimeout(90000, () => { req.destroy(); reject(new Error('groq timeout')); });
      req.write(body);
      req.end();
    });
    const d = JSON.parse(result.body);
    if (d.error) {
      if (result.status === 429 && attempt < retries - 1) {
        const m = d.error.message?.match(/try again in ([0-9.]+)s/i);
        const delay = m ? Math.ceil(parseFloat(m[1]) * 1000) + 500 : (attempt + 1) * 8000;
        await sleep(delay);
        continue;
      }
      throw new Error(d.error.message);
    }
    return d.choices?.[0]?.message?.content || '';
  }
}

// ── Score article with Groq ──────────────────────────────────────────────────
async function scoreArticle(title, label, desc) {
  const prompt = `You are a senior penetration tester grading security articles for a VAPT curriculum.

Score 1-10 based on practical value:
- 9-10: Original research, real bug bounty report, novel technique, real PoC with commands
- 7-8: Good technical walkthrough, working exploitation demo, detailed CTF writeup
- 5-6: Decent tutorial with some practical value
- 3-4: Generic tips, theory only, no exploitation detail
- 1-2: Clickbait, marketing, non-technical

Return ONLY valid JSON, no markdown:
{"score":8,"skip":false,"vapt_level":"Medium","category":"Client-Side Attacks","vulnerability_type":"XSS","severity":"High","tools_mentioned":["burp","xsstrike"],"one_line_summary":"One precise technical sentence","beginner_context":"2 sentences for beginners"}

If NOT about security/hacking/pentesting, return: {"skip":true,"score":0}

Allowed vapt_level values: Foundation | Recon | Low | Medium | High | Critical | Advanced | Expert
Allowed category values: Recon & Enumeration | Client-Side Attacks | Injection Attacks | Broken Access Control | Authentication & Sessions | Server-Side Attacks | API & Web Services | Cloud & Infrastructure | Exploit Chaining | Web Fundamentals
Allowed vulnerability_type values: XSS | CSRF | SQLi | SSRF | XXE | RCE | IDOR | Auth Bypass | SSTI | Open Redirect | Clickjacking | CORS | JWT Attack | OAuth Attack | GraphQL | Deserialization | File Upload | Path Traversal | Subdomain Takeover | Command Injection | Business Logic | Race Condition | Prototype Pollution | Misconfiguration | Info Disclosure | Other

Article Title: ${title}
RSS Feed Hint: ${label}
Article Snippet: ${desc.slice(0, 500)}`;

  const raw = await groqRequest([{ role: 'user', content: prompt }], 400);
  const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  return JSON.parse(cleaned);
}

// ── Generate pentest notes with Groq ────────────────────────────────────────
async function generateNotes(article, score) {
  const prompt = `Article: ${article.title}
VAPT Level: ${score.vapt_level} | Category: ${score.category} | Vuln: ${score.vulnerability_type} | Severity: ${score.severity}
Summary: ${score.one_line_summary}

Context from article:
${article.desc}

Create comprehensive educational pentest notes as this exact JSON (all fields required, no markdown):
{
  "what_is_it": "ELI5 explanation for a complete beginner. What is this vulnerability? Why does it exist? Use a real-world analogy. 3-5 sentences.",
  "mental_model": "ONE powerful analogy that makes this vulnerability click. Format: '[Vuln] is like [real-world scenario] — developer [mistake], attacker [action], result is [impact]'.",
  "memory_hook": "A single punchy sentence or mnemonic to remember this technique. Make it memorable.",
  "where_to_look": "Exactly WHERE in a web app this hides: HTTP methods, content-types, app flows (login/export/webhook), URL patterns, parameters.",
  "behavioral_indicators": "HOW TO DETECT from server behavior: response time differences, error patterns, status codes, out-of-band methods.",
  "how_to_find_it": "Step-by-step discovery methodology with tool commands.",
  "root_cause": "The developer mistake that causes this vulnerability.",
  "exploitation_walkthrough": "Step-by-step exploitation with specific commands and payloads.",
  "payloads_and_commands": "Working payloads, tool commands, one-liners. Be specific.",
  "payload_mutations": "WAF bypass techniques and payload variations when basic fails.",
  "impact": "What an attacker can achieve: data stolen, account takeover, RCE, etc.",
  "chaining_opportunities": "How this combines with other vulnerabilities for higher impact.",
  "detection_and_hunting": "How defenders detect this in logs, WAF rules, SIEM queries.",
  "remediation": "Exact code fixes and security controls to prevent this.",
  "key_takeaways": "3-5 bullet points: the most important things to remember.",
  "difficulty_tips": "Tips specific to ${score.vapt_level} level: what to focus on, common mistakes.",
  "real_world_scenario": "A realistic pentesting scenario showing how this is found in the wild.",
  "custom_header_guide": "Which HTTP headers to test and how for this vulnerability type.",
  "beginner_context": "${score.beginner_context || ''}"
}`;

  const raw = await groqRequest([
    { role: 'system', content: 'You are a senior Red Team pentester and security educator. Return ONLY valid JSON, no markdown backticks.' },
    { role: 'user', content: prompt }
  ], 4000);
  const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  return JSON.parse(cleaned);
}

// ── delay ────────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`\n[fetch-articles] Starting — max ${MAX_ARTICLES} articles, ${DAYS_BACK} days back\n`);

  let allArticles = [];

  // Fetch all feeds
  for (const feed of FEEDS) {
    try {
      const res = await origFetch(feed.url, { timeout: 12000 });
      if (res.status !== 200) { process.stdout.write('x'); continue; }
      const items = parseRSS(res.body, feed);
      allArticles.push(...items);
      process.stdout.write('.');
    } catch (e) {
      process.stdout.write('x');
    }
  }
  console.log(`\n[fetch-articles] Fetched ${allArticles.length} candidate articles from ${FEEDS.length} feeds`);

  // Shuffle and cap
  allArticles = allArticles.sort(() => Math.random() - 0.5).slice(0, MAX_ARTICLES * 3);

  let saved = 0, skipped = 0, errors = 0;

  for (const article of allArticles) {
    if (saved >= MAX_ARTICLES) break;

    try {
      // Quick dedup check via dashboard
      const check = await origFetch(`http://localhost:3000/api/articles?q=${encodeURIComponent(article.title.slice(0,30))}&limit=5`, { timeout: 3000 }).catch(() => null);
      // Score
      let score;
      try {
        score = await scoreArticle(article.title, article.label, article.desc);
      } catch (e) {
        process.stdout.write('s'); // score failed
        errors++;
        await sleep(3000);
        continue;
      }

      if (score.skip || !score.score || score.score < 6) {
        process.stdout.write('-'); // filtered out
        skipped++;
        await sleep(500);
        continue;
      }

      // Generate notes — skip article if this fails
      let notes;
      try {
        notes = await generateNotes(article, score);
        if (!notes.what_is_it) throw new Error('empty notes');
      } catch (e) {
        process.stdout.write('n'); // notes failed — skip
        await sleep(4000);
        continue;
      }

      // Build payload
      const payload = {
        date_added:               new Date().toISOString().split('T')[0],
        title:                    article.title,
        // Use feed level as primary (LLM confuses VAPT curriculum level with severity)
        // Only override if LLM gave a non-generic level (not Medium/High/Low which clash with severity)
        vapt_level:               (['Foundation','Recon','Critical','Advanced','Expert'].includes(score.vapt_level))
                                    ? score.vapt_level
                                    : article.level,
        category:                 score.category || 'Web Fundamentals',
        vulnerability_type:       score.vulnerability_type || 'Other',
        severity:                 score.severity || 'Medium',
        quality_score:            score.score,
        tools_used:               Array.isArray(score.tools_mentioned) ? score.tools_mentioned.join(', ') : '',
        source_url:               article.link,
        one_line_summary:         score.one_line_summary || '',
        beginner_context:         score.beginner_context || notes.beginner_context || '',
        what_is_it:               notes.what_is_it || '',
        how_to_find_it:           notes.how_to_find_it || '',
        root_cause:               notes.root_cause || '',
        exploitation_walkthrough: notes.exploitation_walkthrough || '',
        payloads_and_commands:    notes.payloads_and_commands || '',
        impact:                   notes.impact || '',
        chaining_opportunities:   notes.chaining_opportunities || '',
        detection_and_hunting:    notes.detection_and_hunting || '',
        remediation:              notes.remediation || '',
        key_takeaways:            notes.key_takeaways || '',
        difficulty_tips:          notes.difficulty_tips || '',
        mental_model:             notes.mental_model || '',
        behavioral_indicators:    notes.behavioral_indicators || '',
        where_to_look:            notes.where_to_look || '',
        payload_mutations:        notes.payload_mutations || '',
        custom_header_guide:      notes.custom_header_guide || '',
        real_world_scenario:      notes.real_world_scenario || '',
        memory_hook:              notes.memory_hook || '',
        status:                   'new'
      };

      const r = await post(DASHBOARD, payload);
      const result = JSON.parse(r.body);
      if (result.status === 'saved') {
        console.log(`[+] ${score.score}/10 [${score.vapt_level}/${score.severity}] ${article.title.slice(0,60)}`);
        saved++;
      } else if (result.status === 'duplicate') {
        process.stdout.write('d');
        skipped++;
      }

      // Rate limit: ~1 req/sec to Groq to stay within free tier
      await sleep(1200);

    } catch (e) {
      process.stdout.write('e');
      errors++;
      await sleep(2000);
    }
  }

  console.log(`\n[fetch-articles] Done — saved: ${saved} | skipped/dup: ${skipped} | errors: ${errors}\n`);
}

main().catch(console.error);
