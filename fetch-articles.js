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

// ── Knowledge Base: read user's custom findings per vuln type ─────────────────
let kbDb = null;
try {
  const DB = require('/home/pavan/security-pipeline/webapp/node_modules/better-sqlite3');
  kbDb = new DB('/home/pavan/security-pipeline/webapp/db/security_kb.db', { readonly: true });
} catch(e) { /* KB not available */ }

function getKbContext(vulnType) {
  if (!kbDb || !vulnType) return '';
  try {
    const kbRow   = kbDb.prepare('SELECT content FROM knowledge_base WHERE vuln_type = ?').get(vulnType);
    const pattRow = kbDb.prepare('SELECT content FROM patt_cache WHERE vuln_type = ?').get(vulnType);
    const kbCtx   = kbRow   ? `YOUR PREVIOUS FINDINGS FOR ${vulnType}:\n${kbRow.content}\n\nUse these insights to enhance and validate your analysis.\n\n` : '';
    const pattCtx = pattRow ? `=== PayloadsAllTheThings Reference (${vulnType}) ===\n${pattRow.content.slice(0,2500)}\n===\n\n` : '';
    return kbCtx + pattCtx;
  } catch(e) { return ''; }
}
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

  // ── Followed authors & publications ─────────────────────────────────────────
  { url: 'https://medium.com/feed/@xalgord',                         level: 'High',       label: 'Krishna Kumar' },
  { url: 'https://medium.com/feed/@jatin.b.rx3',                    level: 'High',       label: 'Jatin Banga' },
  { url: 'https://medium.com/feed/@P4RAD0X',                        level: 'High',       label: 'PARADOX' },
  { url: 'https://medium.com/feed/@iamgk808',                       level: 'High',       label: 'iamgk808' },
  { url: 'https://medium.com/feed/@lostsec',                        level: 'High',       label: 'Lostsec' },
  { url: 'https://medium.com/feed/@bugbounty_learners',             level: 'Medium',     label: 'bugbounty_learners' },
  { url: 'https://medium.com/feed/@bugbountycenter',                level: 'High',       label: 'BugBounty.Center' },
  { url: 'https://medium.com/feed/@bugbsurveys',                    level: 'Medium',     label: 'Bugbounty Surveys' },
  { url: 'https://medium.com/feed/@leetsec',                        level: 'High',       label: 'LeetSec' },
  { url: 'https://medium.com/feed/bug-bounty-hunting-a-comprehensive-guide-in', level: 'Medium', label: 'BB Guide EN+FR' },
  { url: 'https://medium.com/feed/xmxa-bug',                        level: 'High',       label: 'XMXA-AI-BUG' },
  { url: 'https://medium.com/feed/bug-bounty-hunting',              level: 'High',       label: 'Bug Bounty Hunting' },
  { url: 'https://medium.com/feed/pinoywhitehat',                   level: 'High',       label: 'Pinoy White Hat' },
  { url: 'https://medium.com/feed/infosec-notes',                   level: 'High',       label: 'Mr.Horbio Notes' },
  { url: 'https://medium.com/feed/bug-bounty',                      level: 'High',       label: 'Bug Bounty Pub' },
  { url: 'https://medium.com/feed/bug-bounty-writeups',             level: 'High',       label: 'BB Writeups' },
  { url: 'https://medium.com/feed/bugbountytips',                   level: 'High',       label: 'BugBountyTips' },
  { url: 'https://medium.com/feed/bountynuggets',                   level: 'High',       label: 'Bug Bounty Nuggets' },
  { url: 'https://medium.com/feed/intigriti',                       level: 'Advanced',   label: 'intigriti' },
  { url: 'https://medium.com/feed/hackenproof',                     level: 'Advanced',   label: 'HackenProof' },
  { url: 'https://medium.com/feed/hackenproof-bug-bounty',          level: 'High',       label: 'HackenProof BB' },
  { url: 'https://medium.com/feed/bug-bounty-infosec',              level: 'High',       label: 'Bug Bounty & InfoSec' },
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

    // Extract images from RSS HTML content
    const images = [];
    const ogImg = rawDesc.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
                  || rawDesc.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    if (ogImg?.[1]) images.push(ogImg[1]);
    const imgRe = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
    let imgM;
    while ((imgM = imgRe.exec(rawDesc)) !== null && images.length < 6) {
      const src = imgM[1];
      if (src.startsWith('http') && !images.includes(src) &&
          !/(pixel|tracker|badge|avatar|icon|logo|emoji|1x1|spacer|ads|count)/i.test(src) &&
          !src.endsWith('.svg') && src.includes('.')) {
        images.push(src);
      }
    }

    if (!link || !link.startsWith('http')) continue;
    if (pubTime < CUTOFF) continue;
    if (!title || title === 'Untitled' || title.length < 10) continue;

    items.push({ title, link, pub_date: dateStr || new Date().toISOString(), level: feed.level, label: feed.label, desc, images });
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
  const prompt = `Vulnerability: ${score.vulnerability_type} | VAPT Level: ${score.vapt_level} | Severity: ${score.severity}
Article: ${article.title}
Context: ${article.desc.slice(0, 800)}

Write attack-ready pentest notes. No theory. No analogies. Write as if briefing a pentester going into a live target right now. Return ONLY this JSON (no markdown):
{
  "what_is_it": "Technical definition: what trust boundary is violated, what the attacker primitive is (read/write/execute/redirect/exfil), which CWE applies. Name the OWASP Top 10 category. 3 sentences, pure technical.",
  "mental_model": "Attack trigger: the exact condition that makes this fire — input point, missing control, and resulting attacker action. One sentence like: 'When [app does X without validating Y], send [payload Z] to [endpoint] and gain [primitive]'.",
  "memory_hook": "The one-liner rule a pentester keeps in their head during recon. E.g. 'If user-supplied data reaches [sink] without [control] — test it.'",
  "where_to_look": "Attack surface enumeration: list every injection point — URL path segments, query params (name common ones: id, url, redirect, file, cmd, template), HTTP headers (Host, Origin, Referer, X-Forwarded-For, X-Forwarded-Host, Content-Type, Authorization), request body fields (JSON keys, XML nodes, multipart parts), GraphQL arguments, WebSocket messages, file upload fields. Include which HTTP methods expose it (GET/POST/PUT/PATCH).",
  "behavioral_indicators": "Differential signals during probing (no guessing — server behavior): 1) time-based: response delay >2s on sleep/waitfor payload 2) error-based: stack traces, DB errors, path disclosure in response 3) size-based: response body length change >20% 4) status-based: 500 on injection, 302 on auth bypass 5) OOB: DNS callback to Burp Collaborator or interactsh. Format each as 'If [probe] → observe [signal]'.",
  "how_to_find_it": "Numbered recon steps with copyable commands. Step 1: passive recon command. Step 2: active fuzzing command (ffuf/nuclei/sqlmap with flags). Step 3: manual Burp verification. Step 4: confirm vuln. Include exact flags, wordlist paths (/usr/share/seclists/...), and what to look for in output.",
  "root_cause": "CWE-[number]: [name]. Missing control: [exactly what was not implemented]. Vulnerable code pattern: show pseudocode or language-specific snippet of the mistake (e.g. string concatenation in SQL, innerHTML without sanitization, SSRF via unchecked URL parameter).",
  "exploitation_walkthrough": "BURP SUITE MANUAL TESTING WORKFLOW:\\nSetup: Proxy → Intercept ON → browse target in Burp browser → HTTP History → Send relevant request to Repeater.\\nStep 1 BASELINE: Send unmodified request in Repeater. Note status code, body length, key headers. This is your comparison point.\\nStep 2 PROBE: Modify [parameter/header] → insert probe payload → Send → look for [error/reflection/redirect/timing change] in Response tab. Explain WHY this probe reveals the vulnerability.\\nStep 3 CONFIRM: Replace probe with exploit payload → Send → confirm [exact success indicator: string in body / status code / header value]. Explain what the response proves.\\nStep 4 ESCALATE: [how to escalate from proof to maximum impact — data exfil, ATO, pivoting]. Burp Intruder for mass testing: Positions → mark §payload§ → Payloads: Simple list → /usr/share/seclists/[path] → Start Attack → sort by Length.\\n\\nTEST CASE 1 — [Basic exploitation name]:\\nTarget endpoint + parameter + HTTP method. Burp Repeater tab: show the raw HTTP request with payload in place. Success indicator: [exact response difference]. What this proves: [impact]. Report evidence: [what to screenshot].\\nTEST CASE 2 — [Authenticated or higher-impact variant]: [Same structure].\\nTEST CASE 3 — [Filter bypass or WAF evasion]: [Same structure with bypass technique explained].",
  "payloads_and_commands": "Ready-to-fire payloads only — no prose. Group by type: [BASIC]: the minimal working payload. [ENCODED]: URL/HTML/Unicode encoded variant. [BLIND]: OOB callback payload (Burp Collaborator URL). [POLYGLOT]: works across multiple contexts. [TOOL]: sqlmap/ffuf/nuclei/xsstrike command with flags. Each on its own line.",
  "payload_mutations": "WAF bypass table — 5+ techniques: [technique name]: [modified payload] — [why it bypasses]. Cover: URL double-encoding, case variation, comment injection (/**/, %0a), whitespace substitution, chunked encoding, parameter pollution (param=a&param=b), null byte injection, unicode normalization.",
  "impact": "Concrete attacker outcomes: 1) what data is accessible (table names, file paths, env vars) 2) what actions are possible (account takeover, file write, RCE, SSRF pivot) 3) lateral movement path 4) estimated CVSS v3 score [n.n] with vector string AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Business impact: data breach notification cost, compliance violation (GDPR/PCI/HIPAA).",
  "chaining_opportunities": "Attack chains with logical steps: [Vuln A] → [how it enables] → [Vuln B] → [final impact]. E.g. 'IDOR on /api/users/{id} leaks admin email → use in password reset → account takeover → SSRF via admin panel → internal network scan'. List 2-3 chains.",
  "detection_and_hunting": "SOC/Blue Team detection. Splunk query: [query]. Elastic query: [query]. Log field patterns: [field] contains [value]. Network IOC: [pattern]. WAF rule snippet: [rule]. Anomaly: [what looks different from baseline traffic].",
  "remediation": "Code-level fix — show vulnerable snippet vs fixed snippet side by side. Specific framework API (e.g. PreparedStatement, DOMPurify.sanitize(), parameterize()). Security headers with exact values (CSP, X-Frame-Options, etc.). Input validation rule. Library/version upgrade if applicable.",
  "key_takeaways": "5 numbered tactical notes from attacker POV: 1) what you must always check 2) what automated scanners miss that manual testing finds 3) most common false positive to eliminate 4) the one header/parameter that most frequently reveals this 5) the fastest way to confirm exploitability in a time-boxed engagement.",
  "difficulty_tips": "For ${score.vapt_level} level practitioners — what trips people up at this stage: common dead-ends, when to move on vs dig deeper, what a scanner won't catch, the manual check that confirms it. Be specific about tools and approaches for this level.",
  "real_world_scenario": "Bug bounty / pentest engagement story (200+ words): target type (SaaS/fintech/e-commerce/healthcare), initial recon phase with tool output snippet, exact parameter/endpoint where vuln found, full exploitation chain with commands, what was exfiltrated/demonstrated, how it was reported, severity awarded. Write in first person past tense as if debriefing.",
  "custom_header_guide": "Header injection table — each row: [Header Name] | [Value to inject] | [Indicator of success]. Cover: Host header (SSRF, password reset poisoning), X-Forwarded-For (IP restriction bypass), Origin (CORS misconfiguration), Referer (info leak, CSRF), Content-Type (XXE switch, JSON→form), X-HTTP-Method-Override (method restriction bypass), Authorization (JWT none alg, Bearer null). Include the curl -H flag for each.",
  "beginner_context": "The minimum a junior pentester must understand before attempting this: what background knowledge is required, what to read first, and the single most important concept to grasp."
}`;

  const kbContext = getKbContext(score.vulnerability_type);
  const raw = await groqRequest([
    { role: 'system', content: 'You are a senior Red Team professional (OSCP, BSCP, CPENT, eWPTX) writing structured pentest playbooks. RULES: (1) Manual testing = Burp Suite workflow (Proxy→Intercept→Repeater→Intruder). Never use curl for manual steps — curl is only for automation. (2) For every Burp step: which tool, what to modify, what to look for in Response tab, what it proves. (3) Every step must explain WHY — a step without the reason is useless. (4) Real tool flags, real seclists paths. Return ONLY valid JSON. Start with { end with }. No markdown fences.' },
    { role: 'user', content: kbContext + prompt }
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
        image_urls:               article.images || [],
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
