#!/usr/bin/env node
// backfill-notes.js — re-generate notes for all articles missing content
// Uses Groq with retry + exponential backoff

const https = require('https');
const Database = require('/home/pavan/security-pipeline/webapp/node_modules/better-sqlite3');

// Load .env if present
try { require('fs').readFileSync(require('path').join(__dirname, '.env'), 'utf8').split('\n').forEach(l => { const m = l.match(/^([A-Z_]+)=(.+)$/); if (m) process.env[m[1]] = m[2].trim(); }); } catch(e) {}

const GROQ_KEY = process.env.GROQ_API_KEY || 'xxxx';
const DB_PATH  = '/home/pavan/security-pipeline/webapp/db/security_kb.db';

const db = new Database(DB_PATH);

// ── Groq request with retry ──────────────────────────────────────────────────
async function groqRequest(messages, maxTokens = 3000, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const body = JSON.stringify({
        model: 'llama-3.1-8b-instant',
        temperature: 0.15,
        max_tokens: maxTokens,
        messages
      });

      const result = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.groq.com', port: 443,
          path: '/openai/v1/chat/completions',
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${GROQ_KEY}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        }, (res) => {
          let b = '';
          res.on('data', d => b += d);
          res.on('end', () => resolve({ status: res.statusCode, body: b }));
        });
        req.on('error', reject);
        req.setTimeout(90000, () => { req.destroy(); reject(new Error('timeout')); });
        req.write(body);
        req.end();
      });

      const d = JSON.parse(result.body);

      if (d.error) {
        if (result.status === 429) {
          const delayMatch = d.error.message?.match(/try again in ([0-9.]+)s/i);
          const delay = delayMatch ? Math.ceil(parseFloat(delayMatch[1]) * 1000) + 1000 : 30000;
          console.log(`  [rate limit] waiting ${Math.round(delay/1000)}s...`);
          await sleep(delay);
          continue;
        }
        throw new Error(d.error.message);
      }

      const content = d.choices?.[0]?.message?.content || '';
      return content;

    } catch (e) {
      if (attempt < retries - 1) {
        const delay = (attempt + 1) * 6000;
        console.log(`  [retry ${attempt+1}] ${e.message}, waiting ${delay/1000}s...`);
        await sleep(delay);
      } else {
        throw e;
      }
    }
  }
}

// ── Generate notes ───────────────────────────────────────────────────────────
async function generateNotes(article) {
  const prompt = `Article Title: ${article.title}
VAPT Level: ${article.vapt_level} | Category: ${article.category || 'Web Security'} | Vulnerability: ${article.vulnerability_type} | Severity: ${article.severity}
Summary: ${article.one_line_summary || ''}
Beginner Context: ${article.beginner_context || ''}

You are a senior Red Team pentester. Create comprehensive pentest notes as this exact JSON.
All fields are required. No markdown backticks. Return ONLY the JSON object.

{
  "what_is_it": "ELI5 for a complete beginner: what is this vulnerability, why does it exist, what does attacker gain. Use a memorable real-world analogy (not IT). 4-5 sentences.",
  "mental_model": "ONE analogy: '[Vuln] is like [real-world scenario] — developer [mistake], attacker [action], result is [impact]'. Make it unforgettable.",
  "memory_hook": "One punchy sentence/mnemonic to remember forever. Rhyme, alliteration, or shocking fact.",
  "where_to_look": "Exactly WHERE in a web app this hides: HTTP methods, content-types (JSON/XML/multipart), app flows (login/logout/password-reset/export/webhook), URL patterns, specific parameters.",
  "behavioral_indicators": "HOW TO DETECT from server behavior (not param names): response time differences, error message patterns, HTTP status codes, response size differences, out-of-band methods (DNS pingback).",
  "how_to_find_it": "Step-by-step discovery methodology. Specific tool commands (burp, ffuf, nuclei, etc).",
  "root_cause": "The exact developer mistake: what they forgot to validate, which security control is missing.",
  "exploitation_walkthrough": "Step-by-step attack with specific commands and HTTP requests. Show the full attack chain.",
  "payloads_and_commands": "Working payloads, one-liners, curl commands. Be concrete and specific. Include multiple variants.",
  "payload_mutations": "WAF bypass techniques, encoding tricks, case variations, when basic payloads fail.",
  "impact": "Concrete impact: what data stolen, what access gained, what systems compromised. Business impact.",
  "chaining_opportunities": "How to combine with other vulns for higher impact (e.g. XSS + CSRF = account takeover).",
  "detection_and_hunting": "How defenders detect this: log patterns, WAF rules, SIEM queries, anomaly indicators.",
  "remediation": "Exact code-level fixes, security headers, input validation rules, framework-specific defenses.",
  "key_takeaways": "5 bullet points: the most critical things a pentester must remember about this vulnerability.",
  "difficulty_tips": "Tips for ${article.vapt_level} level practitioners: common mistakes, what to focus on, how to level up.",
  "real_world_scenario": "A realistic pentesting engagement scenario: target type, how discovered, exploitation steps, impact demonstrated.",
  "custom_header_guide": "Specific HTTP headers to test, inject, or monitor for this vulnerability type. Include examples.",
  "beginner_context": "${article.beginner_context || 'A beginner-friendly explanation of this vulnerability type and why it matters.'}"
}`;

  const raw = await groqRequest([
    { role: 'system', content: 'You are a senior Red Team pentester. Return ONLY valid JSON with no markdown code blocks. Never use unescaped newlines or special characters inside JSON string values — use \\n for newlines.' },
    { role: 'user', content: prompt }
  ], 1800);

  // Extract JSON block — handles markdown fences, leading text, trailing text
  let cleaned = raw;
  const fenceMatch = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) cleaned = fenceMatch[1];
  else {
    const firstBrace = raw.indexOf('{');
    const lastBrace = raw.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1) cleaned = raw.slice(firstBrace, lastBrace + 1);
  }
  cleaned = cleaned.trim();

  // Try standard parse first
  const tryParse = (s) => {
    try { return JSON.parse(s); } catch(e) { return null; }
  };

  let result = tryParse(cleaned)
    || tryParse(cleaned.replace(/,(\s*[}\]])/g, '$1'))
    || tryParse(cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' '))
    || tryParse(cleaned.replace(/[\x00-\x1F\x7F]/g, ' '));

  if (result) return result;

  // Last resort: extract each field with regex (handles unescaped quotes in values)
  const fields = ['what_is_it','mental_model','memory_hook','where_to_look',
    'behavioral_indicators','how_to_find_it','root_cause','exploitation_walkthrough',
    'payloads_and_commands','payload_mutations','impact','chaining_opportunities',
    'detection_and_hunting','remediation','key_takeaways','difficulty_tips',
    'real_world_scenario','custom_header_guide','beginner_context'];
  const extracted = {};
  for (const f of fields) {
    // Match "field": "...value..." where value ends at next "field": pattern or end of object
    const re = new RegExp(`"${f}"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`);
    const m = cleaned.match(re);
    if (m) extracted[f] = m[1].replace(/\\n/g, '\n').replace(/\\"/g, '"');
  }
  if (Object.keys(extracted).length > 3) return extracted;
  throw new Error('JSON parse failed after all attempts');
}

// ── Update article in DB ─────────────────────────────────────────────────────
const update = db.prepare(`
  UPDATE articles SET
    what_is_it = @what_is_it,
    mental_model = @mental_model,
    memory_hook = @memory_hook,
    where_to_look = @where_to_look,
    behavioral_indicators = @behavioral_indicators,
    how_to_find_it = @how_to_find_it,
    root_cause = @root_cause,
    exploitation_walkthrough = @exploitation_walkthrough,
    payloads_and_commands = @payloads_and_commands,
    payload_mutations = @payload_mutations,
    impact = @impact,
    chaining_opportunities = @chaining_opportunities,
    detection_and_hunting = @detection_and_hunting,
    remediation = @remediation,
    key_takeaways = @key_takeaways,
    difficulty_tips = @difficulty_tips,
    real_world_scenario = @real_world_scenario,
    custom_header_guide = @custom_header_guide,
    beginner_context = @beginner_context
  WHERE id = @id
`);

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
  const empty = db.prepare(`
    SELECT id, title, vapt_level, category, vulnerability_type, severity,
           one_line_summary, beginner_context, source_url
    FROM articles
    WHERE (what_is_it IS NULL OR what_is_it = '')
    ORDER BY quality_score DESC
  `).all();

  console.log(`\n[backfill] ${empty.length} articles need notes\n`);

  let done = 0, failed = 0;

  for (const article of empty) {
    console.log(`[${done + failed + 1}/${empty.length}] "${article.title.slice(0, 65)}"`);

    try {
      const notes = await generateNotes(article);

      const str = (v) => (v == null ? '' : Array.isArray(v) ? v.join('\n') : String(v));
      update.run({
        id: article.id,
        what_is_it:               str(notes.what_is_it),
        mental_model:             str(notes.mental_model),
        memory_hook:              str(notes.memory_hook),
        where_to_look:            str(notes.where_to_look),
        behavioral_indicators:    str(notes.behavioral_indicators),
        how_to_find_it:           str(notes.how_to_find_it),
        root_cause:               str(notes.root_cause),
        exploitation_walkthrough: str(notes.exploitation_walkthrough),
        payloads_and_commands:    str(notes.payloads_and_commands),
        payload_mutations:        str(notes.payload_mutations),
        impact:                   str(notes.impact),
        chaining_opportunities:   str(notes.chaining_opportunities),
        detection_and_hunting:    str(notes.detection_and_hunting),
        remediation:              str(notes.remediation),
        key_takeaways:            str(notes.key_takeaways),
        difficulty_tips:          str(notes.difficulty_tips),
        real_world_scenario:      str(notes.real_world_scenario),
        custom_header_guide:      str(notes.custom_header_guide),
        beginner_context:         str(notes.beginner_context) || str(article.beginner_context)
      });

      console.log(`  ✓ done`);
      done++;

    } catch (e) {
      console.log(`  ✗ failed: ${e.message}`);
      failed++;
    }

    // Pace requests: 8s between articles to stay within Groq free tier TPM
    await sleep(8000);
  }

  console.log(`\n[backfill] Complete — filled: ${done} | failed: ${failed}\n`);
  db.close();
}

main().catch(console.error);
