#!/usr/bin/env node
// retry-failed.js — targeted retry for specific article IDs
const https = require('https');
const Database = require('/home/pavan/security-pipeline/webapp/node_modules/better-sqlite3');

try {
  require('fs').readFileSync('/home/pavan/security-pipeline/.env', 'utf8')
    .split('\n').forEach(l => {
      const m = l.match(/^([A-Z_]+)=(.+)$/);
      if (m) process.env[m[1]] = m[2].trim();
    });
} catch(e) {}

const GROQ_KEY = process.env.GROQ_API_KEY || '';
const DB_PATH  = '/home/pavan/security-pipeline/webapp/db/security_kb.db';
const MODEL    = 'llama-3.1-8b-instant';
const TARGET_IDS = [44, 14, 8, 25, 27, 36, 38, 43];

const db = new Database(DB_PATH);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function groqRequest(messages, maxTokens = 3000, retries = 10) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const body = JSON.stringify({ model: MODEL, temperature: 0.1, max_tokens: maxTokens, messages });
      const result = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.groq.com', port: 443,
          path: '/openai/v1/chat/completions', method: 'POST',
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
        req.setTimeout(120000, () => { req.destroy(); reject(new Error('timeout')); });
        req.write(body);
        req.end();
      });

      const d = JSON.parse(result.body);
      if (d.error) {
        if (result.status === 429) {
          const msg = d.error.message || '';
          const mMs = msg.match(/try again in ([0-9.]+)ms/i);
          const mS  = msg.match(/try again in ([0-9.]+)s(?!\w)/i);
          let delay;
          if (mMs)     delay = Math.ceil(parseFloat(mMs[1])) + 2000;
          else if (mS) delay = Math.ceil(parseFloat(mS[1]) * 1000) + 2000;
          else         delay = 15000;
          console.log(`  [rate limit] waiting ${Math.round(delay/1000)}s`);
          await sleep(delay);
          continue;
        }
        throw new Error(d.error.message || JSON.stringify(d.error));
      }
      return d.choices?.[0]?.message?.content || '';
    } catch(e) {
      if (attempt < retries - 1) {
        const delay = (attempt + 1) * 8000;
        console.log(`  [retry ${attempt+1}] ${e.message} — waiting ${delay/1000}s`);
        await sleep(delay);
      } else throw e;
    }
  }
  throw new Error('groqRequest: exhausted all retries');
}

const SYSTEM_PROMPT = `You are a senior Red Team professional (OSCP, BSCP, CPENT, eWPTX). Write attack briefings for junior pentesters entering live engagements.
Rules: (1) Every statement directly actionable. (2) Real tools with exact flags. Real payloads. (3) Exploitation-first. (4) Return ONLY a raw JSON object — no markdown, no code fences, no text before or after the JSON. Start your response with { and end with }.`;

function buildPrompt(article) {
  const kbEntry = db.prepare('SELECT content FROM knowledge_base WHERE vuln_type = ?').get(article.vulnerability_type || '');
  const kbContext = kbEntry ? `YOUR PREVIOUS FINDINGS FOR ${article.vulnerability_type}:\n${kbEntry.content}\n\nUse these insights to enhance and validate your analysis.\n\n` : '';
  return `${kbContext}Vuln: ${article.vulnerability_type} | Level: ${article.vapt_level} | Severity: ${article.severity}
Title: ${article.title}
Summary: ${article.one_line_summary || ''}

Return ONLY this JSON — fill every field with actionable, technical, hands-on content. No markdown fences. Use \\n inside strings for newlines:
{"what_is_it":"CWE#. OWASP category. Trust boundary violated. Attacker primitive (read/write/exec/pivot). Root cause. Real CVEs or frameworks affected. 4-step attack lifecycle.","mental_model":"Attack trigger 1 sentence. HTTP-level breakdown. Raw HTTP request showing the bug. Vulnerable vs patched response diff. Code snippet of the mistake.","key_takeaways":"7 terms: TERM: attack-context definition | Pentest use: how used in engagement | Connected to: related vulns/techniques","exploitation_walkthrough":"3 test cases. Each: Name\\nTarget: endpoint/param\\nVerify: command\\nExploit: exact curl or Burp\\nExpected: response\\nImpact: outcome","chaining_opportunities":"3 chains: VulnA → how enables → VulnB → impact. Escalation: initial→intermediate→max. Post-exploit: what to enumerate/pivot first.","difficulty_tips":"Interview scenario Q (specific target, realistic constraint). Answer bullets. 4 follow-ups. Junior mistakes.","how_to_find_it":"6-step recon checklist with exact commands. Nuclei template. Burp scan issue. What scanners miss.","payloads_and_commands":"BASIC: minimal payload\\nENCODED: filter bypass\\nBLIND/OOB: interactsh callback\\nPOLYGLOT: works in HTML/JS/attr\\nsqlmap: exact flags\\nffuf: seclists path\\nnuclei: template path","payload_mutations":"8 WAF bypass techniques. Each: technique | modified payload | why it works. Cover: double-encode, case, comments, whitespace, chunked, param pollution, unicode, null byte.","where_to_look":"URL params to test. Headers to inject. Body fields. HTTP methods. App flows: file upload/reset/export/webhook/OAuth.","behavioral_indicators":"6 signals: time-based (sleep probe→delay), error-based (probe→error msg), size-based, status-based (500/302), OOB callback, header diff. Baseline first.","root_cause":"CWE-#: name. 1-sentence cause. Vulnerable pseudocode. What's missing. Secure equivalent code.","impact":"Data accessible. Actions possible. Lateral movement path. CVSS v3.1 score+vector. Compliance violation (GDPR/PCI/HIPAA).","detection_and_hunting":"Splunk: query. Elastic: query. Key log fields. Network IOC. WAF rule (ModSecurity/AWS). Anomaly: normal vs attack traffic.","remediation":"Vulnerable snippet. Fixed snippet. Security API/library. Required headers. Input validation rule.","real_world_scenario":"200+ word bug bounty story (first person). Target, recon, endpoint found, full exploit chain with commands, impact, program response.","custom_header_guide":"Table: Header | Inject value | Success indicator | curl command. 8+ headers relevant to this vuln type.","memory_hook":"If [recon signal] → immediately test [specific attack]. One-liner muscle memory rule.","beginner_context":"3 prerequisites. Read-first link (OWASP/PortSwigger/HackTricks). Most critical concept."}`;
}

async function generateNotes(article) {
  const raw = await groqRequest([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user',   content: buildPrompt(article) }
  ], 3000);

  const fenceMatch = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  let cleaned = fenceMatch ? fenceMatch[1] : raw;
  const fi = cleaned.indexOf('{'), li = cleaned.lastIndexOf('}');
  if (fi !== -1 && li !== -1) cleaned = cleaned.slice(fi, li + 1);
  cleaned = cleaned.trim();

  const tryParse = (s) => { try { return JSON.parse(s); } catch(e) { return null; } };

  let result = tryParse(cleaned)
    || tryParse(cleaned.replace(/,(\s*[}\]])/g, '$1'))
    || tryParse(cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' '));

  if (result) return result;

  const FIELDS = ['what_is_it','mental_model','key_takeaways','exploitation_walkthrough',
    'chaining_opportunities','difficulty_tips','how_to_find_it','payloads_and_commands',
    'payload_mutations','where_to_look','behavioral_indicators','root_cause',
    'impact','detection_and_hunting','remediation','real_world_scenario',
    'custom_header_guide','memory_hook','beginner_context'];
  const extracted = {};
  for (const f of FIELDS) {
    const re = new RegExp(`"${f}"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`);
    const m = cleaned.match(re);
    if (m) extracted[f] = m[1].replace(/\\n/g, '\n').replace(/\\"/g, '"');
  }
  if (Object.keys(extracted).length > 5) return extracted;
  throw new Error('JSON parse failed after all attempts');
}

const updateStmt = db.prepare(`
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

async function main() {
  const articles = db.prepare(
    `SELECT id, title, vapt_level, category, vulnerability_type, severity, one_line_summary
     FROM articles WHERE id IN (${TARGET_IDS.join(',')}) ORDER BY quality_score DESC`
  ).all();

  console.log(`\n[retry] ${articles.length} articles to process: ${articles.map(a => a.id).join(', ')}\n`);

  let done = 0, failed = 0;
  const str = v => v == null ? '' : Array.isArray(v) ? v.join('\n') : String(v);

  for (const article of articles) {
    console.log(`[${done + failed + 1}/${articles.length}] id=${article.id} [${article.vapt_level}/${article.severity}] "${article.title.slice(0, 70)}"`);
    try {
      const notes = await generateNotes(article);
      updateStmt.run({
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
        beginner_context:         str(notes.beginner_context)
      });
      console.log(`  saved`);
      done++;
    } catch(e) {
      console.log(`  failed: ${e.message}`);
      failed++;
    }
    if (done + failed < articles.length) await sleep(8000);
  }

  console.log(`\n[retry] Done — ${done} saved | ${failed} failed\n`);
  db.close();
}

main().catch(console.error);
