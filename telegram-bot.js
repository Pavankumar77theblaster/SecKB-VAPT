#!/usr/bin/env node
// telegram-bot.js — Pentest Resource Bot (@Pentest_resource_bot)
// Send any URL → bot imports it via SecKB /api/import-url SSE endpoint

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');

// Load .env from same directory as this script
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n').forEach(l => {
    const m = l.match(/^([A-Z_]+)=(.+)$/);
    if (m) process.env[m[1]] = m[2].trim();
  });
} catch(e) {}

const TOKEN   = process.env.TELEGRAM_TOKEN || '';
const API_URL = `https://api.telegram.org/bot${TOKEN}`;
const KB_URL  = 'http://localhost:3000';

if (!TOKEN) {
  console.error('[bot] FATAL: TELEGRAM_TOKEN not set. Add it to .env file.');
  process.exit(1);
}

let offset = 0;

// ── Telegram helpers ──────────────────────────────────────────────────────────
function tgRequest(method, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TOKEN}/${method}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('JSON parse failed: ' + data.slice(0, 100))); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload);
    req.end();
  });
}

function sendMessage(chatId, text, opts = {}) {
  return tgRequest('sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', ...opts });
}

function editMessage(chatId, messageId, text) {
  return tgRequest('editMessageText', { chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML' });
}

// ── SSE import from SecKB ─────────────────────────────────────────────────────
function importUrl(url) {
  return new Promise((resolve, reject) => {
    const endpoint = `${KB_URL}/api/import-url?url=${encodeURIComponent(url)}`;

    http.get(endpoint, { headers: { 'Accept': 'text/event-stream' } }, res => {
      let buf = '';

      res.on('data', chunk => {
        buf += chunk.toString();

        // SSE blocks are separated by \n\n
        const blocks = buf.split('\n\n');
        buf = blocks.pop(); // keep incomplete block in buffer

        for (const block of blocks) {
          if (!block.trim()) continue;

          const lines = block.split('\n');
          let eventType = 'message';
          let dataStr = '';

          for (const line of lines) {
            if (line.startsWith('event: ')) eventType = line.slice(7).trim();
            else if (line.startsWith('data: ')) dataStr = line.slice(6).trim();
          }

          let data = {};
          try { data = JSON.parse(dataStr); } catch(e) {}

          if (eventType === 'done') {
            resolve({ success: true, ...data });
          } else if (eventType === 'error') {
            resolve({ success: false, message: data.message || 'Unknown error' });
          }
          // 'progress' events are informational — ignore for now
        }
      });

      res.on('end', () => {
        // Stream ended without a done/error — treat as error
        resolve({ success: false, message: 'Import stream ended unexpectedly' });
      });

      res.on('error', err => {
        reject(err);
      });

    }).on('error', err => {
      reject(err);
    });
  });
}

// ── Message handler ───────────────────────────────────────────────────────────
async function handleMessage(msg) {
  const chatId = msg.chat.id;
  const text   = (msg.text || '').trim();

  if (text === '/start' || text === '/help') {
    await sendMessage(chatId,
      `🔐 <b>Pentest Resource Bot</b>\n\n` +
      `Send me any security article URL and I'll add it to your SecKB knowledge base.\n\n` +
      `<b>Supported sources:</b>\n` +
      `• Medium / HackerNoon\n` +
      `• PortSwigger / OWASP\n` +
      `• CTF writeups and blog posts\n` +
      `• Any public security article URL\n\n` +
      `<b>Example:</b>\n` +
      `<code>https://medium.com/...</code>\n\n` +
      `The bot will fetch the article, score it with AI, generate pentest notes, and save it to your dashboard.`
    );
    return;
  }

  // Extract URL from message
  const urlMatch = text.match(/https?:\/\/[^\s]+/);
  if (!urlMatch) {
    await sendMessage(chatId,
      `📎 Please send me a URL to import an article.\n\nType /help for instructions.`
    );
    return;
  }

  const url = urlMatch[0].replace(/[)>.,]+$/, ''); // strip trailing punctuation

  // Send initial status message
  let statusMsg;
  try {
    statusMsg = await sendMessage(chatId,
      `⏳ <b>Importing article...</b>\n\n` +
      `🔗 <code>${url.slice(0, 60)}${url.length > 60 ? '...' : ''}</code>\n\n` +
      `Stage 1/4: Fetching article from URL...`
    );
  } catch(e) {
    console.error('[bot] Failed to send status message:', e.message);
    return;
  }

  const msgId = statusMsg.result?.message_id;

  try {
    const result = await importUrl(url);

    if (result.success) {
      const reply =
        `✅ <b>Added to SecKB!</b>\n\n` +
        `📌 <b>${result.title || 'Article'}</b>\n\n` +
        `⭐ Score: ${result.score || '?'}/10  |  ${result.vapt_level || '?'}  |  ${result.severity || '?'}  |  ${result.vulnerability_type || '?'}\n\n` +
        `🔗 <a href="${KB_URL}">Open Dashboard</a>`;

      if (msgId) {
        await editMessage(chatId, msgId, reply);
      } else {
        await sendMessage(chatId, reply);
      }
    } else {
      const errMsg = result.message || 'Import failed';
      const reply =
        `❌ <b>Import failed</b>\n\n` +
        `${errMsg}\n\n` +
        (errMsg.toLowerCase().includes('already') ? `💡 This article is already in your knowledge base.` :
         `💡 Make sure the URL is a public security article and try again.`);

      if (msgId) {
        await editMessage(chatId, msgId, reply);
      } else {
        await sendMessage(chatId, reply);
      }
    }

  } catch(e) {
    console.error('[bot] Import error:', e.message);
    const reply =
      `❌ <b>Connection error</b>\n\n` +
      `Could not reach the SecKB server. Make sure it's running on port 3000.\n\n` +
      `<code>${e.message}</code>`;

    try {
      if (msgId) await editMessage(chatId, msgId, reply);
      else await sendMessage(chatId, reply);
    } catch(e2) {}
  }
}

// ── Long polling loop ─────────────────────────────────────────────────────────
async function poll() {
  try {
    const data = await tgRequest('getUpdates', { offset, timeout: 30, allowed_updates: ['message'] });

    if (!data.ok) {
      console.error('[bot] getUpdates error:', JSON.stringify(data));
      await sleep(5000);
      return;
    }

    for (const update of (data.result || [])) {
      offset = update.update_id + 1;

      if (update.message) {
        handleMessage(update.message).catch(e => {
          console.error('[bot] handleMessage error:', e.message);
        });
      }
    }

  } catch(e) {
    console.error('[bot] Poll error:', e.message);
    await sleep(5000);
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`\n[bot] Pentest Resource Bot starting...`);

  // Verify bot token
  try {
    const me = await tgRequest('getMe', {});
    if (me.ok) {
      console.log(`[bot] Logged in as @${me.result.username} (${me.result.first_name})`);
    } else {
      console.error('[bot] Token invalid:', me.description);
      process.exit(1);
    }
  } catch(e) {
    console.error('[bot] Could not connect to Telegram:', e.message);
    process.exit(1);
  }

  console.log(`[bot] Polling for messages... (SecKB at ${KB_URL})\n`);

  // Run poll loop indefinitely
  while (true) {
    await poll();
  }
}

process.on('SIGINT',  () => { console.log('\n[bot] Stopped.'); process.exit(0); });
process.on('SIGTERM', () => { console.log('\n[bot] Stopped.'); process.exit(0); });

main().catch(e => { console.error('[bot] Fatal:', e.message); process.exit(1); });
