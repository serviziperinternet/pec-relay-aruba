// server.js — PEC relay + HEADLESS screenshot (Playwright) con Token + HMAC
// Funziona anche senza credenziali PEC: in quel caso /mail risponde 501 (non configurato).

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// nodemailer è opzionale: creiamo il transporter solo se configurato
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch (_) {}

const { chromium } = require('@playwright/test');

const app = express();

// capture RAW per HMAC
app.use(express.json({
  limit: '50mb',
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

/* ===== ENV ===== */
const RELAY_TOKEN   = process.env.RELAY_TOKEN; // obbligatorio per tutte le POST protette
const PEC_USER      = process.env.PEC_USER || '';
const PEC_PASS      = process.env.PEC_PASS || '';
const PEC_TO        = process.env.PEC_TO || PEC_USER;
const MAX_ATTACH_MB = Number(process.env.MAX_ATTACH_MB || '25');
const FAST_REPLY    = String(process.env.FAST_REPLY || '').toLowerCase() === 'true';

if (!RELAY_TOKEN) {
  console.error('Config mancante: RELAY_TOKEN è obbligatorio.');
  process.exit(1);
}

/* ===== Nodemailer (solo se PEC configurata) ===== */
let transporter = null;
if (PEC_USER && PEC_PASS && nodemailer) {
  transporter = nodemailer.createTransport({
    host: 'smtps.pec.aruba.it',
    port: 465,
    secure: true,
    auth: { user: PEC_USER, pass: PEC_PASS },
    connectionTimeout: 20000,
    greetingTimeout:   10000,
    socketTimeout:     60000
  });
}

/* ===== Auth middleware riutilizzabile ===== */
function hmacOk(req) {
  const sigHdr = req.get('X-Relay-Signature') || '';
  const expected = crypto.createHmac('sha256', RELAY_TOKEN)
                         .update(req.rawBody || Buffer.from(''))
                         .digest('base64');
  const a = Buffer.from(sigHdr);
  const b = Buffer.from(expected);
  return (a.length === b.length && crypto.timingSafeEqual(a, b));
}

function authFor(paths) {
  const set = new Set(paths);
  return (req, res, next) => {
    if (req.method !== 'POST' || !set.has(req.path)) return next();
    const tokenHdr = req.get('X-Relay-Token') || (req.get('Authorization')||'').replace(/^Bearer\s+/i,'');
    if (!tokenHdr || tokenHdr !== RELAY_TOKEN) {
      return res.status(401).json({ ok:false, error:'Unauthorized (token)' });
    }
    if (!hmacOk(req)) {
      return res.status(401).json({ ok:false, error:'Unauthorized (bad signature)' });
    }
    next();
  };
}
app.use(authFor(['/mail','/headless/screenshot']));

/* ===== Healthcheck ===== */
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    headless: true,
    pecConfigured: !!transporter,
    routes: ['/mail (PEC)','/headless/screenshot (Playwright)']
  });
});

/* ===== /mail (PEC) ===== */
app.post('/mail', async (req, res) => {
  try {
    if (!transporter) {
      return res.status(501).json({ ok:false, error:'PEC non configurata: imposta PEC_USER e PEC_PASS' });
    }
    const { subject, text, attachments } = req.body || {};
    if (!subject || !text) {
      return res.status(400).json({ ok:false, error:'subject e text sono obbligatori' });
    }
    let totalBytes = 0;
    const atts = Array.isArray(attachments) ? attachments.map(a => {
      const buf = Buffer.from(a.base64 || '', 'base64');
      totalBytes += buf.length;
      return {
        filename: a.filename || 'file.bin',
        content: buf,
        contentType: a.contentType || 'application/octet-stream'
      };
    }) : [];
    if (totalBytes > MAX_ATTACH_MB * 1024 * 1024) {
      return res.status(413).json({ ok:false, error:`Allegati troppo grandi (> ${MAX_ATTACH_MB} MB)` });
    }
    if (FAST_REPLY) {
      res.status(202).json({ ok:true, accepted:true });
      transporter.sendMail({ from: PEC_USER, to: PEC_TO, subject, text, attachments: atts })
        .then(info => console.log('PEC inviata (async):', info.messageId))
        .catch(err => console.error('Errore invio PEC (async):', err));
      return;
    }
    const info = await transporter.sendMail({ from: PEC_USER, to: PEC_TO, subject, text, attachments: atts });
    res.json({ ok:true, messageId: info.messageId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:String(e) });
  }
});

/* ===== Utility headless ===== */
async function autoScroll(page, step=800, pause=350) {
  await page.evaluate(async ({step, pause}) => {
    await new Promise(resolve => {
      let y = 0;
      const H = document.body.scrollHeight || document.documentElement.scrollHeight;
      (function down(){
        y += step; window.scrollTo(0, y);
        if (y >= H) return resolve();
        setTimeout(down, pause);
      })();
    });
  }, {step, pause});
}

/* ===== /headless/screenshot =====
Body JSON:
{
  "url": "https://example.com",
  "fullPage": true,
  "selector": null,
  "clip": null, // {x,y,width,height} in px
  "viewport": {"width":1920,"height":1080},
  "userAgent": "...",
  "extraHeaders": {"X-Foo":"Bar"},
  "waitUntil": "networkidle", // load|domcontentloaded|networkidle
  "scroll": "auto", // auto|none
  "recordVideo": false, // salva video del viewport (solo su disco locale)
  "har": true          // salva HAR (su disco locale)
}
*/
app.post('/headless/screenshot', async (req, res) => {
  const {
    url,
    fullPage = true,
    selector = null,
    clip = null,
    viewport = { width: 1920, height: 1080 },
    userAgent = null,
    extraHeaders = null,
    waitUntil = 'networkidle',
    scroll = 'auto',
    recordVideo = false,
    har = true
  } = req.body || {};

  if (!url) return res.status(400).json({ ok:false, error:'url obbligatoria' });

  let browser, context, page;
  try {
    // cartella artifacts locale (facoltativa)
    const artifactsDir = path.resolve(process.cwd(), 'artifacts');
    fs.mkdirSync(artifactsDir, { recursive: true });

    browser = await chromium.launch({ args: ['--no-sandbox'] });
    context = await browser.newContext({
      viewport,
      userAgent: userAgent || undefined,
      extraHTTPHeaders: extraHeaders || undefined,
      recordVideo: recordVideo ? { dir: artifactsDir } : undefined,
      recordHar: har ? { path: path.join(artifactsDir, 'session.har'), content: 'embed' } : undefined
    });
    page = await context.newPage();

    const resp = await page.goto(url, { waitUntil, timeout: 45000 });

    if (scroll === 'auto') {
      await autoScroll(page);
      await page.waitForTimeout(800);
    }

    let options = {};
    if (selector) {
      const el = page.locator(selector).first();
      await el.waitFor({ state: 'visible', timeout: 10000 });
      options = { clip: await el.boundingBox() };
    } else if (clip && typeof clip === 'object') {
      options = { clip };
    } else {
      options = { fullPage: !!fullPage };
    }

    const buf = await page.screenshot(options);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const pngBase64 = 'data:image/png;base64,' + buf.toString('base64');

    const finalUrl = page.url();
    const status = resp ? resp.status() : null;
    const headers = resp ? resp.headers() : null;

    // nota: HAR e Video vengono scritti su disco alla chiusura del contesto
    await context.close();
    await browser.close();

    res.json({
      ok: true,
      pngBase64,
      sha256,
      finalUrl,
      status,
      headers
      // i file su disco: artifacts/session.har e (se abilitato) artifacts/*.webm
    });
  } catch (e) {
    try { if (context) await context.close(); } catch(_){}
    try { if (browser) await browser.close(); } catch(_){}
    res.status(500).json({ ok:false, error:String(e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server attivo su http://localhost:${PORT}  (PEC:${transporter?'ON':'OFF'}; HEADLESS:ON)`));
