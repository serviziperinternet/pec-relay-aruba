// server.js (CommonJS) — PROTETTO con Token + HMAC
const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// catturo anche il corpo RAW per verificare HMAC
app.use(express.json({
  limit: '50mb',
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ====== CONFIG DA ENV ======
const PEC_USER = process.env.PEC_USER;   // es. [email protected]
const PEC_PASS = process.env.PEC_PASS;
const PEC_TO   = process.env.PEC_TO || PEC_USER;   // destinatario fisso (non modificabile dal client)
const RELAY_TOKEN = process.env.RELAY_TOKEN;       // TOKEN SEGRETO per autorizzare il client
const MAX_ATTACH_MB = Number(process.env.MAX_ATTACH_MB || '25'); // limite allegati per richiesta

if (!PEC_USER || !PEC_PASS || !RELAY_TOKEN) {
  console.error('Config mancante: serve PEC_USER, PEC_PASS, RELAY_TOKEN');
  process.exit(1);
}

// SMTP Aruba PEC (SSL 465)
const transporter = nodemailer.createTransport({
  host: 'smtps.pec.aruba.it',
  port: 465,
  secure: true,
  auth: { user: PEC_USER, pass: PEC_PASS }
});

// --- middleware auth: token + HMAC ---
function verifyAuth(req, res, next) {
  if (req.method !== 'POST' || req.path !== '/mail') return next();

  const token = req.get('X-Relay-Token') || req.get('Authorization')?.replace(/^Bearer\s+/i,'');
  const signature = req.get('X-Relay-Signature'); // base64 dell'HMAC SHA-256 sul body RAW

  if (!token || token !== RELAY_TOKEN) {
    return res.status(401).json({ ok:false, error:'Unauthorized (token)' });
  }

  if (!signature) {
    return res.status(401).json({ ok:false, error:'Unauthorized (missing signature)' });
  }

  const expected = crypto.createHmac('sha256', RELAY_TOKEN)
                         .update(req.rawBody || Buffer.from(''))
                         .digest('base64');

  // confronto costante
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ ok:false, error:'Unauthorized (bad signature)' });
  }

  next();
}

app.use(verifyAuth);

// Healthcheck
app.get('/', (_req, res) => res.send('PEC relay ok'));

// Invio PEC (attachments: [{filename, base64, contentType}])
app.post('/mail', async (req, res) => {
  try {
    const { subject, text, attachments } = req.body || {};
    if (!subject || !text) {
      return res.status(400).json({ ok:false, error:'subject e text sono obbligatori' });
    }

    // limiti allegati
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

    const info = await transporter.sendMail({
      from: PEC_USER,
      to: PEC_TO,    // blocchiamo il destinatario sul server (niente "to" nel body)
      subject,
      text,
      attachments: atts
    });

    res.json({ ok:true, messageId: info.messageId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:String(e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('PEC relay in ascolto su ' + PORT));
