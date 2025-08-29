// server.js (CommonJS) — Relay PEC Aruba con Token+HMAC, timeouts e FAST_REPLY

const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// catturo il corpo RAW per validare l'HMAC
app.use(express.json({
  limit: '50mb',
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

/* ===== ENV OBBLIGATORIE =====
   PEC_USER:   tua casella PEC Aruba (mittente)
   PEC_PASS:   password PEC
   RELAY_TOKEN:sigillo segreto per autorizzare e firmare richieste
   ===== ENV OPZIONALI =====
   PEC_TO:         destinatario fisso (default = PEC_USER)
   MAX_ATTACH_MB:  limite allegati in MB (default 25)
   FAST_REPLY:     "true" per rispondere 202 subito e inviare in background
*/
const PEC_USER = process.env.PEC_USER;
const PEC_PASS = process.env.PEC_PASS;
const PEC_TO   = process.env.PEC_TO || PEC_USER;
const RELAY_TOKEN   = process.env.RELAY_TOKEN;
const MAX_ATTACH_MB = Number(process.env.MAX_ATTACH_MB || '25');
const FAST_REPLY    = String(process.env.FAST_REPLY || '').toLowerCase() === 'true';

if (!PEC_USER || !PEC_PASS || !RELAY_TOKEN) {
  console.error('Config mancante: servono PEC_USER, PEC_PASS, RELAY_TOKEN');
  process.exit(1);
}

// SMTP Aruba PEC con timeouts robusti
const transporter = nodemailer.createTransport({
  host: 'smtps.pec.aruba.it',
  port: 465,
  secure: true,
  auth: { user: PEC_USER, pass: PEC_PASS },
  connectionTimeout: 20000, // 20s
  greetingTimeout:   10000, // 10s
  socketTimeout:     60000  // 60s
});

// Middleware auth: token + firma HMAC del body
function verifyAuth(req, res, next) {
  if (req.method !== 'POST' || req.path !== '/mail') return next();

  const tokenHdr = req.get('X-Relay-Token') || (req.get('Authorization')||'').replace(/^Bearer\s+/i,'');
  const sigHdr   = req.get('X-Relay-Signature');

  if (!tokenHdr || tokenHdr !== RELAY_TOKEN) {
    return res.status(401).json({ ok:false, error:'Unauthorized (token)' });
  }
  if (!sigHdr) {
    return res.status(401).json({ ok:false, error:'Unauthorized (missing signature)' });
  }

  const expected = crypto.createHmac('sha256', RELAY_TOKEN)
                         .update(req.rawBody || Buffer.from(''))
                         .digest('base64');
  const a = Buffer.from(sigHdr);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ ok:false, error:'Unauthorized (bad signature)' });
  }
  next();
}
app.use(verifyAuth);

// Healthcheck
app.get('/', (_req, res) => res.send('PEC relay ok'));

// Invio PEC
app.post('/mail', async (req, res) => {
  try {
    const { subject, text, attachments } = req.body || {};
    if (!subject || !text) {
      return res.status(400).json({ ok:false, error:'subject e text sono obbligatori' });
    }

    // Prepara allegati e controlla dimensione totale
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

    // FAST_REPLY: rispondi subito 202 e invia in background
    if (FAST_REPLY) {
      res.status(202).json({ ok:true, accepted:true });
      transporter.sendMail({
        from: PEC_USER, to: PEC_TO, subject, text, attachments: atts
      }).then(info => {
        console.log('PEC inviata (async):', info.messageId);
      }).catch(err => {
        console.error('Errore invio PEC (async):', err);
      });
      return;
    }

    // Sincrono (risponde dopo l'invio reale)
    const info = await transporter.sendMail({
      from: PEC_USER, to: PEC_TO, subject, text, attachments: atts
    });
    res.json({ ok:true, messageId: info.messageId });

  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:String(e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('PEC relay in ascolto su ' + PORT + (FAST_REPLY ? ' [FAST_REPLY]' : '')));
