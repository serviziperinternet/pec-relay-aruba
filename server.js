// server.js (CommonJS)
const express = require('express');
const nodemailer = require('nodemailer');

const app = express();
// consenti allegati base64 fino a ~50MB
app.use(express.json({ limit: '50mb' }));

const PEC_USER = process.env.PEC_USER;   // es. [email protected]
const PEC_PASS = process.env.PEC_PASS;
const PEC_TO   = process.env.PEC_TO || PEC_USER;

if (!PEC_USER || !PEC_PASS) {
  console.error('Config mancante: impostare ENV PEC_USER e PEC_PASS');
  process.exit(1);
}

// SMTP Aruba PEC (SSL 465)
const transporter = nodemailer.createTransport({
  host: 'smtps.pec.aruba.it',
  port: 465,
  secure: true,
  auth: { user: PEC_USER, pass: PEC_PASS }
});

// Healthcheck
app.get('/', (_req, res) => res.send('PEC relay ok'));

// Invio PEC con allegati (array di {filename, base64, contentType})
app.post('/mail', async (req, res) => {
  try {
    const { subject, text, attachments } = req.body || {};
    if (!subject || !text) {
      return res.status(400).json({ ok: false, error: 'subject e text sono obbligatori' });
    }

    const atts = Array.isArray(attachments)
      ? attachments.map(a => ({
          filename: a.filename || 'file.bin',
          content: Buffer.from(a.base64 || '', 'base64'),
          contentType: a.contentType || 'application/octet-stream'
        }))
      : [];

    const info = await transporter.sendMail({
      from: PEC_USER,
      to: PEC_TO,            // invia a te stesso se PEC_TO non è impostata
      subject,
      text,
      attachments: atts
    });

    res.json({ ok: true, messageId: info.messageId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('PEC relay in ascolto su ' + PORT));
