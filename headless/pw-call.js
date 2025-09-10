// headless/pw-call.js — client di test: chiama /headless/screenshot con Token + HMAC
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RELAY_TOKEN = process.env.RELAY_TOKEN || 'devtoken'; // metti lo stesso del server
const URL_API     = process.env.API || 'http://localhost:8080/headless/screenshot';
const TARGET_URL  = process.env.URL || 'https://example.com';

(async () => {
  const body = {
    url: TARGET_URL,
    fullPage: true,
    scroll: 'auto',
    waitUntil: 'networkidle',
    har: true,
    recordVideo: false
  };
  const raw = Buffer.from(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', RELAY_TOKEN).update(raw).digest('base64');

  const res = await fetch(URL_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Relay-Token': RELAY_TOKEN,
      'X-Relay-Signature': sig
    },
    body: raw
  });
  if (!res.ok) {
    console.error('HTTP', res.status, await res.text());
    process.exit(1);
  }
  const js = await res.json();
  if (!js.ok) {
    console.error('Errore:', js.error);
    process.exit(1);
  }

  const outDir = path.resolve(process.cwd(), 'artifacts');
  fs.mkdirSync(outDir, { recursive: true });
  const png = js.pngBase64.replace(/^data:image\/png;base64,/, '');
  const outPng = path.join(outDir, 'api.png');
  fs.writeFileSync(outPng, Buffer.from(png, 'base64'));

  console.log('OK /headless/screenshot');
  console.log('URL finale:', js.finalUrl);
  console.log('HTTP status:', js.status);
  console.log('SHA256:', js.sha256);
  console.log('PNG:', outPng);
  console.log('HAR (se abilitato):', path.join(outDir, 'session.har'));
})();
