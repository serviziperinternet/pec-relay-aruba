// headless/pw-smoke.js
// Prova fumo: apre un URL e salva uno screenshot fullPage in artifacts/smoke.png

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

(async () => {
  const url = process.env.URL || 'https://example.com/';
  const outDir = path.resolve(__dirname, '..', 'artifacts');
  const outPng = path.join(outDir, 'smoke.png');

  fs.mkdirSync(outDir, { recursive: true });

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordHar: { path: path.join(outDir, 'smoke.har'), content: 'embed' }
  });
  const page = await context.newPage();

  try {
    const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });
    if (!resp) throw new Error('Nessuna risposta HTTP (resp=null)');

    // scroll per risvegliare lazy-load
    await page.evaluate(async () => {
      await new Promise(res => {
        let y = 0, H = document.body.scrollHeight || document.documentElement.scrollHeight;
        (function down() {
          y += 800; window.scrollTo(0, y);
          if (y >= H) return res();
          setTimeout(down, 250);
        })();
      });
    });
    await page.waitForTimeout(800);

    const buf = await page.screenshot({ fullPage: true });
    fs.writeFileSync(outPng, buf);

    const sha256 = require('crypto').createHash('sha256').update(buf).digest('hex');
    console.log('OK smoke test');
    console.log('URL finale:', page.url());
    console.log('HTTP status:', resp.status());
    console.log('PNG:', outPng);
    console.log('HAR:', path.join(outDir, 'smoke.har'));
    console.log('SHA256:', sha256);
  } catch (e) {
    console.error('ERRORE smoke test:', e && e.message ? e.message : e);
    process.exitCode = 1;
  } finally {
    await context.close();
    await browser.close();
  }
})();
