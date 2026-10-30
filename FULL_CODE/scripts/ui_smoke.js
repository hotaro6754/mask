// Browser walkthrough of the Control Room: every page, the playground (builder, SQL, refused write), discovery scan,
// policy dialog, audit row expansion, integrity proof, API lab, identity switch and a phone-width layout.
// Fails on any JavaScript error or horizontal overflow on mobile. Writes screenshots to OUT_DIR.
// Usage: node scripts/ui_smoke.js http://127.0.0.1:8000 OUT_DIR   (needs the `playwright` npm package + Chromium)
const { chromium } = require('playwright');
(async () => {
  const base = process.argv[2], out = process.argv[3];
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1500, height: 1000 }, deviceScaleFactor: 1 });
  const errs = [];
  p.on('console', m => { if (m.type() === 'error') errs.push('console: ' + m.text()); });
  p.on('pageerror', e => errs.push('pageerror: ' + e.message));
  const shot = async (n) => { await p.waitForTimeout(500); await p.screenshot({ path: `${out}/${n}.png`, fullPage: true }); };
  await p.goto(base + '/ui/'); await p.waitForSelector('.stat .value'); await p.waitForTimeout(800); await shot('01-overview');
  await p.goto(base + '/ui/#/playground'); await p.waitForSelector('#pg-run');
  await p.click('#pg-run'); await p.waitForSelector('.results .card'); await p.waitForSelector('.integrity-strip .badge', { timeout: 15000 }); await shot('02-playground');
  // SQL mode, add auditor, preset
  await p.click('text=SQL editor'); await p.selectOption('select[aria-label="Preset queries"]', { index: 2 });
  await p.click('button.chip:has-text("auditor")'); await p.click('#pg-run'); await p.waitForTimeout(2500); await shot('03-playground-sql');
  await p.selectOption('select[aria-label="Preset queries"]', { index: 7 }); await p.click('#pg-run'); await p.waitForTimeout(2000); await shot('04-playground-refused');
  await p.goto(base + '/ui/#/discovery'); await p.waitForSelector('text=Column inventory'); await p.click('text=Dry-run scan'); await p.waitForSelector('text=DRY RUN'); await shot('05-discovery');
  await p.goto(base + '/ui/#/policy'); await p.waitForSelector('.matrix'); await shot('06-policy');
  await p.click('.matrix button.cell >> nth=8'); await p.waitForSelector('dialog[open]'); await p.waitForTimeout(600); await shot('07-policy-dialog');
  await p.click('dialog button:has-text("Cancel")');
  await p.goto(base + '/ui/#/roles'); await p.waitForSelector('text=Compare roles'); await shot('08-roles');
  await p.goto(base + '/ui/#/audit'); await p.waitForSelector('tr.clickable'); await p.click('tr.clickable >> nth=0'); await shot('09-audit');
  await p.goto(base + '/ui/#/integrity'); await p.waitForSelector('text=Run full proof'); await p.click('text=Run full proof'); await p.waitForSelector('text=Source mutation: NONE', { timeout: 20000 }); await shot('10-integrity');
  await p.goto(base + '/ui/#/api'); await p.waitForSelector('text=Send'); await p.click('button.primary:has-text("Send")'); await p.waitForSelector('text=ALLOWED'); await shot('11-api');
  await p.goto(base + '/ui/#/cli'); await p.waitForSelector('text=Command reference'); await shot('12-cli');
  await p.goto(base + '/ui/#/settings'); await p.waitForSelector('text=Configuration'); await shot('13-settings');
  // identity switch to support -> overview shows capability notes
  await p.goto(base + '/ui/#/overview'); await p.selectOption('select[aria-label="Switch demo identity"]', 'support'); await p.waitForTimeout(1500); await shot('14-overview-support');
  await p.goto(base + '/ui/#/audit'); await p.waitForTimeout(800); await shot('15-audit-support');
  // mobile
  await p.setViewportSize({ width: 390, height: 844 }); await p.goto(base + '/ui/#/playground'); await p.waitForSelector('#pg-run'); await p.click('#pg-run'); await p.waitForTimeout(2500); await shot('16-mobile');
  const overflow = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  console.log('mobile horizontal overflow px:', overflow);
  const real = errs.filter(e => !/status of 400/.test(e));  // 400s are the deliberately refused write attempts
  console.log(real.length ? real.join('\n') : 'no console errors');
  await b.close();
  if (real.length || overflow > 0) process.exit(1);
})().catch(e => { console.error('FAILED', e.message); process.exit(1); });
