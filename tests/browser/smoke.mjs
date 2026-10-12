import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const {chromium} = process.env.PLAYWRIGHT_MODULE
  ? await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href)
  : await import('playwright');
const python = process.env.PYTHON || 'python';
const child = spawn(python, ['run.py', 'serve', '--port', '0'], {stdio: ['ignore', 'pipe', 'pipe']});
const base = await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('Server startup timeout')), 20000);
  child.once('error', (error) => {clearTimeout(timeout); reject(error);});
  child.stdout.on('data', (chunk) => {
    const match = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+\//);
    if (match) {clearTimeout(timeout); resolve(match[0]);}
  });
  child.once('exit', (code) => {clearTimeout(timeout); reject(new Error(`Server exit ${code}`));});
});
let browser;
try {
  browser = await chromium.launch({headless: true});
  await mkdir('test-results', {recursive: true});
  const fixture = spawnSync(python, ['-c', 'from tests.fixtures import make_zip; import base64; print(base64.b64encode(make_zip([(\"../escape.exe\", b\"synthetic\"), (\"inner.zip\", b\"synthetic\"), (\"<img src=x onerror=alert(1)>.txt\", b\"synthetic\"), (\"a\\u202etxt\", b\"synthetic\")])).decode())'], {encoding: 'utf8'});
  assert.equal(fixture.status, 0, fixture.stderr);
  const zip = Buffer.from(fixture.stdout.trim(), 'base64');
  const digest = createHash('sha256').update(zip).digest('hex');
  const errors = [];
  for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844], ['compact', 360, 800]]) {
    const context = await browser.newContext({viewport: {width, height}, acceptDownloads: true});
    const page = await context.newPage();
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('dialog', () => errors.push('Unexpected dialog'));
    page.on('request', (request) => {
      if (!request.url().startsWith(base) && !request.url().startsWith('blob:')) errors.push(`External request: ${request.url()}`);
    });
    await page.goto(base);
    await page.locator('#file').setInputFiles({name: 'portfolio.zip', mimeType: 'application/zip', buffer: zip});
    await page.locator('#expected').fill(digest);
    await page.locator('#inspect').click();
    await page.locator('#message').filter({hasText: '검사 완료'}).waitFor();
    assert.equal(await page.locator('#integrity').textContent(), '기준값 일치');
    assert.equal(await page.locator('#risk').textContent(), '높음');
    assert.match(await page.locator('#findings').textContent(), /경로 탈출/);
    assert.equal(await page.locator('#findings img').count(), 0);
    assert.match(await page.locator('#findings').textContent(), /\\u202e/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Horizontal overflow');
    assert.equal(await page.locator('img').evaluateAll((images) => images.every((i) => i.complete && i.naturalWidth > 0)), true);
    await page.screenshot({path: `test-results/${name}.png`, fullPage: true});
    await page.locator('[data-tab=members]').click();
    assert.equal(await page.locator('#members tr').count(), 4);
    await page.locator('#search').fill('inner');
    assert.equal(await page.locator('#members tr').count(), 1);
    await page.locator('[data-tab=json]').click();
    const report = JSON.parse(await page.locator('#json-panel').textContent());
    assert.equal(report.assessment.safe_to_open, null);
    assert.equal(report.archive.crc_check, 'not_performed');
    const downloading = page.waitForEvent('download');
    await page.locator('#export').click();
    const download = await downloading;
    assert.equal(download.suggestedFilename(), 'inspection-report.json');
    await download.saveAs(`test-results/${name}-report.json`);
    await page.locator('#reset').click();
    assert.equal(await page.locator('#results').isVisible(), false);
    assert.equal(await page.locator('#inspect').isDisabled(), true);
    await page.locator('#file').setInputFiles({name: 'sample.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic')});
    await page.locator('#inspect').click();
    await page.locator('#message').filter({hasText: '검사 완료'}).waitFor();
    assert.match(await page.locator('#integrity').textContent(), /판단 불가/);
    await page.locator('#expected').fill('0'.repeat(64));
    await page.locator('#inspect').click();
    await page.locator('#integrity').filter({hasText: '기준값 불일치'}).waitFor();
    await context.close();
  }
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(base);
  let release;
  let entered;
  const intercepted = new Promise((resolve) => {entered = resolve;});
  await page.route('**/api/inspect', async (route) => {
    entered();
    await new Promise((resolve) => {release = resolve;});
    await route.abort().catch(() => {});
  });
  await page.locator('#file').setInputFiles({name: 'cancel.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic')});
  await page.locator('#inspect').click();
  await intercepted;
  await page.locator('#cancel').click();
  await page.locator('#message').filter({hasText: '검사 취소됨'}).waitFor();
  release();
  await page.unrouteAll({behavior: 'wait'});
  await page.locator('#reset').click();
  await context.close();
  assert.deepEqual(errors, []);
  console.log('Browser checks passed: desktop, mobile, compact, hash match/mismatch, ZIP risks, XSS, filter, export, reset, cancellation.');
} finally {
  await browser?.close();
  child.kill();
}
