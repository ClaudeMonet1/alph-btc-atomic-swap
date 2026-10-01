#!/usr/bin/env node
// Renders docs/icons/icon.svg to the PNG sizes the manifest needs, with headless Chromium.
import puppeteer from 'puppeteer-core';
import { readFileSync } from 'node:fs';
const svg = readFileSync(new URL('../docs/icons/icon.svg', import.meta.url), 'utf8');
const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM || '/run/current-system/sw/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-gpu'] });
const page = await browser.newPage();
for (const size of [192, 512]) {
  await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace(/width="512" height="512"/, `width="${size}" height="${size}"`)}</body></html>`);
  await page.screenshot({ path: new URL(`../docs/icons/icon-${size}.png`, import.meta.url).pathname, clip: { x: 0, y: 0, width: size, height: size }, omitBackground: true });
  console.log(`docs/icons/icon-${size}.png`);
}
await browser.close();
