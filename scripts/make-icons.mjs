#!/usr/bin/env node
// Renders the app icon (the Bitcoin and Alephium logos on the page's dark
// background, docs/icons/bitcoin.png and alephium.png) to the PNG sizes the
// manifest needs, with headless Chromium. Also writes docs/icons/icon.svg.
import puppeteer from 'puppeteer-core';
import { readFileSync, writeFileSync } from 'node:fs';
const b64 = (f) => 'data:image/png;base64,' + readFileSync(new URL(`../docs/icons/${f}`, import.meta.url)).toString('base64');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" rx="96" fill="#0d1117"/>
  <image href="${b64('bitcoin.png')}" x="36" y="146" width="220" height="220"/>
  <circle cx="366" cy="256" r="112" fill="#e6edf3"/>
  <image href="${b64('alephium.png')}" x="258" y="148" width="216" height="216"/>
  <path d="M232 236 h48 l-14 -14 M280 276 h-48 l14 14" fill="none" stroke="#8b949e" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
writeFileSync(new URL('../docs/icons/icon.svg', import.meta.url), svg);
const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM || '/run/current-system/sw/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-gpu'] });
const page = await browser.newPage();
for (const size of [192, 512]) {
  await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace(/width="512" height="512"/, `width="${size}" height="${size}"`)}</body></html>`);
  await page.screenshot({ path: new URL(`../docs/icons/icon-${size}.png`, import.meta.url).pathname, clip: { x: 0, y: 0, width: size, height: size }, omitBackground: true });
  console.log(`docs/icons/icon-${size}.png`);
}
await browser.close();
