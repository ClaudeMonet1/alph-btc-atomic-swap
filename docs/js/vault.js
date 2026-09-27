// Passphrase protection for what the page keeps in localStorage (audit W3): the
// Nostr secret and the swap state (adaptor secret, nonces, pre-signatures).
// WebCrypto only: PBKDF2-SHA256 (600k iterations, random salt) derives an
// AES-256-GCM key; each record has its own IV. The derived key lives in memory
// for the session, never in storage. A wrong passphrase fails authentication.
const ITERATIONS = 600_000;
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function deriveVaultKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export function newSalt() { return crypto.getRandomValues(new Uint8Array(16)); }

// Encrypts a string; returns a JSON-serialisable record.
export async function sealString(key, salt, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext)));
  return { v: 1, kdf: 'pbkdf2-sha256', iterations: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

export async function openString(key, record) {
  if (record?.v !== 1) throw new Error('unknown vault record version');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(record.iv) }, key, unb64(record.ct));
  return dec.decode(pt);
}

export const saltOf = (record) => unb64(record.salt);
