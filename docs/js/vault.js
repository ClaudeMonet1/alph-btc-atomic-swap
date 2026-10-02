// Opens a key that a build before 2026-10-02 sealed with a passphrase (audit W3).
// The passphrase option itself is gone; this is the one-time unlock path, kept so
// that a key encrypted by an earlier build can still be read and migrated.
// WebCrypto only: PBKDF2-SHA256 (600k iterations) derives the AES-256-GCM key.
const ITERATIONS = 600_000;
const enc = new TextEncoder(), dec = new TextDecoder();
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function deriveVaultKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

export async function openString(key, record) {
  if (record?.v !== 1) throw new Error('unknown vault record version');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(record.iv) }, key, unb64(record.ct));
  return dec.decode(pt);
}

export const saltOf = (record) => unb64(record.salt);
