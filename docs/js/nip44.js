// NIP-44 v2 encryption for the swap messages (audit W6, S7).
//
// conversation key = HKDF-extract(SHA-256, ikm = x(ECDH(a, B)), salt = "nip44-v2")
// message key      = HKDF-expand(SHA-256, conversation key, nonce, 76)
//                    = chacha key (32) || chacha nonce (12) || hmac key (32)
// payload          = base64( 0x02 || nonce (32) || ChaCha20(padded plaintext) || HMAC-SHA256(hmac key, nonce || ciphertext) )
// Padding: 2-byte big-endian length, then the plaintext padded with zeros to the
// NIP-44 length schedule. Written against the specification and checked against
// nostr-tools' implementation (audit/nip44.test.mjs).
import { secp256k1 } from '@noble/curves/secp256k1';
import { chacha20 } from '@noble/ciphers/chacha';
import { extract, expand } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils';

const MIN_PLAINTEXT = 1, MAX_PLAINTEXT = 65535;

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
const utf8 = new TextEncoder(), utf8d = new TextDecoder();

export function getConversationKey(secKeyBytes, peerPubHex) {
  const shared = secp256k1.getSharedSecret(secKeyBytes, hexToBytes('02' + peerPubHex));
  return extract(sha256, shared.subarray(1, 33), utf8.encode('nip44-v2'));
}

function messageKeys(conversationKey, nonce) {
  const keys = expand(sha256, conversationKey, nonce, 76);
  return { chachaKey: keys.subarray(0, 32), chachaNonce: keys.subarray(32, 44), hmacKey: keys.subarray(44, 76) };
}

export function calcPaddedLen(len) {
  if (!Number.isInteger(len) || len < 1) throw new Error('nip44: invalid plaintext length');
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
  const bytes = utf8.encode(plaintext);
  if (bytes.length < MIN_PLAINTEXT || bytes.length > MAX_PLAINTEXT) throw new Error('nip44: plaintext length out of range');
  const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, bytes.length, false);
  const suffix = new Uint8Array(calcPaddedLen(bytes.length) - bytes.length);
  return concatBytes(prefix, bytes, suffix);
}

function unpad(padded) {
  const len = new DataView(padded.buffer, padded.byteOffset, 2).getUint16(0, false);
  const bytes = padded.subarray(2, 2 + len);
  if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT || bytes.length !== len || padded.length !== 2 + calcPaddedLen(len)) throw new Error('nip44: invalid padding');
  return utf8d.decode(bytes);
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export function encrypt(plaintext, conversationKey, nonce = randomBytes(32)) {
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(conversationKey, nonce);
  const ciphertext = chacha20(chachaKey, chachaNonce, pad(plaintext));
  const mac = hmac(sha256, hmacKey, concatBytes(nonce, ciphertext));
  return b64(concatBytes(new Uint8Array([2]), nonce, ciphertext, mac));
}

export function decrypt(payload, conversationKey) {
  if (payload.length < 132 || payload.length > 87472 || payload[0] === '#') throw new Error('nip44: invalid payload');
  const data = unb64(payload);
  if (data.length < 99 || data[0] !== 2) throw new Error('nip44: unsupported version or too short');
  const nonce = data.subarray(1, 33), ciphertext = data.subarray(33, data.length - 32), mac = data.subarray(data.length - 32);
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(conversationKey, nonce);
  const expected = hmac(sha256, hmacKey, concatBytes(nonce, ciphertext));
  if (!equalBytes(expected, mac)) throw new Error('nip44: invalid MAC');
  return unpad(chacha20(chachaKey, chachaNonce, ciphertext));
}

// Convenience for the swap: encrypt to / decrypt from a peer with our secret key.
export function encryptTo(secKeyBytes, peerPubHex, plaintext) {
  return encrypt(plaintext, getConversationKey(secKeyBytes, peerPubHex));
}
export function decryptFrom(secKeyBytes, peerPubHex, payload) {
  return decrypt(payload, getConversationKey(secKeyBytes, peerPubHex));
}
export { hexToBytes, bytesToHex };
