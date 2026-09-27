// Taproot helpers for single-key P2TR spends (the parties' own outputs). The
// swap key's tweak is handled by adaptor.js tapTweak().

import { G, n, Fn, taggedHash, hasEvenY, mul, bytesToNum, numTo32b } from './curve.js';

// Taproot-tweaked private key for a key-path-only P2TR output of pubkeyXOnly.
export function computeTweakedPrivateKey(privateKeyBytes, pubkeyXOnly) {
  const d = bytesToNum(privateKeyBytes);
  const P = mul(G, d);
  const dAdj = hasEvenY(P) ? d : Fn.create(n - d);
  const tweak = bytesToNum(taggedHash('TapTweak', pubkeyXOnly));
  return numTo32b(Fn.create(dAdj + tweak));
}
