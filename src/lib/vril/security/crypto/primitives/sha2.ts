/**
 * Vril.js — Clean-room FIPS 180-4 SHA-256 and SHA-512 primitives.
 *
 * Implements SHA-256, SHA-512, and HMAC-SHA-256/SHA-512 directly in TypeScript
 * with no runtime dependencies. These are the foundation for FIPS 205 SLH-DSA
 * SHA2-family parameter sets.
 */

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_H0 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function rotr32(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

function sha256Block(state: Uint32Array, block: Uint8Array): void {
  const W = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
  for (let i = 16; i < 64; i++) {
    const s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >>> 3);
    const s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
  }
  let [a, b, c, d, e, f, g, h] = Array.from(state);
  for (let i = 0; i < 64; i++) {
    const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
    const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;
    h = g; g = f; f = e;
    e = (d + temp1) >>> 0;
    d = c; c = b; b = a;
    a = (temp1 + temp2) >>> 0;
  }
  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

/** SHA-256: hash input bytes and return 32-byte digest. */
export function sha256(input: Uint8Array): Uint8Array {
  const state = Uint32Array.from(SHA256_H0);
  const msgLen = input.length;
  const bitLen = msgLen * 8;

  // Pad message: append 0x80, zeros, 64-bit big-endian bit length (mod 512-bit blocks)
  const padLen = ((msgLen + 9 + 63) & ~63);
  const padded = new Uint8Array(padLen);
  padded.set(input);
  padded[msgLen] = 0x80;
  // Write 64-bit big-endian length (JavaScript numbers are safe to 53 bits)
  // Split into two 32-bit halves
  const hiLen = Math.floor(bitLen / 0x100000000);
  const loLen = bitLen >>> 0;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 8, hiLen);
  dv.setUint32(padLen - 4, loLen);

  for (let off = 0; off < padLen; off += 64) {
    sha256Block(state, padded.subarray(off, off + 64));
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, state[i]);
  return out;
}

// ─── SHA-512 (using BigInt for 64-bit words) ──────────────────────────────────

const SHA512_K: bigint[] = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const SHA512_H0: bigint[] = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const MASK64 = (1n << 64n) - 1n;

function rotr64(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

function sha512Block(state: bigint[], block: Uint8Array): void {
  const W: bigint[] = new Array(80);
  const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let i = 0; i < 16; i++) {
    W[i] = (BigInt(dv.getUint32(i * 8)) << 32n) | BigInt(dv.getUint32(i * 8 + 4));
  }
  for (let i = 16; i < 80; i++) {
    const s0 = rotr64(W[i - 15], 1n) ^ rotr64(W[i - 15], 8n) ^ (W[i - 15] >> 7n);
    const s1 = rotr64(W[i - 2], 19n) ^ rotr64(W[i - 2], 61n) ^ (W[i - 2] >> 6n);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & MASK64;
  }
  let [a, b, c, d, e, f, g, h] = state;
  for (let i = 0; i < 80; i++) {
    const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
    const ch = (e & f) ^ (~e & g) & MASK64;
    const temp1 = (h + S1 + ch + SHA512_K[i] + W[i]) & MASK64;
    const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) & MASK64;
    h = g; g = f; f = e;
    e = (d + temp1) & MASK64;
    d = c; c = b; b = a;
    a = (temp1 + temp2) & MASK64;
  }
  state[0] = (state[0] + a) & MASK64;
  state[1] = (state[1] + b) & MASK64;
  state[2] = (state[2] + c) & MASK64;
  state[3] = (state[3] + d) & MASK64;
  state[4] = (state[4] + e) & MASK64;
  state[5] = (state[5] + f) & MASK64;
  state[6] = (state[6] + g) & MASK64;
  state[7] = (state[7] + h) & MASK64;
}

/** SHA-512: hash input bytes and return 64-byte digest. */
export function sha512(input: Uint8Array): Uint8Array {
  const state = [...SHA512_H0];
  const msgLen = input.length;

  // Padding: 128-bit big-endian length, total padded length multiple of 1024 bits
  const padLen = ((msgLen + 17 + 127) & ~127);
  const padded = new Uint8Array(padLen);
  padded.set(input);
  padded[msgLen] = 0x80;
  // 128-bit length in bits - for practical message sizes, upper 64 bits are zero
  const bitLen = BigInt(msgLen) * 8n;
  const dv = new DataView(padded.buffer);
  // Write as 128-bit big-endian (upper 64 bits are 0 for any practical message)
  dv.setUint32(padLen - 16, 0);
  dv.setUint32(padLen - 12, 0);
  dv.setUint32(padLen - 8, Number(bitLen >> 32n));
  dv.setUint32(padLen - 4, Number(bitLen & 0xffffffffn));

  for (let off = 0; off < padLen; off += 128) {
    sha512Block(state, padded.subarray(off, off + 128));
  }

  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    ov.setUint32(i * 8, Number(state[i] >> 32n));
    ov.setUint32(i * 8 + 4, Number(state[i] & 0xffffffffn));
  }
  return out;
}

// ─── HMAC ─────────────────────────────────────────────────────────────────────

function hmac(hashFn: (d: Uint8Array) => Uint8Array, blockLen: number, key: Uint8Array, data: Uint8Array): Uint8Array {
  // If key is longer than block size, hash it
  const k = key.length > blockLen ? hashFn(key) : key;
  // Pad key to block size
  const kp = new Uint8Array(blockLen);
  kp.set(k);
  const ipad = new Uint8Array(blockLen).fill(0x36);
  const opad = new Uint8Array(blockLen).fill(0x5c);
  const ikey = new Uint8Array(blockLen);
  const okey = new Uint8Array(blockLen);
  for (let i = 0; i < blockLen; i++) {
    ikey[i] = kp[i] ^ ipad[i];
    okey[i] = kp[i] ^ opad[i];
  }
  const inner = new Uint8Array(blockLen + data.length);
  inner.set(ikey);
  inner.set(data, blockLen);
  const innerHash = hashFn(inner);
  const outer = new Uint8Array(blockLen + innerHash.length);
  outer.set(okey);
  outer.set(innerHash, blockLen);
  return hashFn(outer);
}

/** HMAC-SHA-256 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, 64, key, data);
}

/** HMAC-SHA-512 */
export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha512, 128, key, data);
}

// ─── MGF1 ─────────────────────────────────────────────────────────────────────

function mgf1(hashFn: (d: Uint8Array) => Uint8Array, hLen: number, seed: Uint8Array, maskLen: number): Uint8Array {
  const out = new Uint8Array(maskLen);
  let offset = 0;
  for (let counter = 0; offset < maskLen; counter++) {
    const C = new Uint8Array(4);
    new DataView(C.buffer).setUint32(0, counter);
    const h = hashFn(new Uint8Array([...seed, ...C]));
    const take = Math.min(hLen, maskLen - offset);
    out.set(h.subarray(0, take), offset);
    offset += take;
  }
  return out;
}

/** MGF1-SHA-256: mask generation function based on SHA-256. */
export function mgf1Sha256(seed: Uint8Array, maskLen: number): Uint8Array {
  return mgf1(sha256, 32, seed, maskLen);
}

/** MGF1-SHA-512: mask generation function based on SHA-512. */
export function mgf1Sha512(seed: Uint8Array, maskLen: number): Uint8Array {
  return mgf1(sha512, 64, seed, maskLen);
}
