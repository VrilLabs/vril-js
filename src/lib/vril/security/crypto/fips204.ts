/**
 * Vril.js — Clean-room FIPS 204 ML-DSA engine.
 *
 * Implements ML-DSA-44, ML-DSA-65, and ML-DSA-87 directly from the
 * NIST FIPS 204 (August 2024) specification. Uses only in-tree FIPS 202
 * SHA-3/SHAKE primitives. Zero external dependencies.
 */

import { shake256, ShakeXof } from './primitives/sha3';
import { randomBytes } from './primitives/random';

// ─── Field parameters ─────────────────────────────────────────────────────────

const Q = 8380417;    // prime modulus (2^23 - 2^13 + 1)
const N = 256;        // polynomial degree
const D = 13;         // Power2Round bit drop (d = 13 in all parameter sets)
const INV256 = 8347681; // 256^(-1) mod q

// ─── NTT table (256 values, computed from ζ = 1753) ──────────────────────────
// ζ = 1753 is a primitive 512th root of unity mod q (ζ^256 ≡ -1 mod q).
// zetas[i] = 1753^BitRev8(i) mod q for i = 0..255.

function _bitRev8(n: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) { r = (r << 1) | (n & 1); n >>= 1; }
  return r;
}

function _modpow(base: number, exp: number, mod: number): number {
  let result = 1;
  base = ((base % mod) + mod) % mod;
  while (exp > 0) {
    if (exp & 1) result = (result * base) % mod;
    exp >>>= 1;
    base = (base * base) % mod;
  }
  return result;
}

const ZETAS = new Int32Array(256);
for (let i = 0; i < 256; i++) ZETAS[i] = _modpow(1753, _bitRev8(i), Q);

// ─── Parameter sets ───────────────────────────────────────────────────────────

interface MLDSAParams {
  k: number;       // rows in A
  l: number;       // columns in A
  eta: number;     // secret key coefficient bound
  tau: number;     // challenge weight
  beta: number;    // tau * eta
  gamma1: number;  // mask bound (2^17 or 2^19)
  gamma2: number;  // low-bits rounding range
  omega: number;   // max ones in hint h
  lambda: number;  // security parameter (128, 192, 256 bits)
  pkBytes: number;
  skBytes: number;
  sigBytes: number;
}

const PARAMS: Record<string, MLDSAParams> = {
  'ML-DSA-44': {
    k: 4, l: 4, eta: 2, tau: 39, beta: 78,
    gamma1: 1 << 17, gamma2: (Q - 1) / 88,
    omega: 80, lambda: 128,
    pkBytes: 1312, skBytes: 2560, sigBytes: 2420,
  },
  'ML-DSA-65': {
    k: 6, l: 5, eta: 4, tau: 49, beta: 196,
    gamma1: 1 << 19, gamma2: (Q - 1) / 32,
    omega: 55, lambda: 192,
    pkBytes: 1952, skBytes: 4032, sigBytes: 3309,
  },
  'ML-DSA-87': {
    k: 8, l: 7, eta: 2, tau: 60, beta: 120,
    gamma1: 1 << 19, gamma2: (Q - 1) / 32,
    omega: 75, lambda: 256,
    pkBytes: 2592, skBytes: 4896, sigBytes: 4627,
  },
};

export type MLDSAVariant = keyof typeof PARAMS;

// ─── Polynomial type ──────────────────────────────────────────────────────────

type Poly = Int32Array; // 256 coefficients in Z_q (centered: may be negative)

function newPoly(): Poly { return new Int32Array(N); }

// ─── Arithmetic ───────────────────────────────────────────────────────────────

/** Reduce x into [0, q-1]. */
function mq(x: number): number { return ((x % Q) + Q) % Q; }

function addPoly(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = mq(a[i] + b[i]);
  return c;
}

function subPoly(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = mq(a[i] - b[i]);
  return c;
}

// ─── NTT (FIPS 204 Algorithms 36-37) ─────────────────────────────────────────

/** Algorithm 36: in-place forward NTT. */
function ntt(f: Poly): void {
  let k = 0;
  let len = 128;
  while (len >= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      k++;
      const z = ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = (z * f[j + len]) % Q;
        f[j + len] = mq(f[j] - t);
        f[j] = mq(f[j] + t);
      }
    }
    len >>= 1;
  }
}

/** Algorithm 37: in-place inverse NTT. */
function intt(f: Poly): void {
  let k = 256;
  let len = 1;
  while (len <= 128) {
    for (let start = 0; start < 256; start += 2 * len) {
      k--;
      const z = ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = f[j];
        f[j] = mq(t + f[j + len]);
        f[j + len] = (z * mq(f[j + len] - t)) % Q;
      }
    }
    len <<= 1;
  }
  for (let i = 0; i < N; i++) f[i] = (f[i] * INV256) % Q;
}

/** Pointwise NTT-domain multiplication. */
function multiplyNTT(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = (a[i] * b[i]) % Q;
  return c;
}

// ─── Decomposition helpers (FIPS 204 Section 8.4) ────────────────────────────

/** Power2Round: return (r1, r0) such that r = r1*2^d + r0, r0 ∈ (-2^(d-1), 2^(d-1)]. */
function power2Round(r: number): [number, number] {
  const rPlus = mq(r);
  const r1 = (rPlus + (1 << (D - 1)) - 1) >> D;
  const r0 = rPlus - r1 * (1 << D);
  return [r1, r0];
}

/**
 * Decompose: r = r1*alpha + r0 where r0 ∈ (-alpha/2, alpha/2].
 * Special case: if r1 = (q-1)/alpha, set r1=0, r0=r0-1.
 */
function decompose(r: number, alpha: number): [number, number] {
  const rPrime = mq(r);
  let r0 = rPrime % alpha;
  if (r0 > alpha / 2) r0 -= alpha;
  if (rPrime - r0 === Q - 1) return [0, r0 - 1];
  return [(rPrime - r0) / alpha, r0];
}

function highBits(r: number, alpha: number): number { return decompose(r, alpha)[0]; }

/** MakeHint: 1 iff highBits(r2) != highBits(r1). */
function makeHint(r2: number, r1: number, alpha: number): number {
  return highBits(r1, alpha) === highBits(r2, alpha) ? 0 : 1;
}

/** recoverHighBits: recover high bits from hint and approximate value (FIPS 204 UseHint). */
function recoverHighBits(hint: number, r: number, alpha: number): number {
  const m = (Q - 1) / alpha;
  const [r1, r0] = decompose(r, alpha);
  if (hint === 0) return r1;
  if (r0 > 0) return (r1 + 1) % m;
  return (r1 - 1 + m) % m;
}

function infNorm(f: Poly): number {
  let max = 0;
  for (let i = 0; i < N; i++) {
    const c = Math.abs(centred(f[i]));
    if (c > max) max = c;
  }
  return max;
}

/** Map x ∈ [0, q-1] to centred representative in (-(q-1)/2, (q-1)/2]. */
function centred(x: number): number {
  const r = mq(x);
  return r > (Q - 1) / 2 ? r - Q : r;
}

// ─── Byte packing helpers (FIPS 204 Section 8.2) ─────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/** Pack t1 coefficients (10-bit, [0, (q-1)/2^d] → [0, 1023]). 320 bytes per poly. */
function packT1(t1: Poly): Uint8Array {
  const out = new Uint8Array(320);
  for (let i = 0; i < 256; i += 4) {
    out[i * 10 / 8]     = t1[i] & 0xff;
    out[i * 10 / 8 + 1] = ((t1[i] >> 8) & 0x3) | ((t1[i + 1] & 0x3f) << 2);
    out[i * 10 / 8 + 2] = ((t1[i + 1] >> 6) & 0xf) | ((t1[i + 2] & 0xf) << 4);
    out[i * 10 / 8 + 3] = ((t1[i + 2] >> 4) & 0x3f) | ((t1[i + 3] & 0x3) << 6);
    out[i * 10 / 8 + 4] = (t1[i + 3] >> 2) & 0xff;
  }
  return out;
}

function unpackT1(buf: Uint8Array): Poly {
  const t1 = newPoly();
  for (let i = 0; i < 256; i += 4) {
    const base = i * 10 / 8;
    t1[i]     =  buf[base]       | ((buf[base + 1] & 0x3)  << 8);
    t1[i + 1] = (buf[base + 1] >> 2) | ((buf[base + 2] & 0xf)  << 6);
    t1[i + 2] = (buf[base + 2] >> 4) | ((buf[base + 3] & 0x3f) << 4);
    t1[i + 3] = (buf[base + 3] >> 6) | ( buf[base + 4]         << 2);
  }
  return t1;
}

/** Pack t0 coefficients as 13-bit values. 416 bytes per poly. */
function packT0(t0: Poly): Uint8Array {
  const out = new Uint8Array(416);
  // Each coefficient in (-2^(d-1), 2^(d-1)] stored as 2^(d-1) - c ∈ [0, 2^d)
  for (let i = 0; i < 256; i += 8) {
    const vals = [];
    for (let j = 0; j < 8; j++) {
      vals.push(((1 << (D - 1)) - centred(t0[i + j])) & ((1 << D) - 1));
    }
    const base = i * 13 / 8;
    out[base]     =  vals[0] & 0xff;
    out[base + 1] = ((vals[0] >> 8) & 0x1f) | ((vals[1] & 0x7) << 5);
    out[base + 2] = ((vals[1] >> 3) & 0xff);
    out[base + 3] = ((vals[1] >> 11) & 0x3)  | ((vals[2] & 0x3f) << 2);
    out[base + 4] = ((vals[2] >> 6)  & 0x7f) | ((vals[3] & 0x1)  << 7);
    out[base + 5] = ((vals[3] >> 1)  & 0xff);
    out[base + 6] = ((vals[3] >> 9)  & 0xf)  | ((vals[4] & 0xf)  << 4);
    out[base + 7] = ((vals[4] >> 4)  & 0xff);
    out[base + 8] = ((vals[4] >> 12) & 0x1)  | ((vals[5] & 0x7f) << 1);
    out[base + 9] = ((vals[5] >> 7)  & 0x3f) | ((vals[6] & 0x3)  << 6);
    out[base + 10]= ((vals[6] >> 2)  & 0xff);
    out[base + 11]= ((vals[6] >> 10) & 0x7)  | ((vals[7] & 0x1f) << 3);
    out[base + 12]= ((vals[7] >> 5)  & 0xff);
  }
  return out;
}

function unpackT0(buf: Uint8Array): Poly {
  const t0 = newPoly();
  for (let i = 0; i < 256; i += 8) {
    const base = i * 13 / 8;
    const vals = [
       buf[base]       | ((buf[base + 1] & 0x1f) << 8),
      (buf[base + 1] >> 5) | (buf[base + 2] << 3) | ((buf[base + 3] & 0x3) << 11),
      (buf[base + 3] >> 2) | ((buf[base + 4] & 0x7f) << 6),
      (buf[base + 4] >> 7) | (buf[base + 5] << 1) | ((buf[base + 6] & 0xf) << 9),
      (buf[base + 6] >> 4) | (buf[base + 7] << 4) | ((buf[base + 8] & 0x1) << 12),
      (buf[base + 8] >> 1) | ((buf[base + 9] & 0x3f) << 7),
      (buf[base + 9] >> 6) | (buf[base + 10] << 2) | ((buf[base + 11] & 0x7) << 10),
      (buf[base + 11] >> 3) | (buf[base + 12] << 5),
    ];
    for (let j = 0; j < 8; j++) {
      const v = vals[j] & ((1 << D) - 1);
      t0[i + j] = mq((1 << (D - 1)) - v);
    }
  }
  return t0;
}

/** Pack s coefficients with eta=2 (3 bits each, 96 bytes per poly). */
function packS_eta2(s: Poly): Uint8Array {
  const out = new Uint8Array(96);
  for (let i = 0; i < 256; i += 8) {
    const cs = Array.from({ length: 8 }, (_, j) => 2 - centred(s[i + j]));
    const base = i * 3 / 8;
    out[base]     = cs[0] | (cs[1] << 3) | ((cs[2] & 0x3) << 6);
    out[base + 1] = (cs[2] >> 2) | (cs[3] << 1) | (cs[4] << 4) | ((cs[5] & 0x1) << 7);
    out[base + 2] = (cs[5] >> 1) | (cs[6] << 2) | (cs[7] << 5);
  }
  return out;
}

function unpackS_eta2(buf: Uint8Array): Poly {
  const s = newPoly();
  for (let i = 0; i < 256; i += 8) {
    const base = i * 3 / 8;
    const cs = [
      buf[base] & 7, (buf[base] >> 3) & 7, ((buf[base] >> 6) & 3) | ((buf[base + 1] & 1) << 2),
      (buf[base + 1] >> 1) & 7, (buf[base + 1] >> 4) & 7,
      ((buf[base + 1] >> 7) & 1) | ((buf[base + 2] & 3) << 1),
      (buf[base + 2] >> 2) & 7, (buf[base + 2] >> 5) & 7,
    ];
    for (let j = 0; j < 8; j++) s[i + j] = mq(2 - cs[j]);
  }
  return s;
}

/** Pack s coefficients with eta=4 (4 bits each, 128 bytes per poly). */
function packS_eta4(s: Poly): Uint8Array {
  const out = new Uint8Array(128);
  for (let i = 0; i < 256; i += 2) {
    const c0 = 4 - centred(s[i]);
    const c1 = 4 - centred(s[i + 1]);
    out[i >> 1] = (c0 & 0xf) | ((c1 & 0xf) << 4);
  }
  return out;
}

function unpackS_eta4(buf: Uint8Array): Poly {
  const s = newPoly();
  for (let i = 0; i < 256; i += 2) {
    s[i]     = mq(4 - (buf[i >> 1] & 0xf));
    s[i + 1] = mq(4 - (buf[i >> 1] >> 4));
  }
  return s;
}

function packS(s: Poly, eta: number): Uint8Array {
  return eta === 2 ? packS_eta2(s) : packS_eta4(s);
}
function unpackS(buf: Uint8Array, eta: number): Poly {
  return eta === 2 ? unpackS_eta2(buf) : unpackS_eta4(buf);
}

/** Pack z polynomial (gamma1=2^17: 18 bits, 576 bytes; gamma1=2^19: 20 bits, 640 bytes). */
function packZ(z: Poly, gamma1: number): Uint8Array {
  if (gamma1 === 1 << 17) {
    const out = new Uint8Array(576);
    for (let i = 0; i < 256; i += 4) {
      const cs = Array.from({ length: 4 }, (_, j) => gamma1 - centred(z[i + j]));
      const base = i * 18 / 8;
      out[base]     =  cs[0] & 0xff;
      out[base + 1] = (cs[0] >> 8) & 0xff;
      out[base + 2] = ((cs[0] >> 16) & 0x3) | ((cs[1] & 0x3f) << 2);
      out[base + 3] = (cs[1] >> 6) & 0xff;
      out[base + 4] = ((cs[1] >> 14) & 0xf) | ((cs[2] & 0xf) << 4);
      out[base + 5] = (cs[2] >> 4) & 0xff;
      out[base + 6] = ((cs[2] >> 12) & 0x3f) | ((cs[3] & 0x3) << 6);
      out[base + 7] = (cs[3] >> 2) & 0xff;
      out[base + 8] = (cs[3] >> 10) & 0xff;
    }
    return out;
  } else { // gamma1 === 1 << 19: pack 4 x 20-bit values into 10 bytes
    const out = new Uint8Array(640);
    for (let i = 0; i < 256; i += 4) {
      const cs = Array.from({ length: 4 }, (_, j) => gamma1 - centred(z[i + j]));
      const base = i * 20 / 8;
      const c0 = cs[0], c1 = cs[1], c2 = cs[2], c3 = cs[3];
      out[base]     =  c0 & 0xff;
      out[base + 1] = (c0 >> 8) & 0xff;
      out[base + 2] = ((c0 >> 16) & 0xf) | ((c1 & 0xf) << 4);
      out[base + 3] = (c1 >> 4) & 0xff;
      out[base + 4] = (c1 >> 12) & 0xff;
      out[base + 5] =  c2 & 0xff;
      out[base + 6] = (c2 >> 8) & 0xff;
      out[base + 7] = ((c2 >> 16) & 0xf) | ((c3 & 0xf) << 4);
      out[base + 8] = (c3 >> 4) & 0xff;
      out[base + 9] = (c3 >> 12) & 0xff;
    }
    return out;
  }
}

function unpackZ(buf: Uint8Array, gamma1: number): Poly {
  const z = newPoly();
  if (gamma1 === 1 << 17) {
    for (let i = 0; i < 256; i += 4) {
      const base = i * 18 / 8;
      const cs = [
        buf[base] | (buf[base + 1] << 8) | ((buf[base + 2] & 0x3) << 16),
        ((buf[base + 2] >> 2) & 0x3f) | (buf[base + 3] << 6) | ((buf[base + 4] & 0xf) << 14),
        ((buf[base + 4] >> 4) & 0xf) | (buf[base + 5] << 4) | ((buf[base + 6] & 0x3f) << 12),
        ((buf[base + 6] >> 6) & 0x3) | (buf[base + 7] << 2) | (buf[base + 8] << 10),
      ];
      for (let j = 0; j < 4; j++) z[i + j] = mq(gamma1 - cs[j]);
    }
  } else {
    for (let i = 0; i < 256; i += 4) {
      const base = i * 20 / 8;
      const cs = [
        buf[base] | (buf[base + 1] << 8) | ((buf[base + 2] & 0xf) << 16),
        ((buf[base + 2] >> 4) & 0xf) | (buf[base + 3] << 4) | (buf[base + 4] << 12),
        buf[base + 5] | (buf[base + 6] << 8) | ((buf[base + 7] & 0xf) << 16),
        ((buf[base + 7] >> 4) & 0xf) | (buf[base + 8] << 4) | (buf[base + 9] << 12),
      ];
      for (let j = 0; j < 4; j++) z[i + j] = mq(gamma1 - cs[j]);
    }
  }
  return z;
}

/** Pack w1 polynomial into bytes (for commitment). */
function packW1(w1: Poly, gamma2: number): Uint8Array {
  if (gamma2 === (Q - 1) / 88) {
    // 6-bit values, 192 bytes
    const out = new Uint8Array(192);
    for (let i = 0; i < 256; i += 4) {
      const base = i * 6 / 8;
      out[base]     = (w1[i] & 0x3f) | ((w1[i + 1] & 0x3) << 6);
      out[base + 1] = ((w1[i + 1] >> 2) & 0xf) | ((w1[i + 2] & 0xf) << 4);
      out[base + 2] = ((w1[i + 2] >> 4) & 0x3) | ((w1[i + 3] & 0x3f) << 2);
    }
    return out;
  } else {
    // 4-bit values, 128 bytes
    const out = new Uint8Array(128);
    for (let i = 0; i < 256; i += 2) {
      out[i >> 1] = (w1[i] & 0xf) | ((w1[i + 1] & 0xf) << 4);
    }
    return out;
  }
}

// ─── Sampling helpers ─────────────────────────────────────────────────────────

/** ExpandA: generate k×l matrix of NTT-domain polynomials from rho using SHAKE128. */
function expandA(rho: Uint8Array, k: number, l: number): Poly[][] {
  const A: Poly[][] = Array.from({ length: k }, () => Array(l));
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < l; j++) {
      const xof = new ShakeXof(128);
      xof.update(concat(rho, new Uint8Array([j, i]))); // ρ || j || i
      const p = newPoly();
      let count = 0;
      while (count < N) {
        const buf = xof.squeeze(3);
        const d1 = buf[0] | ((buf[1] & 0x0f) << 8);
        const d2 = (buf[1] >> 4) | (buf[2] << 4);
        if (d1 < Q) p[count++] = d1;
        if (d2 < Q && count < N) p[count++] = d2;
      }
      A[i][j] = p;
    }
  }
  return A;
}

/** ExpandS: sample l+k secret polynomials from SHAKE256. */
function expandS(rho: Uint8Array, eta: number, l: number, k: number): [Poly[], Poly[]] {
  const s1: Poly[] = [];
  const s2: Poly[] = [];
  for (let r = 0; r < l + k; r++) {
    const xof = new ShakeXof(256);
    xof.update(concat(rho, new Uint8Array([(r >> 8) & 0xff, r & 0xff])));
    const p = newPoly();
    let count = 0;
    const bound = eta === 2 ? 15 : 9; // rejection bound
    while (count < N) {
      const b = xof.squeeze(1)[0];
      const b0 = b & 0xf, b1 = b >> 4;
      if (b0 < bound) { p[count++] = mq(eta - b0); }
      if (b1 < bound && count < N) { p[count++] = mq(eta - b1); }
    }
    if (r < l) s1.push(p); else s2.push(p);
  }
  return [s1, s2];
}

/** ExpandMask: generate l mask polynomials from rho_prime and kappa. */
function expandMask(rho_prime: Uint8Array, kappa: number, l: number, gamma1: number): Poly[] {
  const y: Poly[] = [];
  const bits = gamma1 === (1 << 17) ? 18 : 20;
  for (let r = 0; r < l; r++) {
    const kappaPlusR = kappa + r;
    const xof = new ShakeXof(256);
    xof.update(concat(rho_prime, new Uint8Array([kappaPlusR & 0xff, (kappaPlusR >> 8) & 0xff])));
    const p = newPoly();
    const totalBits = N * bits;
    const bytesNeeded = (totalBits + 7) >> 3;
    const buf = xof.squeeze(bytesNeeded);
    let bitPos = 0;
    const mask = (1 << bits) - 1;
    for (let i = 0; i < N; i++) {
      let val = 0;
      for (let b = 0; b < bits; b++) {
        val |= ((buf[bitPos >> 3] >> (bitPos & 7)) & 1) << b;
        bitPos++;
      }
      p[i] = mq(gamma1 - (val & mask));
    }
    y.push(p);
  }
  return y;
}

/**
 * SampleInBall: sample a polynomial c with exactly tau ±1 entries.
 * Algorithm 29 from FIPS 204.
 */
function sampleInBall(rhoInput: Uint8Array, tau: number): Poly {
  const xof = new ShakeXof(256);
  xof.update(rhoInput);
  const signBytes = xof.squeeze(8);
  let signs = BigInt(0);
  for (let i = 7; i >= 0; i--) signs = (signs << 8n) | BigInt(signBytes[i]);

  const c = newPoly();
  for (let i = N - tau; i < N; i++) {
    // Rejection sample j ∈ [0, i]
    let j: number;
    do { j = xof.squeeze(1)[0]; } while (j > i);
    c[i] = c[j];
    c[j] = mq(1 - 2 * Number(signs & 1n));
    signs >>= 1n;
  }
  return c;
}

// ─── Key generation (FIPS 204 Algorithm 1) ───────────────────────────────────

function mlDSAKeyGenInternal(xi: Uint8Array, p: MLDSAParams): [Uint8Array, Uint8Array] {
  const { k, l, eta } = p;

  // (ρ, ρ', K) ← H(ξ, 128)
  const seed = shake256(xi, 128);
  const rho = seed.subarray(0, 32);
  const rho_prime = seed.subarray(32, 96);
  const K = seed.subarray(96, 128);

  // Â ← ExpandA(ρ)
  const A = expandA(rho, k, l);

  // (s1, s2) ← ExpandS(ρ', eta, l, k)
  const [s1, s2] = expandS(rho_prime, eta, l, k);

  // t = NTT^(-1)(Â · NTT(s1)) + s2
  const s1Hat = s1.map(p => { const q = Int32Array.from(p); ntt(q); return q; });
  const t: Poly[] = [];
  for (let i = 0; i < k; i++) {
    let acc = newPoly();
    for (let j = 0; j < l; j++) acc = addPoly(acc, multiplyNTT(A[i][j], s1Hat[j]));
    const tPoly = Int32Array.from(acc);
    intt(tPoly);
    t.push(addPoly(tPoly, s2[i]));
  }

  // (t1, t0) ← Power2Round(t, D)
  const t1 = t.map(poly => {
    const r = newPoly();
    for (let i = 0; i < N; i++) r[i] = power2Round(poly[i])[0];
    return r;
  });
  const t0 = t.map(poly => {
    const r = newPoly();
    for (let i = 0; i < N; i++) r[i] = power2Round(poly[i])[1];
    return r;
  });

  // pk = ρ ∥ t1_encoded
  const t1Enc = t1.map(packT1);
  const pk = new Uint8Array(p.pkBytes);
  pk.set(rho, 0);
  for (let i = 0; i < k; i++) pk.set(t1Enc[i], 32 + i * 320);

  // tr = H(pk, 64) — SHAKE256
  const tr = shake256(pk, 64);

  // s1Enc, s2Enc, t0Enc
  const sBytes = eta === 2 ? 96 : 128;
  const sk = new Uint8Array(p.skBytes);
  let off = 0;
  sk.set(rho, off); off += 32;
  sk.set(K, off); off += 32;
  sk.set(tr, off); off += 64;
  for (let i = 0; i < l; i++) { sk.set(packS(s1[i], eta), off); off += sBytes; }
  for (let i = 0; i < k; i++) { sk.set(packS(s2[i], eta), off); off += sBytes; }
  for (let i = 0; i < k; i++) { sk.set(packT0(t0[i]), off); off += 416; }

  return [pk, sk];
}

// ─── Signing (FIPS 204 Algorithm 2) ──────────────────────────────────────────

function mlDSASignInternal(sk: Uint8Array, M: Uint8Array, rnd: Uint8Array, p: MLDSAParams): Uint8Array {
  const { k, l, eta, tau, beta, gamma1, gamma2, omega, lambda } = p;
  const sBytes = eta === 2 ? 96 : 128;
  const alpha = 2 * gamma2;

  // Unpack sk
  let off = 0;
  const rho = sk.subarray(off, off + 32); off += 32;
  const K = sk.subarray(off, off + 32); off += 32;
  const tr = sk.subarray(off, off + 64); off += 64;
  const s1: Poly[] = [];
  for (let i = 0; i < l; i++) { s1.push(unpackS(sk.subarray(off, off + sBytes), eta)); off += sBytes; }
  const s2: Poly[] = [];
  for (let i = 0; i < k; i++) { s2.push(unpackS(sk.subarray(off, off + sBytes), eta)); off += sBytes; }
  const t0: Poly[] = [];
  for (let i = 0; i < k; i++) { t0.push(unpackT0(sk.subarray(off, off + 416))); off += 416; }

  // Â, ŝ1, ŝ2, t̂0
  const A = expandA(rho, k, l);
  const s1Hat = s1.map(p => { const q = Int32Array.from(p); ntt(q); return q; });
  const s2Hat = s2.map(p => { const q = Int32Array.from(p); ntt(q); return q; });
  const t0Hat = t0.map(p => { const q = Int32Array.from(p); ntt(q); return q; });

  // μ = H(tr ∥ M, 64)
  const mu = shake256(concat(tr, M), 64);

  // ρ' = H(K ∥ rnd ∥ μ, 64)
  const rho_prime = shake256(concat(K, rnd, mu), 64);

  const ctildeLen = lambda >> 2; // lambda/4 bytes
  let kappa = 0;
  const MAX_ATTEMPTS = 1000;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    // y = ExpandMask(ρ', κ)
    const y = expandMask(rho_prime, kappa, l, gamma1);
    kappa += l;

    // ŷ = NTT(y); w = NTT^(-1)(Â · ŷ)
    const yHat = y.map(p => { const q = Int32Array.from(p); ntt(q); return q; });
    const w: Poly[] = [];
    for (let i = 0; i < k; i++) {
      let acc = newPoly();
      for (let j = 0; j < l; j++) acc = addPoly(acc, multiplyNTT(A[i][j], yHat[j]));
      const wPoly = Int32Array.from(acc);
      intt(wPoly);
      w.push(wPoly);
    }

    // w1 = HighBits(w, alpha)
    const w1 = w.map(poly => {
      const r = newPoly();
      for (let i = 0; i < N; i++) r[i] = highBits(poly[i], alpha);
      return r;
    });

    // c̃ = H(μ ∥ PackW1(w1), lambda/4 bytes)
    const w1Packed = concat(...w1.map(p => packW1(p, gamma2)));
    const ctilde = shake256(concat(mu, w1Packed), ctildeLen);

    // c = SampleInBall(c̃, τ)
    const c = sampleInBall(ctilde, tau);
    const cHat = Int32Array.from(c); ntt(cHat);

    // z = y + c·s1;  r0 = w0 - c·s2
    const z: Poly[] = [];
    for (let i = 0; i < l; i++) {
      const cs1 = Int32Array.from(multiplyNTT(cHat, s1Hat[i]));
      intt(cs1);
      z.push(addPoly(y[i], cs1));
    }

    const w0: Poly[] = w.map((poly) => {
      const r = newPoly();
      for (let j = 0; j < N; j++) r[j] = decompose(poly[j], alpha)[1];
      return r;
    });
    const r0: Poly[] = [];
    for (let i = 0; i < k; i++) {
      const cs2 = Int32Array.from(multiplyNTT(cHat, s2Hat[i]));
      intt(cs2);
      r0.push(subPoly(w0[i], cs2));
    }

    // Check norms
    const zNorm = Math.max(...z.map(infNorm));
    const r0Norm = Math.max(...r0.map(infNorm));
    if (zNorm >= gamma1 - beta || r0Norm >= gamma2 - beta) continue;

    // ct0 = c·t0; h = MakeHint(-ct0, w - cs2 + ct0, 2*gamma2)
    const ct0: Poly[] = [];
    for (let i = 0; i < k; i++) {
      const ct0Poly = Int32Array.from(multiplyNTT(cHat, t0Hat[i]));
      intt(ct0Poly);
      ct0.push(ct0Poly);
    }

    if (Math.max(...ct0.map(infNorm)) >= gamma2) continue;

    const h: Poly[] = [];
    let hCount = 0;
    const cs2Arr: Poly[] = [];
    for (let i = 0; i < k; i++) {
      const cs2Poly = Int32Array.from(multiplyNTT(cHat, s2Hat[i]));
      intt(cs2Poly);
      cs2Arr.push(cs2Poly);
    }
    for (let i = 0; i < k; i++) {
      const hi = newPoly();
      for (let j = 0; j < N; j++) {
        const wMinusCs2 = mq(w[i][j] - cs2Arr[i][j]);
        const wHigh = mq(wMinusCs2 + ct0[i][j]);
        const negCt0 = mq(-ct0[i][j]);
        const neg = mq(wMinusCs2 + negCt0);
        hi[j] = makeHint(neg, wHigh, alpha);
        hCount += hi[j];
      }
      h.push(hi);
    }

    if (hCount > omega) continue;

    // Encode signature: c̃ ∥ z ∥ h
    const zBytesPerPoly = gamma1 === (1 << 17) ? 576 : 640;
    const sig = new Uint8Array(p.sigBytes);
    let sigOff = 0;
    sig.set(ctilde, sigOff); sigOff += ctildeLen;
    for (let i = 0; i < l; i++) { sig.set(packZ(z[i], gamma1), sigOff); sigOff += zBytesPerPoly; }

    // Encode h: omega position bytes + k terminator bytes
    const hEnc = sig.subarray(sigOff);
    let pos = 0;
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < N; j++) {
        if (h[i][j]) hEnc[pos++] = j;
      }
      hEnc[omega + i] = pos;
    }

    return sig;
  }

  throw new Error('[VRIL FIPS 204] ML-DSA signing loop exceeded maximum attempts — randomness may be broken');
}

// ─── Verification (FIPS 204 Algorithm 3) ─────────────────────────────────────

function mlDSAVerifyInternal(pk: Uint8Array, M: Uint8Array, sig: Uint8Array, p: MLDSAParams): boolean {
  const { k, l, tau, beta, gamma1, gamma2, omega, lambda } = p;
  const alpha = 2 * gamma2;
  const ctildeLen = lambda >> 2;
  const zBytesPerPoly = gamma1 === (1 << 17) ? 576 : 640;

  if (sig.byteLength !== p.sigBytes) return false;

  // Unpack pk
  const rho = pk.subarray(0, 32);
  const t1: Poly[] = [];
  for (let i = 0; i < k; i++) t1.push(unpackT1(pk.subarray(32 + i * 320, 32 + (i + 1) * 320)));

  // Unpack sig
  let sigOff = 0;
  const ctilde = sig.subarray(sigOff, sigOff + ctildeLen); sigOff += ctildeLen;
  const z: Poly[] = [];
  for (let i = 0; i < l; i++) { z.push(unpackZ(sig.subarray(sigOff, sigOff + zBytesPerPoly), gamma1)); sigOff += zBytesPerPoly; }
  const hEnc = sig.subarray(sigOff);

  // Decode h
  const h: Poly[] = Array.from({ length: k }, () => newPoly());
  let prev = 0;
  for (let i = 0; i < k; i++) {
    const end = hEnc[omega + i];
    if (end < prev || end > omega) return false;
    for (let j = prev; j < end; j++) {
      if (j > prev && hEnc[j] <= hEnc[j - 1]) return false;
      h[i][hEnc[j]] = 1;
    }
    prev = end;
  }

  // Norm check on z
  if (Math.max(...z.map(infNorm)) >= gamma1 - beta) return false;

  // μ = H(H(pk, 64) ∥ M, 64)
  const tr = shake256(pk, 64);
  const mu = shake256(concat(tr, M), 64);

  // c = SampleInBall(c̃, τ)
  const c = sampleInBall(ctilde, tau);
  const cHat = Int32Array.from(c); ntt(cHat);

  // Â
  const A = expandA(rho, k, l);

  // ŷ = NTT(z)
  const zHat = z.map(p => { const q = Int32Array.from(p); ntt(q); return q; });

  // w' = NTT^(-1)(Â·NTT(z) - 2^d·NTT^(-1)(c·t1))
  const t1Hat = t1.map(p => { const q = Int32Array.from(p); ntt(q); return q; });
  const wApprox: Poly[] = [];
  for (let i = 0; i < k; i++) {
    let acc = newPoly();
    for (let j = 0; j < l; j++) acc = addPoly(acc, multiplyNTT(A[i][j], zHat[j]));
    const ct1 = Int32Array.from(multiplyNTT(cHat, t1Hat[i]));
    intt(ct1);
    // Subtract 2^D * c·t1
    for (let j = 0; j < N; j++) acc[j] = mq(acc[j] - (1 << D) * ct1[j]);
    const wPoly = Int32Array.from(acc);
    intt(wPoly);
    wApprox.push(wPoly);
  }

  // w1' = UseHint(h, w', alpha)
  const w1p = wApprox.map((poly, i) => {
    const r = newPoly();
    for (let j = 0; j < N; j++) r[j] = recoverHighBits(h[i][j], poly[j], alpha);
    return r;
  });

  // c̃' = H(μ ∥ PackW1(w1'), lambda/4 bytes)
  const w1pPacked = concat(...w1p.map(p => packW1(p, gamma2)));
  const ctildePrime = shake256(concat(mu, w1pPacked), ctildeLen);

  // Compare c̃ and c̃'
  for (let i = 0; i < ctildeLen; i++) {
    if (ctilde[i] !== ctildePrime[i]) return false;
  }
  return true;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface MLDSAKeyPair {
  pk: Uint8Array; // public key
  sk: Uint8Array; // secret key
}

export interface MLDSASignatureResult {
  signature: Uint8Array;
}

/** ML-DSA key generation using secure randomness. */
export function mlDSAKeyGen(variant: MLDSAVariant): MLDSAKeyPair {
  const p = PARAMS[variant];
  const xi = randomBytes(32);
  const [pk, sk] = mlDSAKeyGenInternal(xi, p);
  return { pk, sk };
}

/** ML-DSA sign: sign a message with a secret key. */
export function mlDSASign(sk: Uint8Array, message: Uint8Array, variant: MLDSAVariant): MLDSASignatureResult {
  const p = PARAMS[variant];
  const rnd = randomBytes(32); // hedged signing randomness
  return { signature: mlDSASignInternal(sk, message, rnd, p) };
}

/** ML-DSA verify: verify a signature against a public key and message. */
export function mlDSAVerify(pk: Uint8Array, message: Uint8Array, signature: Uint8Array, variant: MLDSAVariant): boolean {
  try {
    return mlDSAVerifyInternal(pk, message, signature, PARAMS[variant]);
  } catch {
    return false;
  }
}

// ─── Self-test ────────────────────────────────────────────────────────────────

export function runMLDSASelfTest(): void {
  const variants: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  const msg = new TextEncoder().encode('Vril.js FIPS 204 ML-DSA self-test');

  for (const variant of variants) {
    const p = PARAMS[variant];
    const { pk, sk } = mlDSAKeyGen(variant);

    if (pk.byteLength !== p.pkBytes) throw new Error(`[VRIL FIPS 204] ${variant} pk size mismatch`);
    if (sk.byteLength !== p.skBytes) throw new Error(`[VRIL FIPS 204] ${variant} sk size mismatch`);

    const { signature } = mlDSASign(sk, msg, variant);
    if (signature.byteLength !== p.sigBytes) throw new Error(`[VRIL FIPS 204] ${variant} sig size mismatch`);

    const valid = mlDSAVerify(pk, msg, signature, variant);
    if (!valid) throw new Error(`[VRIL FIPS 204] ${variant} verification failed`);

    // Test that wrong message fails
    const wrongMsg = new TextEncoder().encode('wrong message');
    const invalid = mlDSAVerify(pk, wrongMsg, signature, variant);
    if (invalid) throw new Error(`[VRIL FIPS 204] ${variant} falsely accepted wrong message`);
  }
}
