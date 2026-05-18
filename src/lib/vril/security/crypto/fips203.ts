/**
 * Vril.js — Clean-room FIPS 203 ML-KEM engine.
 *
 * Implements ML-KEM-512, ML-KEM-768, and ML-KEM-1024 directly from the
 * NIST FIPS 203 (August 2024) specification. Uses only in-tree FIPS 202
 * SHA-3/SHAKE primitives. Zero external dependencies.
 */

import { sha3_256, sha3_512, shake256, ShakeXof } from './primitives/sha3';
import { randomBytes } from './primitives/random';

// ─── Field parameters ─────────────────────────────────────────────────────────

const Q = 3329;      // field modulus
const N = 256;       // polynomial degree
const INV128 = 3303; // 128^(-1) mod 3329, used in inverse NTT

// ─── NTT tables (computed once at module load from ζ = 17) ───────────────────
// ζ = 17 is a primitive 256th root of unity mod q (ζ^128 ≡ -1 mod q).
// zetas[i] = 17^BitRev7(i) mod q for i = 0..127 (NTT uses indices 1..127).
// gammas[i] = 17^(2·BitRev7(i)+1) mod q for i = 0..127 (BaseCaseMultiply).

function _bitRev7(n: number): number {
  let r = 0;
  for (let i = 0; i < 7; i++) { r = (r << 1) | (n & 1); n >>= 1; }
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

const ZETAS = new Int16Array(128);
const GAMMAS = new Int16Array(128);
for (let i = 0; i < 128; i++) {
  ZETAS[i] = _modpow(17, _bitRev7(i), Q);
  GAMMAS[i] = _modpow(17, 2 * _bitRev7(i) + 1, Q);
}

// ─── Parameter sets ───────────────────────────────────────────────────────────

interface MLKEMParams {
  k: number;    // module rank
  eta1: number; // noise parameter η₁
  eta2: number; // noise parameter η₂
  du: number;   // ciphertext compression bits (u vector)
  dv: number;   // ciphertext compression bits (v polynomial)
}

const PARAMS: Record<string, MLKEMParams> = {
  'ML-KEM-512':  { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
  'ML-KEM-768':  { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
  'ML-KEM-1024': { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
};

export type MLKEMVariant = keyof typeof PARAMS;

// ─── Polynomial type ──────────────────────────────────────────────────────────

type Poly = Uint16Array; // 256 coefficients in [0, q-1]

function newPoly(): Poly { return new Uint16Array(N); }

// ─── Arithmetic ───────────────────────────────────────────────────────────────

/** Fast mod-q reduction to [0, q-1]. */
function mq(x: number): number { return ((x % Q) + Q) % Q; }

function addPoly(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = (a[i] + b[i]) % Q;
  return c;
}

function subPoly(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = (a[i] - b[i] + Q) % Q;
  return c;
}

// ─── NTT (FIPS 203 Algorithms 9-12) ──────────────────────────────────────────

/** Algorithm 9: in-place forward NTT. Operates on coefficients mod q. */
function ntt(f: Poly): void {
  let zetaIdx = 1;
  let len = 128;
  while (len >= 2) {
    for (let start = 0; start < 256; start += 2 * len) {
      const z = ZETAS[zetaIdx++];
      for (let j = start; j < start + len; j++) {
        const t = (z * f[j + len]) % Q;
        f[j + len] = (f[j] - t + Q) % Q;
        f[j] = (f[j] + t) % Q;
      }
    }
    len >>= 1;
  }
}

/** Algorithm 10: in-place inverse NTT. Operates on coefficients mod q. */
function intt(f: Poly): void {
  let zetaIdx = 127;
  let len = 2;
  while (len <= 128) {
    for (let start = 0; start < 256; start += 2 * len) {
      const z = ZETAS[zetaIdx--];
      for (let j = start; j < start + len; j++) {
        const t = f[j];
        f[j] = (t + f[j + len]) % Q;
        f[j + len] = (z * ((f[j + len] - t + Q) % Q)) % Q;
      }
    }
    len <<= 1;
  }
  // Scale by 128^(-1) mod q
  for (let i = 0; i < N; i++) f[i] = (f[i] * INV128) % Q;
}

/**
 * Algorithm 12: base-case multiplication for one NTT-domain quadratic pair.
 * Returns (c0, c1) for (a0+a1·X)·(b0+b1·X) mod (X² - γ).
 */
function baseCaseMul(a0: number, a1: number, b0: number, b1: number, gamma: number): [number, number] {
  const c0 = mq(a0 * b0 + ((a1 * b1) % Q) * gamma);
  const c1 = mq(a0 * b1 + a1 * b0);
  return [c0, c1];
}

/** Algorithm 11: pointwise multiplication of two NTT-domain polynomials. */
function multiplyNTT(a: Poly, b: Poly): Poly {
  const c = newPoly();
  for (let i = 0; i < 128; i++) {
    const [c0, c1] = baseCaseMul(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], GAMMAS[i]);
    c[2 * i] = c0;
    c[2 * i + 1] = c1;
  }
  return c;
}

// ─── Encoding / Decoding (FIPS 203 Algorithms 4-7) ───────────────────────────

/** Algorithm 4: ByteEncode_d — pack 256 d-bit integers into a byte array. */
function byteEncode(F: Poly, d: number): Uint8Array {
  const out = new Uint8Array(32 * d);
  let bitPos = 0;
  for (let i = 0; i < N; i++) {
    let val = F[i];
    for (let b = 0; b < d; b++) {
      out[bitPos >> 3] |= (val & 1) << (bitPos & 7);
      val >>= 1;
      bitPos++;
    }
  }
  return out;
}

/** Algorithm 5: ByteDecode_d — unpack byte array into 256 integers (mod q when d=12). */
function byteDecode(B: Uint8Array, d: number): Poly {
  const F = newPoly();
  let bitPos = 0;
  const modulus = d === 12 ? Q : (1 << d);
  for (let i = 0; i < N; i++) {
    let val = 0;
    for (let b = 0; b < d; b++) {
      val |= ((B[bitPos >> 3] >> (bitPos & 7)) & 1) << b;
      bitPos++;
    }
    F[i] = val % modulus;
  }
  return F;
}

/** Algorithm 6: Compress_d — compress x ∈ [0,q) to d bits. */
function compress(x: number, d: number): number {
  const twoD = 1 << d;
  return ((x * twoD + (Q >>> 1)) / Q | 0) & (twoD - 1);
}

/** Algorithm 7: Decompress_d — decompress d-bit value to [0,q). */
function decompress(y: number, d: number): number {
  return ((y * Q + (1 << (d - 1))) >> d);
}

function compressPoly(f: Poly, d: number): Poly {
  const g = newPoly();
  for (let i = 0; i < N; i++) g[i] = compress(f[i], d);
  return g;
}

function decompressPoly(f: Poly, d: number): Poly {
  const g = newPoly();
  for (let i = 0; i < N; i++) g[i] = decompress(f[i], d);
  return g;
}

// ─── Sampling (FIPS 203 Algorithms 8-10) ─────────────────────────────────────

/** Algorithm 7 (SampleNTT): sample a polynomial in NTT form from SHAKE128 XOF. */
function sampleNTT(rho: Uint8Array, i: number, j: number): Poly {
  const xof = new ShakeXof(128);
  const seed = new Uint8Array(34);
  seed.set(rho);
  seed[32] = j;
  seed[33] = i;
  xof.update(seed);
  const f = newPoly();
  let count = 0;
  while (count < N) {
    const buf = xof.squeeze(3);
    const d1 = buf[0] | ((buf[1] & 0x0f) << 8);
    const d2 = (buf[1] >> 4) | (buf[2] << 4);
    if (d1 < Q) f[count++] = d1;
    if (d2 < Q && count < N) f[count++] = d2;
  }
  return f;
}

/** Algorithm 8 (SamplePolyCBD_η): sample from centered binomial distribution. */
function samplePolyCBD(prfOut: Uint8Array, eta: number): Poly {
  const f = newPoly();
  let bitPos = 0;
  for (let i = 0; i < N; i++) {
    let x = 0;
    for (let b = 0; b < eta; b++) {
      x += (prfOut[bitPos >> 3] >> (bitPos & 7)) & 1;
      bitPos++;
    }
    let y = 0;
    for (let b = 0; b < eta; b++) {
      y += (prfOut[bitPos >> 3] >> (bitPos & 7)) & 1;
      bitPos++;
    }
    f[i] = (x - y + Q) % Q;
  }
  return f;
}

/** PRF_η(s, b) = SHAKE256(s ∥ b, 64η) */
function prf(s: Uint8Array, b: number, eta: number): Uint8Array {
  const input = new Uint8Array(33);
  input.set(s);
  input[32] = b;
  return shake256(input, 64 * eta);
}

// ─── K-PKE (FIPS 203 Algorithms 13-15) ───────────────────────────────────────

/**
 * Algorithm 13: K-PKE.KeyGen — generate encapsulation/decapsulation key pair.
 * Returns [ek_PKE (384k+32 bytes), dk_PKE (384k bytes)].
 */
function kPKEKeyGen(d: Uint8Array, p: MLKEMParams): [Uint8Array, Uint8Array] {
  const { k, eta1 } = p;
  // (ρ, σ) ← G(d ∥ k_byte)
  const gInput = new Uint8Array(33);
  gInput.set(d);
  gInput[32] = k;
  const gs = sha3_512(gInput);
  const rho = gs.subarray(0, 32);
  const sigma = gs.subarray(32, 64);

  // Generate matrix A_hat from ρ
  const A: Poly[][] = Array.from({ length: k }, () => Array(k));
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < k; j++) {
      A[i][j] = sampleNTT(rho, i, j);
    }
  }

  // Sample s (k secret polynomials) and e (k error polynomials) via CBD
  const s: Poly[] = [];
  const e: Poly[] = [];
  let nonce = 0;
  for (let i = 0; i < k; i++) s.push(samplePolyCBD(prf(sigma, nonce++, eta1), eta1));
  for (let i = 0; i < k; i++) e.push(samplePolyCBD(prf(sigma, nonce++, eta1), eta1));

  // NTT of s and e
  const sHat = s.map(p => { const pc = Uint16Array.from(p); ntt(pc); return pc; });
  const eHat = e.map(p => { const pc = Uint16Array.from(p); ntt(pc); return pc; });

  // t̂ = A_hat ° ŝ + ê
  const tHat: Poly[] = [];
  for (let i = 0; i < k; i++) {
    let row = newPoly();
    for (let j = 0; j < k; j++) {
      row = addPoly(row, multiplyNTT(A[i][j], sHat[j]));
    }
    tHat.push(addPoly(row, eHat[i]));
  }

  // Encode keys
  const ek = new Uint8Array(384 * k + 32);
  for (let i = 0; i < k; i++) ek.set(byteEncode(tHat[i], 12), i * 384);
  ek.set(rho, 384 * k);

  const dk = new Uint8Array(384 * k);
  for (let i = 0; i < k; i++) dk.set(byteEncode(sHat[i], 12), i * 384);

  return [ek, dk];
}

/**
 * Algorithm 14: K-PKE.Encrypt — encrypt a 32-byte message.
 * Returns ciphertext c.
 */
function kPKEEncrypt(ek: Uint8Array, m: Uint8Array, r: Uint8Array, p: MLKEMParams): Uint8Array {
  const { k, eta1, eta2, du, dv } = p;

  // Decode t̂ and ρ from ek
  const tHat: Poly[] = [];
  for (let i = 0; i < k; i++) tHat.push(byteDecode(ek.subarray(i * 384, i * 384 + 384), 12));
  const rho = ek.subarray(k * 384, k * 384 + 32);

  // Regenerate A_hat (same as KeyGen)
  const A: Poly[][] = Array.from({ length: k }, () => Array(k));
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < k; j++) {
      A[i][j] = sampleNTT(rho, i, j);
    }
  }

  // Sample r_vec, e1, e2
  const rVec: Poly[] = [];
  const e1: Poly[] = [];
  let nonce = 0;
  for (let i = 0; i < k; i++) rVec.push(samplePolyCBD(prf(r, nonce++, eta1), eta1));
  for (let i = 0; i < k; i++) e1.push(samplePolyCBD(prf(r, nonce++, eta2), eta2));
  const e2 = samplePolyCBD(prf(r, nonce, eta2), eta2);

  // r̂ = NTT(r_vec)
  const rHat = rVec.map(p => { const pc = Uint16Array.from(p); ntt(pc); return pc; });

  // u = NTT^(-1)(A^T ° r̂) + e1   [using transpose: A^T[i][j] = A[j][i]]
  const u: Poly[] = [];
  for (let i = 0; i < k; i++) {
    let col = newPoly();
    for (let j = 0; j < k; j++) {
      col = addPoly(col, multiplyNTT(A[j][i], rHat[j]));
    }
    const uAfterINTT = Uint16Array.from(col);
    intt(uAfterINTT);
    u.push(addPoly(uAfterINTT, e1[i]));
  }

  // mu = Decompress_1(ByteDecode_1(m))
  const mu = decompressPoly(byteDecode(m, 1), 1);

  // v = NTT^(-1)(t̂^T ° r̂) + e2 + mu
  let vAcc = newPoly();
  for (let i = 0; i < k; i++) {
    vAcc = addPoly(vAcc, multiplyNTT(tHat[i], rHat[i]));
  }
  const vTemp = Uint16Array.from(vAcc);
  intt(vTemp);
  const v = addPoly(addPoly(vTemp, e2), mu);

  // Encode ciphertext
  const c1ByteLen = du * 32;
  const c2ByteLen = dv * 32;
  const ct = new Uint8Array(c1ByteLen * k + c2ByteLen);
  for (let i = 0; i < k; i++) {
    ct.set(byteEncode(compressPoly(u[i], du), du), i * c1ByteLen);
  }
  ct.set(byteEncode(compressPoly(v, dv), dv), k * c1ByteLen);
  return ct;
}

/**
 * Algorithm 15: K-PKE.Decrypt — recover 32-byte plaintext from ciphertext.
 */
function kPKEDecrypt(dk: Uint8Array, ct: Uint8Array, p: MLKEMParams): Uint8Array {
  const { k, du, dv } = p;
  const c1ByteLen = du * 32;
  const c2ByteLen = dv * 32;

  // Decode u and v from ciphertext
  const u: Poly[] = [];
  for (let i = 0; i < k; i++) {
    u.push(decompressPoly(byteDecode(ct.subarray(i * c1ByteLen, i * c1ByteLen + c1ByteLen), du), du));
  }
  const v = decompressPoly(byteDecode(ct.subarray(k * c1ByteLen, k * c1ByteLen + c2ByteLen), dv), dv);

  // Decode ŝ from dk
  const sHat: Poly[] = [];
  for (let i = 0; i < k; i++) {
    sHat.push(byteDecode(dk.subarray(i * 384, i * 384 + 384), 12));
  }

  // w = v - NTT^(-1)(ŝ^T ° NTT(u))
  let acc = newPoly();
  for (let i = 0; i < k; i++) {
    const uHat = Uint16Array.from(u[i]);
    ntt(uHat);
    acc = addPoly(acc, multiplyNTT(sHat[i], uHat));
  }
  const accTemp = Uint16Array.from(acc);
  intt(accTemp);
  const w = subPoly(v, accTemp);

  return byteEncode(compressPoly(w, 1), 1);
}

// ─── ML-KEM (FIPS 203 Algorithms 16-21) ──────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/** Constant-time byte array equality check. */
function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Constant-time select: returns a if cond else b. */
function ctSelect(cond: boolean, a: Uint8Array, b: Uint8Array): Uint8Array {
  const mask = cond ? 0xff : 0x00;
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] & mask) | (b[i] & (~mask & 0xff));
  return out;
}

/**
 * Algorithm 16: ML-KEM.KeyGen_internal(d, z) — deterministic key generation.
 * Returns [ek (encapsulation key), dk (decapsulation key)].
 */
function mlKEMKeyGenInternal(d: Uint8Array, z: Uint8Array, p: MLKEMParams): [Uint8Array, Uint8Array] {
  const [ekPKE, dkPKE] = kPKEKeyGen(d, p);
  const ek = ekPKE;
  const h = sha3_256(ek);
  const dk = concat(dkPKE, ek, h, z);
  return [ek, dk];
}

/**
 * Algorithm 17: ML-KEM.Encaps_internal(ek, m) — deterministic encapsulation.
 * Returns [K (32-byte shared secret), c (ciphertext)].
 */
function mlKEMEncapsInternal(ek: Uint8Array, m: Uint8Array, p: MLKEMParams): [Uint8Array, Uint8Array] {
  const h = sha3_256(ek);
  const gs = sha3_512(concat(m, h));
  const K = gs.subarray(0, 32);
  const r = gs.subarray(32, 64);
  const ct = kPKEEncrypt(ek, m, r, p);
  return [K, ct];
}

/**
 * Algorithm 18: ML-KEM.Decaps_internal(dk, c) — decapsulation with implicit rejection.
 * Returns 32-byte shared secret K.
 */
function mlKEMDecapsInternal(dk: Uint8Array, ct: Uint8Array, p: MLKEMParams): Uint8Array {
  const { k } = p;
  const dkPKE = dk.subarray(0, 384 * k);
  const ek = dk.subarray(384 * k, 768 * k + 32);
  const h = dk.subarray(768 * k + 32, 768 * k + 64);
  const z = dk.subarray(768 * k + 64, 768 * k + 96);

  const mPrime = kPKEDecrypt(dkPKE, ct, p);
  const gs = sha3_512(concat(mPrime, h));
  const kPrime = gs.subarray(0, 32);
  const rPrime = gs.subarray(32, 64);

  // J(z ∥ c) = SHAKE256(z ∥ c, 32) — implicit rejection value
  const kBar = shake256(concat(z, ct), 32);

  const ctPrime = kPKEEncrypt(ek, mPrime, rPrime, p);

  // Constant-time conditional selection
  return ctSelect(ctEqual(ct, ctPrime), kPrime, kBar);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** ML-KEM key pair result. */
export interface MLKEMKeyPair {
  ek: Uint8Array; // encapsulation key
  dk: Uint8Array; // decapsulation key
}

/** ML-KEM encapsulation result. */
export interface MLKEMEncapsResult {
  sharedSecret: Uint8Array; // 32-byte shared secret
  ciphertext: Uint8Array;   // ciphertext to send to the recipient
}

/** Algorithm 19: ML-KEM.KeyGen — generate a key pair using secure randomness. */
export function mlKEMKeyGen(variant: MLKEMVariant): MLKEMKeyPair {
  const p = PARAMS[variant];
  const d = randomBytes(32);
  const z = randomBytes(32);
  const [ek, dk] = mlKEMKeyGenInternal(d, z, p);
  return { ek, dk };
}

/** Algorithm 20: ML-KEM.Encaps — encapsulate to a recipient public (encapsulation) key. */
export function mlKEMEncaps(ek: Uint8Array, variant: MLKEMVariant): MLKEMEncapsResult {
  const p = PARAMS[variant];
  const m = randomBytes(32);
  const [K, ct] = mlKEMEncapsInternal(ek, m, p);
  return { sharedSecret: K, ciphertext: ct };
}

/** Algorithm 21: ML-KEM.Decaps — recover the shared secret from ciphertext. */
export function mlKEMDecaps(dk: Uint8Array, ciphertext: Uint8Array, variant: MLKEMVariant): Uint8Array {
  return mlKEMDecapsInternal(dk, ciphertext, PARAMS[variant]);
}

// ─── Self-test ────────────────────────────────────────────────────────────────

/**
 * Perform a round-trip consistency check for all three ML-KEM parameter sets.
 * Verifies that encapsulation and decapsulation produce the same shared secret.
 * Throws if any check fails; does not test against NIST KATs but validates
 * internal self-consistency and all size invariants.
 */
export function runMLKEMSelfTest(): void {
  const variants: MLKEMVariant[] = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];
  const expectedSizes: Record<MLKEMVariant, [number, number, number]> = {
    'ML-KEM-512':  [800, 1632, 768],
    'ML-KEM-768':  [1184, 2400, 1088],
    'ML-KEM-1024': [1568, 3168, 1568],
  };

  for (const variant of variants) {
    const { ek, dk } = mlKEMKeyGen(variant);
    const [ekLen, dkLen, ctLen] = expectedSizes[variant];

    if (ek.byteLength !== ekLen) throw new Error(`[VRIL FIPS 203] ${variant} ek size mismatch`);
    if (dk.byteLength !== dkLen) throw new Error(`[VRIL FIPS 203] ${variant} dk size mismatch`);

    const { sharedSecret, ciphertext } = mlKEMEncaps(ek, variant);
    if (ciphertext.byteLength !== ctLen) throw new Error(`[VRIL FIPS 203] ${variant} ct size mismatch`);
    if (sharedSecret.byteLength !== 32) throw new Error(`[VRIL FIPS 203] ${variant} K size mismatch`);

    const recovered = mlKEMDecaps(dk, ciphertext, variant);
    if (recovered.byteLength !== 32) throw new Error(`[VRIL FIPS 203] ${variant} recovered K size mismatch`);

    // Shared secrets must match
    if (!ctEqual(sharedSecret, recovered)) {
      throw new Error(`[VRIL FIPS 203] ${variant} shared secret mismatch`);
    }
  }
}
