/**
 * Vril.js — Clean-room FIPS 205 SLH-DSA engine.
 *
 * Implements all SLH-DSA parameter sets (SHAKE and SHA2 variants) directly
 * from the NIST FIPS 205 (August 2024) specification. Uses in-tree FIPS 202
 * SHA-3/SHAKE primitives and in-tree FIPS 180-4 SHA-256/SHA-512 primitives.
 * Zero external dependencies.
 */

import { shake128, shake256 } from './primitives/sha3';
import { sha256, sha512, hmacSha256, hmacSha512, mgf1Sha256, mgf1Sha512 } from './primitives/sha2';
import { randomBytes } from './primitives/random';

// ─── Parameter sets ───────────────────────────────────────────────────────────

interface SLHDSAParams {
  n: number;          // security parameter in bytes
  h: number;          // total hypertree height
  d: number;          // number of layers
  hp: number;         // h/d = layer tree height
  a: number;          // FORS tree height
  k: number;          // number of FORS trees
  lgW: number;        // lg(Winternitz parameter) = 4
  m: number;          // message digest length in bytes
  pkBytes: number;
  skBytes: number;
  sigBytes: number;
  sha2: boolean;      // true = SHA2, false = SHAKE
}

const PARAMS: Record<string, SLHDSAParams> = {
  'SLH-DSA-SHAKE-128s': { n:16, h:63, d:7,  hp:9,  a:12, k:14, lgW:4, m:30, pkBytes:32,  skBytes:64,  sigBytes:7856,  sha2:false },
  'SLH-DSA-SHAKE-128f': { n:16, h:66, d:22, hp:3,  a:6,  k:33, lgW:4, m:34, pkBytes:32,  skBytes:64,  sigBytes:17088, sha2:false },
  'SLH-DSA-SHAKE-192s': { n:24, h:63, d:7,  hp:9,  a:14, k:17, lgW:4, m:39, pkBytes:48,  skBytes:96,  sigBytes:16224, sha2:false },
  'SLH-DSA-SHAKE-192f': { n:24, h:66, d:22, hp:3,  a:8,  k:33, lgW:4, m:42, pkBytes:48,  skBytes:96,  sigBytes:35664, sha2:false },
  'SLH-DSA-SHAKE-256s': { n:32, h:64, d:8,  hp:8,  a:14, k:22, lgW:4, m:47, pkBytes:64,  skBytes:128, sigBytes:29792, sha2:false },
  'SLH-DSA-SHAKE-256f': { n:32, h:68, d:17, hp:4,  a:9,  k:35, lgW:4, m:49, pkBytes:64,  skBytes:128, sigBytes:49856, sha2:false },
  'SLH-DSA-SHA2-128s':  { n:16, h:63, d:7,  hp:9,  a:12, k:14, lgW:4, m:30, pkBytes:32,  skBytes:64,  sigBytes:7856,  sha2:true  },
  'SLH-DSA-SHA2-128f':  { n:16, h:66, d:22, hp:3,  a:6,  k:33, lgW:4, m:34, pkBytes:32,  skBytes:64,  sigBytes:17088, sha2:true  },
  'SLH-DSA-SHA2-192s':  { n:24, h:63, d:7,  hp:9,  a:14, k:17, lgW:4, m:39, pkBytes:48,  skBytes:96,  sigBytes:16224, sha2:true  },
  'SLH-DSA-SHA2-192f':  { n:24, h:66, d:22, hp:3,  a:8,  k:33, lgW:4, m:42, pkBytes:48,  skBytes:96,  sigBytes:35664, sha2:true  },
  'SLH-DSA-SHA2-256s':  { n:32, h:64, d:8,  hp:8,  a:14, k:22, lgW:4, m:47, pkBytes:64,  skBytes:128, sigBytes:29792, sha2:true  },
  'SLH-DSA-SHA2-256f':  { n:32, h:68, d:17, hp:4,  a:9,  k:35, lgW:4, m:49, pkBytes:64,  skBytes:128, sigBytes:49856, sha2:true  },
};

export type SLHDSAVariant = keyof typeof PARAMS;

// ─── Address types (FIPS 205 Section 4) ──────────────────────────────────────

const ADDR_TYPE_WOTS     = 0;
const ADDR_TYPE_WOTSPK   = 1;
const ADDR_TYPE_HASHTREE = 2;
const ADDR_TYPE_FORSTREE = 3;
const ADDR_TYPE_FORSPK   = 4;

type ADRS = Uint8Array; // 32 bytes

function newADRS(): ADRS { return new Uint8Array(32); }

function setLayerAddress(adrs: ADRS, layer: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(0, layer);
}
function setTreeAddress(adrs: ADRS, tree: bigint): void {
  const dv = new DataView(adrs.buffer, adrs.byteOffset);
  dv.setUint32(4, 0);
  dv.setUint32(8, Number(tree >> 32n) >>> 0);
  dv.setUint32(12, Number(tree & 0xffffffffn) >>> 0);
}
function setType(adrs: ADRS, type: number): void {
  const dv = new DataView(adrs.buffer, adrs.byteOffset);
  dv.setUint32(16, type);
  // Clear the address-specific words after the type field.
  dv.setUint32(20, 0); dv.setUint32(24, 0); dv.setUint32(28, 0);
}
function setKeyPairAddress(adrs: ADRS, kp: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(20, kp);
}
function setChainAddress(adrs: ADRS, chain: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(24, chain);
}
function setHashAddress(adrs: ADRS, hash: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(28, hash);
}
function setTreeHeight(adrs: ADRS, z: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(24, z);
}
function setTreeIndex(adrs: ADRS, i: number): void {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(28, i);
}
function getKeyPairAddress(adrs: ADRS): number {
  return new DataView(adrs.buffer, adrs.byteOffset).getUint32(20);
}
function copyADRS(adrs: ADRS): ADRS { return Uint8Array.from(adrs); }

// ─── Compressed address for SHA2 variants ────────────────────────────────────

/** Compress 32-byte ADRS to 22-byte compact form (FIPS 205 Section 9.3). */
function compressADRS(adrs: ADRS): Uint8Array {
  const c = new Uint8Array(22);
  c[0] = adrs[3];                   // Layer address (1 byte, MSB of 4-byte field)
  c.set(adrs.subarray(8, 16), 1);   // Tree address (8 bytes of 12-byte field, offset 4)
  c[9] = adrs[19];                  // Type (1 byte, LSB of 4-byte field)
  c.set(adrs.subarray(20, 32), 10); // Address part (12 bytes)
  return c;
}

// ─── Byte utilities ───────────────────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// ─── Hash function abstraction (FIPS 205 Sections 10.1 and 10.2) ─────────────

interface HashFunctions {
  F(pkSeed: Uint8Array, adrs: ADRS, m: Uint8Array): Uint8Array;
  H(pkSeed: Uint8Array, adrs: ADRS, m: Uint8Array): Uint8Array;
  T_l(pkSeed: Uint8Array, adrs: ADRS, m: Uint8Array): Uint8Array;
  PRF(pkSeed: Uint8Array, skSeed: Uint8Array, adrs: ADRS): Uint8Array;
  PRF_msg(skPRF: Uint8Array, optRand: Uint8Array, m: Uint8Array): Uint8Array;
  H_msg(R: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, m: Uint8Array): Uint8Array;
}

function buildHashFunctions(p: SLHDSAParams): HashFunctions {
  const n = p.n;
  if (!p.sha2) {
    // SHAKE variants (Section 10.1)
    const shakeN = n <= 16 ? shake128 : shake256;
    return {
      F: (pk, adrs, m) => shakeN(concat(pk, adrs, m), n),
      H: (pk, adrs, m) => shakeN(concat(pk, adrs, m), n),
      T_l: (pk, adrs, m) => shakeN(concat(pk, adrs, m), n),
      PRF: (pk, sk, adrs) => shakeN(concat(pk, adrs, sk), n),
      PRF_msg: (skPRF, opt, m) => shakeN(concat(skPRF, opt, m), n),
      H_msg: (R, pkSeed, pkRoot, m) => shakeN(concat(R, pkSeed, pkRoot, m), p.m),
    };
  } else {
    // SHA2 variants (Section 10.2)
    const hashFn = n <= 24 ? sha256 : sha512;
    const hmacFn = n <= 24 ? hmacSha256 : hmacSha512;
    const mgf1Fn = n <= 24 ? mgf1Sha256 : mgf1Sha512;
    const pad = new Uint8Array(64 - n); // zero-padding to align to 64 bytes
    return {
      F: (pk, adrs, m) => hashFn(concat(pk, pad, compressADRS(adrs), m)).subarray(0, n),
      H: (pk, adrs, m) => hashFn(concat(pk, pad, compressADRS(adrs), m)).subarray(0, n),
      T_l: (pk, adrs, m) => hashFn(concat(pk, pad, compressADRS(adrs), m)).subarray(0, n),
      PRF: (pk, sk, adrs) => hashFn(concat(pk, pad, compressADRS(adrs), sk)).subarray(0, n),
      PRF_msg: (skPRF, opt, m) => hmacFn(skPRF, concat(opt, m)).subarray(0, n),
      H_msg: (R, pkSeed, pkRoot, m) => mgf1Fn(concat(R, pkSeed, pkRoot, m), p.m),
    };
  }
}

// ─── Winternitz helpers ───────────────────────────────────────────────────────

const W = 16; // Winternitz parameter (always 16 in FIPS 205)

/** baseW encoding: split byte array into base-W digits. */
function baseW(x: Uint8Array, outLen: number): number[] {
  const out: number[] = [];
  let bits = 0, total = 0;
  let i = 0;
  for (let j = 0; j < outLen; j++) {
    if (bits === 0) { total = x[i++]; bits = 8; }
    bits -= 4; // lgW = 4
    out.push((total >> bits) & (W - 1));
  }
  return out;
}

/**
 * Compute WOTS+ checksum for a message digest.
 * Per FIPS 205 Section 5: csum is encoded as big-endian in ceil(len2*lgW/8) bytes,
 * shifted left so the len2 base-W digits occupy the MSBs.
 */
function wotsChecksum(M: number[], n: number): number[] {
  const len1 = wotsLen1(n);
  const len2 = wotsLen2(n);
  let csum = 0;
  for (let i = 0; i < len1; i++) csum += W - 1 - M[i];
  // Pack csum into ceil(len2*4/8) bytes, MSB-aligned
  const csumBits = len2 * 4; // lgW = 4
  const csumBytesNeeded = Math.ceil(csumBits / 8);
  const shift = 8 * csumBytesNeeded - csumBits; // bits to shift into MSB position
  const csumShifted = csum << shift;
  const s = new Uint8Array(csumBytesNeeded);
  for (let i = 0; i < csumBytesNeeded; i++) {
    s[i] = (csumShifted >>> (8 * (csumBytesNeeded - 1 - i))) & 0xff;
  }
  return baseW(s, len2);
}

/** WOTS+ chain function. */
function chain(x: Uint8Array, start: number, steps: number, pk: Uint8Array, adrs: ADRS, hf: HashFunctions): Uint8Array {
  if (steps === 0) return Uint8Array.from(x);
  const out = chain(x, start, steps - 1, pk, adrs, hf);
  const a2 = copyADRS(adrs);
  setHashAddress(a2, start + steps - 1);
  return hf.F(pk, a2, out);
}

// WOTS+ parameter: len = len1 + len2
function wotsLen1(n: number): number { return Math.ceil(8 * n / 4); }
function wotsLen2(n: number): number { return Math.floor(Math.log2(wotsLen1(n) * (W - 1)) / 4) + 1; }
function wotsLen(n: number): number { return wotsLen1(n) + wotsLen2(n); }

/** Generate WOTS+ public key from secret seed. */
function wotsPKGen(sk: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, n: number): Uint8Array {
  const len = wotsLen(n);
  const pks: Uint8Array[] = [];
  for (let i = 0; i < len; i++) {
    const a2 = copyADRS(adrs);
    setChainAddress(a2, i);
    setHashAddress(a2, 0);
    const sk_i = hf.PRF(pkSeed, sk, a2);
    const a3 = copyADRS(adrs);
    setChainAddress(a3, i);
    pks.push(chain(sk_i, 0, W - 1, pkSeed, a3, hf));
  }
  const a4 = copyADRS(adrs);
  setType(a4, ADDR_TYPE_WOTSPK);
  setKeyPairAddress(a4, getKeyPairAddress(adrs));
  return hf.T_l(pkSeed, a4, concat(...pks));
}

/** Generate WOTS+ signature. */
function wotsSign(M: Uint8Array, sk: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, n: number): Uint8Array {
  const len1 = wotsLen1(n);
  const len = wotsLen(n);
  const msg = baseW(M, len1);
  const cs = wotsChecksum(msg, n);
  const allMsg = [...msg, ...cs];
  const sig: Uint8Array[] = [];
  for (let i = 0; i < len; i++) {
    const a2 = copyADRS(adrs);
    setChainAddress(a2, i);
    setHashAddress(a2, 0);
    const sk_i = hf.PRF(pkSeed, sk, a2);
    const a3 = copyADRS(adrs);
    setChainAddress(a3, i);
    sig.push(chain(sk_i, 0, allMsg[i], pkSeed, a3, hf));
  }
  return concat(...sig);
}

/** Recover WOTS+ public key from signature. */
function wotsPKFromSig(sig: Uint8Array, M: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, n: number): Uint8Array {
  const len1 = wotsLen1(n);
  const len = wotsLen(n);
  const msg = baseW(M, len1);
  const cs = wotsChecksum(msg, n);
  const allMsg = [...msg, ...cs];
  const pks: Uint8Array[] = [];
  for (let i = 0; i < len; i++) {
    const a3 = copyADRS(adrs);
    setChainAddress(a3, i);
    pks.push(chain(sig.subarray(i * n, i * n + n), allMsg[i], W - 1 - allMsg[i], pkSeed, a3, hf));
  }
  const a4 = copyADRS(adrs);
  setType(a4, ADDR_TYPE_WOTSPK);
  setKeyPairAddress(a4, getKeyPairAddress(adrs));
  return hf.T_l(pkSeed, a4, concat(...pks));
}

// ─── XMSS (FIPS 205 Algorithms 9-11) ─────────────────────────────────────────

/** Compute xmss subtree node at height z, index i. */
function xmssNode(skSeed: Uint8Array, pkSeed: Uint8Array, i: number, z: number, adrs: ADRS, hf: HashFunctions, n: number, hp: number): Uint8Array {
  if (z === 0) {
    // Leaf node = WOTS+ public key
    const a2 = copyADRS(adrs);
    setType(a2, ADDR_TYPE_WOTS);
    setKeyPairAddress(a2, i);
    return wotsPKGen(skSeed, pkSeed, a2, hf, n);
  }
  const left  = xmssNode(skSeed, pkSeed, 2 * i, z - 1, adrs, hf, n, hp);
  const right = xmssNode(skSeed, pkSeed, 2 * i + 1, z - 1, adrs, hf, n, hp);
  const a2 = copyADRS(adrs);
  setType(a2, ADDR_TYPE_HASHTREE);
  setTreeHeight(a2, z);
  setTreeIndex(a2, i);
  return hf.H(pkSeed, a2, concat(left, right));
}

/** Sign one XMSS layer: returns auth path. */
function xmssSign(M: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array, idx: number, adrs: ADRS, hf: HashFunctions, n: number, hp: number): Uint8Array {
  // Authentication path
  const auth: Uint8Array[] = [];
  for (let j = 0; j < hp; j++) {
    const k = Math.floor(idx / (1 << j)) ^ 1;
    auth.push(xmssNode(skSeed, pkSeed, k, j, adrs, hf, n, hp));
  }
  // WOTS+ signature
  const a2 = copyADRS(adrs);
  setType(a2, ADDR_TYPE_WOTS);
  setKeyPairAddress(a2, idx);
  const wotsSig = wotsSign(M, skSeed, pkSeed, a2, hf, n);
  return concat(wotsSig, ...auth);
}

/** Recover XMSS root from signature. */
function xmssPKFromSig(idx: number, sig: Uint8Array, M: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, n: number, hp: number): Uint8Array {
  const wotsSigLen = wotsLen(n) * n;
  const wotsSig = sig.subarray(0, wotsSigLen);
  const auth = Array.from({ length: hp }, (_, j) => sig.subarray(wotsSigLen + j * n, wotsSigLen + (j + 1) * n));

  const a2 = copyADRS(adrs);
  setType(a2, ADDR_TYPE_WOTS);
  setKeyPairAddress(a2, idx);
  let node = wotsPKFromSig(wotsSig, M, pkSeed, a2, hf, n);

  let index = idx;
  for (let j = 0; j < hp; j++) {
    const a3 = copyADRS(adrs);
    setType(a3, ADDR_TYPE_HASHTREE);
    setTreeHeight(a3, j + 1);
    if (Math.floor(index / 2) % 2 === 0) {
      setTreeIndex(a3, Math.floor(index / 2));
      node = hf.H(pkSeed, a3, concat(node, auth[j]));
    } else {
      setTreeIndex(a3, Math.floor(index / 2));
      node = hf.H(pkSeed, a3, concat(auth[j], node));
    }
    index = Math.floor(index / 2);
  }
  return node;
}

// ─── HyperTree (FIPS 205 Algorithms 12-13) ────────────────────────────────────

/** Sign with the hypertree. */
function htSign(M: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array, idxTree: bigint, idxLeaf: number, hf: HashFunctions, p: SLHDSAParams): Uint8Array {
  const { n, d, hp } = p;
  const htSigs: Uint8Array[] = [];
  let mPrime = M;
  let treeAddr = idxTree;
  let leafAddr = idxLeaf;

  for (let j = 0; j < d; j++) {
    const adrs = newADRS();
    setLayerAddress(adrs, j);
    setTreeAddress(adrs, treeAddr);
    htSigs.push(xmssSign(mPrime, skSeed, pkSeed, leafAddr, adrs, hf, n, hp));

    // Compute root to use as message for next layer
    const adrs2 = newADRS();
    setLayerAddress(adrs2, j);
    setTreeAddress(adrs2, treeAddr);
    mPrime = xmssPKFromSig(leafAddr, htSigs[j], mPrime, pkSeed, adrs2, hf, n, hp);

    // Move up the tree
    const xmssHeight = hp;
    leafAddr = Number(treeAddr & BigInt((1 << xmssHeight) - 1));
    treeAddr >>= BigInt(xmssHeight);
  }
  return concat(...htSigs);
}

/** Verify the hypertree signature. */
function htVerify(M: Uint8Array, htSig: Uint8Array, pkSeed: Uint8Array, idxTree: bigint, idxLeaf: number, pkRoot: Uint8Array, hf: HashFunctions, p: SLHDSAParams): boolean {
  const { n, d, hp } = p;
  const xmssSigLen = (wotsLen(n) + hp) * n;
  let mPrime = M;
  let treeAddr = idxTree;
  let leafAddr = idxLeaf;

  for (let j = 0; j < d; j++) {
    const sig = htSig.subarray(j * xmssSigLen, (j + 1) * xmssSigLen);
    const adrs = newADRS();
    setLayerAddress(adrs, j);
    setTreeAddress(adrs, treeAddr);
    mPrime = xmssPKFromSig(leafAddr, sig, mPrime, pkSeed, adrs, hf, n, hp);

    leafAddr = Number(treeAddr & BigInt((1 << hp) - 1));
    treeAddr >>= BigInt(hp);
  }

  for (let i = 0; i < n; i++) {
    if (mPrime[i] !== pkRoot[i]) return false;
  }
  return true;
}

// ─── FORS (FIPS 205 Algorithms 14-17) ────────────────────────────────────────

/** Generate FORS secret key element. */
function forsSkGen(skSeed: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, idx: number, hf: HashFunctions): Uint8Array {
  const a2 = copyADRS(adrs);
  setTreeHeight(a2, 0);
  setTreeIndex(a2, idx);
  return hf.PRF(pkSeed, skSeed, a2);
}

/** Compute FORS subtree node. */
function forsNode(skSeed: Uint8Array, pkSeed: Uint8Array, i: number, z: number, adrs: ADRS, hf: HashFunctions, n: number, a: number): Uint8Array {
  if (z === 0) {
    const sk = forsSkGen(skSeed, pkSeed, adrs, i, hf);
    const a2 = copyADRS(adrs);
    setTreeHeight(a2, 0);
    setTreeIndex(a2, i);
    return hf.F(pkSeed, a2, sk);
  }
  const left  = forsNode(skSeed, pkSeed, 2 * i, z - 1, adrs, hf, n, a);
  const right = forsNode(skSeed, pkSeed, 2 * i + 1, z - 1, adrs, hf, n, a);
  const a2 = copyADRS(adrs);
  setTreeHeight(a2, z);
  setTreeIndex(a2, i);
  return hf.H(pkSeed, a2, concat(left, right));
}

/** Compute FORS signature. */
function forsSign(md: Uint8Array, skSeed: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, p: SLHDSAParams): Uint8Array {
  const { n, k, a } = p;
  const treeSz = 1 << a;
  const sigs: Uint8Array[] = [];
  for (let i = 0; i < k; i++) {
    // Get a-bit index from the i-th chunk of the message digest
    let idx = 0;
    for (let b = 0; b < a; b++) {
      const bitPos = i * a + b;
      idx |= ((md[bitPos >> 3] >> (bitPos & 7)) & 1) << b;
    }
    // Secret value
    const a2 = copyADRS(adrs);
    setType(a2, ADDR_TYPE_FORSTREE);
    setTreeIndex(a2, i * treeSz + idx);
    const sk = forsSkGen(skSeed, pkSeed, a2, i * treeSz + idx, hf);
    // Auth path
    const authPath: Uint8Array[] = [];
    for (let j = 0; j < a; j++) {
      const s = Math.floor(idx / (1 << j)) ^ 1;
      authPath.push(forsNode(skSeed, pkSeed, i * (treeSz >> j) + s, j, adrs, hf, n, a));
    }
    sigs.push(concat(sk, ...authPath));
  }
  return concat(...sigs);
}

/** Recover FORS public key from signature. */
function forsPKFromSig(sig: Uint8Array, md: Uint8Array, pkSeed: Uint8Array, adrs: ADRS, hf: HashFunctions, p: SLHDSAParams): Uint8Array {
  const { n, k, a } = p;
  const treeSz = 1 << a;
  const elSize = n + a * n; // sk + auth path size per tree
  const roots: Uint8Array[] = [];

  for (let i = 0; i < k; i++) {
    let idx = 0;
    for (let b = 0; b < a; b++) {
      const bitPos = i * a + b;
      idx |= ((md[bitPos >> 3] >> (bitPos & 7)) & 1) << b;
    }
    const sk = sig.subarray(i * elSize, i * elSize + n);
    const authPath = Array.from({ length: a }, (_, j) => sig.subarray(i * elSize + n + j * n, i * elSize + n + (j + 1) * n));

    const a2 = copyADRS(adrs);
    setType(a2, ADDR_TYPE_FORSTREE);
    setTreeIndex(a2, i * treeSz + idx);
    setTreeHeight(a2, 0);
    let node = hf.F(pkSeed, a2, sk);

    let treeIdx = idx;
    for (let j = 0; j < a; j++) {
      const a3 = copyADRS(adrs);
      setType(a3, ADDR_TYPE_FORSTREE);
      setTreeHeight(a3, j + 1);
      const parentTreeIdx = Math.floor(treeIdx / 2);
      setTreeIndex(a3, i * (treeSz >> (j + 1)) + parentTreeIdx);
      if (treeIdx % 2 === 0) {
        node = hf.H(pkSeed, a3, concat(node, authPath[j]));
      } else {
        node = hf.H(pkSeed, a3, concat(authPath[j], node));
      }
      treeIdx = parentTreeIdx;
    }
    roots.push(node);
  }

  const adrs2 = copyADRS(adrs);
  setType(adrs2, ADDR_TYPE_FORSPK);
  return hf.T_l(pkSeed, adrs2, concat(...roots));
}

// ─── SLH-DSA main algorithms (FIPS 205 Algorithms 18-22) ─────────────────────

/**
 * Algorithm 18: SLH-DSA.KeyGen — generate a key pair.
 */
function slhKeyGenInternal(skSeed: Uint8Array, skPRF: Uint8Array, pkSeed: Uint8Array, p: SLHDSAParams): [Uint8Array, Uint8Array] {
  const { n, d, hp } = p;
  const hf = buildHashFunctions(p);

  // Root of hypertree = top-layer XMSS root
  const adrs = newADRS();
  setLayerAddress(adrs, d - 1);
  setTreeAddress(adrs, 0n);
  const pkRoot = xmssNode(skSeed, pkSeed, 0, hp, adrs, hf, n, hp);

  const pk = concat(pkSeed, pkRoot);
  const sk = concat(skSeed, skPRF, pk);
  return [sk, pk];
}

/**
 * Algorithm 19: SLH-DSA.Sign — sign a message.
 */
function slhSignInternal(M: Uint8Array, sk: Uint8Array, p: SLHDSAParams, adRand: Uint8Array | null): Uint8Array {
  const { n, hp, a, k, h } = p;
  const hf = buildHashFunctions(p);

  const skSeed = sk.subarray(0, n);
  const skPRF  = sk.subarray(n, 2 * n);
  const pkSeed = sk.subarray(2 * n, 3 * n);
  const pkRoot = sk.subarray(3 * n, 4 * n);

  // R = PRF_msg(sk_prf, opt_rand, M)
  const optRand = adRand ?? pkSeed;
  const R = hf.PRF_msg(skPRF, optRand, M);

  // Digest = H_msg(R, pk_seed, pk_root, M)
  const digest = hf.H_msg(R, pkSeed, pkRoot, M);

  // Split digest into (md, idxTree, idxLeaf)
  const mdLen = Math.ceil(k * a / 8);
  const treeIdxLen = Math.ceil((h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const md = digest.subarray(0, mdLen);

  let idxTree = 0n;
  for (let i = 0; i < treeIdxLen; i++) {
    idxTree = (idxTree << 8n) | BigInt(digest[mdLen + i]);
  }
  // Mask to h - hp bits
  if (h - hp < 64) idxTree &= (1n << BigInt(h - hp)) - 1n;

  let idxLeaf = 0;
  for (let i = 0; i < leafIdxLen; i++) {
    idxLeaf = (idxLeaf << 8) | digest[mdLen + treeIdxLen + i];
  }
  idxLeaf &= (1 << hp) - 1;

  // FORS signature
  const forsAdrs = newADRS();
  setLayerAddress(forsAdrs, 0);
  setTreeAddress(forsAdrs, idxTree);
  setType(forsAdrs, ADDR_TYPE_FORSTREE);
  setKeyPairAddress(forsAdrs, idxLeaf);
  const forsSig = forsSign(md, skSeed, pkSeed, forsAdrs, hf, p);

  // FORS public key (for hypertree input)
  const forsAdrs2 = copyADRS(forsAdrs);
  const forsPK = forsPKFromSig(forsSig, md, pkSeed, forsAdrs2, hf, p);

  // Hypertree signature
  const htSig = htSign(forsPK, skSeed, pkSeed, idxTree, idxLeaf, hf, p);

  return concat(R, forsSig, htSig);
}

/**
 * Algorithm 20: SLH-DSA.Verify — verify a signature.
 */
function slhVerifyInternal(M: Uint8Array, sig: Uint8Array, pk: Uint8Array, p: SLHDSAParams): boolean {
  const { n, d, hp, a, k, h } = p;
  if (sig.byteLength !== p.sigBytes) return false;

  const hf = buildHashFunctions(p);
  const pkSeed = pk.subarray(0, n);
  const pkRoot = pk.subarray(n, 2 * n);

  let off = 0;
  const R = sig.subarray(off, off + n); off += n;

  const forsElSize = n + a * n;
  const forsSig = sig.subarray(off, off + k * forsElSize); off += k * forsElSize;

  const xmssSigLen = (wotsLen(n) + hp) * n;
  const htSig = sig.subarray(off, off + d * xmssSigLen);

  // Recompute digest
  const digest = hf.H_msg(R, pkSeed, pkRoot, M);
  const mdLen = Math.ceil(k * a / 8);
  const treeIdxLen = Math.ceil((h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const md = digest.subarray(0, mdLen);

  let idxTree = 0n;
  for (let i = 0; i < treeIdxLen; i++) idxTree = (idxTree << 8n) | BigInt(digest[mdLen + i]);
  if (h - hp < 64) idxTree &= (1n << BigInt(h - hp)) - 1n;

  let idxLeaf = 0;
  for (let i = 0; i < leafIdxLen; i++) idxLeaf = (idxLeaf << 8) | digest[mdLen + treeIdxLen + i];
  idxLeaf &= (1 << hp) - 1;

  // Recover FORS PK
  const forsAdrs = newADRS();
  setLayerAddress(forsAdrs, 0);
  setTreeAddress(forsAdrs, idxTree);
  setType(forsAdrs, ADDR_TYPE_FORSTREE);
  setKeyPairAddress(forsAdrs, idxLeaf);
  const forsPK = forsPKFromSig(forsSig, md, pkSeed, forsAdrs, hf, p);

  return htVerify(forsPK, htSig, pkSeed, idxTree, idxLeaf, pkRoot, hf, p);
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface SLHDSAKeyPair {
  sk: Uint8Array;
  pk: Uint8Array;
}

export interface SLHDSASignatureResult {
  signature: Uint8Array;
}

/** SLH-DSA key generation. */
export function slhDSAKeyGen(variant: SLHDSAVariant): SLHDSAKeyPair {
  const p = PARAMS[variant];
  const skSeed = randomBytes(p.n);
  const skPRF  = randomBytes(p.n);
  const pkSeed = randomBytes(p.n);
  const [sk, pk] = slhKeyGenInternal(skSeed, skPRF, pkSeed, p);
  return { sk, pk };
}

/** SLH-DSA sign. */
export function slhDSASign(sk: Uint8Array, message: Uint8Array, variant: SLHDSAVariant): SLHDSASignatureResult {
  const p = PARAMS[variant];
  return { signature: slhSignInternal(message, sk, p, null) };
}

/** SLH-DSA verify. */
export function slhDSAVerify(pk: Uint8Array, message: Uint8Array, signature: Uint8Array, variant: SLHDSAVariant): boolean {
  try {
    return slhVerifyInternal(message, signature, pk, PARAMS[variant]);
  } catch {
    return false;
  }
}

// ─── Self-test ────────────────────────────────────────────────────────────────

/**
 * Light self-test for FIPS 205 SLH-DSA.
 * Runs only the two smallest parameter sets for speed.
 */
export function runSLHDSASelfTest(): void {
  const variants: SLHDSAVariant[] = ['SLH-DSA-SHAKE-128f', 'SLH-DSA-SHA2-128f'];
  const msg = new TextEncoder().encode('Vril.js FIPS 205 SLH-DSA self-test');

  for (const variant of variants) {
    const p = PARAMS[variant];
    const { sk, pk } = slhDSAKeyGen(variant);
    if (sk.byteLength !== p.skBytes) throw new Error(`[VRIL FIPS 205] ${variant} sk size mismatch`);
    if (pk.byteLength !== p.pkBytes) throw new Error(`[VRIL FIPS 205] ${variant} pk size mismatch`);

    const { signature } = slhDSASign(sk, msg, variant);
    if (signature.byteLength !== p.sigBytes) throw new Error(`[VRIL FIPS 205] ${variant} sig size mismatch`);

    const valid = slhDSAVerify(pk, msg, signature, variant);
    if (!valid) throw new Error(`[VRIL FIPS 205] ${variant} verification failed`);
  }
}
