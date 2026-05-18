/**
 * Vril.js — Clean-room FIPS 202 SHA-3 / SHAKE primitives.
 *
 * Implements Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, and SHAKE256
 * directly in TypeScript with no runtime dependencies. This module is the
 * foundation for from-specification FIPS 203/204/205 implementations.
 */

const MASK_64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS = Object.freeze([
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
]);

const RHO_OFFSETS = Object.freeze([
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
]);

export type BytesLike = Uint8Array | ArrayBuffer | ArrayBufferView | string;

function rotl64(value: bigint, shift: number): bigint {
  if (shift === 0) return value & MASK_64;
  const bits = BigInt(shift);
  return ((value << bits) | (value >> (64n - bits))) & MASK_64;
}

function toBytes(input: BytesLike): Uint8Array {
  if (typeof input === 'string') return new TextEncoder().encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

function readLaneLE(bytes: Uint8Array, offset: number): bigint {
  let lane = 0n;
  for (let i = 0; i < 8; i++) {
    lane |= BigInt(bytes[offset + i]) << BigInt(8 * i);
  }
  return lane;
}

function writeLaneLE(lane: bigint, out: Uint8Array, offset: number, count: number): void {
  for (let i = 0; i < count; i++) {
    out[offset + i] = Number((lane >> BigInt(8 * i)) & 0xffn);
  }
}

function keccakF1600(state: bigint[]): void {
  const c = new Array<bigint>(5).fill(0n);
  const d = new Array<bigint>(5).fill(0n);
  const b = new Array<bigint>(25).fill(0n);

  for (const rc of ROUND_CONSTANTS) {
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & MASK_64;
      }
    }

    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const source = x + 5 * y;
        const targetX = y;
        const targetY = (2 * x + 3 * y) % 5;
        b[targetX + 5 * targetY] = rotl64(state[source], RHO_OFFSETS[source]);
      }
    }

    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] = (b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])) & MASK_64;
      }
    }

    state[0] = (state[0] ^ rc) & MASK_64;
  }
}

class KeccakSponge {
  private readonly state = new Array<bigint>(25).fill(0n);
  private readonly block: Uint8Array;
  private blockOffset = 0;
  private finalized = false;
  private squeezeOffset = 0;

  constructor(
    private readonly rateBytes: number,
    private readonly domain: number,
  ) {
    this.block = new Uint8Array(rateBytes);
  }

  update(input: BytesLike): this {
    if (this.finalized) throw new Error('[VRIL SHA3] Cannot absorb after finalization');
    const bytes = toBytes(input);
    let offset = 0;
    while (offset < bytes.length) {
      const take = Math.min(this.rateBytes - this.blockOffset, bytes.length - offset);
      this.block.set(bytes.subarray(offset, offset + take), this.blockOffset);
      this.blockOffset += take;
      offset += take;
      if (this.blockOffset === this.rateBytes) this.absorbBlock();
    }
    return this;
  }

  digest(length: number): Uint8Array {
    this.finalize();
    return this.squeeze(length);
  }

  squeeze(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error('[VRIL SHA3] Output length must be a non-negative safe integer');
    }
    this.finalize();
    const out = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      if (this.squeezeOffset === this.rateBytes) {
        keccakF1600(this.state);
        this.squeezeOffset = 0;
      }
      const laneIndex = Math.floor(this.squeezeOffset / 8);
      const laneOffset = this.squeezeOffset % 8;
      // Defensive invariant check: rateBytes <= 168, so normal operation never reaches lane 25.
      if (laneIndex >= 25) {
        throw new Error('[VRIL SHA3] Invalid lane index during squeeze');
      }
      const take = Math.min(8 - laneOffset, length - written);
      const lane = this.state[laneIndex];
      for (let i = 0; i < take; i++) {
        out[written + i] = Number((lane >> BigInt(8 * (laneOffset + i))) & 0xffn);
      }
      this.squeezeOffset += take;
      written += take;
    }
    return out;
  }

  reset(): this {
    this.state.fill(0n);
    this.block.fill(0);
    this.blockOffset = 0;
    this.finalized = false;
    this.squeezeOffset = 0;
    return this;
  }

  private absorbBlock(): void {
    const laneCount = this.rateBytes / 8;
    for (let i = 0; i < laneCount; i++) {
      this.state[i] = (this.state[i] ^ readLaneLE(this.block, i * 8)) & MASK_64;
    }
    this.block.fill(0);
    this.blockOffset = 0;
    keccakF1600(this.state);
  }

  private finalize(): void {
    if (this.finalized) return;
    this.block[this.blockOffset] ^= this.domain;
    this.block[this.rateBytes - 1] ^= 0x80;
    const laneCount = this.rateBytes / 8;
    for (let i = 0; i < laneCount; i++) {
      this.state[i] = (this.state[i] ^ readLaneLE(this.block, i * 8)) & MASK_64;
    }
    this.block.fill(0);
    keccakF1600(this.state);
    this.finalized = true;
    this.squeezeOffset = 0;
  }

  exportState(): Uint8Array {
    const out = new Uint8Array(200);
    for (let i = 0; i < 25; i++) writeLaneLE(this.state[i], out, i * 8, 8);
    return out;
  }
}

export class ShakeXof {
  private readonly sponge: KeccakSponge;

  constructor(strength: 128 | 256) {
    this.sponge = new KeccakSponge(strength === 128 ? 168 : 136, 0x1f);
  }

  update(input: BytesLike): this {
    this.sponge.update(input);
    return this;
  }

  squeeze(length: number): Uint8Array {
    return this.sponge.squeeze(length);
  }

  reset(): this {
    this.sponge.reset();
    return this;
  }
}

export function sha3_256(input: BytesLike): Uint8Array {
  return new KeccakSponge(136, 0x06).update(input).digest(32);
}

export function sha3_512(input: BytesLike): Uint8Array {
  return new KeccakSponge(72, 0x06).update(input).digest(64);
}

export function shake128(input: BytesLike, outputLength: number): Uint8Array {
  return new ShakeXof(128).update(input).squeeze(outputLength);
}

export function shake256(input: BytesLike, outputLength: number): Uint8Array {
  return new ShakeXof(256).update(input).squeeze(outputLength);
}

/** Run built-in FIPS 202 known-answer checks for the empty message. */
export function runSha3SelfTest(): void {
  const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

  const vectors: Array<[string, string]> = [
    ['SHA3-256', bytesToHex(sha3_256(''))],
    ['SHA3-512', bytesToHex(sha3_512(''))],
    ['SHAKE128', bytesToHex(shake128('', 32))],
    ['SHAKE256', bytesToHex(shake256('', 64))],
  ];
  const expected = new Map<string, string>([
    ['SHA3-256', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'],
    ['SHA3-512', 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'],
    ['SHAKE128', '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'],
    ['SHAKE256', '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'],
  ]);

  for (const [name, actual] of vectors) {
    if (actual !== expected.get(name)) {
      throw new Error(`[VRIL SHA3] ${name} self-test failed`);
    }
  }
}
