/**
 * Vril.js v2.2.1 — Active Surface PQC
 *
 * Zero-dependency orchestration layer for authentic post-quantum providers.
 * It only selects authentic PQC. It chooses the strongest registered
 * provider-backed FIPS 203/204/205 algorithm and degrades to authenticated
 * classical/symmetric encryption surfaces when no authentic PQC provider is
 * available.
 */

import { PQCHandler, type KEMResult, type PQCAlgorithm, type PQCKeyPair, type PQCProvider, type PQCValidationEvidence } from './pqc';

/** Runtime encryption surface selected by Active Surface PQC */
export type ActiveSurfaceMode = 'pqc-kem' | 'classical-kem' | 'symmetric-vault';

/** Policy for selecting an encryption surface */
export interface ActiveSurfacePolicy {
  /** Prefer higher-security ML-KEM-1024 before ML-KEM-768 */
  preferHighSecurity?: boolean;
  /** Allow native classical X25519 when no authentic PQC provider is present */
  allowClassicalFallback?: boolean;
  /** Allow ΩVault symmetric encryption when no KEM is available */
  allowSymmetricFallback?: boolean;
}

/** Selected surface metadata */
export interface ActiveSurfaceSelection {
  mode: ActiveSurfaceMode;
  algorithm: PQCAlgorithm | 'AES-256-GCM';
  quantumResistant: boolean;
  evidence: PQCValidationEvidence | null;
}

/** Result of generating key material for a selected surface */
export interface ActiveSurfaceKeyPair {
  selection: ActiveSurfaceSelection;
  keyPair: PQCKeyPair | null;
}

/** Result of KEM encapsulation for a selected surface */
export interface ActiveSurfaceKEMResult {
  selection: ActiveSurfaceSelection;
  result: KEMResult;
}

const DEFAULT_POLICY: Required<ActiveSurfacePolicy> = {
  preferHighSecurity: false,
  allowClassicalFallback: true,
  allowSymmetricFallback: true,
};

/**
 * Orchestrates authentic PQC providers and graceful fallback surfaces.
 *
 * This class is intentionally small: it does not embed third-party algorithms,
 * copy external source, or use placeholder PQC. Providers can be first-party,
 * browser-compatible, WASM-backed, or formally validated modules, but they must
 * expose evidence through PQCProvider before PQC operations are selected.
 */
export class ActiveSurfacePQC {
  private readonly pqc: PQCHandler;
  private readonly policy: Required<ActiveSurfacePolicy>;

  constructor(provider: PQCProvider | null | undefined = undefined, policy: ActiveSurfacePolicy = {}) {
    this.pqc = provider === undefined ? new PQCHandler() : new PQCHandler(provider);
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  /** Register an authentic PQC provider */
  registerProvider(provider: PQCProvider): void {
    this.pqc.registerProvider(provider);
  }

  /** Remove the current PQC provider */
  clearProvider(): void {
    this.pqc.clearProvider();
  }

  /** Select the strongest currently available encryption surface */
  selectSurface(): ActiveSurfaceSelection {
    const kemPreference: PQCAlgorithm[] = this.policy.preferHighSecurity
      ? ['ML-KEM-1024', 'ML-KEM-768', 'ML-KEM-512']
      : ['ML-KEM-768', 'ML-KEM-1024', 'ML-KEM-512'];

    for (const algorithm of kemPreference) {
      const evidence = this.pqc.getValidationEvidence(algorithm);
      if (evidence && this.pqc.isSupported(algorithm)) {
        return { mode: 'pqc-kem', algorithm, quantumResistant: true, evidence };
      }
    }

    if (this.policy.allowClassicalFallback && this.pqc.isSupported('X25519')) {
      return {
        mode: 'classical-kem',
        algorithm: 'X25519',
        quantumResistant: false,
        evidence: this.pqc.getValidationEvidence('X25519'),
      };
    }

    if (this.policy.allowSymmetricFallback) {
      return {
        mode: 'symmetric-vault',
        algorithm: 'AES-256-GCM',
        quantumResistant: false,
        evidence: null,
      };
    }

    throw new Error('[VRIL Active Surface PQC] No encryption surface is available under the current policy');
  }

  /** Generate key material for the selected KEM surface */
  async generateKeyPair(): Promise<ActiveSurfaceKeyPair> {
    const selection = this.selectSurface();
    if (selection.mode === 'symmetric-vault') {
      return { selection, keyPair: null };
    }
    return { selection, keyPair: await this.pqc.generateKeyPair(selection.algorithm as PQCAlgorithm) };
  }

  /** Encapsulate to a recipient public key using the selected KEM surface */
  async encapsulate(recipientPublicKey: Uint8Array): Promise<ActiveSurfaceKEMResult> {
    const selection = this.selectSurface();
    if (selection.mode === 'symmetric-vault') {
      throw new Error('[VRIL Active Surface PQC] Symmetric fallback uses ΩVault and does not support KEM encapsulation');
    }
    return {
      selection,
      result: await this.pqc.encapsulate(recipientPublicKey, selection.algorithm as PQCAlgorithm),
    };
  }
}
