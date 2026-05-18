# Vril.js Native Active Surface PQC Bundle

This directory contains the zero-runtime-dependency JavaScript bundle used by `PQCHandler` through `nativePQCProvider`.

## Coverage

The bundle covers the post-quantum algorithms claimed by the Vril.js README and public docs:

| Vril.js algorithm | Standard | Native export used |
| --- | --- | --- |
| `ML-KEM-768` | FIPS 203 | `ml_kem768` |
| `ML-KEM-1024` | FIPS 203 | `ml_kem1024` |
| `ML-DSA-65` | FIPS 204 | `ml_dsa65` |
| `ML-DSA-87` | FIPS 204 | `ml_dsa87` |
| `SLH-DSA-SHA2-128s` | FIPS 205 | `slh_dsa_sha2_128s` |
| `SLH-DSA-SHA2-256f` | FIPS 205 | `slh_dsa_sha2_256f` |

The generated bundle also includes the Noble utility/hash/curve primitives required by those exports, including the bundled equivalents of `@noble/post-quantum/utils.js`, `@noble/post-quantum/_crystals.js`, `@noble/post-quantum/ml-kem.js`, `@noble/post-quantum/ml-dsa.js`, `@noble/post-quantum/slh-dsa.js`, `@noble/hashes`, and `@noble/curves` helpers referenced by the selected algorithms.

`PQCHandler` uses `nativePQCProvider` by default. Pass `null` to `new PQCHandler(null)` for the older metadata-only fail-closed mode, or pass a certified external `PQCProvider` to replace the bundled implementation.

## Notices

`NOTICE.md` preserves the applicable MIT notices for the vendored implementation code. Do not remove those notices when regenerating or modifying this bundle.

## Validation language

The bundled provider supplies standards-conformant native operations and Vril.js validates algorithm identity plus key, ciphertext, shared-secret, and signature byte sizes at the `PQCHandler` boundary. Formal FIPS validation still requires CAVP/ACVP and CMVP/FIPS 140-3 certificate identifiers for the exact implementation/module boundary.

NIST validation resources:

- CAVP/ACVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- CMVP/FIPS 140-3: https://csrc.nist.gov/projects/cryptographic-module-validation-program
