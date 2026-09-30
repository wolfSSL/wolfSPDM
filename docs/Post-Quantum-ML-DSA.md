# Post-Quantum ML-DSA

SPDM 1.4 (DMTF DSP0274 1.4.0) adds post-quantum cryptography: **ML-DSA**
(FIPS 204) for signatures and **ML-KEM** (FIPS 203) for key exchange. wolfSPDM
implements the requester side of **ML-DSA signature verification** and
certificate-chain validation, dual-stacked alongside the classical ECDSA
P-384 profile. ML-DSA rides the certificate flow, so it is only available
when the standard requester is built (not `WOLFSPDM_NO_CERT`).

All three parameter sets work over the wire: ML-DSA-87's larger responses are
reassembled with SPDM message chunking ([[Message Chunking]]). ML-KEM key
exchange is also implemented ([[Post-Quantum ML-KEM]]); combining the two
gives a **fully post-quantum SPDM handshake** (ML-KEM key exchange + ML-DSA
authentication, no classical asymmetric crypto).

## How negotiation works

In `NEGOTIATE_ALGORITHMS`, wolfSPDM advertises ECDSA P-384 in `BaseAsymAlgo`
**and** whichever ML-DSA parameter sets the linked wolfSSL was built with, in
the SPDM 1.4 `PqcAsymAlgo` field. Per DSP0274 1.4, the responder selects
exactly one signature algorithm across `BaseAsymSel` and `PqcAsymSel`.
wolfSPDM records the choice and verifies `KEY_EXCHANGE_RSP`,
`CHALLENGE_AUTH`, and signed `MEASUREMENTS` with whichever family was
negotiated.

| PqcAsymSel bit | Algorithm | SigLen | Public key |
|----------------|-----------|--------|------------|
| `0x01` | ML-DSA-44 | 2420 B | 1312 B |
| `0x02` | ML-DSA-65 | 3309 B | 1952 B |
| `0x04` | ML-DSA-87 | 4627 B | 2592 B |

## Certificate chain verification

`wolfSPDM_ValidateCertChain` (`src/spdm_standard.c`) walks the retrieved
chain link by link:

- If a trusted root CA is configured (`wolfSPDM_SetTrustedCAs`), its SHA-384
  hash must match the chain header's `RootHash`, and the root itself signs
  the next certificate in the chain.
- Each subsequent certificate must be signed by the one before it — either
  ECDSA-SHA384 (`ECDSAk`), or pure ML-DSA (`wc_MlDsaKey_VerifyCtx` with an
  empty context) when the issuer carries an ML-DSA key.
- The leaf key must match the negotiated signature algorithm: for ML-DSA, its
  parameter set (OID) must equal the negotiated level; for ECDSA, it must
  decode as a P-384 key. A pinned responder key
  (`wolfSPDM_SetResponderPubKey`) is compared against the leaf instead of
  being trusted from the chain.
- Without a trusted root, a pinned key, or `wolfSPDM_AllowUntrustedCerts`,
  validation fails with `WOLFSPDM_E_CERT_FAIL`.

## Responder key handling

The negotiated-algorithm responder public key is kept as raw bytes in the
context (`ctx->rspPubKey`, the ML-DSA public key or a P-384 point). An
`MlDsaKey` is not kept live in the context: `wolfSPDM_MlDsaVerify`
(`src/spdm_crypto.c`) creates one for each verification (on the stack, or on
the heap with `WOLFSPDM_DYNAMIC_MEMORY`) and imports the raw key
with `wc_MlDsaKey_ImportPubRaw` before calling `wc_MlDsaKey_VerifyCtx`; with
`--enable-dynamic-mem`, the key is heap-allocated instead of living on the
stack for that call.

## Signing construction (DSP0274 1.4 §15.5)

ML-DSA uses **Algorithm 2 (pure `ML-DSA.Sign`)**, not the pre-hash variant:

- `M = combined_spdm_prefix || message_hash`
  - `combined_spdm_prefix` = `"dmtf-spdm-v1.4.*"` ×4, zero-pad, `spdm_context`
    (100 bytes)
  - `message_hash` = SHA-384 of the data to be signed (the negotiated
    `BaseHashSel`)
- ML-DSA `ctx` parameter = `spdm_context` (the `"responder-<context> signing"`
  string)

wolfSPDM verifies with `wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, ctxLen, M,
mLen, &res)`.

## Building

ML-DSA follows the linked wolfSSL automatically: it is enabled when wolfSSL
reports `WOLFSSL_HAVE_MLDSA` and provides the `wc_MlDsaKey` context API
(build wolfSSL with `--enable-mldsa`), the standard requester is built
(not `WOLFSPDM_NO_CERT`), and `--disable-mldsa` was not passed. The
capability is detected at configure time — wolfSPDM does not gate on a
wolfSSL version number.

```sh
# wolfSSL with ML-DSA
./configure --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf \
            --enable-sp --enable-mldsa --prefix=$HOME/wolfssl-install
make && make install

# wolfSPDM (ML-DSA auto-enabled; --enable-mldsa asserts it, --disable-mldsa off)
./configure --with-wolfssl=$HOME/wolfssl-install
make && make check
```

The configure summary prints `ML-DSA: yes|no`.

## Memory note

PQC signatures, public keys, and certificate chains are multi-kilobyte, so
`WOLFSPDM_CTX_STATIC_SIZE` grows to 73728 bytes when ML-DSA is built in (32768
classical, 40960 ML-KEM only — see [[Configuration and Macros]]). Measured
`sizeof(WOLFSPDM_CTX)` on arm64 is roughly 59 KB with ML-DSA, well under that
cap. ML-DSA-44 and ML-DSA-65 responses fit a single SPDM message at common
`DataTransferSize` values; ML-DSA-87 responses (sig 4627 B) typically exceed
it, so the responder chunks them and wolfSPDM reassembles via
`CHUNK_GET` — see [[Message Chunking]].

## References

- DMTF DSP0274 1.4.0 — SPDM Specification (§15 SPDMsign, §15.5 ML-DSA, Tables 19/20)
- NIST FIPS 204 — ML-DSA; FIPS 203 — ML-KEM
- wolfSSL `wc_mldsa.h` — `wc_MlDsaKey_*` API
