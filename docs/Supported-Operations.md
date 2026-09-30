# Supported Operations

wolfSPDM implements requester-side SPDM operations for session establishment, secure data exchange, attestation, and session maintenance, plus the TCG binding, TPM vendor commands, PSK and a responder for TPM builds.

## Operation coverage

| Operation | SPDM area | wolfSPDM API |
|----------|-----------|--------------|
| Version negotiation | GET_VERSION | `wolfSPDM_GetVersion` |
| Capability negotiation | GET_CAPABILITIES | `wolfSPDM_GetCapabilities` |
| Algorithm negotiation | NEGOTIATE_ALGORITHMS | `wolfSPDM_NegotiateAlgorithms` |
| Certificate digest retrieval | GET_DIGESTS | `wolfSPDM_GetDigests` |
| Certificate chain retrieval | GET_CERTIFICATE | `wolfSPDM_GetCertificate` |
| Session key exchange | KEY_EXCHANGE | `wolfSPDM_KeyExchange` |
| Session finalization | FINISH | `wolfSPDM_Finish` |
| One-shot full connect | Full handshake | `wolfSPDM_Connect` |
| Secured app exchange | Secured messages | `wolfSPDM_SecuredExchange` |
| MCTP application messages | Secured messages (DSP0275) | `wolfSPDM_SendData`, `wolfSPDM_ReceiveData` |
| Caller-driven secured records | Secured messages | `wolfSPDM_EncryptMessage`, `wolfSPDM_DecryptMessage` |
| Large messages | CHUNK_SEND / CHUNK_GET | automatic once both sides set CHUNK_CAP |
| Measurements (signed/unsigned) | GET_MEASUREMENTS | `wolfSPDM_GetMeasurements` |
| Measurement block access | Measurement parsing | `wolfSPDM_GetMeasurementCount`, `wolfSPDM_GetMeasurementBlock` |
| Sessionless challenge auth | CHALLENGE / CHALLENGE_AUTH | `wolfSPDM_Challenge` |
| Keep-alive | HEARTBEAT | `wolfSPDM_Heartbeat` |
| Session key rotation | KEY_UPDATE | `wolfSPDM_KeyUpdate` |
| TCG binding session (TPM) | TCG SPDM binding, GIVE_PUB mutual auth | `wolfSPDM_Connect` in a Nuvoton or Nations mode |
| PSK session (TPM) | PSK_EXCHANGE / PSK_FINISH | `wolfSPDM_SetPSK`, `wolfSPDM_Connect` |
| Responder (fwTPM) | TCG binding and PSK responder | `wolfSPDM_Resp*` (`spdm_responder.h`) |

## Supported protocol versions

- SPDM 1.2 (`0x12`)
- SPDM 1.3 (`0x13`)
- SPDM 1.4 (`0x14`)

Maximum negotiated version can be capped with `wolfSPDM_SetMaxVersion`.

## Fixed cryptographic profile (Algorithm Set B)

- Hash: SHA-384
- Asymmetric signature: ECDSA P-384
- Key exchange: ECDHE secp384r1
- AEAD: AES-256-GCM
- Key schedule: SPDM key schedule + HKDF-SHA384

## Post-quantum cryptography (SPDM 1.4, optional)

When built against a wolfSSL with the matching support, wolfSPDM adds two
independent post-quantum capabilities, each dual-stacked with the classical
profile so the responder selects one:

- **Signatures (ML-DSA, FIPS 204):** advertises **ML-DSA-44 / 65 / 87** in the
  1.4 `PqcAsymAlgo` field alongside ECDSA P-384; verifies whichever was
  negotiated. See [[Post-Quantum ML-DSA]].
- **Key exchange (ML-KEM, FIPS 203):** advertises **ML-KEM-512 / 768 / 1024**
  as a `KEMAlg` struct alongside the ECDHE group; sends the encapsulation key and
  decapsulates the responder's ciphertext. Standalone (not hybrid). See
  [[Post-Quantum ML-KEM]].

Enabling both yields a **fully post-quantum SPDM handshake** (ML-KEM key
exchange + ML-DSA authentication). Large responses (e.g. an ML-DSA-87 signature,
or ML-DSA + the ML-KEM ciphertext, exceeding the negotiated `DataTransferSize`)
are reassembled with **SPDM 1.2 message chunking** (`CHUNK_GET`), and a large
ML-KEM `KEY_EXCHANGE` request is split with `CHUNK_SEND`; see
[[Message Chunking]].

## Notable implementation scope

- Standard requester for standards-based SPDM peers and DMTF spdm-emu; the
  responder covers the TCG binding and PSK used by wolfTPM's fwTPM
- Build switches compile out either side (see [[Configuration and Macros]])
- Trust anchor support via `wolfSPDM_SetTrustedCAs` (single DER CA cert buffer)
