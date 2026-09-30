# Project Structure

## Top-level layout

| Path | Purpose |
|------|---------|
| `src/` | Core protocol, crypto glue, transcript, secured messaging, session logic, and TPM/TCG side |
| `src/vendor/` | Nuvoton and Nations TPM-specific vendor commands |
| `wolfspdm/` | Public headers |
| `examples/` | Demo client and emulator integration script |
| `test/` | Unit tests and test certificate data |
| `docs/` | Project documentation (this wiki, mirrored under `docs/`) |
| `.github/workflows/` | CI workflows |

## Core source modules

| File | Responsibility |
|------|----------------|
| `src/spdm_context.c` | Context init/free lifecycle and state setup |
| `src/spdm_msg.c` | SPDM message construction, parsing, and signature verification helpers |
| `src/spdm_crypto.c` | Cryptographic helper operations (ECDSA/ML-DSA verify, hashing) |
| `src/spdm_kdf.c` | HKDF-based key derivation |
| `src/spdm_transcript.c` | Transcript management (TH computations) |
| `src/spdm_secured.c` | Secured message protection (AES-256-GCM), app data (`SendData`/`ReceiveData`/`Encrypt`/`DecryptMessage`) |
| `src/spdm_session.c` | Handshake exchange helper, `KeyExchange`/`Finish`, `Heartbeat`, `KeyUpdate` |
| `src/spdm_internal.h` | Internal types, constants, and internal APIs shared across `src/` |

## Standard (certificate) requester modules — built with `BUILD_CERT`

Compiled when the standard requester is enabled (`--disable-cert` removes
these; requires `WOLFSPDM_NO_CERT` not set):

| File | Responsibility |
|------|----------------|
| `src/spdm_standard.c` | `GET_CAPABILITIES`/`NEGOTIATE_ALGORITHMS`/`GET_DIGESTS`/`GET_CERTIFICATE`, certificate-chain validation, trust anchor configuration, `Connect` |
| `src/spdm_attest.c` | `GET_MEASUREMENTS` and `CHALLENGE`, L1/L2 and M1 running transcript hashes |
| `src/spdm_chunk.c` | `CHUNK_SEND`/`CHUNK_GET` large-message chunking engine |

## TPM/TCG side modules

| File | Built with | Responsibility |
|------|-----------|-----------------|
| `src/spdm_tcg.c` | `--enable-tcg` (`BUILD_TCG`) | TCG SPDM binding message framing, vendor-command helpers, identity-key exchange, `ConnectTCG` |
| `src/spdm_psk.c` | `--enable-psk` (`BUILD_PSK`) | `PSK_EXCHANGE`/`PSK_FINISH`, PSK key derivation, `ConnectPsk` |
| `src/vendor/spdm_nuvoton.c` | `--enable-nuvoton` (`BUILD_NUVOTON`) | Nuvoton NPCT75x status/lock vendor commands |
| `src/vendor/spdm_nations.c` | `--enable-nations` (`BUILD_NATIONS`) | Nations NS350 status/lock/PSK-provisioning vendor commands |
| `src/spdm_responder.c` | `--enable-responder` (`BUILD_RESPONDER`) | SPDM responder: answers requester-driven messages over the TCG binding, TPM command tunneling |

## Public API surface

| Header | Content |
|--------|---------|
| `wolfspdm/spdm.h` | Main public API, `WOLFSPDM_MODE`, feature macros (`WOLFSPDM_HAS_*`) |
| `wolfspdm/spdm_types.h` | SPDM protocol constants, algorithm identifiers, build-switch implications |
| `wolfspdm/spdm_error.h` | Error code enum and error-string helper |
| `wolfspdm/spdm_tcg.h` | TCG SPDM binding framing, vendor-command codes and helpers |
| `wolfspdm/spdm_nuvoton.h` | Nuvoton-specific status API |
| `wolfspdm/spdm_nations.h` | Nations-specific status/PSK-provisioning API |
| `wolfspdm/spdm_psk.h` | Shared PSK protocol API |
| `wolfspdm/spdm_responder.h` | SPDM responder API |
| `wolfspdm/options.h` | Auto-generated from `config.h` at build time |

## Build/test assets

| File | Purpose |
|------|---------|
| `configure.ac` | Autotools configure logic and options |
| `Makefile.am` | Library, test, and example build targets |
| `examples/spdm_demo.c` | CLI demo: session, measurements, challenge, heartbeat, key update, app data, version and key-exchange selection |
| `examples/spdm_test.sh` | 21-test emulator integration driver (7 scenarios x SPDM 1.2/1.3/1.4) |
| `test/unit_test.c` | Unit test coverage |
| `test/test_certs.h` | Classical (ECDSA P-384) test certificate chains |
| `test/test_certs_mldsa.h` | ML-DSA test certificate chains |
