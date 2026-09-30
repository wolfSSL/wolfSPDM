# wolfSPDM Documentation

Welcome to the wolfSPDM wiki. wolfSPDM implements SPDM over two layers: a
**wolfTPM-derived TCG binding core** (Nuvoton / Nations Technology TPM
transport, PSK, identity-key mutual auth, and an SPDM responder) and, layered
on top of it behind compile-time switches, the **standard DMTF requester**
(certificates, measurements, challenge, chunking, PQC).

## What is wolfSPDM?

wolfSPDM is a C library implementing:
- **SPDM 1.2 / 1.3 / 1.4** ([DMTF DSP0274](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf))
- **Secured Messages over MCTP** ([DMTF DSP0277](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf))
- **TCG SPDM Binding** (TPM transport, vendor commands) for Nuvoton NPCT75x and
  Nations NS350 TPMs

It uses [wolfSSL / wolfCrypt](https://www.wolfssl.com/) as its crypto backend
and is tested end-to-end against the DMTF
[spdm-emu](https://github.com/DMTF/spdm-emu) responder emulator.

## Two build profiles

- **wolfTPM builds** (`WOLFTPM_SPDM`, which implies `WOLFSPDM_PROFILE_TPM`):
  compile only the TCG binding side. The standard certificate requester,
  HEARTBEAT, KEY_UPDATE, and application data are compiled out
  (`WOLFSPDM_NO_CERT`/`NO_HEARTBEAT`/`NO_KEY_UPDATE`/`NO_APP_DATA`).
- **Standalone builds** (`./configure`): compile the standard requester by
  default; the TPM side (TCG binding, Nuvoton/Nations vendor commands, PSK,
  responder) is compiled in only with `--enable-tcg` / `--enable-nuvoton` /
  `--enable-nations` / `--enable-psk` / `--enable-responder`.

## Key Features

| Feature | Description |
|---------|-------------|
| Standard SPDM 1.2/1.3/1.4 requester | Certificate-based DSP0274 flow (`--disable-cert` to drop it) |
| TCG SPDM binding | Nuvoton / Nations TPM transport, vendor commands, identity-key mutual auth (`--enable-tcg`) |
| PSK mode | `PSK_EXCHANGE`/`PSK_FINISH` over the TCG binding (`--enable-psk`) |
| SPDM responder | Answers requester-driven messages for a TPM-backed device (`--enable-responder`) |
| Fixed Algorithm Set B | ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384 |
| Post-quantum signatures (1.4) | Optional ML-DSA-44/65/87 (FIPS 204), dual-stacked with ECDSA P-384 |
| Post-quantum key exchange (1.4) | Optional ML-KEM-512/768/1024 (FIPS 203), advertised alongside ECDHE P-384 |
| Fully post-quantum handshake | ML-KEM key exchange + ML-DSA authentication, no classical asymmetric crypto |
| Message chunking | CHUNK_SEND and CHUNK_GET, in the clear and inside secured sessions |
| Zero-malloc by default | Static context (`WOLFSPDM_CTX_STATIC_SIZE`) |
| Optional dynamic context | `--enable-dynamic-mem` enables `wolfSPDM_New()` |
| Attestation operations | Signed/unsigned `GET_MEASUREMENTS`, sessionless `CHALLENGE_AUTH` |
| Session operations | `HEARTBEAT`, `KEY_UPDATE`, secured app data transfer |

## Documentation

| Page | Description |
|------|--------------|
| [[Getting Started]] | Dependencies, build, install, and first connection flow |
| [[Supported Operations]] | Supported SPDM flows and operation/API mapping |
| [[Post-Quantum ML-DSA]] | SPDM 1.4 ML-DSA (FIPS 204) post-quantum signatures |
| [[Post-Quantum ML-KEM]] | SPDM 1.4 ML-KEM (FIPS 203) post-quantum key exchange + fully post-quantum handshake |
| [[Message Chunking]] | CHUNK_SEND / CHUNK_GET large message chunking |
| [[API Reference]] | Public API grouped by lifecycle and purpose |
| [[Configuration and Macros]] | Configure flags and compile-time feature controls |
| [[Testing and CI]] | Unit tests, emulator tests, and CI workflow coverage |
| [[Project Structure]] | Repository layout and module responsibilities |
| [[Attestation Notes]] | Measurement and challenge attestation details |

## Protocol Session Flow

Standard (certificate) requester:

`GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS -> GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH`

TCG binding (identity-key mode, no `GET_CAPABILITIES`/`NEGOTIATE_ALGORITHMS`
since Algorithm Set B is fixed):

`GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH`

After `FINISH`, secured messaging and maintenance operations are available.

## Quick Links

- [GitHub Repository](https://github.com/aidangarske/wolfSPDM)
- [README](https://github.com/aidangarske/wolfSPDM/blob/main/README.md)
- [DMTF DSP0274 (SPDM)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf)
- [DMTF DSP0277 (Secured Messages)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf)
- [wolfSSL Website](https://www.wolfssl.com/)

## License

wolfSPDM is free software licensed under GPLv3.
For commercial licensing and support, contact [wolfSSL](https://www.wolfssl.com/contact/).
