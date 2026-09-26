# wolfSPDM

wolfSPDM is a lightweight C library implementing [SPDM 1.2 / 1.3 / 1.4](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf) and [Secured Messages over MCTP (DSP0277)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf) using [wolfSSL](https://www.wolfssl.com/) as the crypto backend. It is a standalone, requester-only stack designed for embedded use, tested end-to-end against the DMTF [spdm-emu](https://github.com/DMTF/spdm-emu) emulator.

## Main Features

- **Standard SPDM 1.2 / 1.3 / 1.4 requester** per DMTF DSP0274 and DSP0277
- **Algorithm Set B fixed:** ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- **Post-quantum signatures (SPDM 1.4):** optional ML-DSA-44 / 65 / 87 (FIPS 204), dual-stacked with ECDSA P-384 — see the [Post-Quantum ML-DSA](https://github.com/aidangarske/wolfSPDM/wiki/Post-Quantum-ML-DSA) wiki page
- **Post-quantum key exchange (SPDM 1.4):** optional ML-KEM-512 / 768 / 1024 (FIPS 203), advertised alongside ECDHE P-384 — see the [Post-Quantum ML-KEM](https://github.com/aidangarske/wolfSPDM/wiki/Post-Quantum-ML-KEM) wiki page
- **Fully post-quantum SPDM handshake:** ML-KEM key exchange + ML-DSA authentication (no classical asymmetric crypto), proven end-to-end against spdm-emu
- **Zero-malloc by default:** static memory, ~32 KB context, ideal for constrained/embedded environments
- **Optional `--enable-dynamic-mem`** for heap-allocated contexts on small-stack platforms
- **Full session lifecycle:** key exchange, finish, encrypted messaging, heartbeat keep-alive, key update
- **Device attestation:** signed / unsigned `GET_MEASUREMENTS`, sessionless `CHALLENGE_AUTH`, certificate-chain validation against trusted root CAs
- **Compatible with DMTF spdm-emu** for interoperability testing (18-test matrix across 1.2 / 1.3 / 1.4)
- **Path to FIPS 140-3** via wolfCrypt FIPS Certificate #4718 (sole crypto dependency)

## Supported Operations (RFC / DSP0274)

| Operation | DSP0274 | wolfSPDM API |
|---|---|---|
| Session establishment | Sec. 10.7 | `wolfSPDM_Connect`, `wolfSPDM_KeyExchange`, `wolfSPDM_Finish` |
| Encrypted application data | DSP0277 | `wolfSPDM_SecuredExchange`, `wolfSPDM_SendData`, `wolfSPDM_ReceiveData` |
| Measurements (signed/unsigned) | Sec. 10.11 | `wolfSPDM_GetMeasurements`, `wolfSPDM_GetMeasurementBlock` |
| Challenge authentication (sessionless) | Sec. 10.8 | `wolfSPDM_Challenge` |
| Session keep-alive | Sec. 10.10 | `wolfSPDM_Heartbeat` |
| Session key rotation | Sec. 10.9 | `wolfSPDM_KeyUpdate` |
| Trust anchor | Sec. 10.6 | `wolfSPDM_SetTrustedCAs` |

## Prerequisites (wolfSSL)

wolfSPDM requires [wolfSSL](https://www.wolfssl.com/) configured with ECC P-384, SHA-384, AES-GCM, and HKDF:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
            --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install
sudo ldconfig
```

`--enable-sp` enables Single Precision math with optimized ECC P-384, required for SPDM Algorithm Set B on ARM64 and other constrained targets. `--enable-all` works as a superset.

For post-quantum cryptography, add `--enable-mldsa` (signatures, FIPS 204) and/or `--enable-mlkem` (key exchange, FIPS 203) to wolfSSL — use wolfSSL master (or a release that ships the `wc_MlDsaKey` context API and `wc_MlKemKey` API). wolfSPDM then auto-enables each when the linked wolfSSL provides it; `./configure --disable-mldsa` / `--disable-mlkem` force them off. Enabling both gives a fully post-quantum SPDM handshake (ML-KEM key exchange + ML-DSA authentication).

## Build

```bash
./autogen.sh
./configure
make
make check
```

### Configure Options

| Option | Description |
|---|---|
| `--enable-debug` | Debug output with `-g -O0` (default: `-O2`) |
| `--enable-dynamic-mem` | Use heap allocation for `WOLFSPDM_CTX` (default: static) |
| `--disable-mldsa` / `--disable-mlkem` | Force off ML-DSA signatures / ML-KEM key exchange (default: auto-follow wolfSSL) |
| `--disable-chunking` | Compile out CHUNK_SEND/CHUNK_GET large message chunking (default: enabled) |
| `--disable-meas` / `--disable-challenge` | Compile out GET_MEASUREMENTS / CHALLENGE (default: enabled) |
| `--disable-heartbeat` / `--disable-key-update` | Compile out HEARTBEAT / KEY_UPDATE (default: enabled) |
| `--enable-tcg` / `--enable-nuvoton` / `--enable-nations` / `--enable-psk` / `--enable-responder` | TPM side: TCG SPDM binding, vendor commands, PSK and the responder (default: all disabled, so a standalone build carries none of it) |
| `--disable-mctp` | Pure TCG build: drops MCTP secured messages and the whole standard requester (needs `--enable-tcg` or a vendor) |
| `--with-wolfssl=PATH` | wolfSSL installation path |
| `CFLAGS=-DWOLFSPDM_DATA_TRANSFER_SIZE=N` | Largest single SPDM message, 42 to 4096 (default 4096). Smaller values shrink the per-message transport buffers; larger messages then travel in CHUNK_SEND/CHUNK_GET pieces when the responder supports chunking |

### Memory Modes

**Static (default):** zero heap allocation. The caller provides a buffer (`WOLFSPDM_CTX_STATIC_SIZE` bytes, ~32 KB) and wolfSPDM operates entirely within it. Ideal for embedded and constrained environments where malloc is unavailable or undesirable.

```c
#include <wolfspdm/spdm.h>

byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
/* ... use ctx ... */
wolfSPDM_Free(ctx);
```

**Dynamic (`--enable-dynamic-mem`):** context is heap-allocated via `wolfSPDM_New()`. Useful on platforms with small stacks where a ~32 KB local variable is impractical.

```c
#include <wolfspdm/spdm.h>

WOLFSPDM_CTX* ctx = wolfSPDM_New();
/* ... use ctx ... */
wolfSPDM_Free(ctx);  /* frees heap memory */
```

## Quick Start

`examples/spdm_demo` is a CLI driver that exercises each SPDM operation against `spdm-emu` over TCP/MCTP:

```bash
# Build the DMTF spdm-emu emulator
git clone --recursive https://github.com/DMTF/spdm-emu.git
cd spdm-emu && mkdir build && cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key && make

# Run the 18-test integration matrix from this repo
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

The driver starts/stops `spdm_responder_emu` per test and runs six scenarios — Session, Signed Measurements, Unsigned Measurements, Challenge, Heartbeat, Key Update — across SPDM 1.2, 1.3, and 1.4 (18 tests total).

## Relationship to wolfTPM's SPDM

wolfTPM ships its own SPDM implementation in `src/spdm/` for hardware-backed responders (Nuvoton NPCT75x, NSING NS350) with PSK / TCG-binding extensions. **wolfSPDM is a separate implementation** focused on the standard DSP0274 / DSP0277 requester for embedded use with `spdm-emu` and any standards-compliant peer. The two share heritage and are both designed for lightweight embedded use, with different deployment targets:

| | wolfSPDM | wolfTPM `src/spdm/` |
|---|---|---|
| Role | Requester only | Requester + responder |
| Scope | Pure standard SPDM 1.2 / 1.3 / 1.4 | Same, plus PSK / TCG / Nuvoton / Nations vendor bindings |
| Target | Embedded / spdm-emu / generic SPDM peer | TPM hardware (Nuvoton, NS350) |
| Footprint | ~32 KB context, zero-malloc (default static mode) | Lightweight embedded footprint; size depends on TPM stack, target, and build configuration |

Either library can be used standalone; they aren't link-time compatible.

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu 22.04 / 24.04, debug and release, static-mem and `--enable-dynamic-mem`
- **Multi-compiler**: GCC 11-13 and Clang 14-17 with `-Wall -Wextra -Werror`
- **Compiler Warnings**: strict `-Wpedantic -Werror -Wconversion -Wshadow`
- **Static Analysis**: cppcheck and Clang Static Analyzer (`scan-build`)
- **CodeQL Security**: weekly + per-PR analysis
- **Memory Check**: Valgrind `--leak-check=full` (static and dynamic mem)
- **SPDM Emulator Integration**: 18-test matrix (6 scenarios x SPDM 1.2 / 1.3 / 1.4) across ubuntu-22.04 x64, ubuntu-24.04 x64, and ubuntu-24.04-arm aarch64
- **Skoll review**: wolfSSL deep-review pipeline, pre-merge security and code review

<a href="https://github.com/aidangarske/wolfSPDM/actions">
  <img src="https://img.shields.io/github/actions/workflow/status/aidangarske/wolfSPDM/build-test.yml?label=CI&logo=github">
</a>
<a href="https://github.com/wolfssl/skoll">
  <img src="https://img.shields.io/badge/skoll-passed-blue">
</a>
<a href="https://github.com/wolfssl/fenrir">
  <img src="https://img.shields.io/badge/fenrir-passed-blueviolet">
</a>

## Documentation

Full documentation is available in the [GitHub Wiki](https://github.com/aidangarske/wolfSPDM/wiki):

- [Getting Started](https://github.com/aidangarske/wolfSPDM/wiki/Getting-Started): Build instructions, prerequisites, memory modes, and first connection steps
- [Supported Operations](https://github.com/aidangarske/wolfSPDM/wiki/Supported-Operations): SPDM operation coverage and API mapping
- [API Reference](https://github.com/aidangarske/wolfSPDM/wiki/API-Reference): Public function groups and common error-code references
- [Configuration and Macros](https://github.com/aidangarske/wolfSPDM/wiki/Configuration-and-Macros): Configure flags and compile-time feature controls
- [Post-Quantum ML-DSA](https://github.com/aidangarske/wolfSPDM/wiki/Post-Quantum-ML-DSA): Post-quantum signatures (FIPS 204)
- [Post-Quantum ML-KEM](https://github.com/aidangarske/wolfSPDM/wiki/Post-Quantum-ML-KEM): Post-quantum key exchange (FIPS 203) and the fully post-quantum handshake
- [Message Chunking](https://github.com/aidangarske/wolfSPDM/wiki/Message-Chunking): SPDM 1.2 CHUNK_GET reassembly for large responses
- [Testing and CI](https://github.com/aidangarske/wolfSPDM/wiki/Testing-and-CI): Unit tests, emulator integration tests, and CI workflow coverage
- [Project Structure](https://github.com/aidangarske/wolfSPDM/wiki/Project-Structure): Source layout and module responsibilities
- [Attestation Notes](https://github.com/aidangarske/wolfSPDM/wiki/Attestation-Notes): Measurement and challenge attestation behavior

## License

wolfSPDM is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

> **Note:** wolfSPDM is currently maintained by wolfSSL developers but is not yet classified as an officially supported product. It was designed from the ground up to meet the same quality standards as the rest of the wolfSSL suite with future adoption in mind. We are eager to transition this to a fully supported product as demand grows; if your organization requires official support, has specific feature requirements, or just has general questions or guidance with the product, please reach out.

For commercial licensing, professional support contracts, or to discuss moving wolfSPDM into your production environment, contact [wolfSSL](https://www.wolfssl.com/contact/).
