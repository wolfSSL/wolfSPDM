# wolfSPDM

wolfSPDM is a lightweight C library implementing [SPDM 1.2 / 1.3 / 1.4](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf) and [Secured Messages over MCTP (DSP0277)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf), using [wolfSSL](https://www.wolfssl.com/) as the crypto backend. It provides both the **standard DMTF SPDM requester** for embedded use and the **TCG-spec TPM SPDM binding** that powers wolfTPM, tested end-to-end against the DMTF [spdm-emu](https://github.com/DMTF/spdm-emu) emulator.

## Supported TPM hardware

| Part | Configure | Session type | Vendor commands on top of the binding |
|---|---|---|---|
| Nuvoton NPCT75x | `--enable-nuvoton` | Identity key | `wolfSPDM_Nuvoton_*` |
| Nations NS350 | `--enable-nations` | Identity key, PSK | `wolfSPDM_Nations_*`, including PSK provisioning |
| Infineon OPTIGA SLB9678 | `--enable-infineon` | Identity key | `wolfSPDM_Infineon_GetStatus`, `wolfSPDM_Infineon_SetOnlyMode` |

Every one of these speaks the same TCG TPM SPDM binding, and a part that implements that binding with no vendor extensions needs only `--enable-tcg`. The vendor switch adds that part's own commands on top; it is not what makes the session work. Build details and the per-part notes are below.

## Standard and TCG TPM SPDM

wolfSPDM is one SPDM implementation with a shared core: version, capability, and algorithm negotiation, key exchange, secured sessions, transcript, and crypto. The standard DMTF requester and the TCG TPM binding are closely related modes on that core, selected by build switches:

- **Standard DMTF SPDM** (default): the 1.2 / 1.3 / 1.4 certificate requester (DSP0274 and Secured Messages over MCTP DSP0277), post-quantum ready, for embedded use.
- **TCG TPM SPDM**: the TCG-spec SPDM binding (TPM transport, identity-key mutual auth, PSK, responder) that provides wolfTPM's SPDM support.

**Standalone (DMTF requester):**

```bash
./configure
make
```

**With wolfTPM (TCG TPM SPDM):** wolfTPM builds wolfSPDM automatically when its SPDM support is enabled (`WOLFTPM_SPDM`). To build the TPM side here, opt into the pieces you need on top of the default:

```bash
./configure --enable-tcg --enable-psk --enable-responder
make
```

Add `--disable-mctp` for a TPM-only build that drops the standard DMTF requester entirely, and `--enable-nuvoton` / `--enable-nations` / `--enable-infineon` for vendor TPM commands. Each piece is independent, so you can compose exactly what you want: `--enable-tcg` alone gives just the TCG binding (PSK and the responder stay off until you enable them).

### Infineon OPTIGA SLB9678

The SLB9678 is the part that needs the least from this library. Its identity handshake is the plain TCG binding, so `WOLFSPDM_MODE_TCG` connects to it with no vendor adapter at all:

```bash
./configure --enable-tcg --enable-infineon
make
```

`--enable-infineon` adds only the two vendor commands above; drop it and `wolfSPDM_Connect` in `WOLFSPDM_MODE_TCG` still completes the handshake. The mode uses Algorithm Set B like every other TCG session: ECDHE and ECDSA P-384, SHA-384, AES-256-GCM. Trust comes from pinning the responder's P-384 public key with `wolfSPDM_SetResponderPubKey`, 96 bytes of X followed by Y, since the part presents a raw key rather than a certificate chain. Note that `WOLFSPDM_MODE_TCG` has to be set explicitly: `WOLFSPDM_MODE_AUTO` selects the standard DMTF requester, not the TCG binding.

Asymmetric sessions need firmware advertising `KEY_EX_CAP` and `PUB_KEY_ID_CAP`. Do not infer that from the part number: read the capabilities before relying on the mode.

## Main Features

- **Standard SPDM 1.2 / 1.3 / 1.4 requester** per DMTF DSP0274 and DSP0277
- **Algorithm Set B fixed:** ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- **Post-quantum signatures (SPDM 1.4):** optional ML-DSA-44 / 65 / 87 (FIPS 204), dual-stacked with ECDSA P-384. See the [Post-Quantum ML-DSA](https://github.com/wolfSSL/wolfSPDM/wiki/Post-Quantum-ML-DSA) wiki page.
- **Post-quantum key exchange (SPDM 1.4):** optional ML-KEM-512 / 768 / 1024 (FIPS 203), advertised alongside ECDHE P-384. See the [Post-Quantum ML-KEM](https://github.com/wolfSSL/wolfSPDM/wiki/Post-Quantum-ML-KEM) wiki page.
- **Fully post-quantum SPDM handshake:** ML-KEM key exchange + ML-DSA authentication (no classical asymmetric crypto), proven end-to-end against spdm-emu
- **Zero-malloc by default:** static context for constrained targets; optional `--enable-dynamic-mem` for heap-allocated contexts on small-stack platforms
- **Full session lifecycle:** key exchange, finish, encrypted messaging, heartbeat keep-alive, key update
- **Device attestation:** signed / unsigned `GET_MEASUREMENTS`, sessionless `CHALLENGE_AUTH`, certificate-chain validation against trusted root CAs
- **Compatible with DMTF spdm-emu** for interoperability testing (21-test matrix across 1.2 / 1.3 / 1.4)
- **Path to FIPS 140-3** via wolfCrypt FIPS Certificate #4718 (sole crypto dependency)

## Supported Operations (DSP0274 / DSP0277)

| Operation | DSP0274 | wolfSPDM API |
|---|---|---|
| Session establishment | Sec. 10.7 | `wolfSPDM_Connect`, `wolfSPDM_KeyExchange`, `wolfSPDM_Finish` |
| Encrypted application data | DSP0277 | `wolfSPDM_SecuredExchange`, `wolfSPDM_SendData`, `wolfSPDM_ReceiveData`, `wolfSPDM_EncryptMessage`, `wolfSPDM_DecryptMessage` |
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

The responder and TCG builds sign with long-term identity keys, so they also require wolfSSL's default `--enable-harden` (`ECC_TIMING_RESISTANT`). Configure and the build reject a wolfSSL built with `--disable-harden`.

For post-quantum support, build wolfSSL with `--enable-mldsa` (FIPS 204) and/or `--enable-mlkem` (FIPS 203). Use wolfSSL master or a release carrying the `wc_MlDsaKey` and `wc_MlKemKey` APIs. wolfSPDM auto-enables each when the linked wolfSSL provides it (`--disable-mldsa` / `--disable-mlkem` force them off); enabling both gives a fully post-quantum handshake (ML-KEM key exchange + ML-DSA authentication).

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
| `--disable-app-data` | Compile out `SendData`/`ReceiveData` MCTP application messages and `Encrypt`/`DecryptMessage` (default: enabled) |
| `--enable-tcg` / `--enable-nuvoton` / `--enable-nations` / `--enable-infineon` / `--enable-psk` / `--enable-responder` | TPM side: TCG SPDM binding, vendor commands, PSK and the responder (default: all disabled, so a standalone build carries none of it) |
| `--disable-mctp` | Pure TCG build: drops MCTP secured messages and the whole standard requester (needs `--enable-tcg` or a vendor) |
| `--with-wolfssl=PATH` | wolfSSL installation path |
| `CFLAGS=-DWOLFSPDM_DATA_TRANSFER_SIZE=N` | Largest single SPDM message, 42 to 4096 (default 4096). Smaller values shrink the per-message transport buffers; larger messages then travel in CHUNK_SEND/CHUNK_GET pieces when the responder supports chunking |

### Memory Modes

**Static (default):** zero heap allocation. The caller provides a buffer of `WOLFSPDM_CTX_STATIC_SIZE` bytes and wolfSPDM operates entirely within it. Ideal for embedded and constrained environments where malloc is unavailable or undesirable.

```c
#include <wolfspdm/spdm.h>

byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
/* ... use ctx ... */
wolfSPDM_Free(ctx);
```

**Dynamic (`--enable-dynamic-mem`):** context is heap-allocated via `wolfSPDM_New()`. Useful on platforms with small stacks where a large local variable is impractical.

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

# Run the 21-test integration matrix from this repo
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

The driver starts/stops `spdm_responder_emu` per test and runs seven scenarios across SPDM 1.2, 1.3, and 1.4 (21 tests total): Session, Signed Measurements, Unsigned Measurements, Challenge, Heartbeat, Key Update, and Application Data (PLDM GetTID).

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu 22.04 / 24.04, debug and release, static-mem and `--enable-dynamic-mem`
- **Multi-compiler**: GCC 11-13 and Clang 14-17 with `-Wall -Wextra -Werror`
- **Compiler Warnings**: strict `-Wpedantic -Werror -Wconversion -Wshadow`
- **Static Analysis**: cppcheck and Clang Static Analyzer (`scan-build`)
- **CodeQL Security**: weekly + per-PR analysis
- **Memory Check**: Valgrind `--leak-check=full` (static and dynamic mem)
- **SPDM Emulator Integration**: 21-test matrix (7 scenarios x SPDM 1.2 / 1.3 / 1.4) across ubuntu-22.04 x64, ubuntu-24.04 x64, and ubuntu-24.04-arm aarch64, plus chunking against small-buffer responders
- **SPDM Emulator PQC**: ML-DSA-44 / 65 / 87, ML-KEM-512 / 768 / 1024 and the fully post-quantum handshake against spdm-emu on OpenSSL
- **wolfTPM downstream**: wolfTPM master built with this wolfSPDM in its 14 SPDM configurations, its unit tests, and the fwTPM TCG and PSK end-to-end runs; the standard requester must stay compiled out

<a href="https://github.com/wolfSSL/wolfSPDM/actions">
  <img src="https://img.shields.io/github/actions/workflow/status/wolfSSL/wolfSPDM/build-test.yml?label=CI&logo=github">
</a>

## Documentation

Full documentation is available in the [GitHub Wiki](https://github.com/wolfSSL/wolfSPDM/wiki):

- [Getting Started](https://github.com/wolfSSL/wolfSPDM/wiki/Getting-Started): Build instructions, prerequisites, memory modes, and first connection steps
- [Supported Operations](https://github.com/wolfSSL/wolfSPDM/wiki/Supported-Operations): SPDM operation coverage and API mapping
- [API Reference](https://github.com/wolfSSL/wolfSPDM/wiki/API-Reference): Public function groups and common error-code references
- [Configuration and Macros](https://github.com/wolfSSL/wolfSPDM/wiki/Configuration-and-Macros): Configure flags and compile-time feature controls
- [Post-Quantum ML-DSA](https://github.com/wolfSSL/wolfSPDM/wiki/Post-Quantum-ML-DSA): Post-quantum signatures (FIPS 204)
- [Post-Quantum ML-KEM](https://github.com/wolfSSL/wolfSPDM/wiki/Post-Quantum-ML-KEM): Post-quantum key exchange (FIPS 203) and the fully post-quantum handshake
- [Message Chunking](https://github.com/wolfSSL/wolfSPDM/wiki/Message-Chunking): SPDM 1.2 CHUNK_GET reassembly for large responses
- [Testing and CI](https://github.com/wolfSSL/wolfSPDM/wiki/Testing-and-CI): Unit tests, emulator integration tests, and CI workflow coverage
- [Project Structure](https://github.com/wolfSSL/wolfSPDM/wiki/Project-Structure): Source layout and module responsibilities
- [Attestation Notes](https://github.com/wolfSSL/wolfSPDM/wiki/Attestation-Notes): Measurement and challenge attestation behavior

## License

wolfSPDM is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

For commercial licensing, professional support contracts, or to discuss moving wolfSPDM into your production environment, contact [wolfSSL](https://www.wolfssl.com/contact/).
