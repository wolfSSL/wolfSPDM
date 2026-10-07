# wolfSPDM

wolfSPDM is a lightweight C library implementing [SPDM 1.2 / 1.3 / 1.4](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf) and [Secured Messages over MCTP (DSP0277)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf), using [wolfSSL](https://www.wolfssl.com/) as the crypto backend. It provides both the **standard DMTF SPDM requester** for embedded use and the **TCG-spec TPM SPDM binding** that powers wolfTPM, tested end-to-end against the DMTF [spdm-emu](https://github.com/DMTF/spdm-emu) emulator.

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

Add `--disable-mctp` for a TPM-only build that drops the standard DMTF requester entirely, and `--enable-nuvoton` / `--enable-nations` for vendor TPM commands. Each piece is independent, so you can compose exactly what you want: `--enable-tcg` alone gives just the TCG binding (PSK and the responder stay off until you enable them).

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

wolfSPDM links against [wolfSSL](https://www.wolfssl.com/). wolfSSL is bundled as
the `lib/wolfssl` submodule at a known-good commit, so clone wolfSPDM with
`--recursive` (or run `git submodule update --init lib/wolfssl`) and build it
from there. **`--enable-wolftpm` is required** on the wolfSSL build (it turns on
the wolfCrypt features wolfSPDM relies on); the remaining flags select the SPDM
algorithm set.

**Supported wolfSSL versions:**

- Classical SPDM (Algorithm Set B): wolfSSL **>= v5.8.0-stable** (hard minimum, enforced by `configure`).
- ML-KEM key exchange: works on the classical floor, wolfSSL **>= v5.8.0-stable** (detected by the `wc_MlKemKey` API probe).
- ML-DSA authentication: wolfSSL **>= v5.9.2-stable** (the `wc_MlDsaKey` context API lands there). Requesting ML-DSA against older wolfSSL fails `configure`; in auto mode ML-DSA is disabled with a warning.

### Default build (Algorithm Set B: ECC P-384, SHA-384, AES-256-GCM, HKDF)

```bash
cd lib/wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
            --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install
sudo ldconfig
cd ../..
```

`--enable-sp` enables Single Precision math with optimized ECC P-384, required
for Algorithm Set B on ARM64 and other constrained targets. `--enable-all` works
as a superset.

### Post-quantum build (ML-KEM key exchange + ML-DSA authentication)

Needs wolfSSL **>= v5.9.2-stable** for ML-DSA (ML-KEM alone works on v5.8.0).
Post-quantum extends Algorithm Set B rather
than replacing it: ML-KEM and ML-DSA take over key exchange and authentication,
while the secured session still uses SHA-384, AES-256-GCM, and HKDF. Keep the
Set B flags and add `--enable-mldsa` (FIPS 204) and `--enable-mlkem` (FIPS 203):

```bash
cd lib/wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
            --enable-aesgcm --enable-hkdf --enable-sp \
            --enable-mldsa --enable-mlkem
make
sudo make install
sudo ldconfig
cd ../..
```

wolfSPDM auto-enables each when the linked wolfSSL provides it (`--disable-mldsa`
/ `--disable-mlkem` force them off).

The pinned wolfSSL submodule can be updated like any checkout: `cd lib/wolfssl`,
check out or rebuild whatever you need (at or above the floors above), then
reinstall. `git submodule update` restores the pin. To build against your own
installed wolfSSL instead, pass `--with-wolfssl=PATH` to wolfSPDM.

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
| `--enable-tcg` / `--enable-nuvoton` / `--enable-nations` / `--enable-psk` / `--enable-responder` | TPM side: TCG SPDM binding, vendor commands, PSK and the responder (default: all disabled, so a standalone build carries none of it) |
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
