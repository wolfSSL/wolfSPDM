# Getting Started

## Prerequisites

wolfSPDM depends on wolfSSL/wolfCrypt with SPDM-required algorithms enabled.

Minimum validated wolfSSL version: **v5.8.0-stable**.

Example wolfSSL build:

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

For optional post-quantum support add `--enable-mldsa` (signatures, FIPS 204)
and/or `--enable-mlkem` (key exchange, FIPS 203); wolfSPDM then auto-enables
each capability it finds. See [[Post-Quantum ML-DSA]] and
[[Post-Quantum ML-KEM]].

## Build wolfSPDM

```bash
./autogen.sh
./configure --with-wolfssl=/usr/local
make
make check
```

### Configure options

| Option | Description |
|--------|-------------|
| `--with-wolfssl=PATH` | Path to wolfSSL headers/libs |
| `--enable-debug` | Enables debug build flags and `WOLFSPDM_DEBUG` |
| `--enable-dynamic-mem` | Enables heap-allocated context APIs (`wolfSPDM_New`) |
| `--disable-cert` | Disables the standard certificate requester |
| `--disable-mctp` | Pure TCG build: drops MCTP secured messages and the whole standard requester (needs `--enable-tcg` or a vendor) |
| `--disable-app-data` | Disables the MCTP application data API |
| `--disable-chunking` | Disables CHUNK_SEND/CHUNK_GET |
| `--disable-meas` / `--disable-challenge` | Disables GET_MEASUREMENTS / CHALLENGE |
| `--disable-heartbeat` / `--disable-key-update` | Disables HEARTBEAT / KEY_UPDATE |
| `--disable-mldsa` / `--disable-mlkem` | Forces ML-DSA / ML-KEM off (default auto-follows wolfSSL) |
| `--enable-tcg` / `--enable-nuvoton` / `--enable-nations` / `--enable-psk` / `--enable-responder` | TPM side: TCG SPDM binding, vendor commands, PSK, responder (default: all off) |

See [[Configuration and Macros]] for the full option-to-macro mapping and
their implications.

## Memory modes

### Static mode (default)

Zero-malloc operation with caller-managed context memory:

```c
byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
```

`WOLFSPDM_CTX_STATIC_SIZE` is 32768 bytes by default, 40960 with ML-KEM only,
and 73728 with ML-DSA built in (see [[Configuration and Macros]]).

### Dynamic mode (optional)

Enable with `--enable-dynamic-mem`, then:

```c
WOLFSPDM_CTX* ctx = wolfSPDM_New();
```

## Minimal connection flow (standard requester)

1. Initialize context (`wolfSPDM_Init` or `wolfSPDM_InitStatic`)
2. Register transport callback with `wolfSPDM_SetIO`
3. Optionally set trust root with `wolfSPDM_SetTrustedCAs`, or pin the
   responder key with `wolfSPDM_SetResponderPubKey`
4. Establish session with `wolfSPDM_Connect`
5. Exchange secured data using `wolfSPDM_SecuredExchange` (or the
   `SendData`/`ReceiveData` MCTP application-message helpers)
6. End session with `wolfSPDM_Disconnect`
7. Cleanup via `wolfSPDM_Free`

## Transport callback contract

All transport is caller-owned through:

```c
typedef int (*WOLFSPDM_IO_CB)(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx);
```

The callback sends raw SPDM/SPDM-secured records and returns the responder
message. `wolfSPDM_SendData` calls it with `rxBuf` NULL and `*rxSz` 0
(send only); `wolfSPDM_ReceiveData` calls it with `txBuf` NULL and `txSz` 0
(receive only).

## Running the demo against spdm-emu

`examples/spdm_demo` drives each SPDM operation against `spdm-emu` over
TCP/MCTP:

```bash
git clone --recursive https://github.com/DMTF/spdm-emu.git
cd spdm-emu && mkdir build && cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key && make

export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

`spdm_demo` accepts `--emu`, `--meas` (add `--no-sig` for unsigned
measurements), `--challenge`, `--heartbeat`, `--key-update`, `--app-data`,
`--ver 1.2|1.3|1.4`, `--kex ecdhe|mlkem512|mlkem768|mlkem1024`, and `--debug`.
`examples/spdm_test.sh` runs the 21-test matrix (7 scenarios x SPDM
1.2/1.3/1.4): session, signed measurements, unsigned measurements, challenge,
heartbeat, key update, and application data (PLDM GetTID).
