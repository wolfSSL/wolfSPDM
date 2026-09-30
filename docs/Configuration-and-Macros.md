# Configuration and Macros

## Configure-time options

From `configure.ac`:

| Option | Default | Defines | Effect |
|--------|---------|---------|--------|
| `--with-wolfssl=PATH` | system paths | — | Adds wolfSSL include/library search paths |
| `--enable-debug` | off | `WOLFSPDM_DEBUG` | Debug output, `-g -O0` |
| `--enable-dynamic-mem` | off | `WOLFSPDM_DYNAMIC_MEMORY` | Heap-allocated context, enables `wolfSPDM_New` |
| `--disable-cert` | enabled | `WOLFSPDM_NO_CERT` | Drops the standard certificate-based requester |
| `--disable-mctp` | enabled | `WOLFSPDM_NO_MCTP` | Pure TCG build: drops MCTP secured messages (implies `--disable-cert`); needs `--enable-tcg` or a vendor |
| `--disable-app-data` | enabled | `WOLFSPDM_NO_APP_DATA` | Drops `SendData`/`ReceiveData`/`Encrypt`/`DecryptMessage` |
| `--disable-chunking` | enabled | `WOLFSPDM_NO_CHUNK` | Drops CHUNK_SEND/CHUNK_GET (see [[Message Chunking]]) |
| `--disable-meas` | enabled | `WOLFSPDM_NO_MEAS` | Drops GET_MEASUREMENTS |
| `--disable-challenge` | enabled | `WOLFSPDM_NO_CHALLENGE` | Drops CHALLENGE |
| `--disable-heartbeat` | enabled | `WOLFSPDM_NO_HEARTBEAT` | Drops HEARTBEAT |
| `--disable-key-update` | enabled | `WOLFSPDM_NO_KEY_UPDATE` | Drops KEY_UPDATE |
| `--disable-mldsa` | auto | `WOLFSPDM_NO_MLDSA` | Force ML-DSA off (default follows wolfSSL — see [[Post-Quantum ML-DSA]]) |
| `--disable-mlkem` | auto | `WOLFSPDM_NO_MLKEM` | Force ML-KEM off (default follows wolfSSL — see [[Post-Quantum ML-KEM]]) |
| `--enable-tcg` | off | `WOLFSPDM_TCG` | TCG SPDM binding (TPM transport) |
| `--enable-nuvoton` | off | `WOLFSPDM_NUVOTON` | Nuvoton NPCT75x vendor commands (implies `--enable-tcg`) |
| `--enable-nations` | off | `WOLFSPDM_NATIONS` | Nations NS350 vendor commands (implies `--enable-tcg` and `--enable-psk`) |
| `--enable-psk` | off | `WOLFSPDM_PSK` | SPDM PSK_EXCHANGE/PSK_FINISH (requires `--enable-tcg`) |
| `--enable-responder` | off | `WOLFSPDM_RESPONDER` | SPDM responder (requires `--enable-tcg`) |

`CFLAGS=-DWOLFSPDM_DATA_TRANSFER_SIZE=N` sets the largest single SPDM message
(42 to `WOLFSPDM_MAX_MSG_SIZE`); smaller values shrink transport buffers and
rely more on chunking.

## wolfTPM build profile

Built inside wolfTPM (`WOLFTPM_SPDM`), `WOLFSPDM_PROFILE_TPM` is implied, and
wolfTPM's own switches (`WOLFTPM_SPDM_TCG`, `WOLFTPM_SPDM_PSK`,
`WOLFTPM_SPDM_RESPONDER`, `DEBUG_WOLFTPM`, `WOLFTPM_SMALL_STACK`) map onto the
matching `WOLFSPDM_*` macro. `WOLFSPDM_PROFILE_TPM` implies:

- `WOLFSPDM_NO_CERT` (the TPM only speaks the TCG binding)
- `WOLFSPDM_NO_HEARTBEAT`, `WOLFSPDM_NO_KEY_UPDATE`
- `WOLFSPDM_NO_APP_DATA` (application messages ride MCTP, which the TPM profile doesn't use)
- `WOLFSPDM_SECURED_PAD` = 16 instead of 48 (the TCG binding only pads to 16;
  MCTP secured records may carry up to 32 bytes of random padding per DSP0277)

## Implication chain

- `WOLFSPDM_NO_CERT` implies `WOLFSPDM_NO_MEAS`, `WOLFSPDM_NO_CHALLENGE`, and
  `WOLFSPDM_NO_CHUNK` (attestation and chunking need the certificate flow's
  VCA transcript), and blocks ML-DSA/ML-KEM (both ride the certificate flow).
  `NO_ASN` also forces `WOLFSPDM_NO_CERT`.
- `WOLFSPDM_NO_MCTP` implies `WOLFSPDM_NO_CERT` (and therefore everything
  above) and `WOLFSPDM_NO_APP_DATA`.
- `WOLFSPDM_PROFILE_TPM` implies `WOLFSPDM_NO_CERT`, `WOLFSPDM_NO_HEARTBEAT`,
  `WOLFSPDM_NO_KEY_UPDATE`, `WOLFSPDM_NO_APP_DATA`.
- `WOLFSPDM_NUVOTON` or `WOLFSPDM_NATIONS` implies `WOLFSPDM_TCG`.
- `WOLFSPDM_NATIONS` implies `WOLFSPDM_PSK`.
- `WOLFSPDM_TCG` or `WOLFSPDM_PROFILE_TPM` implies `WOLFSPDM_MUTUAL_AUTH`
  (requester identity-key API for TCG GIVE_PUB).
- `WOLFSPDM_LEAN` is accepted as an older alias for `WOLFSPDM_NO_APP_DATA`.

## Public feature macros

Defined in `wolfspdm/spdm.h` depending on build flags:

- `WOLFSPDM_HAS_APP_DATA` *(not defined if `WOLFSPDM_NO_APP_DATA`)*
- `WOLFSPDM_HAS_MEASUREMENTS` *(not defined if `WOLFSPDM_NO_MEAS`)*
- `WOLFSPDM_HAS_CHALLENGE` *(not defined if `WOLFSPDM_NO_CHALLENGE`)*
- `WOLFSPDM_HAS_HEARTBEAT` *(not defined if `WOLFSPDM_NO_HEARTBEAT`)*
- `WOLFSPDM_HAS_KEY_UPDATE` *(not defined if `WOLFSPDM_NO_KEY_UPDATE`)*
- `WOLFSPDM_HAVE_MLDSA` *(defined when ML-DSA is built in; follows wolfSSL's
  `WOLFSSL_HAVE_MLDSA`, suppress with `WOLFSPDM_NO_MLDSA`)* — see
  [[Post-Quantum ML-DSA]]
- `WOLFSPDM_HAVE_MLKEM` *(defined when ML-KEM is built in; follows wolfSSL's
  `WOLFSSL_HAVE_MLKEM`, suppress with `WOLFSPDM_NO_MLKEM`)* — see
  [[Post-Quantum ML-KEM]]. The advertised key-exchange methods are chosen at
  runtime with `wolfSPDM_SetKeyExchangePref(ctx, advDhe, kemMask)` (default:
  ECDHE + every ML-KEM set built in).

There is no `WOLFSPDM_HAVE_CHUNK` macro; chunking compiles in unless
`WOLFSPDM_NO_CHUNK` is defined (or implied by `WOLFSPDM_NO_CERT`).

## Size and protocol constants

From `wolfspdm/spdm.h` and `wolfspdm/spdm_types.h`. The buffer/context
defaults grow when ML-DSA or ML-KEM is built in (all are overridable with
`-D`):

| Constant | Classical | ML-KEM only | With ML-DSA |
|----------|-----------|-------------|-------------|
| `WOLFSPDM_CTX_STATIC_SIZE` | `32768` | `40960` | `73728` |
| `WOLFSPDM_MAX_MSG_SIZE` | `4096` | `4096` | `8192` |
| `WOLFSPDM_MAX_CERT_CHAIN` | `4096` | `4096` | `24576` |
| `WOLFSPDM_MAX_TRUSTED_CA` | `4096` | `4096` | `8192` |
| `WOLFSPDM_MAX_TRANSCRIPT` | `4096` | `8192` | `16384` |

Measured `sizeof(WOLFSPDM_CTX)` on arm64: ~19 KB classical, ~24 KB ML-KEM
only, ~59 KB with ML-DSA, ~9.5 KB in the TPM profile (well under the
corresponding `WOLFSPDM_CTX_STATIC_SIZE`).

Other overridable size macros (`wolfspdm/spdm_types.h`):
`WOLFSPDM_DATA_TRANSFER_SIZE` (default `WOLFSPDM_MAX_MSG_SIZE`, floor 42),
`WOLFSPDM_MAX_MEAS_RECORD` (`1024`), `WOLFSPDM_REQ_CAPS` (the CAPABILITIES
flags this requester advertises).

ML-KEM/ML-DSA size constants: `WOLFSPDM_MLDSA{44,65,87}_SIG_SIZE`,
`WOLFSPDM_MAX_SIG_SIZE`, `WOLFSPDM_MAX_KEX_DATA`. KEM algorithm bits:
`SPDM_KEM_ALGO_ML_KEM_512/768/1024` (`0x0001/0x0002/0x0004`). PQC asym bits:
`SPDM_PQC_ASYM_ALGO_ML_DSA_44/65/87` (`0x01/0x02/0x04`).

Version constants: `SPDM_VERSION_10`, `SPDM_VERSION_12`, `SPDM_VERSION_13`,
`SPDM_VERSION_14`.

Measurement constants (when enabled): `SPDM_MEAS_OPERATION_TOTAL_NUMBER`,
`SPDM_MEAS_OPERATION_ALL`, `SPDM_MEAS_SUMMARY_HASH_NONE`/`_TCB`/`_ALL`.

## Removed / renamed macros

These names from the old standalone design no longer exist:

- `NO_WOLFSPDM_MEAS` -> `WOLFSPDM_NO_MEAS`
- `NO_WOLFSPDM_CHALLENGE` -> `WOLFSPDM_NO_CHALLENGE`
- `WOLFSPDM_HAVE_CHUNK` -> chunking is on by default; use `WOLFSPDM_NO_CHUNK` to disable
- `WOLFSPDM_CHUNK_BUF_SIZE` -> removed; the chunk MTU is `WOLFSPDM_DATA_TRANSFER_SIZE`
- `WOLFSPDM_CHUNK_MAX_CHUNKS` -> removed, no configurable loop guard
- `WOLFSPDM_CHUNK_NO_SECURED` -> removed; secured chunking (e.g. GET_MEASUREMENTS) is always available when chunking is built in

## Notes

- `wolfspdm/options.h` is auto-generated from `config.h` during the build
  (`Makefile.am` greps `WOLFSPDM_` defines out of `config.h`).
- API availability should be detected using the `WOLFSPDM_HAS_*` feature
  macros rather than hard-coded assumptions.
