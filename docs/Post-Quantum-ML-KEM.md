# Post-Quantum ML-KEM

SPDM 1.4 (DMTF DSP0274 1.4.0) adds **ML-KEM** (FIPS 203) as a post-quantum
**key-exchange** method. wolfSPDM implements the requester side, advertised
alongside the classical ECDHE P-384 group so the responder selects one.
ML-KEM rides the certificate flow, so it is only available when the standard
requester is built (not `WOLFSPDM_NO_CERT`).

ML-KEM in SPDM 1.4 is **standalone, not hybrid** — DSP0274 §23.5 states "key
encapsulation (ML-KEM) for session establishment. **No support for hybrid
algorithms.**" When ML-KEM is negotiated it *replaces* the DHE group, and its
decapsulated 32-byte shared secret feeds the existing key schedule in place of
the ECDH secret. Combine it with [[Post-Quantum ML-DSA]] signing for a **fully
post-quantum SPDM handshake**.

## How it works (DSP0274 1.4 §10.17.2)

1. The requester generates an ephemeral ML-KEM key pair and sends the
   **encapsulation key `ek`** as the `KEY_EXCHANGE` `ExchangeData` (replacing
   the 96-byte ECDHE X‖Y point). The ephemeral key lives in the context as a
   union of `ecc_key` and `MlKemKey` (`ctx->ephemeral`) — only one is ever
   live per session.
2. The responder encapsulates, returning the **ciphertext `c`** as the
   `KEY_EXCHANGE_RSP` `ExchangeData` (alongside its signature and HMAC).
3. The requester **decapsulates** `c` with its decapsulation key `dk` to
   recover the 32-byte shared secret `K′`, which drives the key schedule
   (§12.2). TH1/TH2 and all downstream derivation are unchanged from the
   ECDHE path.

Per FIPS 203 implicit rejection, a `K′ ≠ K` mismatch surfaces only as a FINISH
integrity-check failure and is handled like any other session-message
failure.

## How negotiation works

In `NEGOTIATE_ALGORITHMS`, wolfSPDM advertises a `KEMAlg` `AlgStruct`
(`AlgType = 0x07`, DSP0274 1.4 Table 24) with the ML-KEM sets the linked
wolfSSL was built with, dual-stack alongside the DHE group. The responder
selects **exactly one** key-exchange method — a DHE group **or** a KEM, never
both (no hybrid). wolfSPDM enforces that mutual exclusivity when parsing
`ALGORITHMS`.

| KEMAlg bit | Algorithm | `ek` (request) | ciphertext `c` (response) | shared secret |
|-----------|-----------|----------------|---------------------------|---------------|
| `0x0001` | ML-KEM-512  | 800 B  | 768 B  | 32 B |
| `0x0002` | ML-KEM-768  | 1184 B | 1088 B | 32 B |
| `0x0004` | ML-KEM-1024 | 1568 B | 1568 B | 32 B |

By default wolfSPDM advertises ECDHE **and** every ML-KEM set built in. To
force a PQC-only key exchange (e.g. for testing), pin it at runtime:

```c
/* Advertise only ML-KEM-768 (advDhe = 0). The responder must use it or fail. */
wolfSPDM_SetKeyExchangePref(ctx, 0, SPDM_KEM_ALGO_ML_KEM_768);
```

A KEM-only preference below SPDM 1.4 fails (`WOLFSPDM_E_ALGO_MISMATCH`) rather
than silently downgrading to DHE.

## Building

ML-KEM follows the linked wolfSSL automatically: it is enabled when wolfSSL
reports `WOLFSSL_HAVE_MLKEM` and provides the `wc_MlKemKey` API (build
wolfSSL with `--enable-mlkem`), the standard requester is built (not
`WOLFSPDM_NO_CERT`), and `--disable-mlkem` was not passed. The capability is
detected at configure time.

```sh
# wolfSSL with ML-KEM (and ML-DSA for a fully post-quantum handshake)
./configure --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf \
            --enable-sp --enable-mlkem --enable-mldsa --prefix=$HOME/wolfssl-install
make && make install

# wolfSPDM (ML-KEM auto-enabled; --enable-mlkem asserts it, --disable-mlkem off)
./configure --with-wolfssl=$HOME/wolfssl-install
make && make check
```

The configure summary prints `ML-KEM: yes|no`. wolfSPDM uses the
`wc_MlKemKey_*` API only (`Init`, `MakeKey`, `EncodePublicKey`, `Decapsulate`,
the size getters, `Free`); the legacy `wc_KyberKey_*` aliases are not used.

The demo selects a key exchange with `--kex`:

```sh
./examples/spdm_demo --emu --ver 1.4 --kex mlkem768   # ML-KEM key exchange
./examples/spdm_demo --emu --ver 1.4 --kex ecdhe      # classical ECDHE
```

## Memory and message-size notes

ML-KEM only changes the key-exchange `ExchangeData`; everything downstream is
unchanged. Two size effects:

- **Larger KEY_EXCHANGE request.** The `ek` (up to 1568 B for ML-KEM-1024)
  makes the request larger than the ~158 B classical ECDHE request. If it
  exceeds the negotiated `DataTransferSize`, wolfSPDM sends it with
  `CHUNK_SEND` when the responder has negotiated `CHUNK_CAP` — see
  [[Message Chunking]]. Without chunking support on either side, a request
  that exceeds `DataTransferSize` is refused locally with
  `WOLFSPDM_E_BUFFER_SMALL` rather than sent oversized.
- **Static context.** The ephemeral ML-KEM key lives in the context (a union
  with the classical `ecc_key`; only one is ever live), so ML-KEM-only builds
  use a larger `WOLFSPDM_CTX_STATIC_SIZE` (40960) than the classical profile
  (32768) — see [[Configuration and Macros]]. A fully post-quantum
  (ML-KEM + ML-DSA) build uses the ML-DSA budget (73728), which already
  covers it.

When ML-KEM and ML-DSA are combined, an ML-DSA-87 signed response plus the
ML-KEM ciphertext can exceed the `DataTransferSize`, so the responder chunks
it and wolfSPDM reassembles via `CHUNK_GET` — the full-PQ path exercises
ML-KEM, ML-DSA, and chunking together.

## References

- DMTF DSP0274 1.4.0 — §10.17.2 (ML-KEM scheme), §10.17.3 (message formats,
  Table 77), §12.2 (KEM K/K′ computation), Table 24 (KEMAlg), §23.5 (no hybrid)
- NIST FIPS 203 — ML-KEM
- wolfSSL `wc_mlkem.h` — `wc_MlKemKey_*` API
