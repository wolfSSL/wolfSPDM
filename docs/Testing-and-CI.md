# Testing and CI

## Local tests

### Unit tests

```bash
make check
./test/unit_test
```

### Integration test with DMTF spdm-emu

```bash
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

`spdm_test.sh` runs 21 tests, seven scenarios across SPDM 1.2, 1.3 and 1.4:
- Session
- Signed measurements
- Unsigned measurements
- Challenge
- Heartbeat
- Key update
- Application data (PLDM GetTID as an MCTP application message)

`SPDM_EMU_ARGS` passes extra responder options, e.g. `--cap ...,CHUNK`.

## CI workflow coverage

Documented workflows include:

- Build and Test (OS/config matrix)
- Multiple Compilers (GCC 11-13, Clang 14-17)
- Compiler Warnings (`-Werror`, pedantic/conversion/shadow checks)
- Static Analysis (cppcheck + scan-build)
- Memory Check (Valgrind)
- Empty Brace Scope Scan
- CodeQL Security
- Codespell
- SPDM Emulator Test (integration matrix on x64 + aarch64, plus chunking
  against small-buffer responders at DataTransferSize 42 and 64)
- wolfTPM downstream: wolfTPM master built with this wolfSPDM in its 14 SPDM
  configurations, its SPDM unit tests, and the fwTPM TCG and PSK end-to-end
  runs; the standard requester symbols must stay out of `libwolftpm`
- SPDM Emulator PQC Test — wolfSSL master + spdm-emu (OpenSSL backend) on the
  full x64 + aarch64 matrix. Builds wolfSPDM ML-KEM-only as well as the combined
  config, then runs over the wire: ML-DSA-44/65/87 (signatures), ML-KEM-512/768/1024
  (key exchange), and a **fully post-quantum** leg (ML-KEM-768 + ML-DSA-65/87) for
  session, measurements, challenge, heartbeat, key update and application data.

See `.github/workflows/README.md` for workflow inventory details.

## ML-DSA (post-quantum signatures) test coverage

- **Unit (`make check`, ML-DSA build):** PqcAsymAlgo/PqcAsymSel wire offsets and
  the Base/Pqc mutual exclusion; a real wolfSSL ML-DSA sign + verify round trip
  through `wolfSPDM_VerifyRspSig` for ML-DSA-44/65/87 with tamper, wrong-context
  and wrong-size negatives; and the KEY_EXCHANGE_RSP signature-size guard.
- **Certificate chains:** `wolfSPDM_ValidateCertChain` verifies every link of
  the libspdm ML-DSA-44 sample chain against its root, rejects a forged leaf
  signature, and rejects a leaf whose set differs from the negotiated one.
- **Over-the-wire (CI):** ML-DSA-44/65/87 all complete against spdm-emu;
  ML-DSA-87 responses exceed the 4608 B DataTransferSize and are reassembled via
  the SPDM 1.2 chunking engine (see [[Message Chunking]]).

## ML-KEM (post-quantum key exchange) test coverage

- **Unit (`make check`, ML-KEM build):** KEMAlg negotiation wire offsets, the
  DHE-xor-KEM mutual-exclusion, a real wolfSSL ML-KEM encapsulate/decapsulate
  round-trip asserting `K′ == K`, the KEY_EXCHANGE `ek` placement, the
  KEY_EXCHANGE_RSP ciphertext-offset math, the reconnect key-type-switch (no
  type-confused free), the KEM-only-below-1.4 refusal, and the refusal of an
  unchunked request above the responder's DataTransferSize.
- **Over-the-wire (CI):** ML-KEM-512/768/1024 against spdm-emu (`--dhe NONE
  --kem ML_KEM_*`), and a **fully post-quantum** leg pairing ML-KEM-768 with
  ML-DSA-65/87 — the ML-DSA-87 case also exercises chunking, so ML-KEM + ML-DSA +
  CHUNK_GET reassembly all run in a single handshake.
- **Config coverage (CI):** an ML-KEM-only build (`--disable-mldsa
  --enable-mlkem`) exercises the ML-KEM-only `WOLFSPDM_CTX_STATIC_SIZE` budget.

## Validation caveat

Building/tests require a compatible wolfSSL installation and may fail if `--with-wolfssl` is not provided or wolfSSL is absent from default search paths.
