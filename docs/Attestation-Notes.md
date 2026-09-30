# Attestation Notes

wolfSPDM supports SPDM attestation through both measurement retrieval and
challenge authentication (`src/spdm_attest.c`). Both ride the certificate
flow, so they require the standard requester (not `WOLFSPDM_NO_CERT`) and are
compiled out entirely without it.

## Measurement attestation (`GET_MEASUREMENTS`)

Primary API:

```c
int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature);
```

Behavior:
- `requestSignature=1`: requests signed measurements; the responder's
  signature is verified against the running L1/L2 transcript hash before the
  blocks are exposed to the caller.
- `requestSignature=0`: retrieves unsigned measurements without a signature
  check.
- The call requires `SPDM_CAP_MEAS_CAP_SIG` (signed) or
  `SPDM_CAP_MEAS_CAP_NO_SIG` (unsigned) from the responder's negotiated
  capabilities, else `WOLFSPDM_E_CAPS_MISMATCH`.

**L1/L2 running hash.** L1/L2 spans *consecutive* `GET_MEASUREMENTS`
exchanges: each call restarts the hash at the VCA transcript unless the
previous `GET_MEASUREMENTS` left it open (`WOLFSPDM_RUN_OPEN`, i.e. the prior
call was unsigned). A signed request closes the run and verifies the
signature over it; an unsigned request adds itself to the hash and leaves the
run open for the next call.

Signature verification (measurements and `CHALLENGE_AUTH`) uses whichever
asymmetric algorithm was negotiated — ECDSA P-384 or, on SPDM 1.4 with ML-DSA
built in, ML-DSA-44/65/87. See [[Post-Quantum ML-DSA]].

Result access:
- `wolfSPDM_GetMeasurementCount`
- `wolfSPDM_GetMeasurementBlock` — `valueSz` is in/out; `measType` is the DMTF
  value type, 0 for raw (non-DMTF-spec) blocks

Relevant return codes:
- `WOLFSPDM_SUCCESS`
- `WOLFSPDM_E_CAPS_MISMATCH` — signed/unsigned measurement capability not negotiated
- `WOLFSPDM_E_MEASUREMENT` — malformed or inconsistent `MEASUREMENTS` response
- `WOLFSPDM_E_BAD_SIGNATURE` / `WOLFSPDM_E_CRYPTO_FAIL` — signature length mismatch or verification failure

## Sessionless challenge attestation (`CHALLENGE_AUTH`)

Primary API:

```c
int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType);
```

Prerequisite state (checked, returns `WOLFSPDM_E_BAD_STATE` otherwise):
- Certificate chain retrieved for `slotId` (`ctx->state >= WOLFSPDM_STATE_CERT`)
- `slotId` matches the slot the chain was fetched for
- An M1 transcript run is open (started by `GET_DIGESTS`/`GET_CERTIFICATE`)
- `SPDM_CAP_CHAL_CAP` negotiated, else `WOLFSPDM_E_CAPS_MISMATCH`

**M1 running hash.** M1 starts at the VCA transcript when the certificate
chain is fetched and accumulates through `CHALLENGE`/`CHALLENGE_AUTH`.
`wolfSPDM_KeyExchange` restarts M1 at the VCA before building its request —
`KEY_EXCHANGE` drops `GET_DIGESTS`/`GET_CERTIFICATE` from its own M1 — and a
successful `CHALLENGE` restarts M1 again afterward, so the next M1 is the VCA
plus only the messages that follow.

`wolfSPDM_ValidateCertChain` is run before building the request; see
[[Post-Quantum ML-DSA]] for how the chain is verified link by link.

Relevant return codes:
- `WOLFSPDM_E_BAD_STATE`, `WOLFSPDM_E_CAPS_MISMATCH`
- `WOLFSPDM_E_CERT_FAIL` — chain validation failed
- `WOLFSPDM_E_CHALLENGE` — malformed or mismatched `CHALLENGE_AUTH`
- `WOLFSPDM_E_BAD_SIGNATURE` / `WOLFSPDM_E_CRYPTO_FAIL` — signature failure

## Signature context strings

Each signed exchange uses its own SPDM signing context string, mixed into the
ML-DSA `ctx` parameter or the classical signed-hash construction:
`"responder-measurements signing"`, `"responder-challenge_auth signing"`,
`"responder-key_exchange_rsp signing"`.

## Trust anchor handling

Load trusted CA material with:

```c
int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz);
```

`wolfSPDM_SetTrustedCAs` accepts a single DER root certificate; its SHA-384
hash is compared against the chain header's `RootHash`. Alternatively, pin
the responder's leaf key directly with `wolfSPDM_SetResponderPubKey`, or
explicitly opt out of anchoring with `wolfSPDM_AllowUntrustedCerts`. Without
one of the three, `wolfSPDM_ValidateCertChain` fails with
`WOLFSPDM_E_CERT_FAIL`.

## Feature toggles

- `--disable-meas` / `WOLFSPDM_NO_MEAS` disables `GET_MEASUREMENTS` (also
  implied by `WOLFSPDM_NO_CERT`)
- `--disable-challenge` / `WOLFSPDM_NO_CHALLENGE` disables `CHALLENGE` (also
  implied by `WOLFSPDM_NO_CERT`)

See [[Configuration and Macros]] for the full implication chain.
