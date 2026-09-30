# API Reference

Public APIs are declared in `wolfspdm/spdm.h`, plus `wolfspdm/spdm_tcg.h`,
`spdm_nuvoton.h`, `spdm_nations.h`, `spdm_psk.h`, and `spdm_responder.h` for
the TPM/TCG side.

All APIs return `WOLFSPDM_SUCCESS` (`0`) on success unless documented
otherwise; failures are negative error codes from `wolfspdm/spdm_error.h`.

## Context and lifecycle

- `wolfSPDM_Init`
- `wolfSPDM_InitStatic`
- `wolfSPDM_GetCtxSize`
- `wolfSPDM_Free`
- `wolfSPDM_New` *(only when built with `WOLFSPDM_DYNAMIC_MEMORY`)*

## Configuration

- `wolfSPDM_SetIO`
- `wolfSPDM_SetMode` / `wolfSPDM_GetMode` *(`WOLFSPDM_MODE_AUTO` / `_NUVOTON` / `_NATIONS` / `_NATIONS_PSK`)*
- `wolfSPDM_SetResponderPubKey` — pin the responder key (96-byte P-384 X‖Y) for cert-less operation
- `wolfSPDM_SetRequesterKeyPair` *(`WOLFSPDM_MUTUAL_AUTH` builds — TCG or TPM profile)*
- `wolfSPDM_SetMaxVersion` — cap the negotiated version (0x12-0x14)
- `wolfSPDM_SetRequesterSessionId` — rejects `0x0000`, `0xFFFF`, and low bytes `0x10`-`0x1F`
- `wolfSPDM_SetTrustedCAs` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_AllowUntrustedCerts` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_SetKeyExchangePref` *(not with `WOLFSPDM_NO_CERT`)* — see [[Post-Quantum ML-KEM]]
- `wolfSPDM_SetDebug`

## Session establishment and state

- `wolfSPDM_Connect`
- `wolfSPDM_IsConnected`
- `wolfSPDM_Disconnect`
- `wolfSPDM_GetSessionId`
- `wolfSPDM_GetNegotiatedVersion`
- `wolfSPDM_GetVersion_Negotiated` *(older name for `wolfSPDM_GetNegotiatedVersion`)*
- `wolfSPDM_GetLastPeerError` — Param1 of the last SPDM ERROR, 0 if none
- `wolfSPDM_GetConnectionHandle` / `wolfSPDM_GetFipsIndicator` *(`WOLFSPDM_TCG` only)*

## Fine-grained handshake (standard requester)

- `wolfSPDM_GetVersion`
- `wolfSPDM_GetCapabilities` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_NegotiateAlgorithms` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_GetDigests` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_GetCertificate` *(not with `WOLFSPDM_NO_CERT`)*
- `wolfSPDM_KeyExchange`
- `wolfSPDM_Finish`

## Secured messaging

- `wolfSPDM_SecuredExchange`
- `wolfSPDM_SendData` / `wolfSPDM_ReceiveData` *(`WOLFSPDM_HAS_APP_DATA`, not over the TCG binding)*
- `wolfSPDM_EncryptMessage` / `wolfSPDM_DecryptMessage` *(`WOLFSPDM_HAS_APP_DATA`)*

## Attestation

- `wolfSPDM_GetMeasurements` *(`WOLFSPDM_HAS_MEASUREMENTS`)*
- `wolfSPDM_GetMeasurementCount` *(`WOLFSPDM_HAS_MEASUREMENTS`)*
- `wolfSPDM_GetMeasurementBlock` *(`WOLFSPDM_HAS_MEASUREMENTS`)*
- `wolfSPDM_Challenge` *(`WOLFSPDM_HAS_CHALLENGE`)*

## Session maintenance

- `wolfSPDM_Heartbeat` *(`WOLFSPDM_HAS_HEARTBEAT`)*
- `wolfSPDM_KeyUpdate` *(`WOLFSPDM_HAS_KEY_UPDATE`)*

## TCG SPDM binding (`wolfspdm/spdm_tcg.h`, `WOLFSPDM_TCG`)

- `wolfSPDM_ConnectTCG` *(alias `wolfSPDM_ConnectNuvoton`)*
- `wolfSPDM_TCG_GetPubKey` / `wolfSPDM_TCG_GivePubKey`
- `wolfSPDM_TCG_GetCapabilities` / `wolfSPDM_TCG_NegotiateAlgorithms`
- `wolfSPDM_SetRequesterKeyTPMT`
- `wolfSPDM_TCG_VendorCmdClear` / `wolfSPDM_TCG_VendorCmdSecured`
- `wolfSPDM_BuildTcgClearMessage` / `wolfSPDM_ParseTcgClearMessage`
- `wolfSPDM_BuildVendorDefined` / `wolfSPDM_ParseVendorDefined`

## Nuvoton (`wolfspdm/spdm_nuvoton.h`, `WOLFSPDM_NUVOTON`)

- `wolfSPDM_Nuvoton_GetStatus`
- `wolfSPDM_Nuvoton_SetOnlyMode`

## Nations (`wolfspdm/spdm_nations.h`, `WOLFSPDM_NATIONS`)

- `wolfSPDM_Nations_GetStatus`
- `wolfSPDM_Nations_SetOnlyMode`
- `wolfSPDM_Nations_PskSet` / `wolfSPDM_Nations_PskClear` / `wolfSPDM_Nations_PskClearWithVCA`

## PSK (`wolfspdm/spdm_psk.h`, `WOLFSPDM_PSK`)

- `wolfSPDM_SetPSK`
- `wolfSPDM_ConnectPsk` *(alias `wolfSPDM_ConnectNationsPsk`)*
- `wolfSPDM_BuildPskExchange` / `wolfSPDM_ParsePskExchangeRsp`
- `wolfSPDM_BuildPskFinish` / `wolfSPDM_ParsePskFinishRsp`
- `wolfSPDM_DeriveHandshakeKeysPsk`

## Responder (`wolfspdm/spdm_responder.h`, `WOLFSPDM_RESPONDER`)

- `wolfSPDM_RespInit` / `wolfSPDM_RespFree` / `wolfSPDM_RespGetCtxSize`
- `wolfSPDM_RespSetMode`, `wolfSPDM_RespSetPSK`, `wolfSPDM_RespSetIdentityKey`
- `wolfSPDM_RespSetTpmCallback`, `wolfSPDM_RespSetDebug`
- `wolfSPDM_RespHandleMessage` — returns `WOLFSPDM_E_FRAMING` on a non-TCG
  inbound frame; callers must drop the connection rather than fall through to
  the TPM parser
- `wolfSPDM_RespReset`, `wolfSPDM_RespIsLocked`, `wolfSPDM_RespIsSessionActive`
- `wolfSPDM_RespGetIdentityKey`

## Error utilities

- `wolfSPDM_GetErrorString`

## Common error codes

Defined in `wolfspdm/spdm_error.h`:

- `WOLFSPDM_E_INVALID_ARG`, `WOLFSPDM_E_BUFFER_SMALL`, `WOLFSPDM_E_BAD_STATE`
- `WOLFSPDM_E_VERSION_MISMATCH`, `WOLFSPDM_E_ALGO_MISMATCH`, `WOLFSPDM_E_CAPS_MISMATCH`
- `WOLFSPDM_E_CRYPTO_FAIL`, `WOLFSPDM_E_BAD_SIGNATURE`, `WOLFSPDM_E_BAD_HMAC`, `WOLFSPDM_E_DECRYPT_FAIL`
- `WOLFSPDM_E_IO_FAIL`, `WOLFSPDM_E_TIMEOUT`, `WOLFSPDM_E_PEER_ERROR`, `WOLFSPDM_E_SEQUENCE`
- `WOLFSPDM_E_NOT_CONNECTED`, `WOLFSPDM_E_ALREADY_INIT`, `WOLFSPDM_E_NO_MEMORY`
- `WOLFSPDM_E_SESSION_INVALID`, `WOLFSPDM_E_KEY_EXCHANGE`, `WOLFSPDM_E_NOT_AVAILABLE`
- `WOLFSPDM_E_FRAMING` — frame did not parse (e.g. plaintext TPM2 while SPDM mode is active)
- `WOLFSPDM_E_NOT_IMPL`, `WOLFSPDM_E_CERT_FAIL`, `WOLFSPDM_E_CERT_PARSE`
- `WOLFSPDM_E_KEY_UPDATE`, `WOLFSPDM_E_MEASUREMENT`, `WOLFSPDM_E_CHALLENGE`, `WOLFSPDM_E_CHUNK`
