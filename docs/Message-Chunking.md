# Message Chunking (CHUNK_SEND / CHUNK_GET)

SPDM 1.2 added a *Large SPDM message transfer mechanism* (DSP0274 Sec. 10.27):
when a message is larger than a peer's `DataTransferSize`, it is split into
pieces and reassembled on the other end. wolfSPDM implements **both**
directions — `CHUNK_SEND` for large outbound requests and `CHUNK_GET` for
large inbound responses — in the clear and inside secured sessions, once both
sides negotiate `CHUNK_CAP`.

This is what lets ML-DSA-87 and ML-KEM work over the wire: ML-DSA-87 signed
responses (KEY_EXCHANGE_RSP, CHALLENGE_AUTH, signed MEASUREMENTS, ~4.6-4.8 KB)
exceed common `DataTransferSize` values, and an ML-KEM KEY_EXCHANGE request
carries a multi-hundred-byte encapsulation key. See
[[Post-Quantum ML-DSA]] and [[Post-Quantum ML-KEM]].

## How it works

`src/spdm_chunk.c` implements the engine:

- `wolfSPDM_ChunkExchange` is the entry point used from the session/attest
  code (in the clear for KEY_EXCHANGE, or via `wolfSPDM_SecuredExchange` for
  in-session requests like GET_MEASUREMENTS). It sends the request in one
  shot when it fits the negotiated transfer limit, chunks it with
  `CHUNK_SEND` when it doesn't, and reassembles a chunked response with
  `CHUNK_GET` when the reply is `ERROR(LargeResponse)`.
- `wolfSPDM_ChunkSend` splits an outbound message into `CHUNK_SEND` requests.
  Only the last `CHUNK_SEND_ACK` carries the actual response (or an
  `ERROR(LargeResponse)` handing off to `CHUNK_GET` when the response itself
  needs chunking).
- `wolfSPDM_ChunkGet` reassembles a chunked response by issuing `CHUNK_GET`
  requests and validating each `CHUNK_RESPONSE`'s `Handle`, `ChunkSeqNo`, and
  `LargeMessageSize`/`ChunkSize` bounds before copying it into the caller's
  buffer.
- `ChunkSeqNo` is `u16` for SPDM < 1.4 and `u32` for >= 1.4; wolfSPDM emits
  and checks the version-appropriate width and never lets the 16-bit counter
  wrap (`WOLFSPDM_E_CHUNK` if it would).
- **Zero dynamic allocation**: chunk buffers are fixed
  `WOLFSPDM_DATA_TRANSFER_SIZE` stack arrays; the reassembled message lands in
  the caller's existing message buffer.

## Without chunking

`wolfSPDM_ClearExchange` (the non-session request path) checks the request
against the responder's negotiated `DataTransferSize` even when
`WOLFSPDM_NO_CHUNK` is defined or `CHUNK_CAP` was not negotiated: a clear
request larger than that limit is refused locally with
`WOLFSPDM_E_BUFFER_SMALL` — wolfSPDM never emits an oversized, non-conformant
message.

## Compile-time configuration

| Macro / option | Default | Effect |
|----------------|---------|--------|
| `--disable-chunking` / `WOLFSPDM_NO_CHUNK` | enabled | Compiles the engine out entirely (no `CHUNK_CAP` advertised); implied by `WOLFSPDM_NO_CERT` |
| `WOLFSPDM_DATA_TRANSFER_SIZE` | `WOLFSPDM_MAX_MSG_SIZE` | The largest single message sent or received (the chunk MTU). Must be 42 to `WOLFSPDM_MAX_MSG_SIZE`; below `WOLFSPDM_MAX_MSG_SIZE` requires chunking to be enabled (a compile-time `#error` enforces both) |

The configure summary prints `Chunking: yes|no`.

## Memory and interop notes

- **`WOLFSPDM_DATA_TRANSFER_SIZE` is the advertised MTU.** GET_CAPABILITIES
  advertises this value as `DataTransferSize`. Lowering it shrinks transport
  buffers (more round-trips under chunking); it can never exceed
  `WOLFSPDM_MAX_MSG_SIZE`, which bounds `MaxSPDMmsgSize` and every
  single-message stage buffer.
- **The TCG binding is never chunked.** `WOLFSPDM_XFER_MSG_SIZE` is
  `WOLFSPDM_MAX_MSG_SIZE` under `WOLFSPDM_TCG` (single-message buffers only)
  and `WOLFSPDM_DATA_TRANSFER_SIZE` otherwise.
- **Untrusted input.** Every `CHUNK_SEND_ACK`/`CHUNK_RESPONSE` byte is
  peer-controlled; the reassembler validates `ChunkSize` with overflow-safe
  (subtraction) bounds, echoes of `Handle`/`ChunkSeqNo`, and the per-message
  and total length before any copy.

## References

- DMTF DSP0274 1.4.0 — Sec. 10.27 (Large SPDM message transfer)
- `ERROR(LargeResponse)` = error code `0x0F`; `CHUNK_SEND` = `0x85`,
  `CHUNK_GET` = `0x86`, `CHUNK_SEND_ACK` = `0x05`, `CHUNK_RESPONSE` = `0x06`;
  `CHUNK_CAP` = `0x00020000`
