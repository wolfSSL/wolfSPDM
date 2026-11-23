/* spdm_tcg.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Shared TCG SPDM code used by both Nuvoton and Nations Technology TPMs. */

#include "spdm_internal.h"

#ifdef WOLFSPDM_TCG

#include <limits.h>
#include <wolfspdm/spdm_tcg.h>

/* VENDOR_DEFINED responses use the same payload layout as requests. */
static int VendorDefinedPayload(const byte* buf, word32 bufSz,
    word32* offset, word32* len)
{
    if (bufSz < 9 + WOLFSPDM_VDCODE_LEN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    *offset = 7 + buf[6]; /* Skip StandardID and VendorID. */
    if (*offset + 2 > bufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    *len = SPDM_Get16LE(buf + *offset);
    *offset += 2;
    if (*len < WOLFSPDM_VDCODE_LEN || *len > bufSz - *offset) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    return WOLFSPDM_SUCCESS;
}

/* ----- Vendor Command Helpers ----- */

/* Every locality-aware TPM2CMDn request is answered with TPM2_CMD. */
static const char* TcgResponseVdCode(const char* vdCode)
{
    char locality = vdCode[WOLFSPDM_VDCODE_LEN - 1];

    if (XMEMCMP(vdCode, WOLFSPDM_VDCODE_TPM2CMD0,
            WOLFSPDM_VDCODE_LEN - 1) == 0 &&
            locality >= '0' && locality <= '4') {
        return WOLFSPDM_VDCODE_TPM2_CMD;
    }
    return vdCode;
}

static int TcgCheckVendorResponse(WOLFSPDM_CTX* ctx, byte ver,
    const char* vdCode, const byte* buf, word32 bufSz, WOLFSPDM_VENDOR_RSP* rsp)
{
    word32 offset;
    word32 len;
    int rc;

    if (bufSz >= 4 && buf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "%s: SPDM ERROR 0x%02x 0x%02x\n",
            vdCode, buf[2], buf[3]);
        ctx->lastPeerErrorCode = buf[2];
        return WOLFSPDM_E_PEER_ERROR;
    }
    if (bufSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    /* The requests use the 16-bit length form. */
    if (buf[0] != ver || buf[1] != SPDM_VENDOR_DEFINED_RESPONSE ||
            (buf[2] & 0x80) != 0) {
        return WOLFSPDM_E_FRAMING;
    }

    rc = VendorDefinedPayload(buf, bufSz, &offset, &len);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    if (len != bufSz - offset || SPDM_Get16LE(buf + 4) != 0x0001) {
        return WOLFSPDM_E_FRAMING;
    }
    if (XMEMCMP(buf + offset, TcgResponseVdCode(vdCode),
            WOLFSPDM_VDCODE_LEN) != 0) {
        wolfSPDM_DebugPrint(ctx, "%s: unexpected VdCode '%.8s'\n",
            vdCode, buf + offset);
        return WOLFSPDM_E_PEER_ERROR;
    }
    if (rsp != NULL) {
        len -= WOLFSPDM_VDCODE_LEN;
        if (len > sizeof(rsp->payload)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }
        XMEMCPY(rsp->vdCode, buf + offset, WOLFSPDM_VDCODE_LEN);
        rsp->vdCode[WOLFSPDM_VDCODE_LEN] = '\0';
        XMEMCPY(rsp->payload, buf + offset + WOLFSPDM_VDCODE_LEN, len);
        rsp->payloadSz = len;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_VendorCmdClear(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz, WOLFSPDM_VENDOR_RSP* rsp)
{
    byte spdmMsg[WOLFSPDM_VENDOR_BUF_SZ];
    int spdmMsgSz;
    byte rxBuf[WOLFSPDM_VENDOR_RX_SZ];
    word32 rxSz = sizeof(rxBuf);
    int rc = WOLFSPDM_SUCCESS;
    byte ver;

    if (ctx == NULL || vdCode == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ver = ctx->spdmVersion ? ctx->spdmVersion : SPDM_VERSION_13;
    spdmMsgSz = wolfSPDM_BuildVendorDefined(ver, vdCode, payload,
        payloadSz, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        rc = spdmMsgSz;
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, spdmMsg, (word32)spdmMsgSz, rxBuf,
            &rxSz);
    }

    if (rc == WOLFSPDM_SUCCESS) {
        rc = TcgCheckVendorResponse(ctx, ver, vdCode, rxBuf, rxSz, rsp);
    }

    /* PSK_SET_ and PSK_CLR_ carry secrets */
    wc_ForceZero(spdmMsg, sizeof(spdmMsg));
    wc_ForceZero(rxBuf, sizeof(rxBuf));
    return rc;
}

int wolfSPDM_TCG_VendorCmdSecured(WOLFSPDM_CTX* ctx, const char* vdCode,
    const byte* payload, word32 payloadSz)
{
    byte spdmMsg[WOLFSPDM_VENDOR_BUF_SZ];
    int spdmMsgSz;
    byte decBuf[WOLFSPDM_VENDOR_BUF_SZ];
    word32 decSz = 0;
    int rc;
    byte ver;

    if (ctx == NULL || vdCode == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ver = ctx->spdmVersion ? ctx->spdmVersion : SPDM_VERSION_13;
    spdmMsgSz = wolfSPDM_BuildVendorDefined(ver, vdCode, payload,
        payloadSz, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        rc = spdmMsgSz;
    }
    else {
        decSz = sizeof(decBuf);
        rc = wolfSPDM_SecuredExchange(ctx, spdmMsg, (word32)spdmMsgSz,
            decBuf, &decSz);
    }

    if (rc == WOLFSPDM_SUCCESS) {
        rc = TcgCheckVendorResponse(ctx, ver, vdCode, decBuf, decSz, NULL);
    }

    /* Always zero sensitive stack buffers */
    wc_ForceZero(spdmMsg, sizeof(spdmMsg));
    wc_ForceZero(decBuf, sizeof(decBuf));

    return rc;
}

/* ----- TCG SPDM Binding Message Framing ----- */

int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;

    if (ctx == NULL || spdmPayload == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (outBufSz < WOLFSPDM_TCG_HEADER_SIZE ||
            spdmPayloadSz > outBufSz - WOLFSPDM_TCG_HEADER_SIZE ||
            spdmPayloadSz > (word32)(INT_MAX - WOLFSPDM_TCG_HEADER_SIZE)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    totalSz = WOLFSPDM_TCG_HEADER_SIZE + spdmPayloadSz;
    wolfSPDM_WriteTcgHeader(outBuf, WOLFSPDM_TCG_TAG_CLEAR, totalSz,
        ctx->connectionHandle, ctx->fipsIndicator);
    XMEMCPY(outBuf + WOLFSPDM_TCG_HEADER_SIZE, spdmPayload, spdmPayloadSz);

    return (int)totalSz;
}

int wolfSPDM_ParseTcgClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    WOLFSPDM_TCG_CLEAR_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 payloadSz;

    if (inBuf == NULL || spdmPayload == NULL || spdmPayloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (inBufSz < WOLFSPDM_TCG_HEADER_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_CLEAR) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize < WOLFSPDM_TCG_HEADER_SIZE || msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;
    if (*spdmPayloadSz < payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    XMEMCPY(spdmPayload, inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz);
    *spdmPayloadSz = payloadSz;

    return (int)payloadSz;
}

/* ----- SPDM Vendor Defined Message Helpers ----- */

int wolfSPDM_BuildVendorDefined(
    byte spdmVersion,
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset = 0;
    word32 i;

    if (vdCode == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    /* Fixed 8-byte code: a NUL inside it means the caller's string is short */
    for (i = 0; i < WOLFSPDM_VDCODE_LEN; i++) {
        if (vdCode[i] == '\0') {
            return WOLFSPDM_E_INVALID_ARG;
        }
    }
    if (payload == NULL && payloadSz != 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Reject a payload that would overflow the 16-bit request-length field */
    if (payloadSz > (word32)(0xFFFF - WOLFSPDM_VDCODE_LEN)) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM VENDOR_DEFINED_REQUEST format:
     * SPDMVersion(1) + reqRspCode(1) + param1(1) + param2(1) +
     * standardId(2/LE) + vendorIdLen(1) + reqLength(2/LE) +
     * vdCode(8) + payload */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + WOLFSPDM_VDCODE_LEN + payloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    outBuf[offset++] = spdmVersion;
    outBuf[offset++] = SPDM_VENDOR_DEFINED_REQUEST;
    outBuf[offset++] = 0x00;
    outBuf[offset++] = 0x00;
    /* Standard ID (0x0001 = TCG, little-endian) */
    SPDM_Set16LE(outBuf + offset, 0x0001);
    offset += 2;
    /* Vendor ID Length (0 for TCG) */
    outBuf[offset++] = 0x00;
    /* Request Length (vdCode + payload, little-endian) */
    SPDM_Set16LE(outBuf + offset, (word16)(WOLFSPDM_VDCODE_LEN + payloadSz));
    offset += 2;
    /* VdCode (8-byte ASCII) */
    XMEMCPY(outBuf + offset, vdCode, WOLFSPDM_VDCODE_LEN);
    offset += WOLFSPDM_VDCODE_LEN;
    /* Payload */
    if (payload != NULL && payloadSz > 0) {
        XMEMCPY(outBuf + offset, payload, payloadSz);
        offset += payloadSz;
    }

    return (int)offset;
}

int wolfSPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz,
    char* vdCode,
    byte* payload, word32* payloadSz)
{
    word32 offset;
    word32 reqLength;
    word32 dataLen;
    int rc;

    if (inBuf == NULL || vdCode == NULL || payload == NULL ||
        payloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = VendorDefinedPayload(inBuf, inBufSz, &offset, &reqLength);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMCPY(vdCode, inBuf + offset, WOLFSPDM_VDCODE_LEN);
    vdCode[WOLFSPDM_VDCODE_LEN] = '\0';
    offset += WOLFSPDM_VDCODE_LEN;

    dataLen = reqLength - WOLFSPDM_VDCODE_LEN;
    if (*payloadSz < dataLen) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (dataLen > 0) {
        XMEMCPY(payload, inBuf + offset, dataLen);
    }
    *payloadSz = dataLen;

    return (int)dataLen;
}

/* ----- Shared TCG SPDM Functions ----- */

static int wolfSPDM_TCG_CheckPubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    const byte* pubKeyX;
    const byte* pubKeyY;
    int rc;

    if (!ctx->flags.hasRspPubKey) {
        return WOLFSPDM_SUCCESS;
    }
    if (ctx->rspPubKeyLen != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_BAD_STATE;
    }

    rc = wolfSPDM_ExtractEccPoint(pubKey, pubKeySz, &pubKeyX, &pubKeyY);
    if (rc != WOLFSPDM_SUCCESS) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    if (XMEMCMP(pubKeyX, ctx->rspPubKey, WOLFSPDM_ECC_KEY_SIZE) != 0 ||
        XMEMCMP(pubKeyY, ctx->rspPubKey + WOLFSPDM_ECC_KEY_SIZE,
            WOLFSPDM_ECC_KEY_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Responder key mismatch\n");
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_GetPubKey(
    WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    WOLFSPDM_VENDOR_RSP rsp;
    int rc;

    if (ctx == NULL || pubKey == NULL || pubKeySz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Responders reject GET_PUBK with UnexpectedRequest before GET_VERSION */
    if (ctx->state == WOLFSPDM_STATE_INIT) {
        rc = wolfSPDM_GetVersion(ctx);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "GET_PUBK: GET_VERSION failed %d\n", rc);
            return rc;
        }
    }

    wolfSPDM_DebugPrint(ctx, "TCG: GET_PUBK\n");

    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_PUBK,
        NULL, 0, &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (XMEMCMP(rsp.vdCode, WOLFSPDM_VDCODE_GET_PUBK,
            WOLFSPDM_VDCODE_LEN) != 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Unexpected VdCode '%.8s'\n",
            rsp.vdCode);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "GET_PUBK: Got TPMT_PUBLIC (%u bytes)\n",
        rsp.payloadSz);

    rc = wolfSPDM_TCG_CheckPubKey(ctx, rsp.payload, rsp.payloadSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    if (*pubKeySz < rsp.payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    XMEMCPY(pubKey, rsp.payload, rsp.payloadSz);
    *pubKeySz = rsp.payloadSz;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_GivePubKey(
    WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    int rc;

    if (ctx == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state < WOLFSPDM_STATE_KEY_EX) {
        return WOLFSPDM_E_BAD_STATE;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: GIVE_PUB (%u bytes)\n", pubKeySz);

    rc = wolfSPDM_TCG_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_GIVE_PUB,
        pubKey, pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: SecuredExchange failed %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Success\n");
    return WOLFSPDM_SUCCESS;
}

/* ----- Shared GET_CAPABILITIES + NEGOTIATE_ALGORITHMS ----- */

#define WOLFSPDM_TCG_CAPABILITIES_RSP       0x61
#define WOLFSPDM_TCG_ALGORITHMS_RSP         0x63
#define WOLFSPDM_TCG_CAPABILITIES_RSP_SZ    20
#define WOLFSPDM_TCG_ALGORITHMS_RSP_SZ      52
#define WOLFSPDM_TCG_MIN_DATA_TRANSFER_SZ   42

#define WOLFSPDM_TCG_CAP_ENCRYPT            0x00000040UL
#define WOLFSPDM_TCG_CAP_MAC                0x00000080UL
#define WOLFSPDM_TCG_CAP_KEY_EX             0x00000200UL
#define WOLFSPDM_TCG_CAP_PSK                0x00000400UL
#define WOLFSPDM_TCG_CAP_PSK_WITH_CONTEXT   0x00000800UL
#define WOLFSPDM_TCG_CAP_PSK_MASK           0x00000C00UL
#define WOLFSPDM_TCG_CAP_PUB_KEY_ID         0x00010000UL

static int wolfSPDM_TCG_CheckResponse(WOLFSPDM_CTX* ctx, const byte* rsp,
    word32 rspSz, word32 minRspSz, byte expectedCode)
{
    int errorCode;

    if (rspSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    if (wolfSPDM_CheckError(rsp, rspSz, &errorCode)) {
        ctx->lastPeerErrorCode = (byte)errorCode;
        wolfSPDM_DebugPrint(ctx, "SPDM error: 0x%02x\n", errorCode);
        return WOLFSPDM_E_PEER_ERROR;
    }
    if (rspSz < minRspSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    if (rsp[0] != ctx->spdmVersion) {
        return WOLFSPDM_E_VERSION_MISMATCH;
    }
    if (rsp[1] != expectedCode) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_SUCCESS;
}

static int wolfSPDM_TCG_CheckCapabilities(WOLFSPDM_CTX* ctx,
    const byte* rsp, word32 rspSz, word32 capsFlags)
{
    word32 requiredFlags;
    word32 rspFlags;
    word32 dataTransferSz;
    word32 maxSpdmMsgSz;
    int rc;

    rc = wolfSPDM_TCG_CheckResponse(ctx, rsp, rspSz,
        WOLFSPDM_TCG_CAPABILITIES_RSP_SZ, WOLFSPDM_TCG_CAPABILITIES_RSP);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    if (rspSz != WOLFSPDM_TCG_CAPABILITIES_RSP_SZ) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    requiredFlags = WOLFSPDM_TCG_CAP_ENCRYPT | WOLFSPDM_TCG_CAP_MAC |
        WOLFSPDM_TCG_CAP_PUB_KEY_ID;
    if ((capsFlags & WOLFSPDM_TCG_CAP_PSK) == 0) {
        requiredFlags |= WOLFSPDM_TCG_CAP_KEY_EX;
    }

    rspFlags = SPDM_Get32LE(rsp + 8);
    dataTransferSz = SPDM_Get32LE(rsp + 12);
    maxSpdmMsgSz = SPDM_Get32LE(rsp + 16);
    if ((rspFlags & requiredFlags) != requiredFlags ||
        ((capsFlags & WOLFSPDM_TCG_CAP_PSK) != 0 &&
         (rspFlags & WOLFSPDM_TCG_CAP_PSK_MASK) != WOLFSPDM_TCG_CAP_PSK &&
         (rspFlags & WOLFSPDM_TCG_CAP_PSK_MASK) !=
             WOLFSPDM_TCG_CAP_PSK_WITH_CONTEXT) ||
        dataTransferSz < WOLFSPDM_TCG_MIN_DATA_TRANSFER_SZ ||
        maxSpdmMsgSz < dataTransferSz) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_SUCCESS;
}

static int wolfSPDM_TCG_CheckAlgorithms(WOLFSPDM_CTX* ctx,
    const byte* rsp, word32 rspSz)
{
    static const byte expectedAlgStructs[16] = {
        0x02, 0x20, 0x10, 0x00,
        0x03, 0x20, 0x02, 0x00,
        0x04, 0x20, 0x80, 0x00,
        0x05, 0x20, 0x01, 0x00
    };
    int rc;

    rc = wolfSPDM_TCG_CheckResponse(ctx, rsp, rspSz,
        WOLFSPDM_TCG_ALGORITHMS_RSP_SZ, WOLFSPDM_TCG_ALGORITHMS_RSP);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    if (rspSz != WOLFSPDM_TCG_ALGORITHMS_RSP_SZ ||
        SPDM_Get16LE(rsp + 4) != rspSz || rsp[2] != 4 || rsp[3] != 0 ||
        rsp[6] != 0 || rsp[7] != 0x02 ||
        SPDM_Get32LE(rsp + 8) != 0 ||
        SPDM_Get32LE(rsp + 12) != 0x00000080UL ||
        SPDM_Get32LE(rsp + 16) != 0x00000002UL ||
        SPDM_Get32LE(rsp + 20) != 0 || SPDM_Get32LE(rsp + 24) != 0 ||
        SPDM_Get32LE(rsp + 28) != 0 || rsp[32] != 0 || rsp[33] != 0 ||
        rsp[34] != 0 || rsp[35] != 0 ||
        XMEMCMP(rsp + 36, expectedAlgStructs,
            sizeof(expectedAlgStructs)) != 0) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TCG_GetCapabilities(WOLFSPDM_CTX* ctx, word32 capsFlags)
{
    byte capsReq[20];
    byte capsRsp[64];
    word32 capsRspSz = sizeof(capsRsp);
    word32 off = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    capsReq[off++] = ctx->spdmVersion;
    capsReq[off++] = 0xE1; /* GET_CAPABILITIES */
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* Reserved(1) + CTExponent(1) + Reserved(2) */
    capsReq[off++] = 0x00; capsReq[off++] = 0x1F;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* Flags (4 bytes LE) */
    SPDM_Set32LE(capsReq + off, capsFlags);
    off += 4;
    /* DataTransferSize */
    capsReq[off++] = 0xC0; capsReq[off++] = 0x07;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;
    /* MaxSPDMmsgSize */
    capsReq[off++] = 0xC0; capsReq[off++] = 0x07;
    capsReq[off++] = 0x00; capsReq[off++] = 0x00;

    wolfSPDM_DebugPrint(ctx, "TCG: GET_CAPABILITIES\n");
    rc = wolfSPDM_TranscriptAdd(ctx, capsReq, off);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_SendReceive(ctx, capsReq, off, capsRsp, &capsRspSz);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TCG_CheckCapabilities(ctx, capsRsp, capsRspSz,
            capsFlags);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, capsRsp, capsRspSz);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
    }
    return rc;
}

int wolfSPDM_TCG_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    /* Algorithm Set B: P-384/SHA-384/AES-256-GCM */
    byte algReq[48];
    byte algRsp[128];
    word32 algRspSz = sizeof(algRsp);
    word32 off = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    algReq[off++] = ctx->spdmVersion;
    algReq[off++] = 0xE3; /* NEGOTIATE_ALGORITHMS */
    algReq[off++] = 0x04; /* Param1: NumAlgStructs = 4 */
    algReq[off++] = 0x00;
    algReq[off++] = 0x30; algReq[off++] = 0x00; /* Length = 48 */
    algReq[off++] = 0x00; /* MeasurementSpecification */
    algReq[off++] = 0x02; /* OtherParamsSupport advertises OpaqueDataFmt1 */
    /* BaseAsymAlgo: ECDSA_ECC_NIST_P384 */
    algReq[off++] = 0x80; algReq[off++] = 0x00;
    algReq[off++] = 0x00; algReq[off++] = 0x00;
    /* BaseHashAlgo: SHA_384 */
    algReq[off++] = 0x02; algReq[off++] = 0x00;
    algReq[off++] = 0x00; algReq[off++] = 0x00;
    /* Reserved (16 bytes) */
    XMEMSET(&algReq[off], 0, 16); off += 16;
    /* AlgStruct[0]: DHE = SECP_384_R1 */
    algReq[off++] = 0x02; algReq[off++] = 0x20;
    algReq[off++] = 0x10; algReq[off++] = 0x00;
    /* AlgStruct[1]: AEAD = AES_256_GCM */
    algReq[off++] = 0x03; algReq[off++] = 0x20;
    algReq[off++] = 0x02; algReq[off++] = 0x00;
    /* AlgStruct[2]: ReqBaseAsymAlg = ECDSA_P384 */
    algReq[off++] = 0x04; algReq[off++] = 0x20;
    algReq[off++] = 0x80; algReq[off++] = 0x00;
    /* AlgStruct[3]: KeySchedule = SPDM */
    algReq[off++] = 0x05; algReq[off++] = 0x20;
    algReq[off++] = 0x01; algReq[off++] = 0x00;

    wolfSPDM_DebugPrint(ctx, "TCG: NEGOTIATE_ALGORITHMS\n");
    rc = wolfSPDM_TranscriptAdd(ctx, algReq, off);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_SendReceive(ctx, algReq, off, algRsp, &algRspSz);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TCG_CheckAlgorithms(ctx, algRsp, algRspSz);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, algRsp, algRspSz);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
    }
    return rc;
}

/* ----- TCG SPDM Connection Flow ----- */

/* GET_VERSION -> [GET_CAPS -> NEG_ALGO] -> GET_PUBK -> KEY_EXCHANGE ->
 * GIVE_PUB -> FINISH */
int wolfSPDM_ConnectTCG(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte pubKey[WOLFSPDM_PUBKEY_BUF_SZ];
    word32 pubKeySz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (!ctx->flags.hasRspPubKey ||
#ifndef WOLFSPDM_NO_CERT
            ctx->flags.rspKeyFromCert ||
#endif
            ctx->rspPubKeyLen != WOLFSPDM_ECC_POINT_SIZE) {
        wolfSPDM_DebugPrint(ctx,
            "TCG: Trusted responder public key is not configured\n");
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: Starting SPDM connection\n");

    /* Step 1: GET_VERSION */
    SPDM_CONNECT_STEP(ctx, "TCG Step 1: GET_VERSION\n",
        wolfSPDM_GetVersion(ctx));

    /* Steps 2-3: GET_CAPABILITIES + NEGOTIATE_ALGORITHMS.
     * TCG SPDM Binding mandates these before GET_PUB_KEY. Nuvoton silicon
     * uses a simplified flow that skips them, so gate at runtime by mode. */
    if (ctx->mode != WOLFSPDM_MODE_NUVOTON) {
        SPDM_CONNECT_STEP(ctx, "TCG Step 2: GET_CAPABILITIES\n",
            wolfSPDM_TCG_GetCapabilities(ctx, WOLFSPDM_TCG_CAPS_FLAGS_DEFAULT));
        SPDM_CONNECT_STEP(ctx, "TCG Step 3: NEGOTIATE_ALGORITHMS\n",
            wolfSPDM_TCG_NegotiateAlgorithms(ctx));
    }

    /* Step 4: GET_PUBK */
    wolfSPDM_DebugPrint(ctx, "TCG Step 4: GET_PUBK\n");
    pubKeySz = sizeof(pubKey);
    rc = wolfSPDM_TCG_GetPubKey(ctx, pubKey, &pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }
    ctx->state = WOLFSPDM_STATE_CERT;

    /* Compute Ct from the fetched wire object after its public point has
     * matched the separately configured responder key. */
    wolfSPDM_DebugPrint(ctx, "TCG: Computing Ct = SHA-384(GET_PUBK[%u])\n",
        pubKeySz);
    rc = wolfSPDM_Sha384Hash(ctx->certChainHash,
        pubKey, pubKeySz, NULL, 0, NULL, 0);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }
    rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash,
        WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 5: KEY_EXCHANGE */
    SPDM_CONNECT_STEP(ctx, "TCG Step 5: KEY_EXCHANGE\n",
        wolfSPDM_KeyExchange(ctx));

    /* Step 6: GIVE_PUB (secured) */
    if (ctx->flags.hasReqKeyPair && ctx->reqPubKeyTPMTLen > 0) {
        wolfSPDM_DebugPrint(ctx, "TCG Step 6: GIVE_PUB\n");
        rc = wolfSPDM_TCG_GivePubKey(ctx, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB failed: %d\n", rc);
        }
    } else {
        wolfSPDM_DebugPrint(ctx,
            "TCG Step 6: GIVE_PUB (skipped, no host key)\n");
    }

    /* Step 7: FINISH */
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "TCG Step 7: FINISH\n");
        rc = wolfSPDM_Finish(ctx);
    }
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_ResetSession(ctx);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "TCG: SPDM Session Established! "
        "SessionID=0x%08x\n", ctx->sessionId);

    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_TCG */
