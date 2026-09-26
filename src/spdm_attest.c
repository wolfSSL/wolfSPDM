/* spdm_attest.c
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

#include "spdm_internal.h"

#if !defined(WOLFSPDM_NO_MEAS) || !defined(WOLFSPDM_NO_CHALLENGE)

#define SPDM_NONCE_SZ           32
#define SPDM_REQ_CONTEXT_SZ     8

/* OpaqueLength, room for OpaqueData, RequesterContext and the signature */
#define WOLFSPDM_ATTEST_TAIL_SZ (2 + 512 + SPDM_REQ_CONTEXT_SZ + \
                                 WOLFSPDM_ECC_SIG_SIZE)

/* 1.3+ requests end with a RequesterContext the response echoes */
static word32 wolfSPDM_ReqContextSz(const WOLFSPDM_CTX* ctx)
{
    return (ctx->spdmVersion >= SPDM_VERSION_13) ? SPDM_REQ_CONTEXT_SZ : 0;
}

/* (Re)start a running transcript hash at the VCA */
static int wolfSPDM_RunStart(const WOLFSPDM_CTX* ctx, wc_Sha384* sha,
    byte* state)
{
    int rc;

    if (*state != WOLFSPDM_RUN_NONE) {
        wc_Sha384Free(sha);
        *state = WOLFSPDM_RUN_NONE;
    }
    rc = wc_InitSha384(sha);
    if (rc == 0) {
        *state = WOLFSPDM_RUN_LIVE;
        rc = wc_Sha384Update(sha, ctx->transcript, ctx->vcaLen);
    }
    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

static int wolfSPDM_RunAdd(wc_Sha384* sha, const byte* req, word32 reqSz,
    const byte* rsp, word32 rspSz)
{
    int rc;

    rc = wc_Sha384Update(sha, req, reqSz);
    if (rc == 0) {
        rc = wc_Sha384Update(sha, rsp, rspSz);
    }
    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

/* Close the run with this exchange (response up to its signature) and verify
 * the responder signature over the SPDM signing digest */
static int wolfSPDM_RunVerify(WOLFSPDM_CTX* ctx, wc_Sha384* sha, byte* state,
    const char* label, word32 labelSz, const byte* req, word32 reqSz,
    const byte* rsp, word32 sigOff)
{
    byte digest[WOLFSPDM_HASH_SIZE];
    byte signHash[WOLFSPDM_HASH_SIZE];
    int rc;

    rc = wolfSPDM_RunAdd(sha, req, reqSz, rsp, sigOff);
    if (rc == WOLFSPDM_SUCCESS && wc_Sha384Final(sha, digest) != 0) {
        rc = WOLFSPDM_E_CRYPTO_FAIL;
    }
    wc_Sha384Free(sha);
    *state = WOLFSPDM_RUN_NONE;

    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion, label, labelSz,
            digest, signHash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifySignature(ctx, signHash, WOLFSPDM_HASH_SIZE,
            rsp + sigOff, WOLFSPDM_ECC_SIG_SIZE);
    }
    return rc;
}

/* OpaqueLength, OpaqueData, the RequesterContext echo, then exactly sigSz
 * signature bytes; returns 1 when well formed */
static int wolfSPDM_ParseTail(const WOLFSPDM_CTX* ctx, const byte* req,
    word32 reqSz, const byte* buf, word32 bufSz, word32 off, word32 sigSz,
    word32* sigOff)
{
    word32 ctxSz = wolfSPDM_ReqContextSz(ctx);

    if (off + 2 > bufSz) {
        return 0;
    }
    off += 2 + (word32)SPDM_Get16LE(&buf[off]);
    if (off > bufSz || bufSz - off != ctxSz + sigSz || reqSz < ctxSz ||
            XMEMCMP(&buf[off], req + reqSz - ctxSz, ctxSz) != 0) {
        return 0;
    }
    *sigOff = off + ctxSz;
    return 1;
}

void wolfSPDM_AttestFree(WOLFSPDM_CTX* ctx)
{
#ifndef WOLFSPDM_NO_MEAS
    if (ctx->l1l2State != WOLFSPDM_RUN_NONE) {
        wc_Sha384Free(&ctx->l1l2Hash);
        ctx->l1l2State = WOLFSPDM_RUN_NONE;
    }
#endif
#ifndef WOLFSPDM_NO_CHALLENGE
    if (ctx->m1State != WOLFSPDM_RUN_NONE) {
        wc_Sha384Free(&ctx->m1Hash);
        ctx->m1State = WOLFSPDM_RUN_NONE;
    }
#endif
}

/* ----- GET_MEASUREMENTS ----- */

#ifndef WOLFSPDM_NO_MEAS

#define WOLFSPDM_MEAS_RSP_SZ    (8 + WOLFSPDM_MAX_MEAS_RECORD + \
                                 SPDM_NONCE_SZ + WOLFSPDM_ATTEST_TAIL_SZ)

int wolfSPDM_BuildGetMeasurements(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz, byte operation, int requestSig)
{
    word32 ctxSz;
    word32 sz;
    int rc = WOLFSPDM_SUCCESS;

    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctxSz = wolfSPDM_ReqContextSz(ctx);
    sz = 4 + (requestSig ? (word32)SPDM_NONCE_SZ + 1 : 0) + ctxSz;
    if (*bufSz < sz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_GET_MEASUREMENTS;
    buf[2] = requestSig ? SPDM_MEAS_REQUEST_SIG_BIT : 0x00;
    buf[3] = operation;
    if (requestSig) {
        rc = wolfSPDM_GetRandom(ctx, &buf[4], SPDM_NONCE_SZ);
        buf[4 + SPDM_NONCE_SZ] = ctx->currentSlotId;
    }
    if (rc == WOLFSPDM_SUCCESS && ctxSz > 0) {
        rc = wolfSPDM_GetRandom(ctx, &buf[sz - ctxSz], ctxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        *bufSz = sz;
    }
    return rc;
}

int wolfSPDM_ParseMeasurements(WOLFSPDM_CTX* ctx, const byte* req,
    word32 reqSz, const byte* buf, word32 bufSz, word32* sigOff)
{
    word32 recordEnd;
    word32 off = 8;
    word32 i;
    int signedReq;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 8);
    if (req == NULL || reqSz < 4 || sigOff == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_MEASUREMENTS,
        WOLFSPDM_E_MEASUREMENT);

    signedReq = (req[2] & SPDM_MEAS_REQUEST_SIG_BIT) != 0;
    recordEnd = 8 + ((word32)buf[5] | ((word32)buf[6] << 8) |
        ((word32)buf[7] << 16));
    if (buf[0] != ctx->spdmVersion || recordEnd > bufSz ||
            (signedReq && (buf[3] & 0x0F) != ctx->currentSlotId)) {
        return WOLFSPDM_E_MEASUREMENT;
    }

    /* NumberOfBlocks blocks must exactly fill MeasurementRecordLength */
    for (i = 0; i < buf[4] && off + WOLFSPDM_MEAS_BLOCK_HDR_SZ <= recordEnd;
            i++) {
        off += WOLFSPDM_MEAS_BLOCK_HDR_SZ + SPDM_Get16LE(&buf[off + 2]);
    }
    if (i != buf[4] || off != recordEnd ||
            !wolfSPDM_ParseTail(ctx, req, reqSz, buf, bufSz,
                recordEnd + SPDM_NONCE_SZ,
                signedReq ? WOLFSPDM_ECC_SIG_SIZE : 0, sigOff)) {
        return WOLFSPDM_E_MEASUREMENT;
    }
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature)
{
    byte req[4 + SPDM_NONCE_SZ + 1 + SPDM_REQ_CONTEXT_SZ];
    byte rsp[WOLFSPDM_MEAS_RSP_SZ];
    word32 reqSz = sizeof(req);
    word32 rspSz = sizeof(rsp);
    word32 sigOff = 0;
    word32 recLen = 0;
    word32 cap = SPDM_CAP_MEAS_CAP_SIG;
    int rc = WOLFSPDM_SUCCESS;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
    if (!requestSignature) {
        cap |= SPDM_CAP_MEAS_CAP_NO_SIG;
    }
    if ((ctx->rspCaps & cap) == 0) {
        return WOLFSPDM_E_CAPS_MISMATCH;
    }
    ctx->measBlockCount = 0;
    ctx->measRecordLen = 0;

    /* L1/L2 spans consecutive GET_MEASUREMENTS; any other request resets */
    if (ctx->l1l2State != WOLFSPDM_RUN_OPEN) {
        rc = wolfSPDM_RunStart(ctx, &ctx->l1l2Hash, &ctx->l1l2State);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildGetMeasurements(ctx, req, &reqSz, measOperation,
            requestSignature);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SecuredExchange(ctx, req, reqSz, rsp, &rspSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseMeasurements(ctx, req, reqSz, rsp, rspSz, &sigOff);
    }
    if (rc == WOLFSPDM_SUCCESS && requestSignature) {
        rc = wolfSPDM_RunVerify(ctx, &ctx->l1l2Hash, &ctx->l1l2State,
            "responder-measurements signing", 30, req, reqSz, rsp, sigOff);
    }
    else if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_RunAdd(&ctx->l1l2Hash, req, reqSz, rsp, rspSz);
        if (rc == WOLFSPDM_SUCCESS) {
            ctx->l1l2State = WOLFSPDM_RUN_OPEN;
        }
    }

    if (rc == WOLFSPDM_SUCCESS) {
        recLen = (word32)rsp[5] | ((word32)rsp[6] << 8) |
            ((word32)rsp[7] << 16);
        if (recLen > sizeof(ctx->measRecord)) {
            rc = WOLFSPDM_E_BUFFER_SMALL;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(ctx->measRecord, &rsp[8], recLen);
        ctx->measRecordLen = recLen;
        ctx->measBlockCount = rsp[4];
    }
    return rc;
}

int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx)
{
    return (ctx == NULL) ? 0 : (int)ctx->measBlockCount;
}

int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz)
{
    const byte* blk;
    word32 off = 0;
    word32 len;
    int i;

    if (ctx == NULL || measIndex == NULL || measType == NULL ||
            value == NULL || valueSz == NULL || blockIdx < 0 ||
            blockIdx >= (int)ctx->measBlockCount) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* The stored record was validated block by block when received */
    for (i = 0; i < blockIdx; i++) {
        off += WOLFSPDM_MEAS_BLOCK_HDR_SZ +
            SPDM_Get16LE(&ctx->measRecord[off + 2]);
    }
    blk = &ctx->measRecord[off];
    *measIndex = blk[0];
    *measType = 0;
    len = SPDM_Get16LE(&blk[2]);
    if (blk[1] == SPDM_MEAS_SPEC_DMTF && len >= 3 &&
            SPDM_Get16LE(&blk[WOLFSPDM_MEAS_BLOCK_HDR_SZ + 1]) <= len - 3) {
        /* DMTF value: Type(1) + ValueSize(2) + Value */
        *measType = blk[WOLFSPDM_MEAS_BLOCK_HDR_SZ];
        len = SPDM_Get16LE(&blk[WOLFSPDM_MEAS_BLOCK_HDR_SZ + 1]);
        blk += 3;
    }
    blk += WOLFSPDM_MEAS_BLOCK_HDR_SZ;

    if (len > *valueSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    XMEMCPY(value, blk, len);
    *valueSz = len;
    return WOLFSPDM_SUCCESS;
}

#endif /* !WOLFSPDM_NO_MEAS */

/* ----- CHALLENGE ----- */

#ifndef WOLFSPDM_NO_CHALLENGE

#define WOLFSPDM_CHAL_RSP_SZ    (4 + 2 * WOLFSPDM_HASH_SIZE + SPDM_NONCE_SZ + \
                                 WOLFSPDM_ATTEST_TAIL_SZ)

int wolfSPDM_M1Start(WOLFSPDM_CTX* ctx)
{
    return wolfSPDM_RunStart(ctx, &ctx->m1Hash, &ctx->m1State);
}

int wolfSPDM_M1Add(WOLFSPDM_CTX* ctx, const byte* req, word32 reqSz,
    const byte* rsp, word32 rspSz)
{
    if (ctx->m1State == WOLFSPDM_RUN_NONE) {
        return WOLFSPDM_SUCCESS;
    }
    return wolfSPDM_RunAdd(&ctx->m1Hash, req, reqSz, rsp, rspSz);
}

int wolfSPDM_BuildChallenge(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, byte measHashType)
{
    word32 sz;
    int rc;

    if (ctx == NULL || buf == NULL || bufSz == NULL || slotId < 0 ||
            slotId > 7) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    sz = 4 + SPDM_NONCE_SZ + wolfSPDM_ReqContextSz(ctx);
    if (*bufSz < sz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_CHALLENGE;
    buf[2] = (byte)slotId;
    buf[3] = measHashType;
    /* Nonce, then the 1.3+ RequesterContext */
    rc = wolfSPDM_GetRandom(ctx, &buf[4], sz - 4);
    if (rc == WOLFSPDM_SUCCESS) {
        *bufSz = sz;
    }
    return rc;
}

int wolfSPDM_ParseChallengeAuth(WOLFSPDM_CTX* ctx, const byte* req,
    word32 reqSz, const byte* buf, word32 bufSz, word32* sigOff)
{
    word32 off = 4 + WOLFSPDM_HASH_SIZE + SPDM_NONCE_SZ;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    if (req == NULL || reqSz < 4 || sigOff == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CHALLENGE_AUTH,
        WOLFSPDM_E_CHALLENGE);

    if (req[3] != SPDM_MEAS_SUMMARY_HASH_NONE) {
        off += WOLFSPDM_HASH_SIZE;
    }
    if (buf[0] != ctx->spdmVersion || (buf[2] & 0x0F) != req[2] ||
            bufSz < off ||
            XMEMCMP(&buf[4], ctx->certChainHash, WOLFSPDM_HASH_SIZE) != 0 ||
            !wolfSPDM_ParseTail(ctx, req, reqSz, buf, bufSz, off,
                WOLFSPDM_ECC_SIG_SIZE, sigOff)) {
        return WOLFSPDM_E_CHALLENGE;
    }
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType)
{
    byte req[4 + SPDM_NONCE_SZ + SPDM_REQ_CONTEXT_SZ];
    byte rsp[WOLFSPDM_CHAL_RSP_SZ];
    word32 reqSz = sizeof(req);
    word32 rspSz = sizeof(rsp);
    word32 sigOff = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    /* M1 covers the chain fetched for this slot */
    if (ctx->state < WOLFSPDM_STATE_CERT ||
            ctx->state == WOLFSPDM_STATE_ERROR ||
            ctx->m1State == WOLFSPDM_RUN_NONE ||
            slotId != (int)ctx->currentSlotId) {
        return WOLFSPDM_E_BAD_STATE;
    }
    if ((ctx->rspCaps & SPDM_CAP_CHAL_CAP) == 0) {
        return WOLFSPDM_E_CAPS_MISMATCH;
    }

    rc = wolfSPDM_ValidateCertChain(ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildChallenge(ctx, req, &reqSz, slotId, measHashType);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ClearExchange(ctx, req, reqSz, rsp, &rspSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseChallengeAuth(ctx, req, reqSz, rsp, rspSz,
            &sigOff);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_RunVerify(ctx, &ctx->m1Hash, &ctx->m1State,
            "responder-challenge_auth signing", 32, req, reqSz, rsp, sigOff);
    }
    /* After CHALLENGE_AUTH the next M1 is VCA plus its own messages */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_M1Start(ctx);
    }
    return rc;
}

#endif /* !WOLFSPDM_NO_CHALLENGE */

#endif /* !WOLFSPDM_NO_MEAS || !WOLFSPDM_NO_CHALLENGE */
