/* spdm_chunk.c
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

#ifndef WOLFSPDM_NO_CHUNK

/* CHUNK_SEND and CHUNK_RESPONSE: header(4), ChunkSeqNo (u16 + reserved before
 * 1.4, u32 from 1.4), ChunkSize(4); the first chunk adds LargeMessageSize(4) */
#define SPDM_CHUNK_HDR_SZ       12
#define SPDM_CHUNK_FIRST_HDR_SZ (SPDM_CHUNK_HDR_SZ + 4)

static word32 wolfSPDM_ChunkSeqSz(const WOLFSPDM_CTX* ctx)
{
    return (ctx->spdmVersion >= SPDM_VERSION_14) ? 4 : 2;
}

static void wolfSPDM_ChunkSetSeq(const WOLFSPDM_CTX* ctx, byte* p, word32 seq)
{
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        SPDM_Set32LE(p, seq);
    }
    else {
        SPDM_Set16LE(p, (word16)seq);
    }
}

static word32 wolfSPDM_ChunkGetSeq(const WOLFSPDM_CTX* ctx, const byte* p)
{
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        return SPDM_Get32LE(p);
    }
    return SPDM_Get16LE(p);
}

/* ChunkSeqNo is 16 bits before 1.4 and shall not wrap */
static int wolfSPDM_ChunkSeqOk(const WOLFSPDM_CTX* ctx, word32 seq)
{
    return ctx->spdmVersion >= SPDM_VERSION_14 || seq <= 0xFFFF;
}

/* A response that is an SPDM ERROR; records its code */
static int wolfSPDM_ChunkPeerError(WOLFSPDM_CTX* ctx, const byte* msg,
    word32 msgSz)
{
    if (msgSz >= 4 && msg[1] == SPDM_ERROR) {
        ctx->lastPeerErrorCode = msg[2];
        wolfSPDM_DebugPrint(ctx, "CHUNK: SPDM error 0x%02x\n", msg[2]);
        return 1;
    }
    return 0;
}

static int wolfSPDM_ChunkXfer(WOLFSPDM_CTX* ctx, int secured,
    const byte* req, word32 reqSz, byte* rsp, word32* rspSz)
{
    if (secured) {
        return wolfSPDM_SecuredXfer(ctx, req, reqSz, rsp, rspSz);
    }
    return wolfSPDM_SendReceive(ctx, req, reqSz, rsp, rspSz);
}

static void wolfSPDM_ChunkCopyOut(const byte* src, word32 srcSz, byte* rsp,
    word32 cap, word32* rspSz, int* rc)
{
    if (srcSz > cap) {
        *rc = WOLFSPDM_E_BUFFER_SMALL;
    }
    else {
        XMEMCPY(rsp, src, srcSz);
        *rspSz = srcSz;
    }
}

/* Send a request the responder cannot take in one message; the last
 * CHUNK_SEND_ACK carries the response, or an ERROR(LargeResponse) stands in
 * for it when the two would not fit together */
static int wolfSPDM_ChunkSend(WOLFSPDM_CTX* ctx, int secured, word32 limit,
    const byte* req, word32 reqSz, byte* rsp, word32* rspSz)
{
    byte msg[WOLFSPDM_DATA_TRANSFER_SIZE];
    byte ack[WOLFSPDM_DATA_TRANSFER_SIZE];
    word32 ackHdr = 4 + wolfSPDM_ChunkSeqSz(ctx);
    word32 cap = *rspSz;
    word32 sent = 0;
    word32 seq = 0;
    word32 ackSz;
    byte handle = ctx->chunkHandle++;
    int done = 0;
    int rc = WOLFSPDM_SUCCESS;

    while (rc == WOLFSPDM_SUCCESS && !done) {
        word32 hdr = SPDM_CHUNK_HDR_SZ;
        word32 take;

        if (!wolfSPDM_ChunkSeqOk(ctx, seq)) {
            rc = WOLFSPDM_E_CHUNK;
            break;
        }
        XMEMSET(msg, 0, SPDM_CHUNK_FIRST_HDR_SZ);
        msg[0] = ctx->spdmVersion;
        msg[1] = SPDM_CHUNK_SEND;
        msg[3] = handle;
        wolfSPDM_ChunkSetSeq(ctx, &msg[4], seq);
        if (seq == 0) {
            SPDM_Set32LE(&msg[hdr], reqSz);
            hdr += 4;
        }
        take = limit - hdr;
        if (take > reqSz - sent) {
            take = reqSz - sent;
        }
        SPDM_Set32LE(&msg[8], take);
        XMEMCPY(&msg[hdr], req + sent, take);
        sent += take;
        if (sent == reqSz) {
            msg[2] = SPDM_CHUNK_LAST_CHUNK;
        }

        ackSz = sizeof(ack);
        rc = wolfSPDM_ChunkXfer(ctx, secured, msg, hdr + take, ack, &ackSz);
        if (rc != WOLFSPDM_SUCCESS) {
            break;
        }

        if (ackSz >= 5 && ack[0] == ctx->spdmVersion &&
                ack[1] == SPDM_ERROR &&
                ack[2] == SPDM_ERROR_LARGE_RESPONSE && sent == reqSz) {
            /* Handed back for the CHUNK_GET that follows */
            wolfSPDM_ChunkCopyOut(ack, ackSz, rsp, cap, rspSz, &rc);
            done = 1;
        }
        else if (wolfSPDM_ChunkPeerError(ctx, ack, ackSz)) {
            rc = WOLFSPDM_E_PEER_ERROR;
        }
        else if (ackSz < ackHdr || ack[0] != ctx->spdmVersion ||
                ack[1] != SPDM_CHUNK_SEND_ACK || ack[3] != handle ||
                wolfSPDM_ChunkGetSeq(ctx, &ack[4]) != seq) {
            rc = WOLFSPDM_E_CHUNK;
        }
        else if (ack[2] & SPDM_CHUNK_EARLY_ERROR) {
            /* The responder rejected the request before the last chunk */
            if (!wolfSPDM_ChunkPeerError(ctx, ack + ackHdr, ackSz - ackHdr)) {
                rc = WOLFSPDM_E_CHUNK;
            }
            else {
                rc = WOLFSPDM_E_PEER_ERROR;
            }
        }
        else if (sent < reqSz) {
            /* Only the last acknowledgement carries a response */
            if (ackSz != ackHdr) {
                rc = WOLFSPDM_E_CHUNK;
            }
            seq++;
        }
        else {
            wolfSPDM_ChunkCopyOut(ack + ackHdr, ackSz - ackHdr, rsp, cap,
                rspSz, &rc);
            done = 1;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "CHUNK: sent %u bytes in %u chunks\n", reqSz,
            seq + 1);
    }

    wc_ForceZero(msg, sizeof(msg));
    wc_ForceZero(ack, sizeof(ack));
    return rc;
}

/* Reassemble a response the responder split after ERROR(LargeResponse) */
static int wolfSPDM_ChunkGet(WOLFSPDM_CTX* ctx, int secured, byte handle,
    byte* rsp, word32 cap, word32* rspSz)
{
    byte req[8];
    byte msg[WOLFSPDM_DATA_TRANSFER_SIZE];
    word32 reqSz = 4 + wolfSPDM_ChunkSeqSz(ctx);
    word32 msgSz;
    word32 total = 0;
    word32 off = 0;
    word32 seq = 0;
    int last = 0;
    int rc = WOLFSPDM_SUCCESS;

    /* No larger than the MaxSPDMmsgSize we advertised */
    if (cap > WOLFSPDM_MAX_MSG_SIZE) {
        cap = WOLFSPDM_MAX_MSG_SIZE;
    }
    req[0] = ctx->spdmVersion;
    req[1] = SPDM_CHUNK_GET;
    req[2] = 0x00;
    req[3] = handle;

    while (rc == WOLFSPDM_SUCCESS && !last) {
        word32 hdr = (seq == 0) ? SPDM_CHUNK_FIRST_HDR_SZ : SPDM_CHUNK_HDR_SZ;
        word32 size;

        if (!wolfSPDM_ChunkSeqOk(ctx, seq)) {
            rc = WOLFSPDM_E_CHUNK;
            break;
        }
        wolfSPDM_ChunkSetSeq(ctx, &req[4], seq);
        msgSz = sizeof(msg);
        rc = wolfSPDM_ChunkXfer(ctx, secured, req, reqSz, msg, &msgSz);
        if (rc != WOLFSPDM_SUCCESS) {
            break;
        }
        if (wolfSPDM_ChunkPeerError(ctx, msg, msgSz)) {
            rc = WOLFSPDM_E_PEER_ERROR;
            break;
        }

        if (msgSz < hdr || msg[0] != ctx->spdmVersion ||
                msg[1] != SPDM_CHUNK_RESPONSE || msg[3] != handle ||
                wolfSPDM_ChunkGetSeq(ctx, &msg[4]) != seq) {
            rc = WOLFSPDM_E_CHUNK;
            break;
        }
        if (seq == 0) {
            total = SPDM_Get32LE(&msg[SPDM_CHUNK_HDR_SZ]);
            if (total == 0) {
                rc = WOLFSPDM_E_CHUNK;
                break;
            }
            if (total > cap) {
                rc = WOLFSPDM_E_BUFFER_SMALL;
                break;
            }
        }

        /* Each CHUNK_RESPONSE is exactly its header and a non-empty chunk,
         * and the one flagged last completes the message */
        size = SPDM_Get32LE(&msg[8]);
        last = (msg[2] & SPDM_CHUNK_LAST_CHUNK) != 0;
        if (size == 0 || size != msgSz - hdr || size > total - off) {
            rc = WOLFSPDM_E_CHUNK;
            break;
        }
        XMEMCPY(rsp + off, &msg[hdr], size);
        off += size;
        if (last != (off == total)) {
            rc = WOLFSPDM_E_CHUNK;
            break;
        }
        seq++;
    }

    if (rc == WOLFSPDM_SUCCESS) {
        *rspSz = total;
        wolfSPDM_DebugPrint(ctx, "CHUNK: reassembled %u bytes in %u chunks\n",
            total, seq);
    }
    wc_ForceZero(msg, sizeof(msg));
    return rc;
}

int wolfSPDM_ChunkExchange(WOLFSPDM_CTX* ctx, int secured,
    const byte* req, word32 reqSz, byte* rsp, word32* rspSz)
{
    word32 limit;
    word32 cap;
    int rc;

    if (ctx == NULL || req == NULL || rsp == NULL || rspSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    cap = *rspSz;

    /* Each message fits both the responder's DataTransferSize and ours */
    limit = ctx->dataTransferSize;
    if (limit == 0 || limit > WOLFSPDM_DATA_TRANSFER_SIZE) {
        limit = WOLFSPDM_DATA_TRANSFER_SIZE;
    }

    if (reqSz <= limit) {
        rc = wolfSPDM_ChunkXfer(ctx, secured, req, reqSz, rsp, rspSz);
    }
    else if (ctx->maxSpdmMsgSize != 0 && reqSz > ctx->maxSpdmMsgSize) {
        rc = WOLFSPDM_E_BUFFER_SMALL;
    }
    else {
        rc = wolfSPDM_ChunkSend(ctx, secured, limit, req, reqSz, rsp, rspSz);
    }

    /* ERROR(LargeResponse): ExtendedErrorData is the chunk Handle */
    if (rc == WOLFSPDM_SUCCESS && *rspSz >= 5 &&
            rsp[0] == ctx->spdmVersion && rsp[1] == SPDM_ERROR &&
            rsp[2] == SPDM_ERROR_LARGE_RESPONSE) {
        rc = wolfSPDM_ChunkGet(ctx, secured, rsp[4], rsp, cap, rspSz);
    }
    return rc;
}

int wolfSPDM_ClearExchange(WOLFSPDM_CTX* ctx, const byte* req, word32 reqSz,
    byte* rsp, word32* rspSz)
{
    if (ctx != NULL && wolfSPDM_ChunkOn(ctx)) {
        return wolfSPDM_ChunkExchange(ctx, 0, req, reqSz, rsp, rspSz);
    }
    return wolfSPDM_SendReceive(ctx, req, reqSz, rsp, rspSz);
}

#endif /* !WOLFSPDM_NO_CHUNK */
