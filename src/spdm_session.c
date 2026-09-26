/* spdm_session.c
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

/* Exchange helper: build -> transcript(tx) -> sendrecv -> transcript(rx) -> parse */
int wolfSPDM_ExchangeMsg(WOLFSPDM_CTX* ctx,
    wolfSPDM_BuildFn buildFn, wolfSPDM_ParseFn parseFn,
    byte* txBuf, word32 txBufSz, byte* rxBuf, word32 rxBufSz)
{
    word32 txSz = txBufSz;
    word32 rxSz = rxBufSz;
    int rc;

    rc = buildFn(ctx, txBuf, &txSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ClearExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = parseFn(ctx, rxBuf, rxSz);
    }

    return rc;
}

/* Adapter: BuildGetVersion doesn't take ctx */
static int wolfSPDM_BuildGetVersionAdapter(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz)
{
    (void)ctx;
    return wolfSPDM_BuildGetVersion(buf, bufSz);
}

int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];  /* VERSION: 4 hdr + 2 count + up to 8 entries * 2 = 22 */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetVersionAdapter,
        wolfSPDM_ParseVersion, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx)
{
    byte txBuf[WOLFSPDM_KEY_EX_TX_SZ];
    byte rxBuf[WOLFSPDM_KEY_EX_RX_SZ];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildKeyExchange(ctx, txBuf, &txSz);
#ifndef WOLFSPDM_NO_CHALLENGE
    /* KEY_EXCHANGE drops DIGESTS and CERTIFICATE from M1 */
    if (rc == WOLFSPDM_SUCCESS && ctx->m1State != WOLFSPDM_RUN_NONE) {
        rc = wolfSPDM_M1Start(ctx);
    }
#endif
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ClearExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE: SendReceive failed: %d\n", rc);
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: received %u bytes\n", rxSz);
        rc = wolfSPDM_ParseKeyExchangeRsp(ctx, rxBuf, rxSz);
    }

    return rc;
}

/* FINISH must be sent encrypted (HANDSHAKE_IN_THE_CLEAR not negotiated) */
static int wolfSPDM_FinishXfer(WOLFSPDM_CTX* ctx, const byte* finishBuf,
    word32 finishSz, byte* decBuf, word32* decSz)
{
    byte encBuf[WOLFSPDM_VENDOR_BUF_SZ];
    byte rxBuf[128];      /* Encrypted FINISH_RSP: ~94 bytes max */
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

#ifndef WOLFSPDM_NO_CHUNK
    if (wolfSPDM_ChunkOn(ctx)) {
        return wolfSPDM_ChunkExchange(ctx, 1, finishBuf, finishSz, decBuf,
            decSz);
    }
#endif

    rc = wolfSPDM_EncryptInternal(ctx, finishBuf, finishSz, encBuf, &encSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    }

    /* Check for unencrypted SPDM error response */
    if (rc == WOLFSPDM_SUCCESS &&
        rxSz >= 2 && rxBuf[0] >= 0x10 && rxBuf[0] <= 0x1F) {
    #ifdef WOLFSPDM_DEBUG
        if (rxBuf[1] == 0x7F) {
            byte errCode = (rxSz >= 3) ? rxBuf[2] : 0xFF;
            wolfSPDM_DebugPrint(ctx, "FINISH: SPDM ERROR 0x%02x\n", errCode);
        }
    #endif
        rc = WOLFSPDM_E_PEER_ERROR;
    }

    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, decSz);
    }

    return rc;
}

int wolfSPDM_Finish(WOLFSPDM_CTX* ctx)
{
    byte finishBuf[WOLFSPDM_FINISH_BUF_SZ];
    byte decBuf[64];      /* Decrypted FINISH_RSP: 4 hdr + 48 verify = 52 */
    word32 finishSz = sizeof(finishBuf);
    word32 decSz = sizeof(decBuf);
    int rc;

    /* FINISH is only valid after a successful KEY_EXCHANGE; otherwise the
     * session keys are unestablished (zero-entropy). */
    if (ctx == NULL || ctx->state < WOLFSPDM_STATE_KEY_EX) {
        return WOLFSPDM_E_BAD_STATE;
    }

    rc = wolfSPDM_BuildFinish(ctx, finishBuf, &finishSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_FinishXfer(ctx, finishBuf, finishSz, decBuf, &decSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseFinishRsp(ctx, decBuf, decSz);
    }

    /* Derive application data keys (transition from handshake to app phase) */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DeriveAppDataKeys(ctx);
    }

    /* Always zero sensitive stack buffers */
    wc_ForceZero(finishBuf, sizeof(finishBuf));
    wc_ForceZero(decBuf, sizeof(decBuf));
    return rc;
}

#if !defined(WOLFSPDM_NO_HEARTBEAT) || !defined(WOLFSPDM_NO_KEY_UPDATE)
/* Standard mode checks the responder's CAPABILITIES; TCG profiles fix them */
static int wolfSPDM_CheckSessionCap(const WOLFSPDM_CTX* ctx, word32 cap)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
#ifndef WOLFSPDM_NO_CERT
    if (!wolfSPDM_IsTcgMode(ctx) && (ctx->rspCaps & cap) == 0) {
        return WOLFSPDM_E_CAPS_MISMATCH;
    }
#else
    (void)cap;
#endif
    return WOLFSPDM_SUCCESS;
}
#endif

#ifndef WOLFSPDM_NO_HEARTBEAT
int wolfSPDM_Heartbeat(WOLFSPDM_CTX* ctx)
{
    byte txBuf[4];
    byte rxBuf[32];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_CheckSessionCap(ctx, SPDM_CAP_HBEAT_CAP);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildHeartbeat(ctx, txBuf, &txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseHeartbeatAck(ctx, rxBuf, rxSz);
    }
    return rc;
}
#endif /* !WOLFSPDM_NO_HEARTBEAT */

#ifndef WOLFSPDM_NO_KEY_UPDATE
int wolfSPDM_KeyUpdate(WOLFSPDM_CTX* ctx, int updateAll)
{
    byte txBuf[4];
    byte rxBuf[32];
    byte encBuf[64];
    byte rawBuf[64];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 encSz = sizeof(encBuf);
    word32 rawSz = sizeof(rawBuf);
    byte op;
    byte tag = 0;
    int rotated = 0;
    int rc;

    op = updateAll ? SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS :
                     SPDM_KEY_UPDATE_OP_UPDATE_KEY;

    rc = wolfSPDM_CheckSessionCap(ctx, SPDM_CAP_KEY_UPD_CAP);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz, op, &tag);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_EncryptInternal(ctx, txBuf, txSz, encBuf, &encSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rawBuf, &rawSz);
    }
    /* A rejection arrives under the current keys, an UpdateAllKeys ACK under
     * the new ones, so keys rotate only once the response proves it */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rawBuf, rawSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS && updateAll) {
            rotated = 1;
            rc = wolfSPDM_DeriveUpdatedKeys(ctx, 1);
            ctx->reqSeqNum = 0;
            ctx->rspSeqNum = 0;
            rxSz = sizeof(rxBuf);
            if (rc == WOLFSPDM_SUCCESS) {
                rc = wolfSPDM_DecryptInternal(ctx, rawBuf, rawSz, rxBuf,
                    &rxSz);
            }
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz, op, tag);
    }
    if (rc == WOLFSPDM_SUCCESS && updateAll && !rotated) {
        rc = WOLFSPDM_E_KEY_UPDATE;
    }
    if (rc == WOLFSPDM_SUCCESS && !updateAll) {
        rc = wolfSPDM_DeriveUpdatedKeys(ctx, 0);
        ctx->reqSeqNum = 0;
    }

    if (rc == WOLFSPDM_SUCCESS) {
        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz,
            SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, &tag);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz,
            SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, tag);
    }

    return rc;
}
#endif /* !WOLFSPDM_NO_KEY_UPDATE */
