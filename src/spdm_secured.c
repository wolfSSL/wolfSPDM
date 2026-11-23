/* spdm_secured.c
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

#define MCTP_MESSAGE_TYPE_SECURED_SPDM  0x06
#define MCTP_MESSAGE_TYPE_MASK          0x7F

/*
 * SPDM Secured Message Format (DSP0277):
 *
 * MCTP transport:
 *   Header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
 *   IV XOR: Leftmost 2 bytes (bytes 0-1) with 2-byte LE sequence number (DSP0277)
 *
 * Nuvoton TCG binding (Rev 1.11):
 *   Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
 *   IV XOR: Leftmost 8 bytes (bytes 0-7) with 8-byte LE sequence number (DSP0277 1.2)
 *   Plaintext: AppDataLength(2 LE) + SPDM msg + RandomData (pad to 16)
 *
 * Full message: Header || Ciphertext || Tag (16)
 */

/* appMsg: plain is an MCTP application message carrying its own type byte */
static int wolfSPDM_EncryptRecord(WOLFSPDM_CTX* ctx, int appMsg,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];  /* Up to 14 bytes for TCG format */
    byte plainBuf[WOLFSPDM_XFER_MSG_SIZE + 2 + 16]; /* AppDataLength, pad */
    byte tag[WOLFSPDM_AEAD_TAG_SIZE];
    word32 plainBufSz;
    word32 recordLen;
    word32 hdrSz;
    word32 aadSz;
    int aesInit = 0;
    int rc;

    if (ctx == NULL || plain == NULL || enc == NULL || encSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (plainSz > WOLFSPDM_XFER_MSG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

#ifdef WOLFSPDM_TCG
    if (wolfSPDM_IsTcgMode(ctx)) {
        /* Nuvoton TCG binding format per Rev 1.11 spec page 25:
         * Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
         * IV XOR: Leftmost 8 bytes (bytes 0-7) with 8-byte LE sequence number
         */
        word32 unpadded = 2 + plainSz;
        word32 padLen = (16 - (unpadded % 16)) % 16;
        word32 encPayloadSz = unpadded + padLen;

        plainBufSz = encPayloadSz;
        /* Length field = ciphertext + MAC
         * (per Nuvoton spec page 25: Length=160=144+16) */
        recordLen = encPayloadSz + WOLFSPDM_AEAD_TAG_SIZE;
        hdrSz = 14;  /* 4 + 8 + 2 (TCG binding format) */

        if (recordLen > 0xFFFF ||
                *encSz < hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLength(2 LE) || SPDM message || RandomData */
        SPDM_Set16LE(plainBuf, (word16)plainSz);
        XMEMCPY(&plainBuf[2], plain, plainSz);
        /* Fill RandomData with actual random bytes per Nuvoton spec */
        if (padLen > 0) {
            rc = wolfSPDM_GetRandom(ctx, &plainBuf[unpadded], padLen);
            if (rc != WOLFSPDM_SUCCESS) {
                wc_ForceZero(plainBuf, sizeof(plainBuf));
                return rc;
            }
        }

        /* Build header/AAD: SessionID(4 LE) + SeqNum(8 LE) +
         * Length(2 LE) = 14 bytes */
        SPDM_Set32LE(&enc[0], ctx->sessionId);
        SPDM_Set64LE(&enc[4], ctx->reqSeqNum);
        SPDM_Set16LE(&enc[12], (word16)recordLen);

        aadSz = 14;
        XMEMCPY(aad, enc, aadSz);
    } else
#endif
    {
#ifdef WOLFSPDM_NO_MCTP
        (void)appMsg;
        return WOLFSPDM_E_NOT_AVAILABLE;
#else
        /* MCTP format (per DSP0277):
         * Plaintext: AppDataLen(2 LE) + MCTP header(0x05) + SPDM message
         * Header: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
         * AAD = Header
         */
        word32 appDataLen = appMsg ? plainSz : 1 + plainSz;
        word32 encDataLen = 2 + appDataLen;

        plainBufSz = encDataLen;
        recordLen = encDataLen + WOLFSPDM_AEAD_TAG_SIZE;
        hdrSz = 8;  /* 4 + 2 + 2 */

        /* The record Length is a 16-bit field */
        if (recordLen > 0xFFFF || *encSz < hdrSz + recordLen) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLen(2 LE) || MCTP header(0x05) || SPDM msg */
        SPDM_Set16LE(plainBuf, (word16)appDataLen);
        if (appMsg) {
            XMEMCPY(&plainBuf[2], plain, plainSz);
        } else {
            plainBuf[2] = MCTP_MESSAGE_TYPE_SPDM;
            XMEMCPY(&plainBuf[3], plain, plainSz);
        }

        /* Build header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) */
        SPDM_Set32LE(&enc[0], ctx->sessionId);
        /* DSP0276 1.3 4.1: the wire carries the low 16 bits and both ends
         * track the upper 48, so the DSP0277 IV uses the full counter */
        SPDM_Set16LE(&enc[4], (word16)ctx->reqSeqNum);
        SPDM_Set16LE(&enc[6], (word16)recordLen);

        aadSz = 8;
        XMEMCPY(aad, enc, aadSz);
#endif
    }

    /* Build IV: BaseIV XOR sequence number (DSP0277) */
    wolfSPDM_BuildIV(iv, ctx->reqDataIv, ctx->reqSeqNum);

    /* AES-GCM encrypt — cascade with single cleanup */
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        aesInit = 1;
        rc = wc_AesGcmSetKey(&aes, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    }
    if (rc == 0) {
        rc = wc_AesGcmEncrypt(&aes, &enc[hdrSz], plainBuf, plainBufSz,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
    }
    wc_ForceZero(iv, sizeof(iv));
    if (aesInit) {
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
    }

    if (rc == 0) {
        XMEMCPY(&enc[hdrSz + plainBufSz], tag, WOLFSPDM_AEAD_TAG_SIZE);
        *encSz = hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE;
        ctx->reqSeqNum++;
#ifndef WOLFSPDM_NO_MEAS
        /* Only back-to-back GET_MEASUREMENTS extend L1/L2 */
        if (!appMsg && ctx->l1l2State == WOLFSPDM_RUN_OPEN) {
            ctx->l1l2State = WOLFSPDM_RUN_LIVE;
        }
#endif
        wolfSPDM_DebugPrint(ctx, "Encrypted %u bytes -> %u bytes (seq=%llu)\n",
            plainSz, *encSz, (unsigned long long)(ctx->reqSeqNum - 1));
    }

    wc_ForceZero(plainBuf, sizeof(plainBuf));
    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    return wolfSPDM_EncryptRecord(ctx, 0, plain, plainSz, enc, encSz);
}

/* appMsg: return the MCTP application message with its type byte */
static int wolfSPDM_DecryptRecord(WOLFSPDM_CTX* ctx, int appMsg,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];
    byte decrypted[WOLFSPDM_XFER_MSG_SIZE + WOLFSPDM_SECURED_PAD];
    const byte* ciphertext;
    const byte* tag;
    word32 cipherLen;
    word16 appDataLen;
    word32 hdrSz;
    word32 aadSz;
    int aesInit = 0;
    int ret;
    int rc;

    if (ctx == NULL || enc == NULL || plain == NULL || plainSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* ----- Transport-specific header parsing ----- */

#ifdef WOLFSPDM_TCG
    if (wolfSPDM_IsTcgMode(ctx)) {
        word64 rspSeqNum64;
        word32 rspSessionId;
        word16 rspLen;
        hdrSz = 14;
        aadSz = 14;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE)
            return WOLFSPDM_E_BUFFER_SMALL;

        rspSessionId = SPDM_Get32LE(&enc[0]);
        rspSeqNum64 = SPDM_Get64LE(&enc[4]);
        rspLen = SPDM_Get16LE(&enc[12]);

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }
        if (rspSeqNum64 != ctx->rspSeqNum) {
            wolfSPDM_DebugPrint(ctx, "Seq mismatch: %llu != %llu\n",
                (unsigned long long)rspSeqNum64,
                (unsigned long long)ctx->rspSeqNum);
            return WOLFSPDM_E_SEQUENCE;
        }
        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz != hdrSz + rspLen)
            return WOLFSPDM_E_BUFFER_SMALL;

        cipherLen = (word32)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        if (cipherLen > sizeof(decrypted))
            return WOLFSPDM_E_BUFFER_SMALL;

        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;
        XMEMCPY(aad, enc, aadSz);
        wolfSPDM_BuildIV(iv, ctx->rspDataIv, rspSeqNum64);
    } else
#endif
    {
#ifdef WOLFSPDM_NO_MCTP
        (void)appMsg;
        return WOLFSPDM_E_NOT_AVAILABLE;
#else
        word32 rspSessionId;
        word16 rspSeqNum, rspLen;
        hdrSz = 8;
        aadSz = 8;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE)
            return WOLFSPDM_E_BUFFER_SMALL;

        rspSessionId = SPDM_Get32LE(&enc[0]);
        rspSeqNum = SPDM_Get16LE(&enc[4]);
        rspLen = SPDM_Get16LE(&enc[6]);

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }
        /* Partial sequence number against the tracked 64-bit counter */
        if (rspSeqNum != (word16)ctx->rspSeqNum) {
            wolfSPDM_DebugPrint(ctx, "Seq mismatch: %u != %llu\n",
                rspSeqNum, (unsigned long long)ctx->rspSeqNum);
            return WOLFSPDM_E_SEQUENCE;
        }
        /* DSP0277: Length covers exactly the rest of the record */
        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz != (word32)(hdrSz + rspLen))
            return WOLFSPDM_E_BUFFER_SMALL;

        cipherLen = (word32)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        if (cipherLen > sizeof(decrypted))
            return WOLFSPDM_E_BUFFER_SMALL;

        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;
        XMEMCPY(aad, enc, aadSz);
        wolfSPDM_BuildIV(iv, ctx->rspDataIv, ctx->rspSeqNum);
#endif
    }

    /* ----- AES-GCM decrypt (shared for both transports) ----- */

    ret = WOLFSPDM_E_CRYPTO_FAIL;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        aesInit = 1;
        rc = wc_AesGcmSetKey(&aes, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    }
    if (rc == 0) {
        rc = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, cipherLen,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE,
            aad, aadSz);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "AES-GCM decrypt failed: %d\n", rc);
            ret = WOLFSPDM_E_DECRYPT_FAIL;
        }
        else {
            /* Record is authenticated (tag verified) so the peer has advanced;
             * advance now. A forged record fails the tag and never reaches
             * here, and a later payload parse error stays fatal without
             * desyncing the sequence. */
            ctx->rspSeqNum++;
        }
    }
    wc_ForceZero(iv, sizeof(iv));
    if (aesInit) {
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
    }

    /* ----- Parse decrypted payload ----- */

    if (rc == 0 && cipherLen < 2) {
        /* authenticated record too short to hold the application length */
        ret = WOLFSPDM_E_BUFFER_SMALL;
    }
    else if (rc == 0) {
        appDataLen = SPDM_Get16LE(decrypted);
#ifdef WOLFSPDM_TCG
        if (wolfSPDM_IsTcgMode(ctx)) {
            /* TCG binding: AppDataLen(2) || SPDM msg || RandomData */
            if (cipherLen < (word32)(2 + appDataLen) ||
                *plainSz < appDataLen) {
                ret = WOLFSPDM_E_BUFFER_SMALL;
            } else {
                XMEMCPY(plain, &decrypted[2], appDataLen);
                *plainSz = appDataLen;
                ret = WOLFSPDM_SUCCESS;
            }
        } else
#endif
        {
#ifdef WOLFSPDM_NO_MCTP
            ret = WOLFSPDM_E_NOT_AVAILABLE;
#else
            /* MCTP: AppDataLen(2) || MCTP(1) || SPDM msg */
            word32 typeSz = appMsg ? 0 : 1;
            if (appDataLen < 1 || cipherLen < (word32)(2 + appDataLen) ||
                *plainSz < (word32)(appDataLen - typeSz)) {
                ret = WOLFSPDM_E_BUFFER_SMALL;
            } else if (!appMsg && decrypted[2] != MCTP_MESSAGE_TYPE_SPDM) {
                ret = WOLFSPDM_E_DECRYPT_FAIL;
            } else if (appMsg && (decrypted[2] & MCTP_MESSAGE_TYPE_MASK) ==
                    MCTP_MESSAGE_TYPE_SECURED_SPDM) {
                ret = WOLFSPDM_E_DECRYPT_FAIL;
            } else {
                XMEMCPY(plain, &decrypted[2 + typeSz], appDataLen - typeSz);
                *plainSz = appDataLen - typeSz;
                ret = WOLFSPDM_SUCCESS;
            }
#endif
        }
    }

    if (ret == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "Decrypted %u bytes -> %u bytes\n",
            encSz, *plainSz);
    }

    wc_ForceZero(decrypted, sizeof(decrypted));
    return ret;
}

/* DSP0274 section 11: an authenticated DecryptError ends the session */
static void wolfSPDM_CheckSessionEnd(WOLFSPDM_CTX* ctx, const byte* msg,
    word32 msgSz)
{
    int errorCode = 0;

    if (wolfSPDM_CheckError(msg, msgSz, &errorCode) &&
            errorCode == SPDM_ERROR_DECRYPT_ERROR) {
        wolfSPDM_ResetSession(ctx);
        ctx->state = WOLFSPDM_STATE_ERROR;
    }
}

int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    int rc = wolfSPDM_DecryptRecord(ctx, 0, enc, encSz, plain, plainSz);

    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_CheckSessionEnd(ctx, plain, *plainSz);
    }
    return rc;
}

#ifdef WOLFSPDM_RESPONDER
/* The responder retires its sessions through its own reset */
int wolfSPDM_DecryptRequest(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    return wolfSPDM_DecryptRecord(ctx, 0, enc, encSz, plain, plainSz);
}
#endif

/* Returns 1 for a cleartext SPDM reply, which only an ERROR should be.
 * A record starts with our session ID, whose requester half keeps its first
 * byte out of 0x10-0x1F (wolfSPDM_SetRequesterSessionId). */
int wolfSPDM_ClearPeerError(WOLFSPDM_CTX* ctx, const byte* rx, word32 rxSz)
{
    if (rxSz < 2 || rx[0] < 0x10 || rx[0] > 0x1F ||
            (rxSz >= 4 && SPDM_Get32LE(rx) == ctx->sessionId)) {
        return 0;
    }
    if (rxSz >= 4 && rx[1] == SPDM_ERROR) {
        ctx->lastPeerErrorCode = rx[2];
        wolfSPDM_DebugPrint(ctx, "SPDM ERROR 0x%02x in the clear\n", rx[2]);
    }
    return 1;
}

int wolfSPDM_SecuredXfer(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    byte encBuf[WOLFSPDM_XFER_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    byte rxBuf[WOLFSPDM_XFER_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_EncryptInternal(ctx, cmdPlain, cmdSz, encBuf, &encSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS && wolfSPDM_ClearPeerError(ctx, rxBuf, rxSz)) {
        rc = WOLFSPDM_E_PEER_ERROR;
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, rspPlain, rspSz);
    }

    return rc;
}

int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    if (ctx == NULL || cmdPlain == NULL || rspPlain == NULL || rspSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    /* Session keys exist from KEY_EXCHANGE_RSP on, but only the TCG
     * binding sends a request (GIVE_PUB) under handshake keys */
    if (ctx->state < WOLFSPDM_STATE_KEY_EX ||
            ctx->state == WOLFSPDM_STATE_ERROR || ctx->sessionId == 0 ||
            (ctx->state == WOLFSPDM_STATE_KEY_EX &&
             !wolfSPDM_IsTcgMode(ctx))) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
#ifndef WOLFSPDM_NO_CHUNK
    if (wolfSPDM_ChunkOn(ctx)) {
        return wolfSPDM_ChunkExchange(ctx, 1, cmdPlain, cmdSz, rspPlain,
            rspSz);
    }
#endif

    return wolfSPDM_SecuredXfer(ctx, cmdPlain, cmdSz, rspPlain, rspSz);
}


#ifndef WOLFSPDM_NO_APP_DATA
int wolfSPDM_EncryptMessage(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz, byte* enc, word32* encSz)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
    return wolfSPDM_EncryptRecord(ctx, 0, plain, plainSz, enc, encSz);
}

int wolfSPDM_DecryptMessage(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz, byte* plain, word32* plainSz)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
    return wolfSPDM_DecryptRecord(ctx, 0, enc, encSz, plain, plainSz);
}

static int wolfSPDM_AppDataReady(const WOLFSPDM_CTX* ctx)
{
    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
    /* The TCG binding only carries SPDM request/response pairs */
    if (wolfSPDM_IsTcgMode(ctx)) {
        return WOLFSPDM_E_NOT_AVAILABLE;
    }
    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz)
{
    byte encBuf[WOLFSPDM_XFER_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    word32 encSz = sizeof(encBuf);
    word32 rxSz = 0;
    int rc;

    if (ctx == NULL || data == NULL || dataSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    /* SPDM requests have a separate API. DSP0276 forbids nesting records. */
    if (data[0] == MCTP_MESSAGE_TYPE_SPDM ||
            (data[0] & MCTP_MESSAGE_TYPE_MASK) ==
                MCTP_MESSAGE_TYPE_SECURED_SPDM) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wolfSPDM_AppDataReady(ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_EncryptRecord(ctx, 1, data, dataSz, encBuf, &encSz);
    }
    if (rc == WOLFSPDM_SUCCESS &&
            ctx->ioCb(ctx, encBuf, encSz, NULL, &rxSz, ctx->ioUserCtx) != 0) {
        rc = WOLFSPDM_E_IO_FAIL;
    }

    return rc;
}

int wolfSPDM_ReceiveData(WOLFSPDM_CTX* ctx, byte* data, word32* dataSz)
{
    byte rxBuf[WOLFSPDM_XFER_MSG_SIZE + WOLFSPDM_AEAD_OVERHEAD];
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL || data == NULL || dataSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wolfSPDM_AppDataReady(ctx);
    if (rc == WOLFSPDM_SUCCESS &&
            (ctx->ioCb(ctx, NULL, 0, rxBuf, &rxSz, ctx->ioUserCtx) != 0 ||
             rxSz > sizeof(rxBuf))) {
        rc = WOLFSPDM_E_IO_FAIL;
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptRecord(ctx, 1, rxBuf, rxSz, data, dataSz);
    }
    /* The responder answers undeliverable application data in SPDM */
    if (rc == WOLFSPDM_SUCCESS && data[0] == MCTP_MESSAGE_TYPE_SPDM) {
        if (*dataSz >= 4 && data[2] == SPDM_ERROR) {
            ctx->lastPeerErrorCode = data[3];
        }
        wolfSPDM_CheckSessionEnd(ctx, data + 1, *dataSz - 1);
        rc = WOLFSPDM_E_PEER_ERROR;
    }

    return rc;
}
#endif /* !WOLFSPDM_NO_APP_DATA */
