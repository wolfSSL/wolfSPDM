/* spdm_msg.c
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

int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz)
{
    /* Note: ctx is not used for GET_VERSION, check buf/bufSz directly */
    if (buf == NULL || bufSz == NULL || *bufSz < 4)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Per SPDM spec, GET_VERSION always uses version 1.0 */
    buf[0] = SPDM_VERSION_10;
    buf[1] = SPDM_GET_VERSION;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

static int wolfSPDM_BuildSimpleMsg(WOLFSPDM_CTX* ctx, byte msgCode,
    byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    buf[0] = ctx->spdmVersion;
    buf[1] = msgCode;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;
    return WOLFSPDM_SUCCESS;
}

/* KEY_EXCHANGE request size: 8-byte header, 32-byte RandomData and two ECC
 * coordinates, followed by the mode's OpaqueData block. */
#define WOLFSPDM_KEYEX_FIXED_SZ  (40 + 2 * WOLFSPDM_ECC_KEY_SIZE)

#ifndef WOLFSPDM_NO_MCTP
/* Standard SPDM 1.2+ secured message version list: OpaqueLength(2) + 20 */
static const byte kexOpaqueStd[] = {
    0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x01,
    0x03, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x00, 0x00
};
#endif
#ifdef WOLFSPDM_NUVOTON
static const byte kexOpaqueNuvoton[] = {
    0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x01, 0x01, 0x00, 0x10, 0x00,
    0x00, 0x00
};
#endif
#ifdef WOLFSPDM_NATIONS
/* Nations only accepts OpaqueLength=0 */
static const byte kexOpaqueNations[] = { 0x00, 0x00 };
#endif

static void wolfSPDM_KeyExOpaque(const WOLFSPDM_CTX* ctx,
    const byte** opaque, word32* opaqueSz)
{
#ifndef WOLFSPDM_NO_MCTP
    *opaque = kexOpaqueStd;
    *opaqueSz = (word32)sizeof(kexOpaqueStd);
#else
    *opaque = NULL;
    *opaqueSz = 0;
#endif
#ifdef WOLFSPDM_NUVOTON
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON) {
        *opaque = kexOpaqueNuvoton;
        *opaqueSz = (word32)sizeof(kexOpaqueNuvoton);
    }
#endif
#ifdef WOLFSPDM_NATIONS
    if (ctx->mode == WOLFSPDM_MODE_NATIONS) {
        *opaque = kexOpaqueNations;
        *opaqueSz = (word32)sizeof(kexOpaqueNations);
    }
#endif
#if !defined(WOLFSPDM_NUVOTON) && !defined(WOLFSPDM_NATIONS)
    (void)ctx;
#endif
}

int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    word32 offset = 0;
    word32 exSz = WOLFSPDM_ECC_POINT_SIZE;
    word32 xSz = WOLFSPDM_ECC_KEY_SIZE;
    word32 ySz = WOLFSPDM_ECC_KEY_SIZE;
    const byte* opaque;
    word32 opaqueSz;
    int useKem = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    wolfSPDM_KeyExOpaque(ctx, &opaque, &opaqueSz);
    if (opaque == NULL) {
        return WOLFSPDM_E_NOT_AVAILABLE;
    }
#ifdef WOLFSPDM_HAVE_MLKEM
    useKem = (ctx->kemAlgSel != 0 && !wolfSPDM_IsTcgMode(ctx));
#endif

    /* ECDHE: exactly the encoded request size; ML-KEM bounds its own key */
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, WOLFSPDM_KEYEX_FIXED_SZ + opaqueSz -
        (useKem ? WOLFSPDM_ECC_POINT_SIZE : 0));
    XMEMSET(buf, 0, *bufSz);

    /* Use negotiated SPDM version (not hardcoded 1.2) */
    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_KEY_EXCHANGE;
    buf[offset++] = 0x00;  /* MeasurementSummaryHashType = None */
    /* SlotID: 0xFF = provisioned public key (TCG), else the cert slot */
#ifndef WOLFSPDM_NO_CERT
    buf[offset++] = wolfSPDM_IsTcgMode(ctx) ? 0xFF : ctx->currentSlotId;
#else
    buf[offset++] = wolfSPDM_IsTcgMode(ctx) ? 0xFF : 0x00;
#endif

    /* ReqSessionID (2 LE) */
    buf[offset++] = (byte)(ctx->reqSessionId & 0xFF);
    buf[offset++] = (byte)((ctx->reqSessionId >> 8) & 0xFF);

    buf[offset++] = 0x00;  /* SessionPolicy */
    buf[offset++] = 0x00;  /* Reserved */

    /* RandomData (32 bytes) */
    rc = wolfSPDM_GetRandom(ctx, &buf[offset], WOLFSPDM_RANDOM_SIZE);
    offset += WOLFSPDM_RANDOM_SIZE;

    /* ExchangeData: the ML-KEM encapsulation key, or ECDHE X || Y */
#ifdef WOLFSPDM_HAVE_MLKEM
    if (rc == WOLFSPDM_SUCCESS && useKem) {
        exSz = *bufSz - offset - opaqueSz;
        rc = wolfSPDM_GenerateMlKemKey(ctx, &buf[offset], &exSz);
    }
    else
#endif
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_GenerateEphemeralKey(ctx);
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_ExportEphemeralPubKey(ctx, &buf[offset], &xSz,
                &buf[offset + WOLFSPDM_ECC_KEY_SIZE], &ySz);
        }
    }

    if (rc == WOLFSPDM_SUCCESS) {
        offset += exSz;

        /* OpaqueData for secured message version negotiation */
        XMEMCPY(&buf[offset], opaque, opaqueSz);
        offset += opaqueSz;

        *bufSz = offset;
    }

    return rc;
}

/* ----- Shared Signing Helpers ----- */

/* Build the SPDM 1.2+ signing input per DSP0274 (148 bytes at most):
 * M = combined_spdm_prefix || zero_pad || context_str || inputDigest
 *
 * combined_spdm_prefix = "dmtf-spdm-v1.X.*" x4 = 64 bytes
 * zero_pad = (36 - contextStrLen) bytes of 0x00
 * context_str = signing context string (variable length, max 36) */
static int wolfSPDM_BuildSignedMsg(byte spdmVersion,
    const char* contextStr, word32 contextStrLen,
    const byte* inputDigest, byte* signMsg, word32* signMsgLen)
{
    word32 len = 0;
    byte majorVer, minorVer;
    int i;

    if (contextStrLen > 36) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    majorVer = (byte)('0' + ((spdmVersion >> 4) & 0xF));
    minorVer = (byte)('0' + (spdmVersion & 0xF));

    /* combined_spdm_prefix: "dmtf-spdm-v1.X.*" x4 = 64 bytes */
    for (i = 0; i < 4; i++) {
        XMEMCPY(&signMsg[len], "dmtf-spdm-v1.2.*", 16);
        signMsg[len + 11] = majorVer;
        signMsg[len + 13] = minorVer;
        signMsg[len + 15] = '*';
        len += 16;
    }

    /* Zero padding: 36 - contextStrLen bytes */
    XMEMSET(&signMsg[len], 0x00, 36 - contextStrLen);
    len += 36 - contextStrLen;

    /* Signing context string */
    XMEMCPY(&signMsg[len], contextStr, contextStrLen);
    len += contextStrLen;

    /* Input digest */
    XMEMCPY(&signMsg[len], inputDigest, WOLFSPDM_HASH_SIZE);
    len += WOLFSPDM_HASH_SIZE;

    *signMsgLen = len;
    return WOLFSPDM_SUCCESS;
}

/* outputDigest = Hash(M) */
int wolfSPDM_BuildSignedHash(byte spdmVersion,
    const char* contextStr, word32 contextStrLen,
    const byte* inputDigest, byte* outputDigest)
{
    byte signMsg[200]; /* 64 + 36 + 48 = 148 bytes max */
    word32 signMsgLen = 0;
    int rc;

    rc = wolfSPDM_BuildSignedMsg(spdmVersion, contextStr, contextStrLen,
        inputDigest, signMsg, &signMsgLen);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_Sha384Hash(outputDigest, signMsg, signMsgLen,
            NULL, 0, NULL, 0);
    }
    wc_ForceZero(signMsg, sizeof(signMsg));
    return rc;
}

/* ECDSA signs Hash(M); ML-DSA signs M itself with spdm_context as its
 * context string (DSP0274 1.4 Sec. 15) */
int wolfSPDM_VerifyRspSig(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen, const byte* messageHash,
    const byte* sig, word32 sigSz)
{
    byte signHash[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL || contextStr == NULL || messageHash == NULL ||
            sig == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (!ctx->flags.hasRspPubKey) {
        wolfSPDM_DebugPrint(ctx, "No responder public key set\n");
        return WOLFSPDM_E_BAD_STATE;
    }
    if (sigSz != wolfSPDM_SigSize(ctx)) {
        return WOLFSPDM_E_BAD_SIGNATURE;
    }

#ifdef WOLFSPDM_HAVE_MLDSA
    if (wolfSPDM_RspMlDsaLevel(ctx) != 0) {
        byte signMsg[200];
        word32 signMsgLen = 0;

        rc = wolfSPDM_BuildSignedMsg(ctx->spdmVersion, contextStr,
            contextStrLen, messageHash, signMsg, &signMsgLen);
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_MlDsaVerify(wolfSPDM_RspMlDsaLevel(ctx),
                ctx->rspPubKey, ctx->rspPubKeyLen, (const byte*)contextStr,
                contextStrLen, signMsg, signMsgLen, sig, sigSz);
        }
        wc_ForceZero(signMsg, sizeof(signMsg));
        return rc;
    }
#endif

    rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion, contextStr, contextStrLen,
        messageHash, signHash);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifySignature(ctx, signHash, WOLFSPDM_HASH_SIZE, sig,
            sigSz);
    }
    wc_ForceZero(signHash, sizeof(signHash));
    return rc;
}

int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
#ifdef WOLFSPDM_MUTUAL_AUTH
    byte signature[WOLFSPDM_ECC_POINT_SIZE];  /* 96 bytes for P-384 */
    word32 sigSz = sizeof(signature);
#endif
    word32 offset = 4;  /* Start after header */
    word32 minSz;
    int mutualAuth = 0;
    int rc;

    /* Check arguments first before any ctx dereference */
    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

#ifdef WOLFSPDM_MUTUAL_AUTH
    /* Mutual auth is enabled when the responder requested it (MutAuthRequested
     * bit 0) AND we have a requester key pair to sign with */
    if ((ctx->mutAuthRequested & 0x01) && !ctx->flags.hasReqKeyPair) {
        wolfSPDM_DebugPrint(ctx, "FINISH: mutual auth requested, no "
            "requester key\n");
        return WOLFSPDM_E_BAD_STATE;
    }
    if (ctx->mutAuthRequested & 0x01) {
        mutualAuth = 1;
        wolfSPDM_DebugPrint(ctx, "FINISH: Mutual auth ENABLED "
            "(MutAuth=0x%02x ReqSlot=0x%02x)\n",
            ctx->mutAuthRequested, ctx->reqSlotIdParam);
    }
#endif

    /* Check buffer size: header(4) + [OpaqueLength(2) for 1.4+] +
     * [signature(96) for mutual auth] + HMAC(48) */
    minSz = 4 + WOLFSPDM_HASH_SIZE;  /* header + HMAC */
    if (ctx->spdmVersion >= SPDM_VERSION_14)
        minSz += 2;  /* OpaqueLength */
    if (mutualAuth)
        minSz += WOLFSPDM_ECC_POINT_SIZE;  /* Signature */
    if (*bufSz < minSz)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Build FINISH header */
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_FINISH;
    if (mutualAuth) {
        buf[2] = 0x01;  /* Param1: Signature field is included */
        /* Param2: For PUB_KEY_ID mode, shall be 0xFF per DSP0274 */
        buf[3] = 0xFF;
    } else {
        buf[2] = 0x00;  /* Param1: No signature */
        buf[3] = 0x00;  /* Param2: SlotID = 0 when no signature */
    }

    /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) after header */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        buf[offset++] = 0x00;  /* OpaqueLength = 0 (LE) */
        buf[offset++] = 0x00;
    }

    rc = WOLFSPDM_SUCCESS;

    /* Mutual auth: add Hash(Cm_requester) to transcript between message_k
     * and FINISH header. For PUB_KEY_ID mode, Cm = SHA-384(TPMT_PUBLIC)
     * of the requester's public key (matching how Ct is computed for
     * responder per TCG SPDM binding). */
#ifdef WOLFSPDM_TCG
    if (rc == WOLFSPDM_SUCCESS && mutualAuth && ctx->reqPubKeyTPMTLen > 0) {
        byte cmHash[WOLFSPDM_HASH_SIZE];
        rc = wolfSPDM_Sha384Hash(cmHash, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen, NULL, 0, NULL, 0);
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_TranscriptAdd(ctx, cmHash, WOLFSPDM_HASH_SIZE);
    }
#endif

    /* Add FINISH header to transcript, compute TH2 */
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptAdd(ctx, buf, offset);
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc == WOLFSPDM_SUCCESS)
        XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);

#ifdef WOLFSPDM_MUTUAL_AUTH
    /* Mutual auth: sign TH2, add signature to transcript, recompute TH2 */
    if (rc == WOLFSPDM_SUCCESS && mutualAuth) {
        byte signMsgHash[WOLFSPDM_HASH_SIZE];

        rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion,
            "requester-finish signing", 24, th2Hash, signMsgHash);
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_SignHash(ctx, signMsgHash, WOLFSPDM_HASH_SIZE,
                signature, &sigSz);
        if (rc == WOLFSPDM_SUCCESS) {
            XMEMCPY(&buf[offset], signature, WOLFSPDM_ECC_POINT_SIZE);
            offset += WOLFSPDM_ECC_POINT_SIZE;
            rc = wolfSPDM_TranscriptAdd(ctx, signature,
                WOLFSPDM_ECC_POINT_SIZE);
        }
        if (rc == WOLFSPDM_SUCCESS)
            rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    }
#endif

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) */
    if (rc == WOLFSPDM_SUCCESS)
        rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash,
            verifyData);
    if (rc == WOLFSPDM_SUCCESS) {
        XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
        offset += WOLFSPDM_HASH_SIZE;
        rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS)
        *bufSz = offset;

    /* Always zero sensitive stack buffers */
    wc_ForceZero(th2Hash, sizeof(th2Hash));
    wc_ForceZero(verifyData, sizeof(verifyData));
#ifdef WOLFSPDM_MUTUAL_AUTH
    wc_ForceZero(signature, sizeof(signature));
#endif
    return rc;
}

int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_END_SESSION, buf, bufSz);
}

int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode)
{
    if (buf == NULL || bufSz < 4) {
        return 0;
    }

    if (buf[1] == SPDM_ERROR) {
        if (errorCode != NULL) {
            *errorCode = buf[2];
        }
        return 1;
    }

    return 0;
}

int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 entryCount;
    word32 i;
    byte highestVersion = 0;  /* No version found yet */
    byte maxVer;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 6);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_VERSION, WOLFSPDM_E_VERSION_MISMATCH);

    /* VersionNumberEntryCount is the one-byte field at offset 5 (byte 4
     * reserved) per DSP0274; older wolfTPM responders placed it at
     * offset 4, so fall back to that when offset 5 is zero.
     * Offset 6+: VersionNumberEntry array (2 bytes each, LE) */
    entryCount = buf[5];
    if (entryCount == 0) {
        entryCount = buf[4];
    }

    /* Reject a truncated entry list instead of negotiating from a subset */
    if ((word32)6 + (word32)entryCount * 2 > bufSz) {
        return WOLFSPDM_E_VERSION_MISMATCH;
    }

    /* Find highest mutually supported version.
     * Per DSP0274, negotiated version must be the highest version
     * that both sides support. We support WOLFSPDM_MIN_SPDM_VERSION
     * through WOLFSPDM_MAX_SPDM_VERSION (or ctx->maxVersion if set). */
    maxVer = (ctx->maxVersion != 0) ? ctx->maxVersion
                                          : WOLFSPDM_MAX_SPDM_VERSION;
    for (i = 0; i < entryCount; i++) {
        /* Each entry is 2 bytes; high byte (offset +1) is Major.Minor */
        byte ver = buf[6 + i * 2 + 1];
        if (ver >= WOLFSPDM_MIN_SPDM_VERSION &&
            ver <= maxVer &&
            ver > highestVersion) {
            highestVersion = ver;
        }
    }

    /* If no mutually supported version found, fail */
    if (highestVersion == 0) {
        wolfSPDM_DebugPrint(ctx, "No mutually supported SPDM version found "
            "(require >= 0x%02x)\n", WOLFSPDM_MIN_SPDM_VERSION);
        return WOLFSPDM_E_VERSION_MISMATCH;
    }

    ctx->spdmVersion = highestVersion;
    ctx->state = WOLFSPDM_STATE_VERSION;

    wolfSPDM_DebugPrint(ctx, "Negotiated SPDM version: 0x%02x\n", ctx->spdmVersion);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 exSz = WOLFSPDM_ECC_POINT_SIZE;
    word32 sigSz;
    word32 opaqueOff;
    word32 sigOffset;
    byte th1SigHash[WOLFSPDM_HASH_SIZE];
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    const byte* signature;
    const byte* rspVerifyData;
    int rc;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 140);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_EXCHANGE_RSP, WOLFSPDM_E_KEY_EXCHANGE);

    /* Only the TCG binding carries a requester identity (GIVE_PUB) */
    if (!wolfSPDM_IsTcgMode(ctx) && buf[6] != 0) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: mutual auth unsupported\n");
        return WOLFSPDM_E_KEY_EXCHANGE;
    }

    /* RspSessionID (4-5), MutAuthRequested (6), ReqSlotIDParam (7) are
     * committed to ctx only after the signature and HMAC verify */
    wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: MutAuth=0x%02x ReqSlotID=0x%02x\n",
        buf[6], buf[7]);

    /* ExchangeData at offset 40: the ECDHE point, or the ML-KEM ciphertext */
#ifdef WOLFSPDM_HAVE_MLKEM
    if (ctx->flags.ephemeralKeyInit && ctx->flags.ephemeralIsKem &&
            wc_MlKemKey_CipherTextSize(&ctx->ephemeral.mlkem, &exSz) != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
#endif
    sigSz = wolfSPDM_SigSize(ctx);
    opaqueOff = 40 + exSz;
    if (bufSz < opaqueOff + 2) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    sigOffset = opaqueOff + 2 + SPDM_Get16LE(&buf[opaqueOff]);
    if (bufSz < sigOffset + sigSz + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    signature = buf + sigOffset;
    rspVerifyData = buf + sigOffset + sigSz;

    /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, sigOffset);

    /* Verify responder signature over TH1 (DSP0274). Responder public key
     * must be provisioned before KEY_EXCHANGE. */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, th1SigHash);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifyRspSig(ctx, "responder-key_exchange_rsp signing",
            34, th1SigHash, signature, sigSz);
        if (rc != WOLFSPDM_SUCCESS)
            wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP signature INVALID\n");
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, signature, sigSz);
    }
#ifdef WOLFSPDM_HAVE_MLKEM
    if (rc == WOLFSPDM_SUCCESS && ctx->flags.ephemeralIsKem) {
        rc = wolfSPDM_MlKemDecapsulate(ctx, &buf[40], exSz);
    }
    else
#endif
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeSharedSecret(ctx, &buf[40],
            &buf[40 + WOLFSPDM_ECC_KEY_SIZE]);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptHash(ctx, ctx->th1);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DeriveHandshakeKeys(ctx, ctx->th1);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1, expectedHmac);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        if (wolfSPDM_ConstCompare(expectedHmac, rspVerifyData,
                WOLFSPDM_HASH_SIZE) != 0) {
            wolfSPDM_DebugPrint(ctx, "ResponderVerifyData MISMATCH\n");
            rc = WOLFSPDM_E_BAD_HMAC;
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData VERIFIED OK\n");
        rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->rspSessionId = SPDM_Get16LE(&buf[4]);
        ctx->sessionId = (word32)ctx->reqSessionId |
            ((word32)ctx->rspSessionId << 16);
        ctx->mutAuthRequested = buf[6];
        ctx->reqSlotIdParam = buf[7];
        ctx->state = WOLFSPDM_STATE_KEY_EX;
    }

    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(th1SigHash, sizeof(th1SigHash));
    return rc;
}

int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);

    if (buf[1] == SPDM_FINISH_RSP) {
        int addRc;
        word32 rspMsgLen = 4;

        /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) to FINISH_RSP */
        if (ctx->spdmVersion >= SPDM_VERSION_14) {
            word16 opaqueLen;
            if (bufSz < 6) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
            opaqueLen = SPDM_Get16LE(&buf[4]);
            if (opaqueLen > WOLFSPDM_FINISH_OPAQUE_MAX) {
                return WOLFSPDM_E_INVALID_ARG;
            }
            rspMsgLen = 4 + 2 + opaqueLen;
            if (bufSz < rspMsgLen) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
        }

        /* Add FINISH_RSP (header + OpaqueData for 1.4) to transcript */
        addRc = wolfSPDM_TranscriptAdd(ctx, buf, rspMsgLen);
        if (addRc != WOLFSPDM_SUCCESS) {
            return addRc;
        }
        ctx->state = WOLFSPDM_STATE_FINISH;
        wolfSPDM_DebugPrint(ctx, "FINISH_RSP received - session established\n");
        return WOLFSPDM_SUCCESS;
    }

    if (buf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "FINISH error: 0x%02x\n", buf[2]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_E_BAD_STATE;
}

/* PSK message builders/parsers moved to spdm_psk.c */

#ifndef WOLFSPDM_NO_HEARTBEAT
int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_HEARTBEAT, buf, bufSz);
}

int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_HEARTBEAT_ACK,
        WOLFSPDM_E_PEER_ERROR);
    if (bufSz != 4 || buf[0] != ctx->spdmVersion) {
        return WOLFSPDM_E_PEER_ERROR;
    }
    return WOLFSPDM_SUCCESS;
}
#endif /* !WOLFSPDM_NO_HEARTBEAT */

#ifndef WOLFSPDM_NO_KEY_UPDATE
int wolfSPDM_BuildKeyUpdate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte* tag)
{
    int rc;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    if (tag == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wolfSPDM_GetRandom(ctx, tag, 1);
    if (rc == WOLFSPDM_SUCCESS) {
        buf[0] = ctx->spdmVersion;
        buf[1] = SPDM_KEY_UPDATE;
        buf[2] = operation;
        buf[3] = *tag;
        *bufSz = 4;
    }
    return rc;
}

int wolfSPDM_ParseKeyUpdateAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, byte operation, byte tag)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_UPDATE_ACK,
        WOLFSPDM_E_KEY_UPDATE);
    if (bufSz != 4 || buf[0] != ctx->spdmVersion || buf[2] != operation ||
            buf[3] != tag) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK mismatch\n");
        return WOLFSPDM_E_KEY_UPDATE;
    }
    return WOLFSPDM_SUCCESS;
}
#endif /* !WOLFSPDM_NO_KEY_UPDATE */
