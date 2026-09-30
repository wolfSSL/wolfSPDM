/* spdm_standard.c
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

#ifndef WOLFSPDM_NO_CERT

#include <wolfssl/wolfcrypt/asn.h>

/* Largest certificate portion requested per GET_CERTIFICATE; the response
 * fits our DataTransferSize so certificates are never chunked */
#if WOLFSPDM_DATA_TRANSFER_SIZE < 1024 + 8
    #define WOLFSPDM_CERT_PORTION_SZ  (WOLFSPDM_DATA_TRANSFER_SIZE - 8)
#else
    #define WOLFSPDM_CERT_PORTION_SZ  1024
#endif

/* ----- VCA: GET_CAPABILITIES / NEGOTIATE_ALGORITHMS ----- */

int wolfSPDM_BuildGetCapabilities(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 20);

    XMEMSET(buf, 0, 20);
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_GET_CAPABILITIES;
    SPDM_Set32LE(&buf[8], WOLFSPDM_REQ_CAPS);
    SPDM_Set32LE(&buf[12], WOLFSPDM_DATA_TRANSFER_SIZE);
    SPDM_Set32LE(&buf[16], WOLFSPDM_MAX_MSG_SIZE);  /* MaxSPDMmsgSize */
    *bufSz = 20;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    const word32 required = SPDM_CAP_CERT_CAP | SPDM_CAP_ENCRYPT_CAP |
        SPDM_CAP_MAC_CAP | SPDM_CAP_KEY_EX_CAP;
    word32 caps;
    word32 dts;
    word32 maxMsg;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CAPABILITIES,
        WOLFSPDM_E_CAPS_MISMATCH);

    if (bufSz < 20 || buf[0] != ctx->spdmVersion) {
        return WOLFSPDM_E_CAPS_MISMATCH;
    }

    caps = SPDM_Get32LE(&buf[8]);
    dts = SPDM_Get32LE(&buf[12]);
    maxMsg = SPDM_Get32LE(&buf[16]);

    /* DSP0274: MinDataTransferSize is 42 */
    if ((caps & required) != required || dts < 42 || maxMsg < dts) {
        wolfSPDM_DebugPrint(ctx, "CAPABILITIES rejected: caps=0x%08x "
            "dts=%u max=%u\n", caps, dts, maxMsg);
        return WOLFSPDM_E_CAPS_MISMATCH;
    }

    ctx->rspCaps = caps;
    ctx->dataTransferSize = dts;
    ctx->maxSpdmMsgSize = maxMsg;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz)
{
    word32 off = 32;
    int advDhe = 1;
#ifdef WOLFSPDM_HAVE_MLKEM
    int advKem;
#endif

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, WOLFSPDM_NEG_ALGO_SZ);

#ifdef WOLFSPDM_HAVE_MLKEM
    /* KEMAlg exists from 1.4; a KEM-only preference must not fall back */
    advDhe = (ctx->kexAdvDhe != 0);
    advKem = (ctx->spdmVersion >= SPDM_VERSION_14 && ctx->kexAdvKem != 0);
    if (!advDhe && !advKem) {
        wolfSPDM_DebugPrint(ctx, "NEGOTIATE_ALGORITHMS: ML-KEM only needs "
            "SPDM 1.4\n");
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
#endif

    XMEMSET(buf, 0, WOLFSPDM_NEG_ALGO_SZ);
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_NEGOTIATE_ALGORITHMS;
    buf[6] = 0x01;                  /* MeasurementSpecification = DMTF */
    buf[7] = 0x02;                  /* OtherParams = OpaqueDataFmt1 */
    SPDM_Set32LE(&buf[8], SPDM_ASYM_ALGO_ECDSA_P384);
    SPDM_Set32LE(&buf[12], SPDM_HASH_ALGO_SHA_384);
#ifdef WOLFSPDM_HAVE_MLDSA
    /* PqcAsymAlgo, reserved before 1.4 */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        SPDM_Set32LE(&buf[16], WOLFSPDM_MLDSA_SETS);
    }
#endif

    if (advDhe) {
        buf[off] = SPDM_ALG_TYPE_DHE;
        buf[off + 1] = 0x20;
        SPDM_Set16LE(&buf[off + 2], SPDM_DHE_ALGO_SECP384R1);
        off += 4;
    }
    buf[off] = SPDM_ALG_TYPE_AEAD;
    buf[off + 1] = 0x20;
    SPDM_Set16LE(&buf[off + 2], SPDM_AEAD_ALGO_AES_256_GCM);
    off += 4;
    buf[off] = SPDM_ALG_TYPE_REQ_BASE_ASYM;
    buf[off + 1] = 0x20;
    SPDM_Set16LE(&buf[off + 2], (word16)SPDM_ASYM_ALGO_ECDSA_P384);
    off += 4;
    buf[off] = SPDM_ALG_TYPE_KEY_SCHEDULE;
    buf[off + 1] = 0x20;
    SPDM_Set16LE(&buf[off + 2], SPDM_KEY_SCHEDULE_SPDM);
    off += 4;
#ifdef WOLFSPDM_HAVE_MLKEM
    if (advKem) {
        buf[off] = SPDM_ALG_TYPE_KEM;
        buf[off + 1] = 0x20;
        SPDM_Set16LE(&buf[off + 2], ctx->kexAdvKem);
        off += 4;
    }
#endif

    buf[2] = (byte)((off - 32) / 4);    /* AlgStruct count */
    SPDM_Set16LE(&buf[4], (word16)off); /* Length */
    *bufSz = off;

    return WOLFSPDM_SUCCESS;
}

/* The responder picks one signature algorithm across BaseAsymSel and the
 * 1.4 PqcAsymSel, and one key exchange: a DHE group or a KEM, never both */
int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 off;
    word32 baseAsymSel;
    word32 pqcAsymSel = 0;
#ifdef WOLFSPDM_HAVE_MLKEM
    word16 kemSel = 0;
#endif
    byte numAlgs;
    byte i;
    int dheOk = 0;
    int kemOk = 0;
    int aeadOk = 0;
    int ksOk = 0;

    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_ALGORITHMS,
        WOLFSPDM_E_ALGO_MISMATCH);

    if (bufSz < 36 || buf[0] != ctx->spdmVersion ||
            SPDM_Get16LE(&buf[4]) != bufSz) {
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
    /* MeasurementSpecificationSel (none or DMTF), OtherParamsSel */
    if (buf[6] > 0x01 || buf[7] != 0x02) {
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
    if (SPDM_Get32LE(&buf[16]) != SPDM_HASH_ALGO_SHA_384) {
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

#ifdef WOLFSPDM_HAVE_MLDSA
    ctx->pqcAsymSel = 0;
#endif
#ifdef WOLFSPDM_HAVE_MLKEM
    ctx->kemAlgSel = 0;
#endif
    baseAsymSel = SPDM_Get32LE(&buf[12]);
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        pqcAsymSel = SPDM_Get32LE(&buf[20]);
    }
    if (pqcAsymSel != 0) {
#ifdef WOLFSPDM_HAVE_MLDSA
        if (baseAsymSel != 0 || wolfSPDM_MlDsaLevel(pqcAsymSel) == 0) {
            return WOLFSPDM_E_ALGO_MISMATCH;
        }
#else
        return WOLFSPDM_E_ALGO_MISMATCH;
#endif
    }
    else if (baseAsymSel != SPDM_ASYM_ALGO_ECDSA_P384) {
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    /* AlgStructs follow the ExtAsymSel and ExtHashSel tables */
    numAlgs = buf[2];
    off = 36 + (word32)buf[32] * 4 + (word32)buf[33] * 4;
    for (i = 0; i < numAlgs; i++) {
        word16 algSel;
        word32 extLen;

        if (off > bufSz || bufSz - off < 4) {
            return WOLFSPDM_E_ALGO_MISMATCH;
        }
        algSel = SPDM_Get16LE(&buf[off + 2]);
        extLen = (word32)(buf[off + 1] & 0x0F) * 4;
        switch (buf[off]) {
            case SPDM_ALG_TYPE_DHE:
                dheOk = (algSel == SPDM_DHE_ALGO_SECP384R1);
            #ifdef WOLFSPDM_HAVE_MLKEM
                /* Zero when the responder picked a KEM instead */
                if ((algSel != 0 && !dheOk) || (dheOk && !ctx->kexAdvDhe)) {
                    return WOLFSPDM_E_ALGO_MISMATCH;
                }
            #endif
                break;
        #ifdef WOLFSPDM_HAVE_MLKEM
            case SPDM_ALG_TYPE_KEM:
                if (algSel != 0 && ((algSel & (algSel - 1)) != 0 ||
                        (algSel & ctx->kexAdvKem & WOLFSPDM_MLKEM_SETS) == 0 ||
                        ctx->spdmVersion < SPDM_VERSION_14)) {
                    return WOLFSPDM_E_ALGO_MISMATCH;
                }
                kemOk = (algSel != 0);
                kemSel = algSel;
                break;
        #endif
            case SPDM_ALG_TYPE_AEAD:
                aeadOk = (algSel == SPDM_AEAD_ALGO_AES_256_GCM);
                break;
            case SPDM_ALG_TYPE_KEY_SCHEDULE:
                ksOk = (algSel == SPDM_KEY_SCHEDULE_SPDM);
                break;
            default:
                break;
        }
        off += 4 + extLen;
    }
    if (dheOk + kemOk != 1 || !aeadOk || !ksOk) {
        wolfSPDM_DebugPrint(ctx, "ALGORITHMS: not Algorithm Set B "
            "(dhe=%d kem=%d aead=%d ks=%d)\n", dheOk, kemOk, aeadOk, ksOk);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
#ifdef WOLFSPDM_HAVE_MLDSA
    ctx->pqcAsymSel = pqcAsymSel;
#endif
#ifdef WOLFSPDM_HAVE_MLKEM
    ctx->kemAlgSel = kemSel;
#endif
    wolfSPDM_DebugPrint(ctx, "ALGORITHMS: asym 0x%08x pqc 0x%08x kem %d\n",
        baseAsymSel, pqcAsymSel, kemOk);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx)
{
    byte txBuf[20];
    byte rxBuf[64];

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetCapabilities,
        wolfSPDM_ParseCapabilities, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    byte txBuf[WOLFSPDM_NEG_ALGO_SZ];
    byte rxBuf[128];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    rc = wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildNegotiateAlgorithms,
        wolfSPDM_ParseAlgorithms, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->vcaLen = ctx->transcriptLen;
    #ifndef WOLFSPDM_NO_CHALLENGE
        rc = wolfSPDM_M1Start(ctx);
    #endif
    }
    return rc;
}

/* ----- GET_DIGESTS / GET_CERTIFICATE (not part of the TH transcript) ----- */

int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_DIGESTS, WOLFSPDM_E_CERT_FAIL);

    /* Param2 is the (provisioned) slot mask in SPDM 1.2 and 1.3 */
    ctx->slotMask = buf[3];
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_GetDigests(WOLFSPDM_CTX* ctx)
{
    byte txBuf[4];
    byte rxBuf[512];
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    txBuf[0] = ctx->spdmVersion;
    txBuf[1] = SPDM_GET_DIGESTS;
    txBuf[2] = 0x00;
    txBuf[3] = 0x00;

    rc = wolfSPDM_ClearExchange(ctx, txBuf, sizeof(txBuf), rxBuf, &rxSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseDigests(ctx, rxBuf, rxSz);
    }
#ifndef WOLFSPDM_NO_CHALLENGE
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_M1Add(ctx, txBuf, sizeof(txBuf), rxBuf, rxSz);
    }
#endif
    return rc;
}

int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, word16* portionLen, word16* remainderLen)
{
    SPDM_CHECK_PARSE_ARGS(ctx, buf, bufSz, 4);
    if (portionLen == NULL || remainderLen == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CERTIFICATE,
        WOLFSPDM_E_CERT_FAIL);

    /* Param1[3:0] must echo the requested slot */
    if (bufSz < 8 || (buf[2] & 0x0F) != ctx->currentSlotId) {
        return WOLFSPDM_E_CERT_FAIL;
    }

    *portionLen = SPDM_Get16LE(&buf[4]);
    *remainderLen = SPDM_Get16LE(&buf[6]);
    if (bufSz - 8 < *portionLen ||
            *portionLen > WOLFSPDM_MAX_CERT_CHAIN - ctx->certChainLen) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->certChain + ctx->certChainLen, buf + 8, *portionLen);
    ctx->certChainLen += *portionLen;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_GetCertificate(WOLFSPDM_CTX* ctx, int slotId)
{
    byte txBuf[8];
    byte rxBuf[8 + WOLFSPDM_CERT_PORTION_SZ];
    word32 rxSz;
    word16 offset = 0;
    word16 portionLen = 0;
    word16 remainderLen = 1;
    word16 reqLen = WOLFSPDM_CERT_PORTION_SZ;
    int rc = WOLFSPDM_SUCCESS;

    if (ctx == NULL || slotId < 0 || slotId > 7) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* The CERTIFICATE response (8-byte header + portion) must fit the
     * responder's DataTransferSize */
    if (ctx->dataTransferSize != 0 &&
            ctx->dataTransferSize < (word32)reqLen + 8) {
        reqLen = (word16)(ctx->dataTransferSize - 8);
    }
    ctx->currentSlotId = (byte)slotId;
    ctx->certChainLen = 0;

    while (rc == WOLFSPDM_SUCCESS && remainderLen > 0) {
        txBuf[0] = ctx->spdmVersion;
        txBuf[1] = SPDM_GET_CERTIFICATE;
        txBuf[2] = (byte)slotId;
        txBuf[3] = 0x00;
        SPDM_Set16LE(&txBuf[4], offset);
        SPDM_Set16LE(&txBuf[6], reqLen);

        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_ClearExchange(ctx, txBuf, sizeof(txBuf), rxBuf, &rxSz);
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_ParseCertificate(ctx, rxBuf, rxSz, &portionLen,
                &remainderLen);
        }
    #ifndef WOLFSPDM_NO_CHALLENGE
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_M1Add(ctx, txBuf, sizeof(txBuf), rxBuf,
                8u + portionLen);
        }
    #endif
        /* Every non-final portion must make progress */
        if (rc == WOLFSPDM_SUCCESS && portionLen == 0 && remainderLen > 0) {
            rc = WOLFSPDM_E_CERT_FAIL;
        }
        offset = (word16)(offset + portionLen);
    }

    if (rc == WOLFSPDM_SUCCESS &&
            (ctx->certChainLen <= WOLFSPDM_CERT_CHAIN_HDR_SZ ||
             SPDM_Get16LE(ctx->certChain) != ctx->certChainLen)) {
        rc = WOLFSPDM_E_CERT_FAIL;
    }

    /* Ct = Hash(certificate chain) is part of TH */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_Sha384Hash(ctx->certChainHash, ctx->certChain,
            ctx->certChainLen, NULL, 0, NULL, 0);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash,
            WOLFSPDM_HASH_SIZE);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_CERT;
    }
    return rc;
}

/* ----- Certificate chain verification ----- */

/* Returns the full length of the DER SEQUENCE at der, or 0 if malformed */
static word32 wolfSPDM_DerSeqLen(const byte* der, word32 derSz)
{
    word32 len = 0;
    word32 hdr = 2;

    if (derSz < 2 || der[0] != 0x30) {
        return 0;
    }
    if (der[1] < 0x80) {
        len = der[1];
    }
    else {
        word32 n = der[1] & 0x7FU;
        word32 i;

        if (n == 0 || n > 3 || derSz < 2 + n) {
            return 0;
        }
        for (i = 0; i < n; i++) {
            len = (len << 8) | der[2 + i];
        }
        hdr += n;
    }
    if (len > derSz - hdr) {
        return 0;
    }
    return hdr + len;
}

/* A certificate's subject key: an ECC SubjectPublicKeyInfo, or a raw ML-DSA
 * public key */
#define WOLFSPDM_CERT_KEY_SZ    (WOLFSPDM_RSP_PUBKEY_SZ > 256 ? \
                                 WOLFSPDM_RSP_PUBKEY_SZ : 256)
typedef struct {
    word32 oid;
    word32 len;
    byte   der[WOLFSPDM_CERT_KEY_SZ];
} WOLFSPDM_CERT_KEY;

#ifdef WOLFSPDM_HAVE_MLDSA
static byte wolfSPDM_KeyOidMlDsaLevel(word32 oid)
{
    switch (oid) {
        case ML_DSA_44k:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_44);
        case ML_DSA_65k:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_65);
        case ML_DSA_87k:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_87);
        default:
            return 0;
    }
}

static byte wolfSPDM_SigOidMlDsaLevel(word32 oid)
{
    switch (oid) {
        case CTC_ML_DSA_44:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_44);
        case CTC_ML_DSA_65:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_65);
        case CTC_ML_DSA_87:
            return wolfSPDM_MlDsaLevel(SPDM_PQC_ASYM_ALGO_ML_DSA_87);
        default:
            return 0;
    }
}
#endif /* WOLFSPDM_HAVE_MLDSA */

/* Read the subject key and CA flag of a certificate */
static int wolfSPDM_CertKey(const byte* der, word32 derSz,
    WOLFSPDM_CERT_KEY* key, int* isCA)
{
    DecodedCert cert;
    int rc;

    wc_InitDecodedCert(&cert, der, derSz, NULL);
    rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0 && cert.keyOID != ECDSAk
    #ifdef WOLFSPDM_HAVE_MLDSA
            && wolfSPDM_KeyOidMlDsaLevel(cert.keyOID) == 0
    #endif
            ) {
        rc = -1;
    }
    if (rc == 0 && (cert.publicKey == NULL ||
            cert.pubKeySize > sizeof(key->der))) {
        rc = -1;
    }
    if (rc == 0) {
        key->oid = cert.keyOID;
        key->len = cert.pubKeySize;
        XMEMCPY(key->der, cert.publicKey, cert.pubKeySize);
        *isCA = cert.isCA;
    }
    wc_FreeDecodedCert(&cert);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CERT_PARSE;
}

/* ECDSA verify of hash under an ECC SubjectPublicKeyInfo */
static int wolfSPDM_EccSpkiVerify(const byte* spki, word32 spkiSz,
    const byte* sig, word32 sigSz, const byte* hash, word32 hashSz)
{
    ecc_key key;
    word32 idx = 0;
    int verified = 0;
    int rc;

    rc = wc_ecc_init(&key);
    if (rc == 0) {
        rc = wc_EccPublicKeyDecode(spki, &idx, &key, spkiSz);
        if (rc == 0) {
            rc = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &verified, &key);
        }
        wc_ecc_free(&key);
    }

    return (rc == 0 && verified == 1) ? WOLFSPDM_SUCCESS :
        WOLFSPDM_E_CERT_FAIL;
}

/* Verify that the certificate at der was signed by issuer: ECDSA-SHA384, or
 * pure ML-DSA with an empty context */
static int wolfSPDM_CertSignedBy(const byte* der, word32 derSz,
    const WOLFSPDM_CERT_KEY* issuer)
{
    DecodedCert cert;
    byte hash[WOLFSPDM_HASH_SIZE];
    const byte* tbs;
    word32 tbsSz;
    int rc;

    wc_InitDecodedCert(&cert, der, derSz, NULL);
    rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0 && cert.sigIndex <= cert.certBegin) {
        rc = -1;
    }
    tbs = cert.source + cert.certBegin;
    tbsSz = cert.sigIndex - cert.certBegin;

    if (rc == 0 && issuer->oid == ECDSAk) {
        rc = (cert.signatureOID == CTC_SHA384wECDSA) ? 0 : -1;
        if (rc == 0) {
            rc = wolfSPDM_Sha384Hash(hash, tbs, tbsSz, NULL, 0, NULL, 0);
        }
        if (rc == 0) {
            rc = wolfSPDM_EccSpkiVerify(issuer->der, issuer->len,
                cert.signature, cert.sigLength, hash, sizeof(hash));
        }
    }
#ifdef WOLFSPDM_HAVE_MLDSA
    else if (rc == 0 && wolfSPDM_KeyOidMlDsaLevel(issuer->oid) != 0) {
        rc = (wolfSPDM_SigOidMlDsaLevel(cert.signatureOID) ==
                wolfSPDM_KeyOidMlDsaLevel(issuer->oid)) ? 0 : -1;
        if (rc == 0) {
            rc = wolfSPDM_MlDsaVerify(wolfSPDM_KeyOidMlDsaLevel(issuer->oid),
                issuer->der, issuer->len, NULL, 0, tbs, tbsSz, cert.signature,
                cert.sigLength);
        }
    }
#endif
    else {
        rc = -1;
    }
    wc_FreeDecodedCert(&cert);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CERT_FAIL;
}

/* The leaf key in the ctx->rspPubKey format: raw P-384 X||Y, or the raw
 * ML-DSA key of the negotiated set */
static int wolfSPDM_LeafKey(const WOLFSPDM_CTX* ctx,
    const WOLFSPDM_CERT_KEY* key, byte* leaf, word32* leafSz)
{
    ecc_key eccKey;
    word32 idx = 0;
    word32 xSz = WOLFSPDM_ECC_KEY_SIZE;
    word32 ySz = WOLFSPDM_ECC_KEY_SIZE;
    int rc;

#ifdef WOLFSPDM_HAVE_MLDSA
    if (wolfSPDM_RspMlDsaLevel(ctx) != 0) {
        if (wolfSPDM_KeyOidMlDsaLevel(key->oid) !=
                wolfSPDM_RspMlDsaLevel(ctx) || key->len > *leafSz) {
            return WOLFSPDM_E_CERT_PARSE;
        }
        XMEMCPY(leaf, key->der, key->len);
        *leafSz = key->len;
        return WOLFSPDM_SUCCESS;
    }
#else
    (void)ctx;
#endif

    /* Algorithm Set B: the leaf carries a P-384 key */
    if (key->oid != ECDSAk || *leafSz < WOLFSPDM_ECC_POINT_SIZE ||
            wc_ecc_init(&eccKey) != 0) {
        return WOLFSPDM_E_CERT_PARSE;
    }
    rc = wc_EccPublicKeyDecode(key->der, &idx, &eccKey, key->len);
    if (rc == 0 && wc_ecc_get_curve_id(eccKey.idx) != ECC_SECP384R1) {
        rc = -1;
    }
    if (rc == 0) {
        rc = wc_ecc_export_public_raw(&eccKey, leaf, &xSz,
            leaf + WOLFSPDM_ECC_KEY_SIZE, &ySz);
    }
    if (rc == 0 && (xSz != WOLFSPDM_ECC_KEY_SIZE ||
            ySz != WOLFSPDM_ECC_KEY_SIZE)) {
        rc = -1;
    }
    wc_ecc_free(&eccKey);
    *leafSz = WOLFSPDM_ECC_POINT_SIZE;

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CERT_PARSE;
}

/* Walk the retrieved chain: each certificate must be signed by the one
 * before it, the first by the trusted root when one is set. The leaf key
 * must match the negotiated signature algorithm and becomes the responder
 * key, or must match a pinned key. */
int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx)
{
    WOLFSPDM_CERT_KEY key;
    word32 leafSz = WOLFSPDM_RSP_PUBKEY_SZ;
    word32 pos = WOLFSPDM_CERT_CHAIN_HDR_SZ;
    int haveKey = 0;
    int isCA = 0;
    int anchored = 0;
    int rc = WOLFSPDM_SUCCESS;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (ctx->certChainLen <= WOLFSPDM_CERT_CHAIN_HDR_SZ) {
        return WOLFSPDM_E_CERT_FAIL;
    }
    /* A key taken from an earlier chain is not an anchor for this one */
    if (ctx->flags.rspKeyFromCert) {
        ctx->flags.hasRspPubKey = 0;
        ctx->flags.rspKeyFromCert = 0;
        ctx->rspPubKeyLen = 0;
    }

    /* RootHash in the chain header must name the configured root */
    if (ctx->trustedCASz > 0) {
        byte hash[WOLFSPDM_HASH_SIZE];

        rc = wolfSPDM_Sha384Hash(hash, ctx->trustedCA, ctx->trustedCASz,
            NULL, 0, NULL, 0);
        if (rc == WOLFSPDM_SUCCESS &&
                XMEMCMP(hash, ctx->certChain + 4, WOLFSPDM_HASH_SIZE) != 0) {
            rc = WOLFSPDM_E_CERT_FAIL;
        }
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_CertKey(ctx->trustedCA, ctx->trustedCASz, &key,
                &isCA);
            haveKey = (rc == WOLFSPDM_SUCCESS);
        }
        anchored = 1;
    }

    while (rc == WOLFSPDM_SUCCESS && pos < ctx->certChainLen) {
        word32 certSz = wolfSPDM_DerSeqLen(ctx->certChain + pos,
            ctx->certChainLen - pos);
        if (certSz == 0) {
            rc = WOLFSPDM_E_CERT_PARSE;
        }
        if (rc == WOLFSPDM_SUCCESS && haveKey) {
            rc = isCA ? wolfSPDM_CertSignedBy(ctx->certChain + pos, certSz,
                &key) : WOLFSPDM_E_CERT_FAIL;
        }
        if (rc == WOLFSPDM_SUCCESS) {
            rc = wolfSPDM_CertKey(ctx->certChain + pos, certSz, &key, &isCA);
            haveKey = (rc == WOLFSPDM_SUCCESS);
        }
        pos += certSz;
    }

    if (rc == WOLFSPDM_SUCCESS && !haveKey) {
        rc = WOLFSPDM_E_CERT_PARSE;
    }
    if (rc == WOLFSPDM_SUCCESS && ctx->flags.hasRspPubKey &&
            !ctx->flags.rspKeyFromCert) {
        byte leaf[WOLFSPDM_ECC_POINT_SIZE];

        leafSz = sizeof(leaf);
        rc = wolfSPDM_LeafKey(ctx, &key, leaf, &leafSz);
        if (rc == WOLFSPDM_SUCCESS && (ctx->rspPubKeyLen != leafSz ||
                XMEMCMP(ctx->rspPubKey, leaf, leafSz) != 0)) {
            wolfSPDM_DebugPrint(ctx, "Leaf key does not match pinned key\n");
            rc = WOLFSPDM_E_CERT_FAIL;
        }
    }
    else if (rc == WOLFSPDM_SUCCESS && !anchored &&
            !ctx->flags.allowUntrustedCert) {
        wolfSPDM_DebugPrint(ctx, "No trust anchor: set a root CA, pin the "
            "responder key, or allow untrusted certificates\n");
        rc = WOLFSPDM_E_CERT_FAIL;
    }
    /* Only a chain that passed every check supplies the responder key */
    else if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_LeafKey(ctx, &key, ctx->rspPubKey, &leafSz);
        if (rc == WOLFSPDM_SUCCESS) {
            ctx->rspPubKeyLen = leafSz;
            ctx->flags.hasRspPubKey = 1;
            ctx->flags.rspKeyFromCert = 1;
        }
    }

    return rc;
}

/* ----- Configuration and connect ----- */

int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz)
{
    if (ctx == NULL || derCerts == NULL || derCertsSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (derCertsSz > sizeof(ctx->trustedCA)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->trustedCA, derCerts, derCertsSz);
    ctx->trustedCASz = derCertsSz;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_AllowUntrustedCerts(WOLFSPDM_CTX* ctx, int allow)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctx->flags.allowUntrustedCert = (allow != 0);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetKeyExchangePref(WOLFSPDM_CTX* ctx, int advDhe, word16 kemMask)
{
    if (ctx == NULL || (advDhe == 0 && kemMask == 0)) {
        return WOLFSPDM_E_INVALID_ARG;
    }
#ifdef WOLFSPDM_HAVE_MLKEM
    if ((kemMask & (word16)~WOLFSPDM_MLKEM_SETS) != 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctx->kexAdvDhe = (byte)(advDhe != 0);
    ctx->kexAdvKem = kemMask;
#else
    if (kemMask != 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }
#endif
    return WOLFSPDM_SUCCESS;
}

/* GET_VERSION -> CAPS -> ALGO -> DIGESTS -> CERTIFICATE -> KEY_EXCHANGE ->
 * FINISH */
int wolfSPDM_ConnectStandard(WOLFSPDM_CTX* ctx)
{
    int slot = 0;
    int rc;

    /* A key taken from a previous responder's chain is not a trust anchor */
    if (ctx->flags.rspKeyFromCert) {
        ctx->flags.hasRspPubKey = 0;
        ctx->flags.rspKeyFromCert = 0;
        ctx->rspPubKeyLen = 0;
    }
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->lastPeerErrorCode = 0;
    /* No chunking or other peer capability until CAPABILITIES says so */
    ctx->rspCaps = 0;
    wolfSPDM_TranscriptReset(ctx);
#if !defined(WOLFSPDM_NO_MEAS) || !defined(WOLFSPDM_NO_CHALLENGE)
    wolfSPDM_AttestFree(ctx);
#endif

    SPDM_CONNECT_STEP(ctx, "GET_VERSION\n", wolfSPDM_GetVersion(ctx));
    SPDM_CONNECT_STEP(ctx, "GET_CAPABILITIES\n",
        wolfSPDM_GetCapabilities(ctx));
    SPDM_CONNECT_STEP(ctx, "NEGOTIATE_ALGORITHMS\n",
        wolfSPDM_NegotiateAlgorithms(ctx));
    SPDM_CONNECT_STEP(ctx, "GET_DIGESTS\n", wolfSPDM_GetDigests(ctx));

    /* Lowest populated slot, slot 0 if the responder reports none */
    while (slot < 7 && ctx->slotMask != 0 &&
            (ctx->slotMask & (1 << slot)) == 0) {
        slot++;
    }
    SPDM_CONNECT_STEP(ctx, "GET_CERTIFICATE\n",
        wolfSPDM_GetCertificate(ctx, slot));
    SPDM_CONNECT_STEP(ctx, "Validating certificate chain\n",
        wolfSPDM_ValidateCertChain(ctx));
    SPDM_CONNECT_STEP(ctx, "KEY_EXCHANGE\n", wolfSPDM_KeyExchange(ctx));
    SPDM_CONNECT_STEP(ctx, "FINISH\n", wolfSPDM_Finish(ctx));

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    wolfSPDM_DebugPrint(ctx, "SPDM session established, SessionID=0x%08x\n",
        ctx->sessionId);
    return WOLFSPDM_SUCCESS;
}

#endif /* !WOLFSPDM_NO_CERT */
