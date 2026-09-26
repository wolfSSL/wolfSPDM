/* spdm_types.h
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

#ifndef WOLFSPDM_TYPES_H
#define WOLFSPDM_TYPES_H

/* wolfSSL options MUST be included first */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(HAVE_CONFIG_H) && !defined(WOLFTPM_SPDM) && \
    !defined(WOLFSPDM_USER_SETTINGS)
    #include <wolfspdm/options.h>
#endif

/* wolfTPM's configure spells these switches with its own prefix */
#if defined(WOLFTPM_SPDM_TCG) && !defined(WOLFSPDM_TCG)
    #define WOLFSPDM_TCG
#endif
#if defined(WOLFTPM_SPDM_PSK) && !defined(WOLFSPDM_PSK)
    #define WOLFSPDM_PSK
#endif
#if defined(WOLFTPM_SPDM_RESPONDER) && !defined(WOLFSPDM_RESPONDER)
    #define WOLFSPDM_RESPONDER
#endif
#if defined(DEBUG_WOLFTPM) && !defined(WOLFSPDM_DEBUG)
    #define WOLFSPDM_DEBUG
#endif
#if defined(WOLFTPM_SMALL_STACK) && !defined(WOLFSPDM_DYNAMIC_MEMORY)
    #define WOLFSPDM_DYNAMIC_MEMORY
#endif

#if defined(BUILDING_WOLFTPM) || defined(WOLFTPM_SPDM)
    #include <wolftpm/visibility.h>
    #define WOLFSPDM_API      WOLFTPM_API
    #define WOLFSPDM_LOCAL    WOLFTPM_LOCAL
    #define WOLFSPDM_TEST_API WOLFTPM_TEST_API
#else
    #ifndef WOLFSPDM_API
        #define WOLFSPDM_API
    #endif
    #ifndef WOLFSPDM_LOCAL
        #define WOLFSPDM_LOCAL
    #endif
    #ifndef WOLFSPDM_TEST_API
        #define WOLFSPDM_TEST_API WOLFSPDM_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Include wolfSSL types */
#ifndef WOLFSSL_TYPES
    #include <wolfssl/wolfcrypt/types.h>
#endif

/* ----- SPDM Protocol Constants (DMTF DSP0274 / DSP0277) ----- */

/* SPDM Version Numbers (used in version negotiation and key derivation) */
#define SPDM_VERSION_10             0x10    /* GET_VERSION always uses 1.0 */
#define SPDM_VERSION_12             0x12    /* SPDM 1.2 */
#define SPDM_VERSION_13             0x13    /* SPDM 1.3 */
#define SPDM_VERSION_14             0x14    /* SPDM 1.4 */

/* SPDM Request Codes (used by this implementation) */
#define SPDM_GET_VERSION            0x84
#define SPDM_KEY_EXCHANGE           0xE4
#define SPDM_FINISH                 0xE5
#define SPDM_END_SESSION            0xEC
#define SPDM_VENDOR_DEFINED_REQUEST 0xFE

/* SPDM Response Codes (used by this implementation) */
#define SPDM_VERSION                0x04
#define SPDM_KEY_EXCHANGE_RSP       0x64
#define SPDM_FINISH_RSP             0x65
#define SPDM_END_SESSION_ACK        0x6C
#define SPDM_ERROR                  0x7F

/* SPDM Error Codes (in Param1 of ERROR response) */
#define SPDM_ERROR_INVALID_REQUEST      0x01
#define SPDM_ERROR_BUSY                 0x03
#define SPDM_ERROR_UNEXPECTED_REQUEST   0x04
#define SPDM_ERROR_UNSPECIFIED          0x05
#define SPDM_ERROR_DECRYPT_ERROR        0x06
#define SPDM_ERROR_UNSUPPORTED_REQUEST  0x07
#define SPDM_ERROR_REQUEST_IN_FLIGHT    0x08
#define SPDM_ERROR_INVALID_RESPONSE     0x09
#define SPDM_ERROR_SESSION_LIMIT        0x0A
#define SPDM_ERROR_SESSION_REQUIRED     0x0B
#define SPDM_ERROR_RESET_REQUIRED       0x0C
#define SPDM_ERROR_RESPONSE_TOO_LARGE   0x0D
#define SPDM_ERROR_REQUEST_TOO_LARGE    0x0E
#define SPDM_ERROR_LARGE_RESPONSE       0x0F
#define SPDM_ERROR_MSG_LOST             0x10
#define SPDM_ERROR_MAJOR_VERSION_MISMATCH 0x41
#define SPDM_ERROR_RESPONSE_NOT_READY   0x42
#define SPDM_ERROR_REQUEST_RESYNCH      0x43

/* Algorithm Set B Fixed Parameters (FIPS 140-3 Level 3 compliant)
 * P-384 ECDSA/ECDH, SHA-384, AES-256-GCM, HKDF */
#define WOLFSPDM_HASH_SIZE          48  /* SHA-384 output size */
#define WOLFSPDM_ECC_KEY_SIZE       48  /* P-384 coordinate size */
#define WOLFSPDM_ECC_POINT_SIZE     (2 * WOLFSPDM_ECC_KEY_SIZE)  /* P-384 X||Y */
#define WOLFSPDM_ECC_SIG_SIZE       (2 * WOLFSPDM_ECC_KEY_SIZE)  /* ECDSA r||s */
#define WOLFSPDM_AEAD_KEY_SIZE      32  /* AES-256 key size */
#define WOLFSPDM_AEAD_IV_SIZE       12  /* AES-GCM IV size */
#define WOLFSPDM_AEAD_TAG_SIZE      16  /* AES-GCM tag size */
/* Secured record bytes around a message: up to 32 of header and tag plus
 * WOLFSPDM_SECURED_PAD of AppDataLength, MCTP type and padding */
#define WOLFSPDM_AEAD_OVERHEAD      (32 + WOLFSPDM_SECURED_PAD)

/* ----- Buffer/Message Size Limits ----- */

#define WOLFSPDM_MAX_MSG_SIZE       4096    /* Maximum SPDM message size */
#define WOLFSPDM_MAX_TRANSCRIPT     4096    /* Maximum transcript buffer */
#define WOLFSPDM_RANDOM_SIZE        32      /* Random data in KEY_EXCHANGE */

/* ----- MCTP Transport Constants ----- */

#define MCTP_MESSAGE_TYPE_SPDM      0x05    /* SPDM over MCTP */

/* ----- Key Derivation Labels (SPDM 1.2 per DSP0277) ----- */

#define SPDM_BIN_CONCAT_PREFIX_12   "spdm1.2 "
#define SPDM_BIN_CONCAT_PREFIX_13   "spdm1.3 "
#define SPDM_BIN_CONCAT_PREFIX_14   "spdm1.4 "
#define SPDM_BIN_CONCAT_PREFIX_LEN  8

#define SPDM_LABEL_REQ_HS_DATA      "req hs data"
#define SPDM_LABEL_RSP_HS_DATA      "rsp hs data"
#define SPDM_LABEL_REQ_DATA         "req app data"
#define SPDM_LABEL_RSP_DATA         "rsp app data"
#define SPDM_LABEL_FINISHED         "finished"
#define SPDM_LABEL_KEY              "key"
#define SPDM_LABEL_IV               "iv"

/* ----- Buffer Size Macros (overridable) ----- */

#ifndef WOLFSPDM_KEY_EX_TX_SZ
#define WOLFSPDM_KEY_EX_TX_SZ      192  /* KEY_EXCHANGE request (~158 bytes) */
#endif
#ifndef WOLFSPDM_KEY_EX_RX_SZ
#define WOLFSPDM_KEY_EX_RX_SZ      384  /* KEY_EXCHANGE_RSP (~302 bytes) */
#endif
#ifndef WOLFSPDM_FINISH_BUF_SZ
#define WOLFSPDM_FINISH_BUF_SZ     152  /* FINISH mutual auth (~148 bytes) */
#endif
#ifndef WOLFSPDM_VENDOR_BUF_SZ
#define WOLFSPDM_VENDOR_BUF_SZ     256  /* Vendor command message/payload */
#endif
#ifndef WOLFSPDM_VENDOR_RX_SZ
#define WOLFSPDM_VENDOR_RX_SZ      512  /* Vendor response buffer */
#endif
#ifndef WOLFSPDM_PUBKEY_BUF_SZ
#define WOLFSPDM_PUBKEY_BUF_SZ     256  /* Public key buffer */
#endif

/* ----- TPM Build Profile ----- */

/* Built inside wolfTPM: the TPM only speaks the TCG binding */
#if defined(WOLFTPM_SPDM) && !defined(WOLFSPDM_PROFILE_TPM)
    #define WOLFSPDM_PROFILE_TPM
#endif
#if defined(WOLFSPDM_PROFILE_TPM) && !defined(WOLFSPDM_NO_CERT)
    #define WOLFSPDM_NO_CERT
#endif
#if defined(NO_ASN) && !defined(WOLFSPDM_NO_CERT)
    #define WOLFSPDM_NO_CERT
#endif
/* A pure TCG build drops MCTP secured messages and the standard requester */
#if defined(WOLFSPDM_NO_MCTP) && !defined(WOLFSPDM_NO_CERT)
    #define WOLFSPDM_NO_CERT
#endif
/* MCTP records may carry up to 32 random bytes (DSP0277); the TCG binding
 * only pads to 16, and wolfTPM speaks nothing else */
#ifdef WOLFSPDM_PROFILE_TPM
    #define WOLFSPDM_SECURED_PAD    16
#else
    #define WOLFSPDM_SECURED_PAD    48
#endif
#if defined(WOLFSPDM_PROFILE_TPM) && !defined(WOLFSPDM_NO_HEARTBEAT)
    #define WOLFSPDM_NO_HEARTBEAT
#endif
#if defined(WOLFSPDM_PROFILE_TPM) && !defined(WOLFSPDM_NO_KEY_UPDATE)
    #define WOLFSPDM_NO_KEY_UPDATE
#endif
/* Application messages ride MCTP; WOLFSPDM_LEAN is the older spelling */
#if (defined(WOLFSPDM_PROFILE_TPM) || defined(WOLFSPDM_NO_MCTP) || \
     defined(WOLFSPDM_LEAN)) && !defined(WOLFSPDM_NO_APP_DATA)
    #define WOLFSPDM_NO_APP_DATA
#endif
/* Attestation needs the certificate flow (VCA transcript, chain hash) */
#if defined(WOLFSPDM_NO_CERT) && !defined(WOLFSPDM_NO_MEAS)
    #define WOLFSPDM_NO_MEAS
#endif
#if defined(WOLFSPDM_NO_CERT) && !defined(WOLFSPDM_NO_CHALLENGE)
    #define WOLFSPDM_NO_CHALLENGE
#endif
/* Chunking is negotiated in CAPABILITIES */
#if defined(WOLFSPDM_NO_CERT) && !defined(WOLFSPDM_NO_CHUNK)
    #define WOLFSPDM_NO_CHUNK
#endif

/* ----- Session Keep-Alive and Key Rotation ----- */

#define SPDM_CAP_HBEAT_CAP          0x00002000
#define SPDM_CAP_KEY_UPD_CAP        0x00004000

#ifndef WOLFSPDM_NO_HEARTBEAT
#define SPDM_HEARTBEAT              0xE8
#define SPDM_HEARTBEAT_ACK          0x68
#define WOLFSPDM_HBEAT_REQ_CAP      SPDM_CAP_HBEAT_CAP
#else
#define WOLFSPDM_HBEAT_REQ_CAP      0
#endif

#ifndef WOLFSPDM_NO_KEY_UPDATE
#define SPDM_KEY_UPDATE             0xE9
#define SPDM_KEY_UPDATE_ACK         0x69
#define SPDM_KEY_UPDATE_OP_UPDATE_KEY      1
#define SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS 2
#define SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY  3
#define SPDM_LABEL_UPDATE           "traffic upd"
#define WOLFSPDM_KEY_UPD_REQ_CAP    SPDM_CAP_KEY_UPD_CAP
#else
#define WOLFSPDM_KEY_UPD_REQ_CAP    0
#endif

#ifndef WOLFSPDM_NO_CERT
/* ----- Standard (certificate) Requester, DSP0274 ----- */

#define SPDM_GET_DIGESTS            0x81
#define SPDM_GET_CERTIFICATE        0x82
#define SPDM_GET_CAPABILITIES       0xE1
#define SPDM_NEGOTIATE_ALGORITHMS   0xE3
#define SPDM_DIGESTS                0x01
#define SPDM_CERTIFICATE            0x02
#define SPDM_CAPABILITIES           0x61
#define SPDM_ALGORITHMS             0x63

/* CAPABILITIES flags */
#define SPDM_CAP_CERT_CAP           0x00000002
#define SPDM_CAP_ENCRYPT_CAP        0x00000040
#define SPDM_CAP_MAC_CAP            0x00000080
#define SPDM_CAP_KEY_EX_CAP         0x00000200

#ifndef WOLFSPDM_REQ_CAPS
#define WOLFSPDM_REQ_CAPS  (SPDM_CAP_ENCRYPT_CAP | SPDM_CAP_MAC_CAP | \
                            SPDM_CAP_KEY_EX_CAP | WOLFSPDM_HBEAT_REQ_CAP | \
                            WOLFSPDM_KEY_UPD_REQ_CAP | WOLFSPDM_CHUNK_REQ_CAP)
#endif

/* Algorithm Set B selections */
#define SPDM_HASH_ALGO_SHA_384      0x00000002
#define SPDM_ASYM_ALGO_ECDSA_P384   0x00000080
#define SPDM_DHE_ALGO_SECP384R1     0x0010
#define SPDM_AEAD_ALGO_AES_256_GCM  0x0002
#define SPDM_KEY_SCHEDULE_SPDM      0x0001

/* ALGORITHMS AlgStruct AlgType values (DSP0274 Table 16) */
#define SPDM_ALG_TYPE_DHE           2
#define SPDM_ALG_TYPE_AEAD          3
#define SPDM_ALG_TYPE_REQ_BASE_ASYM 4
#define SPDM_ALG_TYPE_KEY_SCHEDULE  5

/* SPDM cert chain header: Length(2) + Reserved(2) + RootHash(48) */
#define WOLFSPDM_CERT_CHAIN_HDR_SZ  (4 + WOLFSPDM_HASH_SIZE)

#ifndef WOLFSPDM_MAX_CERT_CHAIN
#define WOLFSPDM_MAX_CERT_CHAIN     4096
#endif
#ifndef WOLFSPDM_MAX_TRUSTED_CA
#define WOLFSPDM_MAX_TRUSTED_CA     2048
#endif
#endif /* !WOLFSPDM_NO_CERT */

/* ----- Attestation: measurements and challenge ----- */

#ifndef WOLFSPDM_NO_MEAS
#define SPDM_GET_MEASUREMENTS       0xE0
#define SPDM_MEASUREMENTS           0x60
#define SPDM_CAP_MEAS_CAP_NO_SIG    0x00000008
#define SPDM_CAP_MEAS_CAP_SIG       0x00000010
#define SPDM_MEAS_REQUEST_SIG_BIT   0x01
#define SPDM_MEAS_OPERATION_TOTAL_NUMBER 0x00
#define SPDM_MEAS_OPERATION_ALL     0xFF
#define SPDM_MEAS_SPEC_DMTF         0x01
#define WOLFSPDM_MEAS_BLOCK_HDR_SZ  4   /* Index + MeasSpec + Size(2) */
#ifndef WOLFSPDM_MAX_MEAS_RECORD
#define WOLFSPDM_MAX_MEAS_RECORD    1024
#endif
#endif /* !WOLFSPDM_NO_MEAS */

#ifndef WOLFSPDM_NO_CHALLENGE
#define SPDM_CHALLENGE              0x83
#define SPDM_CHALLENGE_AUTH         0x03
#define SPDM_CAP_CHAL_CAP           0x00000004
#define SPDM_MEAS_SUMMARY_HASH_NONE 0x00
#define SPDM_MEAS_SUMMARY_HASH_TCB  0x01
#define SPDM_MEAS_SUMMARY_HASH_ALL  0xFF
#endif /* !WOLFSPDM_NO_CHALLENGE */

/* ----- Large message chunking (CHUNK_SEND / CHUNK_GET) ----- */

#define SPDM_MIN_DATA_TRANSFER_SIZE 42

/* Largest single message sent or received. MaxSPDMmsgSize stays
 * WOLFSPDM_MAX_MSG_SIZE, so anything smaller relies on chunking. */
#ifndef WOLFSPDM_DATA_TRANSFER_SIZE
#define WOLFSPDM_DATA_TRANSFER_SIZE WOLFSPDM_MAX_MSG_SIZE
#endif
#if WOLFSPDM_DATA_TRANSFER_SIZE < SPDM_MIN_DATA_TRANSFER_SIZE || \
    WOLFSPDM_DATA_TRANSFER_SIZE > WOLFSPDM_MAX_MSG_SIZE
    #error "WOLFSPDM_DATA_TRANSFER_SIZE must be 42 to WOLFSPDM_MAX_MSG_SIZE"
#endif
#if defined(WOLFSPDM_NO_CHUNK) && \
    WOLFSPDM_DATA_TRANSFER_SIZE != WOLFSPDM_MAX_MSG_SIZE
    #error "WOLFSPDM_DATA_TRANSFER_SIZE below WOLFSPDM_MAX_MSG_SIZE needs chunking"
#endif

#ifndef WOLFSPDM_NO_CHUNK
#define SPDM_CHUNK_SEND             0x85
#define SPDM_CHUNK_GET              0x86
#define SPDM_CHUNK_SEND_ACK         0x05
#define SPDM_CHUNK_RESPONSE         0x06
#define SPDM_CAP_CHUNK_CAP          0x00020000
#define SPDM_CHUNK_LAST_CHUNK       0x01    /* CHUNK_SEND, CHUNK_RESPONSE */
#define SPDM_CHUNK_EARLY_ERROR      0x01    /* CHUNK_SEND_ACK */
#define WOLFSPDM_CHUNK_REQ_CAP      SPDM_CAP_CHUNK_CAP
#else
#define WOLFSPDM_CHUNK_REQ_CAP      0
#endif

/* ----- TCG Build Option ----- */

/* Nuvoton or Nations enables TCG SPDM binding; future chips can set directly */
#if (defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)) && \
    !defined(WOLFSPDM_TCG)
    #define WOLFSPDM_TCG
#endif

#if defined(WOLFSPDM_NO_MCTP) && !defined(WOLFSPDM_TCG)
    #error "WOLFSPDM_NO_MCTP leaves no transport without the TCG binding"
#endif

/* Requester identity key for TCG GIVE_PUB mutual auth; wolfTPM builds keep
 * the API whether or not the binding is compiled */
#if (defined(WOLFSPDM_TCG) || defined(WOLFSPDM_PROFILE_TPM)) && \
    !defined(WOLFSPDM_MUTUAL_AUTH)
    #define WOLFSPDM_MUTUAL_AUTH
#endif

/* Single-message buffers; the TCG binding is never chunked */
#ifdef WOLFSPDM_TCG
    #define WOLFSPDM_XFER_MSG_SIZE  WOLFSPDM_MAX_MSG_SIZE
#else
    #define WOLFSPDM_XFER_MSG_SIZE  WOLFSPDM_DATA_TRANSFER_SIZE
#endif

/* ----- PSK Build Option ----- */

/* Nations build enables PSK by default; can also be set independently */
#if defined(WOLFSPDM_NATIONS) && !defined(WOLFSPDM_PSK)
    #define WOLFSPDM_PSK
#endif

/* ----- PSK Message Codes (SPDM 1.2+ DSP0274) ----- */

#define SPDM_PSK_EXCHANGE           0xE6
#define SPDM_PSK_EXCHANGE_RSP       0x66
#define SPDM_PSK_FINISH             0xE7
#define SPDM_PSK_FINISH_RSP         0x67

/* ----- PSK Size Limits ----- */

#define WOLFSPDM_PSK_MAX_SIZE       64  /* Max PSK size (Nations NS350) */
#define WOLFSPDM_PSK_HINT_MAX       32  /* Max PSK hint size */
#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_TYPES_H */
