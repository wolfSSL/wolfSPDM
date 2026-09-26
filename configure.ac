AC_PREREQ([2.69])
AC_INIT([wolfspdm],[1.0.0],[support@wolfssl.com])
AC_CONFIG_SRCDIR([src/spdm_context.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 foreign subdir-objects -Wall -Werror])

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

# Checks for header files
AC_CHECK_HEADERS([stdint.h string.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# wolfSSL/wolfCrypt detection
AC_ARG_WITH([wolfssl],
    [AS_HELP_STRING([--with-wolfssl=PATH], [Path to wolfSSL installation])],
    [WOLFSSL_DIR=$withval],
    [WOLFSSL_DIR=""])

if test -n "$WOLFSSL_DIR"; then
    # Prepend local wolfSSL includes to ensure they take priority over system
    CPPFLAGS="-I$WOLFSSL_DIR -I$WOLFSSL_DIR/include $CPPFLAGS"
    LDFLAGS="-L$WOLFSSL_DIR/src/.libs -L$WOLFSSL_DIR/lib $LDFLAGS"
fi

AC_CHECK_LIB([wolfssl], [wc_InitRng], [],
    [AC_MSG_ERROR([wolfSSL library not found. Use --with-wolfssl=PATH])])

AC_CHECK_HEADER([wolfssl/wolfcrypt/ecc.h], [],
    [AC_MSG_ERROR([wolfSSL headers not found. Use --with-wolfssl=PATH])])

# wolfSSL minimum version: v5.8.0-stable. This is the oldest release the CI
# matrix in .github/workflows/wolfssl-versions.yml exercises end-to-end; older
# releases are not validated and may be missing API/curve fixes wolfSPDM relies
# on (ECDHE P-384, HKDF-SHA384, AES-256-GCM record protection).
AC_MSG_CHECKING([wolfSSL version >= v5.8.0])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <wolfssl/version.h>
    #if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX < 0x05008000
    #error "wolfSSL < v5.8.0"
    #endif
    int main(void) { return 0; }
]])],
[AC_MSG_RESULT([yes])],
[AC_MSG_RESULT([no])
 AC_MSG_ERROR([wolfSPDM requires wolfSSL >= v5.8.0-stable. Please upgrade wolfSSL.])])

# Debug mode
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug output])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "x$enable_debug" = "xyes"; then
    AC_DEFINE([WOLFSPDM_DEBUG], [1], [Enable debug output])
    CFLAGS="$CFLAGS -g -O0"
else
    CFLAGS="$CFLAGS -O2"
fi

# Dynamic memory allocation (enables wolfSPDM_New/XMALLOC)
AC_ARG_ENABLE([dynamic-mem],
    [AS_HELP_STRING([--enable-dynamic-mem], [Enable dynamic memory allocation (wolfSPDM_New)])],
    [enable_dynamic_mem=$enableval],
    [enable_dynamic_mem=no])

if test "x$enable_dynamic_mem" = "xyes"; then
    AC_DEFINE([WOLFSPDM_DYNAMIC_MEMORY], [1], [Enable dynamic memory allocation])
fi

# MCTP secured messages carry the standard requester; a pure TCG build drops both
AC_ARG_ENABLE([mctp],
    [AS_HELP_STRING([--disable-mctp], [Drop MCTP secured messages and the standard requester for a pure TCG build (default: enabled)])],
    [enable_mctp=$enableval],
    [enable_mctp=yes])

# Standard certificate-based requester (DSP0274 flow for non-TPM responders)
AC_ARG_ENABLE([cert],
    [AS_HELP_STRING([--disable-cert], [Disable the standard certificate-based requester (default: enabled)])],
    [enable_cert=$enableval],
    [enable_cert=yes])

if test "x$enable_mctp" = "xno"; then
    enable_cert=no
fi

if test "x$enable_cert" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_CERT], [1], [Disable the standard certificate requester])
fi
AM_CONDITIONAL([BUILD_CERT], [test "x$enable_cert" = "xyes"])

AC_ARG_ENABLE([heartbeat],
    [AS_HELP_STRING([--disable-heartbeat], [Disable HEARTBEAT session keep-alive (default: enabled)])],
    [enable_heartbeat=$enableval],
    [enable_heartbeat=yes])

if test "x$enable_heartbeat" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_HEARTBEAT], [1], [Disable HEARTBEAT])
fi

AC_ARG_ENABLE([app-data],
    [AS_HELP_STRING([--disable-app-data], [Disable the MCTP application data API (default: enabled)])],
    [enable_app_data=$enableval],
    [enable_app_data=yes])

if test "x$enable_mctp" = "xno"; then
    enable_app_data=no
fi
if test "x$enable_app_data" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_APP_DATA], [1], [Disable the application data API])
fi

AC_ARG_ENABLE([chunking],
    [AS_HELP_STRING([--disable-chunking], [Disable CHUNK_SEND/CHUNK_GET large message chunking (default: enabled)])],
    [enable_chunking=$enableval],
    [enable_chunking=yes])

if test "x$enable_chunking" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_CHUNK], [1], [Disable large message chunking])
fi

AC_ARG_ENABLE([meas],
    [AS_HELP_STRING([--disable-meas], [Disable GET_MEASUREMENTS attestation (default: enabled)])],
    [enable_meas=$enableval],
    [enable_meas=yes])

if test "x$enable_meas" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_MEAS], [1], [Disable GET_MEASUREMENTS])
fi

AC_ARG_ENABLE([challenge],
    [AS_HELP_STRING([--disable-challenge], [Disable CHALLENGE attestation (default: enabled)])],
    [enable_challenge=$enableval],
    [enable_challenge=yes])

if test "x$enable_challenge" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_CHALLENGE], [1], [Disable CHALLENGE])
fi

AC_ARG_ENABLE([key-update],
    [AS_HELP_STRING([--disable-key-update], [Disable KEY_UPDATE session key rotation (default: enabled)])],
    [enable_key_update=$enableval],
    [enable_key_update=yes])

if test "x$enable_key_update" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_KEY_UPDATE], [1], [Disable KEY_UPDATE])
fi

# TCG SPDM binding (TPM transport). Nuvoton/Nations imply it.
AC_ARG_ENABLE([tcg],
    [AS_HELP_STRING([--enable-tcg], [Enable the TCG SPDM binding (default: disabled)])],
    [enable_tcg=$enableval],
    [enable_tcg=no])

AC_ARG_ENABLE([psk],
    [AS_HELP_STRING([--enable-psk], [Enable SPDM PSK_EXCHANGE/PSK_FINISH (default: disabled)])],
    [enable_psk=$enableval],
    [enable_psk=no])

AC_ARG_ENABLE([nuvoton],
    [AS_HELP_STRING([--enable-nuvoton], [Enable Nuvoton NPCT75x SPDM vendor commands (default: disabled)])],
    [enable_nuvoton=$enableval],
    [enable_nuvoton=no])

AC_ARG_ENABLE([nations],
    [AS_HELP_STRING([--enable-nations], [Enable Nations NS350 SPDM vendor commands (default: disabled)])],
    [enable_nations=$enableval],
    [enable_nations=no])

AC_ARG_ENABLE([responder],
    [AS_HELP_STRING([--enable-responder], [Enable the SPDM responder (default: disabled)])],
    [enable_responder=$enableval],
    [enable_responder=no])

if test "x$enable_nuvoton" = "xyes" || test "x$enable_nations" = "xyes"; then
    enable_tcg=yes
fi
if test "x$enable_nations" = "xyes"; then
    enable_psk=yes
fi
if test "x$enable_psk" = "xyes" && test "x$enable_tcg" != "xyes"; then
    AC_MSG_ERROR([--enable-psk requires --enable-tcg (PSK handshake uses TCG SPDM binding framing)])
fi
if test "x$enable_responder" = "xyes" && test "x$enable_tcg" != "xyes"; then
    AC_MSG_ERROR([--enable-responder requires --enable-tcg])
fi
if test "x$enable_mctp" = "xno"; then
    if test "x$enable_tcg" != "xyes"; then
        AC_MSG_ERROR([--disable-mctp requires --enable-tcg or a TCG vendor])
    fi
    AC_DEFINE([WOLFSPDM_NO_MCTP], [1], [Drop MCTP secured messages])
fi

if test "x$enable_tcg" = "xyes"; then
    AC_DEFINE([WOLFSPDM_TCG], [1], [Enable the TCG SPDM binding])
fi
if test "x$enable_psk" = "xyes"; then
    AC_DEFINE([WOLFSPDM_PSK], [1], [Enable SPDM PSK mode])
fi
if test "x$enable_nuvoton" = "xyes"; then
    AC_DEFINE([WOLFSPDM_NUVOTON], [1], [Enable Nuvoton SPDM vendor commands])
fi
if test "x$enable_nations" = "xyes"; then
    AC_DEFINE([WOLFSPDM_NATIONS], [1], [Enable Nations SPDM vendor commands])
fi
if test "x$enable_responder" = "xyes"; then
    AC_DEFINE([WOLFSPDM_RESPONDER], [1], [Enable the SPDM responder])
fi

AM_CONDITIONAL([BUILD_TCG], [test "x$enable_tcg" = "xyes"])
AM_CONDITIONAL([BUILD_PSK], [test "x$enable_psk" = "xyes"])
AM_CONDITIONAL([BUILD_NUVOTON], [test "x$enable_nuvoton" = "xyes"])
AM_CONDITIONAL([BUILD_NATIONS], [test "x$enable_nations" = "xyes"])
AM_CONDITIONAL([BUILD_RESPONDER], [test "x$enable_responder" = "xyes"])

# Output files
AC_CONFIG_FILES([Makefile wolfspdm.pc])
AC_OUTPUT

# These ride on the certificate flow and are compiled out without it
if test "x$enable_cert" = "xno"; then
    enable_chunking=no
    enable_meas=no
    enable_challenge=no
fi

echo ""
echo "wolfSPDM configuration summary:"
echo "  Version:     $PACKAGE_VERSION"
echo "  Debug:       $enable_debug"
echo "  Dynamic mem: $enable_dynamic_mem"
echo "  MCTP:        $enable_mctp"
echo "  Standard:    $enable_cert"
echo "  App data:    $enable_app_data"
echo "  Chunking:    $enable_chunking"
echo "  Meas:        $enable_meas"
echo "  Challenge:   $enable_challenge"
echo "  Heartbeat:   $enable_heartbeat"
echo "  Key update:  $enable_key_update"
echo "  TCG:         $enable_tcg"
echo "  PSK:         $enable_psk"
echo "  Nuvoton:     $enable_nuvoton"
echo "  Nations:     $enable_nations"
echo "  Responder:   $enable_responder"
echo "  wolfSSL:     ${WOLFSSL_DIR:-system}"
echo ""
