#!/bin/sh
# Replace a wolfTPM checkout's embedded SPDM sources with this wolfSPDM tree.
# wolfTPM keeps its own src/spdm/unit_test.c, so its regression tests run
# against this code.
set -e

usage() {
    echo "usage: $0 <wolfTPM source dir>" >&2
    exit 1
}

[ -n "$1" ] || usage
TPM=$1
SPDM=$(cd "$(dirname "$0")/.." && pwd)

[ -d "$TPM/src/spdm" ] && [ -d "$TPM/wolftpm/spdm" ] || {
    echo "error: $TPM does not look like a wolfTPM tree with src/spdm" >&2
    exit 1
}

rm -f "$TPM"/src/spdm/spdm_*.c "$TPM"/src/spdm/spdm_internal.h
cp "$SPDM"/src/spdm_*.c "$SPDM"/src/vendor/spdm_*.c \
   "$SPDM"/src/spdm_internal.h "$TPM"/src/spdm/

mkdir -p "$TPM"/wolfspdm
cp "$SPDM"/wolfspdm/spdm*.h "$TPM"/wolfspdm/
for h in "$SPDM"/wolfspdm/spdm*.h; do
    b=$(basename "$h")
    printf '#include <wolfspdm/%s>\n' "$b" > "$TPM/wolftpm/spdm/$b"
done

cat >> "$TPM/wolftpm/spdm/spdm_nations.h" <<'EOF'
#ifdef WOLFSPDM_NATIONS
    #define TPM_CC_Nations_SpdmIdentityKeySet  (0x20000708)
    #define TPM_PT_VENDOR_NATIONS_FIPS_SL2     (TPM_PT_VENDOR + 11)
    #define TPM_PT_VENDOR_NATIONS_IDENTITY_KEY (TPM_PT_VENDOR + 12)
#endif
EOF

echo "wolfSPDM overlaid onto $TPM"
