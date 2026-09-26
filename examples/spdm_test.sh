#!/bin/bash
#
# spdm_test.sh - SPDM emulator test script
#
# Tests SPDM protocol with libspdm emulator (session + measurements + challenge
# + heartbeat + key update) across SPDM versions 1.2, 1.3, and 1.4.
#
# Usage:
#   ./spdm_test.sh                     # Run emulator tests
#   ./spdm_test.sh [path-to-spdm_demo] # Custom spdm_demo path
#

SPDM_DEMO="./examples/spdm_demo"
PASS=0
FAIL=0
SKIP=0
TOTAL=0
EMU_PID=""
EMU_LOG="/tmp/spdm_emu_$$.log"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

usage() {
    echo "Usage: $0 [path-to-spdm_demo]"
    echo ""
    echo "Runs SPDM emulator tests (session, measurements, challenge,"
    echo "heartbeat, key update) across SPDM versions 1.2, 1.3, and 1.4."
    echo ""
    echo "Expects spdm_responder_emu to be found via:"
    echo "  1. SPDM_EMU_PATH environment variable"
    echo "  2. ../spdm-emu/build/bin/ (cloned next to wolfSPDM)"
    echo "  3. spdm_responder_emu in PATH"
    echo ""
    echo "SPDM_EMU_ARGS adds responder options, e.g. --cap ...,CHUNK"
}

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # Treat as path to spdm_demo
            SPDM_DEMO="$arg"
            ;;
    esac
done

# Find spdm_responder_emu
find_emu() {
    # 1. Check SPDM_EMU_PATH
    if [ -n "$SPDM_EMU_PATH" ]; then
        if [ -x "$SPDM_EMU_PATH/spdm_responder_emu" ]; then
            EMU_DIR="$SPDM_EMU_PATH"
            EMU_BIN="$SPDM_EMU_PATH/spdm_responder_emu"
            return 0
        elif [ -x "$SPDM_EMU_PATH" ]; then
            EMU_DIR="$(dirname "$SPDM_EMU_PATH")"
            EMU_BIN="$SPDM_EMU_PATH"
            return 0
        fi
    fi

    # 2. Check common relative paths
    for dir in \
        "../spdm-emu/build/bin" \
        "../../spdm-emu/build/bin" \
        "$HOME/spdm-emu/build/bin"; do
        if [ -x "$dir/spdm_responder_emu" ]; then
            EMU_DIR="$dir"
            EMU_BIN="$dir/spdm_responder_emu"
            return 0
        fi
    done

    # 3. Check PATH
    if command -v spdm_responder_emu >/dev/null 2>&1; then
        EMU_BIN="$(command -v spdm_responder_emu)"
        EMU_DIR="$(dirname "$EMU_BIN")"
        return 0
    fi

    return 1
}

# Start the emulator (must run from its bin dir for cert files)
# Usage: start_emu [version]
start_emu() {
    local ver="${1:-1.2}"
    echo "  Starting spdm_responder_emu (SPDM $ver)..."

    # Reap any emulator we started ourselves earlier (do NOT kill unrelated
    # spdm_responder_emu instances - a developer may have one in another
    # shell). Only the previous $EMU_PID is fair game.
    if [ -n "$EMU_PID" ] && kill -0 "$EMU_PID" 2>/dev/null; then
        kill -9 "$EMU_PID" 2>/dev/null
        wait "$EMU_PID" 2>/dev/null
        EMU_PID=""
        sleep 1
    fi

    # If port 2323 is still occupied, it isn't ours - surface that clearly
    # rather than kicking the unrelated holder off the port. Try ss, then
    # netstat, then lsof - skip the check (with a warning) if none exist.
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ":2323 "; then
            echo -e "  ${RED}ERROR: Port 2323 already in use by another process${NC}"
            ss -tlnp 2>/dev/null | grep ":2323 "
            return 1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tlnp 2>/dev/null | grep -q ":2323 "; then
            echo -e "  ${RED}ERROR: Port 2323 already in use by another process${NC}"
            netstat -tlnp 2>/dev/null | grep ":2323 "
            return 1
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -iTCP:2323 -sTCP:LISTEN >/dev/null 2>&1; then
            echo -e "  ${RED}ERROR: Port 2323 already in use by another process${NC}"
            lsof -iTCP:2323 -sTCP:LISTEN
            return 1
        fi
    else
        echo -e "  ${YELLOW}WARNING: ss/netstat/lsof unavailable - skipping port-in-use check${NC}"
    fi

    # Verify cert/key files exist in EMU_DIR (spdm-emu uses lowercase 'ecp384')
    if [ ! -d "$EMU_DIR/ecp384" ] && [ ! -d "$EMU_DIR/EcP384" ]; then
        echo -e "  ${YELLOW}WARNING: Certificate files may be missing in $EMU_DIR${NC}"
        echo "  Run 'make copy_sample_key' in the spdm-emu build directory"
    fi

    # SPDM_EMU_ARGS adds responder options, e.g. --cap ...,CHUNK
    (cd "$EMU_DIR" && ./spdm_responder_emu --ver "$ver" \
        --hash SHA_384 --asym ECDSA_P384 \
        --dhe SECP_384_R1 --aead AES_256_GCM $SPDM_EMU_ARGS \
        >"$EMU_LOG" 2>&1) &
    EMU_PID=$!
    sleep 2

    # Verify it started
    if ! kill -0 "$EMU_PID" 2>/dev/null; then
        echo -e "  ${RED}ERROR: Emulator failed to start${NC}"
        if [ -s "$EMU_LOG" ]; then
            echo "  Emulator output:"
            sed 's/^/    /' "$EMU_LOG" | head -20
        fi
        EMU_PID=""
        return 1
    fi
    return 0
}

# Stop the emulator
stop_emu() {
    if [ -n "$EMU_PID" ]; then
        kill "$EMU_PID" 2>/dev/null
        wait "$EMU_PID" 2>/dev/null
        EMU_PID=""
    fi
}

# Cleanup on exit
cleanup() {
    stop_emu
    rm -f "$EMU_LOG"
}
trap cleanup EXIT

# Run a test (start/stop emulator around each test)
# Usage: run_test <name> <emu_ver> <command...>
run_test() {
    local name="$1"
    local emu_ver="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"

    if ! start_emu "$emu_ver"; then
        echo -e "  ${RED}FAIL (emulator start)${NC}"
        FAIL=$((FAIL + 1))
        echo ""
        return 1
    fi

    "$@"
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "  ${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    elif [ $rc -eq 77 ]; then
        echo -e "  ${YELLOW}SKIP (not built)${NC}"
        SKIP=$((SKIP + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi

    stop_emu
    sleep 1  # Let port release
    echo ""
}

# Check spdm_demo exists
if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found or not executable"
    usage
    exit 1
fi

# ==========================================================================
# Emulator Tests
# ==========================================================================
echo "=== SPDM Emulator Tests ==="

if ! find_emu; then
    echo -e "${RED}ERROR: spdm_responder_emu not found${NC}"
    echo ""
    echo "Set SPDM_EMU_PATH or clone spdm-emu next to wolfSPDM:"
    echo "  git clone https://github.com/DMTF/spdm-emu.git ../spdm-emu"
    echo "  cd ../spdm-emu && mkdir build && cd build"
    echo "  cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls .."
    echo "  make copy_sample_key && make"
    exit 1
fi

echo "Using emulator: $EMU_BIN"
echo "Using demo:     $SPDM_DEMO"
echo ""

# Test each SPDM version (1.2, 1.3, 1.4) against the emulator
for VER in 1.2 1.3 1.4; do
    echo "--- SPDM $VER ---"

    # Session establishment
    run_test "Session (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --emu --ver "$VER"

    # Session + signed measurements
    run_test "Signed measurements (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --meas --ver "$VER"

    # Session + unsigned measurements
    run_test "Unsigned measurements (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --meas --no-sig --ver "$VER"

    # Challenge authentication (sessionless)
    run_test "Challenge (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --challenge --ver "$VER"

    # Session + heartbeat
    run_test "Heartbeat (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --emu --heartbeat --ver "$VER"

    # Session + key update
    run_test "Key update (SPDM $VER)" "$VER" \
        "$SPDM_DEMO" --emu --key-update --ver "$VER"

    echo ""
done

# ==========================================================================
# Summary
# ==========================================================================
echo "=== Results ==="
echo "Total: $TOTAL  Passed: $PASS  Skipped: $SKIP  Failed: $FAIL"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"
    exit 1
fi
