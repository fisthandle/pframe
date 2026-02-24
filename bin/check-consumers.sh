#!/usr/bin/env bash
set -euo pipefail

PFRAME_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEV_DIR="$(dirname "$PFRAME_DIR")"

SRC_PFRAME="$PFRAME_DIR/src/PFrame.php"
SRC_TESTING="$PFRAME_DIR/src/PFrameTesting.php"

RED='\033[0;31m'
GREEN='\033[0;32m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

has_outdated=0

check_file() {
    local src="$1"
    local dst="$2"
    local proj="$3"
    local filename="$4"

    if [[ ! -f "$dst" ]]; then
        printf "  %-22s ${GRAY}(not used)${NC}\n" "$filename"
        return
    fi

    if diff -q "$src" "$dst" >/dev/null 2>&1; then
        printf "  %-22s ${GREEN}CURRENT${NC}\n" "$filename"
    else
        local added removed
        added=$(diff "$src" "$dst" 2>/dev/null | grep -c '^>' || true)
        removed=$(diff "$src" "$dst" 2>/dev/null | grep -c '^<' || true)
        printf "  %-22s ${RED}OUTDATED${NC}  +%s -%s lines\n" "$filename" "$added" "$removed"
        has_outdated=1
    fi
}

echo ""
echo -e "${BOLD}PFrame Consumer Status${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

found=0
# Scan both lib/ and app/lib/ locations (posredniak uses app/lib/)
for lib_file in "$DEV_DIR"/*/lib/PFrame.php "$DEV_DIR"/*/app/lib/PFrame.php; do
    [[ -f "$lib_file" ]] || continue
    lib_dir="$(dirname "$lib_file")"
    proj_dir="${lib_file%/lib/PFrame.php}"
    proj_dir="${proj_dir%/app}"
    proj_name="$(basename "$proj_dir")"

    # skip pframe itself
    [[ "$proj_name" == "pframe" ]] && continue

    found=1
    echo -e "${BOLD}$proj_name${NC}"
    check_file "$SRC_PFRAME" "$lib_dir/PFrame.php" "$proj_name" "PFrame.php"
    check_file "$SRC_TESTING" "$lib_dir/PFrameTesting.php" "$proj_name" "PFrameTesting.php"
    echo ""
done

if [[ $found -eq 0 ]]; then
    echo "No consumers found in $DEV_DIR/*/lib/PFrame.php"
    exit 0
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $has_outdated -eq 1 ]]; then
    echo -e "${RED}Some consumers are outdated.${NC} Run /sync-pframe to update."
    exit 1
else
    echo -e "${GREEN}All consumers up to date.${NC}"
    exit 0
fi
