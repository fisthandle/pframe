#!/usr/bin/env bash
set -euo pipefail

PFRAME_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=consumers.sh
source "$PFRAME_DIR/bin/consumers.sh"

usage() {
    echo "Usage: $0 [dev-directory]"
}

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

DEV_DIR="${1:-$(dirname "$PFRAME_DIR")}"
if [[ ! -d "$DEV_DIR" ]]; then
    echo "Consumer root does not exist: $DEV_DIR" >&2
    exit 2
fi
DEV_DIR="$(cd "$DEV_DIR" && pwd)"

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
    local filename="$3"

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
while IFS= read -r -d '' lib_dir; do
    found=1
    echo -e "${BOLD}$(pframe_consumer_name "$DEV_DIR" "$lib_dir")${NC}"
    check_file "$SRC_PFRAME" "$lib_dir/PFrame.php" "PFrame.php"
    check_file "$SRC_TESTING" "$lib_dir/PFrameTesting.php" "PFrameTesting.php"
    echo ""
done < <(pframe_consumer_lib_dirs "$DEV_DIR")

if [[ $found -eq 0 ]]; then
    echo "No consumers found under $DEV_DIR (expected */lib/PFrame.php)"
    exit 2
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $has_outdated -eq 1 ]]; then
    echo -e "${RED}Some consumers are outdated.${NC} Synchronize them from $SRC_PFRAME before release."
    exit 1
else
    echo -e "${GREEN}All consumers up to date.${NC}"
    exit 0
fi
