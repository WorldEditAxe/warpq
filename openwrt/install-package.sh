#!/bin/sh
set -e

SDK="$1"
[ -n "$SDK" ] || { echo "usage: $0 <openwrt-sdk-dir>" >&2; exit 1; }
[ -f "$SDK/rules.mk" ] || { echo "$SDK does not look like an OpenWrt SDK" >&2; exit 1; }

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST="$SDK/package/warpq"

rm -rf "$DEST/src"
mkdir -p "$DEST/src"
cp "$ROOT"/src/*.c "$ROOT"/src/*.h "$DEST/src/"
cp -r "$ROOT/openwrt/files" "$DEST/"
cp "$ROOT/openwrt/Makefile" "$DEST/Makefile"
cp "$ROOT/Makefile" "$DEST/Makefile.pkg"
echo "installed into $DEST"
