#!/bin/sh
# Build a static x86-64 warpq (musl) with zig, mbedTLS linked in.
#
#   ./openwrt/build-x64.sh [workdir]
#
# Leaves the binary at build-x64/warpq.
#
# mbedTLS is compiled here, from the same tree and the same mbedtls_config.h
# that warpq is compiled against. A prebuilt libmbedtls.a from another config
# links cleanly but disagrees about struct layout -- MBEDTLS_SSL_RENEGOTIATION
# alone adds fields to mbedtls_ssl_config and mbedtls_ssl_context -- and the
# library then calls through what is really the ciphersuite list.

set -e

WORK="${1:-./build-x64-work}"
MBEDTLS_VER=3.6.7
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET="x86_64-linux-musl"
OUT="$ROOT/build-x64"

mkdir -p "$WORK" "$OUT"
cd "$WORK"

command -v zig >/dev/null || { echo "zig not found in PATH" >&2; exit 1; }

# 1. mbedTLS source
[ -d "mbedtls-$MBEDTLS_VER" ] || {
	echo "### fetching mbedTLS $MBEDTLS_VER"
	curl -sSL -o mbedtls.tar.bz2 \
	  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VER/mbedtls-$MBEDTLS_VER.tar.bz2"
	tar xf mbedtls.tar.bz2
}

# 2. the OpenWrt config, so this build matches the router's
cp "$ROOT/openwrt/mbedtls_config.h" "mbedtls-$MBEDTLS_VER/include/mbedtls/mbedtls_config.h"

# 3. static mbedTLS
echo "### building mbedTLS"
mkdir -p obj-x64 && rm -f obj-x64/*.o
for f in "mbedtls-$MBEDTLS_VER"/library/*.c; do
	zig cc -target "$TARGET" -O2 -std=c99 -D_GNU_SOURCE \
	   -I"mbedtls-$MBEDTLS_VER/include" -I"mbedtls-$MBEDTLS_VER/library" \
	   -c "$f" -o "obj-x64/$(basename "${f%.c}").o"
done
rm -f "$OUT/libmbedtls.a"
zig ar rcs "$OUT/libmbedtls.a" obj-x64/*.o

# 4. warpq
echo "### building warpq"
zig cc -target "$TARGET" -static \
   -O2 -std=c99 -D_GNU_SOURCE -Wall -Wextra \
   -ffunction-sections -fdata-sections \
   -I"mbedtls-$MBEDTLS_VER/include" \
   "$ROOT"/src/*.c "$OUT/libmbedtls.a" \
   -Wl,--gc-sections -Wl,-s -o "$OUT/warpq"

echo "### done: $OUT/warpq"
ls -l "$OUT/warpq"
