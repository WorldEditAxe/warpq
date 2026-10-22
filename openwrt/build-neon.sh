#!/bin/sh
# Build warpq for ipq40xx (arm_cortex-a7_neon-vfpv4) with a statically linked
# mbedTLS carrying a NEON ChaCha20.
#
# OpenWrt only publishes an x86_64 SDK, so on an arm64 host the official route
# needs an emulated VM. zig cross-compiles natively instead, and static linking
# keeps the router's own libmbedcrypto untouched -- uhttpd and wpad link it too,
# so replacing it would put LuCI and WiFi at risk.
#
#   ./openwrt/build-neon.sh <workdir>
#
# Leaves the binary at <workdir>/warpq.
#
# ECH ("warpq register --secure") is optional and off by default. Set
# WARPQ_ECH=1 to also cross-build a static wolfSSL and link it in, so the
# secure path can use TLS Encrypted Client Hello instead of only falling back
# to a handshake with no SNI (mbedTLS, the default TLS, has no ECH):
#
#   WARPQ_ECH=1 ./openwrt/build-neon.sh <workdir>

set -e

WORK="${1:-./build-neon}"
MBEDTLS_VER=3.6.7
WOLFSSL_VER=5.9.4-stable
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET="arm-linux-musleabihf"
CPU="cortex_a7+neon+vfp4"

# filled in by the ECH step below when WARPQ_ECH=1
ECH_CFLAGS=""
ECH_LIBS=""

mkdir -p "$WORK"
cd "$WORK"

command -v zig >/dev/null || { echo "zig not found in PATH" >&2; exit 1; }

# 1. mbedTLS source
[ -d "mbedtls-$MBEDTLS_VER" ] || {
	echo "### fetching mbedTLS $MBEDTLS_VER"
	curl -sSL -o mbedtls.tar.bz2 \
	  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VER/mbedtls-$MBEDTLS_VER.tar.bz2"
	tar xf mbedtls.tar.bz2
}

# 2. The config must match what OpenWrt builds, or struct layouts drift. Use
#    the copy in openwrt/ when present, otherwise keep mbedTLS's stock one.
if [ -f "$ROOT/openwrt/mbedtls_config.h" ]; then
	cp "$ROOT/openwrt/mbedtls_config.h" "mbedtls-$MBEDTLS_VER/include/mbedtls/mbedtls_config.h"
fi

# 3. NEON ChaCha20
cp "$ROOT/openwrt/chacha20_neon.inc" "mbedtls-$MBEDTLS_VER/library/chacha20_neon.inc"
if ! grep -q WARPQ_CHACHA20_NEON "mbedtls-$MBEDTLS_VER/library/chacha20.c"; then
	echo "### patching chacha20.c" >&2
	echo "    apply it first: (cd $WORK/mbedtls-$MBEDTLS_VER && patch -p1 < $ROOT/openwrt/chacha20-neon.patch)" >&2
	exit 1
fi

# 4. static mbedTLS
echo "### building mbedTLS"
mkdir -p obj && rm -f obj/*.o
for f in "mbedtls-$MBEDTLS_VER"/library/*.c; do
	zig cc -target "$TARGET" -mcpu="$CPU" -O2 -std=c99 -D_GNU_SOURCE \
	   -DWARPQ_CHACHA20_NEON \
	   -I"mbedtls-$MBEDTLS_VER/include" -I"mbedtls-$MBEDTLS_VER/library" \
	   -c "$f" -o "obj/$(basename "${f%.c}").o"
done
zig ar rcs libmbedtls_neon.a obj/*.o

# 4b. static wolfSSL with ECH, only when asked. wolfSSL's autotools build is
#     driven with zig as the cross compiler; --host keeps configure from trying
#     to run target binaries on the host. The feature set is the minimum ECH
#     needs: TLS 1.3, the ECH extension itself, HPKE and X25519 for its key
#     exchange, SNI for the inner name. The CA bundle is read from a file at
#     runtime (load_verify_locations), so no system-CA probing is enabled.
if [ "${WARPQ_ECH:-0}" = "1" ]; then
	[ -d "wolfssl-$WOLFSSL_VER" ] || {
		echo "### fetching wolfSSL $WOLFSSL_VER"
		curl -sSL -o wolfssl.tar.gz \
		  "https://github.com/wolfSSL/wolfssl/releases/download/v$WOLFSSL_VER/wolfssl-$WOLFSSL_VER.tar.gz"
		tar xf wolfssl.tar.gz
	}
	if [ ! -f "wolfssl-$WOLFSSL_VER/src/.libs/libwolfssl.a" ]; then
		echo "### building wolfSSL (ECH)"
		( cd "wolfssl-$WOLFSSL_VER" && \
		  CC="zig cc -target $TARGET -mcpu=$CPU" \
		  AR="zig ar" RANLIB="zig ranlib" STRIP="zig strip" \
		  CFLAGS="-O2 -fomit-frame-pointer" \
		  ./configure --host="$TARGET" \
		    --enable-static --disable-shared \
		    --enable-tls13 --enable-ech --enable-hpke --enable-sni \
		    --enable-curve25519 --enable-ecc \
		    --disable-examples --disable-crypttests --disable-oldtls >/dev/null && \
		  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" )
	fi
	ECH_CFLAGS="-DWARPQ_ECH -Iwolfssl-$WOLFSSL_VER"
	ECH_LIBS="wolfssl-$WOLFSSL_VER/src/.libs/libwolfssl.a"
fi

# 5. warpq
echo "### building warpq${ECH_CFLAGS:+ (with ECH)}"
zig cc -target "$TARGET" -mcpu="$CPU" \
   -O2 -std=c99 -D_GNU_SOURCE -Wall -Wextra \
   -ffunction-sections -fdata-sections \
   $ECH_CFLAGS \
   -I"mbedtls-$MBEDTLS_VER/include" \
   "$ROOT"/src/*.c libmbedtls_neon.a $ECH_LIBS \
   -Wl,--gc-sections -Wl,-s -o warpq

echo "### done: $WORK/warpq"
ls -l warpq
