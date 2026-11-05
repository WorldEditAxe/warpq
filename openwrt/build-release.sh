#!/bin/sh
# Build static warpq release binaries for the common Linux architectures with
# zig, mbedTLS linked in.
#
#   ./openwrt/build-release.sh [name...]
#
# With no names every target in the table below is built. Binaries land in
# dist/ as warpq-<version>-linux-<name>, next to SHA256SUMS. Work files go to
# $WORK (default ./build-release-work); $JOBS caps how many targets build at
# once (default: the number of CPUs).
#
# Each target gets its own static mbedTLS, compiled from one tree and the
# OpenWrt mbedtls_config.h -- see build-x64.sh for why the config has to match.
# neon=1 builds mbedTLS with the 4-block NEON ChaCha20 (chacha20_neon.inc);
# kuser=1 links arm-kuser-atomics.c, for cores without ldrex/strex.
#
# The binaries are fully static against musl, so one runs on any Linux of its
# architecture whatever the distribution's libc; the soft-float targets also
# run on cores with no FPU.
#
# ECH (WARPQ_ECH) is not built here; see build-neon.sh for that.

set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="${WORK:-$ROOT/build-release-work}"
OUT="$ROOT/dist"
MBEDTLS_VER=3.6.7
MBEDTLS="$WORK/mbedtls-$MBEDTLS_VER"
VERSION=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/openwrt/Makefile")

# name         zig target               cpu                  neon  kuser  typical hardware
TARGETS='
x86_64         x86_64-linux-musl        baseline             0     0      PCs, servers, OpenWrt x86/64
i686           x86-linux-musl           i686                 0     0      32-bit PCs, OpenWrt x86/generic
aarch64        aarch64-linux-musl       baseline             1     0      Pi 3+, filogic, rockchip, ARM servers
armv7          arm-linux-musleabihf     generic+v7a+vfp3d16  0     0      mvebu, Cortex-A9 without NEON
armv7-neon     arm-linux-musleabihf     generic+v7a+neon     1     0      ipq40xx, ipq806x, Pi 2, Cortex-A7/A15
armv6          arm-linux-musleabihf     arm1176jzf_s         0     0      Pi 1, Pi Zero
armv5          arm-linux-musleabi       arm926ej_s           0     1      kirkwood, other ARMv5TE
mips           mips-linux-musleabi      mips32r2             0     0      ath79, lantiq (24Kc/34Kc/74Kc)
mipsel         mipsel-linux-musleabi    mips32r2             0     0      ramips (MT7621, MT7620, MT76x8)
mips64         mips64-linux-muslabi64   mips64r2             0     0      octeon
riscv64        riscv64-linux-musl       baseline             0     0      RV64GC boards
ppc64le        powerpc64le-linux-musl   baseline             0     0      POWER8+
loongarch64    loongarch64-linux-musl   baseline             0     0      Loongson 3A5000+
'

field() { printf '%s\n' "$TARGETS" | awk -v n="$1" -v f="$2" '$1 == n { print $f }'; }

# Build one target. Runs as its own process (see the xargs below), so it
# reports through its exit status and the log file.
build_one() {
	name="$1"
	target=$(field "$name" 2)
	cpu=$(field "$name" 3)
	neon=$(field "$name" 4)
	kuser=$(field "$name" 5)
	[ -n "$target" ] || { echo "unknown target: $name" >&2; return 1; }

	flags="-target $target -mcpu=$cpu -O2 -std=c99 -D_GNU_SOURCE"
	[ "$neon" = 1 ] && flags="$flags -DWARPQ_CHACHA20_NEON"
	extra=""
	[ "$kuser" = 1 ] && extra="$ROOT/openwrt/arm-kuser-atomics.c"

	obj="$WORK/obj-$name"
	mkdir -p "$obj" && rm -f "$obj"/*.o
	for f in "$MBEDTLS"/library/*.c; do
		zig cc $flags -I"$MBEDTLS/include" -I"$MBEDTLS/library" \
		   -c "$f" -o "$obj/$(basename "${f%.c}").o"
	done
	rm -f "$WORK/libmbedtls-$name.a"
	zig ar rcs "$WORK/libmbedtls-$name.a" "$obj"/*.o

	zig cc $flags -static -Wall -Wextra \
	   -ffunction-sections -fdata-sections \
	   -I"$MBEDTLS/include" \
	   "$ROOT"/src/*.c $extra "$WORK/libmbedtls-$name.a" \
	   -Wl,--gc-sections -Wl,-s -o "$OUT/warpq-$VERSION-linux-$name"
}

if [ "$1" = "--one" ]; then
	build_one "$2" >"$WORK/log/$2.log" 2>&1 || {
		echo "### $2 FAILED, last lines of $WORK/log/$2.log:" >&2
		tail -n 20 "$WORK/log/$2.log" >&2
		exit 1
	}
	echo "### $2 done"
	exit 0
fi

command -v zig >/dev/null || { echo "zig not found in PATH" >&2; exit 1; }
[ -n "$VERSION" ] || { echo "no PKG_VERSION in openwrt/Makefile" >&2; exit 1; }

if [ $# -gt 0 ]; then
	NAMES="$*"
else
	NAMES=$(printf '%s\n' "$TARGETS" | awk 'NF { print $1 }')
fi
for n in $NAMES; do
	[ -n "$(field "$n" 2)" ] || { echo "unknown target: $n" >&2; exit 1; }
done

mkdir -p "$WORK/log" "$OUT"

# 1. mbedTLS source
[ -d "$MBEDTLS" ] || {
	echo "### fetching mbedTLS $MBEDTLS_VER"
	curl -sSL -o "$WORK/mbedtls.tar.bz2" \
	  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VER/mbedtls-$MBEDTLS_VER.tar.bz2"
	tar xf "$WORK/mbedtls.tar.bz2" -C "$WORK"
}

# 2. the OpenWrt config, so every build matches the router's
cp "$ROOT/openwrt/mbedtls_config.h" "$MBEDTLS/include/mbedtls/mbedtls_config.h"

# 3. NEON ChaCha20. The patch only adds code under WARPQ_CHACHA20_NEON, so
#    the one patched tree serves the scalar targets too.
cp "$ROOT/openwrt/chacha20_neon.inc" "$MBEDTLS/library/chacha20_neon.inc"
grep -q WARPQ_CHACHA20_NEON "$MBEDTLS/library/chacha20.c" ||
	(cd "$MBEDTLS" && patch -p1 -s < "$ROOT/openwrt/chacha20-neon.patch")

# 4. every target, in parallel
echo "### building $(echo $NAMES | wc -w | tr -d ' ') targets: $(echo $NAMES)"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
export WORK
printf '%s\n' $NAMES | xargs -n 1 -P "$JOBS" "$ROOT/openwrt/build-release.sh" --one ||
	{ echo "### some targets failed" >&2; exit 1; }

# 5. checksums over everything in dist/ for this version
if command -v sha256sum >/dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$OUT" && $sum warpq-"$VERSION"-linux-* > SHA256SUMS)
echo "### done: $OUT"
ls -l "$OUT"
