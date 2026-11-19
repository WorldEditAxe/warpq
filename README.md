# warpq

A mbedTLS-only Cloudflare WARP client, originally made for OpenWrt.

## Build

```sh
make # needs libmbedtls-dev
```

For OpenWRT:

```sh
./openwrt/install-package.sh ~/openwrt-sdk-24.10-ath79
cd ~/openwrt-sdk-24.10-ath79
make package/warpq/compile V=s
```

### Release binaries

`./openwrt/build-release.sh` cross-builds fully static binaries (musl, mbedTLS
linked in) with zig for every common Linux architecture, into `dist/` with a
`SHA256SUMS`. Pass target names to build only some of them.

| Name | Runs on |
|------|---------|
| `x86_64` | PCs, servers, OpenWrt x86/64 |
| `i686` | 32-bit PCs, OpenWrt x86/generic |
| `aarch64` | Pi 3+, MediaTek Filogic, Rockchip, ARM servers (NEON ChaCha20) |
| `armv7` | ARMv7 with VFPv3-D16 (mvebu, Cortex-A9 without NEON) |
| `armv7-neon` | ipq40xx, ipq806x, Pi 2, Cortex-A7/A15 (NEON ChaCha20) |
| `armv6` | Pi 1, Pi Zero |
| `armv5` | kirkwood and other ARMv5TE |
| `mips` | ath79, lantiq (big-endian MIPS32r2, soft-float) |
| `mipsel` | ramips: MT7621, MT7620, MT76x8 |
| `mips64` | octeon |
| `riscv64` | RV64GC boards |
| `ppc64le` | POWER8 and later |
| `loongarch64` | Loongson 3A5000 and later |

### With ECH/"stealth" mode (`--secure`)

`--secure` attempts to obscure the connection (albeit a poor job at doing so).
It primarily works by attempting to hide the SNI: first by using ECH, with a fallback
towards SNI stripping if necessary. Since mbedTLS doesn't support ECH, you'll need to use
wolfSSL built ith `--enable-ech --enable-hpke --enable-sni --enable-curve25519` and define `WARPQ_ECH`:

```sh
make CFLAGS="-Os -std=c99 -D_GNU_SOURCE -DWARPQ_ECH -I/path/to/wolfssl/include" \
     LIBS="-lmbedtls -lmbedx509 -lmbedcrypto -lwolfssl" \
     LDFLAGS="-L/path/to/wolfssl/lib"
```

Without `WARPQ_ECH` SNI won't be used. SNI stripping will be attempted instead. This mode
is mainly for deployment scenarios where an context-aware firewall is present (e.g. filters
that read the "SNI" field of outgoing TLS connections).

On OpenWrt, set `option enabled 1` in `/etc/config/warpq` and
`/etc/init.d/warpq start`; the service registers on first run.

On a systemd distribution, build a static binary with
`./openwrt/build-x64.sh`, register once (`warpq register`), then:

```sh
install -m 0755 build-x64/warpq /usr/local/bin/warpq
install -m 0644 systemd/warpq.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now warpq
```

## Use

```sh
warpq register -n my-router     # one free account, saved to /etc/warpq.json
warpq register -n my-router --secure   # the same, hiding the API server name
warpq up                        # tunnel up, everything routed through it
warpq up --secure               # the same, without sending the endpoint SNI
warpq status                    # ask the running daemon how it is doing
warpq status -j                 # the same as JSON, for scripts and rpcd
warpq stop                      # ask it to shut down and undo its routing
warpq account                   # account type, WARP+ status, quota
warpq license <KEY>             # bind a WARP+ licence
warpq license --clear           # unbind it
```

The daemon listens on a Unix socket (`/var/run/warpq.sock`, mode 0600) and
answers `status`, `status.json`, `ping` and `stop`:

```
$ warpq status
state: connected
transport: masque/http2
interface: warp0
ipv4: 172.16.0.2
ipv6: 2606:4700:110:8a54:599f:1223:6bd5:13cb
endpoint: 162.159.198.2:443
routed: yes
uptime: 8
rx: 76 packets 14728 bytes
tx: 109 packets 89320 bytes
reconnects: 0
```

Use `-s PATH` to move the socket, or `--no-ctl` on `up` to do without one.

## Tunnel encryption

mbedTLS does the handshake and checks the endpoint's pinned key. After that,
`up` moves the tunnel's record encryption to something faster, best first:

1. **The kernel's TLS layer (kTLS).** Its ChaCha20-Poly1305 and AES-GCM are
   hand-tuned for each CPU, and it decrypts straight into warpq's buffers.
   It needs the `tls` kernel module and the kernel's ChaCha20-Poly1305 AEAD;
   on OpenWrt that is `kmod-tls` plus the ChaCha20-Poly1305 crypto module.
2. **warpq's own record layer** (`src/aead.c`), for ChaCha20-Poly1305 when
   the kernel can't take it. ChaCha20 runs four or eight blocks at a time
   in SIMD registers: NEON on ARM, SSE2 or AVX2 (picked at run time) on x86,
   AltiVec on POWER, LSX on LoongArch. Poly1305 uses 64x64-bit multiplies on
   64-bit CPUs. Records move up to 64 KiB per system call.
3. **mbedTLS**, for everything else (AES-GCM without kTLS, or TLS 1.2).

The `tunnel up` line says which one is in use:

```
tunnel up: CONNECT accepted (HTTP/2, TLS1-3-CHACHA20-POLY1305-SHA256, kernel TLS)
tunnel up: CONNECT accepted (HTTP/2, TLS1-3-CHACHA20-POLY1305-SHA256, warpq ChaCha20/NEON)
```

Measured with ChaCha20-Poly1305 on an i7-13700KF, with warpq held to a
quarter of a core:

| engine | download | upload | CPU per GB (down/up) |
|--------|----------|--------|----------------------|
| mbedTLS | 990 Mbit/s | 790 Mbit/s | 1.9 s / 2.4 s |
| warpq (AVX2) | 1590 Mbit/s | 1430 Mbit/s | 1.1 s / 1.3 s |
| kernel TLS | 1560 Mbit/s | 1350 Mbit/s | 1.2 s / 1.4 s |

The cipher alone, sealing 16 KiB records, compared with stock mbedTLS:
3.3x faster with AVX2 and 2x with SSE2 (i7-13700KF), 2.9x with NEON (Apple
M2). On CPUs with no SIMD and no 64-bit multiply (MIPS32, ARMv5/v6) the
cipher runs at mbedTLS's speed (measured on 32-bit x86 without SIMD); the
gain there is the fewer system calls.

`--tls-engine warpq` skips the kernel, and `--tls-engine mbedtls` keeps
mbedTLS for the whole connection.

## LuCI

`luci/` holds `luci-app-warpq`: a status panel (state, addresses, endpoint,
counters, uptime, refreshed every 5s), Start/Stop/Register buttons, and a form
over the UCI config. It talks to an rpcd backend at
`/usr/libexec/rpcd/warpq`, which reads the daemon's control socket via
`warpq status -j`.

```sh
cp -r luci ~/openwrt-sdk/package/luci-app-warpq
cd ~/openwrt-sdk && make package/luci-app-warpq/compile V=s
```

## Limitations

- MASQUE over HTTP/2 is only available. Using QUIC would pull ngtcp2 and nghttp3 in.
  This client is mainly built with a focus on "obfuscation" and thus wouldn't be best
  used with a UDP connection anyway (will likely be blocked).
- Linux only, and `up` needs `CAP_NET_ADMIN` and `/dev/net/tun`.
- No Zero Trust (`--jwt`) enrollment.
