# warpq (C)

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
