# capwap-acdisc — CAPWAP AC discovery from DHCP option 43 / 138

A small, dependency‑free C helper that lets the openCAPWAP **WTP** learn its
**Access Controller (AC) IP** from DHCP — option **138** (RFC 5417 CAPWAP‑AC) or
option **43** (vendor‑specific, sub‑option `0xF1`) — in addition to the static
`config.wtp` list. Fully **in‑process**: the WTP queries DHCP itself; there is
no `udhcpc`, no shell hook, no netifd `reqopts` dependency, and no extra link
libraries.

Trimmed to exactly what the WTP build uses — nothing else.

---

## 1. Architecture

```
 ┌──────────────┐   DHCPDISCOVER (PRL: opt 43,138)   ┌───────────────────────────────────────┐
 │ DHCP server  │◀───────────────────────────────────│             openCAPWAP WTP            │
 │ serves opt   │   DHCPOFFER (opt43 / opt138)        │  CWWTPLoadConfiguration() (WTP.c)     │
 │ 43 and/or 138│────────────────────────────────────▶│   1. capwap_dhcp_query()  ── opt hex  │
 └──────────────┘   UDP 67/68 broadcast               │   2. capwap_acdisc_ip()   ── AC IP    │
                                                       │   3. prepend AC to gCWACList          │
                                                       │      (else: static list unchanged)    │
                                                       └───────────────────────────────────────┘
```

| File | Role | Deps |
|---|---|---|
| `capwap_dhcp_query.{c,h}` | In‑process DHCP client: broadcast a DISCOVER requesting opt 43+138, parse the reply, return values as hex | sockets only |
| `capwap_dhcp_opt.{c,h}` | Byte decoders: opt 138 (4‑byte IPv4 list), opt 43 TLV (sub‑opt `0xF1`); validate + de‑dupe + hexdecode | none (pure C) |
| `capwap_acdisc.{c,h}` | One call: opt 138/43 hex → preferred AC IP (138 wins, 43 fallback) | none (pure C) |

**Preference / safety:** option 138 wins, option 43 is the fallback. Invalid
addresses (`0.0.0.0`, `127/8`, `224/4`+, `255.255.255.255`) are rejected and the
list de‑duped. If nothing valid is found, `capwap_acdisc_ip()` returns `-1` and
the WTP keeps its static AC list — purely additive, non‑breaking. DHCP is
unauthenticated, so a learned IP is only a *pointer*; trust is still established
by the CAPWAP DTLS/X.509 control channel.

---

## 2. Public API

```c
#include "capwap_dhcp_query.h"   /* step 1: ask DHCP for opt 43/138 */
#include "capwap_acdisc.h"       /* step 2: decode them to an AC IP */

/* Broadcast a DHCPDISCOVER on iface (e.g. "br-lan") requesting opt 43+138 and
 * return the option values as lowercase hex. 0 = at least one captured, -1 = none. */
int capwap_dhcp_query(const char *iface,
                      char *opt43_hex,  size_t opt43_sz,
                      char *opt138_hex, size_t opt138_sz);

/* Preferred single AC IP from opt 138/43 hex (138 wins). Either arg may be
 * NULL/"". Writes "a.b.c.d" into ip_out (>= 16 bytes). 0 = ok, -1 = none. */
int capwap_acdisc_ip(const char *opt138_hex, const char *opt43_hex,
                     char *ip_out, size_t ip_out_sz);
```
(`capwap_dhcp_opt.h` exposes the lower‑level `decode_opt138`/`decode_opt43`/`hexdecode`
primitives if needed directly.)

---

## 3. How it is wired into this WTP

**Build** — `Makefile.arm` compiles three pure‑C objects (no extra libs):
```make
INCLUDES += -I./src/dhcp-option/
WTP_OBJS += ./src/dhcp-option/capwap_dhcp_opt.o
WTP_OBJS += ./src/dhcp-option/capwap_acdisc.o
WTP_OBJS += ./src/dhcp-option/capwap_dhcp_query.o
```

**Call site** — `WTP.c : CWWTPLoadConfiguration()`:
```c
char optBuf43[256] = "", optBuf138[256] = "";
capwap_dhcp_query(qiface, optBuf43, sizeof optBuf43, optBuf138, sizeof optBuf138);
if (capwap_acdisc_ip(optBuf138, optBuf43, dhcpAC, sizeof dhcpAC) == 0)
        /* prepend dhcpAC ahead of the static gCWACList */ ;
```
`qiface` is the uplink (`br-lan`) from `settings.wtp.txt`.

---

## 4. Option value formats

- **Option 138** (RFC 5417): value = `N × 4` bytes, each big‑endian IPv4.
  AC `161.118.191.249` → `a176bff9`. Two ACs → `a176bff9<next>`.
- **Option 43**: vendor TLV stream; sub‑option `0xF1` carries the same `N × 4`
  IPv4 list. One AC `161.118.191.249` → `F1 04 A1 76 BF F9` (hex `f104a176bff9`).

---

## 5. Verifying

Look for, in the WTP log:
```
DHCP query on br-lan: opt43='f104a176bff9' opt138='...'
AC 161.118.191.249 learned from DHCP option 43/138 (tried first)
```
For a real test, configure the DHCP server to advertise option 138 (or 43
sub‑option `0xF1`) with the AC's reachable IP.
