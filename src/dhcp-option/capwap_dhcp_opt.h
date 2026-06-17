/*
 * capwap_dhcp_opt.h - CAPWAP AC discovery: DHCP option 43/138 decoders.
 *
 * Pure, dependency-free C. Parses bytes as bytes (never as text), fully
 * bounds-checked against attacker-controllable length fields. See README.md.
 */
#ifndef _CAPWAP_DHCP_OPT_H_
#define _CAPWAP_DHCP_OPT_H_

#include <stdint.h>
#include <stddef.h>

#define CAPWAP_AC_MAX          8        /* max AC addresses we keep */
#define CAPWAP_SUBOPT_AC_LIST  0xF1     /* opt43 sub-option: AC IPv4 list */

struct ac_list {
	uint32_t ip[CAPWAP_AC_MAX];        /* host byte order */
	unsigned count;
};

/* Decode option 138 (RFC 5417): value = N x 4 bytes IPv4 list.
 * Returns count on success, -1 if malformed (len 0 or not a multiple of 4). */
int decode_opt138(const uint8_t *buf, size_t len, struct ac_list *out);

/* Decode option 43 (vendor TLV): walk sub-options, harvest sub-opt 0xF1.
 * Returns count (>=0). Truncated TLVs stop the walk without overread. */
int decode_opt43(const uint8_t *buf, size_t len, struct ac_list *out);

/* Decode an ASCII hex string ("c0a80101") into bytes. Returns byte count,
 * or -1 on odd length / non-hex char / output overflow. */
int hexdecode(const char *hex, uint8_t *out, size_t out_sz);

#endif /* _CAPWAP_DHCP_OPT_H_ */
