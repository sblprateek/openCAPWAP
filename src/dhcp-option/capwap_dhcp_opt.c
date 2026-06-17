/*
 * capwap_dhcp_opt.c - CAPWAP AC discovery DHCP option 43/138 decoders.
 */
#include "capwap_dhcp_opt.h"

static uint32_t read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Reject 0.0.0.0, 127/8 loopback, 224/4 multicast, 255.255.255.255. */
static int ip_is_valid_ac(uint32_t ip)
{
	uint8_t a = (ip >> 24) & 0xff;

	if (ip == 0x00000000u)            /* 0.0.0.0            */
		return 0;
	if (ip == 0xFFFFFFFFu)            /* 255.255.255.255    */
		return 0;
	if (a == 127)                     /* 127/8 loopback     */
		return 0;
	if (a >= 224)                     /* 224/4 mcast + 240/4 */
		return 0;
	return 1;
}

/* Append one AC IPv4 (host order). De-dupes; drops invalid; caps at MAX. */
static int ac_list_add(struct ac_list *out, uint32_t ip_host)
{
	if (!ip_is_valid_ac(ip_host))
		return 0;
	if (out->count >= CAPWAP_AC_MAX)
		return 0;
	for (unsigned i = 0; i < out->count; i++)   /* de-dupe */
		if (out->ip[i] == ip_host)
			return 0;
	out->ip[out->count++] = ip_host;
	return 1;
}

int decode_opt138(const uint8_t *buf, size_t len, struct ac_list *out)
{
	if (len == 0 || (len % 4) != 0)
		return -1;
	for (size_t i = 0; i + 4 <= len; i += 4)
		ac_list_add(out, read_be32(buf + i));
	return (int)out->count;
}

int decode_opt43(const uint8_t *buf, size_t len, struct ac_list *out)
{
	size_t i = 0;

	while (i + 2 <= len) {                 /* need code + length byte */
		uint8_t code = buf[i];
		uint8_t slen = buf[i + 1];

		if (i + 2 + slen > len)        /* truncated value -> stop */
			break;

		if (code == CAPWAP_SUBOPT_AC_LIST) {
			const uint8_t *val = buf + i + 2;
			for (size_t j = 0; j + 4 <= slen; j += 4)
				ac_list_add(out, read_be32(val + j));
		}
		i += 2 + slen;
	}
	return (int)out->count;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int hexdecode(const char *hex, uint8_t *out, size_t out_sz)
{
	size_t n = 0;

	while (hex[0] && hex[1]) {
		int hi = hexval(hex[0]);
		int lo = hexval(hex[1]);
		if (hi < 0 || lo < 0)
			return -1;
		if (n >= out_sz)
			return -1;
		out[n++] = (uint8_t)((hi << 4) | lo);
		hex += 2;
	}
	if (hex[0])                /* odd number of nibbles */
		return -1;
	return (int)n;
}
