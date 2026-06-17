/*
 * capwap_dhcp_query.c - in-process DHCP option 43/138 fetch (see header).
 *
 * Sends a DHCPDISCOVER (broadcast) requesting options 43 + 138 and reads the
 * OFFER/ACK, extracting those options. This reproduces, fully in C, the
 * `udhcpc -O 43 -O 138` probe we verified works against the DHCP server -- no
 * udhcpc, no shell scripts, no dependence on netifd reqopts.
 */
#include "capwap_dhcp_query.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCP_MAGIC       0x63825363u
#define DHCP_DISCOVER    1
#define DHCP_BOOTREPLY   2

struct dhcp_packet {
	uint8_t  op, htype, hlen, hops;
	uint32_t xid;
	uint16_t secs, flags;
	uint32_t ciaddr, yiaddr, siaddr, giaddr;
	uint8_t  chaddr[16];
	uint8_t  sname[64];
	uint8_t  file[128];
	uint8_t  options[312];
} __attribute__((packed));

static void to_hex(const uint8_t *b, int n, char *out, size_t osz)
{
	static const char h[] = "0123456789abcdef";
	int i, j = 0;
	for (i = 0; i < n && (size_t)(j + 3) <= osz; i++) {
		out[j++] = h[b[i] >> 4];
		out[j++] = h[b[i] & 0xf];
	}
	out[j] = '\0';
}

int capwap_dhcp_query(const char *iface,
		      char *o43, size_t s43,
		      char *o138, size_t s138)
{
	int fd = -1, rc = -1, tries;
	int one = 1;
	struct ifreq ifr;
	uint8_t mac[6];
	uint32_t xid, magic;
	struct sockaddr_in dst, me;
	struct timeval tv;
	struct dhcp_packet pkt;
	uint8_t *o;

	if (o43 && s43)  o43[0] = '\0';
	if (o138 && s138) o138[0] = '\0';
	if (!iface || !*iface)
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
	setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1);
	tv.tv_sec = 2; tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	memset(&me, 0, sizeof me);
	me.sin_family = AF_INET;
	me.sin_port = htons(DHCP_CLIENT_PORT);
	me.sin_addr.s_addr = INADDR_ANY;
	if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) {
		close(fd);
		return -1;
	}

	memset(&ifr, 0, sizeof ifr);
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	xid = ((uint32_t)rand() << 16) ^ (uint32_t)rand();

	/* build DHCPDISCOVER */
	memset(&pkt, 0, sizeof pkt);
	pkt.op = 1; pkt.htype = 1; pkt.hlen = 6;
	pkt.xid = xid;                       /* echoed back verbatim; compared raw */
	pkt.flags = htons(0x8000);           /* ask server to broadcast the reply */
	memcpy(pkt.chaddr, mac, 6);
	o = pkt.options;
	magic = htonl(DHCP_MAGIC); memcpy(o, &magic, 4); o += 4;
	*o++ = 53; *o++ = 1; *o++ = DHCP_DISCOVER;
	*o++ = 55; *o++ = 4; *o++ = 43; *o++ = 138; *o++ = 1; *o++ = 3;  /* PRL */
	*o++ = 61; *o++ = 7; *o++ = 1; memcpy(o, mac, 6); o += 6;        /* client id */
	*o++ = 0xff;

	memset(&dst, 0, sizeof dst);
	dst.sin_family = AF_INET;
	dst.sin_port = htons(DHCP_SERVER_PORT);
	dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	for (tries = 0; tries < 4 && rc != 0; tries++) {
		if (sendto(fd, &pkt, sizeof pkt, 0,
			   (struct sockaddr *)&dst, sizeof dst) < 0)
			continue;

		for (;;) {
			struct dhcp_packet rsp;
			ssize_t n = recv(fd, &rsp, sizeof rsp, 0);
			uint8_t *p, *end;
			uint32_t m;

			if (n < 240)                       /* timeout or runt */
				break;
			if (rsp.op != DHCP_BOOTREPLY || rsp.xid != xid)
				continue;                  /* not our reply */

			p = rsp.options;
			end = (uint8_t *)&rsp + n;
			if (p + 4 > end) break;
			memcpy(&m, p, 4);
			if (ntohl(m) != DHCP_MAGIC) break;
			p += 4;

			while (p < end) {
				uint8_t code = *p++;
				uint8_t len;
				if (code == 0xff) break;   /* end */
				if (code == 0) continue;   /* pad */
				if (p >= end) break;
				len = *p++;
				if (p + len > end) break;
				if (code == 43 && o43 && s43)
					to_hex(p, len, o43, s43);
				else if (code == 138 && o138 && s138)
					to_hex(p, len, o138, s138);
				p += len;
			}
			if ((o43 && o43[0]) || (o138 && o138[0])) {
				rc = 0;
				break;
			}
		}
	}

	close(fd);
	return rc;
}
