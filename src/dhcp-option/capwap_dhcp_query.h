/*
 * capwap_dhcp_query.h - in-process DHCP option 43/138 fetch (no udhcpc, no scripts).
 *
 * Broadcasts a DHCPDISCOVER on the given interface with options 43 and 138 in
 * the Parameter Request List, then parses the server's reply and returns the
 * raw option values as lowercase hex strings (the same form the decoders in
 * capwap_dhcp_opt.h expect). Pure sockets; needs CAP_NET_RAW/root for the
 * broadcast + SO_BINDTODEVICE (the WTP runs as root).
 */
#ifndef _CAPWAP_DHCP_QUERY_H_
#define _CAPWAP_DHCP_QUERY_H_

#include <stddef.h>

/*
 * Query DHCP on `iface` (e.g. "br-lan") for CAPWAP options 43/138.
 * Writes lowercase-hex option values into opt43_hex / opt138_hex (each set to
 * "" if that option wasn't returned). Either output may be NULL.
 * Returns 0 if at least one option was captured, -1 otherwise.
 */
int capwap_dhcp_query(const char *iface,
                      char *opt43_hex,  size_t opt43_sz,
                      char *opt138_hex, size_t opt138_sz);

#endif /* _CAPWAP_DHCP_QUERY_H_ */
