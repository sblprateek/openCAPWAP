/*
 * ac_sntp.h - AC-side SNTP client for CAPWAP time distribution.
 *
 * The AC is the time authority for its WTPs. Rather than trust the AC host's
 * local clock, this disciplines an offset against a real NTP server (RFC 4330
 * SNTP) and exposes the resulting authoritative UTC. The AC then ships that
 * time to WTPs in the standard CAPWAP Timestamp message element (RFC 5415,
 * type 6). Self-contained: sockets + pthread only.
 */
#ifndef _AC_SNTP_H_
#define _AC_SNTP_H_

#include <stdint.h>

/*
 * Start the background SNTP client thread.
 *   server       - NTP server hostname or IPv4 (e.g. "pool.ntp.org"); if NULL
 *                  or empty, time sync is disabled and acTimeSyncGetUTC() will
 *                  always report "not synced".
 *   pollInterval - seconds between SNTP queries:
 *                    <  0  -> unset, use the default periodic interval (64s)
 *                    == 0  -> one-shot: sync once at startup, periodic poll OFF
 *                    >  0  -> re-sync every N seconds (min clamp applies)
 * Idempotent: a second call is ignored. Returns 0 on success, -1 on error.
 */
int acTimeSyncStart(const char *server, int pollInterval);

/*
 * Authoritative UTC (seconds since 1970-01-01), NTP-disciplined.
 * Returns 0 and writes *utc once at least one SNTP sync has succeeded;
 * returns -1 if not synced yet (caller should not distribute time).
 */
int acTimeSyncGetUTC(uint32_t *utc);

#endif /* _AC_SNTP_H_ */
