/*
 * wtp_timesync.h - WTP-side clock discipline from the CAPWAP Timestamp element.
 *
 * The AC sends its NTP-disciplined UTC in the standard CAPWAP Timestamp message
 * element (RFC 5415, type 6). The WTP applies it here, stepping CLOCK_REALTIME
 * when it differs from the AC by more than a small threshold.
 */
#ifndef _WTP_TIMESYNC_H_
#define _WTP_TIMESYNC_H_

#include <stdint.h>

/*
 * Apply an AC-supplied UTC (seconds since 1970-01-01) received in a CAPWAP
 * Timestamp element. A value of 0 means the AC is not time-synced yet and is
 * ignored. Implausible values are rejected. Stepping the clock needs root
 * (the WTP runs as root on the AP).
 */
void CWWTPApplyACTime(uint32_t acUTC);

/*
 * Scan a raw message-element buffer (msg, len bytes) for a CAPWAP Timestamp
 * element and apply it via CWWTPApplyACTime(). Used for messages whose body
 * is not otherwise parsed for elements (e.g. the periodic Echo Response).
 */
void CWWTPApplyACTimeFromElems(char *msg, int len);

#endif /* _WTP_TIMESYNC_H_ */
