/*
 * wtp_timesync.c - WTP-side clock discipline (see wtp_timesync.h).
 */
#include "wtp_timesync.h"

#include <time.h>
#include <errno.h>
#include <string.h>

#include "CWWTP.h"   /* CWLog */

/* Below this the timestamp is implausible (well before 2020) -> ignore. */
#define TS_MIN_VALID_UTC   1600000000u
/* Don't step for sub-threshold drift (the element is whole-seconds anyway). */
#define TS_STEP_THRESHOLD  2

void CWWTPApplyACTime(uint32_t acUTC)
{
	struct timespec ts;
	time_t now;
	long delta;

	if (acUTC == 0)                    /* AC not synced -> nothing to apply */
		return;
	if (acUTC < TS_MIN_VALID_UTC) {    /* garbage -> ignore */
		CWLog("Time sync: ignoring implausible AC timestamp %u", acUTC);
		return;
	}

	now = time(NULL);
	delta = (long)acUTC - (long)now;
	if (delta >= -TS_STEP_THRESHOLD && delta <= TS_STEP_THRESHOLD)
		return;                    /* already in sync within threshold */

	ts.tv_sec  = (time_t)acUTC;
	ts.tv_nsec = 0;
	if (clock_settime(CLOCK_REALTIME, &ts) == 0)
		CWLog("Time sync: stepped clock to AC time %u (was off by %ld s)",
		      acUTC, delta);
	else
		CWLog("Time sync: clock_settime failed (%s)", strerror(errno));
}

void CWWTPApplyACTimeFromElems(char *msg, int len)
{
	CWProtocolMessage m;

	if (msg == NULL || len <= 0)
		return;

	m.msg = msg;
	m.offset = 0;
	while (m.offset < len) {
		unsigned short int type = 0, elen = 0;
		CWParseFormatMsgElem(&m, &type, &elen);
		if (type == CW_MSG_ELEMENT_TIMESTAMP_CW_TYPE)
			CWWTPApplyACTime(CWProtocolRetrieve32(&m));
		else
			m.offset += elen;        /* skip any other element */
	}
}
