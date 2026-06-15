/*
 * ac_sntp.c - AC-side SNTP client (see ac_sntp.h).
 *
 * Periodically queries an NTP server, computes the clock offset using the
 * standard four-timestamp method, and keeps an authoritative UTC the AC can
 * hand to WTPs. Pure POSIX: sockets + pthread, no external deps.
 */
#include "ac_sntp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* AC application logger (CWLog.c); avoids pulling the whole CW header stack. */
extern void CWLog(const char *format, ...);

#define NTP_PORT            "123"
#define NTP_PKT_LEN         48
#define NTP_UNIX_EPOCH_DIFF 2208988800u   /* seconds between 1900 and 1970 */
#define SNTP_DEFAULT_POLL   64
#define SNTP_RECV_TIMEOUT   5             /* seconds */
#define SNTP_MIN_POLL       16

/* shared state */
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static double          s_offset;          /* true_utc - local_clock (seconds) */
static int             s_synced;          /* at least one good sync done */
static int             s_started;

static char            s_server[256];
static int             s_poll = SNTP_DEFAULT_POLL;

/* Current local clock as a double (seconds since 1970, sub-second precision). */
static double now_unix(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Read a 64-bit NTP timestamp (32b seconds-since-1900 + 32b fraction) at buf,
 * return it as Unix seconds (double). Returns 0.0 if the field is zero. */
static double ntp_ts_to_unix(const unsigned char *buf)
{
	uint32_t sec  = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
			((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
	uint32_t frac = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
			((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
	if (sec == 0 && frac == 0)
		return 0.0;
	return (double)(sec - NTP_UNIX_EPOCH_DIFF) + (double)frac / 4294967296.0;
}

/*
 * One SNTP transaction. On success writes the freshly computed offset to
 * *offset_out and returns 0; returns -1 on any socket/parse/sanity failure.
 */
static int sntp_query(const char *server, double *offset_out)
{
	struct addrinfo hints, *res = NULL, *rp;
	int fd = -1, rc = -1;
	unsigned char pkt[NTP_PKT_LEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family   = AF_INET;        /* IPv4 NTP for now */
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(server, NTP_PORT, &hints, &res) != 0 || res == NULL)
		return -1;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd >= 0)
			break;
	}
	if (fd < 0) {
		freeaddrinfo(res);
		return -1;
	}

	{
		struct timeval tv = { SNTP_RECV_TIMEOUT, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}

	/* build client request: LI=0, VN=4, Mode=3 (client) */
	memset(pkt, 0, sizeof pkt);
	pkt[0] = (0 << 6) | (4 << 3) | 3;

	double t1 = now_unix();             /* originate */
	if (sendto(fd, pkt, sizeof pkt, 0, rp->ai_addr, rp->ai_addrlen) != NTP_PKT_LEN)
		goto out;

	if (recv(fd, pkt, sizeof pkt, 0) != NTP_PKT_LEN)
		goto out;
	double t4 = now_unix();             /* destination */

	/* sanity: must be a server reply (mode 4) with a usable stratum (1..15) */
	{
		int mode    = pkt[0] & 0x07;
		int stratum = pkt[1];
		if (mode != 4 || stratum < 1 || stratum > 15)
			goto out;
	}

	double t2 = ntp_ts_to_unix(pkt + 32);   /* server receive  */
	double t3 = ntp_ts_to_unix(pkt + 40);   /* server transmit */
	if (t2 == 0.0 || t3 == 0.0)
		goto out;

	/* offset = ((T2 - T1) + (T3 - T4)) / 2 */
	*offset_out = ((t2 - t1) + (t3 - t4)) / 2.0;
	rc = 0;
out:
	close(fd);
	freeaddrinfo(res);
	return rc;
}

static void *sntp_thread(void *arg)
{
	(void)arg;
	for (;;) {
		double offset;
		if (sntp_query(s_server, &offset) == 0) {
			pthread_mutex_lock(&s_lock);
			s_offset = offset;
			s_synced = 1;
			pthread_mutex_unlock(&s_lock);
			CWLog("[ac_sntp] synced to %s: offset %+.3f s, AC UTC now %u",
			      s_server, offset,
			      (uint32_t)(now_unix() + offset + 0.5));
		} else {
			CWLog("[ac_sntp] query to %s failed (keeping last offset, synced=%d)",
			      s_server, s_synced);
		}

		if (s_poll <= 0) {
			/* one-shot: periodic poll disabled. Keep retrying only until
			 * the first successful sync, then stop the thread. */
			if (s_synced) {
				CWLog("[ac_sntp] periodic poll OFF: synced once, "
				      "stopping NTP polling");
				break;
			}
			sleep(SNTP_MIN_POLL);      /* retry cadence until first sync */
		} else {
			sleep((unsigned)s_poll);   /* periodic re-sync */
		}
	}
	return NULL;
}

int acTimeSyncStart(const char *server, int pollInterval)
{
	pthread_t tid;

	if (s_started)
		return 0;
	if (server == NULL || server[0] == '\0')
		return 0;                       /* disabled, not an error */

	snprintf(s_server, sizeof s_server, "%s", server);
	/* pollInterval semantics:
	 *   < 0  : unset -> default periodic interval
	 *   == 0 : one-shot, periodic poll OFF (sync once at startup, then stop)
	 *   > 0  : re-sync every N seconds (clamped to a sane minimum)         */
	if (pollInterval < 0)
		s_poll = SNTP_DEFAULT_POLL;
	else if (pollInterval == 0)
		s_poll = 0;
	else
		s_poll = (pollInterval < SNTP_MIN_POLL) ? SNTP_MIN_POLL : pollInterval;

	if (pthread_create(&tid, NULL, sntp_thread, NULL) != 0)
		return -1;
	pthread_detach(tid);
	s_started = 1;
	return 0;
}

int acTimeSyncGetUTC(uint32_t *utc)
{
	int synced;
	double offset;

	pthread_mutex_lock(&s_lock);
	synced = s_synced;
	offset = s_offset;
	pthread_mutex_unlock(&s_lock);

	if (!synced)
		return -1;
	if (utc)
		*utc = (uint32_t)(now_unix() + offset + 0.5);
	return 0;
}
