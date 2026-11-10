/* libFuzzer harness for libupsclient's handling of upsd replies (clients/upsclient.c):
 * upscli_get(), upscli_list_start() and upscli_list_next() against a fabricated server.
 *
 * Input layout: <mode byte> <query words on one line> '\n' <bytes the "server" sends back>.
 * The reply is pre-loaded into one end of a socketpair that the client reads from. */
#include "config.h"
#include "upsclient.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* private to clients/upsclient.c; upscli_tryconnect() stamps it on a live connection */
#define UPSCLIENT_MAGIC 0x19980308
#define MAX_SIZE 16384
#define MAX_QUERY 6

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	signal(SIGPIPE, SIG_IGN);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	UPSCONN_t ups;
	int sv[2];
	char *buf, *nl, *tok, *save = NULL;
	const char *query[MAX_QUERY];
	size_t numq = 0, numa = 0, replylen, off = 0, n;
	char **answer = NULL;
	uint8_t mode;

	if (size < 3 || size > MAX_SIZE)
		return -1;

	buf = (char *)malloc(size);
	if (!buf)
		return -1;
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';
	mode = data[0];

	nl = (char *)memchr(buf, '\n', size - 1);
	if (!nl) {
		free(buf);
		return -1;
	}
	*nl = '\0';
	replylen = (size_t)((buf + size - 1) - (nl + 1));

	for (tok = strtok_r(buf, " ", &save); tok && numq < MAX_QUERY; tok = strtok_r(NULL, " ", &save))
		query[numq++] = tok;
	if (numq == 0) {
		free(buf);
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		free(buf);
		return -1;
	}

	/* the whole reply, then EOF; the client's own request goes to sv[1]'s (unread) buffer */
	while (off < replylen) {
		ssize_t w = write(sv[1], nl + 1 + off, replylen - off);

		if (w <= 0)
			break;
		off += (size_t)w;
	}
	shutdown(sv[1], SHUT_WR);

	memset(&ups, 0, sizeof(ups));
	ups.fd = sv[0];
	ups.upsclient_magic = UPSCLIENT_MAGIC;
	pconf_init(&ups.pc_ctx, NULL);

	if (mode & 1) {
		if (upscli_list_start(&ups, numq, query) == 0) {
			for (n = 0; n < 64; n++) {
				if (upscli_list_next(&ups, numq, query, &numa, &answer) != 1)
					break;
			}
		}
	} else {
		upscli_get(&ups, numq, query, &numa, &answer);
	}

	upscli_upserror(&ups);
	upscli_strerror(&ups);
	upscli_disconnect(&ups);

	close(sv[0]);
	close(sv[1]);
	free(buf);
	return 0;
}
