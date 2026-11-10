/* libFuzzer harness for libupsclient's pure string parsers (clients/upsclient.c):
 * upscli_splitname() "ups[@host[:port]]" and upscli_splitaddr() "host[:port]" (including bracketed
 * IPv6 literals) as given to upsc/upsmon/upslog and monitoring plugins; the connect-timeout seconds
 * parsers upscli_set_default_connect_timeout() / upscli_init_default_connect_timeout()
 * (NUT_DEFAULT_CONNECT_TIMEOUT, -w); and the token helpers upscli_str_contains_token() /
 * upscli_str_add_unique_token().
 *
 * Input layout: <mode byte> <text>. Mode (low two bits): 0 splitaddr, 1 splitname, 2 connect timeout
 * (up to three newline-separated values), 3 tokens (text is "<target string>\n<token>"). */
#include "config.h"
#include "upsclient.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 1024
#define TGT_SIZE 64

static int cb_always(char *tgt, size_t tgtsize, const char *token)
{
	(void)tgt;
	(void)tgtsize;
	return token[0] != '!';
}

static int cb_unique(char *tgt, size_t tgtsize, const char *token)
{
	(void)tgt;
	(void)tgtsize;
	return token[0] != '#';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf, *upsname = NULL, *hostname = NULL;
	uint16_t port = 0;
	int rc = 0;

	if (size < 2 || size > MAX_SIZE)
		return -1;

	buf = (char *)malloc(size);
	if (!buf)
		return -1;
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';

	switch (data[0] & 3) {
	case 0:
		rc = upscli_splitaddr(buf, &hostname, &port);
		break;
	case 1:
		rc = upscli_splitname(buf, &upsname, &hostname, &port);
		break;
	case 2: {
		struct timeval tv;
		const char *secs[3] = { NULL, NULL, NULL };
		char *line = buf, *nl;
		size_t i;

		rc = upscli_set_default_connect_timeout(buf);
		upscli_get_default_connect_timeout(&tv);
		/* up to three newline-separated values: command line, config file, built-in default */
		for (i = 0; i < 3 && line; i++) {
			secs[i] = line;
			nl = strchr(line, '\n');
			if (nl)
				*nl++ = '\0';
			line = nl;
		}
		upscli_init_default_connect_timeout(secs[0], secs[1], secs[2]);
		upscli_get_default_connect_timeout(&tv);
		/* NULL restores the built-in blocking default, so no input leaks into the next */
		upscli_set_default_connect_timeout(NULL);
		break;
	}
	default: {
		char tgt[TGT_SIZE];
		char *token = strchr(buf, '\n');

		if (!token) {
			rc = -1;
			break;
		}
		*token++ = '\0';

		/* the target must be a NUL-terminated string that fits in tgt */
		snprintf(tgt, sizeof(tgt), "%s", buf);
		upscli_str_contains_token(tgt, token);
		rc = upscli_str_add_unique_token(tgt, sizeof(tgt), token, NULL, NULL);
		upscli_str_contains_token(tgt, token);
		upscli_str_add_unique_token(tgt, sizeof(tgt), token, cb_always, cb_unique);
		break;
	}
	}

	free(upsname);
	free(hostname);
	free(buf);
	return rc >= 0 ? 0 : -1;
}
