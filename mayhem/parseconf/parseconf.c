/* libFuzzer harness for NUT's configuration/protocol line tokenizer (common/parseconf.c),
 * which parses ups.conf-style files and every upsd/upsc network reply. */
#include "config.h"
#include "parseconf.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 65536

static void quiet_errhandler(const char *msg)
{
	(void)msg;
}

static size_t walk_args(const PCONF_CTX_t *ctx)
{
	size_t i, total = 0;

	for (i = 0; i < ctx->numargs; i++)
		total += strlen(ctx->arglist[i]);

	return total;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	PCONF_CTX_t ctx;
	size_t i, sink = 0;
	char enc[512];
	char *line;

	if (size < 2 || size > MAX_SIZE)
		return -1;

	pconf_init(&ctx, quiet_errhandler);

	if (data[0] & 1) {
		/* one character at a time, as the file reader does */
		for (i = 1; i < size; i++) {
			int rc = pconf_char(&ctx, (char)data[i]);

			if (rc == 1) {
				sink += walk_args(&ctx);
			} else if (rc < 0) {
				break;
			}
		}
	} else {
		/* a whole NUL-terminated line, as the network client parser does */
		line = (char *)malloc(size);
		if (!line) {
			pconf_finish(&ctx);
			return -1;
		}
		memcpy(line, data + 1, size - 1);
		line[size - 1] = '\0';

		if (pconf_line(&ctx, line)) {
			sink += walk_args(&ctx);
			for (i = 0; i < ctx.numargs; i++) {
				pconf_encode(ctx.arglist[i], enc, 1 + (data[0] >> 1) % (sizeof(enc) - 1));
				sink += (unsigned char)enc[0];
			}
		}
		free(line);
	}

	pconf_finish(&ctx);

	return sink > MAX_SIZE * 64 ? -1 : 0;
}
