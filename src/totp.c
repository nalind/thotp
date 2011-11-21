#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "thotp.h"

int
main(int argc, char **argv)
{
	struct thotp_blob *key;
	char *code;
	int i;

	for (i = 1; i < argc; i++) {
		fflush(NULL);
		if (thotp_base32_parse(argv[i], &key) != 0) {
			fprintf(stderr, "Error parsing key \"%s\".\n", argv[i]);
			continue;
		}
		if (thotp_totp(key, thotp_alg_sha1,
			       30, time(NULL), 6, &code) != 0) {
			fprintf(stderr, "Error calculating TOTP.\n");
			continue;
		}
		printf("\"%s\" = %s\n", argv[i], code);
		free(code);
	}
	return 0;
}
