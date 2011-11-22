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
	char *code, *p;
	unsigned long long counter;
	int i;

	for (i = 1; i < argc; i++) {
		fflush(NULL);
		if (thotp_base32_parse(argv[i], &key) != 0) {
			fprintf(stderr, "Error parsing key \"%s\".\n", argv[i]);
			continue;
		}
		if (argv[i + 1] == NULL) {
			fprintf(stderr, "No counter value.\n");
			continue;
		}
		counter = strtoull(argv[i + 1], &p, 10);
		if ((p == NULL) || (*p != '\0')) {
			fprintf(stderr, "Error parsing counter %s%s%s.\n",
				argv[i + 1] ? "\"" : "",
				argv[i + 1] ?: "",
				argv[i + 1] ? "\"" : "");
			continue;
		}
		i++;
		if (thotp_hotp(key, thotp_alg_sha1,
			       (uint64_t) counter, 6, &code) != 0) {
			fprintf(stderr, "Error calculating TOTP.\n");
			continue;
		}
		printf("\"%s\"(%llu) = %s\n", argv[i - 1], counter, code);
		free(code);
	}
	return 0;
}
