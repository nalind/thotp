#include "../src/config.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/thotp.h"

int
main(int argc, char **argv)
{
	struct thotp_blob *blob, blub;
	struct {
		size_t size;
		const unsigned char *vector;
		const char *output;
	} vectors[] = {
		{0, "", ""},
		{1, "f", "MY======"},
		{2, "fo", "MZXQ===="},
		{3, "foo", "MZXW6==="},
		{4, "foob", "MZXW6YQ="},
		{5, "fooba", "MZXW6YTB"},
		{6, "foobar", "MZXW6YTBOI======"},
	};
	unsigned int i;
	char *encoded;

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		blob = NULL;
		if (thotp_base32_parse(vectors[i].output, &blob) != 0) {
			fprintf(stderr, "Error decoding \"%s\".\n",
				vectors[i].output);
			return 1;
		}
		if (blob->length != strlen(vectors[i].vector)) {
			fprintf(stderr, "Wrong output length decoding \"%s\" "
			        "(got %u, expected %u).\n", vectors[i].output,
				blob->length, strlen(vectors[i].vector));
			return 2;
		}
		if (strcmp(blob->data, vectors[i].vector) != 0) {
			fprintf(stderr, "Wrong output decoding \"%s\" "
				"(\"%.*s\").\n",
				vectors[i].output, blob->length, blob->data);
			return 3;
		}
		if (thotp_base32_unparse(blob, &encoded) != 0) {
			fprintf(stderr, "Error encoding \"%.*s\".\n",
				(int) blob->length, blob->data);
			return 4;
		}
		if (strcmp(encoded, vectors[i].output) != 0) {
			fprintf(stderr, "Wrong output encoding \"%.*s\" "
				"(\"%s\").\n",
				(int) blob->length, blob->data, encoded);
			return 5;
		}
	}

	return 0;
}
