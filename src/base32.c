#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "thotp.h"


static const char b32alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int
thotp_base32_parse(const char *base32, struct thotp_blob **blob)
{
	unsigned char buf[5];
	unsigned int counter, v;
	const char *p, *q;

	*blob = malloc(sizeof(**blob));
	if (*blob == NULL) {
		return ENOMEM;
	}
	(*blob)->data = malloc((howmany(strlen(base32), 8) * 5) + 5 + 1);
	if ((*blob)->data == NULL) {
		free(*blob);
		*blob = NULL;
		return ENOMEM;
	}
	for (p = base32, counter = 0, (*blob)->length = 0; *p != '\0'; p++) {
		if (*p == '=') {
			break;
		}
		if ((q = strchr(b32alphabet, toupper(*p))) == NULL) {
			continue;
		}
		v = (q - b32alphabet) & 0x1f;
		if ((counter % 8) == 0) {
			memset(buf, '\0', sizeof(buf));
		}
		switch (counter % 8) {
		case 0:
			buf[0] &= 0x07;
			buf[0] |= (v << 3);
			break;
		case 1:
			buf[0] &= 0xf8;
			buf[0] |= (v >> 2);
			buf[1] &= 0x3f;
			buf[1] |= (v << 6);
			break;
		case 2:
			buf[1] &= 0xc0;
			buf[1] |= (v << 1);
			break;
		case 3:
			buf[1] &= 0xfe;
			buf[1] |= (v >> 4);
			buf[2] &= 0x0f;
			buf[2] |= (v << 4);
			break;
		case 4:
			buf[2] &= 0xf0;
			buf[2] |= (v >> 1);
			buf[3] &= 0x7f;
			buf[3] |= (v << 7);
			break;
		case 5:
			buf[3] &= 0x80;
			buf[3] |= (v << 2);
			break;
		case 6:
			buf[3] &= 0xfc;
			buf[3] |= v >> 3;
			buf[4] &= 0x1f;
			buf[4] |= v << 5;
			break;
		case 7:
			buf[4] &= 0xe0;
			buf[4] |= v;
			break;
		}
		counter++;
		if ((counter % 8) == 0) {
			memcpy((*blob)->data + (*blob)->length, buf, 5);
			(*blob)->length += 5;
		}
	}
	if ((counter % 8) != 0) {
		v = ((counter % 8) * 5) / 8;
		memcpy((*blob)->data + (*blob)->length, buf, v);
		(*blob)->length += v;
	}
	(*blob)->data[(*blob)->length] = '\0';
	return 0;
}

int
thotp_base32_unparse(struct thotp_blob *blob, char **base32)
{
	size_t length;
	unsigned int i, j;
	unsigned char v[8];

	*base32 = malloc((howmany(blob->length, 5) * 8) + 1);
	if (*base32 == NULL) {
		return ENOMEM;
	}
	for (i = 0, length = 0; i < blob->length; i++) {
		if ((i % 5) == 0) {
			memset(v, 0, sizeof(v));
		}
		switch (i % 5) {
		case 0:
			v[0] |= (blob->data[i]) >> 3;
			v[1] |= (blob->data[i] & 0x07) << 2;
			break;
		case 1:
			v[1] |= (blob->data[i] & 0xc0) >> 6;
			v[2] |= (blob->data[i] & 0x3e) >> 1;
			v[3] |= (blob->data[i] & 0x01) << 4;
			break;
		case 2:
			v[3] |= (blob->data[i] & 0xf0) >> 4;
			v[4] |= (blob->data[i] & 0x0f) << 1;
			break;
		case 3:
			v[4] |= (blob->data[i] & 0x80) >> 7;
			v[5] |= (blob->data[i] & 0x7c) >> 2;
			v[6] |= (blob->data[i] & 0x03) << 3;
			break;
		case 4:
			v[6] |= (blob->data[i] & 0xe0) >> 5;
			v[7] |= (blob->data[i] & 0x1f);
			break;
		}
		if ((i % 5) == 4) {
			for (j = 0; j < 8; j++) {
				(*base32)[length++] = b32alphabet[v[j]];
			}
		}
	}
	if ((i % 5) != 0) {
		for (j = 0; j < 8; j++) {
			if (j < howmany((i % 5) * 8, 5)) {
				(*base32)[length++] = b32alphabet[v[j]];
			} else {
				(*base32)[length++] = '=';
			}
		}
	}
	(*base32)[length] = '\0';

	return 0;
}
