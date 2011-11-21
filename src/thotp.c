#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "thotp.h"

#define MAX_HMAC_SIZE	(512 / 8)
#define MAX_BLOCK_SIZE	(512 / 8)
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
	(*blob)->data = malloc(howmany(strlen(base32), 8) * 5);
	if ((*blob)->data == NULL) {
		free(*blob);
		*blob = NULL;
		return ENOMEM;
	}
	for (p = base32, counter = 0, (*blob)->length = 0; *p != '\0'; p++) {
		if (*p == '=') {
			break;
		}
		if ((q = strchr(b32alphabet, *p)) == NULL) {
			continue;
		}
		v = (q - b32alphabet) & 0x1f;
		if (counter == 0) {
			memset(buf, '\0', sizeof(buf));
		}
		switch (counter) {
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
		if (counter == 0) {
			memcpy((*blob)->data + (*blob)->length, buf, 5);
			(*blob)->length += 5;
		}
	}
	if (counter != 0) {
		memcpy((*blob)->data + (*blob)->length, buf, 5);
		(*blob)->length += howmany((counter * 5), 8);
	}
	return 0;
}

int
thotp_base32_unparse(struct thotp_blob **blob, char **base32)
{
	size_t length;
	unsigned int i, j;
	unsigned char v[8];

	*base32 = malloc((howmany((*blob)->length, 5) * 8) + 1);
	if (*base32 == NULL) {
		return ENOMEM;
	}
	for (i = 0, length = 0; i < (*blob)->length; i++) {
		if ((i % 5) == 0) {
			memset(v, 0, sizeof(v));
		}
		switch (i % 5) {
		case 0:
			v[0] |= ((*blob)->data[i]) >> 3;
			v[1] |= ((*blob)->data[i] & 0x07) << 2;
			break;
		case 1:
			v[1] |= ((*blob)->data[i] & 0xc0) >> 6;
			v[2] |= ((*blob)->data[i] & 0x3e) >> 1;
			v[3] |= ((*blob)->data[i] & 0x01) << 4;
			break;
		case 2:
			v[3] |= ((*blob)->data[i] & 0xf0) >> 4;
			v[4] |= ((*blob)->data[i] & 0x0f) << 1;
			break;
		case 3:
			v[4] |= ((*blob)->data[i] & 0x80) >> 4;
			v[5] |= ((*blob)->data[i] & 0x7c) >> 2;
			v[6] |= ((*blob)->data[i] & 0x03) << 3;
			break;
		case 4:
			v[6] |= ((*blob)->data[i] & 0xe0) >> 2;
			v[7] |= ((*blob)->data[i] & 0x1f);
			break;
		}
		i++;
		if ((i % 5) == 0) {
			for (j = 0; j < 8; j++) {
				(*base32)[length++] = b32alphabet[v[j]];
			}
		}
	}
	if ((i % 5) != 0) {
		for (j = 0; j < 8; j++) {
			if (j < howmany(i * 8, 5)) {
				(*base32)[length++] = b32alphabet[v[j]];
			} else {
				(*base32)[length++] = '=';
			}
		}
	}

	return 0;
}

static int
thotp_digest_base(unsigned char *data1, size_t data1_size, unsigned char pad,
		  unsigned char *data2_value, size_t data2_size,
		  enum thotp_alg algorithm,
		  unsigned char *out, size_t space, size_t *space_used)
{
	size_t hmac_size, block_size;
	unsigned char block[MAX_BLOCK_SIZE];
	EVP_MD_CTX ctx;
	const EVP_MD *digest;
	unsigned int s;

	memset(&ctx, 0, sizeof(ctx));
	switch (algorithm) {
	case thotp_alg_sha1:
		digest = EVP_sha1();
		break;
	case thotp_alg_sha224:
		digest = EVP_sha224();
		break;
	case thotp_alg_sha256:
		digest = EVP_sha256();
		break;
	case thotp_alg_sha384:
		digest = EVP_sha384();
		break;
	case thotp_alg_sha512:
		digest = EVP_sha512();
		break;
	default:
		return ENOSYS;
	};

	hmac_size = EVP_MD_size(digest);
	if (hmac_size > space) {
		return ENOSPC;
	}
	block_size = EVP_MD_block_size(digest);
	if (data1_size > 0) {
		if (data1_size < block_size) {
			memcpy(block, data1, data1_size);
			memset(block + data1_size, 0, block_size - data1_size);
		} else {
			if ((EVP_DigestInit(&ctx, digest) != 1) ||
			    (EVP_DigestUpdate(&ctx, data1, data1_size) != 1) ||
			    (EVP_DigestFinal(&ctx, block, &s) != 1)) {
				return ENOSYS;
			}
			if (s < block_size) {
				memset(block + s, 0, block_size - s);
			}
		}
		for (s = 0; s < block_size; s++) {
			block[s] ^= pad;
		}
	}

	if ((EVP_DigestInit(&ctx, digest) != 1) ||
	    ((block_size > 0) &&
	     (EVP_DigestUpdate(&ctx, block, block_size) != 1)) ||
	    (EVP_DigestUpdate(&ctx, data2_value, data2_size) != 1) ||
	    (EVP_DigestFinal(&ctx, out, &s) != 1)) {
		return ENOSYS;
	}
	*space_used = s;
	return 0;
}

static int
thotp_hmac_base(struct thotp_blob *key,
		unsigned char *counter_value, size_t counter_size,
		enum thotp_alg algorithm,
		unsigned char *out, size_t space, size_t *space_used)
{
	unsigned char buf2[space];
	int result;

	result = thotp_digest_base(key->data, key->length, 0x36,
				   counter_value, counter_size,
				   algorithm, buf2, space, space_used);
	if (result == 0) {
		result = thotp_digest_base(key->data, key->length, 0x5c,
					   buf2, *space_used,
					   algorithm, out, space, space_used);
	}

	return result;
}

int
thotp_hmac(struct thotp_blob *key, uint64_t counter, enum thotp_alg algorithm,
	   unsigned char *out, size_t space, size_t *space_used)
{
	unsigned char counter_value[64 / 8];
	int i;

	for (i = 0; i < 8; i++) {
		counter_value[i] = (counter >> (64 - ((i + 1) * 8))) & 0xff;
	}
	return thotp_hmac_base(key, counter_value, sizeof(counter_value),
			       algorithm, out, space, space_used);
}

static int
thotp_truncate(unsigned char *hmac, size_t hmac_size, int digits, char *data)
{
	unsigned int offset;
	uint32_t bin_code, multiplier;
	int i;

	if (hmac_size < 1) {
		return ENOSYS;
	}

	offset = hmac[hmac_size - 1] & 0x0f;
	bin_code = ((hmac[offset] & 0x7f) << 24) |
		   ((hmac[offset + 1] & 0xff) << 16) |
		   ((hmac[offset + 2] & 0xff) <<  8) |
		   (hmac[offset + 3] & 0xff);

	for (i = 0, multiplier = 1; i < digits; i++) {
		multiplier *= 10;
	}
	snprintf(data, digits + 1, "%0*lu",
		 digits, (long) (bin_code % multiplier));

	return 0;
}

int
thotp_hotp(struct thotp_blob *key,
	   enum thotp_alg algorithm, uint64_t counter, int digits,
	   char **code)
{
	unsigned char hmac[MAX_HMAC_SIZE];
	size_t hmac_size;
	int result;

	*code = NULL;

	result = thotp_hmac(key, counter, algorithm,
			    hmac, sizeof(hmac), &hmac_size);
	if (result != 0) {
		return result;
	}

	*code = malloc(digits + 1);
	if (*code == NULL) {
		free(*code);
		*code = NULL;
		return ENOMEM;
	}
	memset(*code, '\0', digits + 1);

	result = thotp_truncate(hmac, hmac_size, digits, *code);
	if (result != 0)  {
		free(*code);
		*code = NULL;
		return result;
	}

	return 0;
}

int
thotp_totp(struct thotp_blob *key,
	   enum thotp_alg algorithm, uint64_t step, time_t when, int digits,
	   char **code)
{
	return thotp_hotp(key, algorithm, (when / step), digits, code);
}
