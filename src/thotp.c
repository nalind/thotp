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
