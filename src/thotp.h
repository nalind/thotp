#ifndef thotp_h
#define thotp_h

struct thotp_blob {
	unsigned char *data;
	size_t length;
};
enum thotp_alg {
	thotp_alg_sha1,
	thotp_alg_sha224,
	thotp_alg_sha256,
	thotp_alg_sha384,
	thotp_alg_sha512,
};

int thotp_base32_parse(const char *base32, struct thotp_blob **blob);
int thotp_base32_unparse(struct thotp_blob **blob, char **base32);
int thotp_hotp(struct thotp_blob *key,
	       enum thotp_alg algorithm, uint64_t counter, int digits,
	       char **code);
int thotp_totp(struct thotp_blob *key,
	       enum thotp_alg algorithm, uint64_t step, time_t when, int digits,
	       char **code);

#endif
