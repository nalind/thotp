noinst_LIBRARIES = libthotp.a
libthotp_a_SOURCES = thotp.h thotp.c base32.c

bin_PROGRAMS = totp hotp
totp_LDADD = libthotp.a
hotp_LDADD = libthotp.a
