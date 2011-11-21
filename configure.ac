AC_INIT(thotp,0.0)
AM_INIT_AUTOMAKE([foreign])
AC_LANG_C
AC_PROG_CC
AC_PROG_RANLIB
AC_CHECK_FUNCS(EVP_DigestInit,,AC_CHECK_LIB(crypto,EVP_DigestInit))
AC_CONFIG_HEADER(src/config.h)
AC_OUTPUT(Makefile src/Makefile)
