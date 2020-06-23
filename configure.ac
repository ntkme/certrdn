AC_PREREQ([2.69])
AC_INIT([certrdn], [1.0.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls])

AC_TYPE_SIZE_T

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    test/Makefile
])
AC_OUTPUT
