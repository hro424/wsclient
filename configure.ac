#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([libwebsocket], [0.1])
AM_INIT_AUTOMAKE([foreign -Wall -Werror -Wno-extra-portability])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA1])
AC_CHECK_LIB([ssl], [SSL_library_init])

# Checks for header files.
AC_CHECK_HEADERS([netdb.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket strchr strncasecmp strstr strtol])

AC_ARG_ENABLE([ldc], AS_HELP_STRING([--enable-ldc], [LDC protocol support]))
AS_IF([test "x$enable_ldc" = "xyes"],
      [AC_DEFINE([LDC], [1], [LDC protocol support])]
      )

AC_ARG_ENABLE([client-cert],
	      AS_HELP_STRING([--enable-client-cert],
			     [Enable client certificate]))
AS_IF([test "x$enable_client_cert" = "xyes"],
      [AC_DEFINE([CLIENT_CERT], [1], [Enable client certificate])]
      )

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile])
AC_OUTPUT
