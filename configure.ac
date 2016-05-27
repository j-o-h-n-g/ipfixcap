#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipfixcap], [0.1], [github@giggled.org])
AC_CONFIG_SRCDIR([src/ipfixcap.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# PKG
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([FIXBUF],[libfixbuf >= 1.6.0])
PKG_CHECK_MODULES([SYSTEMD],[libsystemd >= 219])

# Silk
IPFIXCAP_AC_OPT_WITH_SILK

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lfixbuf':
AC_CHECK_LIB([fixbuf], [fbSessionAlloc])
# FIXME: Replace `main' with a function in `-lflowsource':
#AC_CHECK_LIB([flowsource], [main])
# FIXME: Replace `main' with a function in `-lsilk':
AC_CHECK_LIB([silk], [appSetup])
# FIXME: Replace `main' with a function in `-lsystemd':
AC_CHECK_LIB([systemd], [sd_journal_open])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset socket strerror strrchr])

AC_CONFIG_FILES([Makefile src/Makefile ipfixcap.spec ipfixcap ipfixcap.conf])
AC_OUTPUT
