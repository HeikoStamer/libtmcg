# Copyright (C) 2005 Heiko Stamer <stamer@gaos.org>
#
# This file is part of libTMCG.
#
# libTMCG is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser general Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# libTMCG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with libTMCG; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#
# (Process this file with autoconf to produce a configure script.)

AC_REVISION($Revision: 1.4 $)
AC_PREREQ(2.57)

AC_INIT(libTMCG, 1.0.0, stamer@gaos.org)

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBTMCG_LT_CURRENT=1
LIBTMCG_LT_AGE=0
LIBTMCG_LT_REVISION=0

# If the API is changed in an incompatible way: increment the next counter.
LIBTMCG_CONFIG_API_VERSION=1

AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_LANG(C++)
AC_CONFIG_SRCDIR([src/libTMCG.hh])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION", [Version of this package])
AC_SUBST(LIBTMCG_LT_CURRENT)
AC_SUBST(LIBTMCG_LT_AGE)
AC_SUBST(LIBTMCG_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

# Used by libgcrypt-config
LIBTMCG_CONFIG_LIBS="-lTMCG"
LIBTMCG_CONFIG_CFLAGS=""

# Check commandline switches.

AC_DEFINE(TMCG_LIBGCRYPT_VERSION, "1.2.0",
	[Define appropriate version number of the necessary gcrypt library])
AC_DEFINE(TMCG_MPZ_IO_BASE, 36,
	[Define input/ouput base encoding of the iostream operators])
AC_DEFINE(TMCG_GCRY_MD_ALGO, GCRY_MD_RMD160,
	[Define message digest algorithm for signatures and FS-heuristic; Underlying assumptions: Random Oracle Model])
AC_DEFINE(TMCG_DDH_P_SIZE, 1024L,
	[Define security parameter of the DDH-hard group G; Underlying assumptions: DDH, CDH, DLOG])
AC_DEFINE(TMCG_DLSE_SIZE, 160L,
	[Define security parameter of the used exponents; Underlying assumptions: DLSE (related to DDH)])
AC_DEFINE(TMCG_KEY_SIZE, 1024L,
	[Define security parameter of the TMCG public key; Underlying assumptions: QRA, FAKTOR])
AC_DEFINE(TMCG_KEYID_SIZE, 5,
	[Define size of the unique TMCG key ID (in characters)])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries.
AC_CHECK_LIB(gmp, __gmpz_import, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
##AC_CHECK_LIB(gmpxx, __gmpz_set_str, , AC_MSG_ERROR([libgmpxx (C++ support) >= 4.1 is needed]))
LIBGMP_LIBS = -lgmp

AM_PATH_LIBGCRYPT("1.2.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.2.0 is needed])
fi

AM_PATH_GPG_ERROR("0.5")
if test "x$GPG_ERROR_LIBS" = "x"; then
	AC_MSG_ERROR([libgpg-error >= 0.5 is needed])
fi

# Checks for header files.
AC_PATH_X
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h strings.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([bzero memcpy memset strchr strncasecmp strrchr strstr strtol strtoul])

CXXFLAGS="-O2 -Wall -g3 -pedantic"
##CXXFLAGS="$CXXFLAGS -O2 -Wall -D NODEBUG"

AC_SUBST(LIBTMCG_CONFIG_API_VERSION)
AC_SUBST(LIBTMCG_CONFIG_LIBS)
AC_SUBST(LIBTMCG_CONFIG_CFLAGS)

AC_CONFIG_COMMANDS([libTMCG-conf],[[
chmod +x src/libTMCG-config
]],[[
prefix=$prefix
exec_prefix=$exec_prefix
libdir=$libdir
datadir=$datadir
DATADIRNAME=$DATADIRNAME
]])

AC_CONFIG_FILES([Makefile src/Makefile src/libTMCG-config])
AC_OUTPUT

echo "Now type 'make && make install' to build and to install libTMCG."
