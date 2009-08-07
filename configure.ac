# Copyright (C) 2005, 2006, 2007, 2009  Heiko Stamer <stamer@gaos.org>
#
# This file is part of LibTMCG.
#
# LibTMCG is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser general Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# LibTMCG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with LibTMCG; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (Process this file with autoconf to produce a configure script.)

AC_REVISION($Revision: 1.44 $)
AC_PREREQ(2.57)

AC_INIT(libTMCG, 1.1.2, stamer@gaos.org)

# The next two paragraphs are copies of libgcrypt behaviour.

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBTMCG_LT_CURRENT=2
LIBTMCG_LT_AGE=1
LIBTMCG_LT_REVISION=1

# If API is changed in an incompatible way: increment the next counter.
LIBTMCG_CONFIG_API_VERSION=2

AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_LANG(C++)
AC_CONFIG_SRCDIR(src/libTMCG.hh)
#AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_SUBST(LIBTMCG_LT_CURRENT)
AC_SUBST(LIBTMCG_LT_AGE)
AC_SUBST(LIBTMCG_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION", [Version of this package])

# Compiler and linker switches used by libTMCG-config script
LIBTMCG_CONFIG_LIBS="-lTMCG"
LIBTMCG_CONFIG_CFLAGS=""

# Check commandline switches

# Define some security parameters and helping macros
# (NOTE: Please update also libTMCG.hh, if changed!)
AC_DEFINE(TMCG_LIBGCRYPT_VERSION, "1.2.0",
	[Define the necessary version number of the GNU gcrypt library])
AC_DEFINE(TMCG_LIBGMP_VERSION, "4.1.0",
	[Define the necessary version number of the GNU gmp library])
AC_DEFINE(TMCG_MAX_FPOWM_T, 2048,
	[Define the maximum size of the exponent for fast exponentiation])
AC_DEFINE(TMCG_MPZ_IO_BASE, 36,
	[Define the input/ouput base encoding of the iostream operators])
AC_DEFINE(TMCG_GCRY_MD_ALGO, GCRY_MD_RMD160,
	[Define the message digest algorithm for signatures and FS-heuristic;
	Underlying assumption: Random Oracle Model])

AC_DEFINE(TMCG_MR_ITERATIONS, 64,
	[Define the number of iterations for the Miller-Rabin primality test.
	(maximum soundness error probability 4^{-TMCG_MR_ITERATIONS})])
AC_DEFINE(TMCG_GROTH_L_E, 80,
	[Define the security parameter for the soundness of the
	interactive argument for Groth's VSSHE and SKC.])
AC_DEFINE(TMCG_DDH_SIZE, 1024,
	[Define the security parameter of the DDH-hard group G;
	Underlying assumptions: DDH, CDH, DLOG])
AC_DEFINE(TMCG_DLSE_SIZE, 160,
	[Define the security parameter of the shortened exponents;
	Underlying assumptions: DLSE (related to DDH), DLOG])
AC_DEFINE(TMCG_QRA_SIZE, 1024,
	[Define the security parameter of the TMCG public key;
	Underlying assumptions: QRA, FACTOR])
AC_DEFINE(TMCG_KEYID_SIZE, 8,
	[Define the size of the unique TMCG key ID (in characters)])
AC_DEFINE(TMCG_HASH_COMMITMENT, true,
	[Define whether hashed commitments (short values) should be used;
	Underlying assumption: Random Oracle Model])
AC_DEFINE(TMCG_SAEP_S0, 20,
	[Define the security parameter for the encryption with Rabin/SAEP])
AC_DEFINE(TMCG_PRAB_K0, 20,
	[Define the security parameter for the signature generation with Rabin/PRab])
AC_DEFINE(TMCG_KEY_NIZK_STAGE1, 16,
	[Define the maximum soundness error probability of the TMCG public key;
	NIZK proof (Gennaro, Micciancio, Rabin), Stage 1: m is square free;
	d^{-TMCG_KEY_NIZK_STAGE1} with d = ...])
AC_DEFINE(TMCG_KEY_NIZK_STAGE2, 128,
	[Define the maximum soundness error probability of the TMCG public key;
	NIZK proof (Gennaro, Micciancio, Rabin), Stage 2: m is prime power product;
	2^{-TMCG_KEY_NIZK_STAGE2}])
AC_DEFINE(TMCG_KEY_NIZK_STAGE3, 128,
	[Define the maximum soundness error probability for the TMCG public key;
	NIZK proof (Goldwasser, Micali); Stage 3: y \in NQR^\circ_m;
	2^{-TMCG_KEY_NIZK_STAGE3}])
	
AC_DEFINE(TMCG_MAX_PLAYERS, 32,
	[Define the maximum number of players in the scheme of Schindelhauer])
AC_DEFINE(TMCG_MAX_CARDS, 128,
	[Define the maximum number of stackable cards])
AC_DEFINE(TMCG_MAX_TYPEBITS, 8,
	[Define the number of bits which represents the maximum number of
	different card types in the scheme of Schindelhauer and the maximum
	size of the message space in the scheme of Barnett and Smart])
	
AC_DEFINE(TMCG_MAX_KEYBITS,
	[((TMCG_DDH_SIZE > TMCG_QRA_SIZE) ? TMCG_DDH_SIZE : TMCG_QRA_SIZE)],
	[Define a helping macro])
AC_DEFINE(TMCG_MAX_VALUE_CHARS,
	[(TMCG_MAX_KEYBITS / 2L)],
	[Define a helping macro])
AC_DEFINE(TMCG_MAX_CARD_CHARS,
	[(TMCG_MAX_PLAYERS * TMCG_MAX_TYPEBITS * TMCG_MAX_VALUE_CHARS)],
	[Define a helping macro])
AC_DEFINE(TMCG_MAX_STACK_CHARS,
	[(TMCG_MAX_CARDS * TMCG_MAX_CARD_CHARS)],
	[Define a helping macro])
AC_DEFINE(TMCG_MAX_KEY_CHARS,
	[(TMCG_MAX_KEYBITS * 1024L)],
	[Define a helping macro])

# Checks for programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries
AC_CHECK_LIB(gmp, __gmpz_import, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, , AC_MSG_ERROR([libgmp >= 4.1 is needed]))
##AC_CHECK_LIB(gmpxx, __gmpz_set_str, ,
##	AC_MSG_ERROR([libgmpxx (C++ support) >= 4.1 is needed]))
LIBGMP_LIBS="-lgmp"
AC_SUBST(LIBGMP_LIBS)

AM_PATH_LIBGCRYPT("1.2.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.2.0 is needed])
fi

AM_PATH_GPG_ERROR("0.5")
if test "x$GPG_ERROR_LIBS" = "x"; then
	AC_MSG_ERROR([libgpg-error >= 0.5 is needed])
fi

# Checks for header files
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS([algorithm assert.h cassert cstdarg cstdio cstdlib cstring\
 errno.h functional gcrypt.h gmp.h iostream limits.h map sstream stdio.h\
 string sys/wait.h time.h unistd.h vector], , AC_MSG_ERROR([headers are missing]))

# Checks for typedefs, structures, and compiler characteristics
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_PID_T

# Checks for library functions
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([clock close fork fprintf memcmp memcpy memset pipe snprintf\
 strtoul waitpid], , AC_MSG_ERROR([functions are missing]))

# Enable all compiler warnings
CFLAGS="$CFLAGS -Wall"
CXXFLAGS="$CXXFLAGS -Wall"

# Initialize libTMCG-config script
AC_SUBST(LIBTMCG_CONFIG_API_VERSION)
AC_SUBST(LIBTMCG_CONFIG_LIBS)
AC_SUBST(LIBTMCG_CONFIG_CFLAGS)

AC_CONFIG_COMMANDS([libTMCG-config],[[
chmod +x src/libTMCG-config
]],[[
prefix=$prefix
exec_prefix=$exec_prefix
libdir=$libdir
datadir=$datadir
]])

# Define output
AC_CONFIG_FILES([Makefile src/Makefile src/libTMCG-config doc/Makefile tests/Makefile])
AC_OUTPUT

echo "Now type 'make && make install' to build and install LibTMCG."
