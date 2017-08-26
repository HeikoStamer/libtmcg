# Copyright (C) 2005, 2006, 2007, 2009, 2015, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>
#
# This file is part of LibTMCG.
#
#   LibTMCG is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   LibTMCG is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with LibTMCG; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (Process this file with autoconf to produce a configure script.)

AC_REVISION([20170827])
AC_PREREQ(2.61)

AC_INIT([LibTMCG], [1.3.2], [HeikoStamer@gmx.net], [libTMCG], [http://www.nongnu.org/libtmcg/])

# The next two paragraphs are copies of libgcrypt behaviour.

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBTMCG_LT_CURRENT=6
LIBTMCG_LT_AGE=0
LIBTMCG_LT_REVISION=0

# If API is changed in an incompatible way: increment the next counter.
LIBTMCG_CONFIG_API_VERSION=4

AC_LANG(C++)
AC_CONFIG_SRCDIR([src/libTMCG.hh])
AC_CONFIG_HEADERS([libTMCG_config.h])
AM_INIT_AUTOMAKE
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
AC_DEFINE(TMCG_LIBGCRYPT_VERSION, "1.6.0",
	[Define the necessary version number of the GNU gcrypt library])
AC_DEFINE(TMCG_LIBGMP_VERSION, "4.2.0",
	[Define the necessary version number of the GNU gmp library])
AC_DEFINE(TMCG_MAX_FPOWM_T, 2048,
	[Define the maximum size of the exponent for fast exponentiation])
AC_DEFINE(TMCG_MAX_FPOWM_N, 256,
	[Define the maximum number of bases for doing the precomputation])
AC_DEFINE(TMCG_MPZ_IO_BASE, 62,
	[Define the input/ouput base encoding of the iostream operators])
AC_DEFINE(TMCG_GCRY_MD_ALGO, GCRY_MD_SHA256,
	[Define the message digest algorithm for signatures and FS-heuristic;
	Underlying assumption: Random Oracle Model])
AC_DEFINE(TMCG_GCRY_MAC_ALGO, GCRY_MAC_HMAC_SHA256,
	[Define the message authentication algorithm for authenticated channels])
AC_DEFINE(TMCG_GCRY_ENC_ALGO, GCRY_CIPHER_AES256,
	[Define the cipher for encryption of private channels])

AC_DEFINE(TMCG_OPENPGP_CRC24_INIT, 0xB704CE,
	[Define the initial value for OPENPGP CRC24 algorithm])
AC_DEFINE(TMCG_OPENPGP_CRC24_POLY, 0x1864CFB,
	[Define the generator for OPENPGP CRC24 algorithm])
AC_DEFINE(TMCG_OPENPGP_RADIX64_MC, 64,
	[Define the maximum number of characters in a single line of Radix-64 encoding])

AC_DEFINE(TMCG_MR_ITERATIONS, 64,
	[Define the number of iterations for the Miller-Rabin primality test.
	(maximum soundness error probability 4^{-TMCG_MR_ITERATIONS})])
AC_DEFINE(TMCG_MAX_ZNP_ITERATIONS, 80,
	[Define the maximum number of iterations for the prover in cut-and-choose
	style zero-knowledge protocols of Schindelhauer's toolbox. This limits the
	soundness error probability to 2^{-TMCG_MAX_ZNP_ITERATIONS}, however, it
	avoids some obvious denial-of-service attacks.])
AC_DEFINE(TMCG_MAX_DKG_PLAYERS, 256,
	[Define the maximum number of parties for DKG protocols.])
AC_DEFINE(TMCG_GROTH_L_E, 80,
	[Define the security parameter for the soundness of the
	interactive argument for Groth's VSSHE and SKC.])
AC_DEFINE(TMCG_DDH_SIZE, 2048,
	[Define the security parameter of the DDH-hard group G;
	Underlying assumptions: DDH, CDH, DLOG])
AC_DEFINE(TMCG_DLSE_SIZE, 256,
	[Define the security parameter of the used exponents (subgroup size);
	Underlying assumptions: DLSE (related to DDH), DLOG])
AC_DEFINE(TMCG_AIO_HIDE_SIZE, 256,
	[Define the security parameter for hiding the length of integers.])
AC_DEFINE(TMCG_QRA_SIZE, 2048,
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
AC_DEFINE(TMCG_MAX_CARDS, 1024,
	[Define the maximum number of stackable cards])
AC_DEFINE(TMCG_MAX_TYPEBITS, 10,
	[Define the number of bits which represents the maximum number of
	different card types in the scheme of Schindelhauer and the maximum
	size of the message space in the scheme of Barnett and Smart])
	
AC_DEFINE(TMCG_MAX_KEYBITS,
	[((TMCG_DDH_SIZE > TMCG_QRA_SIZE) ? (4 * TMCG_DDH_SIZE) : (4 * TMCG_QRA_SIZE))],
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

# Checks for Libtool
LT_PREREQ([2.4.2])
LT_INIT
LT_LANG([C++])

# Checks for programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Checks for libraries
backup_LDFLAGS="$LDFLAGS"       
backup_CPPLAGS="$CPPFLAGS"
AC_ARG_WITH(gmp, [AS_HELP_STRING([--with-gmp=<path>], [prefix of libgmp installation e.g. /usr/local])],\
 [GMP_PREFIX="$with_gmp" LDFLAGS="-L${with_gmp}/lib $backup_LDFLAGS" CPPFLAGS="-I${with_gmp}/include $backup_CPPFLAGS"],\
 [AC_CHECK_LIB(gmp, __gmpz_init, [LIBS=""], AC_MSG_ERROR([libgmp is needed; maybe you want call configure with the --with-gmp=<path> option]))])
AC_CHECK_LIB(gmp, __gmpz_import, [LIBS=""], AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, [LIBS=""], AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_LIB(gmp, __gmpz_powm_sec, AC_DEFINE(HAVE_POWMSEC, , [Defined if your libgmp have the mpz_powm_sec() function]), AC_MSG_WARN([libgmp >= 5.0.3 is recommended]))
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([libgmp headers are missing]))
if test "x$GMP_PREFIX" != x ; then
	LIBGMP_LIBS=" -L${GMP_PREFIX}/lib"
	LIBGMP_CFLAGS=" -I${GMP_PREFIX}/include"
else
	LIBGMP_LIBS=""
	LIBGMP_CFLAGS=""
fi
LIBGMP_LIBS="${GMP_LIBS} -lgmp"
AC_SUBST(LIBGMP_LIBS)
AC_SUBST(LIBGMP_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

AM_PATH_LIBGCRYPT("1.6.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.6.0 is needed])
fi
backup_CPPLAGS="$CPPFLAGS"
CPPFLAGS="$LIBGCRYPT_CFLAGS $backup_CPPFLAGS"
AC_CHECK_HEADERS([gcrypt.h], , AC_MSG_ERROR([libgcrypt headers are missing]))
CPPFLAGS="$backup_CPPFLAGS"

AM_PATH_GPG_ERROR("1.12")
if test "x$GPG_ERROR_LIBS" = "x"; then
	AC_MSG_ERROR([libgpg-error >= 1.12 is needed])
fi

# Checks for header files
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([algorithm assert.h cassert cstdarg cstdio cstdlib cstring\
 ctime errno.h fcntl.h fstream functional inttypes.h iostream limits.h list\
 map sstream stdio.h string string.h sys/select.h time.h unistd.h vector], , 
	AC_MSG_ERROR([some headers are missing]))

# Checks for typedefs, structures, and compiler characteristics
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([abs clock close fcntl fprintf memcmp memcpy memset open perror\
 read sscanf select sleep snprintf strrchr strtoul time write], ,
	AC_MSG_ERROR([some functions are missing]))

# Checks for forking tests feature
AC_MSG_CHECKING([whether forking tests are enabled])
AC_ARG_ENABLE(forking, [AS_HELP_STRING([--disable-forking],
	[disable forking tests])], use_forking=$enableval, use_forking=yes)
AC_MSG_RESULT($use_forking)
if test "$use_forking" = yes ; then
	AC_HEADER_SYS_WAIT
	AC_TYPE_PID_T
	AC_FUNC_FORK
	AC_CHECK_HEADERS([unistd.h sys/types.h sys/wait.h signal.h], ,
		AC_MSG_ERROR([some headers are missing]))
	AC_CHECK_FUNCS([fork kill pipe pipe2 waitpid], ,
		AC_MSG_ERROR([some functions are missing]))
	AC_DEFINE(FORKING, , [Define to enable the forking tests])
fi

# Checks for dkg-tools
AC_MSG_CHECKING([whether building dkg-tools is enabled])
AC_ARG_ENABLE(dkgtools, [AS_HELP_STRING([--disable-dkg-tools],
	[disable building of dkg-tools])], use_dkgtools=$enableval, use_dkgtools=yes)
AC_MSG_RESULT($use_dkgtools)
if test "$use_dkgtools" = yes ; then
	AC_HEADER_SYS_WAIT
	AC_TYPE_PID_T
	AC_TYPE_SIGNAL
	AC_FUNC_FORK
	AC_CHECK_HEADERS([unistd.h sys/types.h sys/wait.h signal.h arpa/inet.h\
 netdb.h netinet/in.h sys/socket.h], ,
		AC_MSG_ERROR([some headers are missing]))
	AC_CHECK_FUNCS([fork kill pipe pipe2 waitpid getaddrinfo getnameinfo\
 htons htonl socket setsockopt connect bind listen accept signal sigaction\
 gai_strerror freeaddrinfo inet_ntop], , 
		AC_MSG_ERROR([some functions are missing]))
	AC_DEFINE(DKGTOOLS, , [Define to enable building of dkg-tools])
fi
AM_CONDITIONAL([DKGTOOLS], [test x$use_dkgtools = xyes])

# Checks for GNUnet
gnunet=0
lookin=${prefix}
backup_LDFLAGS="$LDFLAGS"       
backup_CPPLAGS="$CPPFLAGS"
GNUNET_LIBS=""
GNUNET_CFLAGS=""
AC_MSG_CHECKING([for GNUnet])
AC_ARG_WITH(gnunet, [AS_HELP_STRING([--with-gnunet=<path>],
	[prefix of GNUnet installation])], [AC_MSG_RESULT([$with_gnunet])
	case $with_gnunet in
		no)
			lookin=""
			;;
		yes)
			lookin="${prefix}"
			;;
		*)
			lookin="$with_gnunet"
			;;
	esac
	], [AC_MSG_RESULT([--with-gnunet not specified])])

if test "x$gnunet" == "x0" -a ! "x$lookin" == "x"
then
	GNUNET_LIBS="-L${lookin}/lib"
	GNUNET_CFLAGS="-I${lookin}/include"
	LDFLAGS="$GNUNET_LIBS $backup_LDFLAGS"
	CPPFLAGS="$GNUNET_CFLAGS $backup_CPPFLAGS"
	AC_CHECK_HEADERS([gnunet/gnunet_util_lib.h], [gnunet=1], [gnunet=0], [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunetutil], [GNUNET_xfree_], [LIBS=""], [gnunet=0])
##	AC_CHECK_HEADERS([gnunet/gnunet_peerinfo_service.h], , [gnunet=0], [#include <gnunet/platform.h>])
##	AC_CHECK_LIB([gnunetpeerinfo], [GNUNET_PEERINFO_connect], [LIBS=""], [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_hello_lib.h], , [gnunet=0], [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunethello], [GNUNET_HELLO_get_id], [LIBS=""], [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_transport_hello_service.h], , [gnunet=0], [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunettransport], [GNUNET_TRANSPORT_hello_get], [LIBS=""], [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_cadet_service.h], , [gnunet=0], [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunetcadet], [GNUNET_CADET_connect], [LIBS=""], [gnunet=0])
fi
if test "x$gnunet" == "x1"
then
	AC_DEFINE(GNUNET, , [Define to enable the GNUnet-based tools])
	GNUNET_LIBS="${GNUNET_LIBS} -lgnunetutil -lgnunethello -lgnunettransport -lgnunetcadet"
fi
if test "x$gnunet" == "x0"
then
	GNUNET_LIBS=""
	GNUNET_CFLAGS=""
fi
AC_SUBST(GNUNET_LIBS)
AC_SUBST(GNUNET_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

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
AC_CONFIG_FILES([Makefile src/Makefile src/libTMCG-config doc/Makefile tests/Makefile tools/Makefile])
AC_OUTPUT

echo "Now type 'make && make install' to build and install LibTMCG."
