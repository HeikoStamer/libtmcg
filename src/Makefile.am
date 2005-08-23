# Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>
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

EXTRA_DIST = libTMCG-config.in libTMCG.m4

bin_SCRIPTS = libTMCG-config

include_HEADERS = mpz_srandom.h mpz_sqrtm.h mpz_spowm.h mpz_sprime.h\
	mpz_shash.hh parse_helper.hh mpz_helper.hh\
	BarnettSmartVTMF_dlog.hh BarnettSmartVTMF_dlog_GroupQR.hh\
	GrothVSSHE.hh SchindelhauerTMCG.hh\
	VTMF_Card.hh VTMF_CardSecret.hh\
	TMCG_Card.hh TMCG_CardSecret.hh\
	TMCG_Stack.hh TMCG_OpenStack.hh TMCG_StackSecret.hh\
	TMCG_SecretKey.hh TMCG_PublicKey.hh TMCG_PublicKeyRing.hh\
	libTMCG.hh

m4datadir = $(datadir)/aclocal
m4data_DATA = libTMCG.m4

lib_LTLIBRARIES = libTMCG.la

libTMCG_la_SOURCES = mpz_srandom.c mpz_srandom.h\
	mpz_sqrtm.c mpz_sqrtm.h\
	mpz_spowm.c mpz_spowm.h\
	mpz_sprime.c mpz_sprime.h\
	mpz_shash.cc mpz_shash.hh\
	parse_helper.cc parse_helper.hh\
	mpz_helper.cc mpz_helper.hh\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	BarnettSmartVTMF_dlog_GroupQR.cc BarnettSmartVTMF_dlog_GroupQR.hh\
	GrothVSSHE.cc GrothVSSHE.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh\
	VTMF_Card.cc VTMF_Card.hh\
	VTMF_CardSecret.cc VTMF_CardSecret.hh\
	TMCG_Card.cc TMCG_Card.hh\
	TMCG_CardSecret.cc TMCG_CardSecret.hh\
	TMCG_Stack.hh\
	TMCG_OpenStack.hh\
	TMCG_StackSecret.hh\
	TMCG_SecretKey.cc TMCG_SecretKey.hh\
	TMCG_PublicKey.cc TMCG_PublicKey.hh\
	TMCG_PublicKeyRing.hh\
	libTMCG.cc libTMCG.hh

libTMCG_la_CFLAGS = @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@

libTMCG_la_CXXFLAGS = @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@

libTMCG_la_LDFLAGS = -version-info\
	@LIBTMCG_LT_CURRENT@:@LIBTMCG_LT_REVISION@:@LIBTMCG_LT_AGE@

libTMCG_la_LIBADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
