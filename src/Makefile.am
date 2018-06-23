# Copyright (C) 2005, 2009, 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>
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

EXTRA_DIST = libTMCG-config.in libTMCG.m4 sha3.c

bin_SCRIPTS = libTMCG-config

include_HEADERS = mpz_srandom.hh mpz_sqrtm.hh mpz_spowm.hh mpz_sprime.hh\
	mpz_shash.hh parse_helper.hh mpz_helper.hh\
	BarnettSmartVTMF_dlog.hh BarnettSmartVTMF_dlog_GroupQR.hh\
	PedersenCOM.hh\
	GrothVSSHE.hh\
	HooghSchoenmakersSkoricVillegasVRHE.hh\
	NaorPinkasEOTP.hh\
	aiounicast.hh aiounicast_nonblock.hh aiounicast_select.hh\
	CachinKursawePetzoldShoupSEABP.hh\
	GennaroJareckiKrawczykRabinDKG.hh\
	PedersenVSS.hh\
	CanettiGennaroJareckiKrawczykRabinASTC.hh\
	JareckiLysyanskayaASTC.hh\
	CallasDonnerhackeFinneyShawThayerRFC4880.hh\
	GolleDCPG_elgamal.hh\
	SchindelhauerTMCG.hh\
	VTMF_Card.hh VTMF_CardSecret.hh\
	TMCG_Card.hh TMCG_CardSecret.hh\
	TMCG_Stack.hh TMCG_OpenStack.hh TMCG_StackSecret.hh\
	TMCG_SecretKey.hh TMCG_PublicKey.hh TMCG_PublicKeyRing.hh\
	libTMCG.hh

m4datadir = $(datadir)/aclocal
m4data_DATA = libTMCG.m4

lib_LTLIBRARIES = libTMCG.la

libTMCG_la_SOURCES = mpz_srandom.cc mpz_srandom.hh\
	mpz_sqrtm.cc mpz_sqrtm.hh\
	mpz_spowm.cc mpz_spowm.hh\
	mpz_sprime.cc mpz_sprime.hh\
	mpz_shash.cc mpz_shash.hh\
	parse_helper.cc parse_helper.hh\
	mpz_helper.cc mpz_helper.hh\
	BarnettSmartVTMF_dlog.cc BarnettSmartVTMF_dlog.hh\
	BarnettSmartVTMF_dlog_GroupQR.cc BarnettSmartVTMF_dlog_GroupQR.hh\
	PedersenCOM.cc PedersenCOM.hh\
	GrothVSSHE.cc GrothVSSHE.hh\
	HooghSchoenmakersSkoricVillegasVRHE.cc\
	HooghSchoenmakersSkoricVillegasVRHE.hh\
	NaorPinkasEOTP.cc NaorPinkasEOTP.hh\
	aiounicast.hh\
	aiounicast_nonblock.cc aiounicast_nonblock.hh\
	aiounicast_select.cc aiounicast_select.hh\
	CachinKursawePetzoldShoupSEABP.cc CachinKursawePetzoldShoupSEABP.hh\
	GennaroJareckiKrawczykRabinDKG.cc GennaroJareckiKrawczykRabinDKG.hh\
	PedersenVSS.cc PedersenVSS.hh\
	CanettiGennaroJareckiKrawczykRabinASTC.cc\
	CanettiGennaroJareckiKrawczykRabinASTC.hh\
	JareckiLysyanskayaASTC.cc JareckiLysyanskayaASTC.hh\
	CallasDonnerhackeFinneyShawThayerRFC4880.cc\
	CallasDonnerhackeFinneyShawThayerRFC4880.hh\
	SchindelhauerTMCG.cc SchindelhauerTMCG.hh\
	GolleDCPG_elgamal.cc GolleDCPG_elgamal.hh\
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

libTMCG_la_CFLAGS = @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@\
 @BOTAN_CFLAGS@

libTMCG_la_CXXFLAGS = @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@\
 @BOTAN_CFLAGS@

libTMCG_la_LDFLAGS = -version-info\
	@LIBTMCG_LT_CURRENT@:@LIBTMCG_LT_REVISION@:@LIBTMCG_LT_AGE@

libTMCG_la_LIBADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@ @BOTAN_LIBS@

