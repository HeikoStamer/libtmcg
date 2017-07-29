# Copyright (C) 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>
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


AM_CPPFLAGS = -I$(top_srcdir)/src @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@ @GNUNET_CFLAGS@
LDADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@ @GNUNET_LIBS@ ../src/libTMCG.la

bin_PROGRAMS = dkg-gencrs dkg-generate dkg-encrypt dkg-decrypt dkg-sign dkg-revoke

dist_man_MANS = dkg-generate.1 dkg-encrypt.1 dkg-decrypt.1 dkg-sign.1

dkg_gencrs_SOURCES = dkg-gencrs.cc
dkg_generate_SOURCES = dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-generate.cc
dkg_encrypt_SOURCES = dkg-encrypt.cc
dkg_decrypt_SOURCES = dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-decrypt.cc
dkg_sign_SOURCES = dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-sign.cc
dkg_revoke_SOURCES = dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-revoke.cc


