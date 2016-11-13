# Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>
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

## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/src @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
LDADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@ ../src/libTMCG.la

bin_PROGRAMS = dkg-generate dkg-encrypt dkg-decrypt

dkg_generate_SOURCES = pipestream.hh dkg-generate.cc
dkg_encrypt_SOURCES = pipestream.hh dkg-encrypt.cc
dkg_decrypt_SOURCES = pipestream.hh dkg-decrypt.cc


