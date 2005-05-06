# Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>
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

## Process this file with automake to produce Makefile.in

TESTS = t-mpz t-key t-vtmf

INCLUDES = -I$(top_srcdir)/src
LDADD = @LIBGCRYPT_LIBS@ ../src/libTMCG.la

EXTRA_PROGRAMS = SchwarzerPeterAlice SchwarzerPeterBob
noinst_PROGRAMS = $(TESTS)

SchwarzerPeterAlice_SOURCES = SchwarzerPeterAlice.cc

SchwarzerPeterBob_SOURCES = SchwarzerPeterBob.cc

t_mpz_SOURCES = t-mpz.cc
t_key_SOURCES = t-key.cc
t_vtmf_SOURCES = t-vtmf.cc
