# Copyright (C) 2005, 2007  Heiko Stamer <stamer@gaos.org>
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

TESTS = t-mpz t-vtmf t-vsshe t-mpc t-key t-poker

INCLUDES = -I$(top_srcdir)/src @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@
LDADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ ../src/libTMCG.la

EXTRA_PROGRAMS = SchwarzerPeterAlice SchwarzerPeterBob
noinst_PROGRAMS = $(TESTS)

SchwarzerPeterAlice_SOURCES = SchwarzerPeterAlice.cc

SchwarzerPeterBob_SOURCES = SchwarzerPeterBob.cc

t_mpz_SOURCES = test_helper.c test_helper.h t-mpz.cc
t_vtmf_SOURCES = pipestream.hh test_helper.c test_helper.h t-vtmf.cc
t_vsshe_SOURCES = pipestream.hh test_helper.c test_helper.h t-vsshe.cc
t_mpc_SOURCES = StiglicMPC.cc StiglicMPC.hh t-mpc.cc
t_key_SOURCES = t-key.cc
t_poker_SOURCES = pipestream.hh test_helper.c test_helper.h t-poker.cc
