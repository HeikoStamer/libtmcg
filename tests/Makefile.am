# Copyright (C) 2005, 2007, 2009, 2015--2018  Heiko Stamer <HeikoStamer@gmx.net>
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

TESTS = t-mpz t-rfc4880 t-aio t-vtmf t-vsshe t-vrhe t-eotp t-mpc t-key t-poker\
 t-poker-cutnchoose t-poker-rot t-votc t-poker-noninteractive\
 t-poker-rot-noninteractive t-poker-aiou t-seabp t-astc t-vss t-astc2 t-dkg

AM_CPPFLAGS = -I$(top_srcdir)/src @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@\
 @LIBGMP_CFLAGS@ @BOTAN_CFLAGS@
LDADD = @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@ @BOTAN_LIBS@\
 ../src/libTMCG.la

EXTRA_PROGRAMS = SchwarzerPeterAlice SchwarzerPeterBob
noinst_PROGRAMS = $(TESTS)

SchwarzerPeterAlice_SOURCES = SchwarzerPeterAlice.cc
SchwarzerPeterBob_SOURCES = SchwarzerPeterBob.cc

t_mpz_SOURCES = test_helper.c test_helper.h t-mpz.cc
t_rfc4880_SOURCES = test_helper.c test_helper.h t-rfc4880.cc
t_aio_SOURCES = test_helper.c test_helper.h t-aio.cc
t_vtmf_SOURCES = pipestream.hh test_helper.c test_helper.h t-vtmf.cc
t_vsshe_SOURCES = pipestream.hh test_helper.c test_helper.h t-vsshe.cc
t_vrhe_SOURCES = pipestream.hh test_helper.c test_helper.h t-vrhe.cc
t_eotp_SOURCES = pipestream.hh test_helper.c test_helper.h t-eotp.cc
t_dkg_SOURCES = pipestream.hh test_helper.c test_helper.h t-dkg.cc
t_astc_SOURCES = pipestream.hh test_helper.c test_helper.h t-astc.cc
t_vss_SOURCES = pipestream.hh test_helper.c test_helper.h t-vss.cc
t_astc2_SOURCES = pipestream.hh test_helper.c test_helper.h t-astc2.cc
t_seabp_SOURCES = pipestream.hh test_helper.c test_helper.h t-seabp.cc
t_mpc_SOURCES = StiglicMPC.cc StiglicMPC.hh test_helper.c test_helper.h t-mpc.cc
t_key_SOURCES = t-key.cc
t_poker_SOURCES = pipestream.hh test_helper.c test_helper.h t-poker.cc
t_poker_cutnchoose_SOURCES = pipestream.hh test_helper.c test_helper.h\
 t-poker-cutnchoose.cc
t_poker_rot_SOURCES = pipestream.hh test_helper.c test_helper.h t-poker-rot.cc
t_votc_SOURCES = pipestream.hh test_helper.c test_helper.h t-votc.cc
t_poker_noninteractive_SOURCES = pipestream.hh test_helper.c test_helper.h\
 t-poker-noninteractive.cc
t_poker_rot_noninteractive_SOURCES = pipestream.hh test_helper.c test_helper.h\
 t-poker-rot-noninteractive.cc
t_poker_aiou_SOURCES = pipestream.hh test_helper.c test_helper.h t-poker-aiou.cc

