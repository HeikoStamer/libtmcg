/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2002, 2004, 2005, 2007,
               2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

   LibTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   LibTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LibTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_mpz_srandom_HH
	#define INCLUDED_mpz_srandom_HH
	
	// C and STL headers
	#include <cstdlib>	
	
	// GNU multiple precision library
	#include <gmp.h>

	unsigned long int tmcg_mpz_ssrandom_ui
		();
	unsigned long int tmcg_mpz_srandom_ui
		();
	unsigned long int tmcg_mpz_wrandom_ui
		();
	unsigned long int tmcg_mpz_ssrandom_mod
		(const unsigned long int modulo);
	unsigned long int tmcg_mpz_srandom_mod
		(const unsigned long int modulo);
	unsigned long int tmcg_mpz_wrandom_mod
		(const unsigned long int modulo);
		
	void tmcg_mpz_ssrandomb
		(mpz_ptr r, const unsigned long int size);
	void tmcg_mpz_srandomb
		(mpz_ptr r, const unsigned long int size);
	void tmcg_mpz_wrandomb
		(mpz_ptr r, const unsigned long int size);
	void tmcg_mpz_ssrandomm
		(mpz_ptr r, mpz_srcptr m);
	void tmcg_mpz_srandomm
		(mpz_ptr r, mpz_srcptr m);
	void tmcg_mpz_wrandomm
		(mpz_ptr r, mpz_srcptr m);

	void tmcg_mpz_ssrandomm_cache_init
		(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
		 mpz_ptr ssrandomm_cache_mod,
		 size_t &ssrandomm_cache_avail,
		 const size_t n,
		 mpz_srcptr m);
	void tmcg_mpz_ssrandomm_cache
		(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
		 mpz_srcptr ssrandomm_cache_mod,
		 size_t &ssrandomm_cache_avail,
		 mpz_ptr r,
		 mpz_srcptr m);
	void tmcg_mpz_ssrandomm_cache_done
		(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
		 mpz_ptr ssrandomm_cache_mod,
		 size_t &ssrandomm_cache_avail);
#endif

