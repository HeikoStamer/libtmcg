/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_mpz_shash_HH
	#define INCLUDED_mpz_shash_HH
	
	// C and STL header
	#include <stdint.h>
	#include <cstdio>
	#include <string>
	#include <vector>
	
	// variable argument lists
	#include <cstdarg>

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	// hash functions h and g
	void tmcg_h
		(unsigned char *output,
		const unsigned char *input, const size_t size,
		int algo = TMCG_GCRY_MD_ALGO);
	void tmcg_g
		(unsigned char *output, const size_t osize,
		const unsigned char *input, const size_t isize);

	// high-level functions mpz_fhash and mpz_shash
	size_t tmcg_mpz_shash_len
		();
	size_t tmcg_mpz_fhash_len
		(int algo);
	void tmcg_mpz_fhash
		(mpz_ptr r, int algo, mpz_srcptr input);
	void tmcg_mpz_fhash_ggen
		(mpz_ptr r, int algo,
		mpz_srcptr input1, const std::string &input2,
		mpz_srcptr input3, mpz_srcptr input4);
	void tmcg_mpz_shash
		(mpz_ptr r, const std::string &input);
	void tmcg_mpz_shash
		(mpz_ptr r, size_t n, ...);
	void tmcg_mpz_shash_1vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v, size_t n, ...);
	void tmcg_mpz_shash_2vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v,
		const std::vector<mpz_ptr>& w, size_t n, ...);
	void tmcg_mpz_shash_4vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v,
		const std::vector<mpz_ptr>& w, const std::vector<mpz_ptr>& x,
		const std::vector<mpz_ptr>& y, size_t n, ...);
	void tmcg_mpz_shash_2pairvec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp, size_t n, ...);
	void tmcg_mpz_shash_2pairvec2vec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
		const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
		size_t n, ...);
	void tmcg_mpz_shash_4pairvec2vec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& xp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& yp,
		const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
		size_t n, ...);
#endif

