/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016  Heiko Stamer <HeikoStamer@gmx.net>

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
	
	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstdio>
	#include <string>
	#include <vector>
	
	// variable argument lists
	#include <cstdarg>
	
	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	/* hash functions h, g, and mpz_shash */
	void h
		(char *output, const char *input, size_t size);
	
	void g
		(char *output, size_t osize, const char *input, size_t isize);
		
	void mpz_shash
		(mpz_ptr r, std::string input);
		
	void mpz_shash
		(mpz_ptr r, size_t n, ...);

	void mpz_shash_1vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v, size_t n, ...);
	void mpz_shash_2vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v,
		const std::vector<mpz_ptr>& w, size_t n, ...);
	void mpz_shash_4vec
		(mpz_ptr r, const std::vector<mpz_ptr>& v,
		const std::vector<mpz_ptr>& w, const std::vector<mpz_ptr>& x,
		const std::vector<mpz_ptr>& y, size_t n, ...);
	void mpz_shash_2pairvec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp, size_t n, ...);
	void mpz_shash_2pairvec2vec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
		const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
		size_t n, ...);
	void mpz_shash_4pairvec2vec
		(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& xp,
		const std::vector<std::pair<mpz_ptr, mpz_ptr> >& yp,
		const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
		size_t n, ...);
#endif
