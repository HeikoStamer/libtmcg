/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004 Heiko Stamer, <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#ifndef INCLUDED_mpz_shash_HH
	#define INCLUDED_mpz_shash_HH
	
	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstdio>
	#include <string>
	#include <vector>
	
	// GNU crypto library
	#include <gcrypt.h> 
	
	// GNU multiple precision library
	#include <gmp.h>
	
	/* Fiat-Shamir heuristic */
	void mpz_shash
		(mpz_ptr r, mpz_srcptr a1, mpz_srcptr a2, mpz_srcptr a3);
	
	void mpz_shash
		(mpz_ptr r, mpz_srcptr a1, mpz_srcptr a2, mpz_srcptr a3,
		mpz_srcptr a4, mpz_srcptr a5, mpz_srcptr a6);
	
	/* hash functions h() and g() [Random Oracles are practical] */
	void h
		(char *output, const char *input, size_t size);
	
	void g
		(char *output, size_t osize, const char *input, size_t isize);
#endif
