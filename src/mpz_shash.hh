/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2005 Heiko Stamer, <stamer@gaos.org>

     [BR95] Mihir Bellare, Phillip Rogaway. Random Oracles are Practical:
            A Paradigm for Designing Efficient Protocols.
            Proceedings First Annual Conference on Computer and
            Communications Security, ACM, 1993.

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
#endif
