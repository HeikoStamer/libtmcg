/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_mpz_spowm_H
	#define INCLUDED_mpz_spowm_H
	
	#include <stdio.h>
	#include <assert.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
			/* Kocher's efficient blinding technique for modular exponentiation [Ko96] 
                           -- cf. the scientific discussion e.g. https://eprint.iacr.org/2013/447 
			   https://eprint.iacr.org/2014/869 and https://eprint.iacr.org/2016/597 */
			void mpz_spowm_init
				(mpz_srcptr x, mpz_srcptr p);
			
			void mpz_spowm_calc
				(mpz_ptr res, mpz_srcptr m);
			
			void mpz_spowm_clear
				();
			
			/* Chaum's blinding technique for modular exponentiation
			   -- cf. the scientific discussion e.g. https://eprint.iacr.org/2013/447 
			   https://eprint.iacr.org/2014/869 and https://eprint.iacr.org/2016/597 */
			void mpz_spowm
				(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p);
			
			/* Fast modular exponentiation using precomputed tables */
			void mpz_fpowm_init
				(mpz_t fpowm_table[]);
			
			void mpz_fpowm_precompute
				(mpz_t fpowm_table[],
				mpz_srcptr m, mpz_srcptr p, size_t t);
			
			void mpz_fpowm
				(mpz_t fpowm_table[],
				mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p);
			
			void mpz_fpowm_ui
				(mpz_t fpowm_table[],
				mpz_ptr res, mpz_srcptr m, unsigned long int x_ui, mpz_srcptr p);
			
			void mpz_fspowm
				(mpz_t fpowm_table[],
				mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p);
			
			void mpz_fpowm_done
				(mpz_t fpowm_table[]);
			
	#if defined(__cplusplus)
		}
	#endif
#endif
