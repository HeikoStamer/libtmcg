/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2005 Heiko Stamer, <stamer@gaos.org>

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

#ifndef INCLUDED_mpz_spowm_H
	#define INCLUDED_mpz_spowm_H
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
			/* Kocher's efficient blinding technique for modexp */
			void mpz_spowm_init
				(mpz_srcptr x, mpz_srcptr p);
			
			void mpz_spowm_calc
				(mpz_ptr res, mpz_srcptr m);
			
			void mpz_spowm_clear
				();
			
			/* Chaum's blinding technique for modular exponentiation */
			void mpz_spowm
				(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p);
			
	#if defined(__cplusplus)
		}
	#endif
#endif
