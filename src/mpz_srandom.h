/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2002, 2004  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_mpz_srandom_H
	#define INCLUDED_mpz_srandom_H
	
	// GNU crypto library
	#include <gcrypt.h> 
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
			unsigned long int mpz_ssrandom_ui
				();
			unsigned long int mpz_srandom_ui
				();
			void mpz_ssrandomb
				(mpz_ptr r, unsigned long int size);
			void mpz_srandomb
				(mpz_ptr r, unsigned long int size);
			void mpz_ssrandomm
				(mpz_ptr r, mpz_srcptr m);
			void mpz_srandomm
				(mpz_ptr r, mpz_srcptr m);
	#if defined(__cplusplus)
		}
	#endif
#endif
