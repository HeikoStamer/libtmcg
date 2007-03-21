/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_mpz_sprime_H
	#define INCLUDED_mpz_sprime_H
	
	#include <stdio.h>
	#include <assert.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
			void mpz_sprime
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
				 unsigned long int mr_iterations);
			void mpz_sprime_naive
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
				 unsigned long int mr_iterations);
			void mpz_sprime2g
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
				 unsigned long int mr_iterations);
			void mpz_sprime3mod4
				(mpz_ptr p, unsigned long int psize, 
				 unsigned long int mr_iterations);
			void mpz_lprime
				(mpz_ptr p, mpz_ptr q, mpz_ptr k, 
				 unsigned long int psize, unsigned long int qsize, 
				 unsigned long int mr_iterations);
			void mpz_oprime
				(mpz_ptr p, unsigned long int psize, 
				 unsigned long int mr_iterations);
	#if defined(__cplusplus)
		}
	#endif
#endif
