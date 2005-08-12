/*******************************************************************************
   This file is part of libTMCG.

     [CS00]  Ronald Cramer, Victor Shoup: 'Signature schemes based on the
              strong RSA assumption', ACM Transactions on Information and
             System Security, Vol.3(3), pp. 161--185, 2000

     [RS00]  Jean-Francois Raymond, Anton Stiglic: 'Security Issues in the
              Diffie-Hellman Key Agreement Protocol', ZKS technical report
             http://citeseer.ist.psu.edu/455251.html

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize);
			void mpz_sprime_naive
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize);
			void mpz_sprime2g
				(mpz_ptr p, mpz_ptr q, unsigned long int qsize);
			void mpz_sprime3mod4
				(mpz_ptr p, unsigned long int psize);
			void mpz_lprime
				(mpz_ptr p, mpz_ptr q, mpz_ptr k,
				unsigned long int psize, unsigned long int qsize);
	#if defined(__cplusplus)
		}
	#endif
#endif
