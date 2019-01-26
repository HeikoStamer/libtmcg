/*******************************************************************************
   This file is part of LibTMCG.

     [CS00]  Ronald Cramer, Victor Shoup: 'Signature schemes based on the
              strong RSA assumption', ACM Transactions on Information and
             System Security, Vol.3(3), pp. 161--185, 2000

     [RS00]  Jean-Francois Raymond, Anton Stiglic: 'Security Issues in the
              Diffie-Hellman Key Agreement Protocol', ZKS technical report
             http://citeseer.ist.psu.edu/455251.html

      [HAC]  Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone:
              'Handbook of Applied Cryptography', CRC Press, 1996.

 Copyright (C) 2004, 2005, 2006, 2007, 
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_mpz_sprime_HH
	#define INCLUDED_mpz_sprime_HH
	
	// GNU multiple precision library
	#include <gmp.h>
	
	void tmcg_mpz_sprime
		(mpz_ptr p, mpz_ptr q,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_smprime
		(mpz_ptr p, mpz_ptr q,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_sprime_naive
		(mpz_ptr p, mpz_ptr q,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_sprime_noninc
		(mpz_ptr p, mpz_ptr q,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_sprime2g
		(mpz_ptr p, mpz_ptr q,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_sprime3mod4
		(mpz_ptr p,
		 const unsigned long int psize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_lprime
		(mpz_ptr p, mpz_ptr q, mpz_ptr k, 
		 const unsigned long int psize,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_lprime_prefix
		(mpz_ptr p, mpz_ptr q, mpz_ptr k, 
		 const unsigned long int psize,
		 const unsigned long int qsize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_oprime
		(mpz_ptr p,
		 const unsigned long int psize, 
		 const unsigned long int mr_iterations);
	void tmcg_mpz_oprime_noninc
		(mpz_ptr p,
		 const unsigned long int psize, 
		 const unsigned long int mr_iterations);
#endif

