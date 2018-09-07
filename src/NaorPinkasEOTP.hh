/*******************************************************************************
  NaorPinkasEOTP.hh,
                                 |E|fficient |O|blivious |T|ransfer |P|rotocols

     Moni Naor and Benny Pinkas: 'Efficient Oblivious Transfer Protocols',
     Symposium on Discrete Algorithms (SODA) 2001, pp. 448--457, ACM/SIAM 2001.

   This file is part of LibTMCG.

 Copyright (C) 2016, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_NaorPinkasEOTP_HH
	#define INCLUDED_NaorPinkasEOTP_HH
	
// C and STL header
#include <cstdlib>
#include <iostream>
#include <vector>

// GNU multiple precision library
#include <gmp.h>

class NaorPinkasEOTP
{
	private:
		mpz_t							*fpowm_table_g;
		const unsigned long int			F_size, G_size;
	
	public:
		mpz_t							p, q, g;
		
		NaorPinkasEOTP
			(unsigned long int fieldsize = TMCG_DDH_SIZE,
			 unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		NaorPinkasEOTP
			(mpz_srcptr p_ENC,
			 mpz_srcptr q_ENC,
			 mpz_srcptr g_ENC,
			 unsigned long int fieldsize = TMCG_DDH_SIZE,
			 unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		NaorPinkasEOTP
			(std::istream &in,
			 unsigned long int fieldsize = TMCG_DDH_SIZE,
			 unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream &out) const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Send_interactive_OneOutOfTwo
			(mpz_srcptr M0,
			 mpz_srcptr M1,
			 std::istream &in,
			 std::ostream &out) const;
		bool Choose_interactive_OneOutOfTwo
			(const size_t sigma,
			 mpz_ptr M,
			 std::istream &in,
			 std::ostream &out) const;
		bool Send_interactive_OneOutOfN
			(const std::vector<mpz_ptr> &M,
			 std::istream &in,
			 std::ostream &out) const;
		bool Choose_interactive_OneOutOfN
			(const size_t sigma,
			 const size_t N,
			 mpz_ptr M,
			 std::istream &in,
			 std::ostream &out) const;
		bool Send_interactive_OneOutOfN_optimized
			(const std::vector<mpz_ptr> &M,
			 std::istream &in,
			 std::ostream &out) const;
		bool Choose_interactive_OneOutOfN_optimized
			(size_t sigma,
			 size_t N,
			 mpz_ptr M,
			 std::istream &in,
			 std::ostream &out) const;
		~NaorPinkasEOTP
			();
};

#endif
