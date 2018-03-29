/*******************************************************************************
   GolleDCPG_elgamal.hh, |D|ealing |C|ards in |P|oker |G|ames, ElGamal variant

     [Go03] Philippe Golle: 'Dealing Cards in Poker Games',
     Proceedings of the International Conference on Information Technology:
     Coding and Computing (ITCC ’05), volume 1, pp. 506--511. IEEE, 2005.

     [JJ99] Markus Jakobsson and Ari Juels: 'Millimix: Mixing in Small Batches',
     DIMACS Technical Report 99-33, 1999.

     [JS99] Markus Jakobsson and Claus Peter Schnorr: 'Efficient Oblivious
       Proofs of Correct Exponentiation',
     Proceedings of Communications and Multimedia Security, pp. 71--86, 1999.

   This file is part of LibTMCG.

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_GolleDCPG_elgamal_HH
	#define INCLUDED_GolleDCPG_elgamal_HH
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <map>

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_spowm.h"
	#include "mpz_sprime.h"
	#include "mpz_helper.hh"
	#include "mpz_shash.hh"

class GolleDCPG_elgamal
{
	private:
		mpz_t							x_i, d, h_i_fp;
		std::map<std::string, mpz_ptr>	h_j;
	
	protected:
		const unsigned long int			F_size, G_size;
		const bool						canonical_g;
		mpz_t							*fpowm_table_g, *fpowm_table_h;
	
	public:
		mpz_t							p, q, g, k, h, h_i;
		
		GolleDCPG_elgamal
			(const unsigned long int fieldsize = TMCG_DDH_SIZE,
			const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			const bool canonical_g_usage = false,
			const bool initialize_group = true);
		GolleDCPG_elgamal
			(std::istream& in,
			const unsigned long int fieldsize = TMCG_DDH_SIZE,
			const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			const bool canonical_g_usage = false,
			const bool precompute = true);
		~GolleDCPG_elgamal
			();
};

#endif
