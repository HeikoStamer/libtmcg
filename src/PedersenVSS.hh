/*******************************************************************************
  PedersenVSS.hh,
                                               |V|erifiable |S|ecret |S|haring

     [Pe92] Torben P. Pedersen: 'Non-Interactive and Information-Theoretic 
       Secure Verifiable Secret Sharing',
     Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 129--140, Springer 1992.

     [GJKR01] Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin:
       'Robust Threshold DSS Signatures',
     Information and Computation 164, pp. 54--84, 2001. 

   This file is part of LibTMCG.

 Copyright (C) 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_PedersenVSS_HH
	#define INCLUDED_PedersenVSS_HH
	
// C and STL header
#include <cstdlib>
#include <string>
#include <iostream>
#include <vector>
#include <map>

// GNU multiple precision library
#include <gmp.h>

#include "aiounicast.hh"
#include "CachinKursawePetzoldShoupSEABP.hh"

/* This protocol by [Pe92] is called Uncond-Secure-VSS in [GJKR01]. */
class PedersenVSS
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		const unsigned long int		F_size, G_size;
		const bool					use_very_strong_randomness;
		const std::string			label;
	
	public:
		mpz_t						p, q, g, h;
		size_t						n, t, i;
		mpz_t						sigma_i, tau_i;
		std::vector<mpz_ptr> 		a_j, b_j, A_j;
		
		PedersenVSS
			(const size_t n_in,
			 const size_t t_in,
			 const size_t i_in,
			 mpz_srcptr p_CRS,
			 mpz_srcptr q_CRS,
			 mpz_srcptr g_CRS,
			 mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		PedersenVSS
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		void PublishState
			(std::ostream &out) const;
		std::string Label
			() const;
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Share
			(mpz_srcptr sigma,
			 aiounicast *aiou,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false);
		bool Share
			(mpz_srcptr sigma,
			 std::map<size_t, size_t> &idx2dkg,
			 aiounicast *aiou,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false);
		bool Share
			(size_t dealer,
			 aiounicast *aiou,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false);
		bool Share
			(size_t dealer,
			 std::map<size_t, size_t> &idx2dkg,
			 aiounicast *aiou,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false);
		bool Reconstruct
			(const size_t dealer,
			 mpz_ptr sigma,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err);
		bool Reconstruct
			(const size_t dealer,
			 mpz_ptr sigma,
			 std::map<size_t, size_t> &idx2dkg,
			 CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err);
		~PedersenVSS
			();
};

#endif
