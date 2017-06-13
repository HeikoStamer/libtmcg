/*******************************************************************************
  PedersenVSS.hh,
                                               |V|erifiable |S|ecret |S|haring

     [Ped] TODO

   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <algorithm>
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

	#include "aiounicast.hh"
	#include "CachinKursawePetzoldShoupSEABP.hh"

class PedersenVSS
{
	private:
		mpz_t					*fpowm_table_g, *fpowm_table_h;
		const unsigned long int			F_size, G_size;
		const bool				use_very_strong_randomness;
		const std::string			label;
	
	public:
		mpz_t					p, q, g, h;
		size_t					n, t, i;
		mpz_t					sigma_i, tau_i;
		std::vector<mpz_ptr>			A_j;
		
		PedersenVSS
			(const size_t n_in, const size_t t_in, const size_t i_in,
			mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
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
		bool Share
			(mpz_srcptr sigma,
			aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			std::ostream &err,
			const bool simulate_faulty_behaviour = false);
		bool Share
			(size_t dealer,
			aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			std::ostream &err,
			const bool simulate_faulty_behaviour = false);
		bool Reconstruct
			(const size_t dealer, mpz_ptr sigma,
			CachinKursawePetzoldShoupRBC *rbc, std::ostream &err);
		~PedersenVSS
			();
};

#endif
