/*******************************************************************************
  CramerDamgardZNPFFA.hh,
                 |Z|ero-|K|nowledge |P|roofs for |F|inite |F|ield |A|rithmetic


     [CD98] Ronald Cramer and Ivan Damgard: 'Zero Knowledge Proofs for Finite
       Field Arithmetic, or: Can Zero-Knowledge Be for Free?',
     Advances in Cryptology - CRYPTO '98, LNCS 1462, pp. 424--441, 1998. 

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

#ifndef INCLUDED_CramerDamgardZNPFFA_HH
	#define INCLUDED_CramerDamgardZNPFFA_HH
	
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

/* The protocols are implemented according to the description in the technical report BRICS RS-97-27.
   However, we consider only the "DISCRETE LOG GENERATOR" as underlying group homomorphism $f$. */
class CramerDamgardZNPFFA
{
	private:
		mpz_t					*fpowm_table_g, *fpowm_table_h;
		const unsigned long int			F_size, G_size;
		const std::string			label;
	
	public:
		mpz_t					p, q, g, h;
		size_t					n, t, i;
		
		CramerDamgardZNPFFA
			(const size_t n_in, const size_t t_in, const size_t i_in,
			mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			const unsigned long int fieldsize = TMCG_DDH_SIZE,
			const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			const std::string label_in = "");
		CramerDamgardZNPFFA
			(std::istream &in,
			const unsigned long int fieldsize = TMCG_DDH_SIZE,
			const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			const std::string label_in = "");
		std::string Label
			() const;
// TODO
		~CramerDamgardZNPFFA
			();
};

#endif
