/*******************************************************************************
  JareckiLysyanskayaASTC.hh,
                             |A|daptively |S|ecure |T|hreshold |C|ryptography

     Stanislaw Jarecki and Anna Lysyanskaya:
       'Adaptively Secure Threshold Cryptography: Introducing Concurrency,
        Removing Erasures', TODO.

   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_JareckiLysyanskayaASTC_HH
	#define INCLUDED_JareckiLysyanskayaASTC_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <algorithm>

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

/* This protocol is based upon [GJKR07] and is called Joint-RVSS [JL01]. */
class JareckiLysyanskayaRVSS
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		const unsigned long int				F_size, G_size;
	
	public:
		mpz_t						p, q, g, h;
		size_t						n, t;
		std::vector<size_t>				Qual;
		mpz_t						alpha_i, hatalpha_i;
		std::vector< std::vector<mpz_ptr> >		alpha_ij, hatalpha_ij;
		
		JareckiLysyanskayaRVSS
			(size_t n_in, size_t t_in,
			mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		bool Generate
			(size_t i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			std::ostream &err, bool simulate_faulty_behaviour = false);
		bool Reconstruct
			(size_t i, std::vector<size_t> &complaints,
			std::vector<mpz_ptr> &a_i_in,
			CachinKursawePetzoldShoupRBC *rbc, std::ostream &err);
		~JareckiLysyanskayaRVSS
			();
};

#endif
