/*******************************************************************************
  GennaroJareckiKrawczykRabinDKG.hh,
                                       Secure |D|istributed |K|ey |G|eneration

     Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin:
       'Secure Distributed Key Generation for Discrete-Log Based Cryptosystems',
     Journal of Cryptology, Vol. 20 Nr. 1, pp. 51--83, Springer 2007.

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

#ifndef INCLUDED_GennaroJareckiKrawczykRabinDKG_HH
	#define INCLUDED_GennaroJareckiKrawczykRabinDKG_HH

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
	#include "aiobroadcast.hh"

class GennaroJareckiKrawczykRabinDKG
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		const unsigned long int				F_size, G_size;
	
	public:
		mpz_t						p, q, g, h;
		size_t						n, t;
		std::vector<size_t>				QUAL;
		mpz_t						x_i, xprime_i, y_i, y;
		
		GennaroJareckiKrawczykRabinDKG
			(size_t n_in, size_t t_in,
			mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		bool Generate
			(size_t i, aiounicast *aiou, aiobroadcast *aiob, std::ostream &err,
			bool simulate_faulty_behaviour = false);
		~GennaroJareckiKrawczykRabinDKG
			();
};

#endif
