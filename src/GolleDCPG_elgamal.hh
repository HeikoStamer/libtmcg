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
#include <cstdlib>

// GNU multiple precision library
#include <gmp.h>

// dlog-based VTMF [BS03] compatible with Golle's ElGamal variant
#include "BarnettSmartVTMF_dlog.hh"

class GolleDCPG_elgamal
{
	private:
		BarnettSmartVTMF_dlog			*vtmf;
		size_t							DCPG_MaxCardType;
		mpz_t							*encoded_cards;
		size_t							k;
		mpz_t							*D;
	
	public:
		
		GolleDCPG_elgamal
			(BarnettSmartVTMF_dlog *vtmf_in,
			 size_t maxcardtype_in = 0);
		~GolleDCPG_elgamal
			();
};

#endif
