/*******************************************************************************
   GolleDCPG_elgamal.cc, |D|ealing |C|ards in |P|oker |G|ames, ElGamal variant

     [Go05] Philippe Golle: 'Dealing Cards in Poker Games',
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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "GolleDCPG_elgamal.hh"

// additional headers
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

GolleDCPG_elgamal::GolleDCPG_elgamal
	(BarnettSmartVTMF_dlog *vtmf_in, size_t maxcardtype_in)
{
	// [Go05] Group establishment
	// [Go05] The players use Pedersen’s protocol to generate a distributed
	// ElGamal public/private key pair. (==> KeyGenerationProtocol of VTMF)

	// Initialize members of the class
	vtmf = vtmf_in;

	// [Go05] Every pair or players ($P_i$, $P_j$) establishes a secret key
	// $k_{i,j}$ for a symmetric cipher such as DES or AES. These keys allow
	// any two players to communicate privately. (==> aiounicast)

	// [Go05] The players precompute and store in memory the values
	// $g^0, g^1, \ldots, g^51 \in G$. These values encode the 52 cards.

	// Initialize array of encoded cards
	if (maxcardtype_in)
	{
		DCPG_MaxCardType = maxcardtype_in;
	}
	else
	{
		DCPG_MaxCardType = 1;
		for (size_t i = 0; i < TMCG_MAX_TYPEBITS; i++)
			DCPG_MaxCardType *= 2; // DCPG_MaxCardType = 2^{TMCG_MAX_TYPEBITS}
	}
	encoded_cards = new mpz_t[DCPG_MaxCardType]();
	for (size_t i = 0; i < DCPG_MaxCardType; i++)
		mpz_init(encoded_cards[i]);

	// Precompute $g^i \bmod p$ for all $0 \le i \le 2^{TMCG_MAX_TYPEBITS}$
	for (size_t i = 0; i < DCPG_MaxCardType; i++)
		vtmf->IndexElement(encoded_cards[i], i);

	// [Go05] Recall that we let $k$ denote the number of players. The
	// players precompute and store in memory the following $k-1$ ElGamal
	// ciphertexts: $D^i = E(g^{52i}) for $i = 0, \ldots, k-1$.
	// Let $S = \{D_0, \ldots, D_{k-1}\}$.
	k = vtmf->KeyGenerationProtocol_NumberOfKeys() + 1;
	D = new	mpz_t[k]();
	for (size_t i = 0; i < k; i++)
	{
		mpz_init(D[i]);
		vtmf->IndexElement(D[i], DCPG_MaxCardType * i);
	}
}

GolleDCPG_elgamal::~GolleDCPG_elgamal
	()
{
	for (size_t i = 0; i < DCPG_MaxCardType; i++)
		mpz_clear(encoded_cards[i]);
	delete [] encoded_cards;
	for (size_t i = 0; i < k; i++)
		mpz_clear(D[i]);
	delete [] D;
}
