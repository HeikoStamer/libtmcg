/*******************************************************************************
  PedersenCOM.hh, Information Theoretically Binding |COM|mitment Scheme

     [Pe92] Torben P. Pedersen: 'Non-Interactive and Information-Theoretic
       Secure Verifiable Secret Sharing',
     Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 129--140, Springer 1992.

     [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of LibTMCG.

 Copyright (C) 2005, 2009
               2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_PedersenCOM_HH
	#define INCLUDED_PedersenCOM_HH
	
// C and STL header
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>

// GNU multiple precision library
#include <gmp.h>

// erasure-free distributed coinflip protocol
#include "JareckiLysyanskayaASTC.hh"

/* This variation of the Pedersen commitment scheme is due to Groth [Gr05]. */
class PedersenCommitmentScheme
{
	private:
		mpz_t							*fpowm_table_h;
		std::vector<mpz_t*>				fpowm_table_g;
		const unsigned long int			F_size, G_size;
	
	public:
		mpz_t							p, q, k, h;
		std::vector<mpz_ptr>			g;
		
		PedersenCommitmentScheme
			(const size_t n,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenCommitmentScheme
			(const size_t n,
			 mpz_srcptr p_ENC,
			 mpz_srcptr q_ENC,
			 mpz_srcptr k_ENC,
			 mpz_srcptr h_ENC,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenCommitmentScheme
			(const size_t n,
			 std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		void SetupGenerators_publiccoin
			(mpz_srcptr a_in,
			 const bool without_h = true);
		bool SetupGenerators_publiccoin
			(const size_t whoami,
			 aiounicast *aiou,
			 CachinKursawePetzoldShoupRBC *rbc,
			 JareckiLysyanskayaEDCF *edcf,
			 std::ostream &err,
			 const bool without_h = true);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream &out) const;
		void Commit
			(mpz_ptr c,
			 mpz_ptr r, 
			 const std::vector<mpz_ptr> &m) const;
		void CommitBy
			(mpz_ptr c,
			 mpz_srcptr r, 
			 const std::vector<mpz_ptr> &m,
			 const bool TimingAttackProtection = true) const;
		bool TestMembership
			(mpz_srcptr c) const;
		bool Verify
			(mpz_srcptr c,
			 mpz_srcptr r,
			 const std::vector<mpz_ptr> &m) const;
		~PedersenCommitmentScheme
			();
};

#endif
