/*******************************************************************************
  JareckiLysyanskayaASTC.hh,
                             |A|daptively |S|ecure |T|hreshold |C|ryptography

     [JL00] Stanislaw Jarecki and Anna Lysyanskaya:
       'Adaptively Secure Threshold Cryptography: Introducing Concurrency,
        Removing Erasures', Advances in Cryptology - EUROCRYPT 2000,
     LNCS 1807, pp. 221--242, Springer 2000.

   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
	
// C and STL header
#include <cstdlib>
#include <iostream>
#include <vector>

// GNU multiple precision library
#include <gmp.h>

#include "aiounicast.hh"
#include "CachinKursawePetzoldShoupSEABP.hh"

/* This is a trapdoor commitment [JL00] based on Pedersen's scheme [Pe92]. */
class PedersenTrapdoorCommitmentScheme
{
	private:
		mpz_t					*fpowm_table_g;
		mpz_t					*fpowm_table_h;
		const unsigned long int			F_size, G_size;

	public:
		mpz_t					p, q, k, g, h;
		mpz_t					sigma;
		
		PedersenTrapdoorCommitmentScheme
			(const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenTrapdoorCommitmentScheme
			(mpz_srcptr p_ENC, mpz_srcptr q_ENC,
			 mpz_srcptr k_ENC, mpz_srcptr g_ENC,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenTrapdoorCommitmentScheme
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream &out) const;
		void Commit
			(mpz_ptr c, mpz_ptr r, mpz_srcptr m) const;
		void CommitBy
			(mpz_ptr c, mpz_srcptr r, mpz_srcptr m,
			 const bool TimingAttackProtection = true) const;
		bool Verify
			(mpz_srcptr c, mpz_srcptr r, mpz_srcptr m) const;
		~PedersenTrapdoorCommitmentScheme
			();
};

/* TODO: This class implements the non-committing encryption scheme [JL00]. */

// TODO 

/* This protocol is based upon [GJKR07] and is called Joint-RVSS [JL00]. */
class JareckiLysyanskayaRVSS
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		const unsigned long int				F_size, G_size;
	
	public:
		mpz_t						p, q, g, h;
		size_t						n, t;
		std::vector<size_t>				Qual;
		mpz_t						a_i, hata_i;
		mpz_t						alpha_i, hatalpha_i;
		std::vector< std::vector<mpz_ptr> >		alpha_ij, hatalpha_ij, C_ik;
		
		JareckiLysyanskayaRVSS
			(const size_t n_in, const size_t t_in,
			 mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Share
			(const size_t i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		bool Share_twoparty
			(const size_t i, std::istream &in, std::ostream &out,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		bool Reconstruct
			(const size_t i, const std::vector<size_t> &complaints,
			 std::vector<mpz_ptr> &a_i_in,
			 CachinKursawePetzoldShoupRBC *rbc, std::ostream &err);
		~JareckiLysyanskayaRVSS
			();
};

/* This protocol is the erasure-free distributed coinflip protocol of [JL00]. */
class JareckiLysyanskayaEDCF
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		const unsigned long int				F_size, G_size;
		JareckiLysyanskayaRVSS				*rvss;
	
	public:
		mpz_t						p, q, g, h;
		size_t						n, t;
		
		JareckiLysyanskayaEDCF
			(const size_t n_in, const size_t t_in,
			 mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		bool Flip
			(const size_t i, mpz_ptr a,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		bool Flip_twoparty
			(const size_t i, mpz_ptr a, std::istream &in, std::ostream &out,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		~JareckiLysyanskayaEDCF
			();
};


#endif
