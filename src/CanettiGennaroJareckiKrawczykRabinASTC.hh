/*******************************************************************************
  CanettiGennaroJareckiKrawczykRabinASTC.hh,
                         |A|daptive |S|ecurity for |T|hreshold |C|ryptosystems

     [CGJKR99] Ran Canetti, Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk,
               and Tal Rabin: 'Adaptive Security for Threshold Cryptosystems',
     Advances in Cryptology - CRYPTO'99, LNCS 1666, pp. 98--116, 1999.

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

#ifndef INCLUDED_CanettiGennaroJareckiKrawczykRabinASTC_HH
	#define INCLUDED_CanettiGennaroJareckiKrawczykRabinASTC_HH
	
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
#include "PedersenVSS.hh"

/* This protocol is called Joint-RVSS in [CGJKR99]. It is basically a joint
   Pedersen VSS of a random value. A slightly corrected version was pusblished
   by the same authors in an extended version of the paper. */
class CanettiGennaroJareckiKrawczykRabinRVSS
{
	private:
		mpz_t									*fpowm_table_g, *fpowm_table_h;
		const unsigned long int					F_size, G_size;
		const bool								canonical_g;
		const bool								use_very_strong_randomness;
		const std::string						label;
	
	public:
		mpz_t									p, q, g, h;
		size_t									n, t, i, tprime;
		std::vector<size_t>						QUAL;
		mpz_t									x_i, xprime_i;
		mpz_t									z_i, zprime_i;
		std::vector< std::vector<mpz_ptr> >		s_ji, sprime_ji, C_ik;
		
		CanettiGennaroJareckiKrawczykRabinRVSS
			(const size_t n_in, const size_t t_in, const size_t i_in,
			 const size_t tprime_in, mpz_srcptr p_CRS, mpz_srcptr q_CRS,
			 mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		CanettiGennaroJareckiKrawczykRabinRVSS
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		void PublishState
			(std::ostream &out) const;
		std::string Label
			() const;
		void EraseSecrets
			();
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Share
			(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Share
			(std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Reconstruct
			(const std::vector<size_t> &complaints,
			 std::vector<mpz_ptr> &a_i_in,
			 CachinKursawePetzoldShoupRBC *rbc, std::ostream &err);
		bool Reconstruct
			(const std::vector<size_t> &complaints,
			 std::vector<mpz_ptr> &a_i_in,
			 std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 CachinKursawePetzoldShoupRBC *rbc, std::ostream &err);
		~CanettiGennaroJareckiKrawczykRabinRVSS
			();
};

/* This protocol is called Joint-ZVSS in [CGJKR99] and stands for "Joint
   Zero VSS". They used it as a subprotocol of Sig-Gen for randomization of
   polynomials to hide all partial information. It is a slight modification of
   Joint-RVSS where all players fix their values $z_i = a_{i0}$ and $b_{i0}$ to
   zero. This can be verified by other players by checking that
   $C_{i0} = 1 \bmod p$. */
class CanettiGennaroJareckiKrawczykRabinZVSS
{
	private:
		mpz_t									*fpowm_table_g, *fpowm_table_h;
		const unsigned long int					F_size, G_size;
		const bool								canonical_g;
		const bool								use_very_strong_randomness;
		const std::string						label;
	
	public:
		mpz_t									p, q, g, h;
		size_t									n, t, i, tprime;
		std::vector<size_t>						QUAL;
		mpz_t									x_i, xprime_i;
		std::vector< std::vector<mpz_ptr> >		s_ji, sprime_ji, C_ik;
		
		CanettiGennaroJareckiKrawczykRabinZVSS
			(const size_t n_in, const size_t t_in, const size_t i_in,
			 const size_t tprime_in, mpz_srcptr p_CRS, mpz_srcptr q_CRS,
			 mpz_srcptr g_CRS, mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		CanettiGennaroJareckiKrawczykRabinZVSS
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		void PublishState
			(std::ostream &out) const;
		std::string Label
			() const;
		void EraseSecrets
			();
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Share
			(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Share
			(std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		~CanettiGennaroJareckiKrawczykRabinZVSS
			();
};

/* This protocol is called DKG in [CGJKR99]. However, we implement a variant
   with optimal resilience $t < n/2$. */
class CanettiGennaroJareckiKrawczykRabinDKG
{
	private:
		mpz_t									*fpowm_table_g, *fpowm_table_h;
		const unsigned long int					F_size, G_size;
		const bool								canonical_g;
		const bool								use_very_strong_randomness;
		const std::string						label;
	
	public:
		mpz_t									p, q, g, h;
		size_t									n, t, i;
		std::vector<size_t>						QUAL;
		CanettiGennaroJareckiKrawczykRabinRVSS	*x_rvss;
		mpz_t									x_i, xprime_i, y;
		
		CanettiGennaroJareckiKrawczykRabinDKG
			(const size_t n_in, const size_t t_in, const size_t i_in,
			 mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS,
			 mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		CanettiGennaroJareckiKrawczykRabinDKG
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true,
			 const std::string label_in = "");
		void PublishState
			(std::ostream &out) const;
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Generate
			(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Generate
			(std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Refresh
			(const size_t n_in, const size_t i_in,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Refresh
			(const size_t n_in, const size_t i_in,
			 std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		~CanettiGennaroJareckiKrawczykRabinDKG
			();
};

/* This protocol is called Sig-Gen in [CGJKR99]. However, we implement a variant
   with optimal resilience $t < n/2$. It is described in the extended version of
   the paper (Figure 6) and is called DSS-Sig-Gen there. */
class CanettiGennaroJareckiKrawczykRabinDSS
{
	private:
		mpz_t									*fpowm_table_g, *fpowm_table_h;
		const unsigned long int					F_size, G_size;
		const bool								canonical_g;
		const bool								use_very_strong_randomness;

	public:
		mpz_t									p, q, g, h;
		size_t									n, t, i;
		std::vector<size_t>						QUAL;
		CanettiGennaroJareckiKrawczykRabinDKG	*dkg;
		mpz_t									x_i, xprime_i, y;

		CanettiGennaroJareckiKrawczykRabinDSS
			(const size_t n_in, const size_t t_in, const size_t i_in,
			 mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS,
			 mpz_srcptr h_CRS,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true);
		CanettiGennaroJareckiKrawczykRabinDSS
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool use_very_strong_randomness_in = true);
		void PublishState
			(std::ostream &out) const;
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		bool Generate
			(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Refresh
			(const size_t n_in, const size_t i_in,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Refresh
			(const size_t n_in, const size_t i_in,
			 std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err,
			 const bool simulate_faulty_behaviour = false,
			 mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE] = NULL,
			 mpz_srcptr ssrandomm_cache_mod = NULL,
			 size_t *ssrandomm_cache_avail = NULL);
		bool Sign
			(const size_t n_in, const size_t i_in,
			 mpz_srcptr m, mpz_ptr r, mpz_ptr s,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		bool Sign
			(const size_t n_in, const size_t i_in,
			 mpz_srcptr m, mpz_ptr r, mpz_ptr s,
			 std::map<size_t, size_t> &idx2dkg,
			 std::map<size_t, size_t> &dkg2idx,
			 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
			 std::ostream &err, const bool simulate_faulty_behaviour = false);
		bool Verify
			(mpz_srcptr m, mpz_srcptr r, mpz_srcptr s) const;
		~CanettiGennaroJareckiKrawczykRabinDSS
			();
};

#endif
