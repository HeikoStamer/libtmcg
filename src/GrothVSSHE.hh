/*******************************************************************************
  GrothVSSHE.hh, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

     Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_GrothVSSHE_HH
	#define INCLUDED_GrothVSSHE_HH

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

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_spowm.h"
	#include "mpz_sprime.h"
	#include "mpz_helper.hh"
	#include "mpz_shash.hh"

class PedersenCommitmentScheme
{
	private:
		mpz_t						*fpowm_table_h;
		std::vector<mpz_t*>			fpowm_table_g;
		const unsigned long int		F_size, G_size;
	
	public:
		mpz_t						p, q, k, h;
		std::vector<mpz_ptr>		g;
		
		PedersenCommitmentScheme
			(size_t n,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenCommitmentScheme
			(size_t n, mpz_srcptr p_ENC, mpz_srcptr q_ENC,
			mpz_srcptr k_ENC, mpz_srcptr h_ENC,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		PedersenCommitmentScheme
			(size_t n, std::istream &in,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream &out) const;
		void Commit
			(mpz_ptr c, mpz_ptr r, std::vector<mpz_ptr> m) const;
		void CommitBy
			(mpz_ptr c, mpz_srcptr r, std::vector<mpz_ptr> m,
			bool TimingAttackProtection = true) const;
		bool TestMembership
			(mpz_srcptr c) const;
		bool Verify
			(mpz_srcptr c, mpz_srcptr r, const std::vector<mpz_ptr> &m) const;
		~PedersenCommitmentScheme
			();
};

// =============================================================================

class GrothSKC
{
	private:
		const unsigned long int			l_e;
		mpz_t												exp2l_e;
		PedersenCommitmentScheme		*com;
	
	public:
		GrothSKC
			(size_t n,
			unsigned long int ell_e = TMCG_GROTH_L_E,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		GrothSKC
			(size_t n, std::istream &in,
			unsigned long int ell_e = TMCG_GROTH_L_E,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream &out) const;
		void Prove_interactive
			(const std::vector<size_t> &pi, mpz_srcptr r,
			const std::vector<mpz_ptr> &m,
			std::istream &in, std::ostream &out) const;
		bool Verify_interactive
			(mpz_srcptr c, const std::vector<mpz_ptr> &m,
			std::istream &in, std::ostream &out, bool optimizations = true) const;
		bool Verify_interactive
			(mpz_srcptr c, const std::vector<mpz_ptr> &f_prime,
			const std::vector<mpz_ptr> &m,
			std::istream &in, std::ostream &out, bool optimizations = true) const;
		~GrothSKC
			();
};

// =============================================================================

class GrothVSSHE
{
	private:
		const unsigned long int			l_e;
		mpz_t												*fpowm_table_g, *fpowm_table_h, exp2l_e;
		GrothSKC										*skc;
	
	public:
		mpz_t												p, q, g, h;
		PedersenCommitmentScheme		*com;
		
		GrothVSSHE
			(size_t n,
			mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC,
			mpz_srcptr h_ENC,
			unsigned long int ell_e = TMCG_GROTH_L_E,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		GrothVSSHE
			(size_t n,
			mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr k_ENC,
			mpz_srcptr g_ENC, mpz_srcptr h_ENC,
			unsigned long int ell_e = TMCG_GROTH_L_E,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		GrothVSSHE
			(size_t n, std::istream& in,
			unsigned long int ell_e = TMCG_GROTH_L_E,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream& out) const;
		void Prove_interactive
			(const std::vector<size_t>& pi, const std::vector<mpz_ptr>& R,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
			std::istream& in, std::ostream& out) const;
		bool Verify_interactive
			(const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
			std::istream& in, std::ostream& out) const;
		~GrothVSSHE
			();
};

#endif
