/*******************************************************************************
  GrothVSSHE.hh, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

     Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of libTMCG.

 Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>

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

class nWay_PedersenCommitmentScheme
{
	private:
		mpz_t						*fpowm_table_h;
		std::vector<mpz_t*>			fpowm_table_g;
		
	public:
		mpz_t						p, q, h, k;
		std::vector<mpz_ptr>		g;

	nWay_PedersenCommitmentScheme
		(size_t n,
		unsigned long int fieldsize = TMCG_DDH_SIZE,
		unsigned long int subgroupsize = TMCG_DLSE_SIZE);
	nWay_PedersenCommitmentScheme
		(size_t n, std::istream &in);
	bool CheckGroup
		(unsigned long int fieldsize = TMCG_DDH_SIZE,
		unsigned long int subgroupsize = TMCG_DLSE_SIZE);
	void PublishGroup
		(std::ostream &out);
	void Commit
		(mpz_ptr c, mpz_ptr r, std::vector<mpz_ptr> m);
	bool Verify
		(mpz_srcptr c, mpz_srcptr r, const std::vector<mpz_ptr> &m);
	~nWay_PedersenCommitmentScheme
		();
};

class GrothVSSHE
{
	private:
	
	public:
};

#endif
