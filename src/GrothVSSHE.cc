/*******************************************************************************
  GrothVSSHE.cc, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

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

#include "GrothVSSHE.hh"

nWay_PedersenCommitmentScheme::nWay_PedersenCommitmentScheme
	(size_t n, unsigned long int fieldsize, unsigned long int subgroupsize)
{
	assert(n >= 1);
	
	// Initalize and choose the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init_set_ui(h, 1L), mpz_init(pm1dq);
	mpz_lprime(p, q, pm1dq, fieldsize, subgroupsize);
	for (size_t i = 0; i <= n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		// choose randomly elements of order $q$
		do
		{
			mpz_srandomm(tmp, p);
			mpz_powm(tmp, tmp, pm1dq, p);
		}
		while (mpz_congruent_p(tmp, h, p));
		
		if (i < n)
		{
			// store the elements $g_1, \ldots, g_n$
			g.push_back(tmp);
		}
		else
		{
			// the last element is $h$
			mpz_set(h, tmp);
			mpz_clear(tmp);
			delete tmp;
		}
	}
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; i < n; i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		mpz_fpowm_init(tmp);
		mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(p, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(p, 2L));
}

nWay_PedersenCommitmentScheme::~nWay_PedersenCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(h), mpz_clear(pm1dq);
	for (size_t i = 0; i < g.size(); i++)
	{
			mpz_clear(g[i]);
			delete g[i];
	}
	g.clear();
	
	for (size_t i = 0; i < fpowm_table_g.size(); i++)
	{
		mpz_fpowm_done(fpowm_table_g[i]);
		delete [] fpowm_table_g[i];
	}
	fpowm_table_g.clear();
	mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_h;
}
