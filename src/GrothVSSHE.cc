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
	mpz_init(p), mpz_init(q), mpz_init_set_ui(h, 1L), mpz_init(k);
	mpz_lprime(p, q, k, fieldsize, subgroupsize);
	for (size_t i = 0; i <= n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		// choose randomly elements of order $q$
		do
		{
			mpz_srandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
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
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		mpz_fpowm_init(tmp);
		mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

nWay_PedersenCommitmentScheme::nWay_PedersenCommitmentScheme
	(size_t n, std::istream &in)
{
	assert(n >= 1);
	
	// Initalize the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init(h), mpz_init(k);
	in >> q >> k >> h;
	mpz_mul(p, q, k), mpz_add_ui(p, p, 1L); // compute p := qk + 1
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		in >> tmp;
		g.push_back(tmp);
	}
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		mpz_fpowm_init(tmp);
		mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool nWay_PedersenCommitmentScheme::CheckGroup
	(unsigned long int fieldsize, unsigned long int subgroupsize)
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// Check whether $p$ and $q$ are prime.
		if (!mpz_probab_prime_p(p, 64) || !mpz_probab_prime_p(q, 64))
			throw false;
		
		// Check whether $q$ is not a divisor of $k$, i.e. $q$ and $k$ are coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are of order $q$.
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			mpz_fpowm(fpowm_table_g[i], foo, g[i], q, p);
			if (mpz_cmp_ui(foo, 1L))
				throw false;
		}
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are different and non-trivial.
		if (!mpz_cmp_ui(h, 1L))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			if (!mpz_cmp_ui(g[i], 1L) || !mpz_cmp(g[i], h))
				throw false;
			for (size_t j = (i + 1); j < g.size(); j++)
			{
				if (!mpz_cmp(g[i], g[j]))
					throw false;
			}	
		}
		
		// anything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void nWay_PedersenCommitmentScheme::PublishGroup
	(std::ostream &out)
{
	out << q << std::endl << k << std::endl << h << std::endl;
	for (size_t i = 0; i < g.size(); i++)
		out << g[i] << std::endl;
}

void nWay_PedersenCommitmentScheme::Commit
	(mpz_ptr c, mpz_ptr r, std::vector<mpz_ptr> m)
{
	assert(m.size() == g.size());
	
	// Choose a randomizer from $\mathbb{Z}_q$
	mpz_srandomm(r, q);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp;
	mpz_init(tmp);
	mpz_fspowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp);
}

bool nWay_PedersenCommitmentScheme::Verify
	(mpz_srcptr c, mpz_srcptr r, const std::vector<mpz_ptr> &m)
{
	assert(m.size() == g.size());
	
	mpz_t tmp, c2;
	mpz_init(tmp), mpz_init(c2);
	try
	{
		// Compute the commitment $c' := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
		mpz_fpowm(fpowm_table_h, c2, h, r, p);
		for (size_t i = 0; i < g.size(); i++)
		{
			mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
			mpz_mul(c2, c2, tmp);
			mpz_mod(c2, c2, p);
		}
		
		// Verify the commitment: 1. $c\in\mathbb{Z}_p$ and 2. $c = c'$
		if ((mpz_cmp(c, p) >= 1) || mpz_cmp(c, c2))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(tmp), mpz_clear(c2);
		return return_value;
	}
}

nWay_PedersenCommitmentScheme::~nWay_PedersenCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(h), mpz_clear(k);
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
