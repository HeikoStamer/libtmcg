/*******************************************************************************
  PedersenCOM.cc, Information Theoretically Binding |COM|mitment Scheme

     [Pe92] Torben P. Pedersen: 'Non-Interactive and Information-Theoretic 
       Secure Verifiable Secret Sharing',
     Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 129--140, Springer 1992.

     [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of LibTMCG.

 Copyright (C) 2005, 2009,
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "PedersenCOM.hh"

// additional headers
#include <cassert>

#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

/* This variation of the Pedersen commitment scheme is due to Groth [Gr05]. */
PedersenCommitmentScheme::PedersenCommitmentScheme
	(const size_t n,
	 const unsigned long int fieldsize,
	 const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t foo;
	assert(n >= 1);
	
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init(k), mpz_init_set_ui(h, 1L);
	tmcg_mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	for (size_t i = 0; i <= n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		
		// choose uniformly at random an element of order $q$
		do
		{
			tmcg_mpz_wrandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
		}
		while (!mpz_cmp_ui(tmp, 0L) || !mpz_cmp_ui(tmp, 1L) || 
			!mpz_cmp(tmp, foo)); // check, whether $1 < tmp < p-1$
		
		if (i < n)
		{
			// store the elements $g_1, \ldots, g_n$
			g.push_back(tmp);
		}
		else
		{
			// the last element is called $h$
			mpz_set(h, tmp);
			mpz_clear(tmp);
			delete [] tmp;
		}
	}
	mpz_clear(foo);
	
	// Do the precomputation for the fast exponentiation.
	// For $g_1, \ldots, g_n$ this computation is only done up to a bound
	// TMCG_MAX_FPOWM_N, in order to keep the memory allocation low.
	for (size_t i = 0; i < g.size() && i < TMCG_MAX_FPOWM_N; i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		tmcg_mpz_fpowm_init(tmp);
		tmcg_mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

PedersenCommitmentScheme::PedersenCommitmentScheme
	(const size_t n,
	 mpz_srcptr p_ENC,
	 mpz_srcptr q_ENC, 
	 mpz_srcptr k_ENC,
	 mpz_srcptr h_ENC, 
	 const unsigned long int fieldsize,
	 const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t foo;
	assert(n >= 1);
	
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), 
		mpz_init_set(k, k_ENC), mpz_init_set(h, h_ENC);
	
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		
		// choose uniformly at random an element of order $q$
		do
		{
			tmcg_mpz_wrandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
		}
		while (!mpz_cmp_ui(tmp, 0L) || !mpz_cmp_ui(tmp, 1L) || 
			!mpz_cmp(tmp, foo)); // check, whether $1 < tmp < p-1$
		
		// store the elements $g_1, \ldots, g_n$
		g.push_back(tmp);
	}
	mpz_clear(foo);
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; i < g.size() && i < TMCG_MAX_FPOWM_N; i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		tmcg_mpz_fpowm_init(tmp);
		tmcg_mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

PedersenCommitmentScheme::PedersenCommitmentScheme
	(const size_t n,
	 std::istream &in,
	 const unsigned long int fieldsize,
	 const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	assert(n >= 1);
	
	// Initialize the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q),mpz_init(k), mpz_init(h);
	in >> p >> q >> k >> h;
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		in >> tmp;
		g.push_back(tmp);
	}
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; (i < g.size()) && (i < TMCG_MAX_FPOWM_N); i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		tmcg_mpz_fpowm_init(tmp);
		tmcg_mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void PedersenCommitmentScheme::SetupGenerators_publiccoin
	(mpz_srcptr a_in,
	 const bool without_h)
{
	// initialize
	mpz_t a, foo;
	mpz_init_set(a, a_in), mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$

	// verifiable generation of $h, g_1, \ldots, g_n$
	std::stringstream U;
	U << "LibTMCG|" << p << "|" << q << "|hggen|" << a << "|";

	// generating $h$, if necessary
	if (!without_h)
	{
		do
		{
			tmcg_mpz_shash(a, U.str());
			mpz_powm(h, a, k, p);
			U << h << "|";
		}
		while (!mpz_cmp_ui(h, 0L) || !mpz_cmp_ui(h, 1L) || 
			!mpz_cmp(h, foo)); // check $1 < h < p-1$
		tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, 
			mpz_sizeinbase(q, 2L));
	}

	// generating $g_1, \ldots, g_n$
	for (size_t i = 0; i < g.size(); i++)
	{
		do
		{
			tmcg_mpz_shash(a, U.str());
			mpz_powm(g[i], a, k, p);
			U << g[i] << "|";
		}
		while (!mpz_cmp_ui(g[i], 0L) || !mpz_cmp_ui(g[i], 1L) ||
			!mpz_cmp(g[i], foo)); // check $1 < g_i < p-1$
		if (i < TMCG_MAX_FPOWM_N)
			tmcg_mpz_fpowm_precompute(fpowm_table_g[i], g[i], p,
				mpz_sizeinbase(q, 2L));
	}

	// release
	mpz_clear(a), mpz_clear(foo);
}

bool PedersenCommitmentScheme::SetupGenerators_publiccoin
	(const size_t whoami,
	 aiounicast *aiou, 
	 CachinKursawePetzoldShoupRBC *rbc,
	 JareckiLysyanskayaEDCF *edcf,
	 std::ostream &err,
	 const bool without_h)
{
	// initialize
	mpz_t a;
	mpz_init_set_ui(a, 0L);

	// set ID for RBC
	std::stringstream myID;
	myID << "PedersenCommitmentScheme::SetupGenerators_publiccoin()" << 
		p << q << rbc->n << rbc->t;
	rbc->setID(myID.str());
	try
	{
		// check EDCF
		if (!edcf->CheckGroup())
		{
			err << "CheckGroup() for EDCF failed" << std::endl;
			throw false;
		}

		// flip commonly public coins to get $a$ and use it as seed
		// value for verifiable generation of $h, g_1, \ldots, g_n$
		if (!edcf->Flip(whoami, a, aiou, rbc, err))
			throw false;
		SetupGenerators_publiccoin(a, without_h);

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		
		mpz_clear(a);
		return return_value;
	}
}

bool PedersenCommitmentScheme::CheckGroup
	() const
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) || 
			(mpz_sizeinbase(q, 2L) < G_size))
				throw false;
		
		// Check whether $p$ has the correct form, i.e. $p = kq + 1$.
		mpz_mul(foo, q, k);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;
		
		// Check whether $p$ and $q$ are both (probable) prime with a
		// soundness error probability ${} \le 4^{-TMCG_MR_ITERATIONS}$.
		if (!mpz_probab_prime_p(p, TMCG_MR_ITERATIONS) || 
			!mpz_probab_prime_p(q, TMCG_MR_ITERATIONS))
				throw false;
		
		// Check whether $k$ is not divisible by $q$, i.e. $q, k$
		// are coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are of 
		// order $q$.
		mpz_powm(foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			mpz_powm(foo, g[i], q, p);
			if (mpz_cmp_ui(foo, 1L))
				throw false;
		}
		
		// Check whether elements $h, g_1, \ldots, g_n$ are different
		// and non-trivial, i.e., $1 < h, g_1, \ldots, g_n < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(h, 1L) <= 0) || (mpz_cmp(h, foo) >= 0))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			if ((mpz_cmp_ui(g[i], 1L) <= 0) || 
				(mpz_cmp(g[i], foo) >= 0) || !mpz_cmp(g[i], h))
					throw false;
			for (size_t j = (i + 1); j < g.size(); j++)
			{
				if (!mpz_cmp(g[i], g[j]))
					throw false;
			}
		}
		
		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void PedersenCommitmentScheme::PublishGroup
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << k << std::endl << 
		h << std::endl;
	for (size_t i = 0; i < g.size(); i++)
		out << g[i] << std::endl;
}

void PedersenCommitmentScheme::Commit
	(mpz_ptr c,
	 mpz_ptr r,
	 const std::vector<mpz_ptr> &m) const
{
	assert(m.size() <= g.size());
	
	// Choose a randomizer from $\mathbb{Z}_q$
	tmcg_mpz_srandomm(r, q);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp, tmp2;
	mpz_init(tmp), mpz_init(tmp2);
	tmcg_mpz_fspowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < m.size(); i++)
	{
		if (i < TMCG_MAX_FPOWM_N)
		{
			tmcg_mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		}
		else
		{
			tmcg_mpz_spowm(tmp, g[i], m[i], p);
		}
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp), mpz_clear(tmp2);
}

void PedersenCommitmentScheme::CommitBy
	(mpz_ptr c,
	 mpz_srcptr r,
	 const std::vector<mpz_ptr> &m,
	 const bool TimingAttackProtection) const
{
	assert(m.size() <= g.size());
	assert(mpz_cmp(r, q) < 0);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp;
	mpz_init(tmp);
	if (TimingAttackProtection)
		tmcg_mpz_fspowm(fpowm_table_h, c, h, r, p);
	else
		tmcg_mpz_fpowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < m.size(); i++)
	{
		if (i < TMCG_MAX_FPOWM_N)
		{
			if (TimingAttackProtection)
				tmcg_mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
			else
				tmcg_mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		}
		else
		{
			if (TimingAttackProtection)
				tmcg_mpz_spowm(tmp, g[i], m[i], p);
			else
				mpz_powm(tmp, g[i], m[i], p);
		}
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp);
}

bool PedersenCommitmentScheme::TestMembership
	(mpz_srcptr c) const
{
	if ((mpz_cmp_ui(c, 0L) > 0) && (mpz_cmp(c, p) < 0))
		return true;
	else
		return false;
}

bool PedersenCommitmentScheme::Verify
	(mpz_srcptr c,
	 mpz_srcptr r,
	 const std::vector<mpz_ptr> &m) const
{
	assert(m.size() <= g.size());
	
	mpz_t tmp, c2;
	mpz_init(tmp), mpz_init(c2);
	try
	{
		// Check whether $r < q$ holds 
		if (mpz_cmp(r, q) >= 0)
			throw false;

		// Compute the commitment for verification
		// $c' := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
		tmcg_mpz_fpowm(fpowm_table_h, c2, h, r, p);
		for (size_t i = 0; i < m.size(); i++)
		{
			if (i < TMCG_MAX_FPOWM_N)
			{
				tmcg_mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
			}
			else
			{
				mpz_powm(tmp, g[i], m[i], p);
			}
			mpz_mul(c2, c2, tmp);
			mpz_mod(c2, c2, p);
		}
		// Verify the commitment: 1. $c\in\mathbb{Z}_p\setminus\{0\}$
		if ((mpz_cmp_ui(c, 0L) <= 0) || (mpz_cmp(c, p) >= 0))
			throw false;
		// Verify the commitment: 2. $c = c'$
		if (mpz_cmp(c, c2))
			throw false;
		
		// commitment is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(tmp), mpz_clear(c2);
		return return_value;
	}
}

PedersenCommitmentScheme::~PedersenCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(k), mpz_clear(h);
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_clear(g[i]);
		delete [] g[i];
	}
	g.clear();
	
	for (size_t i = 0; i < fpowm_table_g.size(); i++)
	{
		tmcg_mpz_fpowm_done(fpowm_table_g[i]);
		delete [] fpowm_table_g[i];
	}
	fpowm_table_g.clear();
	tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_h;
}
