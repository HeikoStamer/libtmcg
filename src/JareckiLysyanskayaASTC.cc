/*******************************************************************************
  JareckiLysyanskayaASTC.cc,
                             |A|daptively |S|ecure |T|hreshold |C|ryptography

     [JL00] Stanislaw Jarecki and Anna Lysyanskaya:
       'Adaptively Secure Threshold Cryptography: Introducing Concurrency,
        Removing Erasures', Advances in Cryptology - EUROCRYPT 2000,
     LNCS 1807, pp. 221--242, Springer 2000.

   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "JareckiLysyanskayaASTC.hh"

// additional headers
#include <cassert>
#include <string>
#include <sstream>
#include <algorithm>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

/* This is a trapdoor commitment [JL00] based on Pedersen's scheme [Pe92]. */
PedersenTrapdoorCommitmentScheme::PedersenTrapdoorCommitmentScheme
	(const unsigned long int fieldsize, const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init(k), mpz_init(g), mpz_init(h);
	tmcg_mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
	mpz_t foo;
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	// choose uniformly at random an element $g$ of order $q$
	do
	{
		tmcg_mpz_wrandomm(g, p);
		mpz_powm(g, g, k, p);
	}
	while (!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
		!mpz_cmp(g, foo)); // check, whether $1 < g < p-1$
	mpz_clear(foo);

	// Initialize and choose the trapdoor of the commitment scheme.
	mpz_init(sigma);
	tmcg_mpz_srandomm(sigma, q);
	// Compute $h := g^\sigma \bmod p$ by using the trapdoor $\sigma$.
	tmcg_mpz_spowm(h, g, sigma, p);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

PedersenTrapdoorCommitmentScheme::PedersenTrapdoorCommitmentScheme
	(mpz_srcptr p_ENC, mpz_srcptr q_ENC, 
	 mpz_srcptr k_ENC, mpz_srcptr g_ENC, 
	 const unsigned long int fieldsize, const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), 
		mpz_init_set(k, k_ENC), mpz_init_set(g, g_ENC);
	mpz_init(h);
	
	// Initialize and choose the trapdoor of the commitment scheme.
	mpz_init(sigma);
	tmcg_mpz_srandomm(sigma, q);
	// Compute $h := g^\sigma \bmod p$ by using the trapdoor $\sigma$.
	tmcg_mpz_spowm(h, g, sigma, p);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

PedersenTrapdoorCommitmentScheme::PedersenTrapdoorCommitmentScheme
	(std::istream &in,
	 const unsigned long int fieldsize, const unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	// Initialize the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q),mpz_init(k), mpz_init(g), mpz_init(h);
	in >> p >> q >> k >> g >> h;

	// Initialize and choose the trapdoor as unknown (only verify).
	mpz_init_set_ui(sigma, 0L);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool PedersenTrapdoorCommitmentScheme::CheckGroup
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
		
		// Check whether the elements $g$ and $h$ are of order $q$.
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_powm(foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether elements $g$ and $h$ are different
		// and non-trivial, i.e., $1 < g, h < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, foo) >= 0))
			throw false;
		if ((mpz_cmp_ui(h, 1L) <= 0) || (mpz_cmp(h, foo) >= 0))
			throw false;
		if (!mpz_cmp(g, h))
			throw false;
		
		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void PedersenTrapdoorCommitmentScheme::PublishGroup
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << k << std::endl << 
		g << std::endl << h << std::endl;
}

void PedersenTrapdoorCommitmentScheme::Commit
	(mpz_ptr c, mpz_ptr r, mpz_srcptr m) const
{
	// Choose a randomizer from $\mathbb{Z}_q$
	tmcg_mpz_srandomm(r, q);
	
	// Compute the commitment $c := g^{H(m)} h^r \bmod p$
	mpz_t foo;
	mpz_init(foo);
	tmcg_mpz_shash(foo, 1, m);
	mpz_mod(foo, foo, q);
	tmcg_mpz_fspowm(fpowm_table_h, c, h, r, p);
	tmcg_mpz_fspowm(fpowm_table_g, foo, g, foo, p);
	mpz_mul(c, c, foo);
	mpz_mod(c, c, p);
	mpz_clear(foo);
}

void PedersenTrapdoorCommitmentScheme::CommitBy
	(mpz_ptr c, mpz_srcptr r, mpz_srcptr m,
	 const bool TimingAttackProtection) const
{
	assert(mpz_cmp(r, q) < 0);
	
	// Compute the commitment $c := g^{H(m)} h^r \bmod p$
	mpz_t foo;
	mpz_init(foo);
	tmcg_mpz_shash(foo, 1, m);
	mpz_mod(foo, foo, q);
	if (TimingAttackProtection)
	{
		tmcg_mpz_fspowm(fpowm_table_h, c, h, r, p);
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, foo, p);
	}
	else
	{
		tmcg_mpz_fpowm(fpowm_table_h, c, h, r, p);
		tmcg_mpz_fpowm(fpowm_table_g, foo, g, foo, p);
	}
	mpz_mul(c, c, foo);
	mpz_mod(c, c, p);
	mpz_clear(foo);
}

bool PedersenTrapdoorCommitmentScheme::Verify
	(mpz_srcptr c, mpz_srcptr r, mpz_srcptr m) const
{
	mpz_t foo, c2;
	mpz_init(foo), mpz_init(c2);
	try
	{
		// Check whether $r < q$ holds
		if (mpz_cmp(r, q) >= 0)
			throw false;

		// Compute the commitment for verification
		// $c' := g^{H(m)} h^r \bmod p$
		tmcg_mpz_shash(foo, 1, m);
		mpz_mod(foo, foo, q);
		tmcg_mpz_fpowm(fpowm_table_h, c2, h, r, p);
		tmcg_mpz_fpowm(fpowm_table_g, foo, g, foo, p);
		mpz_mul(c2, c2, foo);
		mpz_mod(c2, c2, p);
		
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
		mpz_clear(foo), mpz_clear(c2);
		return return_value;
	}
}

PedersenTrapdoorCommitmentScheme::~PedersenTrapdoorCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(k), mpz_clear(g), mpz_clear(h);
	mpz_clear(sigma);
	tmcg_mpz_fpowm_done(fpowm_table_g);
	delete [] fpowm_table_g;
	tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_h;
}

// ===================================================================================================================================

JareckiLysyanskayaRVSS::JareckiLysyanskayaRVSS
	(const size_t n_in, const size_t t_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize, const unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize),
			n(n_in), t(t_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS);
	mpz_init_set(h, h_CRS);

	mpz_init_set_ui(a_i, 0L), mpz_init_set_ui(hata_i, 0L);
	mpz_init_set_ui(alpha_i, 0L), mpz_init_set_ui(hatalpha_i, 0L);
	alpha_ij.resize(n);
	hatalpha_ij.resize(n);
	C_ik.resize(n);
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp1 = new mpz_t();
			mpz_init(tmp1);
			alpha_ij[i].push_back(tmp1);
		}
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp2 = new mpz_t();
			mpz_init(tmp2);
			hatalpha_ij[i].push_back(tmp2);
		}
		for (size_t k = 0; k <= t; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
 			C_ik[i].push_back(tmp3);
		}
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool JareckiLysyanskayaRVSS::CheckGroup
	() const
{
	mpz_t foo, k;

	mpz_init(foo), mpz_init(k);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
		if (!mpz_cmp_ui(q, 0L))
			throw false;
		mpz_div(k, k, q);

		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) ||
			(mpz_sizeinbase(q, 2L) < G_size))
				throw false;

		// Check whether $p$ has the correct form, i.e. $p = kq + 1$.
		mpz_mul(foo, q, k);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;

		// Check whether $p$ and $q$ are both (probable) prime with
		// a soundness error probability ${} \le 4^{-TMCG_MR_ITERATIONS}$.
		if (!mpz_probab_prime_p(p, TMCG_MR_ITERATIONS) || 
			!mpz_probab_prime_p(q, TMCG_MR_ITERATIONS))
				throw false;

		// Check whether $k$ is not divisible by $q$, i.e. $q, k$ are coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;

		// Check whether the elements $h$ and $g$ are of order $q$.
		mpz_powm(foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;

		// Check whether the elements $h$ and $g$ are different and non-trivial,
		// i.e., $1 < h, g < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(h, 1L) <= 0) || (mpz_cmp(h, foo) >= 0))
			throw false;
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, foo) >= 0))
			throw false;
		if (!mpz_cmp(g, h))
			throw false;

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(k);
		return return_value;
	}
}

bool JareckiLysyanskayaRVSS::CheckElement
	(mpz_srcptr a) const
{
	mpz_t foo;
	mpz_init(foo);

	try
	{
		// Check whether $0 < a < p$.
		if ((mpz_cmp_ui(a, 0L) <= 0) || (mpz_cmp(a, p) >= 0))
			throw false;
		
		// Check whether $a^q \equiv 1 \pmod{p}$.
		mpz_powm(foo, a, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

bool JareckiLysyanskayaRVSS::Share
	(const size_t i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(i == rbc->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> c_ik, hatc_ik;
	std::vector<size_t> complaints, complaints_counter, complaints_from;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t k = 0; k <= t; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		c_ik.push_back(tmp1), hatc_ik.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "JareckiLysyanskayaRVSS::Share()" << p << q << g << h << n << t;
	rbc->setID(myID.str());

	try
	{
		// 1. Each player $P_i$ performs a Pedersen-VSS of a random
		//    value $a_i$:
		// (a) $P_i$ picks $t$-deg. polynomials
		//     $f_{a_i}(z) = \sum_{k=0}^t c_{ik} z^k$,
		//     $f_{\hat{a_i}}(z) = \sum_{k=0}^t \hat{c}_{ik} z^k$
		for (size_t k = 0; k <= t; k++)
		{
			tmcg_mpz_srandomm(c_ik[k], q);
			tmcg_mpz_srandomm(hatc_ik[k], q);
		}
		// Let $a_i = f_{a_i}(0)$ and $\hat{a_i} = f_{\hat{a_i}}(0)$.
		mpz_set(a_i, c_ik[0]), mpz_set(hata_i, hatc_ik[0]);
		// $P_i$ broadcasts $C_{ik} = g^{c_{ik}} h^{\hat{c}_{ik}}$
		// for $k = 0..t$. 
		for (size_t k = 0; k <= t; k++)
		{
			tmcg_mpz_fspowm(fpowm_table_g, foo, g, c_ik[k], p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, hatc_ik[k], p);
			mpz_mul(C_ik[i][k], foo, bar);
			mpz_mod(C_ik[i][k], C_ik[i][k], p);
			rbc->Broadcast(C_ik[i][k]);
		}
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				for (size_t k = 0; k <= t; k++)
				{
					if (!rbc->DeliverFrom(C_ik[j][k], j))
					{
						err << "P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!CheckElement(C_ik[j][k]))
					{
						err << "P_" << i << ": bad C_ik received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(C_ik[j][k], 0L); // indicates an error
					}
				}
			}
		}
		// Set $F_{a_i}(z) = \prod_{k=0}^t (C_{ik})^{z^k}$.
		// $P_i$ sends to $P_j$ shares $\alpha_{ij} = f_{a_i}(j)$,
		// $\hat{\alpha}_{ij} = f_{\hat{a}_i}(j)$ for each $j = 1..n$.
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(alpha_ij[i][j], 0L);
			mpz_set_ui(hatalpha_ij[i][j], 0L);
			for (size_t k = 0; k <= t; k++)
			{
				mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
				mpz_mul(bar, foo, hatc_ik[k]);
				mpz_mod(bar, bar, q);
				mpz_mul(foo, foo, c_ik[k]);
				mpz_mod(foo, foo, q);
				mpz_add(alpha_ij[i][j], alpha_ij[i][j], foo);
				mpz_mod(alpha_ij[i][j], alpha_ij[i][j], q);				
				mpz_add(hatalpha_ij[i][j], hatalpha_ij[i][j], bar);
				mpz_mod(hatalpha_ij[i][j], hatalpha_ij[i][j], q);
			}
			if (j != i)
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer)
				{
					mpz_add_ui(alpha_ij[i][j], alpha_ij[i][j], 1L);
				}
				if (!aiou->Send(alpha_ij[i][j], j, aiou->aio_timeout_very_short))
				{
					err << "P_" << i << ": sending alpha_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(hatalpha_ij[i][j], j, aiou->aio_timeout_very_short))
				{
					err << "P_" << i << ": sending hatalpha_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
			}
		}
		// (b) Each $P_j$ verifies if
		//     $g^{\alpha_{ij}} h^{\hat{\alpha}_{ij}} = F_{a_i}(j)$
		//     for $i = 1..n$. If the check fails for any $i$, $P_j$
		//     broadcasts a complaint against $P_i$.
		// Note that in this section the indicies $i$ and $j$ are
		// exchanged for convenience.
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				if (!aiou->Receive(alpha_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving alpha_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(alpha_ij[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad alpha_ij received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(alpha_ij[j][i], 0L); // indicates an error
				}
				if (!aiou->Receive(hatalpha_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving hatalpha_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(hatalpha_ij[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad hatalpha_ij received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(hatalpha_ij[j][i], 0L); // indicates an error
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			// compute LHS for the check
			tmcg_mpz_fspowm(fpowm_table_g, foo, g, alpha_ij[j][i], p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, hatalpha_ij[j][i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// compute RHS for the check
			mpz_set_ui(rhs, 1L);
			for (size_t k = 0; k <= t; k++)
			{
				mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
				mpz_powm(bar, C_ik[j][k], foo, p);
				mpz_mul(rhs, rhs, bar);
				mpz_mod(rhs, rhs, p);
			}
			// check equation (4)
			if (mpz_cmp(lhs, rhs))
			{
				err << "P_" << i << ": checking 1(b) failed; complaint against P_" << j << std::endl;
				complaints.push_back(j);
			}
		}
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "P_" << i << ": broadcast complaint against P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs); // broadcast complaint
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		complaints_counter.clear(), complaints_from.clear(); // reset for final complaint resolution
		for (size_t j = 0; j < n; j++)
			complaints_counter.push_back(0); // initialize counter
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			complaints_counter[*it]++; // count my own complaints
		complaints.clear();
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				size_t who;
				size_t cnt = 0;
				std::map<size_t, bool> dup;
				do
				{
					if (!rbc->DeliverFrom(rhs, j))
					{
						err << "P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(rhs);
					if ((who < n) && !dup.count(who))
					{
						err << "P_" << i << ": receiving complaint against P_" << who << " from P_" << j << std::endl;
						complaints_counter[who]++;
						dup.insert(std::pair<size_t, bool>(who, true)); // mark as counted for $P_j$
						if (who == i)
							complaints_from.push_back(j);
					}
					else if ((who < n) && dup.count(who))
					{
						err << "P_" << i << ": duplicated complaint against P_" << who << " from P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received or maximum exceeded
			}
		}
		// (c) If $P_j$ complained against $P_i$, $P_i$ broadcasts
		//     $\alpha_{ij}$, $\hat{\alpha}_{ij}$; everyone verifies
		//     it. If $P_i$ fails this test or receives more than $t$
		//     complaints, exclude $P_i$ from $Qual$.
		if (complaints_counter[i])
		{
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "P_" << i << ": there are " << complaints_counter[i] << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
			{
				mpz_set_ui(lhs, *it); // who?
				rbc->Broadcast(lhs);
				rbc->Broadcast(alpha_ij[i][*it]);
				rbc->Broadcast(hatalpha_ij[i][*it]);
			}
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		for (size_t j = 0; j < n; j++)
		{
			if (complaints_counter[j] > t)
			{
				complaints.push_back(j);
				continue;
			}
			if (j != i)
			{
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(lhs, j))
					{
						err << "P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					size_t who = mpz_get_ui(lhs);
					if (who >= n)
						break; // end marker received
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "P_" << i << ": receiving foo failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(foo, q) >= 0)
					{
						err << "P_" << i << ": bad foo received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(foo, 0L); // indicates an error
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "P_" << i << ": receiving bar failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(bar, q) >= 0)
					{
						err << "P_" << i << ": bad bar received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(bar, 0L); // indicates an error
					}
					mpz_t alpha, hatalpha;
					mpz_init_set(alpha, foo), mpz_init_set(hatalpha, bar);
					// compute LHS for the check
					tmcg_mpz_fpowm(fpowm_table_g, foo, g, foo, p);
					tmcg_mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, foo, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $j$ in computation
						mpz_powm(bar, C_ik[j][k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (4)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking 1(c) failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious
						if (who == i)
						{
							err << "P_" << i << ": shares adjusted 1(c) from P_" << j << std::endl;
							mpz_set(alpha_ij[j][i], alpha);
							mpz_set(hatalpha_ij[j][i], hatalpha);
						}
					}
					mpz_clear(alpha), mpz_clear(hatalpha);
					cnt++;
				}
				while (cnt <= n);
			}
		}
		Qual.clear();
		for (size_t j = 0; j < n; j++)
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				Qual.push_back(j);
		err << "P_" << i << ": Qual = { ";
		for (std::vector<size_t>::iterator it = Qual.begin(); it != Qual.end(); ++it)
			err << "P_" << *it << " ";
		err << "}" << std::endl;
		// 2. $P_i$ sets his polynomial share of the generated secret $a$
		//    as $\alpha_i = \sum_{P_j \in Qual} \alpha_{ji}$, and their
		//    associated randomness as
		//    $\hat{\alpha}_i = \sum_{P_j \in Qual} \hat{\alpha}_{ji}$.
		// Note that in this section the indicies $i$ and $j$ are exchanged
		// again, because the reverse convention is used in section 1(b).
		mpz_set_ui(alpha_i, 0L), mpz_set_ui(hatalpha_i, 0L);
		for (std::vector<size_t>::iterator it = Qual.begin(); it != Qual.end(); ++it)
		{
			mpz_add(alpha_i, alpha_i, alpha_ij[*it][i]);
			mpz_mod(alpha_i, alpha_i, q);
			mpz_add(hatalpha_i, hatalpha_i, hatalpha_ij[*it][i]);
			mpz_mod(hatalpha_i, hatalpha_i, q);
		}
		err << "P_" << i << ": alpha_i = " << alpha_i << std::endl;
		err << "P_" << i << ": hatalpha_i = " << hatalpha_i << std::endl;
		
		if (std::find(Qual.begin(), Qual.end(), i) == Qual.end())
			throw false;
		if (Qual.size() <= t)
			throw false;

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t k = 0; k <= t; k++)
		{
			mpz_clear(c_ik[k]), mpz_clear(hatc_ik[k]);
			delete [] c_ik[k], delete [] hatc_ik[k];
		}
		c_ik.clear(), hatc_ik.clear();
		// return
		return return_value;
	}
}

/* The two-party protocol "Share" is simply a Pedersen commitment to $a_i$. */
bool JareckiLysyanskayaRVSS::Share_twoparty
	(const size_t i, std::istream &in, std::ostream &out,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(n == 2); // two-party protocol
	assert(i < n);

	// initialize
	mpz_t foo, bar, lhs, rhs;
	mpz_t c_i, hatc_i;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	mpz_init(c_i), mpz_init(hatc_i);

	try
	{
		// 1. Each player $P_i$ performs a Pedersen-VSS of a random
		//    value $a_i$:
		// (a) $P_i$ picks $t$-deg. polynomials
		//     $f_{a_i}(z) = \sum_{k=0}^t c_{ik} z^k$,
		//     $f_{\hat{a_i}}(z) = \sum_{k=0}^t \hat{c}_{ik} z^k$
		tmcg_mpz_srandomm(c_i, q);
		tmcg_mpz_srandomm(hatc_i, q);
		// Let $a_i = f_{a_i}(0)$ and $\hat{a_i} = f_{\hat{a_i}}(0)$.
		mpz_set(a_i, c_i), mpz_set(hata_i, hatc_i);
		// $P_i$ broadcasts $C_{ik} = g^{c_{ik}} h^{\hat{c}_{ik}}$
		// for $k = 0..t$.
		// (in a two-party protocol this reduces simply to sending)
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, c_i, p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, hatc_i, p);
		mpz_mul(C_ik[i][0], foo, bar);
		mpz_mod(C_ik[i][0], C_ik[i][0], p);
		if (simulate_faulty_behaviour)
			mpz_add_ui(C_ik[i][0], C_ik[i][0], 1UL);
		out << C_ik[i][0] << std::endl;
		// (in a two-party protocol this reduces simply to receiving)
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				in >> C_ik[j][0];
				if (!in.good())
				{
					err << "P_" << i << ": receiving C_ik failed" << std::endl;
					throw false;
				}
				if (!CheckElement(C_ik[j][0]))
				{
					err << "P_" << i << ": bad C_ik received" << std::endl;
					throw false;
				}
			}
		}
		// Set $F_{a_i}(z) = \prod_{k=0}^t (C_{ik})^{z^k}$.
		// $P_i$ sends to $P_j$ shares $\alpha_{ij} = f_{a_i}(j)$,
		// $\hat{\alpha}_{ij} = f_{\hat{a}_i}(j)$ for each $j = 1..n$.
		// (b) Each $P_j$ verifies if
		//     $g^{\alpha_{ij}} h^{\hat{\alpha}_{ij}} = F_{a_i}(j)$
		//     for $i = 1..n$. If the check fails for any $i$, $P_j$
		//     broadcasts a complaint against $P_i$.
		// (in a two-party protocol there is no such phase)
		// (c) If $P_j$ complained against $P_i$, $P_i$ broadcasts
		//     $\alpha_{ij}$, $\hat{\alpha}_{ij}$; everyone verifies
		//     it. If $P_i$ fails this test or receives more than $t$
		//     complaints, exclude $P_i$ from $Qual$.
		// (in a two-party protocol there is no such phase)
		// 2. $P_i$ sets his polynomial share of the generated secret $a$ as
		//    $\alpha_i = \sum_{P_j \in Qual} \alpha_{ji}$, and their
		//    associated randomness as
		//    $\hat{\alpha}_i = \sum_{P_j \in Qual} \hat{\alpha}_{ji}$.
		// (in a two-party protocol there is no such phase)

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(c_i), mpz_clear(hatc_i);
		// return
		return return_value;
	}
}

bool JareckiLysyanskayaRVSS::Reconstruct
	(const size_t i, const std::vector<size_t> &complaints,
	std::vector<mpz_ptr> &a_i_in,
	CachinKursawePetzoldShoupRBC *rbc, std::ostream &err)
{
	// initialize
	mpz_t foo, bar, lhs, rhs;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	std::vector<mpz_ptr> shares;
	for (size_t j = 0; j < n; j++)
	{
		mpz_ptr tmp1 = new mpz_t();
		mpz_init(tmp1);
		shares.push_back(tmp1);
	}

	// set ID for RBC
	std::stringstream myID;
	myID << "JareckiLysyanskayaRVSS::Reconstruct()" << p << q << g << h << n << t;
	for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		myID << "[" << *it << "]";
	rbc->setID(myID.str());

	try
	{
		// run reconstruction phase of Pedersen-VSS
		if (complaints.size() > t)
		{
			err << "P_" << i << ": too many faulty parties (" << complaints.size() << " > t)" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			if (std::find(Qual.begin(), Qual.end(), *it) == Qual.end())
			{
				err << "P_" << i << ": reconstruction of z_i failed because P_" << *it << " not in Qual" << std::endl;
				throw false;
			}
			// prepare for collecting shares
			std::vector<size_t> parties;
			parties.push_back(i); // share of this player is always available
			mpz_set(shares[i], alpha_ij[*it][i]);
			// broadcast shares for reconstruction of $z_i$ (where $i = *it$ is here the index of the failed party)
			if ((std::find(complaints.begin(), complaints.end(), i) == complaints.end()) && (std::find(Qual.begin(), Qual.end(), i) != Qual.end()))
			{
				rbc->Broadcast(alpha_ij[*it][i]);
				rbc->Broadcast(hatalpha_ij[*it][i]);
			}
			// collect shares $\alpha_{ij}$ and $\hat{\alpha}_{ij}$ of other parties from Qual
			for (std::vector<size_t>::iterator jt = Qual.begin(); jt != Qual.end(); ++jt)
			{
				if ((*jt != i) && (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end()))
				{
					if (rbc->DeliverFrom(foo, *jt) && rbc->DeliverFrom(bar, *jt))
					{
						if ((mpz_cmpabs(foo, q) >= 0) || (mpz_cmpabs(bar, q) >= 0))
							err << "P_" << i << ": bad share received from " << *jt << std::endl;
						else
						{
							mpz_set(shares[*jt], foo); // save the received share for later following interpolation
							// compute LHS for the check
							tmcg_mpz_fpowm(fpowm_table_g, foo, g, foo, p);
							tmcg_mpz_fpowm(fpowm_table_h, bar, h, bar, p);
							mpz_mul(lhs, foo, bar);
							mpz_mod(lhs, lhs, p);
							// compute RHS for the check
							mpz_set_ui(rhs, 1L);
							for (size_t k = 0; k <= t; k++)
							{
								mpz_ui_pow_ui(foo, *jt + 1, k); // adjust index $j$ in computation
								mpz_powm(bar, C_ik[*it][k], foo, p);
								mpz_mul(rhs, rhs, bar);
								mpz_mod(rhs, rhs, p);
							}
							// check equation (4)
							if (mpz_cmp(lhs, rhs))
								err << "P_" << i << ": bad share received from " << *jt << std::endl;
							else
								parties.push_back(*jt);
						}
					}
					else
						err << "P_" << i << ": no share received from " << *jt << std::endl;					
				}
			}
			// check whether enough shares (i.e. $t + 1$) have been collected
			if (parties.size() <= t)
			{
				err << "P_" << i << ": not enough shares collected" << std::endl;
				throw false;
			}
			if (parties.size() > (t + 1))
				parties.resize(t + 1);
			err << "P_" << i << ": reconstructing parties = ";
			for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
				err << "P_" << *jt << " ";
			err << std::endl;
			// compute $z_i$ using Lagrange interpolation (without corrupted parties)
			mpz_set_ui(foo, 0L);
			for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
			{
				mpz_set_ui(rhs, 1L); // compute the optimized Lagrange multipliers
				for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
				{
					if (*lt != *jt)
						mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index in computation
				}
				mpz_set_ui(lhs, 1L);
				for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
				{
					if (*lt != *jt)
					{
						mpz_set_ui(bar, (*lt + 1)); // adjust index in computation
						mpz_sub_ui(bar, bar, (*jt + 1)); // adjust index in computation
						mpz_mul(lhs, lhs, bar);
					}
				}
				if (!mpz_invert(lhs, lhs, q))
				{
					err << "P_" << i << ": cannot invert LHS during reconstruction" << std::endl;
					throw false;
				}
				mpz_mul(rhs, rhs, lhs);
				mpz_mod(rhs, rhs, q);
				mpz_mul(bar, rhs, shares[*jt]); // use the provided shares (interpolation points)
				mpz_mod(bar, bar, q);
				mpz_add(foo, foo, bar);
				mpz_mod(foo, foo, q);
			}
			mpz_set(a_i_in[*it], foo);
			parties.clear();
		}

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		for (size_t j = 0; j < shares.size(); j++)
		{
			mpz_clear(shares[j]);
			delete [] shares[j];
		}
		shares.clear();
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		// return
		return return_value;
	}
}

JareckiLysyanskayaRVSS::~JareckiLysyanskayaRVSS
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	Qual.clear();
	mpz_clear(a_i), mpz_clear(hata_i);
	mpz_clear(alpha_i), mpz_clear(hatalpha_i);
	for (size_t j = 0; j < alpha_ij.size(); j++)
	{
		for (size_t i = 0; i < alpha_ij[j].size(); i++)
		{
			mpz_clear(alpha_ij[j][i]);
			delete [] alpha_ij[j][i];
		}
		alpha_ij[j].clear();
	}
	alpha_ij.clear();
	for (size_t j = 0; j < hatalpha_ij.size(); j++)
	{
		for (size_t i = 0; i < hatalpha_ij[j].size(); i++)
		{
			mpz_clear(hatalpha_ij[j][i]);
			delete [] hatalpha_ij[j][i];
		}
		hatalpha_ij[j].clear();
	}
	hatalpha_ij.clear();
	for (size_t j = 0; j < C_ik.size(); j++)
	{
		for (size_t k = 0; k <= t; k++)
		{
			mpz_clear(C_ik[j][k]);
			delete [] C_ik[j][k];
		}
		C_ik[j].clear();
	}
	C_ik.clear();

	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

JareckiLysyanskayaEDCF::JareckiLysyanskayaEDCF
	(const size_t n_in, const size_t t_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize, const unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize), n(n_in), t(t_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS),	mpz_init_set(h, h_CRS);

	// initialize RVSS
	rvss = new JareckiLysyanskayaRVSS(n, t, p, q, g, h, F_size, G_size);	

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool JareckiLysyanskayaEDCF::CheckGroup
	() const
{
	return rvss->CheckGroup();
}

bool JareckiLysyanskayaEDCF::Flip
	(const size_t i, mpz_ptr a,
	aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(i == rbc->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;	

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, hata_i;
	std::vector<size_t> complaints;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t j = 0; j < n; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_i.push_back(tmp1), hata_i.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "JareckiLysyanskayaEDCF::Flip()" << p << q << g << h << n << t;
	rbc->setID(myID.str());

	try
	{
		// 1. Players generate RVSS-data[a] (i.e. perform Joint-RVSS)
		if (!rvss->Share(i, aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		mpz_set(a_i[i], rvss->a_i), mpz_set(hata_i[i], rvss->hata_i);
		// 2. Each $P_i \in Qual$ broadcasts his additive shares $a_i$,
		//    $\hat{a}_i$.
		if (std::find(rvss->Qual.begin(), rvss->Qual.end(), i) != rvss->Qual.end())
		{
			if (simulate_faulty_behaviour)
			{
				mpz_add_ui(a_i[i], a_i[i], 1L);
			}
			rbc->Broadcast(a_i[i]);
			if (simulate_faulty_behaviour && simulate_faulty_randomizer)
			{
				mpz_add_ui(hata_i[i], hata_i[i], 1L);
			}
			rbc->Broadcast(hata_i[i]);
		}
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(rvss->Qual.begin(), rvss->Qual.end(), j) != rvss->Qual.end()))
			{
				if (!rbc->DeliverFrom(a_i[j], j))
				{
					err << "P_" << i << ": receiving a_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(a_i[j], q) >= 0)
				{
					err << "P_" << i << ": bad a_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(a_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(hata_i[j], j))
				{
					err << "P_" << i << ": receiving hata_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(hata_i[j], q) >= 0)
				{
					err << "P_" << i << ": bad hata_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(hata_i[j], 0L); // indicates an error
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(rvss->Qual.begin(), rvss->Qual.end(), j) != rvss->Qual.end()))
			{
				// compute LHS for the check
				tmcg_mpz_fspowm(fpowm_table_g, foo, g, a_i[j], p);
				tmcg_mpz_fspowm(fpowm_table_h, bar, h, hata_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				// check $g^{a_i} h^{\hat{a}_i} = F_{a_i}(0)$
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i << ": checking a_i resp. hata_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
				}
			}
		}
		// 3. For $P_i \in Qual$ s.t. $g^{a_i} h^{\hat{a}_i} \neq F_{a_i}(0)$
		//    the players reconstruct $P_i$'s additive share $a_i$
		//    by broadcasting their shares $\alpha_{ij}$, $\hat{\alpha}_{ij}$
		//    and verifying them with $F_{a_i}$.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "P_" << i << ": there are complaints against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		// run reconstruction
		if (!rvss->Reconstruct(i, complaints, a_i, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		// 4. A public random value $a$ is reconstructed
		//    as $a = \sum_{P_i \in Qual} a_i$
		mpz_set_ui(a, 0L);
		for (std::vector<size_t>::iterator it = rvss->Qual.begin(); it != rvss->Qual.end(); ++it)
		{
			mpz_add(a, a, a_i[*it]);
			mpz_mod(a, a, q);
		}
		err << "P_" << i << ": a = " << a << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t j = 0; j < n; j++)
		{
			mpz_clear(a_i[j]), mpz_clear(hata_i[j]);
			delete [] a_i[j], delete [] hata_i[j];
		}
		a_i.clear(), hata_i.clear();
		// return
		return return_value;
	}
}

bool JareckiLysyanskayaEDCF::Flip_twoparty
	(const size_t i, mpz_ptr a, std::istream &in, std::ostream &out,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(n == 2); // two-party protocol
	assert(i < n);

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, hata_i;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t j = 0; j < n; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_i.push_back(tmp1), hata_i.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % 2L;

	try
	{
		// 1. Players generate RVSS-data[a] (i.e. simply a Pedersen commitment)
		if (!rvss->Share_twoparty(i, in, out, err, simulate_faulty_behaviour))
			throw false;
		mpz_set(a_i[i], rvss->a_i), mpz_set(hata_i[i], rvss->hata_i);
		// 2. Each $P_i \in Qual$ broadcasts his additive shares $a_i$,
		//    $\hat{a}_i$.
		// (in a two-party protocol this reduces simply to sending)
		if (simulate_faulty_behaviour)
		{
			mpz_add_ui(a_i[i], a_i[i], 1L);
		}
		out << a_i[i] << std::endl;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer)
		{
			mpz_add_ui(hata_i[i], hata_i[i], 1L);
		}
		out << hata_i[i] << std::endl;
		// (in a two-party protocol this reduces simply to receiving)
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				in >> a_i[j];
				if (!in.good())
				{
					err << "P_" << i << ": receiving a_i failed" << std::endl;
					throw false;
				}
				if (mpz_cmpabs(a_i[j], q) >= 0)
				{
					err << "P_" << i << ": bad a_i received" << std::endl;
					throw false;
				}
				in >> hata_i[j];
				if (!in.good())
				{
					err << "P_" << i << ": receiving hata_i failed" << std::endl;
					throw false;
				}
				if (mpz_cmpabs(hata_i[j], q) >= 0)
				{
					err << "P_" << i << ": bad hata_i received" << std::endl;
					throw false;
				}
				// compute LHS for the check
				tmcg_mpz_fspowm(fpowm_table_g, foo, g, a_i[j], p);
				tmcg_mpz_fspowm(fpowm_table_h, bar, h, hata_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				// check $g^{a_i} h^{\hat{a}_i} = F_{a_i}(0)$
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i << ": checking a_i resp. hata_i failed" << std::endl;
					throw false;
				}
			}
		}
		// 3. For $P_i \in Qual$ s.t. $g^{a_i} h^{\hat{a}_i} \neq F_{a_i}(0)$
		//    the players reconstruct $P_i$'s additive share $a_i$
		//    by broadcasting their shares $\alpha_{ij}$, $\hat{\alpha}_{ij}$
		//    and verifying them with $F_{a_i}$.
		// (in a two-party protocol there is no reconstruction phase)
		// 4. A public random value $a$ is reconstructed
		//    as $a = \sum_{P_i \in Qual} a_i$
		mpz_set_ui(a, 0L);
		for (size_t j = 0; j < n; j++)
		{
			mpz_add(a, a, a_i[j]);
			mpz_mod(a, a, q);
		}
		err << "P_" << i << ": a = " << a << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t j = 0; j < n; j++)
		{
			mpz_clear(a_i[j]), mpz_clear(hata_i[j]);
			delete [] a_i[j], delete [] hata_i[j];
		}
		a_i.clear(), hata_i.clear();
		// return
		return return_value;
	}
}

JareckiLysyanskayaEDCF::~JareckiLysyanskayaEDCF
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);

	delete rvss;

	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

