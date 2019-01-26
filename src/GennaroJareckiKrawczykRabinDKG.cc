/*******************************************************************************
  GennaroJareckiKrawczykRabinDKG.cc,
                                       Secure |D|istributed |K|ey |G|eneration

     [GJKR07] Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin:
       'Secure Distributed Key Generation for Discrete-Log Based Cryptosystems',
     Journal of Cryptology, Vol. 20 Nr. 1, pp. 51--83, Springer 2007.

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
#include "GennaroJareckiKrawczykRabinDKG.hh"

// additional headers
#include <cassert>
#include <sstream>
#include <algorithm>
#include <map>
#include <stdexcept>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

GennaroJareckiKrawczykRabinDKG::GennaroJareckiKrawczykRabinDKG
	(const size_t n_in, const size_t t_in, const size_t i_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool canonical_g_usage,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			canonical_g(canonical_g_usage),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(n_in), t(t_in), i(i_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS),
		mpz_init_set(h, h_CRS);
	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L), mpz_init_set_ui(y, 1L);
	s_ij.resize(n);
	sprime_ij.resize(n);
	C_ik.resize(n);
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp4);
		y_i.push_back(tmp1), z_i.push_back(tmp2), v_i.push_back(tmp4);
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ij[i].push_back(tmp3);
		}
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ij[i].push_back(tmp3);
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

GennaroJareckiKrawczykRabinDKG::GennaroJareckiKrawczykRabinDKG
	(std::istream &in,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool canonical_g_usage,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			canonical_g(canonical_g_usage),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(0), t(0), i(0)
{
	std::string value;

	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	std::getline(in, value);
	std::stringstream(value) >> n;
	if (n > TMCG_MAX_DKG_PLAYERS)
		throw std::invalid_argument("GennaroJareckiKrawczykRabinDKG: n > TMCG_MAX_DKG_PLAYERS");
	std::getline(in, value);
	std::stringstream(value) >> t;
	if (t > n)
		throw std::invalid_argument("GennaroJareckiKrawczykRabinDKG: t > n");
	std::getline(in, value);
	std::stringstream(value) >> i;
	if (i >= n)
		throw std::invalid_argument("GennaroJareckiKrawczykRabinDKG: i >= n");
	mpz_init(x_i), mpz_init(xprime_i), mpz_init(y);
	in >> x_i >> xprime_i >> y;
	size_t qual_size = 0;
	std::getline(in, value);
	std::stringstream(value) >> qual_size;
	if (qual_size > n)
		throw std::invalid_argument("GennaroJareckiKrawczykRabinDKG: |QUAL| > n");
	for (size_t i = 0; (i < qual_size) && (i < n); i++)
	{
		size_t who;
		std::getline(in, value);
		std::stringstream(value) >> who;
		if (who >= n)
			throw std::invalid_argument("GennaroJareckiKrawczykRabinDKG: who >= n");
		QUAL.push_back(who);
	}
	s_ij.resize(n);
	sprime_ij.resize(n);
	C_ik.resize(n);
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp4);
		y_i.push_back(tmp1), z_i.push_back(tmp2), v_i.push_back(tmp4);
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ij[i].push_back(tmp3);
		}
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ij[i].push_back(tmp3);
		}
		for (size_t k = 0; k <= t; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			C_ik[i].push_back(tmp3);
		}
	}
	for (size_t i = 0; i < n; i++)
		in >> y_i[i];
	for (size_t i = 0; i < n; i++)
		in >> z_i[i];
	for (size_t i = 0; i < n; i++)
		in >> v_i[i];
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			in >> s_ij[i][j];
			in >> sprime_ij[i][j];
		}
		for (size_t k = 0; k <= t; k++)
			in >> C_ik[i][k];
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void GennaroJareckiKrawczykRabinDKG::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl
		<< h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl;
	out << x_i << std::endl << xprime_i << std::endl << y << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
	for (size_t i = 0; i < n; i++)
		out << y_i[i] << std::endl;
	for (size_t i = 0; i < n; i++)
		out << z_i[i] << std::endl;
	for (size_t i = 0; i < n; i++)
		out << v_i[i] << std::endl;
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			out << s_ij[i][j] << std::endl;
			out << sprime_ij[i][j] << std::endl;
		}
		for (size_t k = 0; k <= t; k++)
			out << C_ik[i][k] << std::endl;
	}
}

void GennaroJareckiKrawczykRabinDKG::PublishVerificationKeys
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl
		<< h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl;
	out << "0" << std::endl << "0" << std::endl << y << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
	for (size_t i = 0; i < n; i++)
		out << "1" << std::endl;
	for (size_t i = 0; i < n; i++)
		out << "0" << std::endl;
	for (size_t i = 0; i < n; i++)
		out << v_i[i] << std::endl;
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			out << "0" << std::endl;
			out << "0" << std::endl;
		}
		for (size_t k = 0; k <= t; k++)
			out << C_ik[i][k] << std::endl;
	}
}

bool GennaroJareckiKrawczykRabinDKG::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k), mpz_init(g2);
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

		if (canonical_g)
		{
			// We use a procedure similar to FIPS 186-3 A.2.3;
			// it is supposed as verifiable generation of $g$.
			std::stringstream U;
			U << "LibTMCG|" << p << "|" << q << "|ggen|";
			mpz_sub_ui(bar, p, 1L); // compute $p-1$
			do
			{
				tmcg_mpz_shash(foo, U.str());
				mpz_powm(g2, foo, k, p);
				U << g2 << "|";
				mpz_powm(foo, g2, q, p);
				// check $1 < g < p-1$ and $g^q \equiv 1 \pmod{p}$
			}
			while (!mpz_cmp_ui(g2, 0L) || !mpz_cmp_ui(g2, 1L) || 
				!mpz_cmp(g2, bar) || mpz_cmp_ui(foo, 1L));
			// Check that the 1st verifiable $g$ is used.
			if (mpz_cmp(g, g2))
				throw false;
		}

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(k), mpz_clear(g2);
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinDKG::CheckElement
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

bool GennaroJareckiKrawczykRabinDKG::Generate
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour,
	mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	mpz_srcptr ssrandomm_cache_mod,
	size_t *ssrandomm_cache_avail)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);
	err << "GennaroJareckiKrawczykRabinDKG::Generate()" << std::endl;

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, b_i, g__a_i;
	std::vector< std::vector<mpz_ptr> > A_ik, g__s_ij, a_ik;
	std::vector<size_t> complaints, complaints_counter, complaints_from;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t k = 0; k <= t; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3);
		a_i.push_back(tmp1), b_i.push_back(tmp2), g__a_i.push_back(tmp3);
	}
	A_ik.resize(n);
	g__s_ij.resize(n);
	a_ik.resize(n);
	for (size_t i2 = 0; i2 < n; i2++)
	{
		for (size_t k = 0; k <= t; k++)
		{
			mpz_ptr tmp1 = new mpz_t();
			mpz_init(tmp1);
			A_ik[i2].push_back(tmp1);
		}
		for (size_t j = 0; j < n; j++)
		{
			mpz_ptr tmp2 = new mpz_t();
			mpz_init(tmp2);
			g__s_ij[i2].push_back(tmp2);
		}
		for (size_t k = 0; k <= t; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			a_ik[i2].push_back(tmp3);
		}
	}
	size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "GennaroJareckiKrawczykRabinDKG::Generate()" <<
		p << q << g << h << n << t << label;
	rbc->setID(myID.str());

	try
	{
		// 1. Each party $P_i$ performs a Pedersen-VSS of a random
		//    value $z_i$ as a dealer:
		// (a) $P_i$ chooses two random polynomials $f_i(z)$ and
		//     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t$ where
		//     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t$ and
		//     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t$
		for (size_t k = 0; k <= t; k++)
		{
			if (use_very_strong_randomness)
			{
				if ((ssrandomm_cache != NULL) && (ssrandomm_cache_mod != NULL) &&
					(ssrandomm_cache_avail != NULL))
				{
					err << "P_" << i << ": using very strong randomness from cache" << std::endl;
					tmcg_mpz_ssrandomm_cache(ssrandomm_cache, ssrandomm_cache_mod, *ssrandomm_cache_avail, a_i[k], q);
					tmcg_mpz_ssrandomm_cache(ssrandomm_cache, ssrandomm_cache_mod, *ssrandomm_cache_avail, b_i[k], q);
				}
				else
				{
					tmcg_mpz_ssrandomm(a_i[k], q);
					tmcg_mpz_ssrandomm(b_i[k], q);
				}
			}
			else
			{
				tmcg_mpz_srandomm(a_i[k], q);
				tmcg_mpz_srandomm(b_i[k], q);
			}
		}
		// Let $z_i = a_{i0} = f_i(0)$.
		mpz_set(z_i[i], a_i[0]);
		err << "P_" << i << ": z_i = " << z_i[i] << std::endl;
		// $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
		// for $k = 0, \ldots, t$.
		for (size_t k = 0; k <= t; k++)
		{
			tmcg_mpz_fspowm(fpowm_table_g, g__a_i[k], g, a_i[k], p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, b_i[k], p);
			mpz_mul(C_ik[i][k], g__a_i[k], bar);
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
		// $P_i$ computes the shares $s_{ij} = f_i(j) \bmod q$,
		// $s\prime_{ij} = f\prime_i(j) \bmod q$ and
		// sends $s_{ij}$, $s\prime_{ij}$ to party $P_j$.
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ij[i][j], 0L);
			mpz_set_ui(sprime_ij[i][j], 0L);
			for (size_t k = 0; k <= t; k++)
			{
				mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
				mpz_mul(bar, foo, b_i[k]);
				mpz_mod(bar, bar, q);
				mpz_mul(foo, foo, a_i[k]);
				mpz_mod(foo, foo, q);
				mpz_add(s_ij[i][j], s_ij[i][j], foo);
				mpz_mod(s_ij[i][j], s_ij[i][j], q);				
				mpz_add(sprime_ij[i][j], sprime_ij[i][j], bar);
				mpz_mod(sprime_ij[i][j], sprime_ij[i][j], q);
			}
			if (j != i)
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer)
				{
					mpz_add_ui(s_ij[i][j], s_ij[i][j], 1L);
				}
				if (!aiou->Send(s_ij[i][j], j, aiou->aio_timeout_very_short))
				{
					err << "P_" << i << ": sending s_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(sprime_ij[i][j], j, aiou->aio_timeout_very_short))
				{
					err << "P_" << i << ": sending sprime_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
			}
		}
		// (b) Each party $P_j$ verifies the shares he received from
		//     the other parties. For each $i = 1, \ldots, n$, $P_j$
		//     checks if $g^{s_{ij}} h^{s\prime_{ij}} = \prod_{k=0}^t (C_{ik})^{j^k} \bmod p$.
		// In opposite to the notation used in the paper the indicies $i$ and $j$ are
		// exchanged in this section for convenience.
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				if (!aiou->Receive(s_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving s_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(s_ij[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad s_ij received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(s_ij[j][i], 0L); // indicates an error
				}
				if (!aiou->Receive(sprime_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving sprime_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(sprime_ij[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad sprime_ij received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(sprime_ij[j][i], 0L); // indicates an error
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			// compute LHS for the check
			tmcg_mpz_fspowm(fpowm_table_g, g__s_ij[j][i], g, s_ij[j][i], p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, sprime_ij[j][i], p);
			mpz_mul(lhs, g__s_ij[j][i], bar);
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
		// If the check fails for an index $i$,
		// $P_j$ broadcasts a complaint against $P_i$.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "P_" << i << ": broadcast complaint against P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
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
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		// (c) Each party $P_i$ who, as a dealer, received a complaint
		//     from party $P_j$ broadcasts the values $s_{ij}$,
		//     $s\prime_{ij}$ that satisfy (4).
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
				rbc->Broadcast(s_ij[i][*it]);
				rbc->Broadcast(sprime_ij[i][*it]);
			}
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		// (d) Each party marks disqualified any party either
		//      * received more than $t$ complaints in Step 1(b), or
		//      * answered a complaint in Step 1(c) with values that 
		//        falsify (4).
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
					mpz_t s, sprime;
					mpz_init_set(s, foo), mpz_init_set(sprime, bar);
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
						err << "P_" << i << ": checking 1(d) failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious
						if (who == i)
						{
							err << "P_" << i << ": shares adjusted 1(d) from P_" << j << std::endl;
							mpz_set(s_ij[j][i], s);
							mpz_set(sprime_ij[j][i], sprime);
						}

					}
					mpz_clear(s), mpz_clear(sprime);
					cnt++;
				}
				while (cnt <= n);
			}
		}
		// 2. Each party the builds the set of non-disqualified parties $QUAL$.
		QUAL.clear();
		for (size_t j = 0; j < n; j++)
		{
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		}
		err << "P_" << i << ": QUAL = { ";
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			err << "P_" << *it << " ";
		err << "}" << std::endl;
		// 3. Each party $P_i$ sets his share of the secret as
		//    $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the value
		//    $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
		// Note that in this section the indicies $i$ and $j$ are exchanged
		// again, because the reversed convention is used in section 1(b).
		mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_add(x_i, x_i, s_ij[*it][i]);
			mpz_mod(x_i, x_i, q);
			mpz_add(xprime_i, xprime_i, sprime_ij[*it][i]);
			mpz_mod(xprime_i, xprime_i, q);
		}
		err << "P_" << i << ": x_i = " << x_i << std::endl;
		err << "P_" << i << ": xprime_i = " << xprime_i << std::endl;
		
		if (std::find(QUAL.begin(), QUAL.end(), i) == QUAL.end())
			throw false;
		if (QUAL.size() <= t)
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer)
			throw false;

		// 4. Each party $i \in QUAL$ exposes $y_i = g^{z_i} \bmod p$
		//    via Feldman-VSS:
		// (a) Each party $P_i$, $i \in QUAL$, broadcasts $A_{ik} = 
		//     g^{a_{ik}} \bmod p$ for $k = 0, \ldots, t$.
		for (size_t k = 0; k <= t; k++)
		{
			// OPTIMIZED: mpz_fspowm(fpowm_table_g, A_ik[i][k], g, a_i[k], p);
			mpz_set(A_ik[i][k], g__a_i[k]);
			if (simulate_faulty_behaviour)
				mpz_add_ui(A_ik[i][k], A_ik[i][k], 1L);
			rbc->Broadcast(A_ik[i][k]);
		}
		// (b) Each party $P_j$ verifies the values broadcast by the
		//     other parties in $QUAL$, namely for each $i \in QUAL$,
		//     $P_j$ checks if $g^{s_{ij}} = \prod_{k=0}^t (A_{ik})^{j^k} \bmod p$.
		// Note that in this section the indicies $i$ and $j$ are exchanged for convenience.
		complaints.clear();
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) &&
				(std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				for (size_t k = 0; k <= t; k++)
				{
					if (!rbc->DeliverFrom(A_ik[j][k], j))
					{
						err << "P_" << i << ": receiving A_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!CheckElement(A_ik[j][k]))
					{
						err << "P_" << i << ": bad A_ik received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(A_ik[j][k], 0L); // indicates an error
					}
				}
				// compute LHS for the check
				// OPTIMIZED: mpz_fspowm(fpowm_table_g, lhs, g, s_ij[j][i], p);
				mpz_set(lhs, g__s_ij[j][i]);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				for (size_t k = 0; k <= t; k++)
				{
					mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
					mpz_powm(bar, A_ik[j][k], foo, p);
					mpz_mul(rhs, rhs, bar);
					mpz_mod(rhs, rhs, p);
				}
				// check equation (5)
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i << ": checking 4(b) failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
				}
			}
		}
		// If the check fails for an index $i$, $P_j$ complains against
		// $P_i$ by broadcasting the values $s_{ij}$, $s\prime_{ij}$
		// that satisfy (4) but do not satisfy (5).
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
			rbc->Broadcast(s_ij[i][*it]);
			rbc->Broadcast(sprime_ij[i][*it]);
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		// (c) For parties $P_i$ who receive at least one valid complaint,
		//     i.e., values which satisfy (4) and not (5), the other
		//     parties run the reconstruction phase of Pedersen-VSS to
		//     compute $z_i$, $f_i(z)$, $A_{ik}$ for $k = 0, \ldots, t$
		//     in the clear.
		// Note that in this section the indicies $i$ and $j$ are exchanged for convenience.
		complaints.clear();
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j)	!= QUAL.end()))
			{
				size_t who;
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(rhs, j))
					{
						err << "P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(rhs);
					if (who < n)
					{
						err << "P_" << i << ": receiving complaint against P_" << who << " from P_" << j << std::endl;
					}
					else
						break; // end marker received 
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "P_" << i << ": receiving s_ij failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(foo, q) >= 0)
					{
						err << "P_" << i << ": bad s_ij received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(foo, 0L); // indicates an error
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "P_" << i << ": receiving sprime_ij failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(bar, q) >= 0)
					{
						err << "P_" << i << ": bad sprime_ij received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(bar, 0L); // indicates an error
					}
					// verify complaint, i.e. (4) holds (5) not.
					// compute LHS for the check
					tmcg_mpz_fpowm(fpowm_table_g, lhs, g, foo, p);
					tmcg_mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, lhs, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $i$ in computation
						mpz_powm(bar, C_ik[j][k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (4)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking 4(c)(4) failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					// compute LHS for the check
					tmcg_mpz_fpowm(fpowm_table_g, lhs, g, foo, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
						mpz_powm(bar, A_ik[j][k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (5)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking 4(c)(5) failed; complaint against P_" << who;
						if (std::find(QUAL.begin(), QUAL.end(), who) != QUAL.end())
							complaints.push_back(who);
						else
							err << " (ignoring; not in QUAL)";
						err << std::endl;
					}
					else
					{
						err << "P_" << i << ": checking 4(c)(5) not failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // no end marker received
			}
		}
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "P_" << i << ": there are extracting complaints against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		// run reconstruction phase of Pedersen-VSS
		if (!Reconstruct(complaints, z_i, a_ik, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			// compute $A_{ik} = g^{a_{ik}} \bmod p$
			for (size_t k = 0; k <= t; k++)
			{
				err << "P_" << i << ": a_" << *it << "," << k << " = " << a_ik[*it][k] << std::endl;
				tmcg_mpz_fpowm(fpowm_table_g, A_ik[*it][k], g, a_ik[*it][k], p);
			}
		}
		// For all parties in $QUAL$, set $y_i = A_{i0} = g^{z_i} \bmod p$.
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			mpz_set(y_i[*it], A_ik[*it][0]);
		err << "P_" << i << ": y_i = " << y_i[i] << std::endl;
		// Compute $y = \prod_{i \in QUAL} y_i \bmod p$.
		mpz_set_ui(y, 1L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_mul(y, y, y_i[*it]);
			mpz_mod(y, y, p);
		}
		err << "P_" << i << ": y = " << y << std::endl;
		// Compute public verification keys $v_j = \prod_{i \in QUAL} \prod_{k=0}^t (A_{ik})^{j^k} \bmod p$
		for (std::vector<size_t>::iterator jt = QUAL.begin(); jt != QUAL.end(); ++jt)
		{
			mpz_set_ui(v_i[*jt], 1L);
			for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			{
				for (size_t k = 0; k <= t; k++)
				{
					mpz_ui_pow_ui(foo, *jt + 1, k); // adjust index $j$ in computation
					mpz_powm(bar, A_ik[*it][k], foo, p);
					mpz_mul(v_i[*jt], v_i[*jt], bar);
					mpz_mod(v_i[*jt], v_i[*jt], p);
				}
			}
			err << "P_" << i << ": v_" << *jt << " = " << v_i[*jt] << std::endl;
		}
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
			mpz_clear(a_i[k]), mpz_clear(b_i[k]);
			delete [] a_i[k], delete [] b_i[k];
			mpz_clear(g__a_i[k]);
			delete [] g__a_i[k];
		}
		a_i.clear(), b_i.clear(), g__a_i.clear();
		for (size_t j = 0; j < n; j++)
		{
			for (size_t k = 0; k <= t; k++)
			{
				mpz_clear(A_ik[j][k]), mpz_clear(a_ik[j][k]);
				delete [] A_ik[j][k], delete [] a_ik[j][k];
			}
			for (size_t i2 = 0; i2 < n; i2++)
			{
				mpz_clear(g__s_ij[j][i2]);
				delete [] g__s_ij[j][i2];
			}
			A_ik[j].clear(), a_ik[j].clear();
			g__s_ij[j].clear();
		}
		A_ik.clear(), a_ik.clear();
		g__s_ij.clear();
		// return
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinDKG::CheckKey
	(const size_t i_in) const
{
	// initialize
	mpz_t foo;
	mpz_init(foo);

	try
	{
		if (i_in >= n)
			throw false;
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, z_i[i_in], p);
		if (mpz_cmp(y_i[i_in], foo))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo);
		// return
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinDKG::CheckKey
	() const
{
	// initialize
	mpz_t foo;
	mpz_init(foo);

	try
	{
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, x_i, p);
		if (mpz_cmp(v_i[i], foo))
			throw false;

		throw CheckKey(i);
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo);
		// return
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinDKG::Reconstruct
	(const std::vector<size_t> &complaints,
	std::vector<mpz_ptr> &z_i_in,
	std::vector< std::vector<mpz_ptr> > &a_ik_in,
	CachinKursawePetzoldShoupRBC *rbc, std::ostream &err)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(i == rbc->j);
	err << "GennaroJareckiKrawczykRabinDKG::Reconstruct()" << std::endl;

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
	myID << "GennaroJareckiKrawczykRabinDKG::Reconstruct()" << p << q << g << h << n << t;
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
			if (std::find(QUAL.begin(), QUAL.end(), *it) == QUAL.end())
			{
				err << "P_" << i << ": reconstruction of z_i failed because P_" << *it << " not in QUAL" << std::endl;
				throw false;
			}
			// prepare for collecting some shares
			std::vector<size_t> parties;
			parties.push_back(i); // share of this player is always available and correct
			mpz_set(shares[i], s_ij[*it][i]);
			// broadcast shares for reconstruction of $z_i$ (where $i = *it$ is here the index of the failed party)
			if ((std::find(complaints.begin(), complaints.end(), i) == complaints.end()) && (std::find(QUAL.begin(), QUAL.end(), i) != QUAL.end()))
			{
				rbc->Broadcast(s_ij[*it][i]);
				rbc->Broadcast(sprime_ij[*it][i]);
			}			
			// now collect shares $s_{ij}$ and $s\prime_{ij}$ of other parties from QUAL
			for (std::vector<size_t>::iterator jt = QUAL.begin(); jt != QUAL.end(); ++jt)
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
								mpz_ui_pow_ui(foo, *jt + 1, k);
								mpz_powm(bar, C_ik[*it][k], foo, p);
								mpz_mul(rhs, rhs, bar);
								mpz_mod(rhs, rhs, p);
							}
							// check equation (4)
							if (mpz_cmp(lhs, rhs))
								err << "P_" << i << ": bad share received from " << *jt << std::endl;
							else
								parties.push_back(*jt); // good share received
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
				mpz_set_ui(rhs, 1L); // compute optimized Lagrange coefficients
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
			mpz_set(z_i_in[*it], foo);
			err << "P_" << i << ": reconstructed z_" << *it << " = " << z_i_in[*it] << std::endl;
			// compute $f_i(z)$ using general interpolation
			std::vector<mpz_ptr> points, shares_f, f;
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
				mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3);
				points.push_back(tmp1), shares_f.push_back(tmp2), f.push_back(tmp3);
			}
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_set_ui(points[k], parties[k] + 1); // adjust index in computation
				mpz_set(shares_f[k], shares[parties[k]]);
			}
			if (!tmcg_interpolate_polynom(points, shares_f, q, f))
				throw false;
			err << "P_" << i << ": reconstructed f_0 = " << f[0] << std::endl;
			for (size_t k = 0; k < parties.size(); k++)
				mpz_set(a_ik_in[*it][k], f[k]);
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_clear(points[k]), mpz_clear(shares_f[k]), mpz_clear(f[k]);
				delete [] points[k], delete [] shares_f[k], delete [] f[k];
			}
			points.clear(), shares_f.clear(), f.clear();
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

GennaroJareckiKrawczykRabinDKG::~GennaroJareckiKrawczykRabinDKG
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i), mpz_clear(y);
	for (size_t i = 0; i < y_i.size(); i++)
	{
		mpz_clear(y_i[i]);
		delete [] y_i[i];
	}
	y_i.clear();
	for (size_t i = 0; i < z_i.size(); i++)
	{
		mpz_clear(z_i[i]);
		delete [] z_i[i];
	}
	z_i.clear();
	for (size_t i = 0; i < v_i.size(); i++)
	{
		mpz_clear(v_i[i]);
		delete [] v_i[i];
	}
	v_i.clear();
	for (size_t i = 0; i < s_ij.size(); i++)
	{
		for (size_t j = 0; j < s_ij[i].size(); j++)
		{
			mpz_clear(s_ij[i][j]);
			delete [] s_ij[i][j];
		}
		s_ij[i].clear();
	}
	s_ij.clear();
	for (size_t i = 0; i < sprime_ij.size(); i++)
	{
		for (size_t j = 0; j < sprime_ij[i].size(); j++)
		{
			mpz_clear(sprime_ij[i][j]);
			delete [] sprime_ij[i][j];
		}
		sprime_ij[i].clear();
	}
	sprime_ij.clear();
	for (size_t i = 0; i < C_ik.size(); i++)
	{
		for (size_t k = 0; k < C_ik[i].size(); k++)
		{
			mpz_clear(C_ik[i][k]);
			delete [] C_ik[i][k];
		}
		C_ik[i].clear();
	}
	C_ik.clear();
	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ============================================================================

GennaroJareckiKrawczykRabinNTS::GennaroJareckiKrawczykRabinNTS
	(const size_t n_in, const size_t t_in, const size_t i_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize, const unsigned long int subgroupsize,
	const bool canonical_g_usage,
	const bool use_very_strong_randomness_in):
			F_size(fieldsize), G_size(subgroupsize),
			canonical_g(canonical_g_usage),
			use_very_strong_randomness(use_very_strong_randomness_in),
			n(n_in), t(t_in), i(i_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS),
		mpz_init_set(h, h_CRS);
	mpz_init_set_ui(z_i, 0L), mpz_init_set_ui(y, 0L);
	for (size_t i2 = 0; i2 < n; i2++)
	{
		mpz_ptr tmp1 = new mpz_t();
		mpz_init_set_ui(tmp1, 0L);
		y_i.push_back(tmp1);
	}
	
	// initialize required subprotocols
	dkg = new GennaroJareckiKrawczykRabinDKG(n, t, i, p, q, g, h, fieldsize,
		subgroupsize, canonical_g_usage, use_very_strong_randomness_in, "dkg");

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool GennaroJareckiKrawczykRabinNTS::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k) , mpz_init(g2);
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

		if (canonical_g)
		{
			// We use a procedure similar to FIPS 186-3 A.2.3;
			// it is supposed as verifiable generation of $g$.
			std::stringstream U;
			U << "LibTMCG|" << p << "|" << q << "|ggen|";
			mpz_sub_ui(bar, p, 1L); // compute $p-1$
			do
			{
				tmcg_mpz_shash(foo, U.str());
				mpz_powm(g2, foo, k, p);
				U << g2 << "|";
				mpz_powm(foo, g2, q, p);
				// check $1 < g < p-1$ and $g^q \equiv 1 \pmod{p}$
			}
			while (!mpz_cmp_ui(g2, 0L) || !mpz_cmp_ui(g2, 1L) || 
				!mpz_cmp(g2, bar) || mpz_cmp_ui(foo, 1L));
			// Check that the 1st verifiable $g$ is used.
			if (mpz_cmp(g, g2))
				throw false;
		}

		// check whether the group for DKG is sound
		if (!dkg->CheckGroup())
			throw false;

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(k), mpz_clear(g2);
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinNTS::Generate
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour,
	mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	mpz_srcptr ssrandomm_cache_mod,
	size_t *ssrandomm_cache_avail)
{
	assert(n >= t);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);
	err << "GennaroJareckiKrawczykRabinNTS::Generate()" << std::endl;

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// set ID for RBC
	std::stringstream myID;
	myID << "GennaroJareckiKrawczykRabinNTS::Generate()" <<
		p << q << g << h << n << t;
	rbc->setID(myID.str());

	try
	{
		// call of the protocol New-DKG for generating an additive
		// share $z_i$ of a common secret $x$ and the public parameters
		// $y = g^x$ and $y_i = g^{z_i}$ for every $P_i$
		if (!dkg->Generate(aiou, rbc, err, simulate_faulty_behaviour,
			ssrandomm_cache, ssrandomm_cache_mod, ssrandomm_cache_avail))
		{
			throw false;
		}
		// set the public variables of the class by results of New-DKG
		mpz_set(z_i, dkg->z_i[i]);
		for (size_t j = 0; j < y_i.size(); j++)
			mpz_set(y_i[j], dkg->y_i[j]);
		mpz_set(y, dkg->y);
		for (size_t j = 0; j < dkg->QUAL.size(); j++)
			QUAL.push_back(dkg->QUAL[j]);

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// return
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinNTS::Sign
	(mpz_srcptr m, mpz_ptr c, mpz_ptr s, 
	aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(n >= t);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);
	err << "GennaroJareckiKrawczykRabinNTS::Sign()" << std::endl;

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	mpz_t r;
	std::vector<size_t> QUALprime;
	std::vector<mpz_ptr> s_i, r_i, u_i;
	std::vector< std::vector<mpz_ptr> > a_ik;
	std::vector<size_t> complaints;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	mpz_init(r);
	a_ik.resize(n);
	for (size_t i2 = 0; i2 < n; i2++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3);
		s_i.push_back(tmp1), r_i.push_back(tmp2), u_i.push_back(tmp3);
		for (size_t k = 0; k <= t; k++)
		{
			mpz_ptr tmp4 = new mpz_t();
			mpz_init(tmp4);
			a_ik[i2].push_back(tmp4);
		}
	}
	size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % 2L;
	size_t simulate_faulty_randomizer2 = tmcg_mpz_wrandom_ui() % 2L;

	// initialize required subprotocol
	GennaroJareckiKrawczykRabinDKG *k_dkg = new GennaroJareckiKrawczykRabinDKG(n, t, i, p, q, g, h,
		F_size, G_size, canonical_g, use_very_strong_randomness, "k_dkg");

	// set ID for RBC
	std::stringstream myID;
	myID << "GennaroJareckiKrawczykRabinNTS::Sign()" <<
		p << q << g << h << n << t << m;
	rbc->setID(myID.str());

	try
	{
		// check whether the key share generation was successful
		if (QUAL.size() == 0)
			throw false;
		// 1. Parties perform an instance of New-DKG protocol. Denote
		//    the outputs of this run of New-DKG as follows. Each party
		//    $P_i \in QUAL\prime$ holds an additive share $u_i$ of the
		//    secret-shared secret $k$. Each of these additive shares
		//    is itself secret-shared with Feldman-VSS. We denote the
		//    generated public values $r = g^k$ and $r_i = g^{u_i}$
		//    for each $P_i$.
		if (!k_dkg->Generate(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		mpz_set(u_i[i], k_dkg->z_i[i]);
		for (size_t j = 0; j < n; j++)
			mpz_set(r_i[j], k_dkg->y_i[j]);
		mpz_set(r, k_dkg->y);
		for (size_t j = 0; j < k_dkg->QUAL.size(); j++)
			QUALprime.push_back(k_dkg->QUAL[j]);
		// 2. Each party locally computes the challenge $c = H(m, r)$.
		tmcg_mpz_shash(c, 2, m, r);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer)
			mpz_add_ui(c, c, 1L);
		// 3. Parties perform the reconstruction phase of Feldman's
		//    secret-sharing of value $s = k + cx$ as follows.
		//    Each party $P_i \in QUAL \cap QUAL\prime$ broadcasts
		//    its additive share $s_i = u_i + cz_i$.
		if ((std::find(QUAL.begin(), QUAL.end(), i) != QUAL.end()) &&
			(std::find(QUALprime.begin(), QUALprime.end(), i) != QUALprime.end()))
		{
			err << "P_" << i << ": z_i = " << z_i << std::endl;
			err << "P_" << i << ": u_i = " << u_i[i] << std::endl;
			mpz_mul(s_i[i], c, z_i);
			mpz_mod(s_i[i], s_i[i], q);
			mpz_add(s_i[i], s_i[i], u_i[i]);
			mpz_mod(s_i[i], s_i[i], q);
			if (simulate_faulty_behaviour && simulate_faulty_randomizer2)
				mpz_add_ui(s_i[i], s_i[i], 1L);
			rbc->Broadcast(s_i[i]);
		}
		// Each share is verified by checking if $g^{s_i} = r_i {y_i}^c$.
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()) &&
				(std::find(QUALprime.begin(), QUALprime.end(), j) != QUALprime.end()))
			{
				if (!rbc->DeliverFrom(s_i[j], j))
				{
					err << "P_" << i << ": receiving s_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(s_i[j], q) >= 0)
				{
					err << "P_" << i << ": bad s_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				// compute LHS for the check
				tmcg_mpz_fpowm(fpowm_table_g, lhs, g, s_i[j], p);
				// compute RHS for the check
				mpz_powm(rhs, y_i[j], c, p);
				mpz_mul(rhs, rhs, r_i[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i << ": checking s_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
				}
			}
		}
		// Otherwise $x_i$ [H.Stamer: guess this is a typo and means $u_i$] and $z_i$ are
		// reconstructed and $s_i$ is computed publicly.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "P_" << i << ": there are reconstruction complaints against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		// run reconstruction phases
		if (!k_dkg->Reconstruct(complaints, u_i, a_ik, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		if (!dkg->Reconstruct(complaints, dkg->z_i, a_ik, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			// compute $s_i = u_i + cz_i$
			mpz_mul(s_i[*it], c, dkg->z_i[*it]);
			mpz_mod(s_i[*it], s_i[*it], q);
			mpz_add(s_i[*it], s_i[*it], u_i[*it]);
			mpz_mod(s_i[*it], s_i[*it], q);
		}
		// Values $z_i$ for each party in $QUAL\setminus QUAL\prime$
		// are publicly resonstructed and for those parties $s_i$ is
		// set to $cz_i$.
		complaints.clear();
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			if (std::find(QUALprime.begin(), QUALprime.end(), *it) == QUALprime.end())
				complaints.push_back(*it);
		err << "P_" << i << ": there are further reconstruction complaints against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!dkg->Reconstruct(complaints, dkg->z_i, a_ik, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			// compute $s_i = cz_i$
			mpz_mul(s_i[*it], c, dkg->z_i[*it]);
			mpz_mod(s_i[*it], s_i[*it], q);
		}
		// The protocol outputs signature $(c, s)$ where
		// $s = \sum_{i\in QUAL} s_i$.
		mpz_set_ui(s, 0L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_add(s, s, s_i[*it]);
			mpz_mod(s, s, q);
		}
		err << "P_" << i << ": signature (c, s) = (" << c << ", " << s << ")" << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(r);
		for (size_t i = 0; i < n; i++)
		{
			mpz_clear(s_i[i]), mpz_clear(r_i[i]), mpz_clear(u_i[i]);
			delete [] s_i[i], delete [] r_i[i], delete [] u_i[i];
			for (size_t k = 0; k <= t; k++)
			{
				mpz_clear(a_ik[i][k]);
				delete [] a_ik[i][k];
			}
			a_ik[i].clear();
		}
		s_i.clear(), r_i.clear(), u_i.clear();
		a_ik.clear();
		// release subprotocol
		delete k_dkg;
		// return
		return return_value;
	}
}

bool GennaroJareckiKrawczykRabinNTS::Verify
	(mpz_srcptr m, mpz_srcptr c, mpz_srcptr s)
{
	// initialize
	mpz_t foo, bar, r;
	mpz_init(foo), mpz_init(bar), mpz_init(r);

	try
	{
		// 1. Compute $r = g^s y^{-c} \bmod p$
		tmcg_mpz_fpowm(fpowm_table_g, r, g, s, p);
		mpz_powm(foo, y, c, p);
		if (!mpz_invert(bar, foo, p))
			throw false;		
		mpz_mul(r, r, bar);
		mpz_mod(r, r, p);
		// 2. Checking if $c = H(m, r)$.
		tmcg_mpz_shash(foo, 2, m, r);
		if (mpz_cmp(c, foo))
			throw false;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(r);
		// return
		return return_value;
	}
}

GennaroJareckiKrawczykRabinNTS::~GennaroJareckiKrawczykRabinNTS
	()
{
	// release subprotocol
	delete dkg;
	// release
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(z_i), mpz_clear(y);
	for (size_t j = 0; j < y_i.size(); j++)
	{
		mpz_clear(y_i[j]);
		delete [] y_i[j];
	}
	y_i.clear();

	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

