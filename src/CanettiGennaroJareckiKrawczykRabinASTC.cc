/*******************************************************************************
  CanettiGennaroJareckiKrawczykRabinASTC.cc,
                         |A|daptive |S|ecurity for |T|hreshold |C|ryptosystems

     [CGJKR99] Ran Canetti, Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk,
               and Tal Rabin: 'Adaptive Security for Threshold Cryptosystems',
     Advances in Cryptology - CRYPTO'99, LNCS 1666, pp. 98--116, 1999.

     [CD98] Ronald Cramer and Ivan Damgard: 'Zero-knowledge proofs for finite
       field arithmetic, or: Can zero-knowledge be for free?',
     Advances in Cryptology - CRYPTO'98, LNCS 1462, pp. 424--441, 1998.

     [BCCG15] Jonathan Bootle, Andrea Cerulli, Pyrros Chaidos, and Jens Groth:
       'Efficient Zero-Knowledge Proof Systems',
     Foundations of Security Analysis and Design VIII: FOSAD 2014/2015/2016
       Tutorial Lectures, LNCS 9808, pp. 1--31, 2016.

   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "CanettiGennaroJareckiKrawczykRabinASTC.hh"

CanettiGennaroJareckiKrawczykRabinRVSS::CanettiGennaroJareckiKrawczykRabinRVSS
	(const size_t n_in, const size_t t_in, const size_t i_in, const size_t tprime_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(n_in), t(t_in), i(i_in), tprime(tprime_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS), mpz_init_set(h, h_CRS);
	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L);
	mpz_init_set_ui(z_i, 0L), mpz_init_set_ui(zprime_i, 0L);
	s_ji.resize(n);
	sprime_ji.resize(n);
	C_ik.resize(n);
	for (size_t j = 0; j < n_in; j++)
	{
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ji[j].push_back(tmp3);
		}
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ji[j].push_back(tmp3);
		}
		for (size_t k = 0; k <= tprime_in; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			C_ik[j].push_back(tmp3);
		}
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

CanettiGennaroJareckiKrawczykRabinRVSS::CanettiGennaroJareckiKrawczykRabinRVSS
	(std::istream &in,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(0), t(0), i(0), tprime(0)
{
	std::string value;

	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	std::getline(in, value);
	std::stringstream(value) >> n;
	if (n > TMCG_MAX_DKG_PLAYERS)
		n = TMCG_MAX_DKG_PLAYERS;
	std::getline(in, value);
	std::stringstream(value) >> t;
	if (t > n)
		t = n;
	std::getline(in, value);
	std::stringstream(value) >> i;
	if (i >= n)
		i = 0;
	std::getline(in, value);
	std::stringstream(value) >> tprime;
	if (tprime > n)
		tprime = n;
	mpz_init(x_i), mpz_init(xprime_i);
	in >> x_i >> xprime_i;
	mpz_init(z_i), mpz_init(zprime_i);
	in >> z_i >> zprime_i;
	size_t qual_size = 0;
	std::getline(in, value);
	std::stringstream(value) >> qual_size;
	for (size_t i = 0; (i < qual_size) && (i < n); i++)
	{
		size_t who;
		std::getline(in, value);
		std::stringstream(value) >> who;
		QUAL.push_back(who);
	}
	s_ji.resize(n);
	sprime_ji.resize(n);
	C_ik.resize(n);
	for (size_t j = 0; j < n; j++)
	{
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ji[j].push_back(tmp3);
		}
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ji[j].push_back(tmp3);
		}
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			C_ik[j].push_back(tmp3);
		}		
	}
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			in >> s_ji[j][i];
			in >> sprime_ji[j][i];
		}
		for (size_t k = 0; k <= tprime; k++)
			in >> C_ik[i][k];
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void CanettiGennaroJareckiKrawczykRabinRVSS::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl << tprime << std::endl;
	out << x_i << std::endl << xprime_i << std::endl;
	out << z_i << std::endl << zprime_i << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			out << s_ji[j][i] << std::endl;
			out << sprime_ji[j][i] << std::endl;
		}
		for (size_t k = 0; k <= tprime; k++)
			out << C_ik[i][k] << std::endl;
	}
}

std::string CanettiGennaroJareckiKrawczykRabinRVSS::Label
	() const
{
	return label;
}

void CanettiGennaroJareckiKrawczykRabinRVSS::EraseSecrets
	()
{
	mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
	mpz_set_ui(z_i, 0L), mpz_set_ui(zprime_i, 0L);
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[j][i], 0L);
			mpz_set_ui(sprime_ji[j][i], 0L);
		}
	}	
}

bool CanettiGennaroJareckiKrawczykRabinRVSS::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k), mpz_init(g2);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
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
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_fpowm(fpowm_table_g, foo, g, q, p);
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

		// We use a procedure similar to FIPS 186-3 A.2.3;
		// it is supposed as verifiable generation of $g$.
		std::stringstream U;
		U << "LibTMCG|" << p << "|" << q << "|ggen|";
		mpz_sub_ui(bar, p, 1L); // compute $p-1$
		do
		{
			mpz_shash(foo, U.str());
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

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(k), mpz_clear(g2);
		return return_value;
	}
}

bool CanettiGennaroJareckiKrawczykRabinRVSS::CheckElement
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

bool CanettiGennaroJareckiKrawczykRabinRVSS::Share
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(tprime <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, b_i;
	std::vector<size_t> complaints, complaints_counter, complaints_from;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t k = 0; k <= tprime; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_i.push_back(tmp1), b_i.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinRVSS::Share()" << p << q << g << h << n << t << tprime << label;
	rbc->setID(myID.str());

	try
	{
		// 1. Each player $P_i$ performs a Pedersen-VSS of a random value $z_i$ as a dealer:
		// (a) $P_i$ chooses two random polynomials $f_i(z)$ and $f\prime_i(z)$ over $\mathbb{Z}_q$
		//     of degree $t\prime$ where $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t\prime$ and
		//     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t\prime$.
		for (size_t k = 0; k <= tprime; k++)
		{
			if (use_very_strong_randomness)
			{
				mpz_ssrandomm(a_i[k], q);
				mpz_ssrandomm(b_i[k], q);
			}
			else
			{
				mpz_srandomm(a_i[k], q);
				mpz_srandomm(b_i[k], q);
			}
		}
		//     Let $z_i = a_{i0} = f_i(0)$.
		mpz_set(z_i, a_i[0]), mpz_set(zprime_i, b_i[0]);
		err << "RVSS(" << label << "): P_" << i << ": z_i = " << z_i << " zprime_i = " << zprime_i << std::endl;
		//     $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$ for $k = 0, \ldots, t\prime$.
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_fspowm(fpowm_table_g, foo, g, a_i[k], p);
			mpz_fspowm(fpowm_table_h, bar, h, b_i[k], p);
			mpz_mul(C_ik[i][k], foo, bar);
			mpz_mod(C_ik[i][k], C_ik[i][k], p);
			rbc->Broadcast(C_ik[i][k]);
		}
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				for (size_t k = 0; k <= tprime; k++)
				{
					if (!rbc->DeliverFrom(C_ik[j][k], j))
					{
						err << "RVSS(" << label << "): P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!CheckElement(C_ik[j][k]))
					{
						err << "RVSS(" << label << "): P_" << i << ": bad C_ik received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(C_ik[j][k], 0L); // indicates an error
					}
				}
			}
		}
		// $P_i$ sends shares $s_{ij} = f_i(j) \bmod q$, $s\prime_{ij} = f\prime_i(j) \bmod q$ to
		// each $P_j$, for $j = 1, \ldots, n$.
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[i][j], 0L);
			mpz_set_ui(sprime_ji[i][j], 0L);
			for (size_t k = 0; k <= tprime; k++)
			{
				mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
				mpz_mul(bar, foo, b_i[k]);
				mpz_mod(bar, bar, q);
				mpz_mul(foo, foo, a_i[k]);
				mpz_mod(foo, foo, q);
				mpz_add(s_ji[i][j], s_ji[i][j], foo);
				mpz_mod(s_ji[i][j], s_ji[i][j], q);				
				mpz_add(sprime_ji[i][j], sprime_ji[i][j], bar);
				mpz_mod(sprime_ji[i][j], sprime_ji[i][j], q);
			}
			if (j != i)
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer)
					mpz_add_ui(s_ji[i][j], s_ji[i][j], 1L);
				if (!aiou->Send(s_ji[i][j], j, 0))
				{
					err << "RVSS(" << label << "): P_" << i << ": sending s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(sprime_ji[i][j], j, 0))
				{
					err << "RVSS(" << label << "): P_" << i << ": sending sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
			}
		}
		// (b) Each $P_j$ verifies the shares received from other players for $i = 1, \ldots, n$
		//     $g^{s_{ij}} h^{s\prime_{ij}} = \prod_{k=0}^t\prime (C_{ik})^{j^k} \bmod p$.
		// (In opposite to the notation used in the paper the indicies $i$ and $j$ are
		//  exchanged in this step for convenience.)
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				if (!aiou->Receive(s_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "RVSS(" << label << "): P_" << i << ": receiving s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(s_ji[j][i], q) >= 0)
				{
					err << "RVSS(" << label << "): P_" << i << ": bad s_ji received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(s_ji[j][i], 0L); // indicates an error
				}
				if (!aiou->Receive(sprime_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "RVSS(" << label << "): P_" << i << ": receiving sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(sprime_ji[j][i], q) >= 0)
				{
					err << "RVSS(" << label << "): P_" << i << ": bad sprime_ji received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(sprime_ji[j][i], 0L); // indicates an error
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			// compute LHS for the check
			mpz_fspowm(fpowm_table_g, foo, g, s_ji[j][i], p);
			mpz_fspowm(fpowm_table_h, bar, h, sprime_ji[j][i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// compute RHS for the check
			mpz_set_ui(rhs, 1L);
			for (size_t k = 0; k <= tprime; k++)
			{
				mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
				mpz_powm(bar, C_ik[j][k], foo, p);
				mpz_mul(rhs, rhs, bar);
				mpz_mod(rhs, rhs, p);
			}
			// check equation (1)
			if (mpz_cmp(lhs, rhs))
			{
				err << "RVSS(" << label << "): P_" << i << ": checking step 1b failed; complaint against P_" << j << std::endl;
				complaints.push_back(j);
			}
		}
		// If the check fails for an index $i$, $P_j$ broadcasts a complaint against $P_i$.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "RVSS(" << label << "): P_" << i << ": broadcast complaint against P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		complaints.clear(), complaints_counter.clear(), complaints_from.clear(); // reset
		for (size_t j = 0; j < n; j++)
			complaints_counter.push_back(0); // initialize counter
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
						err << "RVSS(" << label << "): P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(rhs);
					if ((who < n) && !dup.count(who))
					{
						err << "RVSS(" << label << "): P_" << i << ": receiving complaint against P_" << who << " from P_" << j << std::endl;
						complaints_counter[who]++;
						dup.insert(std::pair<size_t, bool>(who, true)); // mark as counted for $P_j$
						if (who == i)
							complaints_from.push_back(j); // remember where the complaints are from
					}
					else if ((who < n) && dup.count(who))
					{
						err << "RVSS(" << label << "): P_" << i << ": duplicated complaint for P_" << who << "; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		// (c) Each player $P_i$ who, as a dealer, received a complaint from player $P_j$
		//     broadcasts the values $s_{ij}$, $s\prime_{ij}$ that satisfy Eq. (1).
		if (complaints_counter[i])
		{
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "RVSS(" << label << "): P_" << i << ": there are " << complaints_counter[i] << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
			{
				mpz_set_ui(lhs, *it); // who is complaining?
				rbc->Broadcast(lhs);
				rbc->Broadcast(s_ji[i][*it]);
				rbc->Broadcast(sprime_ji[i][*it]);
			}
			err << "RVSS(" << label << "): P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		// (d) Each player builds the set of players $QUAL$ which excludes any player
		//      - who received more than $t$ complaints in Step 1b, or
		//      - answered to a complaint in Step 1c with values that violate Eq. (1).
		for (size_t j = 0; j < n; j++)
		{
			if (complaints_counter[j] > t)
				complaints.push_back(j);
			if (j != i)
			{
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(lhs, j))
					{
						err << "RVSS(" << label << "): P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					size_t who = mpz_get_ui(lhs);
					if (who >= n)
						break; // end marker received
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "RVSS(" << label << "): P_" << i << ": receiving foo failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(foo, q) >= 0)
					{
						err << "RVSS(" << label << "): P_" << i << ": bad foo received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(foo, 0L); // indicates an error
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "RVSS(" << label << "): P_" << i << ": receiving bar failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(bar, q) >= 0)
					{
						err << "RVSS(" << label << "): P_" << i << ": bad bar received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(bar, 0L); // indicates an error
					}
					mpz_t s, sprime;
					mpz_init_set(s, foo), mpz_init_set(sprime, bar); // save shares
					// compute LHS for the check
					mpz_fpowm(fpowm_table_g, foo, g, foo, p);
					mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, foo, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= tprime; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $j$ in computation
						mpz_powm(bar, C_ik[j][k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (1)
					if (mpz_cmp(lhs, rhs))
					{
						err << "RVSS(" << label << "): P_" << i << ": checking step 1d failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious, store only shares for this player
						if (who == i)
						{
							err << "RVSS(" << label << "): P_" << i << ": shares adjusted in step 1d from P_" << j << std::endl;
							mpz_set(s_ji[j][i], s);
							mpz_set(sprime_ji[j][i], sprime);
						}
					}
					mpz_clear(s), mpz_clear(sprime);
					cnt++;
				}
				while (cnt <= n);
			}
		}
		QUAL.clear();
		for (size_t j = 0; j < n; j++)
		{
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		}
		err << "RVSS(" << label << "): P_" << i << ": QUAL = { ";
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			err << "P_" << *it << " ";
		err << "}" << std::endl;
		// 2. The shared random value $x$ is not computed by any party, but it equals
		//    $x = \sum_{i \in QUAL} z_i \bmod q$. Each $P_i$ sets his share of the
		//    secret to $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the associated
		//    random value $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
		// (Note that in this section the indicies $i$ and $j$ are exchanged
		//  again, because the reversed convention was used in Step 1b.)
		mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_add(x_i, x_i, s_ji[*it][i]);
			mpz_mod(x_i, x_i, q);
			mpz_add(xprime_i, xprime_i, sprime_ji[*it][i]);
			mpz_mod(xprime_i, xprime_i, q);
		}
		err << "RVSS(" << label << "): P_" << i << ": x_i = " << x_i << std::endl;
		err << "RVSS(" << label << "): P_" << i << ": xprime_i = " << xprime_i << std::endl;
		
		if (std::find(QUAL.begin(), QUAL.end(), i) == QUAL.end())
			throw false;
		if (QUAL.size() <= t)
			throw false;

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_clear(a_i[k]), mpz_clear(b_i[k]);
			delete [] a_i[k], delete [] b_i[k];
		}
		a_i.clear(), b_i.clear();
		// return
		return return_value;
	}
}

bool CanettiGennaroJareckiKrawczykRabinRVSS::Reconstruct
	(const std::vector<size_t> &complaints,
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
	myID << "CanettiGennaroJareckiKrawczykRabinRVSS::Reconstruct()" << p << q << g << h << n << t << tprime << label;
	for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		myID << "[" << *it << "]";
	rbc->setID(myID.str());

	try
	{
		// run reconstruction phase of Pedersen-VSS
		if (complaints.size() > t)
		{
			err << "RVSS(" << label << "): P_" << i << ": too many faulty parties (" << complaints.size() << " > t)" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			if (std::find(QUAL.begin(), QUAL.end(), *it) == QUAL.end())
			{
				err << "RVSS(" << label << "): P_" << i << ": reconstruction of z_i failed because P_" << *it << " not in QUAL" << std::endl;
				throw false;
			}
			// prepare for collecting shares
			std::vector<size_t> parties;
			parties.push_back(i); // share of this player is always available and correct
			mpz_set(shares[i], s_ji[*it][i]);
			// broadcast shares for reconstruction of $z_i$ (where $i$ is here the index of the failed party)
			if ((std::find(complaints.begin(), complaints.end(), i) == complaints.end()) && (std::find(QUAL.begin(), QUAL.end(), i) != QUAL.end()))
			{
				rbc->Broadcast(s_ji[*it][i]);
				rbc->Broadcast(sprime_ji[*it][i]);
			}
			// collect shares $s_{ji}$ and $s\prime_{ji}$ of other parties from QUAL
			for (std::vector<size_t>::iterator jt = QUAL.begin(); jt != QUAL.end(); ++jt)
			{
				if ((*jt != i) && (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end()))
				{
					if (rbc->DeliverFrom(foo, *jt) && rbc->DeliverFrom(bar, *jt))
					{
						if ((mpz_cmpabs(foo, q) >= 0) || (mpz_cmpabs(bar, q) >= 0))
							err << "RVSS(" << label << "): P_" << i << ": bad share received from " << *jt << std::endl;
						else
						{
							mpz_set(shares[*jt], foo); // save the received share for later following interpolation
							// compute LHS for the check
							mpz_fpowm(fpowm_table_g, foo, g, foo, p);
							mpz_fpowm(fpowm_table_h, bar, h, bar, p);
							mpz_mul(lhs, foo, bar);
							mpz_mod(lhs, lhs, p);
							// compute RHS for the check
							mpz_set_ui(rhs, 1L);
							for (size_t k = 0; k <= tprime; k++)
							{
								mpz_ui_pow_ui(foo, *jt + 1, k); // adjust index $j$ in computation
								mpz_powm(bar, C_ik[*it][k], foo, p);
								mpz_mul(rhs, rhs, bar);
								mpz_mod(rhs, rhs, p);
							}
							// check equation (1)
							if (mpz_cmp(lhs, rhs))
								err << "RVSS(" << label << "): P_" << i << ": bad share received from " << *jt << std::endl;
							else
								parties.push_back(*jt);
						}
					}
					else
						err << "RVSS(" << label << "): P_" << i << ": no share received from " << *jt << std::endl;					
				}
			}
			// check whether enough shares (i.e. $t + 1$) have been collected
			if (parties.size() <= t)
			{
				err << "RVSS(" << label << "): P_" << i << ": not enough shares collected" << std::endl;
				throw false;
			}
			if (parties.size() > (t + 1))
				parties.resize(t + 1);
			err << "RVSS(" << label << "): P_" << i << ": reconstructing parties = ";
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
					err << "RVSS(" << label << "): P_" << i << ": cannot invert LHS during reconstruction" << std::endl;
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

CanettiGennaroJareckiKrawczykRabinRVSS::~CanettiGennaroJareckiKrawczykRabinRVSS
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i);
	mpz_clear(z_i), mpz_clear(zprime_i);
	for (size_t j = 0; j < s_ji.size(); j++)
	{
		for (size_t i = 0; i < s_ji[j].size(); i++)
		{
			mpz_clear(s_ji[j][i]);
			delete [] s_ji[j][i];
		}
		s_ji[j].clear();
	}
	s_ji.clear();
	for (size_t j = 0; j < sprime_ji.size(); j++)
	{
		for (size_t i = 0; i < sprime_ji[j].size(); i++)
		{
			mpz_clear(sprime_ji[j][i]);
			delete [] sprime_ji[j][i];
		}
		sprime_ji[j].clear();
	}
	sprime_ji.clear();
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
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

CanettiGennaroJareckiKrawczykRabinZVSS::CanettiGennaroJareckiKrawczykRabinZVSS
	(const size_t n_in, const size_t t_in, const size_t i_in, const size_t tprime_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(n_in), t(t_in), i(i_in), tprime(tprime_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS), mpz_init_set(h, h_CRS);
	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L);
	s_ji.resize(n);
	sprime_ji.resize(n);
	C_ik.resize(n);
	for (size_t j = 0; j < n_in; j++)
	{
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ji[j].push_back(tmp3);
		}
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ji[j].push_back(tmp3);
		}
		for (size_t k = 0; k <= tprime_in; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			C_ik[j].push_back(tmp3);
		}
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

CanettiGennaroJareckiKrawczykRabinZVSS::CanettiGennaroJareckiKrawczykRabinZVSS
	(std::istream &in,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(0), t(0), i(0), tprime(0)
{
	std::string value;

	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	std::getline(in, value);
	std::stringstream(value) >> n;
	if (n > TMCG_MAX_DKG_PLAYERS)
		n = TMCG_MAX_DKG_PLAYERS;
	std::getline(in, value);
	std::stringstream(value) >> t;
	if (t > n)
		t = n;
	std::getline(in, value);
	std::stringstream(value) >> i;
	if (i >= n)
		i = 0;
	std::getline(in, value);
	std::stringstream(value) >> tprime;
	if (tprime > n)
		tprime = n;
	mpz_init(x_i), mpz_init(xprime_i);
	in >> x_i >> xprime_i;
	size_t qual_size = 0;
	std::getline(in, value);
	std::stringstream(value) >> qual_size;
	for (size_t i = 0; (i < qual_size) && (i < n); i++)
	{
		size_t who;
		std::getline(in, value);
		std::stringstream(value) >> who;
		QUAL.push_back(who);
	}
	s_ji.resize(n);
	sprime_ji.resize(n);
	C_ik.resize(n);
	for (size_t j = 0; j < n; j++)
	{
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			s_ji[j].push_back(tmp3);
		}
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			sprime_ji[j].push_back(tmp3);
		}
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			C_ik[j].push_back(tmp3);
		}
	}
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			in >> s_ji[j][i];
			in >> sprime_ji[j][i];
		}
		for (size_t k = 0; k <= tprime; k++)
			in >> C_ik[i][k];
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void CanettiGennaroJareckiKrawczykRabinZVSS::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl << tprime << std::endl;
	out << x_i << std::endl << xprime_i << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			out << s_ji[j][i] << std::endl;
			out << sprime_ji[j][i] << std::endl;
		}
		for (size_t k = 0; k <= tprime; k++)
			out << C_ik[i][k] << std::endl;
	}
}

std::string CanettiGennaroJareckiKrawczykRabinZVSS::Label
	() const
{
	return label;
}

void CanettiGennaroJareckiKrawczykRabinZVSS::EraseSecrets
	()
{
	mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[j][i], 0L);
			mpz_set_ui(sprime_ji[j][i], 0L);
		}
	}	
}

bool CanettiGennaroJareckiKrawczykRabinZVSS::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k), mpz_init(g2);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
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
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_fpowm(fpowm_table_g, foo, g, q, p);
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

		// We use a procedure similar to FIPS 186-3 A.2.3;
		// it is supposed as verifiable generation of $g$.
		std::stringstream U;
		U << "LibTMCG|" << p << "|" << q << "|ggen|";
		mpz_sub_ui(bar, p, 1L); // compute $p-1$
		do
		{
			mpz_shash(foo, U.str());
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

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(k), mpz_clear(g2);
		return return_value;
	}
}

bool CanettiGennaroJareckiKrawczykRabinZVSS::CheckElement
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

bool CanettiGennaroJareckiKrawczykRabinZVSS::Share
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(tprime <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, b_i;
	std::vector<size_t> complaints, complaints_counter, complaints_from;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t k = 0; k <= tprime; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_i.push_back(tmp1), b_i.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinZVSS::Share()" << p << q << g << h << n << t << tprime << label;
	rbc->setID(myID.str());

	try
	{
		// 1. Each player $P_i$ performs a Pedersen-VSS of a random
		//    value $z_i$ as a dealer:
		// (a) $P_i$ chooses two random polynomials $f_i(z)$ and
		//     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t\prime$ where
		//     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t\prime$ and
		//     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t\prime$
		for (size_t k = 0; k <= tprime; k++)
		{
			if (k == 0)
			{
				// In Step (1a), each player chooses $a_{i0} = b_{i0} = 0$, [...]
				mpz_set_ui(a_i[k], 0L);
				mpz_set_ui(b_i[k], 0L);
			}
			else if (use_very_strong_randomness)
			{
				mpz_ssrandomm(a_i[k], q);
				mpz_ssrandomm(b_i[k], q);
			}
			else
			{
				mpz_srandomm(a_i[k], q);
				mpz_srandomm(b_i[k], q);
			}
		}
		// Let $z_i = a_{i0} = f_i(0)$.
		// $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
		// for $k = 0, \ldots, t\prime$.
		for (size_t k = 0; k <= t; k++)
		{
			mpz_fspowm(fpowm_table_g, foo, g, a_i[k], p);
			mpz_fspowm(fpowm_table_h, bar, h, b_i[k], p);
			mpz_mul(C_ik[i][k], foo, bar);
			mpz_mod(C_ik[i][k], C_ik[i][k], p);
			rbc->Broadcast(C_ik[i][k]);
		}
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				for (size_t k = 0; k <= tprime; k++)
				{
					if (!rbc->DeliverFrom(C_ik[j][k], j))
					{
						err << "ZVSS(" << label << "): P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!CheckElement(C_ik[j][k]))
					{
						err << "ZVSS(" << label << "): P_" << i << ": bad C_ik received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(C_ik[j][k], 0L); // indicates an error
					}
				}
			}
		}
		// $P_i$ sends shares $s_{ij} = f_i(j) \bmod q$,
		// $s\prime_{ij} = f\prime_i(j) \bmod q$ to each $P_j$,
		// for $j = 1, \ldots, n$.
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[i][j], 0L);
			mpz_set_ui(sprime_ji[i][j], 0L);
			for (size_t k = 0; k <= tprime; k++)
			{
				mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
				mpz_mul(bar, foo, b_i[k]);
				mpz_mod(bar, bar, q);
				mpz_mul(foo, foo, a_i[k]);
				mpz_mod(foo, foo, q);
				mpz_add(s_ji[i][j], s_ji[i][j], foo);
				mpz_mod(s_ji[i][j], s_ji[i][j], q);				
				mpz_add(sprime_ji[i][j], sprime_ji[i][j], bar);
				mpz_mod(sprime_ji[i][j], sprime_ji[i][j], q);
			}
			if (j != i)
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer)
				{
					mpz_add_ui(s_ji[i][j], s_ji[i][j], 1L);
				}
				if (!aiou->Send(s_ji[i][j], j, 0))
				{
					err << "ZVSS(" << label << "): P_" << i << ": sending s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(sprime_ji[i][j], j, 0))
				{
					err << "ZVSS(" << label << "): P_" << i << ": sending sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
			}
		}
		// (b) Each $P_j$ verifies the shares received from other players for $i = 1, \ldots, n$
		//     $g^{s_{ij}} h^{s\prime_{ij}} = \prod_{k=0}^t\prime (C_{ik})^{j^k} \bmod p$.
		// In opposite to the notation used in the paper the indicies $i$ and $j$ are
		// exchanged in this step for convenience.
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				if (!aiou->Receive(s_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "ZVSS(" << label << "): P_" << i << ": receiving s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(s_ji[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad s_ji received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(s_ji[j][i], 0L); // indicates an error
				}
				if (!aiou->Receive(sprime_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "ZVSS(" << label << "): P_" << i << ": receiving sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(sprime_ji[j][i], q) >= 0)
				{
					err << "P_" << i << ": bad sprime_ji received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(sprime_ji[j][i], 0L); // indicates an error
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			// compute LHS for the check
			mpz_fspowm(fpowm_table_g, foo, g, s_ji[j][i], p);
			mpz_fspowm(fpowm_table_h, bar, h, sprime_ji[j][i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// compute RHS for the check
			mpz_set_ui(rhs, 1L);
			for (size_t k = 0; k <= tprime; k++)
			{
				mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
				mpz_powm(bar, C_ik[j][k], foo, p);
				mpz_mul(rhs, rhs, bar);
				mpz_mod(rhs, rhs, p);
			}
			// check equation (1)
			if (mpz_cmp(lhs, rhs))
			{
				err << "ZVSS(" << label << "): P_" << i << ": checking step 1b failed; complaint against P_" << j << std::endl;
				complaints.push_back(j);
			}
			// [...] and in Step (1b) each player $P_j$ additionally checks
			// for each $i$ that $C_{i0} = 1 \bmod p$.
			if (mpz_cmp_ui(C_ik[j][0], 1L))
			{
				err << "ZVSS(" << label << "): P_" << i << ": additional check in step 1b failed; complaint against P_" << j << std::endl;
				complaints.push_back(j);
			}		
		}
		// If the check fails for an index $i$, $P_j$ broadcasts a complaint against $P_i$.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "ZVSS(" << label << "): P_" << i << ": broadcast complaint against P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		complaints.clear(), complaints_counter.clear(), complaints_from.clear(); // reset
		for (size_t j = 0; j < n; j++)
			complaints_counter.push_back(0); // initialize counter
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
						err << "ZVSS(" << label << "): P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(rhs);
					if ((who < n) && !dup.count(who))
					{
						err << "ZVSS(" << label << "): P_" << i << ": receiving complaint against P_" << who << " from P_" << j << std::endl;
						complaints_counter[who]++;
						dup.insert(std::pair<size_t, bool>(who, true)); // mark as counted for $P_j$
						if (who == i)
							complaints_from.push_back(j);
					}
					else if ((who < n) && dup.count(who))
					{
						err << "ZVSS(" << label << "): P_" << i << ": duplicated complaint for P_" << who << "; complaint againts P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		// (c) Each player $P_i$ who, as a dealer, received a complaint
		//     from player $P_j$ broadcasts the values $s_{ij}$,
		//     $s\prime_{ij}$ that satisfy Eq. (1).
		if (complaints_counter[i])
		{
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "ZVSS(" << label << "): P_" << i << ": there are " << complaints_counter[i] << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
			{
				mpz_set_ui(lhs, *it); // who is complaining?
				rbc->Broadcast(lhs);
				rbc->Broadcast(s_ji[i][*it]);
				rbc->Broadcast(sprime_ji[i][*it]);
			}
			err << "ZVSS(" << label << "): P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		// (d) Each player builds the set of players $QUAL$ which excludes any player
		//      - who received more than $t$ complaints in Step 1b, or
		//      - answered to a complaint in Step 1c with values that violate Eq. (1).
		for (size_t j = 0; j < n; j++)
		{
			if (complaints_counter[j] > t)
				complaints.push_back(j);
			if (j != i)
			{
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(lhs, j))
					{
						err << "ZVSS(" << label << "): P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					size_t who = mpz_get_ui(lhs);
					if (who >= n)
						break; // end marker received
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "ZVSS(" << label << "): P_" << i << ": receiving foo failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(foo, q) >= 0)
					{
						err << "ZVSS(" << label << "): P_" << i << ": bad foo received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(foo, 0L); // indicates an error
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "ZVSS(" << label << "): P_" << i << ": receiving bar failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (mpz_cmpabs(bar, q) >= 0)
					{
						err << "ZVSS(" << label << "): P_" << i << ": bad bar received; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						mpz_set_ui(bar, 0L); // indicates an error
					}
					mpz_t s, sprime;
					mpz_init_set(s, foo), mpz_init_set(sprime, bar); // save shares
					// compute LHS for the check
					mpz_fpowm(fpowm_table_g, foo, g, foo, p);
					mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, foo, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= tprime; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $j$ in computation
						mpz_powm(bar, C_ik[j][k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (1)
					if (mpz_cmp(lhs, rhs))
					{
						err << "ZVSS(" << label << "): P_" << i << ": checking step 1d failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious
						if (who == i)
						{
							err << "ZVSS(" << label << "): P_" << i << ": shares adjusted in step 1d from P_" << j << std::endl;
							mpz_set(s_ji[j][i], s);
							mpz_set(sprime_ji[j][i], sprime);
						}
					}
					mpz_clear(s), mpz_clear(sprime);
					cnt++;
				}
				while (cnt <= n);
			}
		}
		QUAL.clear();
		for (size_t j = 0; j < n; j++)
		{
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		}
		err << "ZVSS(" << label << "): P_" << i << ": QUAL = { ";
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			err << "P_" << *it << " ";
		err << "}" << std::endl;
		// 2. The shared random value $x$ is not computed by any party, but it equals
		//    $x = \sum_{i \in QUAL} z_i \bmod q$. Each $P_i$ sets his share of the
		//    secret to $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the associated
		//    random value $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
		// Note that in this section the indicies $i$ and $j$ are exchanged
		// again, because the reversed convention was used in Step 1b.
		mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_add(x_i, x_i, s_ji[*it][i]);
			mpz_mod(x_i, x_i, q);
			mpz_add(xprime_i, xprime_i, sprime_ji[*it][i]);
			mpz_mod(xprime_i, xprime_i, q);
		}
		err << "ZVSS(" << label << "): P_" << i << ": x_i = " << x_i << std::endl;
		err << "ZVSS(" << label << "): P_" << i << ": xprime_i = " << xprime_i << std::endl;
		
		if (std::find(QUAL.begin(), QUAL.end(), i) == QUAL.end())
			throw false;
		if (QUAL.size() <= t)
			throw false;

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_clear(a_i[k]), mpz_clear(b_i[k]);
			delete [] a_i[k], delete [] b_i[k];
		}
		a_i.clear(), b_i.clear();
		// return
		return return_value;
	}
}

CanettiGennaroJareckiKrawczykRabinZVSS::~CanettiGennaroJareckiKrawczykRabinZVSS
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i);
	for (size_t j = 0; j < s_ji.size(); j++)
	{
		for (size_t i = 0; i < s_ji[j].size(); i++)
		{
			mpz_clear(s_ji[j][i]);
			delete [] s_ji[j][i];
		}
		s_ji[j].clear();
	}
	s_ji.clear();
	for (size_t j = 0; j < sprime_ji.size(); j++)
	{
		for (size_t i = 0; i < sprime_ji[j].size(); i++)
		{
			mpz_clear(sprime_ji[j][i]);
			delete [] sprime_ji[j][i];
		}
		sprime_ji[j].clear();
	}
	sprime_ji.clear();
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
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

CanettiGennaroJareckiKrawczykRabinDKG::CanettiGennaroJareckiKrawczykRabinDKG
	(const size_t n_in, const size_t t_in, const size_t i_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			label(label_in),
			n(n_in), t(t_in), i(i_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS), mpz_init_set(h, h_CRS);
	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L), mpz_init_set_ui(y, 1L);

	// initialize required subprotocols
	x_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, fieldsize, subgroupsize, use_very_strong_randomness_in, "x_rvss");
	d_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, fieldsize, subgroupsize, false, "d_rvss");

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

CanettiGennaroJareckiKrawczykRabinDKG::CanettiGennaroJareckiKrawczykRabinDKG
	(std::istream &in,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in, const std::string label_in):
			F_size(fieldsize), G_size(subgroupsize),
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
		n = TMCG_MAX_DKG_PLAYERS;
	std::getline(in, value);
	std::stringstream(value) >> t;
	if (t > n)
		t = n;
	std::getline(in, value);
	std::stringstream(value) >> i;
	if (i >= n)
		i = 0;
	mpz_init(x_i), mpz_init(xprime_i), mpz_init(y);
	in >> x_i >> xprime_i >> y;
	size_t qual_size = 0;
	std::getline(in, value);
	std::stringstream(value) >> qual_size;
	for (size_t j = 0; (j < qual_size) && (j < n); j++)
	{
		size_t who;
		std::getline(in, value);
		std::stringstream(value) >> who;
		QUAL.push_back(who);
	}

	// initialize required subprotocols
	x_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, fieldsize, subgroupsize, use_very_strong_randomness_in, "x_rvss");
	d_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, fieldsize, subgroupsize, false, "d_rvss");

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void CanettiGennaroJareckiKrawczykRabinDKG::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl;
	out << x_i << std::endl << xprime_i << std::endl << y << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
}

bool CanettiGennaroJareckiKrawczykRabinDKG::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k), mpz_init(g2);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
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
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_fpowm(fpowm_table_g, foo, g, q, p);
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

		// We use a procedure similar to FIPS 186-3 A.2.3;
		// it is supposed as verifiable generation of $g$.
		std::stringstream U;
		U << "LibTMCG|" << p << "|" << q << "|ggen|";
		mpz_sub_ui(bar, p, 1L); // compute $p-1$
		do
		{
			mpz_shash(foo, U.str());
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

		// check whether the group for Joint-RVSS is sound
		if (!x_rvss->CheckGroup())
			throw false;
		if (!d_rvss->CheckGroup())
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

bool CanettiGennaroJareckiKrawczykRabinDKG::CheckElement
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

bool CanettiGennaroJareckiKrawczykRabinDKG::Generate
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	mpz_t d, r_i, rprime_i;
	std::vector<mpz_ptr> A_i, B_i, T_i, Tprime_i, z_i, d_i, dprime_i;
	std::vector<size_t> complaints, complaints_counter, complaints_from, d_complaints;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	mpz_init(d), mpz_init(r_i), mpz_init(rprime_i);
	for (size_t j = 0; j < n; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(), tmp4 = new mpz_t();
		mpz_ptr tmp5 = new mpz_t(), tmp6 = new mpz_t(), tmp7 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		mpz_init(tmp5), mpz_init(tmp6), mpz_init(tmp7);
		A_i.push_back(tmp1), B_i.push_back(tmp2), T_i.push_back(tmp3), Tprime_i.push_back(tmp4);
		z_i.push_back(tmp5), d_i.push_back(tmp6), dprime_i.push_back(tmp7);
	}
	size_t simulate_faulty_randomizer[10];
	for (size_t idx = 0; idx < 10; idx++)
		simulate_faulty_randomizer[idx] = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinDKG::Generate()" << p << q << g << h << n << t << label;
	rbc->setID(myID.str());

	try
	{
		// Generating $x$:
		// Players execute Joint-RVSS(t,n,t)
		if (!x_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[0])
			throw false;
		// 1. Player $P_i$ gets the following secret outputs of Joint-RVSS
		//    - $x_i, x\prime_i$ his share of the secret and the associated random value
		mpz_set(x_i, x_rvss->x_i), mpz_set(xprime_i, x_rvss->xprime_i);
		//    - $f_i(z), f\prime_i(z)$ polynomial he used to share his contribution $z_i = f_i(0)$
		mpz_set(z_i[i], x_rvss->z_i);
		//    - $s_{ji}, s\prime_{ji}$ for $j = 1, \ldots, n$ the shares and randomness he received
		//      from others
		//    Players also get public outputs $C_{ik}$ for $i = 1, \ldots, n, k = 0, \ldots, t$
		//    and the set QUAL
		for (size_t j = 0; j < x_rvss->QUAL.size(); j++)
			QUAL.push_back(x_rvss->QUAL[j]);
		// Extracting $y = g^x \bmod p$:
		// Each player exposes $y_i = g^{z_i} \bmod p$ to enable the computation of $y = g^x \bmod p$.
		// 2. Each player $P_i$, $i \in QUAL$, broadcasts $A_i = g^{f_i(0)} = g^{z_i} \bmod p$ and
		//    $B_i = h^{f\prime_i(0)} \bmod p$, s.t. $C_{i0} = A_i B_i$. $P_i$ also chooses random
		//    values $r_i$ and $r\prime_i$ and broadcasts $T_i = g^{r_i}, T\prime_i = h^{r\prime_i} \bmod p$.
		mpz_fspowm(fpowm_table_g, A_i[i], g, x_rvss->z_i, p);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[1])
			mpz_add_ui(A_i[i], A_i[i], 1L);
		mpz_fspowm(fpowm_table_h, B_i[i], h, x_rvss->zprime_i, p);
		mpz_srandomm(r_i, q);
		mpz_srandomm(rprime_i, q);
		mpz_fspowm(fpowm_table_g, T_i[i], g, r_i, p);
		mpz_fspowm(fpowm_table_h, Tprime_i[i], h, rprime_i, p);
		for (size_t j = 0; j < n; j++)
		{
			if ((j == i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				rbc->Broadcast(A_i[i]);
				rbc->Broadcast(B_i[i]);
				rbc->Broadcast(T_i[i]);
				rbc->Broadcast(Tprime_i[i]);
			}
			else if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				if (!rbc->DeliverFrom(A_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving A_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(A_i[j]))
				{
					err << "DKG(" << label << "): P_" << i << ": bad A_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(A_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(B_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving B_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(B_i[j]))
				{
					err << "DKG(" << label << "): P_" << i << ": bad B_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(B_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(T_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving T_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(T_i[j]))
				{
					err << "DKG(" << label << "): P_" << i << ": bad T_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(T_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(Tprime_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving Tprime_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(Tprime_i[j]))
				{
					err << "DKG(" << label << "): P_" << i << ": bad Tprime_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(Tprime_i[j], 0L); // indicates an error
				}
				// compute RHS and check that $C_{j0} = A_j B_j \bmod p$
				mpz_mul(rhs, A_i[j], B_i[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(x_rvss->C_ik[j][0], rhs))
				{
					err << "DKG(" << label << "): P_" << i << ": checking in step 2. failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
				}
			}
			else
				err << "DKG(" << label << "): P_" << i << ": WARNING - P_" << j << " not in QUAL" << std::endl;
		}
		// 3. Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//    his local share of the secret challenge to $d_i$.
		if (!d_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[2])
			throw false;
		mpz_set(d_i[i], d_rvss->z_i), mpz_set(dprime_i[i], d_rvss->zprime_i);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[3])
			mpz_add_ui(d_i[i], d_i[i], 1L);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[4])
			mpz_add_ui(dprime_i[i], dprime_i[i], 1L);
		// remove those players from $QUAL$, who are disqualified in this Joint-RVSS
		for (size_t j = 0; j < n; j++)
		{
			std::vector<size_t>::iterator it = std::find(QUAL.begin(), QUAL.end(), j);
			if ((it != QUAL.end()) && (std::find(d_rvss->QUAL.begin(), d_rvss->QUAL.end(), j) == d_rvss->QUAL.end()))
			{
				err << "DKG(" << label << "): P_" << i << ": WARNING - party erased from QUAL; complaint against P_" << j << std::endl;
				QUAL.erase(it);
				complaints.push_back(j);
			}
		}
		// 4. Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		for (size_t j = 0; j < n; j++)
		{
			if ((j == i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				rbc->Broadcast(d_i[i]);
				rbc->Broadcast(dprime_i[i]);
			}
			else if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				if (!rbc->DeliverFrom(d_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving d_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(d_i[j], q) >= 0)
				{
					err << "DKG(" << label << "): P_" << i << ": bad d_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(d_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(dprime_i[j], j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(dprime_i[j], q) >= 0)
				{
					err << "DKG(" << label << "): P_" << i << ": bad dprime_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(dprime_i[j], 0L); // indicates an error
				}
				// However, we can achieve optimal resilience by sieving out bad shares with
				// Pedersen verification equation (Eq. (1)) if the players submit the associated
				// random values generated by Joint-RVSS together with there shares. Therefore
				// the players must no longer erase these values as in the current Step 3.
				mpz_fpowm(fpowm_table_g, foo, g, d_i[j], p);
				mpz_fpowm(fpowm_table_h, bar, h, dprime_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, d_rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "DKG(" << label << "): P_" << i << ": checking d_i resp. dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
				}
			}
		}
		// public reconstruction of $d_j$, for every failed player $P_j \in QUAL$
		std::sort(d_complaints.begin(), d_complaints.end());
		std::vector<size_t>::iterator it = std::unique(d_complaints.begin(), d_complaints.end());
		d_complaints.resize(std::distance(d_complaints.begin(), it));
		err << "DKG(" << label << "): P_" << i << ": there are extracting complaints against ";
		for (std::vector<size_t>::iterator it = d_complaints.begin(); it != d_complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!d_rvss->Reconstruct(d_complaints, d_i, rbc, err))
		{
			err << "DKG(" << label << "): P_" << i << ": reconstruction in step 4. failed" << std::endl;
			throw false;
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[5])
			throw false;
		// Get $d = \sum_{P_i \in QUAL} d_i$
		mpz_set_ui(d, 0L);
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_add(d, d, d_i[*it]);
			mpz_mod(d, d, q);
		}
		err << "P_" << i << ": d = " << d << std::endl;
		// 5. $P_i$ broadcasts $R_i = r_i + d \cdot f_i(0)$ and $R\prime_i = r\prime_i + d \cdot f\prime_i(0)$
		mpz_mul(foo, d, x_rvss->z_i);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, r_i);
		mpz_mod(foo, foo, q);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[6])
			mpz_add_ui(foo, foo, 1L);
		rbc->Broadcast(foo);
		mpz_mul(bar, d, x_rvss->zprime_i);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, rprime_i);
		mpz_mod(bar, bar, q);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[7])
			mpz_add_ui(bar, bar, 1L);
		rbc->Broadcast(bar);
		// 6. Player $P_j$ checks for each $P_i$ that $g^{R_i} = T_i \cdot A_i^d$ and
		//    $h^{R\prime_i} = T\prime_i \cdot B_i^d$. If the equation is not satisfied
		//    then $P_j$ complains against $P_i$.
		// In opposite to the notation used in the paper the indicies $i$ and $j$ are
		// exchanged in this step for convenience.
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving R_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "DKG(" << label << "): P_" << i << ": receiving Rprime_i failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "DKG(" << label << "): P_" << i << ": bad R_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "DKG(" << label << "): P_" << i << ": bad Rprime_i received; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				mpz_fpowm(fpowm_table_g, lhs, g, foo, p);
				mpz_powm(rhs, A_i[j], d, p);
				mpz_mul(rhs, rhs, T_i[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "DKG(" << label << "): P_" << i << ": checking in step 6. failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_powm(rhs, B_i[j], d, p);
				mpz_mul(rhs, rhs, Tprime_i[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "DKG(" << label << "): P_" << i << ": checking in step 6. failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
				}
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[8])
					complaints.push_back(j);
			}
		}
		// 7. If player $P_i$ receives more than $t$ complaints, then $P_j$ 
		//    broadcasts $s_{ij}$ (and $s\prime_{ij}$ for the optimally-resilient variant). 
		// The broadcasts are done inside public reconstruction of $z_i$.
		// In opposite to the notation used in the paper the indicies $i$ and $j$ are
		// exchanged in this step for convenience.
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[9])
			throw false;
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "DKG(" << label << "): P_" << i << ": broadcast complaint against P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		complaints.clear(), complaints_counter.clear(), complaints_from.clear(); // reset
		for (size_t j = 0; j < n; j++)
			complaints_counter.push_back(0); // initialize counter
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (std::find(QUAL.begin(), QUAL.end(), j)	!= QUAL.end()))
			{
				size_t who;
				size_t cnt = 0;
				std::map<size_t, bool> dup;
				do
				{
					if (!rbc->DeliverFrom(rhs, j))
					{
						err << "DKG(" << label << "): P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(rhs);
					if ((who < n) && !dup.count(who))
					{
						err << "DKG(" << label << "): P_" << i << ": receiving complaint against P_" << who << " from P_" << j << std::endl;
						complaints_counter[who]++;
						dup.insert(std::pair<size_t, bool>(who, true)); // mark as counted for $P_j$
						if (who == i)
							complaints_from.push_back(j);
					}
					else if ((who < n) && dup.count(who))
					{
						err << "DKG(" << label << "): P_" << i << ": duplicated complaint against P_" << who << " from P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		if (complaints_counter[i])
		{
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "DKG(" << label << "): P_" << i << ": there are " << complaints_counter[i] << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
		}
		for (size_t j = 0; j < n; j++)
		{
			if (std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end())
			{
				if (complaints_counter[j] > t)
					complaints.push_back(j);
			}
		}
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "DKG(" << label << "): P_" << i << ": there are extracting complaints against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!x_rvss->Reconstruct(complaints, z_i, rbc, err))
		{
			err << "DKG(" << label << "): P_" << i << ": reconstruction in step 7. failed" << std::endl;
			throw false;
		}
		// Set $A_j = g^{z_j}$, for every failed player $P_j$.
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			mpz_fpowm(fpowm_table_g, A_i[*it], g, z_i[*it], p);
		// 8. The public value $y$ is set to $y = \prod_{i \in QUAL} A_i \bmod p$.
		err << "DKG(" << label << "): P_" << i << ": QUAL = { ";
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			err << "P_" << *it << " ";
			mpz_mul(y, y, A_i[*it]);
			mpz_mod(y, y, p);
		}
		err << "}" << std::endl;
		err << "DKG(" << label << "): P_" << i << ": y = " << y << std::endl;
		// 9. Player $P_i$ erases all secret information aside from his share $x_i$.
		x_rvss->EraseSecrets();
		d_rvss->EraseSecrets();
		for (size_t j = 0; j < z_i.size(); j++)
			mpz_set_ui(z_i[j], 0L);

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(d), mpz_clear(r_i), mpz_clear(rprime_i);
		for (size_t j = 0; j < n; j++)
		{
			mpz_clear(A_i[j]), mpz_clear(B_i[j]), mpz_clear(T_i[j]), mpz_clear(Tprime_i[j]);
			mpz_clear(z_i[j]), mpz_clear(d_i[j]), mpz_clear(dprime_i[j]);
			delete [] A_i[j], delete [] B_i[j], delete [] T_i[j], delete [] Tprime_i[j];
			delete [] z_i[j], delete [] d_i[j], delete [] dprime_i[j];
		}
		A_i.clear(), B_i.clear(), T_i.clear(), Tprime_i.clear();
		z_i.clear(), d_i.clear(), dprime_i.clear();
		// return
		return return_value;
	}
}

CanettiGennaroJareckiKrawczykRabinDKG::~CanettiGennaroJareckiKrawczykRabinDKG
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i), mpz_clear(y);

	// release subprotocols
	delete x_rvss;
	delete d_rvss;

	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

CanettiGennaroJareckiKrawczykRabinDSS::CanettiGennaroJareckiKrawczykRabinDSS
	(const size_t n_in, const size_t t_in, const size_t i_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			n(n_in), t(t_in), i(i_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS), mpz_init_set(h, h_CRS);
	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L), mpz_init_set_ui(y, 1L);

	// initialize required subprotocols
	dkg = new CanettiGennaroJareckiKrawczykRabinDKG(n, t, i, p, q, g, h, fieldsize, subgroupsize, use_very_strong_randomness_in, "dkg");

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

CanettiGennaroJareckiKrawczykRabinDSS::CanettiGennaroJareckiKrawczykRabinDSS
	(std::istream &in,
	const unsigned long int fieldsize,
	const unsigned long int subgroupsize,
	const bool use_very_strong_randomness_in):
			F_size(fieldsize), G_size(subgroupsize),
			use_very_strong_randomness(use_very_strong_randomness_in),
			n(0), t(0), i(0)
{
	std::string value;

	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	std::getline(in, value);
	std::stringstream(value) >> n;
	if (n > TMCG_MAX_DKG_PLAYERS)
		n = TMCG_MAX_DKG_PLAYERS;
	std::getline(in, value);
	std::stringstream(value) >> t;
	if (t > n)
		t = n;
	std::getline(in, value);
	std::stringstream(value) >> i;
	if (i >= n)
		i = 0;
	mpz_init(x_i), mpz_init(xprime_i), mpz_init(y);
	in >> x_i >> xprime_i >> y;
	size_t qual_size = 0;
	std::getline(in, value);
	std::stringstream(value) >> qual_size;
	for (size_t j = 0; (j < qual_size) && (j < n); j++)
	{
		size_t who;
		std::getline(in, value);
		std::stringstream(value) >> who;
		QUAL.push_back(who);
	}

	// initialize required subprotocols
	dkg = new CanettiGennaroJareckiKrawczykRabinDKG(n, t, i, p, q, g, h, fieldsize, subgroupsize, use_very_strong_randomness_in, "dkg");

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void CanettiGennaroJareckiKrawczykRabinDSS::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl;
	out << x_i << std::endl << xprime_i << std::endl << y << std::endl;
	out << QUAL.size() << std::endl;
	for (size_t i = 0; i < QUAL.size(); i++)
		out << QUAL[i] << std::endl;
}

bool CanettiGennaroJareckiKrawczykRabinDSS::CheckGroup
	() const
{
	mpz_t foo, bar, k, g2;

	mpz_init(foo), mpz_init(bar), mpz_init(k), mpz_init(g2);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
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
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_fpowm(fpowm_table_g, foo, g, q, p);
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

		// We use a procedure similar to FIPS 186-3 A.2.3;
		// it is supposed as verifiable generation of $g$.
		std::stringstream U;
		U << "LibTMCG|" << p << "|" << q << "|ggen|";
		mpz_sub_ui(bar, p, 1L); // compute $p-1$
		do
		{
			mpz_shash(foo, U.str());
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

bool CanettiGennaroJareckiKrawczykRabinDSS::CheckElement
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

bool CanettiGennaroJareckiKrawczykRabinDSS::Generate
	(aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinDSS::Generate()" << p << q << g << h << n << t;
	rbc->setID(myID.str());

	try
	{
		// call DKG as subprotocol
		if (!dkg->Generate(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;

		// copy the generated $y$, $x_i$, and $x\prime_i$
		mpz_set(y, dkg->y);
		mpz_set(x_i, dkg->x_i);
		mpz_set(xprime_i, dkg->xprime_i);

		// copy the set of non-disqualified players
		QUAL.clear();
		for (size_t i = 0; i < dkg->QUAL.size(); i++)
			QUAL.push_back(dkg->QUAL[i]);

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

bool CanettiGennaroJareckiKrawczykRabinDSS::Sign
	(const size_t n_in, const size_t i_in,
	mpz_srcptr m, mpz_ptr r, mpz_ptr s,
	aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(n_in <= n);
	assert(i_in < n_in);
	assert(n_in == rbc->n);
	assert(n_in == aiou->n);
	assert(i_in == rbc->j);
	assert(i_in == aiou->j);

	// checking maximum synchronous t-resilience of DSS
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	CanettiGennaroJareckiKrawczykRabinRVSS *k_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n_in, t, i_in, t, p, q, g, h, 
		F_size, G_size, false, "k_rvss");
	CanettiGennaroJareckiKrawczykRabinDKG *a_dkg = new CanettiGennaroJareckiKrawczykRabinDKG(n_in, t, i_in, p, q, g, h, 
		F_size, G_size, false, "a_dkg");
	CanettiGennaroJareckiKrawczykRabinRVSS *d_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n_in, t, i_in, t, p, q, g, h,
		F_size, G_size, false, "d_rvss");
	CanettiGennaroJareckiKrawczykRabinRVSS *dd_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n_in, t, i_in, t, p, q, g, h,
		F_size, G_size, false, "dd_rvss");
	CanettiGennaroJareckiKrawczykRabinRVSS *ddd_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n_in, t, i_in, t, p, q, g, h,
		F_size, G_size, false, "ddd_rvss");
	CanettiGennaroJareckiKrawczykRabinRVSS *dddd_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n_in, t, i_in, t, p, q, g, h,
		F_size, G_size, false, "dddd_rvss");
	std::vector<PedersenVSS*> k_i_vss, a_i_vss, v_i_vss, aa_i_vss, vv_i_vss;
	for (size_t j = 0; j < n_in; j++)
	{
		std::stringstream k_i_vss_label, a_i_vss_label, v_i_vss_label, aa_i_vss_label, vv_i_vss_label;
		k_i_vss_label << "k_i_vss[dealer = " << j << "]";
		k_i_vss.push_back(new PedersenVSS(n_in, t, i_in, p, q, g, h, F_size, G_size, false, k_i_vss_label.str()));
		a_i_vss_label << "a_i_vss[dealer = " << j << "]";
		a_i_vss.push_back(new PedersenVSS(n_in, t, i_in, p, q, g, h, F_size, G_size, false, a_i_vss_label.str()));
		v_i_vss_label << "v_i_vss[dealer = " << j << "]";
		v_i_vss.push_back(new PedersenVSS(n_in, t, i_in, p, q, g, h, F_size, G_size, false, v_i_vss_label.str()));
		aa_i_vss_label << "aa_i_vss[dealer = " << j << "]";
		aa_i_vss.push_back(new PedersenVSS(n_in, t, i_in, p, q, g, h, F_size, G_size, false, aa_i_vss_label.str()));
		vv_i_vss_label << "vv_i_vss[dealer = " << j << "]";
		vv_i_vss.push_back(new PedersenVSS(n_in, t, i_in, p, q, g, h, F_size, G_size, false, vv_i_vss_label.str()));
	}
	mpz_t foo, bar, lhs, rhs, kprime_i, aprime_i, rho_i, sigma_i, d, r_k_i, r_a_i, tau_i, dd, ee, ss, ssprime, tt, mu;
	std::vector<mpz_ptr> k_i, a_i, alpha_i, beta_i, gamma_i, delta_i, v_i, chi_i, Tk_i, Ta_i, d_i, dprime_i, DD, DDprime, EE, shares, lambda_j;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs), mpz_init(kprime_i), mpz_init(aprime_i), mpz_init(rho_i),
		mpz_init(sigma_i), mpz_init(d), mpz_init(r_k_i), mpz_init(r_a_i), mpz_init(tau_i), mpz_init(dd), mpz_init(ee),
		mpz_init(ss), mpz_init(ssprime), mpz_init(tt), mpz_init(mu);
	for (size_t j = 0; j < n_in; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(), tmp4 = new mpz_t();
		mpz_ptr tmp5 = new mpz_t(), tmp6 = new mpz_t(), tmp7 = new mpz_t(), tmp8 = new mpz_t();
		mpz_ptr tmp9 = new mpz_t(), tmp10 = new mpz_t(), tmp11 = new mpz_t(), tmp12 = new mpz_t();
		mpz_ptr tmp13 = new mpz_t(), tmp14 = new mpz_t(), tmp15 = new mpz_t(), tmp16 = new mpz_t();
		mpz_ptr tmp17 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		mpz_init(tmp5), mpz_init(tmp6), mpz_init(tmp7), mpz_init(tmp8);
		mpz_init(tmp9), mpz_init(tmp10), mpz_init(tmp11), mpz_init(tmp12);
		mpz_init(tmp13), mpz_init(tmp13), mpz_init(tmp15), mpz_init(tmp16);
		mpz_init(tmp17);
		k_i.push_back(tmp1), a_i.push_back(tmp2), alpha_i.push_back(tmp3), beta_i.push_back(tmp4);
		gamma_i.push_back(tmp5), delta_i.push_back(tmp6), v_i.push_back(tmp7), chi_i.push_back(tmp8);
		Tk_i.push_back(tmp9), Ta_i.push_back(tmp10), d_i.push_back(tmp11), dprime_i.push_back(tmp12);
		DD.push_back(tmp13), DDprime.push_back(tmp14), EE.push_back(tmp15), shares.push_back(tmp16);
		lambda_j.push_back(tmp17);
	}
	size_t simulate_faulty_randomizer[50];
	for (size_t idx = 0; idx < 50; idx++)
		simulate_faulty_randomizer[idx] = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinDSS::Sign()" << p << q << g << h << n << t << m;
	rbc->setID(myID.str());

	try
	{
		if (n_in < ((2 * t) + 1))
		{
			err << "P_" << i_in << ": not enough players (< 2t+1) for signing" << std::endl;
			throw false;
		}

		// 1. Generate $r = g^{k^{-1}} \bmod p \bmod q$
		//    (a) Generate $k$. Players execute Joint-RVSS(t).
		if (!k_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[0])
			throw false;
		//        Player $P_i$ sets $k_i, k\prime_i$ to his share of the secret and the auxiliary secret.
		mpz_set(k_i[i_in], k_rvss->x_i), mpz_set(kprime_i, k_rvss->xprime_i);
		//        For each $i$ the value $\alpha_i = g^{k_i} h^{k\prime_i} \bmod p$ is public.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set_ui(alpha_i[j], 1L);
			for (std::vector<size_t>::iterator it = k_rvss->QUAL.begin(); it != k_rvss->QUAL.end(); ++it)
			{
				for (size_t k = 0; k <= k_rvss->t; k++)
				{
					mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
					mpz_powm(bar, k_rvss->C_ik[*it][k], foo, p);
					mpz_mul(alpha_i[j], alpha_i[j], bar);
					mpz_mod(alpha_i[j], alpha_i[j], p);
				}
			}
		}
		//    (b) Generate a random value $a$ and $g^a \bmod p$ using (the optimally-resilient) DL-Key-Gen.
		if (!a_dkg->Generate(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[1])
			throw false;
		//        Player $P_i$ sets $a_i, a\prime_i$ to his share of the secret $a$ and the auxiliary secret.
		mpz_set(a_i[i_in], a_dkg->x_i), mpz_set(aprime_i, a_dkg->xprime_i);
		//        For each $i$ the value $\beta_i = g^{a_i} h^{a\prime_i} \bmod p$ is public.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set_ui(beta_i[j], 1L);
			for (std::vector<size_t>::iterator it = a_dkg->x_rvss->QUAL.begin(); it != a_dkg->x_rvss->QUAL.end(); ++it)
			{
				for (size_t k = 0; k <= a_dkg->x_rvss->t; k++)
				{
					mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
					mpz_powm(bar, a_dkg->x_rvss->C_ik[*it][k], foo, p);
					mpz_mul(beta_i[j], beta_i[j], bar);
					mpz_mod(beta_i[j], beta_i[j], p);
				}
			}
		}
		//    (c) Back-up $k_i$ and $a_i$. Each player $P_i$ shares $k_i$ and $a_i$ using Pedersen's VSS.
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!k_i_vss[j]->Share(j, aiou, rbc, err, simulate_faulty_behaviour))
					err << "P_" << i_in << ": WARNING - VSS of k_i failed for P_" << j << std::endl;
				if (!a_i_vss[j]->Share(j, aiou, rbc, err, simulate_faulty_behaviour))
					err << "P_" << i_in << ": WARNING - VSS of a_i failed for P_" << j << std::endl;
			}
			else
			{
				err << "P_" << i_in << ": k_i = " << k_i[i_in] << std::endl;
				err << "P_" << i_in << ": a_i = " << a_i[i_in] << std::endl;
				if (!k_i_vss[j]->Share(k_i[i_in], aiou, rbc, err, simulate_faulty_behaviour))
					throw false;
				if (!a_i_vss[j]->Share(a_i[i_in], aiou, rbc, err, simulate_faulty_behaviour))
					throw false;
			}
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[2])
			throw false;
		//        The values $\gamma_i = g^{k_i} h^{\rho_i} \bmod p$ and $\delta_i = g^{a_i} h^{\sigma_i}$
		//        (for some randomizers $\rho_i, \sigma_i$) are public.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set(gamma_i[j], k_i_vss[j]->A_j[0]);
			mpz_set(delta_i[j], a_i_vss[j]->A_j[0]);
			if (j == i_in)
			{
				mpz_set(rho_i, k_i_vss[i_in]->b_j[0]);
				mpz_set(sigma_i, a_i_vss[i_in]->b_j[0]);
			}
		}
		//        $P_i$ is required to prove in ZK that the value committed to in $\alpha_i$ (resp. $\beta_i$)
		//        is the same value committed to in $\gamma_i$ (resp. $\delta_i$). This ist done using a
		//        zero-knowledge proof from [CD98]. This is a 3-move public coin proof and it is performed
		//        by all players together computing the challenge as in Steps 3-4 of (the optimally-resilient)
		//        DL-Key-Gen. Ignore those that fail this step. At least $t+1$ good players will pass it.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			err << "P_" << i_in << ": alpha_i[" << j << "] = " << alpha_i[j] << std::endl;
			err << "P_" << i_in << ": beta_i[" << j << "] = " << beta_i[j] << std::endl;
			err << "P_" << i_in << ": gamma_i[" << j << "] = " << gamma_i[j] << std::endl;
			err << "P_" << i_in << ": delta_i[" << j << "] = " << delta_i[j] << std::endl;
		}
		err << "P_" << i_in << ": kprime_i = " << kprime_i << std::endl;
		err << "P_" << i_in << ": aprime_i = " << aprime_i << std::endl;
		err << "P_" << i_in << ": rho_i = " << rho_i << std::endl;
		err << "P_" << i_in << ": sigma_i = " << sigma_i << std::endl;
		//        Broadcast commitments for the zero-knowledge proofs of knowledge (we use presentation from [BCCG15]).
		//        Then we show in parallel, that commitment $\alpha_i \gamma_i^{-1}$ resp. $\beta_i \delta_i^{-1}$
		//        equals zero, i.e., the former commitment was made to the same value $k_i$ resp. $a_i$. This works
		//        since Pedersen commitments have homomorphic properties.
		mpz_srandomm(r_k_i, q), mpz_srandomm(r_a_i, q);
		mpz_fspowm(fpowm_table_h, Tk_i[i_in], h, r_k_i, p);
		mpz_fspowm(fpowm_table_h, Ta_i[i_in], h, r_a_i, p);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j == i_in)
			{
				rbc->Broadcast(Tk_i[i_in]);
				rbc->Broadcast(Ta_i[i_in]);
			}
			else
			{
				if (!rbc->DeliverFrom(Tk_i[j], j))
				{
					err << "P_" << i_in << ": receiving Tk_i failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(Ta_i[j], j))
				{
					err << "P_" << i_in << ": receiving Ta_i failed for P_" << j << std::endl;
					continue;
				}
				if (!CheckElement(Tk_i[j]))
				{
					err << "P_" << i_in << ": bad Tk_i received from P_" << j << std::endl;
					mpz_set_ui(Tk_i[j], 0L); // indicates an error
				}
				if (!CheckElement(Ta_i[j]))
				{
					err << "P_" << i_in << ": bad Ta_i received from P_" << j << std::endl;
					mpz_set_ui(Ta_i[j], 0L); // indicates an error
				}
			}
		}
		//        Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//        his local share of the secret challenge to $d_i$. (In [CD98] this callenge is called $e$.)
		if (!d_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[3])
			throw false;
		mpz_set(d_i[i_in], d_rvss->z_i), mpz_set(dprime_i[i_in], d_rvss->zprime_i);
		std::vector<size_t> d_complaints;
		//        Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		for (size_t j = 0; j < n_in; j++)
		{
			if ((j == i_in) && (std::find(d_rvss->QUAL.begin(), d_rvss->QUAL.end(), j) != d_rvss->QUAL.end()))
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[4])
					mpz_add_ui(d_i[i_in], d_i[i_in], 1L);
				rbc->Broadcast(d_i[i_in]);
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[5])
					mpz_add_ui(dprime_i[i_in], dprime_i[i_in], 1L);
				rbc->Broadcast(dprime_i[i_in]);
			}
			else if ((j != i_in) && (std::find(d_rvss->QUAL.begin(), d_rvss->QUAL.end(), j) != d_rvss->QUAL.end()))
			{
				if (!rbc->DeliverFrom(d_i[j], j))
				{
					err << "P_" << i_in << ": receiving d_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(d_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad d_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(d_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(dprime_i[j], j))
				{
					err << "P_" << i_in << ": receiving dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(dprime_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad dprime_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(dprime_i[j], 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, foo, g, d_i[j], p);
				mpz_fpowm(fpowm_table_h, bar, h, dprime_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, d_rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": checking d_i resp. dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
				}
			}
			else
				err << "P_" << i_in << ": WARNING - P_" << j << " not in QUAL of d_rvss" << std::endl;
		}
		//        Public reconstruction of $d_j$, for every failed player $P_j$
		std::sort(d_complaints.begin(), d_complaints.end());
		std::vector<size_t>::iterator it = std::unique(d_complaints.begin(), d_complaints.end());
		d_complaints.resize(std::distance(d_complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of d_rvss against ";
		for (std::vector<size_t>::iterator it = d_complaints.begin(); it != d_complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!d_rvss->Reconstruct(d_complaints, d_i, rbc, err))
		{
			err << "P_" << i_in << ": reconstruction of d_i in Step 1c failed" << std::endl;
			throw false;
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[6])
			throw false;
		//        Get $d = \sum_{P_i \in QUAL} d_i$
		mpz_set_ui(d, 0L);
		for (std::vector<size_t>::iterator it = d_rvss->QUAL.begin(); it != d_rvss->QUAL.end(); ++it)
		{
			mpz_add(d, d, d_i[*it]);
			mpz_mod(d, d, q);
		}
		err << "P_" << i_in << ": d = " << d << std::endl;
		//        Broadcast the reponses $z_{k_i} = r_{k_i} + (k\prime_i - \rho_i) \cdot d \bmod q$
		//        and $z_{a_i} = r_{a_i} + (a\prime_i - \sigma_i) \cdot d$ and verify the results.
		mpz_sub(foo, kprime_i, rho_i);
		mpz_mod(foo, foo, q);
		mpz_mul(foo, foo, d);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, r_k_i);
		mpz_mod(foo, foo, q);
		mpz_sub(bar, aprime_i, sigma_i);
		mpz_mod(bar, bar, q);
		mpz_mul(bar, bar, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, r_a_i);
		mpz_mod(bar, bar, q);
		rbc->Broadcast(foo);
		rbc->Broadcast(bar);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo received from P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar received from P_" << j << std::endl;
					continue;
				}
				if (!mpz_invert(rhs, gamma_i[j], p))
				{
					err << "P_" << i_in << ": cannot invert gamma_i from P_" << j << std::endl;
					continue;
				}
				mpz_mul(rhs, rhs, alpha_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_powm(rhs, rhs, d, p);
				mpz_mul(rhs, rhs, Tk_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_fpowm(fpowm_table_h, lhs, h, foo, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": ZNPoK for k_i in Step 1c failed for P_" << j << std::endl;
					continue;
				}
				if (!mpz_invert(rhs, delta_i[j], p))
				{
					err << "P_" << i_in << ": cannot invert delta_i from P_" << j << std::endl;
					continue;
				}
				mpz_mul(rhs, rhs, beta_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_powm(rhs, rhs, d, p);
				mpz_mul(rhs, rhs, Ta_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": ZNPoK for a_i in Step 1c failed for P_" << j << std::endl;
					continue;
				}
			}
		}
		//    (d) Each player $P_i, i = 1, \ldots, 2t + 1$, shares its value $v_i = k_i a_i \bmod q$
		//        using Pedersen's VSS.
		std::vector<size_t> complaints;
		mpz_mul(v_i[i_in], k_i[i_in], a_i[i_in]);
		mpz_mod(v_i[i_in], v_i[i_in], q);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[7])
			mpz_add_ui(v_i[i_in], v_i[i_in], 1L);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!v_i_vss[j]->Share(j, aiou, rbc, err, simulate_faulty_behaviour))
					err << "P_" << i_in << ": WARNING - VSS of v_i failed; complaint against P_" << j << std::endl;
			}
			else
			{
				err << "P_" << i_in << ": v_i = " << v_i[i_in] << std::endl;
				if (!v_i_vss[j]->Share(v_i[i_in], aiou, rbc, err, simulate_faulty_behaviour))
					throw false;
			}
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[8])
			throw false;
		//        The values $\chi_i = g^{k_i a_i} h^{\tau_i}, i = 1, \ldots, 2t + 1$, (for some
		//        randomizers $\tau_i$) are public.
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set(chi_i[j], v_i_vss[j]->A_j[0]);
			if (j == i_in)
				mpz_set(tau_i, v_i_vss[i_in]->b_j[0]);
		}
		for (size_t j = 0; j < n_in; j++)
		{
			err << "P_" << i_in << ": chi_i[" << j << "] = " << chi_i[j] << std::endl;
		}
		err << "P_" << i_in << ": tau_i = " << tau_i << std::endl;
		//        Each $P_i$ proves in ZK that the value committed in $\chi_i$ is the product
		//        of the values committed to in $\alpha_i$ and $\beta_i$. This is done using
		//        a zero-knowledge proof from [CD98]. This is a 3-move public coin proof and
		//        it is performed by all players as above.
		//        (We use the simplified presentation from [BCCG15] called $\Sigma_{prod}$.)
		mpz_srandomm(dd, q), mpz_srandomm(ee, q), mpz_srandomm(ss, q), mpz_srandomm(ssprime, q), mpz_srandomm(tt, q);
		mpz_fspowm(fpowm_table_g, foo, g, dd, p);
		mpz_fspowm(fpowm_table_h, bar, h, ss, p);
		mpz_mul(DD[i_in], foo, bar);
		mpz_mod(DD[i_in], DD[i_in], p);
		mpz_spowm(foo, beta_i[i_in], dd, p);
		mpz_fspowm(fpowm_table_h, bar, h, ssprime, p);
		mpz_mul(DDprime[i_in], foo, bar);
		mpz_mod(DDprime[i_in], DDprime[i_in], p);
		mpz_fspowm(fpowm_table_g, foo, g, ee, p);
		mpz_fspowm(fpowm_table_h, bar, h, tt, p);
		mpz_mul(EE[i_in], foo, bar);
		mpz_mod(EE[i_in], EE[i_in], p);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j == i_in)
			{
				rbc->Broadcast(DD[i_in]);
				rbc->Broadcast(DDprime[i_in]);
				rbc->Broadcast(EE[i_in]);
			}
			else
			{
				if (!rbc->DeliverFrom(DD[j], j))
				{
					err << "P_" << i_in << ": receiving DD failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!rbc->DeliverFrom(DDprime[j], j))
				{
					err << "P_" << i_in << ": receiving DDprime failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!rbc->DeliverFrom(EE[j], j))
				{
					err << "P_" << i_in << ": receiving EE failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(DD[j]))
				{
					err << "P_" << i_in << ": bad DD received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(DD[j], 0L); // indicates an error
				}
				if (!CheckElement(DDprime[j]))
				{
					err << "P_" << i_in << ": bad DDprime received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(DDprime[j], 0L); // indicates an error
				}
				if (!CheckElement(EE[j]))
				{
					err << "P_" << i_in << ": bad EE received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(EE[j], 0L); // indicates an error
				}
			}
		}
		//        Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//        his local share of the secret challenge to $d_i$. (In [CD98] this callenge is called $e$
		//        and in [BCCG15] it is called $x$.)
		if (!dd_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[9])
			throw false;
		mpz_set(d_i[i_in], dd_rvss->z_i), mpz_set(dprime_i[i_in], dd_rvss->zprime_i);
		d_complaints.clear();
		//        Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		for (size_t j = 0; j < n_in; j++)
		{
			if ((j == i_in) && (std::find(dd_rvss->QUAL.begin(), dd_rvss->QUAL.end(), j) != dd_rvss->QUAL.end()))
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[10])
					mpz_add_ui(d_i[i_in], d_i[i_in], 1L);
				rbc->Broadcast(d_i[i_in]);
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[11])
					mpz_add_ui(dprime_i[i_in], dprime_i[i_in], 1L);
				rbc->Broadcast(dprime_i[i_in]);
			}
			else if ((j != i_in) && (std::find(dd_rvss->QUAL.begin(), dd_rvss->QUAL.end(), j) != dd_rvss->QUAL.end()))
			{
				if (!rbc->DeliverFrom(d_i[j], j))
				{
					err << "P_" << i_in << ": receiving d_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(d_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad d_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(d_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(dprime_i[j], j))
				{
					err << "P_" << i_in << ": receiving dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(dprime_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad dprime_i received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(dprime_i[j], 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, foo, g, d_i[j], p);
				mpz_fpowm(fpowm_table_h, bar, h, dprime_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, dd_rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": checking d_i resp. dprime_i failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
				}
			}
			else
				err << "P_" << i_in << ": WARNING - P_" << j << " not in QUAL of dd_rvss" << std::endl;
		}
		//        Public reconstruction of $d_j$, for every failed player $P_j$
		std::sort(d_complaints.begin(), d_complaints.end());
		it = std::unique(d_complaints.begin(), d_complaints.end());
		d_complaints.resize(std::distance(d_complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of dd_rvss against ";
		for (std::vector<size_t>::iterator it = d_complaints.begin(); it != d_complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!dd_rvss->Reconstruct(d_complaints, d_i, rbc, err))
		{
			err << "P_" << i_in << ": reconstruction of d_i in Step 1d failed" << std::endl;
			throw false;
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[12])
			throw false;
		//        Get $d = \sum_{P_i \in QUAL} d_i$
		mpz_set_ui(d, 0L);
		for (std::vector<size_t>::iterator it = dd_rvss->QUAL.begin(); it != dd_rvss->QUAL.end(); ++it)
		{
			mpz_add(d, d, d_i[*it]);
			mpz_mod(d, d, q);
		}
		err << "P_" << i_in << ": d = " << d << std::endl;
		//        Broadcast the responses...
		//        $f_1 = k_i d + dd \bmod q$
		mpz_mul(foo, k_i[i_in], d);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, dd);
		mpz_mod(foo, foo, q);
		//        $z_1 = kprime_i d + ss \bmod q$
		mpz_mul(bar, kprime_i, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, ss);
		mpz_mod(bar, bar, q);
		//        $f_2 = a_i d + ee \bmod q$
		mpz_mul(lhs, a_i[i_in], d);
		mpz_mod(lhs, lhs, q);
		mpz_add(lhs, lhs, ee);
		mpz_mod(lhs, lhs, q);
		//        $z_2 = aprime_i d + tt \bmod q$
		mpz_mul(rhs, aprime_i, d);
		mpz_mod(rhs, rhs, q);
		mpz_add(rhs, rhs, tt);
		mpz_mod(rhs, rhs, q);
		rbc->Broadcast(foo);
		rbc->Broadcast(bar);
		rbc->Broadcast(lhs);
		rbc->Broadcast(rhs);
		//        $z_3 = (\tau_i - k_i aprime_i) d + ssprime$
		mpz_mul(foo, k_i[i_in], aprime_i);
		mpz_mod(foo, foo, q);
		mpz_sub(bar, tau_i, foo);
		mpz_mod(bar, bar, q);
		mpz_mul(bar, bar, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, ssprime);
		mpz_mod(bar, bar, q);
		rbc->Broadcast(bar);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_set(ssprime, foo); // save $f_1$ for third ZNPoK
				mpz_fpowm(fpowm_table_g, rhs, g, foo, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, alpha_i[j], d, p);
				mpz_mul(rhs, rhs, DD[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": first ZNPoK in Step 1d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, rhs, g, foo, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, beta_i[j], d, p);
				mpz_mul(rhs, rhs, EE[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": second ZNPoK in Step 1d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_powm(rhs, beta_i[j], ssprime, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, chi_i[j], d, p);
				mpz_mul(rhs, rhs, DDprime[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": third ZNPoK in Step 1d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}	
			}
		}
		//    (e) If player $P_j$ fails the proof in the above step, his shares $a_j, k_j$ are publicly
		//        reconstructed via interpolation of the back-ups of shares distributed in Step 1c.
		//        Since each $a_j$ (resp. $k_j$) can be computed as a linear combination of some $t+1$
		//        values $a_i$ (resp. $k_i$) that were properly shared in Step 1c, each player broadcasts
		//        the appropriate linear combination of its shares of these $a_i$'s (resp. $k_i$'s),
		//        together with their associated randomness (computed as the same linear combination of
		//        the associated randomness generated in Step 1c). Bad values are sieved out using the
		//        public commitments of Step 1c, $a_j$ and $k_j$ are reconstructed, and $v_j$ is set to
		//        $a_j k_j$.
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of v_j against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			if (*it != i_in)
			{
				mpz_set_ui(foo, 0L), mpz_set_ui(bar, 0L);
				if (!k_i_vss[*it]->Reconstruct(*it, foo, rbc, err))
				{
					err << "P_" << i_in << ": reconstruction of k_j failed for P_" << *it << std::endl;	
					throw false;
				}
				if (!a_i_vss[*it]->Reconstruct(*it, bar, rbc, err))
				{
					err << "P_" << i_in << ": reconstruction of a_j failed for P_" << *it << std::endl;	
					throw false;
				}
				mpz_mul(v_i[*it], foo, bar);
				mpz_mod(v_i[*it], v_i[*it], q);
			}
			err << "P_" << i_in << ": v_i[" << *it << "] = " << v_i[*it] << std::endl;
		}
		//    (f) The value $\mu = ka$ is a linear combination of the values $v_1, \ldots, v_{2t+1}$.
		//        Thus it can be computed interpolating the polynomial of degree $t$ which is a linear
		//        combination of the polynomials used in Step 1d to share $v_1, \ldots, v_{2t+1}$.
		//        Each player broadcasts its share (together with its associated randomness) of that
		//        $t$-degree polynomial, which is itself a linear combination of the shares of
		//        $v_1, \ldots, v_{2t+1}$ received in Step 1d. For the $v_j$'s that were exposed in
		//        Step 1e, we use the constant sharing polynomial. Bad shares are detected using the
		//        public commitments, and $\mu$ is reconstructed.
		std::vector<size_t> signers;
		for (size_t j = 0; j < n_in; j++)
			signers.push_back(j);
		mpz_set_ui(foo, 0L), mpz_set_ui(bar, 0L);
		for (std::vector<size_t>::iterator jt = signers.begin(); jt != signers.end(); ++jt)
		{
			
			mpz_set_ui(lhs, 1L); // compute the optimized Lagrange multipliers
			for (std::vector<size_t>::iterator lt = signers.begin(); lt != signers.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(rhs, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(rhs, rhs, (*jt + 1)); // adjust index in computation
					mpz_mul(lhs, lhs, rhs);
				}
			}
			if (!mpz_invert(lhs, lhs, q))
			{
				err << "P_" << i_in << ": cannot invert LHS during computation of linear combination for P_" << *jt << std::endl;
				throw false;
			}
			mpz_set_ui(rhs, 1L);
			for (std::vector<size_t>::iterator lt = signers.begin(); lt != signers.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index in computation
			}
			mpz_mul(lambda_j[*jt], rhs, lhs);
			mpz_mod(lambda_j[*jt], lambda_j[*jt], q);
			if (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end())
			{
				mpz_mul(rhs, lambda_j[*jt], v_i_vss[*jt]->sigma_i);
				mpz_mod(rhs, rhs, q);
				mpz_add(foo, foo, rhs);
				mpz_mod(foo, foo, q);
				mpz_mul(rhs, lambda_j[*jt], v_i_vss[*jt]->tau_i);
				mpz_mod(rhs, rhs, q);
				mpz_add(bar, bar, rhs);
				mpz_mod(bar, bar, q);
			}
			else
			{
				mpz_mul(rhs, lambda_j[*jt], v_i[*jt]);
				mpz_mod(rhs, rhs, q);
				mpz_add(foo, foo, rhs);
				mpz_mod(foo, foo, q);
			}
		}
		rbc->Broadcast(foo);
		rbc->Broadcast(bar);
		std::vector<size_t> parties;
		parties.push_back(i_in); // shares of this player are always available
		mpz_set(shares[i_in], foo);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo received from P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar received from P_" << j << std::endl;
					continue;
				}
				mpz_set(shares[j], foo); // save the share for later following reconstruction
				// compute LHS for the check
				mpz_fpowm(fpowm_table_g, foo, g, foo, p);
				mpz_fpowm(fpowm_table_h, bar, h, bar, p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				for (std::vector<size_t>::iterator jt = signers.begin(); jt != signers.end(); ++jt)
				{
					if (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end())
					{
						mpz_set_ui(bar, 1L);
						for (size_t k = 0; k < v_i_vss[*jt]->A_j.size(); k++)
						{
							mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
							mpz_powm(foo, v_i_vss[*jt]->A_j[k], foo, p);
							mpz_mul(bar, bar, foo);
							mpz_mod(bar, bar, p);
						}	
					}
					else
					{
						mpz_fpowm(fpowm_table_g, bar, g, v_i[*jt], p);
					}
					mpz_powm(bar, bar, lambda_j[*jt], p); // include Lagrange multipliers
					mpz_mul(rhs, rhs, bar);
					mpz_mod(rhs, rhs, p);
				}
				// check equation (1)
				if (mpz_cmp(lhs, rhs))
					err << "P_" << i_in << ": bad share received from " << j << std::endl;
				else
					parties.push_back(j);
			}
		}
		// check whether enough shares (i.e. $t + 1$) have been collected
		if (parties.size() <= t)
		{
			err << "P_" << i_in << ": not enough shares collected for reconstructing mu" << std::endl;
			throw false;
		}
		if (parties.size() > (t + 1))
			parties.resize(t + 1);
		err << "P_" << i_in << ": reconstructing parties = ";
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
			err << "P_" << *jt << " ";
		err << std::endl;
		// compute $\mu$ by Lagrange interpolation
		mpz_set_ui(mu, 0L);
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
		{
			mpz_set_ui(lhs, 1L); // compute the optimized Lagrange multipliers
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(rhs, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(rhs, rhs, (*jt + 1)); // adjust index in computation
					mpz_mul(lhs, lhs, rhs);
				}
			}
			if (!mpz_invert(lhs, lhs, q))
			{
				err << "P_" << i_in << ": cannot invert LHS during reconstruction" << std::endl;
				throw false;
			}
			mpz_set_ui(rhs, 1L);
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index in computation
			}
			mpz_mul(rhs, rhs, lhs);
			mpz_mod(rhs, rhs, q);
			mpz_mul(rhs, rhs, shares[*jt]); // use the provided shares (interpolation points)
			mpz_mod(rhs, rhs, q);
			mpz_add(mu, mu, rhs);
			mpz_mod(mu, mu, q);
		}
		parties.clear();
		err << "P_" << i_in << ": mu = " << mu << std::endl;
		//    (g) Player $P_i$ computes locally $\mu^{-1} \bmod q$ and $r = (g^a)^{\mu^{-1}} \bmod p \bmod q$.
		if (!mpz_invert(foo, mu, q))
		{
			err << "P_" << i_in << ": cannot invert mu" << std::endl;
			throw false;
		}
		mpz_powm(r, a_dkg->y, foo, p);
		mpz_mod(r, r, q);
		err << "P_" << i_in << ": r = " << r << std::endl;

		// 2. Generate $s = k(m + xr) \bmod q$
		//    To reconstruct $s = k(m + xr)$, players perform steps equivalent to Steps 1c-1f above, with the
		//    values $m + x_i r$ taking the role of the $a_i$'s, and with $s$ taking the role of $\mu$. The
		//    only difference is that in the back-up step equivalent to Step 1c above, the players need only to
		//    create the back-ups of the $m + x_i r$ values. In the following steps (equivalent to Steps 1d-1f
		//    above), the players reuse the back-ups of the $k_i$ values that were created in Step 1c.
		mpz_mod(m, m, q);
		mpz_mul(a_i[i_in], x_i, r);
		mpz_mod(a_i[i_in], a_i[i_in], q);
		mpz_add(a_i[i_in], a_i[i_in], m);
		mpz_mod(a_i[i_in], a_i[i_in], q);
		mpz_mul(aprime_i, xprime_i, r);
		mpz_mod(aprime_i, aprime_i, q);
		mpz_add(aprime_i, aprime_i, m);
		mpz_mod(aprime_i, aprime_i, q);
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set_ui(beta_i[j], 1L);
			for (std::vector<size_t>::iterator it = dkg->x_rvss->QUAL.begin(); it != dkg->x_rvss->QUAL.end(); ++it)
			{
				for (size_t k = 0; k <= dkg->x_rvss->t; k++)
				{
					mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
					mpz_powm(bar, dkg->x_rvss->C_ik[*it][k], foo, p);
					mpz_mul(beta_i[j], beta_i[j], bar);
					mpz_mod(beta_i[j], beta_i[j], p);
				}
			}
			mpz_powm(beta_i[j], beta_i[j], r, p);
			mpz_fpowm(fpowm_table_g, foo, g, m, p);
			mpz_fpowm(fpowm_table_h, bar, h, m, p);
			mpz_mul(beta_i[j], beta_i[j], foo);
			mpz_mod(beta_i[j], beta_i[j], p);
			mpz_mul(beta_i[j], beta_i[j], bar);
			mpz_mod(beta_i[j], beta_i[j], p);
		}
		//    (c) Back-up $a_i$. Each player $P_i$ shares $a_i$ using Pedersen's VSS.
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!aa_i_vss[j]->Share(j, aiou, rbc, err, simulate_faulty_behaviour))
					err << "P_" << i_in << ": WARNING - VSS of a_i (in Step 2c) failed for P_" << j << std::endl;
			}
			else
			{
				err << "P_" << i_in << ": a_i (Step 2c) = " << a_i[i_in] << std::endl;
				if (!aa_i_vss[j]->Share(a_i[i_in], aiou, rbc, err, simulate_faulty_behaviour))
					throw false;
			}
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[13])
			throw false;
		//        The values $\delta_i = g^{a_i} h^{\sigma_i}$ (for some randomizers $\sigma_i$) are public.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set(delta_i[j], aa_i_vss[j]->A_j[0]);
			if (j == i_in)
				mpz_set(sigma_i, aa_i_vss[i_in]->b_j[0]);
		}
		//        $P_i$ is required to prove in ZK that the value committed to in $\beta_i$ is the same
		//        value committed to in $\delta_i$. This ist done using a zero-knowledge proof from [CD98].
		//        This is a 3-move public coin proof and it is performed by all players together computing
		//        the challenge as in Steps 3-4 of (the optimally-resilient) DL-Key-Gen. Ignore those that
		//        fail this step. At least $t+1$ good players will pass it.
		//        (Note that indices $i$ and $j$ are changed for convenience.)
		for (size_t j = 0; j < n_in; j++)
		{
			err << "P_" << i_in << ": beta_i[" << j << "] (Step 2c) = " << beta_i[j] << std::endl;
			err << "P_" << i_in << ": delta_i[" << j << "] (Step 2c) = " << delta_i[j] << std::endl;
		}
		err << "P_" << i_in << ": aprime_i (Step 2c) = " << aprime_i << std::endl;
		err << "P_" << i_in << ": sigma_i (Step 2c) = " << sigma_i << std::endl;
		//        Broadcast commitments for the zero-knowledge proofs of knowledge (we use presentation from [BCCG15]).
		//        Then we show in parallel, that commitment $\beta_i \delta_i^{-1}$ equals zero, i.e., the former
		//        commitment was made to the same value $k_i$ resp. $a_i$. This works since Pedersen commitments have
		//        homomorphic properties.
		mpz_srandomm(r_a_i, q);
		mpz_fspowm(fpowm_table_h, Ta_i[i_in], h, r_a_i, p);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j == i_in)
			{
				rbc->Broadcast(Ta_i[i_in]);
			}
			else
			{
				if (!rbc->DeliverFrom(Ta_i[j], j))
				{
					err << "P_" << i_in << ": receiving Ta_i (in Step 2c) failed for P_" << j << std::endl;
					continue;
				}
				if (!CheckElement(Ta_i[j]))
				{
					err << "P_" << i_in << ": bad Ta_i (in Step 2c) received from P_" << j << std::endl;
					mpz_set_ui(Ta_i[j], 0L); // indicates an error
				}
			}
		}
		//        Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//        his local share of the secret challenge to $d_i$. (In [CD98] this callenge is called $e$.)
		if (!ddd_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[14])
			throw false;
		mpz_set(d_i[i_in], ddd_rvss->z_i), mpz_set(dprime_i[i_in], ddd_rvss->zprime_i);
		d_complaints.clear();
		//        Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		for (size_t j = 0; j < n_in; j++)
		{
			if ((j == i_in) && (std::find(ddd_rvss->QUAL.begin(), ddd_rvss->QUAL.end(), j) != ddd_rvss->QUAL.end()))
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[15])
					mpz_add_ui(d_i[i_in], d_i[i_in], 1L);
				rbc->Broadcast(d_i[i_in]);
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[16])
					mpz_add_ui(dprime_i[i_in], dprime_i[i_in], 1L);
				rbc->Broadcast(dprime_i[i_in]);
			}
			else if ((j != i_in) && (std::find(ddd_rvss->QUAL.begin(), ddd_rvss->QUAL.end(), j) != ddd_rvss->QUAL.end()))
			{
				if (!rbc->DeliverFrom(d_i[j], j))
				{
					err << "P_" << i_in << ": receiving d_i (in Step 2c) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(d_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad d_i (in Step 2c) received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(d_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(dprime_i[j], j))
				{
					err << "P_" << i_in << ": receiving dprime_i (in Step 2c) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(dprime_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad dprime_i (in Step 2c) received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(dprime_i[j], 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, foo, g, d_i[j], p);
				mpz_fpowm(fpowm_table_h, bar, h, dprime_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, ddd_rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": checking d_i resp. dprime_i (in Step 2c) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
				}
			}
			else
				err << "P_" << i_in << ": WARNING - P_" << j << " not in QUAL of ddd_rvss" << std::endl;
		}
		//        Public reconstruction of $d_j$, for every failed player $P_j$
		std::sort(d_complaints.begin(), d_complaints.end());
		it = std::unique(d_complaints.begin(), d_complaints.end());
		d_complaints.resize(std::distance(d_complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of ddd_rvss against ";
		for (std::vector<size_t>::iterator it = d_complaints.begin(); it != d_complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!ddd_rvss->Reconstruct(d_complaints, d_i, rbc, err))
		{
			err << "P_" << i_in << ": reconstruction of d_i in Step 2c failed" << std::endl;
			throw false;
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[17])
			throw false;
		//        Get $d = \sum_{P_i \in QUAL} d_i$
		mpz_set_ui(d, 0L);
		for (std::vector<size_t>::iterator it = ddd_rvss->QUAL.begin(); it != ddd_rvss->QUAL.end(); ++it)
		{
			mpz_add(d, d, d_i[*it]);
			mpz_mod(d, d, q);
		}
		err << "P_" << i_in << ": d (Step 2c) = " << d << std::endl;
		//        Broadcast the reponse $z_{a_i} = r_{a_i} + (a\prime_i - \sigma_i) \cdot d$ and verify the results.
		mpz_sub(bar, aprime_i, sigma_i);
		mpz_mod(bar, bar, q);
		mpz_mul(bar, bar, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, r_a_i);
		mpz_mod(bar, bar, q);
		rbc->Broadcast(bar);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar (in Step 2c) failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar (in Step 2c) received from P_" << j << std::endl;
					continue;
				}
				if (!mpz_invert(rhs, delta_i[j], p))
				{
					err << "P_" << i_in << ": cannot invert delta_i (in Step 2c) from P_" << j << std::endl;
					continue;
				}
				mpz_mul(rhs, rhs, beta_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_powm(rhs, rhs, d, p);
				mpz_mul(rhs, rhs, Ta_i[j]);
				mpz_mod(rhs, rhs, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": ZNPoK for a_i in Step 2c failed for P_" << j << std::endl;
					continue;
				}
			}
		}
		//    (d) Each player $P_i, i = 1, \ldots, 2t + 1$, shares its value $v_i = k_i a_i \bmod q$
		//        using Pedersen's VSS.
		complaints.clear();
		mpz_mul(v_i[i_in], k_i[i_in], a_i[i_in]);
		mpz_mod(v_i[i_in], v_i[i_in], q);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[18])
			mpz_add_ui(v_i[i_in], v_i[i_in], 1L);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!vv_i_vss[j]->Share(j, aiou, rbc, err, simulate_faulty_behaviour))
					err << "P_" << i_in << ": WARNING - VSS of v_i (in Step 2d) failed; complaint against P_" << j << std::endl;
			}
			else
			{
				err << "P_" << i_in << ": v_i = " << v_i[i_in] << std::endl;
				if (!vv_i_vss[j]->Share(v_i[i_in], aiou, rbc, err, simulate_faulty_behaviour))
					throw false;
			}
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[19])
			throw false;
		//        The values $\chi_i = g^{k_i a_i} h^{\tau_i}, i = 1, \ldots, 2t + 1$, (for some
		//        randomizers $\tau_i$) are public.
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_set(chi_i[j], vv_i_vss[j]->A_j[0]);
			if (j == i_in)
				mpz_set(tau_i, vv_i_vss[i_in]->b_j[0]);
		}
		for (size_t j = 0; j < n_in; j++)
		{
			err << "P_" << i_in << ": chi_i[" << j << "] (Step 2d) = " << chi_i[j] << std::endl;
		}
		err << "P_" << i_in << ": tau_i (Step 2d) = " << tau_i << std::endl;
		//        Each $P_i$ proves in ZK that the value committed in $\chi_i$ is the product
		//        of the values committed to in $\alpha_i$ and $\beta_i$. This is done using
		//        a zero-knowledge proof from [CD98]. This is a 3-move public coin proof and
		//        it is performed by all players as above.
		//        (We use the simplified presentation from [BCCG15] called $\Sigma_{prod}$.)
		mpz_srandomm(dd, q), mpz_srandomm(ee, q), mpz_srandomm(ss, q), mpz_srandomm(ssprime, q), mpz_srandomm(tt, q);
		mpz_fspowm(fpowm_table_g, foo, g, dd, p);
		mpz_fspowm(fpowm_table_h, bar, h, ss, p);
		mpz_mul(DD[i_in], foo, bar);
		mpz_mod(DD[i_in], DD[i_in], p);
		mpz_spowm(foo, beta_i[i_in], dd, p);
		mpz_fspowm(fpowm_table_h, bar, h, ssprime, p);
		mpz_mul(DDprime[i_in], foo, bar);
		mpz_mod(DDprime[i_in], DDprime[i_in], p);
		mpz_fspowm(fpowm_table_g, foo, g, ee, p);
		mpz_fspowm(fpowm_table_h, bar, h, tt, p);
		mpz_mul(EE[i_in], foo, bar);
		mpz_mod(EE[i_in], EE[i_in], p);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j == i_in)
			{
				rbc->Broadcast(DD[i_in]);
				rbc->Broadcast(DDprime[i_in]);
				rbc->Broadcast(EE[i_in]);
			}
			else
			{
				if (!rbc->DeliverFrom(DD[j], j))
				{
					err << "P_" << i_in << ": receiving DD (in Step 2d) failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!rbc->DeliverFrom(DDprime[j], j))
				{
					err << "P_" << i_in << ": receiving DDprime (in Step 2d) failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!rbc->DeliverFrom(EE[j], j))
				{
					err << "P_" << i_in << ": receiving EE (in Step 2d) failed for P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!CheckElement(DD[j]))
				{
					err << "P_" << i_in << ": bad DD (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(DD[j], 0L); // indicates an error
				}
				if (!CheckElement(DDprime[j]))
				{
					err << "P_" << i_in << ": bad DDprime (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(DDprime[j], 0L); // indicates an error
				}
				if (!CheckElement(EE[j]))
				{
					err << "P_" << i_in << ": bad EE (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(EE[j], 0L); // indicates an error
				}
			}
		}
		//        Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//        his local share of the secret challenge to $d_i$. (In [CD98] this callenge is called $e$
		//        and in [BCCG15] it is called $x$.)
		if (!dddd_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[20])
			throw false;
		mpz_set(d_i[i_in], dddd_rvss->z_i), mpz_set(dprime_i[i_in], dddd_rvss->zprime_i);
		d_complaints.clear();
		//        Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		for (size_t j = 0; j < n_in; j++)
		{
			if ((j == i_in) && (std::find(dddd_rvss->QUAL.begin(), dddd_rvss->QUAL.end(), j) != dddd_rvss->QUAL.end()))
			{
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[21])
					mpz_add_ui(d_i[i_in], d_i[i_in], 1L);
				rbc->Broadcast(d_i[i_in]);
				if (simulate_faulty_behaviour && simulate_faulty_randomizer[22])
					mpz_add_ui(dprime_i[i_in], dprime_i[i_in], 1L);
				rbc->Broadcast(dprime_i[i_in]);
			}
			else if ((j != i_in) && (std::find(dddd_rvss->QUAL.begin(), dddd_rvss->QUAL.end(), j) != dddd_rvss->QUAL.end()))
			{
				if (!rbc->DeliverFrom(d_i[j], j))
				{
					err << "P_" << i_in << ": receiving d_i (in Step 2d) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(d_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad d_i (in Step 2d) received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(d_i[j], 0L); // indicates an error
				}
				if (!rbc->DeliverFrom(dprime_i[j], j))
				{
					err << "P_" << i_in << ": receiving dprime_i (in Step 2d) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					continue;
				}
				if (mpz_cmpabs(dprime_i[j], q) >= 0)
				{
					err << "P_" << i_in << ": bad dprime_i (in Step 2d) received; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
					mpz_set_ui(dprime_i[j], 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, foo, g, d_i[j], p);
				mpz_fpowm(fpowm_table_h, bar, h, dprime_i[j], p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				mpz_set_ui(rhs, 1L);
				mpz_mul(rhs, rhs, dddd_rvss->C_ik[j][0]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": checking d_i resp. dprime_i (in Step 2d) failed; complaint against P_" << j << std::endl;
					d_complaints.push_back(j);
				}
			}
			else
				err << "P_" << i_in << ": WARNING - P_" << j << " not in QUAL of dddd_rvss" << std::endl;
		}
		//        Public reconstruction of $d_j$, for every failed player $P_j$
		std::sort(d_complaints.begin(), d_complaints.end());
		it = std::unique(d_complaints.begin(), d_complaints.end());
		d_complaints.resize(std::distance(d_complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of dddd_rvss against ";
		for (std::vector<size_t>::iterator it = d_complaints.begin(); it != d_complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		if (!dddd_rvss->Reconstruct(d_complaints, d_i, rbc, err))
		{
			err << "P_" << i_in << ": reconstruction of d_i in Step 2d failed" << std::endl;
			throw false;
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[23])
			throw false;
		//        Get $d = \sum_{P_i \in QUAL} d_i$
		mpz_set_ui(d, 0L);
		for (std::vector<size_t>::iterator it = dddd_rvss->QUAL.begin(); it != dddd_rvss->QUAL.end(); ++it)
		{
			mpz_add(d, d, d_i[*it]);
			mpz_mod(d, d, q);
		}
		err << "P_" << i_in << ": d (Step 2d) = " << d << std::endl;
		//        Broadcast the responses...
		//        $f_1 = k_i d + dd \bmod q$
		mpz_mul(foo, k_i[i_in], d);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, dd);
		mpz_mod(foo, foo, q);
		//        $z_1 = kprime_i d + ss \bmod q$
		mpz_mul(bar, kprime_i, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, ss);
		mpz_mod(bar, bar, q);
		//        $f_2 = a_i d + ee \bmod q$
		mpz_mul(lhs, a_i[i_in], d);
		mpz_mod(lhs, lhs, q);
		mpz_add(lhs, lhs, ee);
		mpz_mod(lhs, lhs, q);
		//        $z_2 = aprime_i d + tt \bmod q$
		mpz_mul(rhs, aprime_i, d);
		mpz_mod(rhs, rhs, q);
		mpz_add(rhs, rhs, tt);
		mpz_mod(rhs, rhs, q);
		rbc->Broadcast(foo);
		rbc->Broadcast(bar);
		rbc->Broadcast(lhs);
		rbc->Broadcast(rhs);
		//        $z_3 = (\tau_i - k_i aprime_i) d + ssprime$
		mpz_mul(foo, k_i[i_in], aprime_i);
		mpz_mod(foo, foo, q);
		mpz_sub(bar, tau_i, foo);
		mpz_mod(bar, bar, q);
		mpz_mul(bar, bar, d);
		mpz_mod(bar, bar, q);
		mpz_add(bar, bar, ssprime);
		mpz_mod(bar, bar, q);
		rbc->Broadcast(bar);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo (in Step 2d) failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar (in Step 2d) failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_set(ssprime, foo); // save $f_1$ for third ZNPoK
				mpz_fpowm(fpowm_table_g, rhs, g, foo, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, alpha_i[j], d, p);
				mpz_mul(rhs, rhs, DD[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": first ZNPoK in Step 2d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo (in Step 2d) failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar (in Step 2d) failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_fpowm(fpowm_table_g, rhs, g, foo, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, beta_i[j], d, p);
				mpz_mul(rhs, rhs, EE[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": second ZNPoK in Step 2d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar (in Step 2d) failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar (in Step 2d) received from P_" << j << std::endl;
					complaints.push_back(j);
					mpz_set_ui(foo, 0L); // indicates an error
				}
				mpz_powm(rhs, beta_i[j], ssprime, p);
				mpz_fpowm(fpowm_table_h, lhs, h, bar, p);
				mpz_mul(lhs, lhs, rhs);
				mpz_mod(lhs, lhs, p);
				mpz_powm(rhs, chi_i[j], d, p);
				mpz_mul(rhs, rhs, DDprime[j]);
				mpz_mod(rhs, rhs, p);
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i_in << ": third ZNPoK in Step 2d failed for P_" << j << std::endl;
					complaints.push_back(j);
				}	
			}
		}
		//    (e) If player $P_j$ fails the proof in the above step, his shares $a_j, k_j$ are publicly
		//        reconstructed via interpolation of the back-ups of shares distributed in Step 2c resp.
		//        Step 1c. Since each $a_j$ (resp. $k_j$) can be computed as a linear combination of some
		//        $t+1$ values $a_i$ (resp. $k_i$) that were properly shared in Step 2c resp. Step 1c,
		//        each player broadcasts the appropriate linear combination of its shares of these $a_i$'s
		//        (resp. $k_i$'s), together with their associated randomness (computed as the same linear
		//        combination of the associated randomness generated in Step 1c). Bad values are sieved out
		//        using the public commitments of Step 2c resp. Step 1c, $a_j$ and $k_j$ are reconstructed,
		//        and $v_j$ is set to $a_j k_j$.
		std::sort(complaints.begin(), complaints.end());
		it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		err << "P_" << i_in << ": there are extracting complaints of v_j against ";
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
			err << "P_" << *it << " ";
		err << std::endl;
		for (std::vector<size_t>::const_iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			if (*it != i_in)
			{
				mpz_set_ui(foo, 0L), mpz_set_ui(bar, 0L);
				if (!k_i_vss[*it]->Reconstruct(*it, foo, rbc, err))
				{
					err << "P_" << i_in << ": reconstruction of k_j (in Step 2e) failed for P_" << *it << std::endl;	
					throw false;
				}
				if (!aa_i_vss[*it]->Reconstruct(*it, bar, rbc, err))
				{
					err << "P_" << i_in << ": reconstruction of a_j (in Step 2e) failed for P_" << *it << std::endl;	
					throw false;
				}
				mpz_mul(v_i[*it], foo, bar);
				mpz_mod(v_i[*it], v_i[*it], q);
			}
			err << "P_" << i_in << ": v_i[" << *it << "] (Step 2e) = " << v_i[*it] << std::endl;
		}
		//    (f) The value $s = k(m + xr)$ is a linear combination of the values $v_1, \ldots, v_{2t+1}$.
		//        Thus it can be computed interpolating the polynomial of degree $t$ which is a linear
		//        combination of the polynomials used in Step 1d to share $v_1, \ldots, v_{2t+1}$.
		//        Each player broadcasts its share (together with its associated randomness) of that
		//        $t$-degree polynomial, which is itself a linear combination of the shares of
		//        $v_1, \ldots, v_{2t+1}$ received in Step 2d. For the $v_j$'s that were exposed in
		//        Step 2e, we use the constant sharing polynomial. Bad shares are detected using the
		//        public commitments, and $\mu$ is reconstructed.
		signers.clear();
		for (size_t j = 0; j < n_in; j++)
			signers.push_back(j);
		mpz_set_ui(foo, 0L), mpz_set_ui(bar, 0L);
		for (std::vector<size_t>::iterator jt = signers.begin(); jt != signers.end(); ++jt)
		{
			mpz_set_ui(lhs, 1L); // compute the optimized Lagrange multipliers
			for (std::vector<size_t>::iterator lt = signers.begin(); lt != signers.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(rhs, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(rhs, rhs, (*jt + 1)); // adjust index in computation
					mpz_mul(lhs, lhs, rhs);
				}
			}
			if (!mpz_invert(lhs, lhs, q))
			{
				err << "P_" << i_in << ": cannot invert LHS during computation of linear combination for P_" << *jt << std::endl;
				throw false;
			}
			mpz_set_ui(rhs, 1L);
			for (std::vector<size_t>::iterator lt = signers.begin(); lt != signers.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index in computation
			}
			mpz_mul(lambda_j[*jt], rhs, lhs);
			mpz_mod(lambda_j[*jt], lambda_j[*jt], q);
			if (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end())
			{
				mpz_mul(rhs, lambda_j[*jt], vv_i_vss[*jt]->sigma_i);
				mpz_mod(rhs, rhs, q);
				mpz_add(foo, foo, rhs);
				mpz_mod(foo, foo, q);
				mpz_mul(rhs, lambda_j[*jt], vv_i_vss[*jt]->tau_i);
				mpz_mod(rhs, rhs, q);
				mpz_add(bar, bar, rhs);
				mpz_mod(bar, bar, q);
			}
			else
			{
				mpz_mul(rhs, lambda_j[*jt], v_i[*jt]);
				mpz_mod(rhs, rhs, q);
				mpz_add(foo, foo, rhs);
				mpz_mod(foo, foo, q);
			}
		}
		rbc->Broadcast(foo);
		rbc->Broadcast(bar);
		parties.clear();
		parties.push_back(i_in); // shares of this player are always available
		mpz_set(shares[i_in], foo);
		for (size_t j = 0; j < n_in; j++)
		{
			if (j != i_in)
			{
				if (!rbc->DeliverFrom(foo, j))
				{
					err << "P_" << i_in << ": receiving foo (in Step 2f) failed for P_" << j << std::endl;
					continue;
				}
				if (!rbc->DeliverFrom(bar, j))
				{
					err << "P_" << i_in << ": receiving bar (in Step 2f) failed for P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(foo, q) >= 0)
				{
					err << "P_" << i_in << ": bad foo (in Step 2f) received from P_" << j << std::endl;
					continue;
				}
				if (mpz_cmpabs(bar, q) >= 0)
				{
					err << "P_" << i_in << ": bad bar (in Step 2f) received from P_" << j << std::endl;
					continue;
				}
				mpz_set(shares[j], foo); // save the share for later following reconstruction
				// compute LHS for the check
				mpz_fpowm(fpowm_table_g, foo, g, foo, p);
				mpz_fpowm(fpowm_table_h, bar, h, bar, p);
				mpz_mul(lhs, foo, bar);
				mpz_mod(lhs, lhs, p);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				for (std::vector<size_t>::iterator jt = signers.begin(); jt != signers.end(); ++jt)
				{
					if (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end())
					{
						mpz_set_ui(bar, 1L);
						for (size_t k = 0; k < vv_i_vss[*jt]->A_j.size(); k++)
						{
							mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
							mpz_powm(foo, vv_i_vss[*jt]->A_j[k], foo, p);
							mpz_mul(bar, bar, foo);
							mpz_mod(bar, bar, p);
						}	
					}
					else
					{
						mpz_fpowm(fpowm_table_g, bar, g, v_i[*jt], p);
					}
					mpz_powm(bar, bar, lambda_j[*jt], p); // include Lagrange multipliers
					mpz_mul(rhs, rhs, bar);
					mpz_mod(rhs, rhs, p);
				}
				// check equation (1)
				if (mpz_cmp(lhs, rhs))
					err << "P_" << i_in << ": bad share  (in Step 2f) received from " << j << std::endl;
				else
					parties.push_back(j);
			}
		}
		// check whether enough shares (i.e. $t + 1$) have been collected
		if (parties.size() <= t)
		{
			err << "P_" << i_in << ": not enough shares collected for reconstructing s" << std::endl;
			throw false;
		}
		if (parties.size() > (t + 1))
			parties.resize(t + 1);
		err << "P_" << i_in << ": reconstructing parties = ";
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
			err << "P_" << *jt << " ";
		err << std::endl;
		// compute $s$ by Lagrange interpolation
		mpz_set_ui(s, 0L);
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
		{
			mpz_set_ui(lhs, 1L); // compute the optimized Lagrange multipliers
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(rhs, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(rhs, rhs, (*jt + 1)); // adjust index in computation
					mpz_mul(lhs, lhs, rhs);
				}
			}
			if (!mpz_invert(lhs, lhs, q))
			{
				err << "P_" << i_in << ": cannot invert LHS during reconstruction" << std::endl;
				throw false;
			}
			mpz_set_ui(rhs, 1L);
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index in computation
			}
			mpz_mul(rhs, rhs, lhs);
			mpz_mod(rhs, rhs, q);
			mpz_mul(rhs, rhs, shares[*jt]); // use the provided shares (interpolation points)
			mpz_mod(rhs, rhs, q);
			mpz_add(s, s, rhs);
			mpz_mod(s, s, q);
		}
		parties.clear();
		err << "P_" << i_in << ": s = " << s << std::endl;

		// 3. Player $P_i$ erases all secret information generated in this signing protocol.
		k_rvss->EraseSecrets();

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();

		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs), mpz_clear(kprime_i), mpz_clear(aprime_i), mpz_clear(rho_i),
			mpz_clear(sigma_i), mpz_clear(d), mpz_clear(r_k_i), mpz_clear(r_a_i), mpz_clear(tau_i), mpz_clear(dd), mpz_clear(ee),
			mpz_clear(ss), mpz_clear(ssprime), mpz_clear(tt), mpz_clear(mu);
		for (size_t j = 0; j < n_in; j++)
		{
			mpz_clear(k_i[j]), mpz_clear(a_i[j]), mpz_clear(alpha_i[j]), mpz_clear(beta_i[j]);
			mpz_clear(gamma_i[j]), mpz_clear(delta_i[j]), mpz_clear(v_i[j]), mpz_clear(chi_i[j]);
			mpz_clear(Tk_i[j]), mpz_clear(Ta_i[j]), mpz_clear(d_i[j]), mpz_clear(dprime_i[j]);
			mpz_clear(DD[j]), mpz_clear(DDprime[j]), mpz_clear(EE[j]), mpz_clear(shares[j]);
			mpz_clear(lambda_j[j]);
			delete [] k_i[j], delete [] a_i[j], delete [] alpha_i[j], delete [] beta_i[j];
			delete [] gamma_i[j], delete [] delta_i[j], delete [] v_i[j], delete [] chi_i[j];
			delete [] Tk_i[j], delete [] Ta_i[j], delete [] d_i[j], delete [] dprime_i[j];
			delete [] DD[j], delete [] DDprime[j], delete [] EE[j], delete [] shares[j];
			delete [] lambda_j[j];
		}
		k_i.clear(), a_i.clear(), alpha_i.clear(), beta_i.clear();
		gamma_i.clear(), delta_i.clear(), v_i.clear(), chi_i.clear();
		Tk_i.clear(), Ta_i.clear(), d_i.clear(), dprime_i.clear();
		DD.clear(), DDprime.clear(), EE.clear(), shares.clear();
		lambda_j.clear();
		for (size_t j = 0; j < n_in; j++)
		{
			delete k_i_vss[j];
			delete a_i_vss[j];
			delete v_i_vss[j];
			delete aa_i_vss[j];
			delete vv_i_vss[j];
		}
		k_i_vss.clear(), a_i_vss.clear(), v_i_vss.clear(), aa_i_vss.clear(), vv_i_vss.clear();
		delete d_rvss, delete dd_rvss, delete ddd_rvss, delete dddd_rvss;
		delete a_dkg;
		delete k_rvss;

		// return
		return return_value;
	}

}

bool CanettiGennaroJareckiKrawczykRabinDSS::Verify
	(mpz_srcptr m, mpz_srcptr r, mpz_srcptr s) const
{
	// initialize
	mpz_t foo, bar, rprime;
	mpz_init(foo), mpz_init(bar), mpz_init(rprime);

	try
	{
		// 1. Checking that $0 < r < q$ and $0 < s < q$
		if ((mpz_cmp_ui(r, 0L) <= 0) || (mpz_cmp(r, q) >= 0))
			throw false;
		if ((mpz_cmp_ui(s, 0L) <= 0) || (mpz_cmp(s, q) >= 0))
			throw false;
		// 2. Compute $r\prime = (g^{ms^{-1}} y^{rs^{-1}} \bmod p) \bmod q$
		if (!mpz_invert(foo, s, q))
			throw false;
		mpz_mul(bar, m, foo);
		mpz_mod(bar, bar, q);
		mpz_fpowm(fpowm_table_g, rprime, g, bar, p);
		mpz_mul(bar, r, foo);
		mpz_mod(bar, bar, q);
		mpz_powm(foo, y, bar, p);
		mpz_mul(rprime, rprime, foo);
		mpz_mod(rprime, rprime, p);
		mpz_mod(rprime, rprime, q);
		// 3. Checking that $r = r\prime$
		if (mpz_cmp(r, rprime))
			throw false;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(rprime);
		// return
		return return_value;
	}
}

CanettiGennaroJareckiKrawczykRabinDSS::~CanettiGennaroJareckiKrawczykRabinDSS
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i), mpz_clear(y);

	// release subprotocol
	delete dkg;

	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

