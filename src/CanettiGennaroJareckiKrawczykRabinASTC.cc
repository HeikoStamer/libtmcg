/*******************************************************************************
  CanettiGennaroJareckiKrawczykRabinASTC.cc,
                         |A|daptive |S|ecurity for |T|hreshold |C|ryptosystems

     [CGJKR99] Ran Canetti, Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk,
               and Tal Rabin: 'Adaptive Security for Threshold Cryptosystems',
     Advances in Cryptology - CRYPTO'99, LNCS 1666, pp. 98--116, 1999.

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
	for (size_t j = 0; j < n_in; j++)
	{
		std::vector<mpz_ptr> *vtmp1 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp1->push_back(tmp3);
		}
		s_ji.push_back(*vtmp1);
		std::vector<mpz_ptr> *vtmp2 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp2->push_back(tmp3);
		}
		sprime_ji.push_back(*vtmp2);
		std::vector<mpz_ptr> *vtmp3 = new std::vector<mpz_ptr>;
		for (size_t k = 0; k <= tprime_in; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp3->push_back(tmp3);
		}
		C_ik.push_back(*vtmp3);
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
	std::getline(in, value);
	std::stringstream(value) >> t;
	std::getline(in, value);
	std::stringstream(value) >> i;
	std::getline(in, value);
	std::stringstream(value) >> tprime;
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
	for (size_t j = 0; j < n; j++)
	{
		std::vector<mpz_ptr> *vtmp1 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp1->push_back(tmp3);
		}
		s_ji.push_back(*vtmp1);
		std::vector<mpz_ptr> *vtmp2 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp2->push_back(tmp3);
		}
		sprime_ji.push_back(*vtmp2);
		std::vector<mpz_ptr> *vtmp3 = new std::vector<mpz_ptr>;
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp3->push_back(tmp3);
		}
		C_ik.push_back(*vtmp3);
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

void CanettiGennaroJareckiKrawczykRabinRVSS::Erase
	()
{
	mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
	mpz_set_ui(z_i, 0L), mpz_set_ui(zprime_i, 0L);
	QUAL.clear();
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[j][i], 0L);
			mpz_set_ui(sprime_ji[j][i], 0L);
		}
		for (size_t k = 0; k <= tprime; k++)
			mpz_set_ui(C_ik[i][k], 0L);
	}	
}

bool CanettiGennaroJareckiKrawczykRabinRVSS::CheckGroup
	() const
{
	mpz_t foo, k;

	mpz_init(foo), mpz_init(k);
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

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(k);
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
		// 1. Each player $P_i$ performs a Pedersen-VSS of a random
		//    value $z_i$ as a dealer:
		// (a) $P_i$ chooses two random polynomials $f_i(z)$ and
		//     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t\prime$ where
		//     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t\prime$ and
		//     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t\prime$
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
		// Let $z_i = a_{i0} = f_i(0)$.
		mpz_set(z_i, a_i[0]), mpz_set(zprime_i, b_i[0]);
		err << "P_" << i << ": z_i = " << z_i << " zprime_i = " << zprime_i << std::endl;
		// $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
		// for $k = 0, \ldots, t\prime$.
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
						err << "P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
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
				if (!aiou->Send(s_ji[i][j], j))
				{
					err << "P_" << i << ": sending s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(sprime_ji[i][j], j))
				{
					err << "P_" << i << ": sending sprime_ji failed; complaint against P_" << j << std::endl;
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
					err << "P_" << i << ": receiving s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Receive(sprime_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
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
				mpz_powm(bar, C_ik[j][k], foo , p);
				mpz_mul(rhs, rhs, bar);
				mpz_mod(rhs, rhs, p);
			}
			// check equation (1)
			if (mpz_cmp(lhs, rhs))
			{
				err << "P_" << i << ": checking step 1b failed; complaint against P_" << j << std::endl;
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
		complaints.clear(), complaints_from.clear(); // reset
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
		// (c) Each player $P_i$ who, as a dealer, received a complaint
		//     from player $P_j$ broadcasts the values $s_{ij}$,
		//     $s\prime_{ij}$ that satisfy Eq. (1).
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
				rbc->Broadcast(s_ji[i][*it]);
				rbc->Broadcast(sprime_ji[i][*it]);
			}
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		// (d) Each player builds the set of players $QUAL$ which excludes any player
		//      - who received more than $t$ complaints in Step 1b, or
		//      - answered to a complaint in Step 1c with values that violate Eq. (1).
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				size_t who;
				if (complaints_counter[j] > t)
				{
					complaints.push_back(j);
					continue;
				}
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(lhs, j))
					{
						err << "P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(lhs);
					if (who >= n)
						break; // end marker received
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "P_" << i << ": receiving foo failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "P_" << i << ": receiving bar failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					mpz_t s, sprime;
					mpz_init_set(s, foo), mpz_init_set(sprime, bar);
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
						mpz_powm(bar, C_ik[j][k], foo , p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (1)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking step 1d failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious
						if (who == i)
						{
							err << "P_" << i << ": shares adjusted in step 1d from P_" << j << std::endl;
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
		for (size_t j = 0; j < n; j++)
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		err << "P_" << i << ": QUAL = { ";
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
		err << "P_" << i << ": x_i = " << x_i << std::endl;
		err << "P_" << i << ": xprime_i = " << xprime_i << std::endl;
		
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
	}
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
	for (size_t j = 0; j < n_in; j++)
	{
		std::vector<mpz_ptr> *vtmp1 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp1->push_back(tmp3);
		}
		s_ji.push_back(*vtmp1);
		std::vector<mpz_ptr> *vtmp2 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n_in; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp2->push_back(tmp3);
		}
		sprime_ji.push_back(*vtmp2);
		std::vector<mpz_ptr> *vtmp3 = new std::vector<mpz_ptr>;
		for (size_t k = 0; k <= tprime_in; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp3->push_back(tmp3);
		}
		C_ik.push_back(*vtmp3);
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
	std::getline(in, value);
	std::stringstream(value) >> t;
	std::getline(in, value);
	std::stringstream(value) >> i;
	std::getline(in, value);
	std::stringstream(value) >> tprime;
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
	for (size_t j = 0; j < n; j++)
	{
		std::vector<mpz_ptr> *vtmp1 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp1->push_back(tmp3);
		}
		s_ji.push_back(*vtmp1);
		std::vector<mpz_ptr> *vtmp2 = new std::vector<mpz_ptr>;
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp2->push_back(tmp3);
		}
		sprime_ji.push_back(*vtmp2);
		std::vector<mpz_ptr> *vtmp3 = new std::vector<mpz_ptr>;
		for (size_t k = 0; k <= tprime; k++)
		{
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp3->push_back(tmp3);
		}
		C_ik.push_back(*vtmp3);
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

void CanettiGennaroJareckiKrawczykRabinZVSS::Erase
	()
{
	mpz_set_ui(x_i, 0L), mpz_set_ui(xprime_i, 0L);
	QUAL.clear();
	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ji[j][i], 0L);
			mpz_set_ui(sprime_ji[j][i], 0L);
		}
		for (size_t k = 0; k <= tprime; k++)
			mpz_set_ui(C_ik[i][k], 0L);
	}	
}

bool CanettiGennaroJareckiKrawczykRabinZVSS::CheckGroup
	() const
{
	mpz_t foo, k;

	mpz_init(foo), mpz_init(k);
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

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(k);
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
						err << "P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
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
				if (!aiou->Send(s_ji[i][j], j))
				{
					err << "P_" << i << ": sending s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Send(sprime_ji[i][j], j))
				{
					err << "P_" << i << ": sending sprime_ji failed; complaint against P_" << j << std::endl;
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
					err << "P_" << i << ": receiving s_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Receive(sprime_ji[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving sprime_ji failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
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
				mpz_powm(bar, C_ik[j][k], foo , p);
				mpz_mul(rhs, rhs, bar);
				mpz_mod(rhs, rhs, p);
			}
			// check equation (1)
			if (mpz_cmp(lhs, rhs))
			{
				err << "P_" << i << ": checking step 1b failed; complaint against P_" << j << std::endl;
				complaints.push_back(j);
			}
			// [...] and in Step (1b) each player $P_j$ additionally checks
			// for each $i$ that $C_{i0} = 1 \bmod p$.
			if (mpz_cmp_ui(C_ik[j][0], 1L))
			{
				err << "P_" << i << ": additional check in step 1b failed; complaint against P_" << j << std::endl;
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
		complaints.clear(), complaints_from.clear(); // reset
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
		// (c) Each player $P_i$ who, as a dealer, received a complaint
		//     from player $P_j$ broadcasts the values $s_{ij}$,
		//     $s\prime_{ij}$ that satisfy Eq. (1).
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
				rbc->Broadcast(s_ji[i][*it]);
				rbc->Broadcast(sprime_ji[i][*it]);
			}
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}
		mpz_set_ui(lhs, n); // broadcast end marker
		rbc->Broadcast(lhs);
		// (d) Each player builds the set of players $QUAL$ which excludes any player
		//      - who received more than $t$ complaints in Step 1b, or
		//      - answered to a complaint in Step 1c with values that violate Eq. (1).
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				size_t who;
				if (complaints_counter[j] > t)
				{
					complaints.push_back(j);
					continue;
				}
				size_t cnt = 0;
				do
				{
					if (!rbc->DeliverFrom(lhs, j))
					{
						err << "P_" << i << ": receiving who failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					who = mpz_get_ui(lhs);
					if (who >= n)
						break; // end marker received
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "P_" << i << ": receiving foo failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "P_" << i << ": receiving bar failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					mpz_t s, sprime;
					mpz_init_set(s, foo), mpz_init_set(sprime, bar);
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
						mpz_powm(bar, C_ik[j][k], foo , p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (1)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking step 1d failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					else
					{
						// don't be too curious
						if (who == i)
						{
							err << "P_" << i << ": shares adjusted in step 1d from P_" << j << std::endl;
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
		for (size_t j = 0; j < n; j++)
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		err << "P_" << i << ": QUAL = { ";
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
		err << "P_" << i << ": x_i = " << x_i << std::endl;
		err << "P_" << i << ": xprime_i = " << xprime_i << std::endl;
		
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
	}
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================

CanettiGennaroJareckiKrawczykRabinDKG::CanettiGennaroJareckiKrawczykRabinDKG
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
	std::getline(in, value);
	std::stringstream(value) >> t;
	std::getline(in, value);
	std::stringstream(value) >> i;
	mpz_init(x_i), mpz_init(xprime_i), mpz_init(y);
	in >> x_i >> xprime_i >> y;
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
	mpz_t foo, k;

	mpz_init(foo), mpz_init(k);
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

		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(k);
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
	mpz_t d, d_i, dprime_i, r_i, rprime_i;
	std::vector<mpz_ptr> A_i, B_i, T_i, Tprime_i, z_i;
	std::vector<size_t> complaints, complaints_counter, complaints_from;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	mpz_init(d), mpz_init(d_i), mpz_init(dprime_i), mpz_init(r_i), mpz_init(rprime_i);
	for (size_t j = 0; j < n; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(), tmp4 = new mpz_t(), tmp5 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4), mpz_init(tmp5);
		A_i.push_back(tmp1), B_i.push_back(tmp2), T_i.push_back(tmp3), Tprime_i.push_back(tmp4), z_i.push_back(tmp5);
	}
	size_t simulate_faulty_randomizer[10];
	for (size_t idx = 0; idx < 10; idx++)
		simulate_faulty_randomizer[idx] = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinDKG::Generate()" << p << q << g << h << n << t;
	rbc->setID(myID.str());

	// initialize subprotocols
	x_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, F_size, G_size, use_very_strong_randomness, "x_rvss");
	d_rvss = new CanettiGennaroJareckiKrawczykRabinRVSS(n, t, i, t, p, q, g, h, F_size, G_size, use_very_strong_randomness, "d_rvss");

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
		std::copy(x_rvss->QUAL.begin(), x_rvss->QUAL.end(), QUAL.begin()); 

		// Extracting $y = g^x \bmod p$:
		// Each player exposes $y_i = g^{z_i} \bmod p$ to enable the computation of $y = g^x \bmod p$.
		// 2. Each player $P_i$, $i \in QUAL$, broadcasts $A_i = g^{f_i(0)} = g^{z_i} \bmod p$ and
		//    $B_i = h^{f\prime_i(0)} \bmod p$, s.t. $C_{i0} = A_i B_i$. $P_i$ also chooses random
		//    values $r_i$ and $r\prime_i$ and broadcasts $T_i = g^{r_i}, T\prime_i = h^{r\prime_i} \bmod p$.
		mpz_fspowm(fpowm_table_g, A_i[i], g, z_i[i], p);
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[1])
			mpz_add_ui(A_i[i], A_i[i], 1L);
		mpz_fspowm(fpowm_table_h, B_i[i], h, x_rvss->zprime_i, p);
		mpz_srandomm(r_i, q);
		mpz_srandomm(rprime_i, q);
		mpz_fspowm(fpowm_table_g, T_i[i], g, r_i, p);
		mpz_fspowm(fpowm_table_h, Tprime_i[i], h, rprime_i, p);
		rbc->Broadcast(A_i[i]);
		rbc->Broadcast(B_i[i]);
		rbc->Broadcast(T_i[i]);
		rbc->Broadcast(Tprime_i[i]);
		complaints.clear();
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) &&
				(std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
			{
					if (!rbc->DeliverFrom(A_i[j], j))
					{
						err << "P_" << i << ": receiving A_i failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!rbc->DeliverFrom(B_i[j], j))
					{
						err << "P_" << i << ": receiving B_i failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!rbc->DeliverFrom(T_i[j], j))
					{
						err << "P_" << i << ": receiving T_i failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					if (!rbc->DeliverFrom(Tprime_i[j], j))
					{
						err << "P_" << i << ": receiving Tprime_i failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					// compute RHS and check that $C_{j0} = A_j B_j \bmod p$
					mpz_mul(rhs, A_i[j], B_i[j]);
					mpz_mod(rhs, rhs, p);
					if (mpz_cmp(x_rvss->C_ik[j][0], rhs))
					{
						err << "P_" << i << ": checking in step 2. failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
			}
		}
		// 3. Players execute Joint-RVSS(t,n,t) for a joint random challenge $d$. Player $P_i$ sets
		//    his local share of the secret challenge to $d_i$. All other secret output generated by
		//    this Joint-RVSS and held by $P_i$ is erased.
		if (!d_rvss->Share(aiou, rbc, err, simulate_faulty_behaviour))
			throw false;
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[2])
			throw false;
		mpz_set(d_i, d_rvss->x_i), mpz_set(dprime_i, d_rvss->xprime_i);
		d_rvss->Erase();
		// 4. Each player broadcasts $d_i$ (and $d\prime_i$ for the optimally-resilient variant).
		if (simulate_faulty_behaviour && simulate_faulty_randomizer[3])
			mpz_add_ui(d_i, d_i, 1L);
		rbc->Broadcast(d_i);
		rbc->Broadcast(dprime_i);
// TODO: receive shares and get $d$ either by summation, if nobody fails, or otherwise by interpolation


		
// FIXME: next steps are copied from the other DKG protocol and need to be adjusted
		// 4. Each party $i \in QUAL$ exposes $y_i = g^{z_i} \bmod p$
		//    via Feldman-VSS:
		// (a) Each party $P_i$, $i \in QUAL$, broadcasts $A_{ik} = 
		//     g^{a_{ik}} \bmod p$ for $k = 0, \ldots, t$.
		for (size_t k = 0; k <= t; k++)
		{
//			mpz_fspowm(fpowm_table_g, A_ik[i][k], g, a_i[k], p);
//			if (simulate_faulty_behaviour)
//				mpz_add_ui(A_ik[i][k], A_ik[i][k], 1L);
//			rbc->Broadcast(A_ik[i][k]);
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
//					if (!rbc->DeliverFrom(A_ik[j][k], j))
					{
						err << "P_" << i << ": receiving A_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
				}
				// compute LHS for the check
				mpz_fspowm(fpowm_table_g, lhs, g, x_rvss->s_ji[j][i], p);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				for (size_t k = 0; k <= t; k++)
				{
					mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
//					mpz_powm(bar, A_ik[j][k], foo , p);
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
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
			rbc->Broadcast(x_rvss->s_ji[i][*it]);
			rbc->Broadcast(x_rvss->sprime_ji[i][*it]);
		}
		mpz_set_ui(rhs, n); // send end marker
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
					if (!rbc->DeliverFrom(bar, j))
					{
						err << "P_" << i << ": receiving sprime_ij failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
					// verify complaint, i.e. (4) holds (5) not.
					// compute LHS for the check
					mpz_fpowm(fpowm_table_g, lhs, g, foo, p);
					mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, lhs, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $i$ in computation
						mpz_powm(bar, x_rvss->C_ik[j][k], foo, p);
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
					mpz_fpowm(fpowm_table_g, lhs, g, foo, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$ in computation
//						mpz_powm(bar, A_ik[j][k], foo , p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (5)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking 4(c)(5) failed; complaint against P_" << who << std::endl;
						complaints.push_back(who);
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
//		if (!Reconstruct(complaints, x_rvss, z_i, a_ik, rbc, err))
		{
			err << "P_" << i << ": reconstruction failed" << std::endl;
			throw false;
		}
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			// compute $A_{ik} = g^{a_{ik}} \bmod p$
			for (size_t k = 0; k <= t; k++)
			{
//				err << "P_" << i << ": a_" << *it << "," << k << " = " << a_ik[*it][k] << std::endl;
//				mpz_fpowm(fpowm_table_g, A_ik[*it][k], g, a_ik[*it][k], p);
			}
		}






		// 8. The public value $y$ is set to $y = \prod_{i \in QUAL} A_i \bmod p$.
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_mul(y, y, A_i[*it]);
			mpz_mod(y, y, p);
		}
		err << "P_" << i << ": y = " << y << std::endl;
		// 9. Player $P_i$ erases all secret information aside from his share $x_i$.
// TODO

		throw true;
	}
	catch (bool return_value)
	{
		// release subprotocols
		delete x_rvss;
		delete d_rvss;
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(d), mpz_clear(d_i), mpz_clear(dprime_i), mpz_clear(r_i), mpz_clear(rprime_i);
		for (size_t j = 0; j < n; j++)
		{
			mpz_clear(A_i[j]), mpz_clear(B_i[j]), mpz_clear(T_i[j]), mpz_clear(Tprime_i[j]), mpz_clear(z_i[j]);
			delete [] A_i[j], delete [] B_i[j], delete [] T_i[j], delete [] Tprime_i[j], delete [] z_i[j];
		}
		A_i.clear(), B_i.clear(), T_i.clear(), Tprime_i.clear(), z_i.clear();
		// return
		return return_value;
	}
}

bool CanettiGennaroJareckiKrawczykRabinDKG::Reconstruct
	(const std::vector<size_t> &complaints,
	CanettiGennaroJareckiKrawczykRabinRVSS *rvss,
	std::vector<mpz_ptr> &z_i_in,
	std::vector< std::vector<mpz_ptr> > &a_ik_in,
	CachinKursawePetzoldShoupRBC *rbc, std::ostream &err)
{
	assert(t <= n);
	assert(i < n);
	assert(n == rbc->n);
	assert(i == rbc->j);

	// initialize
	mpz_t foo, bar, lhs, rhs;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);

	// set ID for RBC
	std::stringstream myID;
	myID << "CanettiGennaroJareckiKrawczykRabinDKG::Reconstruct()" << p << q << g << h << n << t;
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
			// broadcast shares for reconstruction of $z_i$ (where $i = *it$) 
			rbc->Broadcast(rvss->s_ji[*it][i]);
			rbc->Broadcast(rvss->sprime_ji[*it][i]);
			// prepare for collecting some shares
			std::vector<size_t> parties;
			parties.push_back(i); // our own shares are always available
			// now collect shares $s_{ij}$ and $s\prime_{ij}$ of other parties from QUAL
			for (std::vector<size_t>::iterator jt = QUAL.begin(); jt != QUAL.end(); ++jt)
			{
				if ((*jt != i) && (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end()))
				{
					if (rbc->DeliverFrom(rvss->s_ji[*it][*jt], *jt) && rbc->DeliverFrom(rvss->sprime_ji[*it][*jt], *jt))
					{
						// compute LHS for the check
						mpz_fpowm(fpowm_table_g, foo, g, rvss->s_ji[*it][*jt], p);
						mpz_fpowm(fpowm_table_h, bar, h, rvss->sprime_ji[*it][*jt], p);
						mpz_mul(lhs, foo, bar);
						mpz_mod(lhs, lhs, p);
						// compute RHS for the check
						mpz_set_ui(rhs, 1L);
						for (size_t k = 0; k <= t; k++)
						{
							mpz_ui_pow_ui(foo, *jt + 1, k); // adjust index $i$ in computation
							mpz_powm(bar, rvss->C_ik[*it][k], foo , p);
							mpz_mul(rhs, rhs, bar);
							mpz_mod(rhs, rhs, p);
						}
						// check equation (4)
						if (mpz_cmp(lhs, rhs))
							err << "P_" << i << ": bad share received from " << *jt << std::endl;
						else
							parties.push_back(*jt); // good share received
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
				mpz_mod(rhs, rhs, q); // computation of Lagrange coefficients finished
				mpz_mul(bar, rvss->s_ji[*it][*jt], rhs);
				mpz_mod(bar, bar, q);
				mpz_add(foo, foo, bar);
				mpz_mod(foo, foo, q);
			}
			mpz_set(z_i_in[*it], foo);
			err << "P_" << i << ": reconstructed z_" << *it << " = " << z_i_in[*it] << std::endl;
			// compute $f_i(z)$ using general interpolation
			std::vector<mpz_ptr> points, shares, f;
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
				mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3);
				points.push_back(tmp1), shares.push_back(tmp2), f.push_back(tmp3);
			}
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_set_ui(points[k], parties[k] + 1); // adjust index in computation
				mpz_set(shares[k], rvss->s_ji[*it][parties[k]]);
			}
			if (!interpolate_polynom(points, shares, q, f))
				throw false;
			err << "P_" << i << ": reconstructed f_0 = " << f[0] << std::endl;
			for (size_t k = 0; k < parties.size(); k++)
				mpz_set(a_ik_in[*it][k], f[k]);
			for (size_t k = 0; k < parties.size(); k++)
			{
				mpz_clear(points[k]), mpz_clear(shares[k]), mpz_clear(f[k]);
				delete [] points[k], delete [] shares[k], delete [] f[k];
			}
			points.clear(), shares.clear(), f.clear();
			parties.clear(); 
		}

		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
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

	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// ===================================================================================================================================


