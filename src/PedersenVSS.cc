/*******************************************************************************
  PedersenVSS.cc,
                                               |V|erifiable |S|ecret |S|haring

     [Pe92] Torben P. Pedersen: 'Non-Interactive and Information-Theoretic 
       Secure Verifiable Secret Sharing',
     Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 129--140, Springer 1992.

     [GJKR01] Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin:
       'Robust Threshold DSS Signatures',
     Information and Computation 164, pp. 54--84, 2001. 

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
#include "PedersenVSS.hh"

PedersenVSS::PedersenVSS
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
	mpz_init_set_ui(sigma_i, 0L), mpz_init_set_ui(tau_i, 0L);	
	for (size_t j = 0; j <= t; j++)
	{
		mpz_ptr tmp3 = new mpz_t();
		mpz_init(tmp3);
		A_j.push_back(tmp3);
	}

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

PedersenVSS::PedersenVSS
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
	mpz_init(sigma_i), mpz_init(tau_i);
	in >> sigma_i >> tau_i;
	for (size_t j = 0; j <= t; j++)
	{
		mpz_ptr tmp3 = new mpz_t();
		mpz_init(tmp3);
		A_j.push_back(tmp3);
	}
	for (size_t j = 0; j <= t; j++)
		in >> A_j[j];

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void PedersenVSS::PublishState
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	out << n << std::endl << t << std::endl << i << std::endl;
	out << sigma_i << std::endl;
	out << tau_i << std::endl;
	for (size_t j = 0; j <= t; j++)
		out << A_j[j] << std::endl;
}

std::string PedersenVSS::Label
	() const
{
	return label;
}

bool PedersenVSS::CheckGroup
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

bool PedersenVSS::Share
	(mpz_srcptr sigma,
	aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
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
	mpz_t foo, bar;
	std::vector<mpz_ptr> a_j, b_j;
	size_t complaints_counter = 0;
	std::vector<size_t> complaints_from;
	mpz_init(foo), mpz_init(bar);
	for (size_t j = 0; j <= t; j++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_j.push_back(tmp1), b_j.push_back(tmp2);
	}
	size_t simulate_faulty_randomizer = mpz_wrandom_ui() % 2L;
	size_t simulate_faulty_randomizer2 = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "PedersenVSS::Share()" << p << q << g << h << n << t << i << label;
	rbc->setID(myID.str());

	try
	{
		// The dealer first chooses two $t$-degree polynomials $f(z) = \sum_j a_j z^j$
		// and $f\prime(z) = \sum_j b_j z^j$ with random coefficients subject to
		// $f(0) = \sigma$ and sends to each player $P_i$ the values $\sigma_i = f(i)$
		// and $\tau_i = f\prime(i) \bmod q$. The dealer commits to each coefficient
		// of the polynomials $f$ and $f\prime$ by publishing the values
		// $A_j = g^{a_j} h^{b_j} \bmod p$.
		for (size_t j = 0; j <= t; j++)
		{
			if (use_very_strong_randomness)
			{
				if (j == 0)
					mpz_set(a_j[j], sigma);
				else
					mpz_ssrandomm(a_j[j], q);
				mpz_ssrandomm(b_j[j], q);
			}
			else
			{
				if (j == 0)
					mpz_set(a_j[j], sigma);
				else
					mpz_srandomm(a_j[j], q);
				mpz_srandomm(b_j[j], q);
			}
			mpz_fspowm(fpowm_table_g, foo, g, a_j[j], p);
			mpz_fspowm(fpowm_table_h, bar, h, b_j[j], p);
			mpz_mul(A_j[j], foo, bar);
			mpz_mod(A_j[j], A_j[j], p);
			rbc->Broadcast(A_j[j]);
		} 
		// The dealer sends $\sigma_i$ and $\tau_i$ to each player $P_i$.
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				mpz_set_ui(sigma_i, 0L);
				mpz_set_ui(tau_i, 0L);
				for (size_t k = 0; k <= t; k++)
				{
					mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
					mpz_mul(bar, foo, b_j[k]);
					mpz_mod(bar, bar, q);
					mpz_mul(foo, foo, a_j[k]);
					mpz_mod(foo, foo, q);
					mpz_add(sigma_i, sigma_i, foo);
					mpz_mod(sigma_i, sigma_i, q);				
					mpz_add(tau_i, tau_i, bar);
					mpz_mod(tau_i, tau_i, q);
				}
				if (simulate_faulty_behaviour && simulate_faulty_randomizer && (mpz_wrandom_ui() % 2L))
					mpz_add_ui(sigma_i, sigma_i, 1L);
				if (!aiou->Send(sigma_i, j, 0))
				{
					err << "P_" << i << ": sending sigma_i failed for P_" << j << std::endl;
					continue;
				}
				if (!aiou->Send(tau_i, j, 0))
					err << "P_" << i << ": sending tau_i failed for P_" << j << std::endl;
			}
		}
		// As in Feldman's VSS the players who hold shares that do not satisfy the
		// above equation broadcast a complaint. If more than $t$ players complain
		// the dealer is disqualified. Otherwise the dealer broadcasts the values
		// $\sigma_i$ and $\tau_i$ matching the above equation for each complaining
		// player $P_i$.
		complaints_from.clear(); // reset
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				size_t who;
				size_t cnt = 0;
				std::map<size_t, bool> dup;
				do
				{
					if (!rbc->DeliverFrom(foo, j))
					{
						err << "P_" << i << ": receiving who failed from P_" << j << std::endl;
						break;
					}
					who = mpz_get_ui(foo);
					if ((who < n) && (who == i) && !dup.count(j))
					{
						err << "P_" << i << ": receiving complaint against me from P_" << j << std::endl;
						complaints_counter++;
						dup.insert(std::pair<size_t, bool>(j, true)); // mark as counted for $P_j$
						complaints_from.push_back(j);
					}
					else if (who < n)
						err << "P_" << i << ": bad complaint against P_" << who << " from P_" << j << std::endl;
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		err << "P_" << i << ": complaints_counter = " << complaints_counter << std::endl;
		if (complaints_counter > t)
			throw false;
		else if (complaints_counter > 0)
		{
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "P_" << i << ": there are " << complaints_counter << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
			{
				mpz_set_ui(foo, *it); // who?
				rbc->Broadcast(foo);
				mpz_set_ui(sigma_i, 0L);
				if (simulate_faulty_behaviour && simulate_faulty_randomizer2 && (mpz_wrandom_ui() % 2L))
					mpz_add_ui(sigma_i, sigma_i, 1L);
				mpz_set_ui(tau_i, 0L);
				for (size_t k = 0; k <= t; k++)
				{
					mpz_ui_pow_ui(foo, *it + 1, k); // adjust index $j$ in computation
					mpz_mul(bar, foo, b_j[k]);
					mpz_mod(bar, bar, q);
					mpz_mul(foo, foo, a_j[k]);
					mpz_mod(foo, foo, q);
					mpz_add(sigma_i, sigma_i, foo);
					mpz_mod(sigma_i, sigma_i, q);				
					mpz_add(tau_i, tau_i, bar);
					mpz_mod(tau_i, tau_i, q);
				}
				rbc->Broadcast(sigma_i);
				rbc->Broadcast(tau_i);
			}
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
		}

		mpz_set_ui(sigma_i, 1L);
		mpz_set_ui(tau_i, 1L);
		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(foo), mpz_clear(bar);
		for (size_t j = 0; j <= t; j++)
		{
			mpz_clear(a_j[j]), mpz_clear(b_j[j]);
			delete [] a_j[j], delete [] b_j[j];
		}
		a_j.clear(), b_j.clear();
		// return
		return return_value;
	}
}

bool PedersenVSS::Share
	(size_t dealer,
	aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, const bool simulate_faulty_behaviour)
{
	assert(t <= n);
	assert(i < n);
	assert(dealer < n);
	assert(n == rbc->n);
	assert(n == aiou->n);
	assert(i == rbc->j);
	assert(i == aiou->j);

	// checking maximum synchronous t-resilience
	if ((2 * t) >= n)
		err << "WARNING: maximum synchronous t-resilience exceeded" << std::endl;

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<size_t> complaints, complaints_from;
	size_t complaints_counter = 0;
	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	size_t simulate_faulty_randomizer = mpz_wrandom_ui() % 2L;

	// set ID for RBC
	std::stringstream myID;
	myID << "PedersenVSS::Share()" << p << q << g << h << n << t << dealer << label;
	rbc->setID(myID.str());

	try
	{
		// The dealer commits to each coefficient of the polynomials $f$ and
		// $f\prime$ by publishing the values $A_j = g^{a_j} h^{b_j} \bmod p$.
		for (size_t j = 0; j <= t; j++)
		{
			if (!rbc->DeliverFrom(A_j[j], dealer))
			{
				err << "P_" << i << ": receiving A_j failed; complaint against P_" << dealer << std::endl;
				complaints.push_back(dealer);
				break;
			}
		}
		// This allows the players to verify the received shares by checking that
		// $g^{\sigma_i} h^{\tau_i} = \prod_{j} (A_j)^{i^j} \bmod p$.
		if (!aiou->Receive(sigma_i, dealer, aiou->aio_scheduler_direct))
		{
			err << "P_" << i << ": receiving sigma_i failed; complaint against dealer P_" << dealer << std::endl;
			complaints.push_back(dealer);
		}
		if (!aiou->Receive(tau_i, dealer, aiou->aio_scheduler_direct))
		{
			err << "P_" << i << ": receiving tau_i failed; complaint against dealer P_" << dealer << std::endl;
			complaints.push_back(dealer);
		}
		// compute LHS for the check
		mpz_fspowm(fpowm_table_g, foo, g, sigma_i, p);
		mpz_fspowm(fpowm_table_h, bar, h, tau_i, p);
		mpz_mul(lhs, foo, bar);
		mpz_mod(lhs, lhs, p);
		// compute RHS for the check
		mpz_set_ui(rhs, 1L);
		for (size_t j = 0; j <= t; j++)
		{
			mpz_ui_pow_ui(foo, i + 1, j); // adjust index $i$ in computation
			mpz_powm(bar, A_j[j], foo, p);
			mpz_mul(rhs, rhs, bar);
			mpz_mod(rhs, rhs, p);
		}
		// check equation (2)
		if (mpz_cmp(lhs, rhs))
		{
			err << "P_" << i << ": checking share with equation (2) failed; complaint against dealer P_" << dealer << std::endl;
			complaints.push_back(dealer);
		}
		// As in Feldman's VSS the players who hold shares that do not satisfy the
		// above equation broadcast a complaint. If more than $t$ players complain
		// the dealer is disqualified. Otherwise the dealer broadcasts the values
		// $\sigma_i$ and $\tau_i$ matching the above equation for each complaining
		// player $P_i$.
		std::sort(complaints.begin(), complaints.end());
		std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			err << "P_" << i << ": broadcast complaint against dealer P_" << *it << std::endl;
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
		}
		if (simulate_faulty_behaviour && simulate_faulty_randomizer)
		{
			err << "P_" << i << ": broadcast false complaint against dealer P_" << dealer << std::endl;
			mpz_set_ui(rhs, dealer);
			rbc->Broadcast(rhs);
		}
		mpz_set_ui(rhs, n); // broadcast end marker
		rbc->Broadcast(rhs);
		complaints.clear(), complaints_from.clear(); // reset
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (j != dealer))
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
					if ((who < n) && (who == dealer) && !dup.count(j))
					{
						err << "P_" << i << ": receiving complaint against dealer P_" << dealer << " from P_" << j << std::endl;
						complaints_counter++;
						dup.insert(std::pair<size_t, bool>(j, true)); // mark as counted for $P_j$
						complaints_from.push_back(j);
					}
					else if ((who < n))
					{
						err << "P_" << i << ": bad complaint against P_" << who << " from P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt <= n)); // until end marker received
			}
		}
		err << "P_" << i << ": complaints_counter = " << complaints_counter << std::endl;
		if (complaints_counter > t)
			throw false;
		else if (complaints_counter > 0)
		{
			complaints.clear(); // reset
			std::sort(complaints_from.begin(), complaints_from.end());
			err << "P_" << i << ": there are " << complaints_counter << " complaints against dealer from ";
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			err << "P_" << i << ": some corresponding shares have been revealed to public!" << std::endl;
			for (std::vector<size_t>::iterator it = complaints_from.begin(); it != complaints_from.end(); ++it)
			{
				if (!rbc->DeliverFrom(lhs, dealer))
				{
					err << "P_" << i << ": receiving who failed; complaint against dealer P_" << dealer << std::endl;
					complaints.push_back(dealer);
					break;
				}
				size_t who = mpz_get_ui(lhs);
				if ((who >= n) || (who != *it))
				{
					err << "P_" << i << ": bad who value; complaint against dealer P_" << dealer << std::endl;
					complaints.push_back(dealer);
					break;
				}
				if (!rbc->DeliverFrom(foo, dealer))
				{
					err << "P_" << i << ": receiving foo failed; complaint against dealer P_" << dealer << std::endl;
					complaints.push_back(dealer);
					break;
				}
				if (!rbc->DeliverFrom(bar, dealer))
				{
					err << "P_" << i << ": receiving bar failed; complaint against dealer P_" << dealer << std::endl;
					complaints.push_back(dealer);
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
				for (size_t j = 0; j <= t; j++)
				{
					mpz_ui_pow_ui(foo, who + 1, j); // adjust index $i$ in computation
					mpz_powm(bar, A_j[j], foo , p);
					mpz_mul(rhs, rhs, bar);
					mpz_mod(rhs, rhs, p);
				}
				// check equation (2)
				if (mpz_cmp(lhs, rhs))
				{
					err << "P_" << i << ": checking equation (2) failed; complaint against dealer P_" << dealer << std::endl;
					complaints.push_back(dealer);
				}
				else if (who == i)
				{
					err << "P_" << i << ": shares have been adjusted by public values" << std::endl;
					mpz_set(sigma_i, s);
					mpz_set(tau_i, sprime);
				}
				mpz_clear(s), mpz_clear(sprime);
			}
			std::sort(complaints.begin(), complaints.end());
			std::vector<size_t>::iterator it = std::unique(complaints.begin(), complaints.end());
			complaints.resize(std::distance(complaints.begin(), it));
			if (complaints.size() > 0)
				throw false;
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

bool PedersenVSS::Reconstruct
	(const size_t dealer, mpz_ptr sigma,
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
	myID << "PedersenVSS::Reconstruct()" << p << q << g << h << n << t << dealer << label;
	rbc->setID(myID.str());
	
	try
	{
		// broadcast own shares for public reconstruction
		if (i != dealer)
		{
			if (mpz_cmp_ui(sigma_i, 0L) && mpz_cmp_ui(tau_i, 0L))
			{
				rbc->Broadcast(sigma_i);
				rbc->Broadcast(tau_i);
			}
			else
			{
				err << "P_" << i << ": no shares stored for reconstruction" << std::endl;
				throw false;
			}
		}
		// prepare for collecting shares of other parties
		std::vector<size_t> parties;
		parties.push_back(i); // my own share is always available
		mpz_set(shares[i], sigma_i);
		for (size_t j = 0; j < n; j++)
		{
			if ((j != i) && (j != dealer))
			{
				if (rbc->DeliverFrom(shares[j], j) && rbc->DeliverFrom(bar, j))
				{
					// compute LHS for the check
					mpz_fpowm(fpowm_table_g, foo, g, shares[j], p);
					mpz_fpowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, foo, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k <= t; k++)
					{
						mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$ in computation
						mpz_powm(bar, A_j[k], foo, p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (2)
					if (mpz_cmp(lhs, rhs))
						err << "P_" << i << ": ignore bad share received from P_" << j << std::endl;
					else
						parties.push_back(j);
				}
				else
					err << "P_" << i << ": no share received from P_" << j << std::endl;			
			}
		}
		// no reconstruction, if this party was the dealer
		if (i == dealer)
			throw true;
		// check whether enough verified shares (i.e. ${} \ge t + 1$) have been collected
		if (parties.size() <= t)
		{
			err << "P_" << i << ": not enough shares collected" << std::endl;
			parties.clear();
			throw false;
		}
		else
			parties.resize(t + 1);
		err << "P_" << i << ": reconstructing parties = ";
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
			err << "P_" << *jt << " ";
		err << std::endl;
		// compute $\sigma$ using Lagrange interpolation (without corrupted parties)
		mpz_set_ui(sigma, 0L);
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
			mpz_mul(bar, shares[*jt], rhs); // use the provided shares (interpolation points)
			mpz_mod(bar, bar, q);
			mpz_add(sigma, sigma, bar);
			mpz_mod(sigma, sigma, q);
		}
		parties.clear();
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

PedersenVSS::~PedersenVSS
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	mpz_clear(sigma_i), mpz_clear(tau_i);
	for (size_t j = 0; j < A_j.size(); j++)
	{
		mpz_clear(A_j[j]);
		delete [] A_j[j];
	}
	A_j.clear();
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
