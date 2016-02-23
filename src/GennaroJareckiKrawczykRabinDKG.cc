/*******************************************************************************
  GennaroJareckiKrawczykRabinDKG.cc,
                                       Secure |D|istributed |K|ey |G|eneration

     Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin:
       'Secure Distributed Key Generation for Discrete-Log Based Cryptosystems',
     Journal of Cryptology, Vol. 20 Nr. 1, pp. 51--83, Springer 2007.

   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

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

#include "GennaroJareckiKrawczykRabinDKG.hh"

GennaroJareckiKrawczykRabinDKG::GennaroJareckiKrawczykRabinDKG
	(size_t n_in, size_t t_in,
	mpz_srcptr p_CRS, mpz_srcptr q_CRS, mpz_srcptr g_CRS, mpz_srcptr h_CRS,
	unsigned long int fieldsize, unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize), n(n_in), t(t_in)
{
	mpz_init_set(p, p_CRS), mpz_init_set(q, q_CRS), mpz_init_set(g, g_CRS),
		mpz_init_set(h, h_CRS);

	mpz_init_set_ui(x_i, 0L), mpz_init_set_ui(xprime_i, 0L),
		mpz_init_set_ui(y_i, 1L), mpz_init_set_ui(y, 1L);

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool GennaroJareckiKrawczykRabinDKG::CheckGroup
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

bool GennaroJareckiKrawczykRabinDKG::Generate
	(size_t i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	std::ostream &err, bool simulate_faulty_behaviour)
{
	assert(n >= t);
	assert(n >= ((2 * t) + 1)); // synchronous failure assumption
	assert(i < n);
	assert(n == aiou->n);
	assert(n == rbc->n);
	assert(t == aiou->t);
	assert(t == rbc->t);
	assert(i == aiou->j);
	assert(i == rbc->j);

	// initialize
	mpz_t foo, bar, lhs, rhs;
	std::vector<mpz_ptr> a_i, b_i, g__a_i;
	std::vector< std::vector<mpz_ptr> > C_ik, A_ik, s_ij, sprime_ij, g__s_ij;
	std::vector<size_t> complaints, complaints_counter;

	mpz_init(foo), mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t k = 0; k < t; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		a_i.push_back(tmp1), b_i.push_back(tmp2);
		mpz_ptr tmp3 = new mpz_t();
		mpz_init(tmp3);
		g__a_i.push_back(tmp3);
	}
	for (size_t j = 0; j < n; j++)
	{
		std::vector<mpz_ptr> *vtmp = new std::vector<mpz_ptr>;
		std::vector<mpz_ptr> *vtmp1 = new std::vector<mpz_ptr>;
		for (size_t k = 0; k < t; k++)
		{
			mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
			mpz_init(tmp1), mpz_init(tmp2);
 			vtmp->push_back(tmp1);
			vtmp1->push_back(tmp2);
		}
		C_ik.push_back(*vtmp), A_ik.push_back(*vtmp1);
		std::vector<mpz_ptr> *vtmp2 = new std::vector<mpz_ptr>;
		std::vector<mpz_ptr> *vtmp3 = new std::vector<mpz_ptr>;
		std::vector<mpz_ptr> *vtmp4 = new std::vector<mpz_ptr>;
		for (size_t i2 = 0; i2 < n; i2++)
		{
			mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
			mpz_init(tmp1), mpz_init(tmp2);
			vtmp2->push_back(tmp1);
			vtmp3->push_back(tmp2);
			mpz_ptr tmp3 = new mpz_t();
			mpz_init(tmp3);
			vtmp4->push_back(tmp3);
		}
		s_ij.push_back(*vtmp2), sprime_ij.push_back(*vtmp3);
		g__s_ij.push_back(*vtmp4);
	}
	size_t simulate_faulty_randomizer = mpz_wrandom_ui() % 2L;

	try
	{
		// 1. Each party $P_i$ performs a Pedersen-VSS of a random
		//    value $z_i$ as a dealer:
		// (a) $P_i$ chooses two random polynomials $f_i(z)$ and
		//     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t$ where
		//     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t$ and
		//     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t$
		for (size_t k = 0; k < t; k++)
		{
			mpz_srandomm(a_i[k], q);
			mpz_srandomm(b_i[k], q);
		}
		// $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
		// for $k = 0, \ldots, t$.
		for (size_t k = 0; k < t; k++)
		{
			mpz_fspowm(fpowm_table_g, g__a_i[k], g, a_i[k], p);
			mpz_fspowm(fpowm_table_h, bar, h, b_i[k], p);
			mpz_mul(C_ik[i][k], g__a_i[k], bar);
			mpz_mod(C_ik[i][k], C_ik[i][k], p);
			rbc->Broadcast(C_ik[i][k]);
		}
		// $P_i$ computes the shares $s_{ij} = f_i(j) \bmod q$,
		// $s\prime_{ij} = f\prime_i(j) \bmod q$ and
		// sends $s_{ij}$, $s\prime_{ij}$ to party $P_j$.
		for (size_t j = 0; j < n; j++)
		{
			mpz_set_ui(s_ij[i][j], 0L);
			mpz_set_ui(sprime_ij[i][j], 0L);
			for (size_t k = 0; k < t; k++)
			{
				mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$
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
				aiou->Send(s_ij[i][j], j);
				aiou->Send(sprime_ij[i][j], j);
			}
		}
		// (b) Each party $P_j$ verifies the shares he received from
		//     the other parties. For each $i = 1, \ldots, n$, $P_j$
		//     checks if $g^{s_{ij}} h^{s\prime_{ij}} = \prod_{k=0}^t (C_{ik})^{j^k} \bmod p$.
		// Note that in this section the indicies $i$ and $j$ are exchanged for convenience.
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				for (size_t k = 0; k < t; k++)
				{
					if (!rbc->DeliverFrom(C_ik[j][k], j))
					{
						err << "P_" << i << ": receiving C_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
				}
				if (!aiou->Receive(s_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving s_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
				if (!aiou->Receive(sprime_ij[j][i], j, aiou->aio_scheduler_direct))
				{
					err << "P_" << i << ": receiving sprime_ij failed; complaint against P_" << j << std::endl;
					complaints.push_back(j);
					continue;
				}
			}
		}
		for (size_t j = 0; j < n; j++)
		{
			// compute LHS for the check
			mpz_fspowm(fpowm_table_g, g__s_ij[j][i], g, s_ij[j][i], p);
			mpz_fspowm(fpowm_table_h, bar, h, sprime_ij[j][i], p);
			mpz_mul(lhs, g__s_ij[j][i], bar);
			mpz_mod(lhs, lhs, p);
			// compute RHS for the check
			mpz_set_ui(rhs, 1L);
			for (size_t k = 0; k < t; k++)
			{
				mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$
				mpz_powm(bar, C_ik[j][k], foo , p);
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
		std::vector<size_t>::iterator it =
			std::unique(complaints.begin(), complaints.end());
		complaints.resize(std::distance(complaints.begin(), it));
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			mpz_set_ui(rhs, *it);
			rbc->Broadcast(rhs);
		}
		mpz_set_ui(rhs, n); // send end marker
		rbc->Broadcast(rhs);
		// (c) Each party $P_i$ who, as a dealer, received a complaint
		//     from party $P_j$ broadcasts the values $s_{ij}$,
		//     $s\prime_{ij}$ that satisfy (4).
		complaints.clear();
		for (size_t j = 0; j < n; j++)
			complaints_counter.push_back(0); // initialize counter
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
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
						complaints_counter[who]++;
						if (who == i)
							complaints.push_back(j);
					}
					cnt++;
				}
				while ((who < n) && (cnt < n)); // until end marker received
			}
		}
		if (complaints_counter[i])
		{
			std::sort(complaints.begin(), complaints.end());
			err << "P_" << i << ": there are " << complaints_counter[i] << " complaints against me from ";
			for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
				err << "P_" << *it << " ";
			err << std::endl;
			for (std::vector<size_t>::iterator it = complaints.begin();
				it != complaints.end(); ++it)
			{
				mpz_set_ui(lhs, *it); // who?
				rbc->Broadcast(lhs);
				rbc->Broadcast(s_ij[i][*it]);
				rbc->Broadcast(sprime_ij[i][*it]);
			}
		}
		mpz_set_ui(lhs, n); // send end marker
		rbc->Broadcast(lhs);
		// (d) Each party marks disqualified any party either
		//      * received more than $t$ complaints in Step 1(b), or
		//      * answered a complaint in Step 1(c) with values that 
		//        falsify (4).
		complaints.clear();
		for (size_t j = 0; j < n; j++)
		{
			if (j != i)
			{
				size_t who;
				if (complaints_counter[j] > t)
					complaints.push_back(j);
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
					// compute LHS for the check
					mpz_fspowm(fpowm_table_g, foo, g, foo, p);
					mpz_fspowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, foo, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k < t; k++)
					{
						mpz_ui_pow_ui(foo, j + 1, k); // adjust index $j$
						mpz_powm(bar, C_ik[who][k], foo , p);
						mpz_mul(rhs, rhs, bar);
						mpz_mod(rhs, rhs, p);
					}
					// check equation (4)
					if (mpz_cmp(lhs, rhs))
					{
						err << "P_" << i << ": checking 1(d) failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
					}
					cnt++;
				}
				while (cnt < n);
			}
		}
		// 2. Each party the builds the set of non-disqualified parties $QUAL$.
		for (size_t j = 0; j < n; j++)
			if (std::find(complaints.begin(), complaints.end(), j) == complaints.end())
				QUAL.push_back(j);
		err << "P_" << i << ": QUAL = { ";
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
			err << "P_" << *it << " ";
		err << "}" << std::endl;
		// 3. Each party $P_i$ sets his share of the secret as
		//    $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the value
		//    $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
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
		for (size_t k = 0; k < t; k++)
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
				for (size_t k = 0; k < t; k++)
				{
					if (!rbc->DeliverFrom(A_ik[j][k], j))
					{
						err << "P_" << i << ": receiving A_ik failed; complaint against P_" << j << std::endl;
						complaints.push_back(j);
						break;
					}
				}
				// compute LHS for the check
				// OPTIMIZED: mpz_fspowm(fpowm_table_g, lhs, g, s_ij[j][i], p);
				mpz_set(lhs, g__s_ij[j][i]);
				// compute RHS for the check
				mpz_set_ui(rhs, 1L);
				for (size_t k = 0; k < t; k++)
				{
					mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$
					mpz_powm(bar, A_ik[j][k], foo , p);
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
						break;
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
					mpz_fspowm(fpowm_table_g, lhs, g, foo, p);
					mpz_fspowm(fpowm_table_h, bar, h, bar, p);
					mpz_mul(lhs, lhs, bar);
					mpz_mod(lhs, lhs, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k < t; k++)
					{
						mpz_ui_pow_ui(foo, who + 1, k); // adjust index $i$
						mpz_powm(bar, C_ik[j][k], foo , p);
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
					mpz_fspowm(fpowm_table_g, lhs, g, foo, p);
					// compute RHS for the check
					mpz_set_ui(rhs, 1L);
					for (size_t k = 0; k < t; k++)
					{
						mpz_ui_pow_ui(foo, i + 1, k); // adjust index $i$
						mpz_powm(bar, A_ik[j][k], foo , p);
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
				while ((who < n) && (cnt < n)); // no end marker received
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
		if (complaints.size() > t)
			throw false;
		for (std::vector<size_t>::iterator it = complaints.begin(); it != complaints.end(); ++it)
		{
			// broadcast shares for reconstruction of $z_i$
			rbc->Broadcast(s_ij[i][*it]);
			// collect shares $s_{ij}$ from other parties
			size_t number_of_shares = 0;
			for (size_t j = 0; j < n; j++)
			{
				if ((j != i) && (std::find(complaints.begin(), complaints.end(), j) == complaints.end()) &&
					(std::find(QUAL.begin(), QUAL.end(), j) != QUAL.end()))
				{
					if (rbc->DeliverFrom(s_ij[*it][j], j))
						number_of_shares++;
					else
						err << "P_" << i << ": no share from " << j << std::endl;					
				}
			}
			if (number_of_shares < t)
			{
				err << "P_" << i << ": not enough shares collected" << std::endl;
				throw false;
			}
			// compute $z_i$ using Lagrange interpolation (without faulty party)
			mpz_set_ui(foo, 0L);
			for (std::vector<size_t>::iterator jt = QUAL.begin(); jt != QUAL.end(); ++jt)
			{
				if (std::find(complaints.begin(), complaints.end(), *jt) == complaints.end())
				{
					mpz_set_ui(rhs, 1L); // compute Lagrange constant
					for (std::vector<size_t>::iterator lt = QUAL.begin(); lt != QUAL.end(); ++lt)
					{
						if (*lt != *jt)
							mpz_mul_ui(rhs, rhs, (*lt + 1)); // adjust index
					}
					mpz_set_ui(lhs, 1L);
					for (std::vector<size_t>::iterator lt = QUAL.begin(); lt != QUAL.end(); ++lt)
					{
						if (*lt != *jt)
						{
							mpz_set_ui(bar, (*lt + 1)); // adjust index
							mpz_sub_ui(bar, bar, (*jt + 1)); // adjust index
							mpz_mul(lhs, lhs, bar);
						}
					}
					mpz_invert(lhs, lhs, q);
					mpz_mul(rhs, lhs, q);
					mpz_mod(rhs, rhs, q);
					mpz_mul(bar, s_ij[*it][*jt], rhs);
					mpz_mod(bar, bar, q);
					mpz_add(foo, foo, bar);
					mpz_mod(foo, foo, q);
				}
			}
			// compute $A_{i0} = g^{z_i} \bmod p$
			mpz_fspowm(fpowm_table_g, A_ik[*it][0], g, foo, p);
		}
		// For all parties in $QUAL$, set $y_i = A_{i0} = g^{z_i} \bmod p$.
		mpz_set(y_i, A_ik[i][0]);
		err << "P_" << i << ": y_i = " << y_i << std::endl;
		// Compute $y = \prod_{i \in QUAL} y_i \bmod p$.
		for (std::vector<size_t>::iterator it = QUAL.begin(); it != QUAL.end(); ++it)
		{
			mpz_mul(y, y, A_ik[*it][0]);
			mpz_mod(y, y, p);
		}
		err << "P_" << i << ": y = " << y << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
		for (size_t k = 0; k < t; k++)
		{
			mpz_clear(a_i[k]), mpz_clear(b_i[k]);
			delete a_i[k], delete b_i[k];
			mpz_clear(g__a_i[k]);
			delete g__a_i[k];
		}
		a_i.clear(), b_i.clear(), g__a_i.clear();
		for (size_t j = 0; j < n; j++)
		{
			for (size_t k = 0; k < t; k++)
			{
				mpz_clear(C_ik[j][k]);
				mpz_clear(A_ik[j][k]);
				delete C_ik[j][k];
				delete A_ik[j][k];
			}
			for (size_t i2 = 0; i2 < n; i2++)
			{
				mpz_clear(s_ij[j][i2]);
				mpz_clear(sprime_ij[j][i2]);
				delete s_ij[j][i2];
				delete sprime_ij[j][i2];
				mpz_clear(g__s_ij[j][i2]);
				delete g__s_ij[j][i2];
			}
			C_ik[j].clear(), A_ik[j].clear();
			s_ij[j].clear(), sprime_ij[j].clear();
			g__s_ij[j].clear();
		}
		C_ik.clear(), A_ik.clear();
		s_ij.clear(), sprime_ij.clear();
		g__s_ij.clear();
		// return
		return return_value;
	}
}

GennaroJareckiKrawczykRabinDKG::~GennaroJareckiKrawczykRabinDKG
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	QUAL.clear();
	mpz_clear(x_i), mpz_clear(xprime_i), mpz_clear(y_i), mpz_clear(y);

	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
