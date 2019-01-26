/*******************************************************************************
   BarnettSmartVTMF_dlog_GroupQR.cc, VTMF instance where $G := \mathbb{QR}_p$

     [BS03] Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

     [KK04] Takeshi Koshiba, Kaoru Kurosawa: 'Short Exponent Diffie-Hellman
       Problems', In Public Key Cryptography - PKC 2004: Proceedings 7th
     International Workshop on Theory and Practice in Public Key Cryptography,
     LNCS 2947, pp. 173--186, 2004.

     [Bo98] Dan Boneh: 'The Decision Diffie-Hellman Problem',
     Proceedings of the 3rd Algorithmic Number Theory Symposium,
     LNCS 1423, pp. 48--63, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007, 
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
#include "BarnettSmartVTMF_dlog_GroupQR.hh"

// additional headers
#include "mpz_srandom.hh"
#include "mpz_sprime.hh"
#include "mpz_spowm.hh"
#include "mpz_helper.hh"

BarnettSmartVTMF_dlog_GroupQR::BarnettSmartVTMF_dlog_GroupQR
	(const unsigned long int fieldsize, const unsigned long int exponentsize):
		BarnettSmartVTMF_dlog(fieldsize, fieldsize - 1L, true, false),
		E_size(exponentsize)
{
	// Create a finite abelian group $G$ where DDH is hard:
	// We use the subgroup of quadratic residues modulo $p$,
	// such that $p = 2q + 1$ and $p$, $q$ are both prime.
	// The integer 2 is a generator of $\mathbb{QR}_p$ since
	// we choose $p \equiv 7 \pmod{8}$. [Bo98, RS00]
	tmcg_mpz_sprime2g(p, q, fieldsize - 1L, TMCG_MR_ITERATIONS);
	mpz_set_ui(g, 2L), mpz_set_ui(k, 2L);
	
	// We shift the generator (according to [KK04]) to allow
	// the usage of shortened exponents. (cf. masking protocols)
	// We use the (Short, Full)-ElGamal variant [KK04] here,
	// i.e. the secret key should be still of full size $\ell_q$.
	if (mpz_sizeinbase(p, 2L) >= exponentsize)
	{
		mpz_t foo;
		mpz_init(foo);
		mpz_ui_pow_ui(foo, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
		mpz_powm(g, g, foo, p);
		mpz_clear(foo);
	}
	else
		mpz_set(g, 0L); // indicates an error
	
	// Precompute the $g$-table for the fast exponentiation.
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

BarnettSmartVTMF_dlog_GroupQR::BarnettSmartVTMF_dlog_GroupQR
	(std::istream& in,
	 const unsigned long int fieldsize, const unsigned long int exponentsize):
		BarnettSmartVTMF_dlog(in, fieldsize, fieldsize - 1L, true, false),
		E_size(exponentsize)
{
	mpz_set_ui(g, 2L);

	// We shift the generator (according to [KK04]) to allow
	// the usage of shortened exponents. (cf. masking protocols)
	// We use the (Short, Full)-ElGamal variant [KK04] here,
	// i.e. the secret key should be still of full size $\ell_q$.
	if (mpz_sizeinbase(p, 2L) >= exponentsize)
	{
		mpz_t foo;
		mpz_init(foo);
		mpz_ui_pow_ui(foo, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
		mpz_powm(g, g, foo, p);
		mpz_clear(foo);
	}
	else
		mpz_set(g, 0L); // indicates an error

	// Precompute the $g$-table for the fast exponentiation.
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

bool BarnettSmartVTMF_dlog_GroupQR::CheckGroup
	() const
{
	mpz_t foo, g2;
	
	mpz_init(foo), mpz_init(g2);
	try
	{
		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) || 
			(mpz_sizeinbase(q, 2L) < G_size))
				throw false;

		// Check whether $p$ has the correct form, i.e. $p = 2q + 1$.
		mpz_mul_2exp(foo, q, 1L);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;

		// Check whether $p$ and $q$ are both (probable) prime with a
		// soundness error probability ${} \le 4^{-TMCG_MR_ITERATIONS}$.
		if (!mpz_probab_prime_p(p, TMCG_MR_ITERATIONS) || 
			!mpz_probab_prime_p(q, TMCG_MR_ITERATIONS))
				throw false;

		// Check whether $p$ is congruent 7 modulo 8.
		if (!mpz_congruent_ui_p(p, 7L, 8L))
			throw false;

		// Check whether $g$ is a generator for the subgroup $G$ of 
		// order $q$. It is sufficient to assert that $g$ is a quadratic
		// residue mod $p$, i.e. we can simply do this by computing the
		// Legendre-Jacobi symbol.
		// Of course, we must also ensure that $g$ is not trivial, i.e.,
		// $1 < g < p-1$.
		mpz_sub_ui(foo, p, 1L);
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, foo) >= 0))
			throw false;
		if (mpz_jacobi(g, p) != 1L)
			throw false;

		// If we use a canonical value for $g$, further checks are needed.
		if (canonical_g)
		{
			if (mpz_sizeinbase(p, 2L) < E_size)
				throw false;
			mpz_set_ui(g2, 2L);
			mpz_ui_pow_ui(foo, 2L, mpz_sizeinbase(p, 2L) - E_size);
			mpz_powm(g2, g2, foo, p);
			if (mpz_cmp(g2, g))
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(g2);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog_GroupQR::CheckElement
	(mpz_srcptr a) const
{
	// Check whether $0 < a < p$.
	if ((mpz_cmp_ui(a, 0L) <= 0) || (mpz_cmp(a, p) >= 0))
		return false;
	
	// Check whether $a$ is a quadratic residue.
	return (mpz_jacobi(a, p) == 1L);
}

void BarnettSmartVTMF_dlog_GroupQR::RandomElement
	(mpz_ptr a) const
{
	// Choose randomly and uniformly an element from 
	// $\mathbb{Z}_p \setminus \{ 0 \}$.
	do
		tmcg_mpz_srandomm(a, p);
	while (!mpz_cmp_ui(a, 0L));
	
	// Square $a$ to obtain a quadratic residue from $\mathbb{QR}_p$.
	mpz_mul(a, a, a);
	mpz_mod(a, a, p);
}

void BarnettSmartVTMF_dlog_GroupQR::MaskingValue
	(mpz_ptr r) const
{
	// Choose randomly and uniformly an element from 
	// $\mathbb{Z}_q \setminus \{ 0, 1 \}$.
	if (mpz_sizeinbase(p, 2L) <= E_size)
	{
		do
			tmcg_mpz_srandomm(r, q);
		while (!mpz_cmp_ui(r, 0L) || !mpz_cmp_ui(r, 1L));
	}
	else
	{
		// Under the additional DLSE assumption we can reduce the size of
		// the exponent. Note that generator $g$ must be shifted [KK04].
		do
			tmcg_mpz_srandomb(r, E_size);
		while (!mpz_cmp_ui(r, 0L) || !mpz_cmp_ui(r, 1L));
	}
}

BarnettSmartVTMF_dlog_GroupQR::~BarnettSmartVTMF_dlog_GroupQR
	()
{
}
