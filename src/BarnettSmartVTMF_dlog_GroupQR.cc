/*******************************************************************************
   BarnettSmartVTMF_dlog_GroupQR.cc, VTMF instance where $G := \mathbb{QR}_p$

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
              Statements about Discrete Logarithms', Technical Report, 1997

     [KK04] Takeshi Koshiba, Kaoru Kurosawa: 'Short Exponent Diffie-Hellman
             Problems', In Public Key Cryptography - PKC 2004: Proceedings
            7th International Workshop on Theory and Practice in Public Key
             Cryptography, LNCS 2947, pp. 173--186, 2004

   This file is part of libTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "BarnettSmartVTMF_dlog_GroupQR.hh"

BarnettSmartVTMF_dlog_GroupQR::BarnettSmartVTMF_dlog_GroupQR
	(unsigned long int fieldsize, unsigned long int exponentsize):
		BarnettSmartVTMF_dlog(fieldsize, exponentsize), E_size(exponentsize)
{
	// Create a finite abelian group $G$ where DDH is hard:
	// We use the subgroup of quadratic residues modulo $p$,
	// such that $p = 2q + 1$ and $p$, $q$ are both prime.
	// The number 2 is a generator of $\mathbb{QR}_p$ since
	// $p \equiv 7 \pmod{8}$.
	mpz_sprime2g(p, q, fieldsize - 1L), mpz_set_ui(g, 2L), mpz_set_ui(k, 2L);
	G_size = fieldsize - 1L;
	
	// We shift the generator (according to [KK04]) for the later
	// following usage of shortened exponents.(masking protocols)
	// We use the (Short, Full)-ElGamal variant [KK04] here,
	// i.e. the secret key should be still of full size $\ell_q$.
	assert(mpz_sizeinbase(p, 2L) >= exponentsize);
	mpz_ui_pow_ui(h, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
	mpz_powm(g, g, h, p);
	
	// Precompute the $g$-table for the fast exponentiation.
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

BarnettSmartVTMF_dlog_GroupQR::BarnettSmartVTMF_dlog_GroupQR
	(std::istream &in,
	unsigned long int fieldsize, unsigned long int exponentsize):
		BarnettSmartVTMF_dlog(in, fieldsize, exponentsize), E_size(exponentsize)
{
	mpz_set_ui(g, 2L), mpz_set_ui(k, 2L);
	G_size = fieldsize - 1L;
	
	// Now shift the generator (according to [KK04]) for the later
	// following usage of shortened exponents. (masking protocols)
	// We use the (Short, Full)-ElGamal variant [KK04] here,
	// i.e. the secret key should be still of full size $\ell_q$.
	assert(mpz_sizeinbase(p, 2L) >= exponentsize);
	mpz_ui_pow_ui(h, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
	mpz_powm(g, g, h, p);
	
	// Precompute the $g$-table for the fast exponentiation.
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

bool BarnettSmartVTMF_dlog_GroupQR::CheckGroup
	()
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) || (mpz_sizeinbase(q, 2L) < G_size))
			throw false;
		
		// Check whether $p$ has the correct form, i.e. $p = 2q + 1$.
		mpz_mul_2exp(foo, q, 1L);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;
		
		// Check whether $p$ and $q$ are both (probable) prime with
		// soundness error probability ${} \le 4^{-64}$.
		if (!mpz_probab_prime_p(p, 64L) || !mpz_probab_prime_p(q, 64L))
			throw false;
		
		// Check whether $p$ is congruent 7 modulo 8.
		if (!mpz_congruent_ui_p(p, 7L, 8L))
			throw false;
		
		// Check whether $g$ is a generator of the subgroup $G$. It is sufficient
		// to assert that $g$ is a quadratic residue modulo $p$, i.e. we can
		// simply do this check by computing the Legendre-Jacobi symbol. Further,
		// we have to check that $g$ is not equal one.
		if ((mpz_cmp_ui(g, 1L) == 0L) || (mpz_jacobi(g, p) != 1L))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog_GroupQR::RandomElement
	(mpz_ptr a)
{
	// choose a random element of $\mathbb{Z}_p$
	do
		mpz_srandomm(a, p);
	while (mpz_cmp_ui(a, 0L) == 0L);
	// square $a$ to obtain $a^2 \in\mathbb{QR}_p$ (quadratic residue)
	mpz_powm_ui(a, a, 2L, p);
	
	assert(mpz_jacobi(a, p) == 1L);
}

void BarnettSmartVTMF_dlog_GroupQR::IndexElement
	(mpz_ptr a, std::size_t index)
{
	// simply compute $g^i mod p$
	mpz_fpowm_ui(fpowm_table_g, a, g, index, p);
	
	assert(mpz_jacobi(a, p) == 1L);
}

bool BarnettSmartVTMF_dlog_GroupQR::KeyGenerationProtocol_UpdateKey
	(std::istream &in)
{
	mpz_t foo, t, c, r;
	
	mpz_init(foo), mpz_init(t), mpz_init(c), mpz_init(r);
	in >> foo >> c >> r;
	
	try
	{
		// verify the size of $foo$
		if (mpz_cmp(foo, p) >= 0L)
			throw false;
		
		// verify in-group property
		if (mpz_jacobi(foo, p) != 1L)
			throw false;
		
		// verify the size of $r$
		if (mpz_cmp(r, q) >= 0L)
			throw false;
		
		// verify proof of knowledge [CaS97]
		mpz_fpowm(fpowm_table_g, t, g, r, p);
		mpz_powm(r, foo, c, p);
		mpz_mul(t, t, r);
		mpz_mod(t, t, p);
		mpz_shash(r, 3, g, foo, t);
		if (mpz_cmp(c, r))
			throw false;
		
		// update the global key h
		mpz_mul(h, h, foo);
		mpz_mod(h, h, p);
		
		// store the public key
		mpz_ptr tmp = new mpz_t();
		std::ostringstream fp;
		mpz_init_set(tmp, foo);
		mpz_shash(t, 1, foo);
		fp << t;
		h_j[fp.str()] = tmp;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(t), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog_GroupQR::VerifiableMaskingProtocol_Mask
	(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r)
{
	// choose the masking value $r \in Z_q$ randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= E_size)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the random exponent. [KK04]
		mpz_srandomb(r, E_size);
	}
	
	// compute $c_1 = g^r \bmod p$
	mpz_fspowm(fpowm_table_g, c_1, g, r, p);
	
	// compute $c_2 = m \cdot h^r \bmod p$
	mpz_fspowm(fpowm_table_h, c_2, h, r, p);
	mpz_mul(c_2, c_2, m);
	mpz_mod(c_2, c_2, p);
}

bool BarnettSmartVTMF_dlog_GroupQR::VerifiableMaskingProtocol_Verify
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream &in)
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// verify in-group properties
		if ((mpz_jacobi(c_1, p) != 1L) || (mpz_jacobi(c_2, p) != 1L))
			throw false;
		
		// invoke CP(c_1, c_2/m, g, h; r) as verifier
		assert(mpz_invert(foo, m, p));
		mpz_invert(foo, m, p);
		mpz_mul(foo, foo, c_2);
		mpz_mod(foo, foo, p);
		if (!CP_Verify(c_1, foo, g, h, in, true))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog_GroupQR::VerifiableRemaskingProtocol_Mask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r)
{
	// choose the masking value $r \in Z_q$ randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= E_size)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the random exponent. [KK04]
		mpz_srandomb(r, E_size);
	}
	
	// compute $c'_1 = c_1 \cdot g^r \bmod p$
	mpz_fspowm(fpowm_table_g, c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute $c'_2 = c_2 \cdot h^r \bmod p$
	mpz_fspowm(fpowm_table_h, c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog_GroupQR::VerifiableRemaskingProtocol_RemaskValue
	(mpz_ptr r)
{
	// choose the masking value $r \in Z_q$ randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= E_size)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the random exponent. [KK04]
		mpz_srandomb(r, E_size);
	}
}

bool BarnettSmartVTMF_dlog_GroupQR::VerifiableRemaskingProtocol_Verify
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	std::istream &in)
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// verify in-group properties
		if ((mpz_jacobi(c__1, p) != 1L) || (mpz_jacobi(c__2, p) != 1L))
			throw false;
		
		// invoke CP(c'_1/c_1, c'_2/c_2, g, h; r) as verifier
		assert(mpz_invert(foo, c_1, p));
		mpz_invert(foo, c_1, p);
		mpz_mul(foo, foo, c__1);
		mpz_mod(foo, foo, p);
		assert(mpz_invert(bar, c_2, p));
		mpz_invert(bar, c_2, p);
		mpz_mul(bar, bar, c__2);
		mpz_mod(bar, bar, p);
		if (!CP_Verify(foo, bar, g, h, in, true))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog_GroupQR::VerifiableDecryptionProtocol_Verify_Update
	(mpz_srcptr c_1, std::istream &in)
{
	mpz_t d_j, h_j_fp;
	std::ostringstream fp;
	
	mpz_init(d_j), mpz_init(h_j_fp);
	in >> d_j >> h_j_fp;
	
	try
	{
		// public key stored?
		fp << h_j_fp;
		if (h_j.find(fp.str()) == h_j.end())
			throw false;
		
		// verify the size of $d_j$
		if (mpz_cmp(d_j, p) >= 0L)
			throw false;
		
		// verify in-group property
		if (mpz_jacobi(d_j, p) != 1L)
			throw false;
		
		// invoke CP(d_j, h_j, c_1, g; x_j) as verifier
		if (!CP_Verify(d_j, h_j[fp.str()], c_1, g, in, false))
			throw false;
		
		// update the value of $d$
		mpz_mul(d, d, d_j);
		mpz_mod(d, d, p);
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(d_j), mpz_clear(h_j_fp);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog_GroupQR::VerifiableDecryptionProtocol_Verify_Finalize
	(mpz_srcptr c_2, mpz_ptr m)
{
	assert(mpz_invert(m, d, p));
	
	// finalize the decryption
	mpz_invert(m, d, p);
	mpz_mul(m, m, c_2);
	mpz_mod(m, m, p);
	
	assert(mpz_jacobi(m, p) == 1L);
}

BarnettSmartVTMF_dlog_GroupQR::~BarnettSmartVTMF_dlog_GroupQR
	()
{
}
