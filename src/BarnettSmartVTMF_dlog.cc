/*******************************************************************************
   BarnettSmartVTMF_dlog.cc, Verifiable l-out-of-l Threshold Masking Function

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
             Statements about Discrete Logarithms', Technical Report, 1997

   This file is part of libTMCG.

 Copyright (C) 2004 Heiko Stamer, <stamer@gaos.org>

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

#include "BarnettSmartVTMF_dlog.hh"

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(unsigned long int groupsize)
{
	// initalize libgcrypt
	if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
	{
		std::cerr << "libgcrypt: need library version >= " <<
			TMCG_LIBGCRYPT_VERSION << std::endl;
		exit(-1);
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO))
	{
		std::cerr << "libgcrypt: algorithm " << TMCG_GCRY_MD_ALGO <<
			" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
			"] not available" << std::endl;
		exit(-1);
	}
	
	// Create a finite abelian group G where DDH is hard:
	// We use the subgroup of quadratic residues modulo p,
	// such that p = 2q + 1 and p, q are both prime.
	mpz_init(p), mpz_init(q), mpz_init_set_ui(g, 2L);
	mpz_sprime2g(p, q, groupsize - 1L);
	
	// initalize the key
	mpz_init(x_i), mpz_init(h_i), mpz_init(h), mpz_init(d);
}

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(std::istream &in)
{
	// initalize libgcrypt
	if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
	{
		std::cerr << "libgcrypt: need library version >= " <<
			TMCG_LIBGCRYPT_VERSION << std::endl;
		exit(-1);
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO))
	{
		std::cerr << "libgcrypt: algorithm " << TMCG_GCRY_MD_ALGO <<
			" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
			"] not available" << std::endl;
		exit(-1);
	}
	
	// initalize the finite abelian group G and set the generator to 2
	mpz_init(q);
	in >> q;
	mpz_init(p), mpz_init_set_ui(g, 2L);
	mpz_mul_2exp(p, q, 1L), mpz_add_ui(p, p, 1L);
	
	// initalize the key
	mpz_init(x_i), mpz_init(h_i), mpz_init(h), mpz_init(d);
}

bool BarnettSmartVTMF_dlog::CheckGroup
	(unsigned long int groupsize)
{
	mpz_t foo;
	
	mpz_init(foo);
	
	try
	{
		// check whether q has appropriate length
		if ((mpz_sizeinbase(p, 2L) < (groupsize - 8L)) ||
			(mpz_sizeinbase(p, 2L) > (groupsize + 4096L)))
				throw false;
		
		// check whether p, q are both (probable) prime
		if (!(mpz_probab_prime_p(p, 25L) && mpz_probab_prime_p(q, 25L)))
			throw false;
		
		// check whether p is congruent 7 modulo 8
		if (!mpz_congruent_ui_p(p, 7L, 8L))
			throw false;
		
		// check whether g = 2 is a generator of the group G
		// It is sufficient to assert that g is a quadratic residue
		// modulo p, i.e. we check g^{(p-1)/2} \equiv 1 \pmod{p}.
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
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

void BarnettSmartVTMF_dlog::PublishGroup
	(std::ostream &out)
{
	out << q << std::endl;
}

void BarnettSmartVTMF_dlog::RandomElement
	(mpz_ptr a)
{
	// choose a random element of G (it has to be a quadratic residue)
	do
		mpz_srandomm(a, p);
	while (mpz_cmp_ui(a, 0L) == 0L);
	mpz_powm_ui(a, a, 2L, p);
	
	assert(mpz_jacobi(a, p) == 1L);
}

void BarnettSmartVTMF_dlog::IndexElement
	(mpz_ptr a, std::size_t index)
{
	// choose the index-th element of G (quadratic residue)
	// Notice that a call to IndexElement(a, 0) returns the identity
	// of G, because 1 is the smallest quadratic residue mod p.
	mpz_set_ui(a, 0L);
	do
	{
		do
			mpz_add_ui(a, a, 1L);
		while (mpz_jacobi(a, p) != 1);
	}
	while (index--);
	
	assert(mpz_jacobi(a, p) == 1);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_GenerateKey
	()
{
	// generate the random private key x_i \in Z_q
	mpz_srandomm(x_i, q);
	
	// compute h_i = g^{x_i} \bmod p (with blinding techniques)
	mpz_sspowm(h_i, g, x_i, p);
	
	// set public key h
	mpz_set(h, h_i);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_PublishKey
	(std::ostream &out)
{
	mpz_t v, t, c, r;
	
	// proof of knowledge [CaS97]
	mpz_init(v), mpz_init(t), mpz_init(c), mpz_init(r);
		
		// commitment
		mpz_srandomm(v, q);
		mpz_sspowm(t, g, v, p);
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// this part of the PK non-interactive, i.e. we turn it
		// into a statistically zero-knowledge (signature scheme style)
		// proof of knowledge (SPK) in the random oracle model.
		mpz_shash(c, g, h_i, t);
		// response
		mpz_mul(r, c, x_i);
		mpz_neg(r, r);
		mpz_add(r, r, v);
		mpz_mod(r, r, q);
		
	out << h_i << std::endl << c << std::endl << r << std::endl;
	mpz_clear(v), mpz_clear(t), mpz_clear(c), mpz_clear(r);
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_UpdateKey
	(std::istream &in)
{
	mpz_t foo, t, c, r;
	
	mpz_init(foo), mpz_init(t), mpz_init(c), mpz_init(r);
	in >> foo >> c >> r;
	
	try
	{
		// verify proof of knowledge [CaS97]
		mpz_powm(t, g, r, p);
		mpz_powm(r, foo, c, p);
		mpz_mul(t, t, r);
		mpz_mod(t, t, p);
		mpz_shash(r, g, foo, t);
		if (mpz_cmp(c, r))
			throw false;
		
		// update public key h
		mpz_mul(h, h, foo);
		mpz_mod(h, h, p);
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(t), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::CP_Prove
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, mpz_srcptr alpha,
	std::ostream &out)
{
	mpz_t a, b, omega, c, r;
	
	// proof of knowledge (equality of discrete logarithms) [CaS97]
	mpz_init(c), mpz_init(r), mpz_init(a), mpz_init(b), mpz_init(omega);
		
		// commitment
		mpz_srandomm(omega, q);
		mpz_sspowm(a, gg, omega, p);
		mpz_sspowm(b, hh, omega, p);
		
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// this part of the PK non-interactive, i.e. we turn it
		// into a statistically zero-knowledge (signature scheme style)
		// proof of knowledge (SPK) in the random oracle model.
		mpz_shash(c, a, b, x, y, gg, hh);
		
		// response
		mpz_mul(r, c, alpha);
		mpz_neg(r, r);
		mpz_add(r, r, omega);
		mpz_mod(r, r, q);
		
	out << a << std::endl << b << std::endl << c << std::endl << r << std::endl;
	mpz_clear(c), mpz_clear(r), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
}

bool BarnettSmartVTMF_dlog::CP_Verify
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, std::istream &in)
{
	mpz_t foo, bar, a, b, c, r;
	
	mpz_init(foo), mpz_init(bar);
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r);
	in >> a >> b >> c >> r;
	
	try
	{
		// verify proof of knowledge (equality of discrete logarithms) [CaS97]
		mpz_powm(foo, x, c, p);
		mpz_powm(bar, gg, r, p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, p);
		if (mpz_cmp(foo, a))
			throw false;
		mpz_powm(foo, y, c, p);
		mpz_powm(bar, hh, r, p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, p);
		if (mpz_cmp(foo, b))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Mask
	(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r)
{
	// generate the random masking value r \in Z_q
	mpz_srandomm(r, q);
	
	// compute c_1 = g^r \bmod p
	mpz_sspowm(c_1, g, r, p);
	
	// compute c_2 = m \cdot h^r \bmod p
	mpz_sspowm(c_2, h, r, p);
	mpz_mul(c_2, c_2, m);
	mpz_mod(c_2, c_2, p);
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Prove
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r, std::ostream &out)
{
	mpz_t foo;
	
	// CP(c_1, c_2/m, g, h; r)
	mpz_init(foo);
	assert(mpz_invert(foo, m, p));
	mpz_invert(foo, m, p);
	mpz_mul(foo, foo, c_2);
	mpz_mod(foo, foo, p);
	CP_Prove(c_1, foo, g, h, r, out);
	mpz_clear(foo);
}

bool BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Verify
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream &in)
{
	mpz_t foo;
	
	mpz_init(foo);
	
	try
	{
		// CP(c_1, c_2/m, g, h; r)
		assert(mpz_invert(foo, m, p));
		mpz_invert(foo, m, p);
		mpz_mul(foo, foo, c_2);
		mpz_mod(foo, foo, p);
		if (!CP_Verify(c_1, foo, g, h, in))
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

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Mask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r)
{
	// generate the random masking value r \in Z_q
	mpz_srandomm(r, q);
	
	// compute c'_1 = c_1 \cdot g^r \bmod p
	mpz_sspowm(c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute c'_2 = c_2 \cdot h^r \bmod p
	mpz_sspowm(c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_RemaskValue
	(mpz_ptr r)
{
	// generate random masking value r \in Z_q
	mpz_srandomm(r, q);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Remask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_srcptr r)
{
	// compute c'_1 = c_1 \cdot g^r \bmod p
	mpz_sspowm(c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute c'_2 = c_2 \cdot h^r \bmod p
	mpz_sspowm(c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Prove
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	mpz_srcptr r, std::ostream &out)
{
	mpz_t foo, bar;
	
	// CP(c'_1/c_1, c'_2/c_2, g, h; r)
	mpz_init(foo), mpz_init(bar);
	assert(mpz_invert(foo, c_1, p));
	mpz_invert(foo, c_1, p);
	mpz_mul(foo, foo, c__1);
	mpz_mod(foo, foo, p);
	assert(mpz_invert(bar, c_2, p));
	mpz_invert(bar, c_2, p);
	mpz_mul(bar, bar, c__2);
	mpz_mod(bar, bar, p);
	CP_Prove(foo, bar, g, h, r, out);
	mpz_clear(foo), mpz_clear(bar);
}

bool BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Verify
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	std::istream &in)
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init(bar);
	
	try
	{
		// CP(c'_1/c_1, c'_2/c_2, g, h; r)
		assert(mpz_invert(foo, c_1, p));
		mpz_invert(foo, c_1, p);
		mpz_mul(foo, foo, c__1);
		mpz_mod(foo, foo, p);
		assert(mpz_invert(bar, c_2, p));
		mpz_invert(bar, c_2, p);
		mpz_mul(bar, bar, c__2);
		mpz_mod(bar, bar, p);
		if (!CP_Verify(foo, bar, g, h, in))
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

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Prove
	(mpz_srcptr c_1, std::ostream &out)
{
	mpz_t d_i;
	
	mpz_init(d_i);
	
	// compute d_i = {c_1}^{x_i} \bmod p
	mpz_sspowm(d_i, c_1, x_i, p);
	out << d_i << std::endl << h_i << std::endl;
	
	// CP(d_i, h_i, c_1, g; x_i)
	CP_Prove(d_i, h_i, c_1, g, x_i, out);
	
	mpz_clear(d_i);
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Initalize
	(mpz_srcptr c_1)
{
	mpz_t d_i;
	
	mpz_init(d_i);
	
	// compute d_i = {c_1}^{x_i} \bmod p
	mpz_sspowm(d_i, c_1, x_i, p);
	
	// set the value of d to the above result
	mpz_set(d, d_i);
	
	mpz_clear(d_i);
}

bool BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Update
	(mpz_srcptr c_1, std::istream &in)
{
	mpz_t d_j, h_j;
	
	mpz_init(d_j), mpz_init(h_j);
	in >> d_j >> h_j;
	
	try
	{
		//  verify CP(d_j, h_j, c_1, g; x_j)
		if (!CP_Verify(d_j, h_j, c_1, g, in))
			throw false;
		
		// update the value of d
		mpz_mul(d, d, d_j);
		mpz_mod(d, d, p);
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(d_j), mpz_clear(h_j);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Finalize
	(mpz_srcptr c_2, mpz_ptr m)
{
	assert(mpz_invert(m, d, p));
	mpz_invert(m, d, p);
	mpz_mul(m, m, c_2);
	mpz_mod(m, m, p);
}

BarnettSmartVTMF_dlog::~BarnettSmartVTMF_dlog
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g);
	mpz_clear(x_i), mpz_clear(h_i), mpz_clear(h), mpz_clear(d);
}
