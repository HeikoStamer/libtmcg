/*******************************************************************************
   BarnettSmartVTMF_dlog.cc, Verifiable l-out-of-l Threshold Masking Function

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

#include "BarnettSmartVTMF_dlog.hh"

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(unsigned long int groupsize, unsigned long int exponentsize)
{
	// Create a finite abelian group G where DDH is hard:
	// We use the subgroup of quadratic residues modulo p,
	// such that p = 2q + 1 and p, q are both prime.
	// Two is a generator of QR_p since p \equiv 7 \pmod{8}.
	mpz_init(p), mpz_init(q), mpz_init_set_ui(g, 2L);
	mpz_sprime2g(p, q, groupsize - 1L);
	
	// initalize the key
	mpz_init(x_i), mpz_init(h_i), mpz_init(h), mpz_init(d);
	mpz_init(h_i_fp);
	
	// We shift the generator (according to [KK04]) for the
	// following usage of shortened exponents.
	assert(mpz_sizeinbase(p, 2L) >= exponentsize);
	mpz_ui_pow_ui(h, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
	mpz_powm(g, g, h, p);
}

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(std::istream &in, unsigned long int exponentsize)
{
	// initalize the finite abelian group G
	mpz_init(q), mpz_init(p), mpz_init_set_ui(g, 2L);
	in >> q;
	mpz_mul_2exp(p, q, 1L), mpz_add_ui(p, p, 1L);
	
	// initalize the key
	mpz_init(x_i), mpz_init(h_i), mpz_init(h), mpz_init(d);
	mpz_init(h_i_fp);
	
	// Now shift the generator (according to [KK04]) for the
	// later following usage of shortened exponents. (masking protocols)
	// We will use the (Short, Full)-ElGamal variant [KK04] here,
	// i.e. the secret key should be still of full size.
	assert(mpz_sizeinbase(p, 2L) >= exponentsize);
	mpz_ui_pow_ui(h, 2L, mpz_sizeinbase(p, 2L) - exponentsize);
	mpz_powm(g, g, h, p);
}

bool BarnettSmartVTMF_dlog::CheckGroup
	(unsigned long int groupsize)
{
	mpz_t foo;
	
	mpz_init(foo);
	
	try
	{
		// check whether q has appropriate size
		if ((mpz_sizeinbase(p, 2L) < groupsize) ||
			(mpz_sizeinbase(p, 2L) > (groupsize + 4096L)))
				throw false;
		
		// check whether p, q are both (probable) prime
		// soundness error probability: 4^{-64}
		if (!(mpz_probab_prime_p(p, 64L) && mpz_probab_prime_p(q, 64L)))
			throw false;
		
		// check whether p is congruent 7 modulo 8
		if (!mpz_congruent_ui_p(p, 7L, 8L))
			throw false;
		
		// check whether g is a generator of the group G
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

void BarnettSmartVTMF_dlog::NextElement
	(mpz_ptr a)
{
	// choose the next element of G (quadratic residue)
	do
		mpz_add_ui(a, a, 1L);
	while (mpz_jacobi(a, p) != 1);
}

void BarnettSmartVTMF_dlog::IndexElement
	(mpz_ptr a, std::size_t index)
{
	// choose the index-th element of G (quadratic residue)
	// Notice that a call to IndexElement(a, 0) returns the identity,
	// because 1 is the smallest quadratic residue mod p.
	mpz_set_ui(a, 0L);
	do
		NextElement(a);
	while (index--);
	
	assert(mpz_jacobi(a, p) == 1);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_GenerateKey
	()
{
	// generate the random private key x_i \in Z_q
	mpz_srandomm(x_i, q);
	
	// compute h_i = g^{x_i} \bmod p (with blinding techniques)
	mpz_spowm(h_i, g, x_i, p);
	
	// compute the fingerprint
	mpz_shash(h_i_fp, 1, h_i);
	
	// set the global key h
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
		mpz_spowm(t, g, v, p);
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof of
		// knowledge (SPK) in the random oracle model.
		mpz_shash(c, 3, g, h_i, t);
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

void BarnettSmartVTMF_dlog::CP_Prove
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, mpz_srcptr alpha,
	std::ostream &out)
{
	mpz_t a, b, omega, c, r;
	
	// proof of knowledge (equality of discrete logarithms) [CaS97]
	mpz_init(c), mpz_init(r), mpz_init(a), mpz_init(b), mpz_init(omega);
		
		// commitment
		mpz_srandomm(omega, q);
		mpz_spowm(a, gg, omega, p);
		mpz_spowm(b, hh, omega, p);
		
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof of
		// knowledge (SPK) in the random oracle model.
		mpz_shash(c, 6, a, b, x, y, gg, hh);
		
		// response
		mpz_mul(r, c, alpha);
		mpz_neg(r, r);
		mpz_add(r, r, omega);
		mpz_mod(r, r, q);
		
	out << c << std::endl << r << std::endl;
	mpz_clear(c), mpz_clear(r), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
}

bool BarnettSmartVTMF_dlog::CP_Verify
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, std::istream &in)
{
	mpz_t a, b, c, r;
	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r);
	in >> c >> r;
	
	try
	{
		// verify proof of knowledge (equality of discrete logarithms) [CaS97]
		mpz_powm(a, gg, r, p);
		mpz_powm(b, x, c, p);
		mpz_mul(a, a, b);
		mpz_mod(a, a, p);
		mpz_powm(b, hh, r, p);
		mpz_powm(r, y, c, p);
		mpz_mul(b, b, r);
		mpz_mod(b, b, p);
		mpz_shash(r, 6, a, b, x, y, gg, hh);
		if (mpz_cmp(r, c))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Mask
	(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r,
	unsigned long int exponentsize)
{
	// choose the masking value r \in Z_q randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= exponentsize)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the exponent. [KK04]
		mpz_srandomb(r, exponentsize);
	}
	
	// compute c_1 = g^r \bmod p
	mpz_spowm(c_1, g, r, p);
	
	// compute c_2 = m \cdot h^r \bmod p
	mpz_spowm(c_2, h, r, p);
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
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r,
	unsigned long int exponentsize)
{
	// choose the masking value r \in Z_q randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= exponentsize)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the exponent. [KK04]
		mpz_srandomb(r, exponentsize);
	}
	
	// compute c'_1 = c_1 \cdot g^r \bmod p
	mpz_spowm(c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute c'_2 = c_2 \cdot h^r \bmod p
	mpz_spowm(c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_RemaskValue
	(mpz_ptr r, unsigned long int exponentsize)
{
	// choose the masking value r \in Z_q randomly and uniformly
	if (mpz_sizeinbase(p, 2L) <= exponentsize)
	{
		mpz_srandomm(r, q);
	}
	else
	{
		// Under the additional DLSE assumption we can reduce
		// the size of the exponent. [KK04]
		mpz_srandomb(r, exponentsize);
	}
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Remask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_srcptr r)
{
	// compute c'_1 = c_1 \cdot g^r \bmod p
	mpz_spowm(c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute c'_2 = c_2 \cdot h^r \bmod p
	mpz_spowm(c__2, h, r, p);
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
	mpz_spowm(d_i, c_1, x_i, p);
	out << d_i << std::endl << h_i_fp << std::endl;
	
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
	mpz_spowm(d_i, c_1, x_i, p);
	
	// set the value of d to the above result
	mpz_set(d, d_i);
	
	mpz_clear(d_i);
}

bool BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Update
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
		
		// verify CP(d_j, h_j, c_1, g; x_j)
		if (!CP_Verify(d_j, h_j[fp.str()], c_1, g, in))
			throw false;
		
		// update the value of d
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
	for (std::map<std::string, mpz_ptr>::const_iterator
		j = h_j.begin(); j != h_j.end(); ++j)
			mpz_clear(j->second);
	h_j.clear();
}
