/*******************************************************************************
   This file is part of libTMCG.

     Rosario Gennaro, Daniele Micciancio, Tal Rabin: 
     'An Efficient Non-Interactive Statistical Zero-Knowledge 
     Proof System for Quasi-Safe Prime Products', 1997

     Mihir Bellare, Phillip Rogaway: 'The Exact Security of Digital
     Signatures -- How to Sign with RSA and Rabin', 1996

     Dan Boneh: 'Simplified OAEP for the RSA and Rabin Functions', 2002

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

#include "TMCG_SecretKey.hh"
#include "libTMCG.def"

// SAEP octets
#define rabin_k0 20
#define rabin_s0 20

// soundness error of the NIZK
// d^{-nizk_stage1}
#define nizk_stage1 16
// 2^{-nizk_stage2}
#define nizk_stage2 128
// 2^{-nizk_stage3}
#define nizk_stage3 128

TMCG_SecretKey::TMCG_SecretKey
	()
{
	mpz_init(m), mpz_init(y), mpz_init(p), mpz_init(q);
	mpz_init(y1), mpz_init(m1pq), mpz_init(gcdext_up), mpz_init(gcdext_vq),
		mpz_init(pa1d4), mpz_init(qa1d4);
}

TMCG_SecretKey::TMCG_SecretKey
	(const std::string &n, const std::string &e,
	unsigned long int keysize):
		name(n), email(e)
{
	mpz_init(m), mpz_init(y), mpz_init(p), mpz_init(q);
	mpz_init(y1), mpz_init(m1pq), mpz_init(gcdext_up), mpz_init(gcdext_vq),
		mpz_init(pa1d4), mpz_init(qa1d4);
	
	generate(keysize);
}

TMCG_SecretKey::TMCG_SecretKey
	(const std::string& s)
{
	mpz_init(m), mpz_init(y), mpz_init(p), mpz_init(q);
	mpz_init(y1), mpz_init(m1pq), mpz_init(gcdext_up), mpz_init(gcdext_vq),
		mpz_init(pa1d4), mpz_init(qa1d4);
	
	import(s);
}

TMCG_SecretKey::TMCG_SecretKey
	(const TMCG_SecretKey& that):
		name(that.name), email(that.email), type(that.type),
		nizk(that.nizk), sig(that.sig)
{
	mpz_init_set(m, that.m), mpz_init_set(y, that.m),
		mpz_init_set(p, that.p), mpz_init_set(q, that.q);
	mpz_init_set(y1, that.y1), mpz_init_set(m1pq, that.m1pq),
		mpz_init_set(gcdext_up, that.gcdext_up),
		mpz_init_set(gcdext_vq, that.gcdext_vq),
		mpz_init_set(pa1d4, that.pa1d4), mpz_init_set(qa1d4, that.qa1d4);
}

TMCG_SecretKey& TMCG_SecretKey::operator =
	(const TMCG_SecretKey& that)
{
	name = that.name, email = that.email, type = that.type,
		nizk = that.nizk, sig = that.sig;
	mpz_set(m, that.m), mpz_set(y, that.y),
		mpz_set(p, that.p), mpz_set(q, that.q);
	mpz_set(y1, that.y1), mpz_set(m1pq, that.m1pq),
		mpz_set(gcdext_up, that.gcdext_up), mpz_set(gcdext_vq, that.gcdext_vq),
		mpz_set(pa1d4, that.pa1d4), mpz_set(qa1d4, that.qa1d4);
	
	return *this;
}

void TMCG_SecretKey::generate
	(unsigned long int keysize)
{
	mpz_t foo, bar;
	
	assert(keysize <= TMCG_MAX_KEYBITS);
	mpz_init(foo), mpz_init(bar);
	
	// set type of key
	std::ostringstream t;
	t << "TMCG/RABIN_" << keysize << "_NIZK";
	type = t.str();
	
	// generate appropriate primes for RABIN encryption with SAEP
	do
	{
		// choose random p \in Z, but with fixed size (n/2 + 1) bit
		do
		{
			mpz_ssrandomb(p, (keysize / 2L) + 1L);
		}
		while (mpz_sizeinbase(p, 2L) < ((keysize / 2L) + 1L));
		
		// make p odd
		if (mpz_even_p(p))
			mpz_add_ui(p, p, 1L);
		
		// while p is not probable prime and \equiv 3 (mod 4)
		// choose a safe prime, i.e. (p-1)/2 is probable prime
		do
		{
			mpz_add_ui(p, p, 2L);
			mpz_sub_ui(bar, p, 1L);
			mpz_fdiv_q_2exp(bar, bar, 1L);
		}
		while (!(mpz_congruent_ui_p(p, 3L, 4L) &&
			mpz_probab_prime_p(p, 25) &&
			mpz_probab_prime_p(bar, 25)));
			
		assert(!mpz_congruent_ui_p(p, 1L, 8L));
		
		// choose random q \in Z, but with fixed size (n/2 + 1) bit
		do
		{
			mpz_ssrandomb(q, (keysize / 2L) + 1L);
		}
		while (mpz_sizeinbase(q, 2L) < ((keysize / 2L) + 1L));
		
		// make q odd
		if (mpz_even_p(q))
			mpz_add_ui(q, q, 1L);
		
		// while q is not probable prime, \equiv 3 (mod 4) and
		// p \not\equiv q (mod 8)
		// choose a safe prime, i.e. (p-1)/2 is probable prime
		mpz_set_ui(foo, 8L);
		do
		{
			mpz_add_ui(q, q, 2L);
			mpz_sub_ui(bar, q, 1L);
			mpz_fdiv_q_2exp(bar, bar, 1L);
		}
		while (!(mpz_congruent_ui_p(q, 3L, 4L) &&
			mpz_probab_prime_p(q, 25) &&
			mpz_probab_prime_p(bar, 25) &&
			!mpz_congruent_p(p, q, foo)));
		
		assert(!mpz_congruent_ui_p(q, 1L, 8L));
		assert(!mpz_congruent_p(p, q, foo));
		
		// compute modulus: m = pq
		mpz_mul(m, p, q);
		
		// compute upper bound for SAEP, i.e. 2^{n+1} + 2^n
		mpz_set_ui(foo, 1L);
		mpz_mul_2exp(foo, foo, keysize);
		mpz_mul_2exp(bar, foo, 1L);
		mpz_add(bar, bar, foo);
	}
	while ((mpz_sizeinbase(m, 2L) < (keysize + 1L)) || (mpz_cmp(m, bar) >= 0));
	
	// choose random y \in NQR^\circ_m for TMCG
	do
	{
		mpz_srandomm(y, m);
	}
	while ((mpz_jacobi(y, m) != 1) || mpz_qrmn_p(y, p, q, m));
	
	// pre-compute non-persistent values
	precompute();
	
	// Rosario Gennaro, Daniele Micciancio, Tal Rabin:
	// 'An Efficient Non-Interactive Statistical Zero-Knowledge
	// Proof System for Quasi-Safe Prime Products',
	// 5th ACM Conference on Computer and Communication Security, CCS 1998
	
	// STAGE1/2: m = p^i * q^j, p and q prime
	// STAGE3: y \in NQR^\circ_m
	std::ostringstream nizk2, input;
	input << m << "^" << y, nizk2 << "nzk^";
	size_t mnsize = mpz_sizeinbase(m, 2L) / 8;
	char *mn = new char[mnsize];
	
	// STAGE1: m Square Free, soundness error probability = d^{-nizk_stage1}
	nizk2 << nizk_stage1 << "^";
	for (size_t stage1 = 0; stage1 < nizk_stage1; stage1++)
	{
		// common random number foo \in Z^*_m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod(foo, foo, m);
			mpz_gcd(bar, foo, m);
			input << foo;
		}
		while (mpz_cmp_ui(bar, 1L));
		
		// compute bar = foo^{m^{-1} mod \phi(m)} mod m
		mpz_powm(bar, foo, m1pq, m);
		
		// update NIZK-proof stream
		nizk2 << bar << "^"; 
	}
	
	// STAGE2: m Prime Power Product, soundness error prob. = 2^{-nizk_stage2}
	nizk2 << nizk_stage2 << "^";
	for (size_t stage2 = 0; stage2 < nizk_stage2; stage2++)
	{
		// common random number foo \in Z^*_m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod(foo, foo, m);
			mpz_gcd(bar, foo, m);
			input << foo;
		}
		while (mpz_cmp_ui(bar, 1L));
		
		// compute square root of +-foo or +-2foo mod m
		if (mpz_qrmn_p(foo, p, q, m))
			mpz_sqrtmn_r(bar, foo, p, q, m);
		else
		{
			mpz_neg(foo, foo);
			if (mpz_qrmn_p(foo, p, q, m))
				mpz_sqrtmn_r(bar, foo, p, q, m);
			else
			{
				mpz_mul_2exp(foo, foo, 1L);
				if (mpz_qrmn_p(foo, p, q, m))
					mpz_sqrtmn_r(bar, foo, p, q, m);
				else
				{
					mpz_neg(foo, foo);
					if (mpz_qrmn_p(foo, p, q, m))
						mpz_sqrtmn_r(bar, foo, p, q, m);
					else
						mpz_set_ui(bar, 0L);
				}
			}
		}
		
		// update NIZK-proof stream
		nizk2 << bar << "^";
	}
	
	// STAGE3: y \in NQR^\circ_m, soundness error probability = 2^{-nizk_stage3}
	nizk2 << nizk_stage3 << "^";
	for (size_t stage3 = 0; stage3 < nizk_stage3; stage3++)
	{
		// common random number foo \in Z^\circ_m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod(foo, foo, m);
			input << foo;
		}
		while (mpz_jacobi(foo, m) != 1);
		
		// compute square root
		if (!mpz_qrmn_p(foo, p, q, m))
		{
			mpz_mul(foo, foo, y);
			mpz_mod(foo, foo, m);
		}
		mpz_sqrtmn_r(bar, foo, p, q, m);
		
		// update NIZK-proof stream
		nizk2 << bar << "^";
	}
	
	nizk = nizk2.str();
	delete [] mn;
	mpz_clear(foo), mpz_clear(bar);
	
	// compute self-signature
	std::ostringstream data, repl;
	data << name << "|" << email << "|" << type << "|" <<
		m << "|" << y << "|" << nizk << "|";
	sig = sign(data.str());
	repl << "ID" << TMCG_KEYID_SIZE << "^";
	sig.replace(sig.find(repl.str()),
		(repl.str()).length() + TMCG_KEYID_SIZE, keyid());
}

void TMCG_SecretKey::precompute
	()
{
	// pre-compute non-persistent values
	mpz_t foo;
	mpz_init(foo);
	
	ret = mpz_invert(y1, y, m);
	assert(ret);
	mpz_sub(foo, m, p);
	mpz_sub(foo, foo, q);
	mpz_add_ui(foo, foo, 1L);
	ret = mpz_invert(m1pq, m, foo);
	assert(ret);
	mpz_gcdext(foo, gcdext_up, gcdext_vq, p, q);
	assert(mpz_cmp_ui(foo, 1L) == 0);
	mpz_mul(gcdext_up, gcdext_up, p);
	mpz_mul(gcdext_vq, gcdext_vq, q);
	mpz_set(pa1d4, p), mpz_set(qa1d4, q);
	mpz_add_ui(pa1d4, pa1d4, 1L);
	mpz_add_ui(qa1d4, qa1d4, 1L);
	mpz_fdiv_q_2exp(pa1d4, pa1d4, 2L);
	mpz_fdiv_q_2exp(qa1d4, qa1d4, 2L);
	
	mpz_clear(foo);
}

bool TMCG_SecretKey::import
	(std::string s)
{
	try
	{
		// check magic
		if (!cm(s, "sec", '|'))
			throw false;
		
		// name
		name = gs(s, '|');
		if ((gs(s, '|').length() == 0) || (!nx(s, '|')))
			throw false;
		
		// email
		email = gs(s, '|');
		if ((gs(s, '|').length() == 0) || (!nx(s, '|')))
			throw false;
		
		// type
		type = gs(s, '|');
		if ((gs(s, '|').length() == 0) || (!nx(s, '|')))
			throw false;
		
		// m
		if ((mpz_set_str(m, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		// y
		if ((mpz_set_str(y, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		// p
		if ((mpz_set_str(p, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		// q
		if ((mpz_set_str(q, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		// NIZK
		nizk = gs(s, '|');
		if ((gs(s, '|').length() == 0) || (!nx(s, '|')))
			throw false;
		
		// sig
		sig = s;
		
		// pre-compute non-persistent values
		precompute();
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool TMCG_SecretKey::check
	() const
{
	mpz_t foo, bar;
	std::string s = nizk;
	size_t stage1_size = 0, stage2_size = 0, stage3_size = 0;
	size_t mnsize = mpz_sizeinbase(m, 2L) / 8;
	char *ec, *mn = new char[mnsize];
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// sanity check, whether y \in Z^\circ
		if (mpz_jacobi(y, m) != 1)
			throw false;
		
		// sanity check, whether m \in ODD (odd numbers)
		if (!mpz_odd_p(m))
			throw false;
		
		// sanity check, whether m \not\in P (prime)
		// (here is a very small probability of false-negativ behaviour,
		// FIX: give a short witness in public key)
		if (mpz_probab_prime_p(m, 500))
			throw false;
		
		// check self-signature
		std::ostringstream data;
		data << name << "|" << email << "|" << type << "|" << m << "|" <<
			y << "|" << nizk << "|";
		if (!verify(data.str(), sig))
			throw false;
		
		// check, whether m \not\in FP (fermat primes: m = 2^k + 1)
		mpz_set(foo, m);
		mpz_sub_ui(foo, foo, 1L);
		unsigned long int k = mpz_sizeinbase(m, 2L);
		mpz_set_ui(bar, 2L);
		mpz_pow_ui(bar, bar, k);
		if (!mpz_cmp(foo, bar))
		{
			// check, whether k is power of two
			mpz_set_ui(foo, k);
			unsigned long int l = mpz_sizeinbase(foo, 2L);
			mpz_set_ui(bar, 2L);
			mpz_pow_ui(bar, bar, l);
			if (!mpz_cmp(foo, bar))
			{
				// check, whether m is not equal to 5L
				if (!mpz_cmp_ui(m, 5L))
					throw false;
				
				// check, whether 5^2^(k/2) \equiv -1 (mod m) [Pepin's prime test]
				mpz_set_ui(foo, 2L);
				mpz_powm_ui(foo, foo, (k / 2), m);
				mpz_set_ui(bar, 5L);
				mpz_powm(foo, bar, foo, m);
				mpz_set_si(bar, -1L);
				if (mpz_congruent_p(foo, bar, m))
					throw false;
			}
		}
		
		// check magic of NIZK
		if (!cm(s, "nzk", '^'))
			throw false;
		
		// initalize NIZK proof input
		std::ostringstream input;
		input << m << "^" << y;
		
		// get security parameter of STAGE1
		if (gs(s, '^').length() == 0)
			throw false;
		stage1_size = strtoul(gs(s, '^').c_str(), &ec, 10);
		if ((*ec != '\0') || (stage1_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security constraint of STAGE1
		if (stage1_size < nizk_stage1)
			throw false;
		
		// STAGE1: m is Square Free
		for (size_t i = 0; i < stage1_size; i++)
		{
			// common random number foo \in Z^*_m (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				mpz_gcd(bar, foo, m);
				input << foo;
			}
			while (mpz_cmp_ui(bar, 1L));
			
			// read NIZK proof
			if (gs(s, '^').length() == 0)
				throw false;
			if ((mpz_set_str(bar, gs(s, '^').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				(!nx(s, '^')))
					throw false;
			
			// check, whether bar^m mod m is equal to foo
			mpz_powm(bar, bar, m, m);
			if (mpz_cmp(foo, bar))
				throw false;
		}
		
		// get security parameter of STAGE2
		if (gs(s, '^').length() == 0)
			throw false;
		stage2_size = strtoul(gs(s, '^').c_str(), &ec, 10);
		if ((*ec != '\0') || (stage2_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security constraint of STAGE2
		if (stage2_size < nizk_stage2)
			throw false;
		
		// STAGE2: m is Prime Power Product
		for (size_t i = 0; i < stage2_size; i++)
		{
			// common random number foo \in Z^*_m (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				mpz_gcd(bar, foo, m);
				input << foo;
			}
			while (mpz_cmp_ui(bar, 1L));
			
			// read NIZK proof
			if (gs(s, '^').length() == 0)
				throw false;
			if ((mpz_set_str(bar, gs(s, '^').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				(!nx(s, '^')))
					throw false;
			
			// check, whether bar^2 \equiv +-foo or \equiv +-2foo (mod m)
			mpz_mul(bar, bar, bar);
			mpz_mod(bar, bar, m);
			if (!mpz_congruent_p(bar, foo, m))
			{
				mpz_neg(foo, foo);
				if (!mpz_congruent_p(bar, foo, m))
				{
					mpz_mul_2exp(foo, foo, 1L);
					if (!mpz_congruent_p(bar, foo, m))
					{
						mpz_neg(foo, foo);
						if (!mpz_congruent_p(bar, foo, m))
							throw false;
					}
				}
			}
		}
		
		// get security parameter of STAGE3
		if (gs(s, '^').length() == 0)
			throw false;
		stage3_size = strtoul(gs(s, '^').c_str(), &ec, 10);
		if ((*ec != '\0') || (stage3_size <= 0) || (!nx(s, '^')))
			throw false;
		
		// check security constraint of STAGE3
		if (stage3_size < nizk_stage3)
			throw false;
		
		// STAGE3: y \in NQR^\circ_m
		for (size_t i = 0; i < stage3_size; i++)
		{
			// common random number foo \in Z^\circ_m (build from hash function g)
			do
			{
				g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				input << foo;
			}
			while (mpz_jacobi(foo, m) != 1);
			
			// read NIZK proof
			if (gs(s, '^').length() == 0)
				throw false;
			if ((mpz_set_str(bar, gs(s, '^').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				(!nx(s, '^')))
					throw false;
			
			// check congruence [Goldwasser-Micali NIZK proof for NQR]
			mpz_mul(bar, bar, bar);
			mpz_mod(bar, bar, m);
			if (!mpz_congruent_p(bar, foo, m))
			{
				mpz_mul(foo, foo, y);
				mpz_mod(foo, foo, m);
				if (!mpz_congruent_p(bar, foo, m))
					throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		delete [] mn;
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

std::string TMCG_SecretKey::selfid
	() const
{
	std::string s = sig;
	
	// maybe a self signature
	if (s == "")
		return std::string("SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG");
	
	// check magic
	if (!cm(s, "sig", '|'))
		return std::string("ERROR");
	
	// skip the keyID
	if (!nx(s, '|'))
		return std::string("ERROR");
	
	// get the sigID
	return std::string(gs(s, '|'));
}

std::string TMCG_SecretKey::keyid
	() const
{
	std::ostringstream data;
	std::string tmp = selfid();
	
	data << "ID" << TMCG_KEYID_SIZE << "^" << tmp.substr(tmp.length() -
		((TMCG_KEYID_SIZE < tmp.length()) ? TMCG_KEYID_SIZE : tmp.length()),
		(TMCG_KEYID_SIZE < tmp.length()) ? TMCG_KEYID_SIZE : tmp.length());
	return data.str();
}

std::string TMCG_SecretKey::sigid
	(std::string s) const
{
	// check magic
	if (!cm(s, "sig", '|'))
		return std::string("ERROR");
	
	// get the keyID
	return std::string(gs(s, '|'));
}

const char* TMCG_SecretKey::decrypt
	(std::string value) const
{
	mpz_t vdata, vroot[4];
	size_t rabin_s2 = 2 * rabin_s0;
	size_t rabin_s1 = (mpz_sizeinbase(m, 2L) / 8) - rabin_s2;
	
	assert(rabin_s2 < (mpz_sizeinbase(m, 2L) / 16));
	assert(rabin_s2 < rabin_s1);
	assert(rabin_s0 < (mpz_sizeinbase(m, 2L) / 32));
	assert(rabin_s0 < sizeof(encval));
	
	char *yy = new char[rabin_s2 + rabin_s1 + 1024];
	char *r = new char[rabin_s1];
	char *Mt = new char[rabin_s2];
	char *g12 = new char[rabin_s2];
	mpz_init(vdata), mpz_init(vroot[0]), mpz_init(vroot[1]),
		mpz_init(vroot[2]), mpz_init(vroot[3]);
	try
	{
		// check magic
		if (!cm(value, "enc", '|'))
			throw false;
		
		// check keyID
		if (!cm(value, keyid(), '|'))
			throw false;
		
		// vdata
		if ((mpz_set_str(vdata, gs(value, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(value, '|')))
				throw false;
		
		// decrypt value, compute modular square roots
		if (!mpz_qrmn_p(vdata, p, q, m))
			throw false;
		mpz_sqrtmn_fast_all(vroot[0], vroot[1], vroot[2], vroot[3], vdata,
			p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
		for (size_t k = 0; k < 4; k++)
		{
			if ((mpz_sizeinbase(vroot[k], 2L) / 8) <= (rabin_s1 + rabin_s2))
			{
				size_t cnt = 1;
				mpz_export(yy, &cnt, -1, rabin_s2 + rabin_s1, 1, 0, vroot[k]);
				memcpy(Mt, yy, rabin_s2), memcpy(r, yy + rabin_s2, rabin_s1);
				g(g12, rabin_s2, r, rabin_s1);
				
				for (size_t i = 0; i < rabin_s2; i++)
					Mt[i] ^= g12[i];
				
				memset(g12, 0, rabin_s0);
				if (memcmp(Mt + rabin_s0, g12, rabin_s0) == 0)
				{
					memcpy((char*)encval, Mt, rabin_s0);
					throw true;
				}
			}
		}
		throw false;
	}
	catch (bool success)
	{
		delete [] yy, delete [] g12, delete [] Mt, delete [] r;
		mpz_clear(vdata), mpz_clear(vroot[0]), mpz_clear(vroot[1]),
			mpz_clear(vroot[2]), mpz_clear(vroot[3]);
		if (success)
		{
			return encval;
		}
		else
			return NULL;
	}
}

std::string TMCG_SecretKey::sign
	(const std::string &data) const
{
	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	size_t mnsize = mpz_sizeinbase(m, 2L) / 8;
	mpz_t foo, foo_sqrt[4];
	mpz_init(foo), mpz_init(foo_sqrt[0]), mpz_init(foo_sqrt[1]),
		mpz_init(foo_sqrt[2]), mpz_init(foo_sqrt[3]);
	
	assert(mpz_sizeinbase(m, 2L) > (mnsize * 8));
	assert(mnsize > (mdsize + rabin_k0));
	
	// WARNING: only a probabilistic algorithm (Rabin's signature scheme)
	// PRab from [Bellare, Rogaway: The Exact Security of Digital Signatures]
	do
	{
		char *r = new char[rabin_k0];
		gcry_randomize((unsigned char*)r, rabin_k0, GCRY_STRONG_RANDOM);
		
		char *Mr = new char[data.length() + rabin_k0];
		memcpy(Mr, data.c_str(), data.length());
		memcpy(Mr + data.length(), r, rabin_k0);
		
		char *w = new char[mdsize];
		h(w, Mr, data.length() + rabin_k0);
		
		char *g12 = new char[mnsize];
		g(g12, mnsize - mdsize, w, mdsize);
		
		for (size_t i = 0; i < rabin_k0; i++)
			r[i] ^= g12[i];
		
		char *yy = new char[mnsize];
		memcpy(yy, w, mdsize);
		memcpy(yy + mdsize, r, rabin_k0);
		memcpy(yy + mdsize + rabin_k0, g12 + rabin_k0, mnsize - mdsize - rabin_k0);
		mpz_import(foo, 1, -1, mnsize, 1, 0, yy);
		
		delete [] yy, delete [] g12, delete [] w, delete [] Mr, delete [] r;
	}
	while (!mpz_qrmn_p(foo, p, q, m));
	mpz_sqrtmn_fast_all(foo_sqrt[0], foo_sqrt[1], foo_sqrt[2], foo_sqrt[3], foo,
		p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
	
	// choose square root randomly (one of four)
	mpz_srandomb(foo, 2L);
	
	std::ostringstream ost;
	ost << "sig|" << keyid() << "|" << foo_sqrt[mpz_get_ui(foo) % 4] << "|";
	mpz_clear(foo), mpz_clear(foo_sqrt[0]), mpz_clear(foo_sqrt[1]),
		mpz_clear(foo_sqrt[2]), mpz_clear(foo_sqrt[3]);
	
	return ost.str();
}

std::string TMCG_SecretKey::encrypt
	(const char *value) const
{
	mpz_t vdata;
	size_t rabin_s2 = 2 * rabin_s0;
	size_t rabin_s1 = (mpz_sizeinbase(m, 2L) / 8) - rabin_s2;
	
	assert(rabin_s2 < (mpz_sizeinbase(m, 2L) / 16));
	assert(rabin_s2 < rabin_s1);
	assert(rabin_s0 < (mpz_sizeinbase(m, 2L) / 32));
	
	char *r = new char[rabin_s1];
	gcry_randomize((unsigned char*)r, rabin_s1, GCRY_STRONG_RANDOM);
	
	char *Mt = new char[rabin_s2], *g12 = new char[rabin_s2];
	std::memcpy(Mt, value, rabin_s0);
	std::memset(Mt + rabin_s0, 0, rabin_s0);
	g(g12, rabin_s2, r, rabin_s1);
	
	for (size_t i = 0; i < rabin_s2; i++)
		Mt[i] ^= g12[i];
	
	char *yy = new char[rabin_s2 + rabin_s1];
	memcpy(yy, Mt, rabin_s2), memcpy(yy + rabin_s2, r, rabin_s1);
	mpz_init(vdata);
	mpz_import(vdata, 1, -1, rabin_s2 + rabin_s1, 1, 0, yy);
	delete [] yy, delete [] g12, delete [] Mt, delete [] r;
	
	// apply RABIN function vdata = vdata^2 mod m
	mpz_mul(vdata, vdata, vdata);
	mpz_mod(vdata, vdata, m);
	
	std::ostringstream ost;
	ost << "enc|" << keyid() << "|" << vdata << "|";
	mpz_clear(vdata);
	
	return ost.str();
}

bool TMCG_SecretKey::verify
	(const std::string &data, std::string s) const
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// check magic
		if (!cm(s, "sig", '|'))
			throw false;
		
		// check keyID
		if (!cm(s, keyid().c_str(), '|'))
			throw false;
		
		// value
		if ((mpz_set_str(foo, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		// verify signature
		size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
		size_t mnsize = mpz_sizeinbase(m, 2L) / 8;
		
		assert(mpz_sizeinbase(m, 2L) > (mnsize * 8));
		assert(mnsize > (mdsize + rabin_k0));
		
		mpz_mul(foo, foo, foo);
		mpz_mod(foo, foo, m);
		
		char *w = new char[mdsize], *r = new char[rabin_k0];
		char *gamma = new char[mnsize - mdsize - rabin_k0];
		char *yy = new char[mnsize + 1024];
		size_t cnt = 1;
		mpz_export(yy, &cnt, -1, mnsize, 1, 0, foo);
		memcpy(w, yy, mdsize);
		memcpy(r, yy + mdsize, rabin_k0);
		memcpy(gamma, yy + mdsize + rabin_k0, mnsize - mdsize - rabin_k0);
		
		char *g12 = new char[mnsize];
		g(g12, mnsize - mdsize, w, mdsize);
		
		for (size_t i = 0; i < rabin_k0; i++)
			r[i] ^= g12[i];
		
		char *Mr = new char[data.length() + rabin_k0];
		memcpy(Mr, data.c_str(), data.length());
		memcpy(Mr + data.length(), r, rabin_k0);
		
		char *w2 = new char[mdsize];
		h(w2, Mr, data.length() + rabin_k0);
		
		bool ok = (memcmp(w, w2, mdsize) == 0) && 
			(memcmp(gamma, g12 + rabin_k0, mnsize - mdsize - rabin_k0) == 0);
		delete [] yy, delete [] w, delete [] r, delete [] gamma, 
			delete [] g12, delete [] Mr, delete [] w2;
		
		throw ok;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

TMCG_SecretKey::~TMCG_SecretKey
	()
{
	mpz_clear(m), mpz_clear(y), mpz_clear(p), mpz_clear(q);
	// release non-persistent values
	mpz_clear(y1), mpz_clear(m1pq), mpz_clear(gcdext_up),
	mpz_clear(gcdext_vq), mpz_clear(pa1d4), mpz_clear(qa1d4);
}

std::ostream& operator<< 
	(std::ostream &out, const TMCG_SecretKey &key)
{
	return out << "sec|" << key.name << "|" << key.email << "|" << key.type <<
		"|" << key.m << "|" << key.y << "|" << key.p << "|" << key.q << "|" <<
		key.nizk << "|" << key.sig;
}
