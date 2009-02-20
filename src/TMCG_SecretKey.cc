/*******************************************************************************
   This file is part of LibTMCG.

     Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Technical Report A-98-14, University of L{\"u}beck, 1998.

     Rosario Gennaro, Daniele Micciancio, Tal Rabin:
     'An Efficient Non-Interactive Statistical Zero-Knowledge
      Proof System for Quasi-Safe Prime Products',
     5th ACM Conference on Computer and Communication Security, 1998.

     Mihir Bellare, Phillip Rogaway: 'The Exact Security of Digital
      Signatures -- How to Sign with RSA and Rabin', 1996

     Dan Boneh: 'Simplified OAEP for the RSA and Rabin Functions', 2002

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#include "TMCG_SecretKey.hh"
#include "TMCG_PublicKey.hh"

TMCG_SecretKey::TMCG_SecretKey
	()
{
	mpz_init(m), mpz_init(y), mpz_init(p), mpz_init(q);
	mpz_init(y1), mpz_init(m1pq), mpz_init(gcdext_up), mpz_init(gcdext_vq),
		mpz_init(pa1d4), mpz_init(qa1d4);
}

TMCG_SecretKey::TMCG_SecretKey
	(const std::string& n, const std::string& e,
	unsigned long int keysize, bool nizk_key):
		name(n), email(e)
{
	mpz_init(m), mpz_init(y), mpz_init(p), mpz_init(q);
	mpz_init(y1), mpz_init(m1pq), mpz_init(gcdext_up), mpz_init(gcdext_vq),
		mpz_init(pa1d4), mpz_init(qa1d4);
	
	generate(keysize, nizk_key);
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
	(unsigned long int keysize, bool nizk_key)
{
	mpz_t foo, bar;
	
	assert(keysize <= TMCG_MAX_KEYBITS);
	mpz_init(foo), mpz_init(bar);
	
	// set type of key
	std::ostringstream t;
	if (nizk_key)
		t << "TMCG/RABIN_" << keysize << "_NIZK";
	else
		t << "TMCG/RABIN_" << keysize;
	type = t.str();
	
	// generate appropriate primes for RABIN encryption with SAEP
	do
	{
		// choose a random safe prime p, but with fixed size (n/2 + 1) bit
		mpz_sprime3mod4(p, (keysize / 2L) + 1L, TMCG_MR_ITERATIONS);
		assert(!mpz_congruent_ui_p(p, 1L, 8L));
		
		// choose a random safe prime q, but with fixed size (n/2 + 1) bit
		// and p \not\equiv q (mod 8)
		mpz_set_ui(foo, 8L);
		do
		{
			mpz_sprime3mod4(q, (keysize / 2L) + 1L, TMCG_MR_ITERATIONS);
		}
		while (mpz_congruent_p(p, q, foo));
		assert(!mpz_congruent_ui_p(q, 1L, 8L));
		assert(!mpz_congruent_p(p, q, foo));
		
		// compute modulus: m = p \cdot q
		mpz_mul(m, p, q);
		
		// compute upper bound for SAEP, i.e. 2^{n+1} + 2^n
		mpz_set_ui(foo, 1L);
		mpz_mul_2exp(foo, foo, keysize);
		mpz_mul_2exp(bar, foo, 1L);
		mpz_add(bar, bar, foo);
	}
	while ((mpz_sizeinbase(m, 2L) < (keysize + 1L)) || (mpz_cmp(m, bar) >= 0));
	
	// choose a small $y \in NQR^\circ_m$ for fast TMCG encoding
	mpz_set_ui(y, 1L);
	do
	{
		mpz_add_ui(y, y, 1L);
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
	
	// STAGE1: m Square Free
	// soundness error probability \le d^{-TMCG_KEY_NIZK_STAGE1}
	nizk2 << TMCG_KEY_NIZK_STAGE1 << "^";
	for (size_t stage1 = 0; (stage1 < TMCG_KEY_NIZK_STAGE1) && nizk_key; stage1++)
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
	
	// STAGE2: m Prime Power Product
	// soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE2}
	nizk2 << TMCG_KEY_NIZK_STAGE2 << "^";
	for (size_t stage2 = 0; (stage2 < TMCG_KEY_NIZK_STAGE2) && nizk_key; stage2++)
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
	
	// STAGE3: y \in NQR^\circ_m
	// soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE3}
	nizk2 << TMCG_KEY_NIZK_STAGE3 << "^";
	for (size_t stage3 = 0; (stage3 < TMCG_KEY_NIZK_STAGE3) && nizk_key; stage3++)
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

bool TMCG_SecretKey::check
	() const
{
	TMCG_PublicKey pub(*this);
	return pub.check();
}

std::string TMCG_SecretKey::fingerprint
	() const
{
	TMCG_PublicKey pub(*this);
	return pub.fingerprint();
}

std::string TMCG_SecretKey::selfid
	() const
{
	TMCG_PublicKey pub(*this);
	return pub.selfid();
}

std::string TMCG_SecretKey::keyid
	(size_t size) const
{
	TMCG_PublicKey pub(*this);
	return pub.keyid(size);
}

size_t TMCG_SecretKey::keyid_size
		(const std::string &s) const
{
	TMCG_PublicKey pub(*this);
	return pub.keyid_size(s);
}

std::string TMCG_SecretKey::sigid
	(const std::string &s) const
{
	TMCG_PublicKey pub(*this);
	return pub.sigid(s);
}

bool TMCG_SecretKey::import
	(std::string s)
{
	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(s, "sec", '|'))
			throw false;
		
		// name
		name = TMCG_ParseHelper::gs(s, '|');
		if ((TMCG_ParseHelper::gs(s, '|').length() == 0) || 
			(!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// email
		email = TMCG_ParseHelper::gs(s, '|');
		if ((TMCG_ParseHelper::gs(s, '|').length() == 0) || 
			(!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// type
		type = TMCG_ParseHelper::gs(s, '|');
		if ((TMCG_ParseHelper::gs(s, '|').length() == 0) || 
			(!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// m
		if ((mpz_set_str(m, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// y
		if ((mpz_set_str(y, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// p
		if ((mpz_set_str(p, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// q
		if ((mpz_set_str(q, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// NIZK
		nizk = TMCG_ParseHelper::gs(s, '|');
		if ((TMCG_ParseHelper::gs(s, '|').length() == 0) || 
			(!TMCG_ParseHelper::nx(s, '|')))
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

bool TMCG_SecretKey::decrypt
	(char* value, std::string s) const
{
	mpz_t vdata, vroot[4];
	size_t rabin_s2 = 2 * TMCG_SAEP_S0;
	size_t rabin_s1 = (mpz_sizeinbase(m, 2L) / 8) - rabin_s2;
	
	assert(rabin_s2 < (mpz_sizeinbase(m, 2L) / 16));
	assert(rabin_s2 < rabin_s1);
	assert(TMCG_SAEP_S0 < (mpz_sizeinbase(m, 2L) / 32));
	
	char *yy = new char[rabin_s2 + rabin_s1 + 1024];
	char *r = new char[rabin_s1];
	char *Mt = new char[rabin_s2];
	char *g12 = new char[rabin_s2];
	mpz_init(vdata), mpz_init(vroot[0]), mpz_init(vroot[1]),
		mpz_init(vroot[2]), mpz_init(vroot[3]);
	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(s, "enc", '|'))
			throw false;
		
		// check keyID
		std::string kid = TMCG_ParseHelper::gs(s, '|');
		if ((kid != keyid(keyid_size(kid))) || (!TMCG_ParseHelper::nx(s, '|')))
			throw false;
		
		// vdata
		if ((mpz_set_str(vdata, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// decrypt value, i.e., compute the modular square roots
		if (!mpz_qrmn_p(vdata, p, q, m))
			throw false;
		mpz_sqrtmn_fast_all(vroot[0], vroot[1], vroot[2], vroot[3], vdata,
			p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
		// check all four square roots
		for (size_t k = 0; k < 4; k++)
		{
			if ((mpz_sizeinbase(vroot[k], 2L) / 8) <= (rabin_s1 + rabin_s2))
			{
				size_t cnt = 1;
				mpz_export(yy, &cnt, -1, rabin_s2 + rabin_s1, 1, 0, vroot[k]);
				memcpy(Mt, yy, rabin_s2);
				memcpy(r, yy + rabin_s2, rabin_s1);
				g(g12, rabin_s2, r, rabin_s1);
				
				for (size_t i = 0; i < rabin_s2; i++)
					Mt[i] ^= g12[i];
				
				memset(g12, 0, TMCG_SAEP_S0);
				if (memcmp(Mt + TMCG_SAEP_S0, g12, TMCG_SAEP_S0) == 0)
				{
					memcpy(value, Mt, TMCG_SAEP_S0);
					throw true;
				}
			}
		}
		throw false;
	}
	catch (bool return_value)
	{
		delete [] yy, delete [] g12, delete [] Mt, delete [] r;
		mpz_clear(vdata), mpz_clear(vroot[0]), mpz_clear(vroot[1]),
			mpz_clear(vroot[2]), mpz_clear(vroot[3]);
		return return_value;
	}
}

std::string TMCG_SecretKey::sign
	(const std::string& data) const
{
	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	size_t mnsize = mpz_sizeinbase(m, 2L) / 8;
	mpz_t foo, foo_sqrt[4];
	mpz_init(foo), mpz_init(foo_sqrt[0]), mpz_init(foo_sqrt[1]),
		mpz_init(foo_sqrt[2]), mpz_init(foo_sqrt[3]);
	
	assert(mpz_sizeinbase(m, 2L) > (mnsize * 8));
	assert(mnsize > (mdsize + TMCG_PRAB_K0));
	
	// WARNING: This is only a probabilistic algorithm (Rabin's signature scheme),
	// however, it should work with only a few iterations. Additionally the scheme
	// PRab from [Bellare, Rogaway: The Exact Security of Digital Signatures]
	// was implemented to increase the security.
	do
	{
		char *r = new char[TMCG_PRAB_K0];
		gcry_randomize((unsigned char*)r, TMCG_PRAB_K0, GCRY_STRONG_RANDOM);
		
		char *Mr = new char[data.length() + TMCG_PRAB_K0];
		memcpy(Mr, data.c_str(), data.length());
		memcpy(Mr + data.length(), r, TMCG_PRAB_K0);
		
		char *w = new char[mdsize];
		h(w, Mr, data.length() + TMCG_PRAB_K0);
		
		char *g12 = new char[mnsize];
		g(g12, mnsize - mdsize, w, mdsize);
		
		for (size_t i = 0; i < TMCG_PRAB_K0; i++)
			r[i] ^= g12[i];
		
		char *yy = new char[mnsize];
		memcpy(yy, w, mdsize);
		memcpy(yy + mdsize, r, TMCG_PRAB_K0);
		memcpy(yy + mdsize + TMCG_PRAB_K0, g12 + TMCG_PRAB_K0,
			mnsize - mdsize - TMCG_PRAB_K0);
		mpz_import(foo, 1, -1, mnsize, 1, 0, yy);
		
		delete [] yy, delete [] g12, delete [] w, delete [] Mr, delete [] r;
	}
	while (!mpz_qrmn_p(foo, p, q, m));
	mpz_sqrtmn_fast_all(foo_sqrt[0], foo_sqrt[1], foo_sqrt[2], foo_sqrt[3], foo,
		p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
	
	// choose a square root randomly (one out-of four)
	std::ostringstream ost;
	ost << "sig|" << keyid() << "|" << foo_sqrt[mpz_srandom_mod(4)] << "|";
	mpz_clear(foo), mpz_clear(foo_sqrt[0]), mpz_clear(foo_sqrt[1]),
		mpz_clear(foo_sqrt[2]), mpz_clear(foo_sqrt[3]);
	
	return ost.str();
}

std::string TMCG_SecretKey::encrypt
	(const char* value) const
{
	TMCG_PublicKey pub(*this);
	return pub.encrypt(value);
}

bool TMCG_SecretKey::verify
	(const std::string& data, const std::string& s) const
{
	TMCG_PublicKey pub(*this);
	return pub.verify(data, s);
}

TMCG_SecretKey::~TMCG_SecretKey
	()
{
	mpz_clear(m), mpz_clear(y), mpz_clear(p), mpz_clear(q);
	// release non-persistent values
	mpz_clear(y1), mpz_clear(m1pq), mpz_clear(gcdext_up),
		mpz_clear(gcdext_vq), mpz_clear(pa1d4), mpz_clear(qa1d4);
}

std::ostream& operator <<
	(std::ostream& out, const TMCG_SecretKey& key)
{
	return out << "sec|" << key.name << "|" << key.email << "|" << key.type <<
		"|" << key.m << "|" << key.y << "|" << key.p << "|" << key.q << "|" <<
		key.nizk << "|" << key.sig;
}

std::istream& operator >>
	(std::istream& in, TMCG_SecretKey& key)
{
	char *tmp = new char[TMCG_MAX_KEY_CHARS];
	in.getline(tmp, TMCG_MAX_KEY_CHARS);
	if (!key.import(std::string(tmp)))
		in.setstate(std::istream::iostate(std::istream::failbit));
	delete [] tmp;
	return in;
}
