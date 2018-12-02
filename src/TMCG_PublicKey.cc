/*******************************************************************************
   This file is part of LibTMCG.

     [Sc98] Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Technical Report A-98-14, University of L{\"u}beck, 1998.

     [GMR98] Rosario Gennaro, Daniele Micciancio, Tal Rabin:
     'An Efficient Non-Interactive Statistical Zero-Knowledge
      Proof System for Quasi-Safe Prime Products',
     5th ACM Conference on Computer and Communication Security, 1998.

     [BR96] Mihir Bellare, Phillip Rogaway: 'The Exact Security of Digital
      Signatures -- How to Sign with RSA and Rabin',
     Advances in Cryptology - Eurocrypt 96 Proceedings, LNCS 1070, 1996.

     [Bo01] Dan Boneh: 'Simplified OAEP for the RSA and Rabin Functions',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 275--291, 2001.

 Copyright (C) 2004, 2005, 2006, 2007, 
               2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "TMCG_PublicKey.hh"

// additional headers
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <sstream>
#include <vector>
#include "mpz_sqrtm.hh"
#include "mpz_helper.hh"
#include "parse_helper.hh"
#include "mpz_shash.hh"

// FIXME(C++11): move following static definitions into class
static const std::string tmcg_SELFSIG = "SELFSIG-SELFSIG-SELFSIG-SELFSIG-"
	"SELFSIG-SELFSIG";
static const std::string tmcg_ERROR = "ERROR";

TMCG_PublicKey::TMCG_PublicKey
	()
{
	mpz_init(m), mpz_init(y);
}

TMCG_PublicKey::TMCG_PublicKey
	(const TMCG_SecretKey& skey):
		name(skey.name), email(skey.email), type(skey.type),
		nizk(skey.nizk), sig(skey.sig)
{
	mpz_init_set(m, skey.m);
	mpz_init_set(y, skey.y);
}

TMCG_PublicKey::TMCG_PublicKey
	(const TMCG_PublicKey& pkey):
		name(pkey.name), email(pkey.email), type(pkey.type),
		nizk(pkey.nizk), sig(pkey.sig)
{
	mpz_init_set(m, pkey.m);
	mpz_init_set(y, pkey.y);
}

TMCG_PublicKey::TMCG_PublicKey
	(const std::string& s)
{
	mpz_init(m), mpz_init(y);
	
	import(s);
}

TMCG_PublicKey& TMCG_PublicKey::operator =
	(const TMCG_PublicKey& that)
{
	name = that.name, email = that.email, type = that.type,
		nizk = that.nizk, sig = that.sig;
	mpz_set(m, that.m), mpz_set(y, that.y);
	
	return *this;
}

bool TMCG_PublicKey::check
	()
{
	mpz_t foo, bar;
	std::string s = nizk;
	size_t stage1_size = 0, stage2_size = 0, stage3_size = 0;
	size_t mnsize = mpz_sizeinbase(m, 2UL) / 8;
	unsigned char *mn = new unsigned char[mnsize];
	
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
		// (here is a very small probability of false-negative behaviour,
		// TODO: give a short witness for compositeness in public key)
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
		mpz_sub_ui(foo, foo, 1UL);
		unsigned long int k = mpz_sizeinbase(m, 2UL);
		mpz_ui_pow_ui(bar, 2UL, k);
		if (!mpz_cmp(foo, bar))
		{
			// check, whether k is power of two
			mpz_set_ui(foo, k);
			unsigned long int l = mpz_sizeinbase(foo, 2UL);
			mpz_ui_pow_ui(bar, 2UL, l);
			if (!mpz_cmp(foo, bar))
			{
				// check, whether m is not equal to 5L
				if (!mpz_cmp_ui(m, 5UL))
					throw false;
				
				// check, whether 5^{2^(k/2)} \equiv -1 (mod m)
				// [Pepin's prime test]
				mpz_ui_pow_ui(foo, 2UL, (k / 2));
				mpz_set_ui(bar, 5UL);
				mpz_powm(foo, bar, foo, m);
				mpz_set_si(bar, -1L);
				if (mpz_congruent_p(foo, bar, m))
					throw false;
			}
		}

		// abort, if non-NIZK key
		if (type.find("NIZK", 0) == type.npos)
			throw true;
		
		// check magic of NIZK
		if (!TMCG_ParseHelper::cm(s, "nzk", '^'))
			throw false;
		
		// initialize NIZK proof input
		std::ostringstream input;
		input << m << "^" << y;
		
		// get security parameter of STAGE1
		std::string size_str;
		if (!TMCG_ParseHelper::gs(s, '^', size_str))
			throw false;
		char *ec;
		stage1_size = std::strtoul(size_str.c_str(), &ec, 10);
		if ((*ec != '\0') || (stage1_size <= 0) ||
			!TMCG_ParseHelper::nx(s, '^'))
		{
			throw false;
		}
		
		// check security constraint of STAGE1
		if (stage1_size < TMCG_KEY_NIZK_STAGE1)
			throw false;
		
		// STAGE1: m is Square Free
		for (size_t i = 0; i < stage1_size; i++)
		{
			// common random number foo \in Z^*_m (from hash function g)
			do
			{
				tmcg_g(mn, mnsize, (unsigned char*)(input.str()).c_str(),
					(input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				mpz_gcd(bar, foo, m);
				input << foo;
			}
			while (mpz_cmp_ui(bar, 1UL));
			
			// read NIZK proof
			std::string mpz_str;
			if (!TMCG_ParseHelper::gs(s, '^', mpz_str))
				throw false;
			if ((mpz_set_str(bar, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				!TMCG_ParseHelper::nx(s, '^'))
			{
				throw false;
			}
			
			// check, whether bar^m mod m is equal to foo
			mpz_powm(bar, bar, m, m);
			if (mpz_cmp(foo, bar))
				throw false;
		}
		
		// get security parameter of STAGE2
		if (!TMCG_ParseHelper::gs(s, '^', size_str))
			throw false;
		stage2_size = std::strtoul(size_str.c_str(), &ec, 10);
		if ((*ec != '\0') || (stage2_size <= 0) ||
			!TMCG_ParseHelper::nx(s, '^'))
		{
			throw false;
		}
		
		// check security constraint of STAGE2
		if (stage2_size < TMCG_KEY_NIZK_STAGE2)
			throw false;
		
		// STAGE2: m is Prime Power Product
		for (size_t i = 0; i < stage2_size; i++)
		{
			// common random number foo \in Z^*_m (from hash function g)
			do
			{
				tmcg_g(mn, mnsize, (unsigned char*)(input.str()).c_str(),
					(input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				mpz_gcd(bar, foo, m);
				input << foo;
			}
			while (mpz_cmp_ui(bar, 1L));
			
			// read NIZK proof
			std::string mpz_str;
			if (!TMCG_ParseHelper::gs(s, '^', mpz_str))
				throw false;
			if ((mpz_set_str(bar, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				!TMCG_ParseHelper::nx(s, '^'))
			{
				throw false;
			}
			
			// check, whether bar^2 \equiv +-foo or \equiv +-2foo (mod m)
			mpz_mul(bar, bar, bar);
			mpz_mod(bar, bar, m);
			if (!mpz_congruent_p(bar, foo, m))
			{
				mpz_neg(foo, foo);
				if (!mpz_congruent_p(bar, foo, m))
				{
					mpz_mul_2exp(foo, foo, 1UL);
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
		if (!TMCG_ParseHelper::gs(s, '^', size_str))
			throw false;
		stage3_size = std::strtoul(size_str.c_str(), &ec, 10);
		if ((*ec != '\0') || (stage3_size <= 0) ||
			!TMCG_ParseHelper::nx(s, '^'))
		{
			throw false;
		}
		
		// check security constraint of STAGE3
		if (stage3_size < TMCG_KEY_NIZK_STAGE3)
			throw false;
		
		// STAGE3: y \in NQR^\circ_m
		for (size_t i = 0; i < stage3_size; i++)
		{
			// common random number foo \in Z^\circ_m (from hash function g)
			do
			{
				tmcg_g(mn, mnsize, (unsigned char*)(input.str()).c_str(),
					(input.str()).length());
				mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
				mpz_mod(foo, foo, m);
				input << foo;
			}
			while (mpz_jacobi(foo, m) != 1);
			
			// read NIZK proof
			std::string mpz_str;
			if (!TMCG_ParseHelper::gs(s, '^', mpz_str))
				throw false;
			if ((mpz_set_str(bar, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
				!TMCG_ParseHelper::nx(s, '^'))
			{
				throw false;
			}
			
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

std::string TMCG_PublicKey::fingerprint
	() const
{
	unsigned int hash_size = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	unsigned char *digest = new unsigned char[hash_size];
	char *hex_digest = new char[(3 * hash_size) + 1];
	std::ostringstream data;
	
	// compute the digest
	data << "pub|" << name << "|" << email << "|" << type << 
		"|" << m << "|" << y << "|" << nizk << "|" << sig;
	tmcg_h(digest, (unsigned char*)(data.str()).c_str(), (data.str()).length());
	// convert the digest to a hexadecimal encoded string
	for (size_t i = 0; i < (hash_size / 2); i++)
	{
		snprintf(hex_digest + (5 * i), 6, "%02X%02X ",
			digest[2 * i], digest[(2 * i) + 1]);
	}
	std::string fp_str = hex_digest;
	// release resources
	delete [] digest, delete [] hex_digest;
	
	return std::string(fp_str);
}

std::string TMCG_PublicKey::selfid
	()
{
	std::string s = sig;
	
	// maybe a self signature
	if (s == "")
		return tmcg_SELFSIG;
	
	// check magic
	if (!TMCG_ParseHelper::cm(s, "sig", '|'))
		return tmcg_ERROR;
	
	// skip the keyID
	if (!TMCG_ParseHelper::nx(s, '|'))
		return tmcg_ERROR;
	
	// get the sigID
	if (!TMCG_ParseHelper::gs(s, '|', TMP))
		return tmcg_ERROR;

	return TMP;
}

std::string TMCG_PublicKey::keyid
	(const size_t size)
{
	std::ostringstream data;
	std::string tmp = selfid();
	
	if (tmp == "ERROR")
		return tmcg_ERROR;
	
	data << "ID" << size << "^" << tmp.substr(tmp.length() - 
		((size < tmp.length()) ? size : tmp.length()),
		(size < tmp.length()) ? size : tmp.length());
	TMP = data.str();

	return TMP;
}

size_t TMCG_PublicKey::keyid_size
	(const std::string& s) const
{
	// check the format
	if ((s.length() < 4) || (s.substr(0, 2) != "ID") || (s.find("^") == s.npos))
		return 0;
	
	// extract the size
	char *ec;
	std::string idlen_str = s.substr(2, s.find("^") - 2);
	size_t size = std::strtoul(idlen_str.c_str(), &ec, 10);
	if ((*ec != '\0') || (size != (s.length() - s.find("^") - 1)))
		return 0;
	
	return size;
}

std::string TMCG_PublicKey::sigid
	(std::string s)
{
	// check magic
	if (!TMCG_ParseHelper::cm(s, "sig", '|'))
		return tmcg_ERROR;
	
	// get the keyID
	if (!TMCG_ParseHelper::gs(s, '|', TMP))
		return tmcg_ERROR;

	return TMP;
}

bool TMCG_PublicKey::import
	(std::string s)
{
	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(s, "pub", '|'))
			throw false;
		
		// name
		if (!TMCG_ParseHelper::gs(s, '|', name))
			throw false;
		if (!TMCG_ParseHelper::nx(s, '|'))
			throw false;
		
		// email
		if (!TMCG_ParseHelper::gs(s, '|', email))
			throw false;
		if (!TMCG_ParseHelper::nx(s, '|'))
			throw false;
		
		// type
		if (!TMCG_ParseHelper::gs(s, '|', type))
			throw false;
		if (!TMCG_ParseHelper::nx(s, '|'))
			throw false;

		std::string mpz_str;		
		// m
		if (!TMCG_ParseHelper::gs(s, '|', mpz_str))
			throw false;
		if ((mpz_set_str(m, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(s, '|'))
		{
			throw false;
		}
		
		// y
		if (!TMCG_ParseHelper::gs(s, '|', mpz_str))
			throw false;
		if ((mpz_set_str(y, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(s, '|'))
		{
			throw false;
		}
		
		// NIZK
		if (!TMCG_ParseHelper::gs(s, '|', nizk))
			throw false;
		if (!TMCG_ParseHelper::nx(s, '|'))
			throw false;
		
		// sig
		sig = s;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

std::string TMCG_PublicKey::encrypt
	(const unsigned char* value)
{
	mpz_t vdata;
	size_t rabin_s2 = 2 * TMCG_SAEP_S0;
	size_t rabin_s1 = (mpz_sizeinbase(m, 2UL) / 8) - rabin_s2;
	size_t rabin_s = rabin_s1 + rabin_s2;
	
	assert(rabin_s2 < (mpz_sizeinbase(m, 2UL) / 16));
	assert(rabin_s2 < rabin_s1);
	assert(TMCG_SAEP_S0 < (mpz_sizeinbase(m, 2UL) / 32));
	
	// use simplified OAEP = SAEP [Bo01]
	unsigned char *r = new unsigned char[rabin_s1];
	unsigned char *Mt = new unsigned char[rabin_s2];
	unsigned char *g12 = new unsigned char[rabin_s2];
	gcry_randomize(r, rabin_s1, GCRY_STRONG_RANDOM);
	memcpy(Mt, value, TMCG_SAEP_S0);
	memset(Mt + TMCG_SAEP_S0, 0, TMCG_SAEP_S0);
	tmcg_g(g12, rabin_s2, r, rabin_s1);
	
	for (size_t i = 0; i < rabin_s2; i++)
		Mt[i] ^= g12[i];
	
	unsigned char *yy = new unsigned char[rabin_s];
	memcpy(yy, Mt, rabin_s2);
	memcpy(yy + rabin_s2, r, rabin_s1);
	mpz_init(vdata);
	mpz_import(vdata, 1, -1, rabin_s, 1, 0, yy);
	delete [] yy, delete [] g12, delete [] Mt, delete [] r;
	
	// apply Rabin's encryption function, i.e., vdata = vdata^2 mod m
	mpz_mul(vdata, vdata, vdata);
	mpz_mod(vdata, vdata, m);
	
	std::ostringstream ost;
	ost << "enc|" << keyid() << "|" << vdata << "|";
	mpz_clear(vdata);
	
	return ost.str();
}

bool TMCG_PublicKey::verify
	(const std::string& data, std::string s)
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(s, "sig", '|'))
			throw false;
		
		// check keyID
		std::string kid;
		if (!TMCG_ParseHelper::gs(s, '|', kid))
			throw false;
		if ((kid != keyid(keyid_size(kid))) || !TMCG_ParseHelper::nx(s, '|'))
			throw false;
		
		// value
		std::string mpz_str;
		if (!TMCG_ParseHelper::gs(s, '|', mpz_str))
			throw false;
		if ((mpz_set_str(foo, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(s, '|'))
		{
			throw false;
		}
		
		// verify signature (see PRab [BR96] for details)
		size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
		size_t mnsize = mpz_sizeinbase(m, 2UL) / 8;
		if (mpz_sizeinbase(m, 2UL) <= (mnsize * 8))
			throw false;
		if (mnsize <= (mdsize + TMCG_PRAB_K0))
			throw false;
		mpz_mul(foo, foo, foo); // apply Rabin's verification function
		mpz_mod(foo, foo, m);
		size_t gsize = mnsize - mdsize - TMCG_PRAB_K0;
		unsigned char *w = new unsigned char[mdsize];
		unsigned char *r = new unsigned char[TMCG_PRAB_K0];
		unsigned char *gamma = new unsigned char[gsize];
		unsigned char *yy = new unsigned char[mnsize+1024];
		size_t cnt = 1;
		mpz_export(yy, &cnt, -1, mnsize, 1, 0, foo);
		memcpy(w, yy, mdsize);
		memcpy(r, yy + mdsize, TMCG_PRAB_K0);
		memcpy(gamma, yy + mdsize + TMCG_PRAB_K0, gsize);
		unsigned char *g12 = new unsigned char[mnsize];
		tmcg_g(g12, mnsize - mdsize, w, mdsize);
		for (size_t i = 0; i < TMCG_PRAB_K0; i++)
			r[i] ^= g12[i];
		unsigned char *Mr = new unsigned char[data.length() + TMCG_PRAB_K0];
		memcpy(Mr, data.c_str(), data.length());
		memcpy(Mr + data.length(), r, TMCG_PRAB_K0);
		unsigned char *w2 = new unsigned char[mdsize];
		tmcg_h(w2, Mr, data.length() + TMCG_PRAB_K0);
		bool ok = (memcmp(w, w2, mdsize) == 0) &&
			(memcmp(gamma, g12 + TMCG_PRAB_K0, gsize) == 0);
		delete [] w;
		delete [] r;
		delete [] gamma;
		delete [] yy;
		delete [] g12;
		delete [] Mr;
		delete [] w2;
		
		throw ok;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

TMCG_PublicKey::~TMCG_PublicKey
	()
{
	mpz_clear(m), mpz_clear(y);
}

std::ostream& operator <<
	(std::ostream& out, const TMCG_PublicKey& key)
{
	return out << "pub|" << key.name << "|" << key.email << "|" << key.type <<
		"|" << key.m << "|" << key.y << "|" << key.nizk << "|" << key.sig;
}

std::istream& operator >>
	(std::istream& in, TMCG_PublicKey& key)
{
	char *tmp = new char[TMCG_MAX_KEY_CHARS];
	in.getline(tmp, TMCG_MAX_KEY_CHARS);
	if (!key.import(std::string(tmp)))
		in.setstate(std::istream::iostate(std::istream::failbit));
	delete [] tmp;
	return in;
}

