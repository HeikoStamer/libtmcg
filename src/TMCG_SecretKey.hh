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

#ifndef INCLUDED_TMCG_SecretKey_HH
	#define INCLUDED_TMCG_SecretKey_HH
	
// C++/STL header
#include <string>
#include <iostream>
	
// GNU multiple precision library
#include <gmp.h>

struct TMCG_SecretKey
{
	std::string	name, email, type, nizk, sig;
	mpz_t		m, y, p, q;
	// The following two lines contain non-persistent members (precomputation).
	// These members are only for internal usage and may change in the future.
	mpz_t		y1, m1pq, gcdext_up, gcdext_vq, pa1d4, qa1d4;
	
	TMCG_SecretKey
		();
	
	TMCG_SecretKey
		(const std::string& n, const std::string& e,
		 const unsigned long int keysize = TMCG_QRA_SIZE, 
		 const bool nizk_key = true);
	
	TMCG_SecretKey
		(const std::string& s);
	
	TMCG_SecretKey
		(const TMCG_SecretKey& that);
	
	TMCG_SecretKey& operator =
		(const TMCG_SecretKey& that);
	
	void generate
		(const unsigned long int keysize, const bool nizk_key);
	
	bool precompute
		();
	
	bool check
		() const;
	
	std::string fingerprint
		() const;
	
	std::string selfid
		() const;
	
	std::string keyid
		(const size_t size = TMCG_KEYID_SIZE) const;
	
	size_t keyid_size
		(const std::string& s) const;
	
	std::string sigid
		(const std::string& s) const;
	
	bool import
		(std::string s);
	
	bool decrypt
		(unsigned char* value, std::string s) const;
	
	std::string sign
		(const std::string& data) const;
	
	std::string encrypt
		(const unsigned char* value) const;
	
	bool verify
		(const std::string& data, const std::string& s) const;
	
	~TMCG_SecretKey
		();
};

std::ostream& operator <<
	(std::ostream& out, const TMCG_SecretKey& key);

std::istream& operator >>
	(std::istream& in, TMCG_SecretKey& key);

#endif
