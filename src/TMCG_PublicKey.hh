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

#ifndef INCLUDED_TMCG_PublicKey_HH
	#define INCLUDED_TMCG_PublicKey_HH

	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C++/STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <sstream>
	#include <iostream>
	#include <vector>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_sqrtm.h"
	#include "mpz_helper.hh"
	#include "parse_helper.hh"
	#include "mpz_shash.hh"
	#include "TMCG_SecretKey.hh"

struct TMCG_PublicKey
{
	std::string						name, email, type, nizk, sig;
	mpz_t									m, y;
	
	TMCG_PublicKey
		();
	
	TMCG_PublicKey
		(const TMCG_SecretKey &skey);
	
	TMCG_PublicKey
		(const TMCG_PublicKey &pkey);
	
	TMCG_PublicKey
		(const std::string& s);
	
	TMCG_PublicKey& operator =
	(const TMCG_PublicKey& that);
	
	bool check
		() const;
	
	std::string selfid
		() const;
	
	std::string keyid
		() const;
	
	std::string sigid
		(std::string s) const;
	
	bool import
		(std::string s);
	
	std::string encrypt
		(const char *value) const;
	
	bool verify
		(const std::string &data, std::string s) const;
	
	~TMCG_PublicKey
		();
};

std::ostream& operator<< 
	(std::ostream &out, const TMCG_PublicKey &key);

#endif
