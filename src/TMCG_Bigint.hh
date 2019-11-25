/*******************************************************************************
   Data structure for big integers. This file is part of LibTMCG.

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_TMCG_Bigint_HH
	#define INCLUDED_TMCG_Bigint_HH
	
// C++/STL header
#include <iostream>

// GNU crypto library
#include <gcrypt.h>
	
// GNU multiple precision library
#include <gmp.h>

struct TMCG_Bigint
{
	const bool secret;
	const bool exportable;
	mpz_t bigint;
	gcry_mpi_t secret_bigint;
	size_t ssrandomm_cache_n;
	mpz_t ssrandomm_cache_cache[TMCG_MAX_SSRANDOMM_CACHE];
	gcry_mpi_t ssrandomm_cache_secret_cache[TMCG_MAX_SSRANDOMM_CACHE];
	mpz_t ssrandomm_cache_mod;
	size_t ssrandomm_cache_avail;

	// Constructors
	TMCG_Bigint
		(const bool secret_in = false, const bool exportable_in = false);
	TMCG_Bigint
		(const TMCG_Bigint& that);
	TMCG_Bigint
		(const mpz_t that);

	// Arithmetic operators
	TMCG_Bigint& operator =
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator =
		(const unsigned long int that);
	TMCG_Bigint& operator =
		(const signed long int that);
	TMCG_Bigint& operator +=
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator +=
		(const unsigned long int that);
	TMCG_Bigint& operator -
		();
	TMCG_Bigint& operator -=
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator -=
		(const unsigned long int that);
	TMCG_Bigint& operator *=
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator *=
		(const unsigned long int that);
	TMCG_Bigint& operator /=
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator /=
		(const unsigned long int that);
	TMCG_Bigint& operator %=
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator %=
		(const unsigned long int that);

	// Comparison operators/relational operators
	bool operator ==
		(const TMCG_Bigint& that) const;
	bool operator ==
		(const unsigned long int that) const;
	bool operator ==
		(const signed long int that) const;
	bool operator !=
		(const TMCG_Bigint& that) const;
	bool operator !=
		(const unsigned long int that) const;
	bool operator !=
		(const signed long int that) const;
	bool operator >
		(const TMCG_Bigint& that) const;
	bool operator >
		(const unsigned long int that) const;
	bool operator <
		(const TMCG_Bigint& that) const;
	bool operator <
		(const unsigned long int that) const;
	bool operator >=
		(const TMCG_Bigint& that) const;
	bool operator >=
		(const unsigned long int that) const;
	bool operator <=
		(const TMCG_Bigint& that) const;
	bool operator <=
		(const unsigned long int that) const;
	
	// Other functions
	void abs
		();
	void set_str
		(const std::string& that, const size_t base);
	bool probab_prime
		(const size_t reps = TMCG_MR_ITERATIONS);
	void mul2exp
		(const size_t exp);
	void div2exp
		(const size_t exp);
	void ui_pow_ui
		(const unsigned long int base, const unsigned long int exp);
	void powm
		(const TMCG_Bigint& base, const TMCG_Bigint& exp,
		 const TMCG_Bigint& mod);
	void spowm
		(const TMCG_Bigint& base, const TMCG_Bigint& exp,
		 const TMCG_Bigint& mod);
	void powm_ui
		(const TMCG_Bigint& base, const unsigned long int exp,
		 const TMCG_Bigint& mod);
	unsigned long int get_ui
		();
	size_t size
		(const size_t base = TMCG_MPZ_IO_BASE) const;
	void wrandomb
		(const size_t bits);
	void srandomb
		(const size_t bits);
	void ssrandomb
		(const size_t bits);
	void wrandomm
		(const TMCG_Bigint& mod);
	void srandomm
		(const TMCG_Bigint& mod);
	void ssrandomm
		(const TMCG_Bigint& mod);
	void ssrandomm_cache_init
		(const TMCG_Bigint& mod, const size_t n);
	void ssrandomm_cache
		();
	void ssrandomm_cache_done
		();

	// Destructors
	~TMCG_Bigint
		();
};

std::ostream& operator <<
	(std::ostream& out, const TMCG_Bigint& that);
std::istream& operator >>
	(std::istream& in, TMCG_Bigint& that);

#endif

