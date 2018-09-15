/*******************************************************************************
   Data structure for big integers. This file is part of LibTMCG.

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
	mpz_t bigint;
	gcry_mpi_t secret_bigint;

	TMCG_Bigint
		(const bool secret_in = false);
	TMCG_Bigint
		(const TMCG_Bigint& that);

	TMCG_Bigint& operator =
		(const TMCG_Bigint& that);
	TMCG_Bigint& operator =
		(const unsigned long int that);
	TMCG_Bigint& operator =
		(const signed long int that);
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


	~TMCG_Bigint
		();
};

std::ostream& operator <<
	(std::ostream& out, const TMCG_Bigint& that);
std::istream& operator >>
	(std::istream& in, TMCG_Bigint& that);

#endif

