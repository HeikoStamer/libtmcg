/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_mpz_helper_HH
	#define INCLUDED_mpz_helper_HH
	
	#include <iostream>
	#include <vector>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	// iostream operators for mpz_t
	std::ostream& operator <<
		(std::ostream &out, mpz_srcptr value);
	std::istream& operator >>
		(std::istream &in, mpz_ptr value);

	// polynomial interpolation
	bool interpolate_polynom
		(const std::vector<mpz_ptr> &a, const std::vector<mpz_ptr> &b,
		mpz_srcptr q, std::vector<mpz_ptr> &f);
#endif
