/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_TMCG_Card_HH
	#define INCLUDED_TMCG_Card_HH

	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C++/STL header
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <vector>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "parse_helper.hh"
	
struct TMCG_Card
{
	std::vector< std::vector<MP_INT> >			z;
	
	TMCG_Card
		();
	
	TMCG_Card
		(size_t n, size_t m);
	
	TMCG_Card
		(const TMCG_Card& that);
	
	TMCG_Card& operator =
		(const TMCG_Card& that);
	
	bool operator ==
		(const TMCG_Card& that) const;
	
	bool operator !=
		(const TMCG_Card& that) const;
	
	void resize
		(size_t n, size_t m);
	
	bool import
		(std::string s);
	
	~TMCG_Card
		();
};

std::ostream& operator<< 
	(std::ostream &out, const TMCG_Card &card);

#endif
