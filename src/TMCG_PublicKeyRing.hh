/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2006  Heiko Stamer <stamer@gaos.org>

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_TMCG_PublicKeyRing_HH
	#define INCLUDED_TMCG_PublicKeyRing_HH
	
	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C++/STL header
	#include <cassert>
	#include <vector>

struct TMCG_PublicKeyRing
{
	std::vector<TMCG_PublicKey>			keys;
	
	TMCG_PublicKeyRing
		(size_t n):
			keys(n)
	{
		assert(n > 0);
	}
	
	~TMCG_PublicKeyRing
		()
	{
		keys.clear();
	}
};

#endif
