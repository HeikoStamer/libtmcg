/*******************************************************************************
   This file is part of libTMCG.

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

#ifndef INCLUDED_mpz_helper_HH
	#define INCLUDED_mpz_helper_HH
	
	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <iostream>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	// friendly iostream operators
	std::ostream& operator<<
		(std::ostream &out, mpz_srcptr value);
	std::istream& operator>> 
		(std::istream &in, mpz_ptr value);
#endif
