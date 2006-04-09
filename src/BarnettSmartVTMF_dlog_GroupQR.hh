/*******************************************************************************
   BarnettSmartVTMF_dlog_GroupQR.hh, VTMF instance where $G := \mathbb{QR}_p$

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_GroupQR_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_GroupQR_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <map>

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_spowm.h"
	#include "mpz_sprime.h"
	#include "mpz_helper.hh"
	#include "mpz_shash.hh"
	
	#include "BarnettSmartVTMF_dlog.hh"

class BarnettSmartVTMF_dlog_GroupQR : public BarnettSmartVTMF_dlog
{
	protected:
		unsigned long int		E_size;
	
	public:
		BarnettSmartVTMF_dlog_GroupQR
			(unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		BarnettSmartVTMF_dlog_GroupQR
			(std::istream &in,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		virtual bool CheckGroup
			() const;
		virtual bool CheckElement
			(mpz_srcptr a) const;
		virtual void RandomElement
			(mpz_ptr a) const;
		virtual void MaskingValue
			(mpz_ptr r) const;
		virtual ~BarnettSmartVTMF_dlog_GroupQR
			();
};

#endif
