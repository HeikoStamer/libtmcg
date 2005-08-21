/*******************************************************************************
   BarnettSmartVTMF_dlog_GroupQR.hh, VTMF instance where $G := \mathbb{QR}_p$

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003

     [KK04] Takeshi Koshiba, Kaoru Kurosawa: 'Short Exponent Diffie-Hellman
             Problems', In Public Key Cryptography - PKC 2004: Proceedings
            7th International Workshop on Theory and Practice in Public Key
             Cryptography, LNCS 2947, pp. 173--186, 2004

   This file is part of libTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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
	public:
		unsigned long int		E_size;
		
		BarnettSmartVTMF_dlog_GroupQR
			(unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		BarnettSmartVTMF_dlog_GroupQR
			(std::istream &in,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			();
		bool CheckElement
			(mpz_srcptr a);
		void RandomElement
			(mpz_ptr a);
		void MaskingValue
			(mpz_ptr r);
		~BarnettSmartVTMF_dlog_GroupQR
			();
};

#endif
