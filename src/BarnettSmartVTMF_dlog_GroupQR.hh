/*******************************************************************************
   BarnettSmartVTMF_dlog_GroupQR.hh, VTMF instance where $G := \mathbb{QR}_p$

     [BS03] Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

     [KK04] Takeshi Koshiba, Kaoru Kurosawa: 'Short Exponent Diffie-Hellman
       Problems', In Public Key Cryptography - PKC 2004: Proceedings 7th
     International Workshop on Theory and Practice in Public Key Cryptography,
     LNCS 2947, pp. 173--186, 2004.

     [Bo98] Dan Boneh: 'The Decision Diffie-Hellman Problem',
     Proceedings of the 3rd Algorithmic Number Theory Symposium,
     LNCS 1423, pp. 48--63, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006,
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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_GroupQR_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_GroupQR_HH
	
// C and STL header
#include <iostream>

// GNU multiple precision library
#include <gmp.h>

// base class
#include "BarnettSmartVTMF_dlog.hh"

class BarnettSmartVTMF_dlog_GroupQR : public BarnettSmartVTMF_dlog
{
	protected:
		const unsigned long int		E_size;
	
	public:
		BarnettSmartVTMF_dlog_GroupQR
			(const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int exponentsize = TMCG_DLSE_SIZE);
		BarnettSmartVTMF_dlog_GroupQR
			(std::istream &in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int exponentsize = TMCG_DLSE_SIZE);
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
