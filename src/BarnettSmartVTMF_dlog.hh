/*******************************************************************************
   BarnettSmartVTMF_dlog.hh, Verifiable l-out-of-l Threshold Masking Function

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
             Statements about Discrete Logarithms', Technical Report, 1997

     [KK04] Takeshi Koshiba, Kaoru Kurosawa: 'Short Exponent Diffie-Hellman
            Problems', In Public Key Cryptography - PKC 2004: Proceedings
            7th International Workshop on Theory and Practice in Public Key
            Cryptography, LNCS 2947, pp. 173--186, 2004

   This file is part of libTMCG.

 Copyright (C) 2004, 2005 Heiko Stamer, <stamer@gaos.org>

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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_HH

	// config.h
	#if HAVE_CONFIG_H
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

class BarnettSmartVTMF_dlog
{
	public:
		mpz_t								p, q, g;
		mpz_t								x_i, h_i, h, d, h_i_fp;
		std::map<std::string, mpz_ptr>		h_j;
		
		BarnettSmartVTMF_dlog
			(unsigned long int groupsize = TMCG_DDH_SIZE,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		BarnettSmartVTMF_dlog
			(std::istream &in,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			(unsigned long int groupsize = TMCG_DDH_SIZE);
		void PublishGroup
			(std::ostream &out);
		void RandomElement
			(mpz_ptr a);
		void NextElement
			(mpz_ptr a);
		void IndexElement
			(mpz_ptr a, std::size_t index);
		void KeyGenerationProtocol_GenerateKey
			();
		void KeyGenerationProtocol_PublishKey
			(std::ostream &out);
		bool KeyGenerationProtocol_UpdateKey
			(std::istream &in);
		void CP_Prove
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			mpz_srcptr alpha, std::ostream &out);
		bool CP_Verify
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			std::istream &in);
		void VerifiableMaskingProtocol_Mask
			(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		void VerifiableMaskingProtocol_Prove
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r,
			std::ostream &out);
		bool VerifiableMaskingProtocol_Verify
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream &in);
		void VerifiableRemaskingProtocol_Mask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r,
			unsigned long int exponentsize = TMCG_DLSE_SIZE);
		void VerifiableRemaskingProtocol_RemaskValue
			(mpz_ptr r, unsigned long int exponentsize = TMCG_DLSE_SIZE);
		void VerifiableRemaskingProtocol_Remask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_srcptr r);
		void VerifiableRemaskingProtocol_Prove
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			mpz_srcptr r, std::ostream &out);
		bool VerifiableRemaskingProtocol_Verify
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			std::istream &in);
		void VerifiableDecryptionProtocol_Prove
			(mpz_srcptr c_1, std::ostream &out);
		void VerifiableDecryptionProtocol_Verify_Initalize
			(mpz_srcptr c_1);
		bool VerifiableDecryptionProtocol_Verify_Update
			(mpz_srcptr c_1, std::istream &in);
		void VerifiableDecryptionProtocol_Verify_Finalize
			(mpz_srcptr c_2, mpz_ptr m);
		~BarnettSmartVTMF_dlog
			();
};

#endif
