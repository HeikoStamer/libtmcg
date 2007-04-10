/*******************************************************************************
   BarnettSmartVTMF_dlog.hh, Verifiable k-out-of-k Threshold Masking Function

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_HH

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

class BarnettSmartVTMF_dlog
{
	private:
		mpz_t															x_i, h_i, d, h_i_fp;
		std::map<std::string, mpz_ptr>		h_j;
	
	protected:
		mpz_t															*fpowm_table_g, *fpowm_table_h;
		unsigned long int									F_size, G_size;
	
	public:
		mpz_t															p, q, g, k, h;
		
		BarnettSmartVTMF_dlog
			(unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		BarnettSmartVTMF_dlog
			(std::istream& in,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		virtual bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream& out) const;
		virtual bool CheckElement
			(mpz_srcptr a) const;
		virtual void RandomElement
			(mpz_ptr a) const;
		void IndexElement
			(mpz_ptr a, std::size_t index) const;
		void KeyGenerationProtocol_GenerateKey
			();
		void KeyGenerationProtocol_PublishKey
			(std::ostream& out) const;
		bool KeyGenerationProtocol_UpdateKey
			(std::istream& in);
		bool KeyGenerationProtocol_RemoveKey
			(std::istream& in);
		void KeyGenerationProtocol_Finalize
			();
		void CP_Prove
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			mpz_srcptr alpha, std::ostream& out, bool fpowm_usage = false) const;
		bool CP_Verify
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
			std::istream& in, bool fpowm_usage = false) const;
		void OR_ProveFirst
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
			mpz_srcptr alpha, std::ostream& out) const;
		void OR_ProveSecond
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
			mpz_srcptr alpha, std::ostream& out) const;
		bool OR_Verify
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
			std::istream& in) const;
		virtual void MaskingValue
			(mpz_ptr r) const;
		void VerifiableMaskingProtocol_Mask
			(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r) const;
		void VerifiableMaskingProtocol_Prove
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r,
			std::ostream& out) const;
		bool VerifiableMaskingProtocol_Verify
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream& in) const;
		void VerifiableRemaskingProtocol_Mask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2,
			mpz_ptr r) const;
		void VerifiableRemaskingProtocol_Remask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2,
			mpz_srcptr r, bool TimingAttackProtection = true) const;
		void VerifiableRemaskingProtocol_Prove
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			mpz_srcptr r, std::ostream& out) const;
		bool VerifiableRemaskingProtocol_Verify
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
			std::istream& in) const;
		void VerifiableDecryptionProtocol_Prove
			(mpz_srcptr c_1, std::ostream& out) const;
		void VerifiableDecryptionProtocol_Verify_Initialize
			(mpz_srcptr c_1);
		bool VerifiableDecryptionProtocol_Verify_Update
			(mpz_srcptr c_1, std::istream& in);
		void VerifiableDecryptionProtocol_Verify_Finalize
			(mpz_srcptr c_2, mpz_ptr m) const;
		virtual ~BarnettSmartVTMF_dlog
			();
};

#endif
