/*******************************************************************************
   BarnettSmartVTMF_dlog.hh, Verifiable k-out-of-k Threshold Masking Function

     [BS03] Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
       Statements about Discrete Logarithms', Technical Report, 1997.

     [Bo98] Dan Boneh: 'The Decision Diffie-Hellman Problem',
     Proceedings of the 3rd Algorithmic Number Theory Symposium,
     LNCS 1423, pp. 48--63, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007, 
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

#ifndef INCLUDED_BarnettSmartVTMF_dlog_HH
	#define INCLUDED_BarnettSmartVTMF_dlog_HH
	
// C and STL header
#include <cstdlib>
#include <iostream>
#include <map>

// GNU multiple precision library
#include <gmp.h>
	
// erasure-free distributed coinflip protocol [JL00]
#include "JareckiLysyanskayaASTC.hh"

class BarnettSmartVTMF_dlog
{
	private:
		mpz_t							x_i, d, h_i_fp;
		std::map<std::string, mpz_ptr>	h_j;
	
	protected:
		const unsigned long int			F_size, G_size;
		const bool						canonical_g;
		mpz_t							*fpowm_table_g, *fpowm_table_h;
	
	public:
		mpz_t							p, q, g, k, h, h_i;
		
		BarnettSmartVTMF_dlog
			(const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool initialize_group = true);
		BarnettSmartVTMF_dlog
			(std::istream& in,
			 const unsigned long int fieldsize = TMCG_DDH_SIZE,
			 const unsigned long int subgroupsize = TMCG_DLSE_SIZE,
			 const bool canonical_g_usage = false,
			 const bool precompute = true);
		virtual bool CheckGroup
			() const;
		void PublishGroup
			(std::ostream& out) const;
		virtual bool CheckElement
			(mpz_srcptr a) const;
		virtual void RandomElement
			(mpz_ptr a) const;
		void IndexElement
			(mpz_ptr a, const size_t index) const;
		void KeyGenerationProtocol_GenerateKey
			();
		void KeyGenerationProtocol_ComputeNIZK
			(mpz_ptr c, mpz_ptr r) const;
		void KeyGenerationProtocol_PublishKey
			(std::ostream& out) const;
		bool KeyGenerationProtocol_VerifyNIZK
			(mpz_srcptr foo, mpz_srcptr c, mpz_srcptr r) const;
		bool KeyGenerationProtocol_UpdateKey
			(std::istream& in);
		bool KeyGenerationProtocol_RemoveKey
			(std::istream& in);
		bool KeyGenerationProtocol_ProveKey_interactive
			(std::istream& in, std::ostream& out);
		bool KeyGenerationProtocol_ProveKey_interactive_publiccoin
			(JareckiLysyanskayaEDCF *edcf,
			 std::istream& in, std::ostream& out);
		bool KeyGenerationProtocol_VerifyKey_interactive
			(mpz_srcptr key, std::istream& in, std::ostream& out);
		bool KeyGenerationProtocol_VerifyKey_interactive_publiccoin
			(mpz_srcptr key, JareckiLysyanskayaEDCF *edcf,
			 std::istream& in, std::ostream& out);
		void KeyGenerationProtocol_Finalize
			();
		size_t KeyGenerationProtocol_NumberOfKeys
			();
		void CP_Prove
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg,
			 mpz_srcptr hh, mpz_srcptr alpha, std::ostream& out,
			 const bool fpowm_usage = false) const;
		bool CP_Verify
			(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg,
			 mpz_srcptr hh, std::istream& in,
			 const bool fpowm_usage = false) const;
		void OR_ProveFirst
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1,
			 mpz_srcptr g_2, mpz_srcptr alpha,
			 std::ostream& out) const;
		void OR_ProveSecond
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1,
			 mpz_srcptr g_2, mpz_srcptr alpha,
			 std::ostream& out) const;
		bool OR_Verify
			(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1,
			 mpz_srcptr g_2, std::istream& in) const;
		virtual void MaskingValue
			(mpz_ptr r) const;
		void VerifiableMaskingProtocol_Mask
			(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2,
			 mpz_ptr r) const;
		void VerifiableMaskingProtocol_Prove
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2,
			 mpz_srcptr r, std::ostream& out) const;
		bool VerifiableMaskingProtocol_Verify
			(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, 
			 std::istream& in) const;
		void VerifiableRemaskingProtocol_Mask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1,
			 mpz_ptr c__2, mpz_ptr r) const;
		void VerifiableRemaskingProtocol_Remask
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1,
			 mpz_ptr c__2, mpz_srcptr r, 
			 const bool TimingAttackProtection = true) const;
		void VerifiableRemaskingProtocol_Prove
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1,
			 mpz_srcptr c__2, mpz_srcptr r,
			 std::ostream& out) const;
		bool VerifiableRemaskingProtocol_Verify
			(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1,
			 mpz_srcptr c__2, std::istream& in) const;
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
