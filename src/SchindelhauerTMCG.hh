/*******************************************************************************
   SchindelhauerTMCG.hh, cryptographic |T|oolbox for |M|ental |C|ard |G|ames

     Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Technical Report A-98-14, University of L{\"u}beck, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2002, 2003, 2004, 2005, 2006,
               2015, 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_SchindelhauerTMCG_HH
	#define INCLUDED_SchindelhauerTMCG_HH
	
// C and STL header
#include <cstdlib>
#include <string>
#include <iostream>
#include <vector>
#include <utility>
	
// GNU multiple precision library
#include <gmp.h>
	
#include "TMCG_SecretKey.hh"
#include "TMCG_PublicKey.hh"
#include "TMCG_PublicKeyRing.hh"
#include "VTMF_Card.hh"
#include "VTMF_CardSecret.hh"
#include "TMCG_Card.hh"
#include "TMCG_CardSecret.hh"
#include "TMCG_Stack.hh"
#include "TMCG_OpenStack.hh"
#include "TMCG_StackSecret.hh"
#include "BarnettSmartVTMF_dlog.hh"
#include "GrothVSSHE.hh"
#include "HooghSchoenmakersSkoricVillegasVRHE.hh"

class SchindelhauerTMCG
{
	private:
		size_t							TMCG_MaxCardType;
		mpz_t							*message_space;
		
		// private zero-knowledge proofs on values
		void TMCG_ProveQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t,
			std::istream &in, std::ostream &out);
		void TMCG_ProveNonQuadraticResidue
			(const TMCG_SecretKey &key, mpz_srcptr t, 
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyNonQuadraticResidue
			(const TMCG_PublicKey &key, mpz_srcptr t, 
			std::istream &in, std::ostream &out);
		void TMCG_ProveMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz, 
			mpz_srcptr r, mpz_srcptr b, std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
			std::istream &in, std::ostream &out);
		void TMCG_ProveMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr r, mpz_srcptr b,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskOne
			(const TMCG_PublicKey &key, mpz_srcptr t, 
			std::istream &in, std::ostream &out);
		void TMCG_ProveNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_SecretKey &key, std::istream &in, std::ostream &out);
		bool TMCG_VerifyNonQuadraticResidue_PerfectZeroKnowledge
			(const TMCG_PublicKey &key, std::istream &in, std::ostream &out);
		
		// private and obsolete operations on values, cards, and stacks
		void TMCG_MaskValue
			(const TMCG_PublicKey &key, mpz_srcptr z, mpz_ptr zz,
			mpz_srcptr r, mpz_srcptr b, const bool TimingAttackProtection = true);
		void TMCG_ProvePrivateCard
			(const TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			std::istream &in, std::ostream &out);
		bool TMCG_VerifyPrivateCard
			(const TMCG_Card &c, const TMCG_PublicKeyRing &ring,
			std::istream &in, std::ostream &out);
		void TMCG_GlueStackSecret
			(const TMCG_StackSecret<TMCG_CardSecret> &sigma,
			TMCG_StackSecret<TMCG_CardSecret> &pi, const TMCG_PublicKeyRing &ring);
		void TMCG_GlueStackSecret
			(const TMCG_StackSecret<VTMF_CardSecret> &sigma,
			TMCG_StackSecret<VTMF_CardSecret> &pi, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_MixOpenStack
			(const TMCG_OpenStack<TMCG_Card> &os, TMCG_OpenStack<TMCG_Card> &os2, 
			const TMCG_StackSecret<TMCG_CardSecret> &ss, 
			const TMCG_PublicKeyRing &ring);
		void TMCG_MixOpenStack
			(const TMCG_OpenStack<VTMF_Card> &os, TMCG_OpenStack<VTMF_Card> &os2, 
			const TMCG_StackSecret<VTMF_CardSecret> &ss, 
			BarnettSmartVTMF_dlog *vtmf);
		
		// helper methods for Groth's shuffle proof
		void TMCG_InitializeStackEquality_Groth
			(std::vector<size_t> &pi, std::vector<mpz_ptr> &R,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
			const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss);
		void TMCG_InitializeStackEquality_Groth
			(std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
			const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2);
		void TMCG_ReleaseStackEquality_Groth
			(std::vector<size_t> &pi, std::vector<mpz_ptr> &R,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E);
		void TMCG_ReleaseStackEquality_Groth
			(std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E);

		// helper methods for rotation proof
		void TMCG_InitializeStackEquality_Hoogh
			(std::vector<mpz_ptr> &R,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
			const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			const TMCG_StackSecret<VTMF_CardSecret> &ss);
		void TMCG_ReleaseStackEquality_Hoogh
			(std::vector<mpz_ptr> &R,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
			std::vector<std::pair<mpz_ptr, mpz_ptr> > &E);
	
	public:
		const unsigned long int		TMCG_SecurityLevel;		// # of iterations
		const size_t			TMCG_Players, TMCG_TypeBits;	// k and w
		
		// constructors and destructors
		SchindelhauerTMCG
			(const unsigned long int security, const size_t k, const size_t w);
		~SchindelhauerTMCG
			();
		
		// operations and proofs on cards
		void TMCG_CreateOpenCard
			(TMCG_Card &c, const TMCG_PublicKeyRing &ring, const size_t type);
		void TMCG_CreateOpenCard
			(VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf, const size_t type);
		void TMCG_CreatePrivateCard
			(TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			 const size_t index, const size_t type);
		void TMCG_CreatePrivateCard
			(VTMF_Card &c, VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf,
			 const size_t type);
		void TMCG_CreateCardSecret
			(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
			 const size_t index);
		void TMCG_CreateCardSecret
			(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_MaskCard
			(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
			 const TMCG_PublicKeyRing &ring, const bool TimingAttackProtection = true);
		void TMCG_MaskCard
			(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
			 BarnettSmartVTMF_dlog *vtmf, const bool TimingAttackProtection = true);
		void TMCG_ProveMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_CardSecret &cs,
			 const TMCG_PublicKeyRing &ring, std::istream &in, std::ostream &out);
		void TMCG_ProveMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, const VTMF_CardSecret &cs,
			 BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskCard
			(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_PublicKeyRing &ring,
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyMaskCard
			(const VTMF_Card &c, const VTMF_Card &cc, BarnettSmartVTMF_dlog *vtmf,
			 std::istream &in, std::ostream &out);
		void TMCG_ProveCardSecret
			(const TMCG_Card &c, const TMCG_SecretKey &key, const size_t index,
			 std::istream &in, std::ostream &out);
		void TMCG_ProveCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyCardSecret
			(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKey &key,
			 const size_t index, std::istream &in, std::ostream &out);
		bool TMCG_VerifyCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
			std::istream &in, std::ostream &out);
		void TMCG_SelfCardSecret
			(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_SecretKey &key,
			 const size_t index);
		void TMCG_SelfCardSecret
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf);
		size_t TMCG_TypeOfCard
			(const TMCG_CardSecret &cs);
		size_t TMCG_TypeOfCard
			(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf);
		
		// operations and proofs on stacks
		size_t TMCG_CreateStackSecret
			(TMCG_StackSecret<TMCG_CardSecret> &ss, const bool cyclic,
			 const TMCG_PublicKeyRing &ring, const size_t index,
			 const size_t size);
		size_t TMCG_CreateStackSecret
			(TMCG_StackSecret<VTMF_CardSecret> &ss, const bool cyclic,
			 const size_t size, BarnettSmartVTMF_dlog *vtmf);
		void TMCG_CreateStackSecret
			(TMCG_StackSecret<TMCG_CardSecret> &ss,
			 const std::vector<size_t> &pi, const TMCG_PublicKeyRing &ring,
			 const size_t index, const size_t size);
		void TMCG_CreateStackSecret
			(TMCG_StackSecret<VTMF_CardSecret> &ss,
			 const std::vector<size_t> &pi, const size_t size,
			 BarnettSmartVTMF_dlog *vtmf);
		void TMCG_MixStack
			(const TMCG_Stack<TMCG_Card> &s, TMCG_Stack<TMCG_Card> &s2,
			 const TMCG_StackSecret<TMCG_CardSecret> &ss,
			 const TMCG_PublicKeyRing &ring,
			 const bool TimingAttackProtection = true);
		void TMCG_MixStack
			(const TMCG_Stack<VTMF_Card> &s, TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss,
			 BarnettSmartVTMF_dlog *vtmf,
			 const bool TimingAttackProtection = true);
		void TMCG_ProveStackEquality
			(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2,
			 const TMCG_StackSecret<TMCG_CardSecret> &ss, const bool cyclic,
			 const TMCG_PublicKeyRing &ring, const size_t index, 
			 std::istream &in, std::ostream &out);
		void TMCG_ProveStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss, const bool cyclic,
			 BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out);
		void TMCG_ProveStackEquality_Groth
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss,
			 BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
			 std::istream &in, std::ostream &out);
		void TMCG_ProveStackEquality_Groth_noninteractive
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss,
			 BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
			 std::ostream &out);
		void TMCG_ProveStackEquality_Hoogh
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss,
			 BarnettSmartVTMF_dlog *vtmf, HooghSchoenmakersSkoricVillegasVRHE *vrhe,
			 std::istream &in, std::ostream &out);
		void TMCG_ProveStackEquality_Hoogh_noninteractive
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 const TMCG_StackSecret<VTMF_CardSecret> &ss,
			 BarnettSmartVTMF_dlog *vtmf, HooghSchoenmakersSkoricVillegasVRHE *vrhe,
			 std::ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2, 
			 const bool cyclic, const TMCG_PublicKeyRing &ring, 
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, 
			 const bool cyclic, BarnettSmartVTMF_dlog *vtmf, 
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality_Groth
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, 
			 BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality_Groth_noninteractive
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, 
			 BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
			 std::istream &in);
		bool TMCG_VerifyStackEquality_Hoogh
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 BarnettSmartVTMF_dlog *vtmf, HooghSchoenmakersSkoricVillegasVRHE *vrhe,
			 std::istream &in, std::ostream &out);
		bool TMCG_VerifyStackEquality_Hoogh_noninteractive
			(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
			 BarnettSmartVTMF_dlog *vtmf, HooghSchoenmakersSkoricVillegasVRHE *vrhe,
			 std::istream &in);
};

#endif
