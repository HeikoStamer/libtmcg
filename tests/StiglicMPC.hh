/******************************************************************************
   StiglicMPC.hh, secure |M|ulti-|P|arty |C|omputation with a deck of cards

     Anton Stiglic: 'Computations with a deck of cards', 
     Theoretical Computer Science, 259 (1-2) (2001) pp. 671-678

 Copyright (C) 2002, 2003, 2005, 2007,
               2015, 2019  Heiko Stamer <HeikoStamer@gmx.net>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
******************************************************************************/

#ifndef INCLUDED_StiglicMPC_HH
	#define INCLUDED_StiglicMPC_HH
	
	// C++/STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <vector>
	
	// libTMCG
	#include <libTMCG.hh>

struct MPC_Participant
{
	std::istream	*in;
	std::ostream	*out;
	
	MPC_Participant
		(std::istream *pin, std::ostream *pout):
		in(pin), out(pout)
	{
	}
	
	~MPC_Participant
		()
	{
	}
};

typedef std::vector<MPC_Participant*>			MPC_ParticipantList;
typedef TMCG_Stack<VTMF_Card>					MPC_Bit;
typedef TMCG_StackSecret<VTMF_CardSecret>		MPC_BitSecret;

class StiglicMPC
{
	private:
		SchindelhauerTMCG						*tmcg;
		BarnettSmartVTMF_dlog					*vtmf;
		HooghSchoenmakersSkoricVillegasVRHE		*vrhe;
		MPC_ParticipantList						participants;
		size_t									index;
		MPC_Bit									base, negbase;
	
	public:
		StiglicMPC
			(const size_t security, const MPC_ParticipantList &plist,
			 const size_t pindex);
		
		void MPC_ProveBitCommitment
			(MPC_Bit &bit, const bool b);
		
		void MPC_ProveBitCommitment_Hoogh
			(MPC_Bit &bit, const bool b);

		bool MPC_VerifyBitCommitment
			(MPC_Bit &bit, const size_t from);
		
		bool MPC_VerifyBitCommitment_Hoogh
			(MPC_Bit &bit, const size_t from);

		bool MPC_OpenCardCommitment
			(const VTMF_Card &card, bool &b);
		
		bool MPC_OpenBitCommitment
			(const MPC_Bit &bit, bool &b);
		
		bool MPC_CyclicShift
			(TMCG_Stack<VTMF_Card> &stack);

		bool MPC_CyclicShift_Hoogh
			(TMCG_Stack<VTMF_Card> &stack);
		
		void MPC_ComputeNEG
			(MPC_Bit &result, const MPC_Bit &bit);
		
		bool MPC_ComputeAND
			(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB,
			 const bool use_vrhe = true);
		
		bool MPC_ComputeOR
			(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB);
		
		bool MPC_ComputeXOR
			(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB);
		
		bool MPC_CopyBitCommitment
			(MPC_Bit &copy1, MPC_Bit &copy2, const MPC_Bit &bit,
			 const bool use_vrhe = true);
		
		bool MPC_RandomBitCommitment
			(MPC_Bit &result, const bool use_vrhe = true);
		
		~StiglicMPC
			();
};

#endif
