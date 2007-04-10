/******************************************************************************
   StiglicMPC.hh, secure |M|ulti-|P|arty |C|omputation with a deck of cards

     Anton Stiglic: 'Computations with a deck of cards', 
     Theoretical Computer Science, 259 (1-2) (2001) pp. 671-678

 Copyright (C) 2002, 2003, 2005, 2007  Heiko Stamer <stamer@gaos.org>

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

typedef std::vector<MPC_Participant*>				MPC_ParticipantList;
typedef TMCG_Stack<VTMF_Card>								MPC_Bit;
typedef TMCG_StackSecret<VTMF_CardSecret>		MPC_BitSecret;

class StiglicMPC
{
	private:
		SchindelhauerTMCG				*tmcg;
		BarnettSmartVTMF_dlog		*vtmf;
		MPC_ParticipantList			participants;
		size_t									index;
		MPC_Bit									base, negbase;
	
	public:
	
		StiglicMPC
			(size_t security, MPC_ParticipantList plist, size_t pindex):
				participants(plist), index(pindex)
		{
			if (participants.size() < 1)
			{
				std::cerr << "At least one participant necessary" << std::endl;
				exit(-1);
			}
			tmcg = new SchindelhauerTMCG(security, participants.size(), 1);
			
			// create an instance of the VTMF implementation (create the group G)
			if (index)
			{
				vtmf = new BarnettSmartVTMF_dlog(*participants[0]->in);
			}
			else
			{
				vtmf = new BarnettSmartVTMF_dlog();
				// broadcast the parameters of the group
				for (size_t i = 0; i < participants.size(); i++)
				{
					if (i != index)
						vtmf->PublishGroup(*participants[i]->out);
				}
			}
			// check whether the group G was correctly generated
			if (!vtmf->CheckGroup())
			{
				std::cerr << "Check of Group G failed" << std::endl;
				exit(-1);
			}
			// create and broadcast the (public) key
			vtmf->KeyGenerationProtocol_GenerateKey();
			for (size_t i = 0; i < participants.size(); i++)
			{
				if (i != index)
					vtmf->KeyGenerationProtocol_PublishKey(*participants[i]->out);
			}
			// receive the public keys and update the instance
			for (size_t i = 0; i < participants.size(); i++)
			{
				if (i != index)
				{
					if (!vtmf->KeyGenerationProtocol_UpdateKey(*participants[i]->in))
					{
						std::cerr << "Proof of key from " << i << " failed" << std::endl;
						exit(-1);
					}
				}
			}
			// finish the key generation
			vtmf->KeyGenerationProtocol_Finalize();
			
			// initialize the base stacks with open cards
			VTMF_Card c[2];
			tmcg->TMCG_CreateOpenCard(c[0], vtmf, 0);
			tmcg->TMCG_CreateOpenCard(c[1], vtmf, 1);
			base.push(c[0]), base.push(c[1]);
			negbase.push(c[1]), negbase.push(c[0]);
		}
		
		void MPC_ProveBitCommitment
			(MPC_Bit &bit, bool b);
		
		bool MPC_VerifyBitCommitment
			(MPC_Bit &bit, size_t from);
		
		bool MPC_OpenCardCommitment
			(const VTMF_Card &card, bool &b);
		
		bool MPC_OpenBitCommitment
			(const MPC_Bit &bit, bool &b);
		
		bool MPC_CyclicShift
			(TMCG_Stack<VTMF_Card> &result, TMCG_Stack<VTMF_Card> stack);
		
		void MPC_ComputeNEG
			(MPC_Bit &result, const MPC_Bit bit);
		
		bool MPC_ComputeAND
			(MPC_Bit &result, const MPC_Bit bitA, const MPC_Bit bitB);
		
		bool MPC_ComputeOR
			(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB);
		
		bool MPC_ComputeXOR
			(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB);
		
		bool MPC_CopyBitCommitment
			(MPC_Bit &copy1, MPC_Bit &copy2, const MPC_Bit &bit);
		
		bool MPC_RandomBitCommitment
			(MPC_Bit &result);
		
		~StiglicMPC
			()
		{
			delete tmcg, delete vtmf;
		}
};

#endif
