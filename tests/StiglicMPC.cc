/*******************************************************************************
   StiglicMPC.cc, secure |M|ulti-|P|arty |C|omputation with a deck of cards

     Anton Stiglic: 'Computations with a deck of cards', 
     Theoretical Computer Science, 259 (1-2) (2001) pp. 671-678

 Copyright (C) 2002, 2003, 2005  Heiko Stamer <stamer@gaos.org>

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
*******************************************************************************/

#include "StiglicMPC.hh"

void StiglicMPC::MPC_ProveBitCommitment
	(MPC_Bit &bit, bool b)
{
	MPC_BitSecret bs;
	size_t cyc = 0;
	do
		cyc = tmcg->TMCG_CreateStackSecret(bs, true, base.size(), vtmf);
	while ((b && (cyc == 0)) || (!b && (cyc == 1)));
	bit.clear();
	tmcg->TMCG_MixStack(base, bit, bs, vtmf);
	
	for (size_t i = 0; i < participants.size(); i++)
	{
		if (i != index)
		{
			*participants[i]->out << bit << std::endl << std::flush;
			tmcg->TMCG_ProveStackEquality(base, bit, bs, true, vtmf,
				*participants[i]->in, *participants[i]->out);
		}
	}
}

bool StiglicMPC::MPC_VerifyBitCommitment
	(MPC_Bit &bit, size_t from)
{
	*participants[from]->in >> bit;
	
	if (!participants[from]->in->good())
		return false;
	if (bit.size() != 2)
		return false;
	if (!tmcg->TMCG_VerifyStackEquality(base, bit, true, vtmf,
		*participants[from]->in, *participants[from]->out))
			return false;
	
	return true;
}

bool StiglicMPC::MPC_OpenCardCommitment
	(const VTMF_Card &card, bool &b)
{
	VTMF_CardSecret cs;
	tmcg->TMCG_SelfCardSecret(card, vtmf);
	
	for (size_t i = 0; i < participants.size(); i++)
	{
		if (i == index)
		{
			// use the non-interactiveness of the proof (only VTMF!)
			std::stringstream proof;
			tmcg->TMCG_ProveCardSecret(card, vtmf, proof, proof);
			
			for (size_t j = 0; j < participants.size(); j++)
			{
				if (j != index)
					*participants[j]->out << proof.str() << std::flush;
			}
		}
		else
		{
			if (!tmcg->TMCG_VerifyCardSecret(card, vtmf,
				*participants[i]->in, *participants[i]->out))
					return false;
		}
	}
	
	if (tmcg->TMCG_TypeOfCard(card, vtmf) == 0)
		b = false;
	else if (tmcg->TMCG_TypeOfCard(card, vtmf) == 1)
		b = true;
	else
		return false;
	
	return true;
}

bool StiglicMPC::MPC_OpenBitCommitment
	(const MPC_Bit &bit, bool &b)
{
	bool cb[2];
	if (bit.size() != 2)
		return false;
	if (!MPC_OpenCardCommitment(bit[0], cb[0]))
		return false;
	if (!MPC_OpenCardCommitment(bit[1], cb[1]))
		return false;
	
	if (!cb[0] && cb[1])
		b = false;
	else if (cb[0] && !cb[1])
		b = true;
	else
		return false;
	
	return true;
}

bool StiglicMPC::MPC_CyclicShift
	(TMCG_Stack<VTMF_Card> &result, TMCG_Stack<VTMF_Card> stack)
{
	assert(stack.size() > 0);
	
	for (size_t i = 0; i < participants.size(); i++)
	{
		TMCG_Stack<VTMF_Card> s1;
		TMCG_StackSecret<VTMF_CardSecret> cs1;
		
		if (i == index)
		{
			tmcg->TMCG_CreateStackSecret(cs1, true, stack.size(), vtmf);
			tmcg->TMCG_MixStack(stack, s1, cs1, vtmf);
			
			for (size_t j = 0; j < participants.size(); j++)
			{
				if (j != index)
				{
					*participants[j]->out << s1 << std::endl << std::flush;
					tmcg->TMCG_ProveStackEquality(stack, s1, cs1, true, vtmf,
						*participants[j]->in, *participants[j]->out);
				}
			}
		}
		else
		{
			*participants[i]->in >> s1;
			if (!participants[i]->in->good())
				return false;
			if (!tmcg->TMCG_VerifyStackEquality(stack, s1, true, vtmf,
				*participants[i]->in, *participants[i]->out))
					return false;
		}
		stack = s1;
	}
	result = stack;
	
	return true;
}

void StiglicMPC::MPC_ComputeNEG
	(MPC_Bit &result, const MPC_Bit bit)
{
	assert(bit.size() == 2);
	
	result.clear(), result.push(bit[1]), result.push(bit[0]);
}

bool StiglicMPC::MPC_ComputeAND
	(MPC_Bit &result, const MPC_Bit bitA, const MPC_Bit bitB)
{
	assert((bitA.size() == 2) && (bitB.size() == 2));
	
	TMCG_Stack<VTMF_Card> las_vegas;
	bool cb[3];
	
	// step 1. -- place the public and secret cards
	las_vegas.push(bitA), las_vegas.push(negbase);
	las_vegas.push(bitB), las_vegas.push(base);
	
	while (1)
	{
		// step 2. and 3. -- apply a cyclic shift
		if (!MPC_CyclicShift(las_vegas, las_vegas))
			return false;
		
		// step 4. -- turn over the cards
		if (!MPC_OpenCardCommitment(las_vegas[0], cb[0]))
			return false;
		if (!MPC_OpenCardCommitment(las_vegas[1], cb[1]))
			return false;
		if ((!cb[0] && cb[1]) || (cb[0] && !cb[1]))
		{
			if (!MPC_OpenCardCommitment(las_vegas[2], cb[2]))
				return false;
			if ((!cb[0] && cb[1] && cb[2]) || (cb[0] && !cb[1] && !cb[2]))
				break;
		}
		else
			break;
	};
	
	// step 5. -- choose result
	if (cb[0] && cb[1])
	{
		result.clear(), result.push(las_vegas[5]), result.push(las_vegas[6]);
	}
	else if (!cb[0] && cb[1] && cb[2])
	{
		result.clear(), result.push(las_vegas[6]), result.push(las_vegas[7]);
	}
	else if (!cb[0] && !cb[1])
	{
		result.clear(), result.push(las_vegas[3]), result.push(las_vegas[4]);
	}
	else if (cb[0] && !cb[1] && !cb[2])
	{
		result.clear(), result.push(las_vegas[4]), result.push(las_vegas[5]);
	}
	else
		return false;
	
	return true;
}

bool StiglicMPC::MPC_ComputeOR
	(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB)
{
	MPC_Bit nA, nB, nAB;
	
	MPC_ComputeNEG(nA, bitA), MPC_ComputeNEG(nB, bitB);
	if (!MPC_ComputeAND(nAB, nA, nB))
		return false;
	MPC_ComputeNEG(result, nAB);
	
	return true;
}

bool StiglicMPC::MPC_ComputeXOR
	(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB)
{
	MPC_Bit nA, nB, nAB, AnB;
	
	MPC_ComputeNEG(nA, bitA), MPC_ComputeNEG(nB, bitB);
	if (!MPC_ComputeAND(nAB, nA, bitB))
		return false;
	if (!MPC_ComputeAND(AnB, bitA, nB))
		return false;
	if (!MPC_ComputeOR(result, nAB, AnB))
		return false;
		
	return true;
}

bool StiglicMPC::MPC_CopyBitCommitment
	(MPC_Bit &copy1, MPC_Bit &copy2, const MPC_Bit &bit)
{
	assert(bit.size() == 2);
	
	TMCG_Stack<VTMF_Card> copyshop, left;
	bool cb[4];
	
	// step 1. -- create a stack with three MPC_Bit (set to true)
	copyshop.push(negbase), copyshop.push(negbase), copyshop.push(negbase);
	
	// step 2a. -- apply a cyclic shift to the six rightmost cards
	if (!MPC_CyclicShift(copyshop, copyshop))
		return false;
	
	// step 2b. -- create the necessary configuration
	left.push(bit), left.push(copyshop[0]), left.push(copyshop[1]);
	copyshop.stack.erase(copyshop.stack.begin(), copyshop.stack.begin() + 2);
	assert(copyshop.size() == 4);
	
	// step 3. -- apply a cyclic shift to the four topmost cards
	if (!MPC_CyclicShift(left, left))
		return false;
	
	// step 4. -- open the four topmost cards
	if (!MPC_OpenCardCommitment(left[0], cb[0]))
		return false;
	if (!MPC_OpenCardCommitment(left[1], cb[1]))
		return false;
	if (!MPC_OpenCardCommitment(left[2], cb[2]))
		return false;
	if (!MPC_OpenCardCommitment(left[3], cb[3]))
		return false;
	if ((cb[0] && !cb[1] && cb[2] && !cb[3]) || 
		(!cb[0] && cb[1] && !cb[2] && cb[3]))
	{
		copy1.clear(), copy1.push(copyshop[0]), copy1.push(copyshop[1]);
		copy2.clear(), copy2.push(copyshop[2]), copy2.push(copyshop[3]);
	}
	else
	{
		copy1.clear(), copy1.push(copyshop[0]), copy1.push(copyshop[1]);
		copy2.clear(), copy2.push(copyshop[2]), copy2.push(copyshop[3]);
		MPC_ComputeNEG(copy1, copy1), MPC_ComputeNEG(copy2, copy2);
	}
	
	return true;
}

bool StiglicMPC::MPC_RandomBitCommitment
	(MPC_Bit &result)
{
	result.clear(), result.push(base);
	if (!MPC_CyclicShift(result, result))
		return false;
	return true;
}
