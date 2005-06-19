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
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	try
	{
		(*participants[from]->in).getline(tmp, TMCG_MAX_STACK_CHARS);
		if (!bit.import(tmp))
			throw false;
		if (bit.size() != 2)
			throw false;
		if (!tmcg->TMCG_VerifyStackEquality(base, bit, true, vtmf,
			*participants[from]->in, *participants[from]->out))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		delete [] tmp;
		return return_value;
	}
}

bool StiglicMPC::MPC_OpenCardCommitment
	(const VTMF_Card &card, bool &b)
{
	try
	{
		VTMF_CardSecret cs;
		tmcg->TMCG_SelfCardSecret(card, vtmf);
		for (size_t i = 0; i < participants.size(); i++)
		{
			if (i == index)
			{
				for (size_t j = 0; j < participants.size(); j++)
				{
					if (j != index)
					{
						tmcg->TMCG_ProveCardSecret(card, vtmf,
							*participants[j]->in, *participants[j]->out);
					}
				}
			}
			else
			{
				if (!tmcg->TMCG_VerifyCardSecret(card, vtmf,
					*participants[i]->in, *participants[i]->out))
						throw false;
			}
		}
		
		if (tmcg->TMCG_TypeOfCard(card, vtmf) == 0)
			b = false;
		else if (tmcg->TMCG_TypeOfCard(card, vtmf) == 1)
			b = true;
		else
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
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

void StiglicMPC::MPC_ComputeNEG
	(MPC_Bit &result, const MPC_Bit &bit)
{
	assert(bit.size() == 2);
	
	result.clear(), result.push(bit[1]), result.push(bit[0]);
}

bool StiglicMPC::MPC_ComputeAND
	(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB)
{
	assert((bitA.size() == 2) && (bitB.size() == 2));
	
	TMCG_Stack<VTMF_Card> las_vegas1, las_vegas2;
	TMCG_StackSecret<VTMF_CardSecret> bs;
	bool cb[2];
	
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	try
	{
		// step 1. -- place the public and secret cards
		las_vegas1.push(bitA), las_vegas1.push(negbase);
		las_vegas1.push(bitB), las_vegas1.push(base);
		
		while (1)
		{
			// step 2. and 3. -- apply a cyclic shuffling
			for (size_t i = 0; i < participants.size(); i++)
			{
				if (i == index)
				{
					tmcg->TMCG_CreateStackSecret(bs, true, las_vegas1.size(), vtmf);
					tmcg->TMCG_MixStack(las_vegas1, las_vegas2, bs, vtmf);
						
					for (size_t j = 0; j < participants.size(); j++)
					{
						if (j != index)
						{
							*participants[j]->out << las_vegas2 << std::endl << std::flush;
							tmcg->TMCG_ProveStackEquality(las_vegas1, las_vegas2, bs,
								true,	vtmf, *participants[j]->in, *participants[j]->out);
						}
					}
				}
				else
				{
					(*participants[i]->in).getline(tmp, TMCG_MAX_STACK_CHARS);
					if (!las_vegas2.import(tmp))
						throw false;
					if (!tmcg->TMCG_VerifyStackEquality(las_vegas1, las_vegas2,
						true, vtmf,	*participants[i]->in, *participants[i]->out))
							throw false;
				}
				las_vegas1 = las_vegas2;
			}
			
			// step 4. -- turn over cards
			if (!MPC_OpenCardCommitment(las_vegas1[0], cb[0]))
				throw false;
			if (!MPC_OpenCardCommitment(las_vegas1[1], cb[1]))
				throw false;
			if ((!cb[0] && cb[1]) || (cb[0] && !cb[1]))
			{
				if (!MPC_OpenCardCommitment(las_vegas1[2], cb[2]))
					throw false;
				if ((!cb[0] && cb[1] && cb[2]) || (cb[0] && !cb[1] && !cb[2]))
					break;
			}
			else
				break;
		};
		
		// step 5. -- choose result
		if (cb[0] && cb[1])
		{
			result.clear(), result.push(las_vegas1[5]), result.push(las_vegas1[6]);
		}
		else if (!cb[0] && cb[1] && cb[2])
		{
			result.clear(), result.push(las_vegas1[6]), result.push(las_vegas1[7]);
		}
		else if (!cb[0] && !cb[1])
		{
			result.clear(), result.push(las_vegas1[3]), result.push(las_vegas1[4]);
		}
		else if (cb[0] && !cb[1] && !cb[2])
		{
			result.clear(), result.push(las_vegas1[4]), result.push(las_vegas1[5]);
		}
		else
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		delete [] tmp;
		return return_value;
	}	
}

bool StiglicMPC::MPC_ComputeOR
	(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB)
{
	MPC_Bit nA, nB, nAB;
	try
	{
		MPC_ComputeNEG(nA, bitA), MPC_ComputeNEG(nB, bitB);
		if (!MPC_ComputeAND(nAB, nA, nB))
			throw false;
		MPC_ComputeNEG(result, nAB);
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool StiglicMPC::MPC_ComputeXOR
	(MPC_Bit &result, const MPC_Bit &bitA, const MPC_Bit &bitB)
{
	MPC_Bit nA, nB, nAB, AnB;
	try
	{
		MPC_ComputeNEG(nA, bitA), MPC_ComputeNEG(nB, bitB);
		if (!MPC_ComputeAND(nAB, nA, bitB))
			throw false;
		if (!MPC_ComputeAND(AnB, bitA, nB))
			throw false;
		if (!MPC_ComputeOR(result, nAB, AnB))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}
