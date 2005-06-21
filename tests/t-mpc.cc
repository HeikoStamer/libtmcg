/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#include <sstream>
#include <cassert>

#include <libTMCG.hh>
#include "StiglicMPC.hh"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());
	
	StiglicMPC *mpc;
	MPC_ParticipantList list;
	MPC_Participant *A = new MPC_Participant(&std::cin, &std::cout);
	list.push_back(A);
	
	mpc = new StiglicMPC(16, list, 0);
	
	MPC_Bit a, b, c, result;
	bool x, y, z;
	size_t i = 0;
	
	std::cout << "BitCommitment" << std::endl;
	mpc->MPC_ProveBitCommitment(a, true);
	mpc->MPC_ProveBitCommitment(b, false);
	mpc->MPC_ProveBitCommitment(c, true);
	std::cout << a << std::endl << b << std::endl << c << std::endl;
	assert((a != b) && (b != c) && (a != c));
	assert(mpc->MPC_OpenBitCommitment(a, x));
	assert(mpc->MPC_OpenBitCommitment(b, y));
	assert(mpc->MPC_OpenBitCommitment(c, z));
	std::cout << x << std::endl << y << std::endl << z << std::endl;
	assert((x == true) && (y == false) && (z == true));
	
	std::cout << "CopyBitCommitment" << std::endl;
	assert(mpc->MPC_CopyBitCommitment(result, c, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(mpc->MPC_OpenBitCommitment(c, y));
	assert((x == y) && (y == true));
	assert(mpc->MPC_CopyBitCommitment(result, c, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(mpc->MPC_OpenBitCommitment(c, y));
	assert((x == y) && (y == false));
	
	std::cout << "RandomBitCommitment" << std::endl;
	do
	{
		assert(mpc->MPC_RandomBitCommitment(result));
		assert(mpc->MPC_OpenBitCommitment(result, x));
		std::cout << x << std::endl;
	}
	while (x && (++i < 80));
	assert(i < 80);
	i = 0;
	do
	{
		assert(mpc->MPC_RandomBitCommitment(result));
		assert(mpc->MPC_OpenBitCommitment(result, x));
		std::cout << x << std::endl;
	}
	while (!x && (++i < 80));
	assert(i < 80);
	
	std::cout << "ComputeNEG" << std::endl;
	mpc->MPC_ComputeNEG(result, a);
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	mpc->MPC_ComputeNEG(result, b);
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	
	std::cout << "ComputeAND" << std::endl;
	assert(mpc->MPC_ComputeAND(result, a, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeAND(result, a, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	assert(mpc->MPC_ComputeAND(result, b, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	assert(mpc->MPC_ComputeAND(result, b, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	
	std::cout << "ComputeOR" << std::endl;
	assert(mpc->MPC_ComputeOR(result, a, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeOR(result, a, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeOR(result, b, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeOR(result, b, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	
	std::cout << "ComputeXOR" << std::endl;
	assert(mpc->MPC_ComputeXOR(result, a, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	assert(mpc->MPC_ComputeXOR(result, a, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeXOR(result, b, a));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == true);
	assert(mpc->MPC_ComputeXOR(result, b, b));
	assert(mpc->MPC_OpenBitCommitment(result, x));
	assert(x == false);
	
	delete mpc;
}
