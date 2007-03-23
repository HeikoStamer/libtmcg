/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006  Heiko Stamer <stamer@gaos.org>

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

#include <sstream>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include <libTMCG.hh>
#include "StiglicMPC.hh"
#include "pipestream.hh"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());
	
	pid_t pid = 0;
	int pipe1fd[2], pipe2fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
	{
		perror("t-mpc (pipe)");
		return -1;
	}
	
	ipipestream *pipe_in_A = new ipipestream(pipe1fd[0]);
	opipestream *pipe_out_A = new opipestream(pipe2fd[1]);
	ipipestream *pipe_in_B = new ipipestream(pipe2fd[0]);
	opipestream *pipe_out_B = new opipestream(pipe1fd[1]);
	
	StiglicMPC *mpc;
	MPC_ParticipantList list;
	MPC_Participant *A = new MPC_Participant(pipe_in_A, pipe_out_A);
	MPC_Participant *B = new MPC_Participant(pipe_in_B, pipe_out_B);
	list.push_back(A), list.push_back(B);
	
	if ((pid = fork()) < 0)
	{
		perror("t-mpc (fork)");
		return -1;
	}
	
	if (pid == 0)
	{
		/* BEGIN child code: participant B */
		mpc = new StiglicMPC(16, list, 1);
		
		MPC_Bit a, b, c, result;
		bool x = false, y = false, z = false;
		mpc->MPC_ProveBitCommitment(a, true);
		mpc->MPC_ProveBitCommitment(b, false);
		mpc->MPC_ProveBitCommitment(c, true);
		mpc->MPC_OpenBitCommitment(a, x);
		mpc->MPC_OpenBitCommitment(b, y);
		mpc->MPC_OpenBitCommitment(c, z);
		mpc->MPC_CopyBitCommitment(result, c, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_OpenBitCommitment(c, y);
		mpc->MPC_CopyBitCommitment(result, c, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_OpenBitCommitment(c, y);
		do
		{
			mpc->MPC_RandomBitCommitment(result);
			mpc->MPC_OpenBitCommitment(result, x);
		}
		while (x);
		do
		{
			mpc->MPC_RandomBitCommitment(result);
			mpc->MPC_OpenBitCommitment(result, x);
		}
		while (!x);
		mpc->MPC_ComputeNEG(result, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeNEG(result, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeAND(result, a, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeAND(result, a, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeAND(result, b, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeAND(result, b, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeOR(result, a, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeOR(result, a, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeOR(result, b, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeOR(result, b, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeXOR(result, a, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeXOR(result, a, b);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeXOR(result, b, a);
		mpc->MPC_OpenBitCommitment(result, x);
		mpc->MPC_ComputeXOR(result, b, b);
		mpc->MPC_OpenBitCommitment(result, x);
		
		delete mpc;
		exit(0);
		/* END child code: participant B */
	}
	else
	{
		std::cout << "fork() = " << pid << std::endl;
		/* Participant A */
		mpc = new StiglicMPC(16, list, 0);
		
		MPC_Bit a, b, c, result;
		bool x = false, y = false, z = false;
		size_t i = 0;
		
		std::cout << "BitCommitment" << std::endl;
		assert(mpc->MPC_VerifyBitCommitment(a, 1));
		assert(mpc->MPC_VerifyBitCommitment(b, 1));
		assert(mpc->MPC_VerifyBitCommitment(c, 1));
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
	
	// finalize
	if (waitpid(pid, NULL, 0) != pid)
		perror("t-mpc (waitpid)");
	
	list.clear();
	delete A, delete B;
	
	delete pipe_in_A, delete pipe_out_A, delete pipe_in_B, delete pipe_out_B;
	close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);
}
