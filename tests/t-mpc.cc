/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2009,
               2015, 2016, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

#ifdef FORKING

#include <exception>
#include <sstream>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include "StiglicMPC.hh"
#include "pipestream.hh"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
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
		try
		{
			/* BEGIN child code: participant B */
			mpc = new StiglicMPC(64, list, 1);
		
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
			mpc->MPC_ComputeAND(result, a, a, false);
			mpc->MPC_OpenBitCommitment(result, x);
			mpc->MPC_ComputeAND(result, a, b, false);
			mpc->MPC_OpenBitCommitment(result, x);
			mpc->MPC_ComputeAND(result, b, a, false);
			mpc->MPC_OpenBitCommitment(result, x);
			mpc->MPC_ComputeAND(result, b, b, false);
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
			catch (std::exception& e)
			{
				std::cerr << "exception catched with what = " << e.what() <<
					std::endl;
				exit(-1);
			}
	}
	else
	{
		std::cout << "fork() = " << pid << std::endl;
		try
		{
			/* Participant A */
			mpc = new StiglicMPC(64, list, 0);
		
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
		
			std::cout << "ComputeAND (without VRHE)" << std::endl;
			start_clock();
			assert(mpc->MPC_ComputeAND(result, a, a, false));
			assert(mpc->MPC_OpenBitCommitment(result, x));
			assert(x == true);
			assert(mpc->MPC_ComputeAND(result, a, b, false));
			assert(mpc->MPC_OpenBitCommitment(result, x));
			assert(x == false);
			assert(mpc->MPC_ComputeAND(result, b, a, false));
			assert(mpc->MPC_OpenBitCommitment(result, x));
			assert(x == false);
			assert(mpc->MPC_ComputeAND(result, b, b, false));
			assert(mpc->MPC_OpenBitCommitment(result, x));
			assert(x == false);
			stop_clock();
			std::cout << elapsed_time() << std::endl;

			std::cout << "ComputeAND" << std::endl;
			start_clock();
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
			stop_clock();
			std::cout << elapsed_time() << std::endl;
		
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
		catch (std::exception& e)
		{
			std::cerr << "exception catched with what = " << e.what() <<
				std::endl;
			return -1;
		}
	}
	
	// finalize
	int wstatus = 0;
	std::cerr << "waitpid(" << pid << ")" << std::endl;
	if (waitpid(pid, &wstatus, 0) != pid)
		perror("t-mpc (waitpid)");
	if (!WIFEXITED(wstatus))
	{
		std::cerr << "ERROR: ";
		if (WIFSIGNALED(wstatus))
			std::cerr << pid << " terminated by signal " <<
				WTERMSIG(wstatus) << std::endl;
		if (WCOREDUMP(wstatus))
			std::cerr << pid << " dumped core" << std::endl;
	}
	list.clear();
	delete A, delete B;
	
	delete pipe_in_A, delete pipe_out_A, delete pipe_in_B, delete pipe_out_B;
	close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);
}

#else

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	std::cout << "test skipped" << std::endl;
	return 77;
}

#endif

