/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

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

#include <sstream>
#include <vector>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include "pipestream.hh"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());
	
	size_t N = 32;	
	pid_t pid = 0;
	int pipe1fd[2], pipe2fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
		perror("t-eotp (pipe)");
	else if ((pid = fork()) < 0)
		perror("t-eotp (fork)");
	else
	{
		if (pid == 0)
		{
			// BEGIN child code: Sender
			ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
			opipestream *pipe_out = new opipestream(pipe2fd[1]);
			std::vector<mpz_ptr> M;
			
			// create the public messages
			for (size_t i = 0; i < N; i++)
			{
				mpz_ptr tmp = new mpz_t();
				mpz_init_set_ui(tmp, i);
				M.push_back(tmp);
			}
			
			// initialize EOTP
			NaorPinkasEOTP *eotp = new NaorPinkasEOTP(*pipe_in);	
			assert(eotp->CheckGroup());

			// start (1-out-of-2) oblivious transfer protocol
			start_clock();
			std::cout << "S: eotp.Send_interactive_OneOutOfTwo(...)" << std::endl;
			assert(eotp->Send_interactive_OneOutOfTwo(M[0], M[1], *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;

			// start (1-out-of-N) oblivious transfer protocol
			start_clock();
			std::cout << "S: eotp.Send_interactive_OneOutOfN(...)" << std::endl;
			assert(eotp->Send_interactive_OneOutOfN(M, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;

			// start optimized (1-out-of-N) oblivious transfer protocol
			start_clock();
			std::cout << "S: eotp.Send_interactive_OneOutOfN_optimized(...)" << std::endl;
			assert(eotp->Send_interactive_OneOutOfN_optimized(M, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;
			
			// release
			for (size_t i = 0; i < N; i++)
			{
				mpz_clear(M[i]);
				delete M[i];
			}
			M.clear();
			delete eotp;
			
			delete pipe_in, delete pipe_out;
			exit(0);
			// END child code: Prover
		}
		else
		{
			std::cout << "fork() = " << pid << std::endl;
			// Receiver
			ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
			opipestream *pipe_out = new opipestream(pipe1fd[1]);
			mpz_t M;
			mpz_init_set_ui(M, 0L);
			
			// initialize EOTP
			NaorPinkasEOTP *eotp = new NaorPinkasEOTP();
			eotp->PublishGroup(*pipe_out);

			// start (1-out-of-2) oblivious transfer protocol
			size_t sigma = mpz_srandom_mod(2);
			std::cout << "sigma = " << sigma << std::endl;
			start_clock();
			std::cout << "R: eotp.Choose_interactive_OneOutOfTwo(...)" << std::endl;
			assert(eotp->Choose_interactive_OneOutOfTwo(sigma, M, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			std::cout << "M = " << M << std::endl;
			assert(!mpz_cmp_ui(M, sigma));

			// start (1-out-of-N) oblivious transfer protocol
			sigma = mpz_srandom_mod(N);
			std::cout << "sigma = " << sigma << std::endl;
			start_clock();
			std::cout << "R: eotp.Choose_interactive_OneOutOfN(...)" << std::endl;
			assert(eotp->Choose_interactive_OneOutOfN(sigma, N, M, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			std::cout << "M = " << M << std::endl;
			assert(!mpz_cmp_ui(M, sigma));

			// start optimized (1-out-of-N) oblivious transfer protocol
			sigma = mpz_srandom_mod(N);
			std::cout << "sigma = " << sigma << std::endl;
			start_clock();
			std::cout << "R: eotp.Choose_interactive_OneOutOfN_optimized(...)" << std::endl;
			assert(eotp->Choose_interactive_OneOutOfN_optimized(sigma, N, M, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			std::cout << "M = " << M << std::endl;
			assert(!mpz_cmp_ui(M, sigma));

			// release
			delete eotp;
			
			delete pipe_in, delete pipe_out;
		}
		if (waitpid(pid, NULL, 0) != pid)
			perror("t-eotp (waitpid)");
		close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);
	}

	return 0;
}

#else

int main
	(int argc, char **argv)
{
	std::cout << "test skipped" << std::endl;
	return 77;
}

#endif
