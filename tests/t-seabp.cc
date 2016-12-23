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
#include <aiounicast_fd.hh>

#ifdef FORKING

#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "test_helper.h"

#undef NDEBUG
#define N 7
#define T 2

int broadcast_pipefd[N][N][2];
pid_t pid[N];

void start_instance
	(size_t whoami, bool corrupted, bool someone_corrupted)
{
	if ((pid[whoami] = fork()) < 0)
		perror("t-seabp (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			
			// create pipe streams and handles between all players
			std::vector<int> bP_in, bP_out;
			std::vector<std::string> bP_key;
			for (size_t i = 0; i < N; i++)
			{
				std::stringstream key;
				key << "t-seabp::P_" << (i + whoami);
				bP_in.push_back(broadcast_pipefd[i][whoami][0]);
				bP_out.push_back(broadcast_pipefd[whoami][i][1]);
				bP_key.push_back(key.str());
			}	

			// create asynchronous authenticated broadcast channels
			aiounicast_fd *aiou = new aiounicast_fd(N, whoami, bP_in, bP_out, bP_key);
			
			// create an instance of a reliable broadcast protocol (RBC)
			std::string myID = "t-seabp";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou);
			rbc->setID(myID);
			
			// broadcast
			mpz_t a;
			mpz_init_set_ui(a, whoami);
			rbc->Broadcast(a, corrupted);

			// deliver
			start_clock();
			std::cout << "P_" << whoami << ": rbc.DeliverFrom()" << std::endl;
			for (size_t i = 0; i < N; i++)
			{
				if (someone_corrupted)
				{
					if (rbc->DeliverFrom(a, i))
					{
						std::cout << "P_" << whoami << ": a = " << a << " from " << i << std::endl;
						assert(!mpz_cmp_ui(a, i));
					}					
				}
				else
				{
					assert(rbc->DeliverFrom(a, i));
					assert(!mpz_cmp_ui(a, i));
				}
			}
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;

			// at the end: deliver one more round for waiting parties
			assert(!rbc->DeliverFrom(a, whoami));
			mpz_clear(a);
			
			// release RBC			
			delete rbc;

			// release handles (broadcast channel)
			bP_in.clear(), bP_out.clear(), bP_key.clear();
			std::cout << "P_" << whoami << ": aiou.numRead = " << aiou->numRead <<
				" aiou.numWrite = " << aiou->numWrite << std::endl;

			// release asynchronous broadcast
			delete aiou;
			
			std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
		}
		else
			std::cout << "fork() = " << pid[whoami] << std::endl;
	}
}

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());
	
	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("t-seabp (pipe)");
		}
	}
	
	// start childs (all correct)
	for (size_t i = 0; i < N; i++)
		start_instance(i, false, false);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < N; i++)
	{
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("t-seabp (waitpid)");
		for (size_t j = 0; j < N; j++)
		{
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("t-seabp (close)");
		}
	}

	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("t-seabp (pipe)");
		}
	}
	
	// start childs (two corrupted parties)
	for (size_t i = 0; i < N; i++)
	{
		if ((i == (N - 1)) || (i == (N - 2)))
			start_instance(i, true, true); // corrupted instance
		else
			start_instance(i, false, true); // someone corrupted
	}
	
	// wait for childs and close pipes
	for (size_t i = 0; i < N; i++)
	{
		int wstatus = 0;
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], &wstatus, 0) != pid[i])
			perror("t-seabp (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " << WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
		}
		for (size_t j = 0; j < N; j++)
		{
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("t-seabp (close)");
		}
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
