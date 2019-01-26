/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include <aiounicast_select.hh>

#ifdef FORKING

#include <exception>
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
#define N_MIN 2
#define N 7
#define T 2

int broadcast_pipefd[N][N][2];
pid_t pid[N];

void start_instance
	(size_t n, size_t t, size_t whoami, bool corrupted, bool someone_corrupted)
{
	if ((pid[whoami] = fork()) < 0)
	{
		perror("t-seabp (fork)");
		return;
	}
	if (pid[whoami] != 0)
	{
		std::cout << "fork() = " << pid[whoami] << std::endl;
		return;
	}
	try
	{
		/* BEGIN child code: participant P_i */
			
		// create pipe streams and handles between all players
		std::vector<int> bP_in, bP_out;
		std::vector<std::string> bP_key;
		for (size_t i = 0; i < n; i++)
		{
			std::stringstream key;
			key << "t-seabp::P_" << (i + whoami);
			bP_in.push_back(broadcast_pipefd[i][whoami][0]);
			bP_out.push_back(broadcast_pipefd[whoami][i][1]);
			bP_key.push_back(key.str());
		}	

		// create asynchronous authenticated broadcast channels
		aiounicast_select *aiou = new aiounicast_select(n, whoami,
			bP_in, bP_out, bP_key,
			aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
			
		// create an instance of a reliable broadcast protocol (RBC)
		std::string myID = "t-seabp";
		CachinKursawePetzoldShoupRBC *rbc =	new CachinKursawePetzoldShoupRBC(n,
			t, whoami, aiou,
			aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
		rbc->setID(myID);
			
		// round 1 -- broadcast
		mpz_t a;
		mpz_init_set_ui(a, whoami);
		rbc->Broadcast(a, corrupted);

		// round 1 -- deliver
		start_clock();
		std::cout << "P_" << whoami << ": rbc.DeliverFrom()" << std::endl;
		for (size_t i = 0; i < n; i++)
		{
			if (someone_corrupted)
			{
				if (rbc->DeliverFrom(a, i))
				{
					std::cout << "P_" << whoami << ": a = " << a << " from " <<
						i << std::endl;
					if (i < (n - t))
						assert(!mpz_cmp_ui(a, i));
					else if (mpz_cmp_ui(a, i))
						std::cout << "P_" << whoami << ": got wrong value" <<
							" from " << i << std::endl;
				}
				else
				{
					std::cout << "P_" << whoami << ": got nothing from " <<	
						i << std::endl;
					assert(i >= (n - t));
				}
			}
			else
			{
				assert(rbc->DeliverFrom(a, i));
				assert(!mpz_cmp_ui(a, i));
			}
		}
		stop_clock();
		mpz_clear(a);
		std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;

		// switch to subprotocol
		myID = "t-seabp::subprotocol";
		rbc->setID(myID);
			
		// round 1a -- broadcast again
		mpz_init_set_ui(a, whoami);
		rbc->Broadcast(a, corrupted);

		// round 1a -- deliver again
		start_clock();
		std::cout << "P_" << whoami << ": rbc.DeliverFrom() inside" <<
			" subprotocol" << std::endl;
		for (size_t i = 0; i < n; i++)
		{
			if (someone_corrupted)
			{
				if (rbc->DeliverFrom(a, i))
				{
					std::cout << "P_" << whoami << ": a = " << a << " from " <<
						i << " inside subprotocol" << std::endl;
					if (i < (n - t))
						assert(!mpz_cmp_ui(a, i));
					else if (mpz_cmp_ui(a, i))
						std::cout << "P_" << whoami << ": got wrong value" <<
							" from " << i << std::endl;
				}
				else
				{
					std::cout << "P_" << whoami << ": got nothing from " <<
						i << " inside subprotocol" << std::endl;
					assert(i >= (n - t));
				}
			}
			else
			{
				assert(rbc->DeliverFrom(a, i));
				assert(!mpz_cmp_ui(a, i));
			}
		}
		stop_clock();
		mpz_clear(a);
		std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;

		// round 1b -- broadcast again
		mpz_init_set_ui(a, 42 * whoami);
		rbc->Broadcast(a, corrupted);

		// switch to further subprotocol
		myID = "t-seabp::subprotocol::subprotocol";
		rbc->setID(myID);

		// round 1b(i) -- deliver nothing
		std::cout << "P_" << whoami << ": !rbc.DeliverFrom() inside further" <<
			" subprotocol" << std::endl;
		for (size_t i = 0; i < n; i++)
		{
			if (someone_corrupted)
			{
				if (rbc->DeliverFrom(a, i))
				{
					std::cout << "P_" << whoami << ": a = " << a << " from " <<
						i << " inside further subprotocol" << std::endl;
					assert(i >= (n - t));
				}
			}
			else
				assert(!rbc->DeliverFrom(a, i));
		}

		// switch back to subprotocol
		rbc->unsetID();

		// round 1b -- deliver again
		start_clock();
		std::cout << "P_" << whoami << ": rbc.DeliverFrom() inside" <<
			" subprotocol" << std::endl;
		for (size_t i = 0; i < n; i++)
		{
			if (someone_corrupted)
			{
				if (rbc->DeliverFrom(a, i))
				{
					std::cout << "P_" << whoami << ": a = " << a << " from " <<
						i << " inside subprotocol" << std::endl;
					if (i < (n - t))
						assert(!mpz_cmp_ui(a, 42 * i));
					else if (mpz_cmp_ui(a, 42 * i))
						std::cout << "P_" << whoami << ": got wrong value" <<
							" from " << i << std::endl;
				}
				else
				{
					std::cout << "P_" << whoami << ": got nothing from " <<
						i << " inside subprotocol" << std::endl;
					assert(i >= (n - t));
				}
			}
			else
			{
				assert(rbc->DeliverFrom(a, i));
				assert(!mpz_cmp_ui(a, 42 * i));
			}
		}
		stop_clock();
		mpz_clear(a);
		std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;

		// switch back to main protocol
		rbc->unsetID();
			
		// round 2 -- broadcast again
		mpz_init_set_ui(a, whoami);
		rbc->Broadcast(a, corrupted);

		// round 2 -- deliver again
		start_clock();
		std::cout << "P_" << whoami << ": rbc.DeliverFrom()" << std::endl;
		for (size_t i = 0; i < n; i++)
		{
			if (someone_corrupted)
			{
				if (rbc->DeliverFrom(a, i))
				{
					std::cout << "P_" << whoami << ": a = " << a << " from " <<
						i << std::endl;
					if (i < (n - t))
						assert(!mpz_cmp_ui(a, i));
					else if (mpz_cmp_ui(a, i))
						std::cout << "P_" << whoami << ": got wrong value" <<
							" from " << i << std::endl;
				}
				else
				{
					std::cout << "P_" << whoami << ": got nothing from " <<
						i << std::endl;
					assert(i >= (n - t));
				}
			}
			else
			{
				assert(rbc->DeliverFrom(a, i));
				assert(!mpz_cmp_ui(a, i));
			}
		}
		stop_clock();
		mpz_clear(a);
		std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			
		// at the end: test sync for waiting parties
		std::cout << "P_" << whoami << ": sleeping " << whoami <<
			" seconds ..." << std::endl;
		sleep(whoami);
		std::cout << "P_" << whoami << ": synchronizing ..." << std::endl;
		if (!corrupted)
			assert(rbc->Sync());
		else
			rbc->Sync();
			
		// release RBC			
		delete rbc;

		// release handles and asynchronous broadcast channels
		bP_in.clear(), bP_out.clear(), bP_key.clear();
		aiou->PrintStatistics(std::cout);
		delete aiou;
			
		std::cout << "P_" << whoami << ": exit(0)" << std::endl;
		exit(0);
		/* END child code: participant P_i */
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() << std::endl;
		exit(-1);
	}
}

void init
	(size_t num)
{
	// open pipes
	for (size_t i = 0; i < num; i++)
	{
		for (size_t j = 0; j < num; j++)
		{
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("t-seabp (pipe)");
		}
	}
}

bool done
	(size_t num)
{
	// wait for childs and close pipes
	bool result = true;
	for (size_t i = 0; i < num; i++)
	{
		int wstatus = 0;
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], &wstatus, 0) != pid[i])
			perror("t-seabp (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus))
			{
				std::cerr << pid[i] << " terminated by signal " <<
					WTERMSIG(wstatus) << std::endl;
			}
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			result = false;
		}
		for (size_t j = 0; j < num; j++)
		{
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("t-seabp (close)");
			}
		}
	}
	return result;
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());
	assert(N_MIN <= N);

	// test case #1: n = N_MIN, t = 0
	std::cout << "test case #1" << std::endl;
	init(N_MIN);
	for (size_t i = 0; i < N_MIN; i++)
		start_instance(N_MIN, 0, i, false, false);
	if (!done(N_MIN))
		return 1;

	// test case #2: n = 3, t = 0
	std::cout << "test case #2" << std::endl;
	init(3);
	for (size_t i = 0; i < 3; i++)
		start_instance(3, 0, i, false, false);
	if (!done(3))
		return 1;
	
	// test case #3: all correct
	std::cout << "test case #3" << std::endl;
	init(N);
	for (size_t i = 0; i < N; i++)
		start_instance(N, T, i, false, false);
	if (!done(N))
		return 1;
		
	// test case #4: two corrupted parties
	std::cout << "test case #4" << std::endl;
	init(N);
	for (size_t i = 0; i < N; i++)
	{
		if ((i == (N - 1)) || (i == (N - 2)))
			start_instance(N, T, i, true, true); // corrupted instance
		else
			start_instance(N, T, i, false, true); // someone corrupted
	}
	if (!done(N))
		return 1;
	
	return 0;
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

