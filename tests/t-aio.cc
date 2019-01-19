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
#include <aiounicast_nonblock.hh>
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
#define N 11
#define T 3
#define K 10

int pipefd[N][N][2];
pid_t pid[N];

void start_instance_nonblock
	(const size_t whoami, const bool corrupted, const bool authenticated,
	 const bool encrypted)
{
	if ((pid[whoami] = fork()) < 0)
		perror("t-aio (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			try
			{
				/* BEGIN child code: participant P_i */
			
				// create keys and handles between all players
				std::vector<int> uP_in, uP_out;
				std::vector<std::string> uP_key;
				for (size_t i = 0; i < N; i++)
				{
					std::stringstream key;
					key << "t-aio::P_" << (i + whoami);
					uP_in.push_back(pipefd[i][whoami][0]);
					uP_out.push_back(pipefd[whoami][i][1]);
					uP_key.push_back(key.str());
				}

				// create asynchronous authenticated and encrypted unicast channels
				aiounicast_nonblock *aiou = new aiounicast_nonblock(N, whoami,
					uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin,
					aiounicast::aio_timeout_short, authenticated, encrypted);

				// send a simple message
				bool ret = false;
				std::vector<size_t> froms;
				std::vector<size_t>::iterator ipos;
				mpz_t m;
				mpz_init_set_ui(m, whoami);
				for (size_t i = 0; i < N; i++)
				{
					if (!corrupted)
					{
						ret = aiou->Send(m, i);
						assert(ret);
					}
					froms.push_back(i);
				}
				// receive messages from parties
				for (size_t i = 0; i < N; i++)
				{
					ret = aiou->Receive(m, i, aiounicast::aio_scheduler_direct);
					if (ret)
					{
						assert(!mpz_cmp_ui(m, i)); // data should be always correct
						ipos = std::find(froms.begin(), froms.end(), i);
						if (ipos != froms.end())
							froms.erase(ipos);
						else
							std::cout << "P_" << whoami <<
								": entry not found for " << i << std::endl;
					}
					else
						std::cout << "P_" << whoami <<
							": timeout of " << i << std::endl;
				}
				assert(froms.size() <= T); // at most T messages not received
				for (size_t i = 0; i < froms.size(); i++)
				{
					assert(froms[i] < T); // only corrupted parties should fail
				}
				// send array of K big random numbers
				std::vector<mpz_ptr> mm;
				for (size_t k = 0; k < K; k++)
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init(tmp);
					mm.push_back(tmp);
				}
				for (size_t i = 0; i < N; i++)
				{
					for (size_t k = 0; !corrupted && (k < K); k++)
					{
						tmcg_mpz_wrandomb(m, TMCG_DDH_SIZE);
						mpz_mul_ui(m, m, (i + k + 1));
						ret = aiou->Send(m, i);
						assert(ret);
					}
				}
				// receive array of big random numbers with round-robin scheduler
				size_t num = 0, from = 0;
				do
				{
					ret = aiou->Receive(mm, from,
						aiounicast::aio_scheduler_roundrobin);
					if (num < (N - T))
						assert(ret);
					if (ret)
						std::cout << "P_" << whoami <<
							": received array[" << mm.size() << "] from P_" <<
							from << std::endl;
					for (size_t k = 0; ret && (k < mm.size()); k++)
					{
						assert(mpz_divisible_ui_p(mm[k], (whoami + k + 1)));
					}
					num++;
				}
				while (num < N);

				// release
				mpz_clear(m);
				for (size_t k = 0; k < mm.size(); k++)
				{
					mpz_clear(mm[k]);
					delete [] mm[k];
				}
				mm.clear();

				// release handles (unicast channel)
				uP_in.clear(), uP_out.clear(), uP_key.clear();
				std::cout << "P_" << whoami << ":";
				aiou->PrintStatistics(std::cout);
				std::cout << std::endl;

				// release asynchronous unicast channels
				delete aiou;
			
				std::cout << "P_" << whoami << ": exit(0)" << std::endl;
				exit(0);
				/* END child code: participant P_i */
			}
			catch (std::exception& e)
			{
				std::cerr << "exception catched with what = " << e.what() <<
					std::endl;
				exit(-1);
			}
		}
		else
			std::cout << "fork() = " << pid[whoami] << std::endl;
	}
}

void start_instance_select
	(const size_t whoami, const bool corrupted, const bool authenticated,
	 const bool encrypted)
{
	if ((pid[whoami] = fork()) < 0)
		perror("t-aio (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			try
			{
				/* BEGIN child code: participant P_i */
			
				// create keys and handles between all players
				std::vector<int> uP_in, uP_out;
				std::vector<std::string> uP_key;
				for (size_t i = 0; i < N; i++)
				{
					std::stringstream key;
					key << "t-aio::P_" << (i + whoami);
					uP_in.push_back(pipefd[i][whoami][0]);
					uP_out.push_back(pipefd[whoami][i][1]);
					uP_key.push_back(key.str());
				}

				// create asynchronous authenticated and encrypted unicast channels
				aiounicast_select *aiou = new aiounicast_select(N, whoami,
					uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin,
					aiounicast::aio_timeout_short, authenticated, encrypted);

				// send a simple message
				bool ret = false;
				std::vector<size_t> froms;
				std::vector<size_t>::iterator ipos;
				mpz_t m;
				mpz_init_set_ui(m, whoami);
				for (size_t i = 0; i < N; i++)
				{
					if (!corrupted)
					{
						ret = aiou->Send(m, i);
						assert(ret);
					}
					froms.push_back(i);
				}
				// receive messages from parties
				for (size_t i = 0; i < N; i++)
				{
					ret = aiou->Receive(m, i, aiounicast::aio_scheduler_direct);
					if (ret)
					{
						assert(!mpz_cmp_ui(m, i)); // data should be always correct
						ipos = std::find(froms.begin(), froms.end(), i);
						if (ipos != froms.end())
							froms.erase(ipos);
						else
							std::cout << "P_" << whoami <<
								": entry not found for " << i << std::endl;
					}
					else
						std::cout << "P_" << whoami <<
							": timeout of " << i << std::endl;
				}
				assert(froms.size() <= T); // at most T messages not received
				for (size_t i = 0; i < froms.size(); i++)
				{
					assert(froms[i] < T); // only corrupted parties should fail
				}
				// send array of K big random numbers
				std::vector<mpz_ptr> mm;
				for (size_t k = 0; k < K; k++)
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init(tmp);
					mm.push_back(tmp);
				}
				for (size_t i = 0; i < N; i++)
				{
					for (size_t k = 0; !corrupted && (k < K); k++)
					{
						tmcg_mpz_wrandomb(m, TMCG_DDH_SIZE);
						mpz_mul_ui(m, m, (i + k + 1));
						ret = aiou->Send(m, i);
						assert(ret);
					}
				}
				// receive array of big random numbers with round-robin scheduler
				size_t num = 0, from = 0;
				do
				{
					ret = aiou->Receive(mm, from,
						aiounicast::aio_scheduler_roundrobin);
					if (num < (N - T))
						assert(ret);
					if (ret)
						std::cout << "P_" << whoami <<
							": received array[" << mm.size() << "] from P_" <<
							from << std::endl;
					for (size_t k = 0; ret && (k < mm.size()); k++)
					{
						assert(mpz_divisible_ui_p(mm[k], (whoami + k + 1)));
					}
					num++;
				}
				while (num < N);

				// release
				mpz_clear(m);
				for (size_t k = 0; k < mm.size(); k++)
				{
					mpz_clear(mm[k]);
					delete [] mm[k];
				}
				mm.clear();

				// release handles (unicast channel)
				uP_in.clear(), uP_out.clear(), uP_key.clear();
				std::cout << "P_" << whoami << ":";
				aiou->PrintStatistics(std::cout);
				std::cout << std::endl;

				// release asynchronous unicast channels
				delete aiou;
			
				std::cout << "P_" << whoami << ": exit(0)" << std::endl;
				exit(0);
				/* END child code: participant P_i */
			}
			catch (std::exception& e)
			{
				std::cerr << "exception catched with what = " << e.what() <<
					std::endl;
				exit(-1);
			}
		}
		else
			std::cout << "fork() = " << pid[whoami] << std::endl;
	}
}

void init_nonblock
	()
{
	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("t-aio (pipe)");
		}
	}
}

void init_select
	()
{
	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("t-aio (pipe)");
		}
	}
}

bool done
	()
{
	// wait for childs and close pipes
	bool result = true;
	for (size_t i = 0; i < N; i++)
	{
		int wstatus = 0;
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], &wstatus, 0) != pid[i])
			perror("t-aio (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " <<
					WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			result = false;
		}
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("t-aio (close)");
		}
	}
	return result;
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());
	
	// test case #1a: all correct, not authenticated, not encrypted
	init_nonblock();
	for (size_t i = 0; i < N; i++)
		start_instance_nonblock(i, false, false, false);
	if (!done())
		return 1;
	// test case #1b: all correct, authenticated, not encrypted
	init_nonblock();
	for (size_t i = 0; i < N; i++)
		start_instance_nonblock(i, false, true, false);
	if (!done())
		return 1;
	// test case #1c: all correct, not authenticated, encrypted
	init_nonblock();
	for (size_t i = 0; i < N; i++)
		start_instance_nonblock(i, false, false, true);
	if (!done())
		return 1;
	// test case #1d: all correct, authenticated, encrypted
	init_nonblock();
	for (size_t i = 0; i < N; i++)
		start_instance_nonblock(i, false, true, true);
	if (!done())
		return 1;
	
	// test case #2: T corrupted parties, authenticated, encrypted
	init_nonblock();
	for (size_t i = 0; i < N; i++)
	{
		if (i < T)
			start_instance_nonblock(i, true, true, true); // corrupted
		else
			start_instance_nonblock(i, false, true, true);
	}
	if (!done())
		return 1;

	// test case #3a: all correct, not authenticated, not encrypted
	init_select();
	for (size_t i = 0; i < N; i++)
		start_instance_select(i, false, false, false);
	if (!done())
		return 1;
	// test case #3b: all correct, authenticated, not encrypted
	init_select();
	for (size_t i = 0; i < N; i++)
		start_instance_select(i, false, true, false);
	if (!done())
		return 1;
	// test case #3c: all correct, not authenticated, encrypted
	init_select();
	for (size_t i = 0; i < N; i++)
		start_instance_select(i, false, false, true);
	if (!done())
		return 1;
	// test case #3d: all correct, authenticated, encrypted
	init_select();
	for (size_t i = 0; i < N; i++)
		start_instance_select(i, false, true, true);
	if (!done())
		return 1;

	// test case #4: T corrupted parties, authenticated, encrypted
	init_select();
	for (size_t i = 0; i < N; i++)
	{
		if (i < T)
			start_instance_select(i, true, true, true); // corrupted
		else
			start_instance_select(i, false, true, true);
	}
	if (!done())
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

