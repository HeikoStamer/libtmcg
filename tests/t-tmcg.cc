/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include "pipestream.hh"

#undef NDEBUG

void check
	()
{
	TMCG_SecretKey secA("Alice", "alice@nowhere.org", TMCG_QRA_SIZE);
	TMCG_SecretKey secB("Bob", "bob@nowhere.org", TMCG_QRA_SIZE);
	TMCG_PublicKey pubA(secA);
	TMCG_PublicKey pubB(secB);
	TMCG_PublicKeyRing ring(2);
	ring.keys[0] = pubA, ring.keys[1] = pubB; 

	pid_t pid = 0;
	int pipe1fd[2], pipe2fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
		perror("t-tmcg (pipe)");
	else if ((pid = fork()) < 0)
		perror("t-tmcg (fork)");
	else
	{
		if (pid == 0)
		{
			try
			{
				/* BEGIN child code: participant B */
				ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
				opipestream *pipe_out = new opipestream(pipe2fd[1]);
					
				SchindelhauerTMCG *tmcg = 
					new SchindelhauerTMCG(16, 2, TMCG_MAX_TYPEBITS);
				TMCG_OpenStack<TMCG_Card> os;
				TMCG_Stack<TMCG_Card> sA, sAB, sB;
				TMCG_StackSecret<TMCG_CardSecret> ssB;
				for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
				{
					TMCG_Card c;
					tmcg->TMCG_CreateOpenCard(c, ring, i);
					os.push(i, c);
				}
				sA.push(os);
				for (size_t i = 0; i < sA.size(); i++)
				{
					assert(sA[i] == os[i].second);
				}
				*pipe_in >> sAB;
				assert(pipe_in->good());
				std::cout << "B: VerifyStackEquality()" << std::endl;
				assert(tmcg->TMCG_VerifyStackEquality(sA, sAB, false, ring,
					*pipe_in, *pipe_out));
				std::cout << "B: MixStack()" << std::endl;
				tmcg->TMCG_CreateStackSecret(ssB, false, ring, 1, sAB.size());
				tmcg->TMCG_MixStack(sAB, sB, ssB, ring);
				*pipe_out << sB << std::endl;
				std::cout << "B: ProveStackEquality()" << std::endl;
				tmcg->TMCG_ProveStackEquality(sAB, sB, ssB, false, ring, 1,
					*pipe_in, *pipe_out);
				for (size_t i = 0; i < sB.size(); i++)
				{
					tmcg->TMCG_ProveCardSecret(sB[i], secB, 1,
						*pipe_in, *pipe_out);
				}
				delete tmcg;
		
				delete pipe_in, delete pipe_out;
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
			/* participant A */
			ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
			opipestream *pipe_out = new opipestream(pipe1fd[1]);
			
			std::cout << "Encryption and decryption of cards" << std::endl;
			SchindelhauerTMCG *tmcg = 
				new SchindelhauerTMCG(16, 2, TMCG_MAX_TYPEBITS);
			TMCG_OpenStack<TMCG_Card> os;
			TMCG_Stack<TMCG_Card> sA, sAB, sB;
			std::cout << "A: test basic stack operations" << std::endl;
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				TMCG_Card c;
				os.push(i, c);
			}
			assert(os.size() == TMCG_MAX_CARDS);
			size_t j = (TMCG_MAX_CARDS - 1);
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++, j--)
			{
				TMCG_Card c;
				size_t idx = TMCG_MAX_CARDS;
				bool notempty = os.pop(idx, c);
				assert(notempty);
				assert(idx == j);
			}
			assert(os.empty());
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				TMCG_Card c;
				os.push(i, c);
			}
			os.clear();
			assert(os.empty());
			TMCG_StackSecret<TMCG_CardSecret> ssA;
			std::cout << "A: CreateOpenCard()" << std::endl;
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				TMCG_Card c;
				tmcg->TMCG_CreateOpenCard(c, ring, i);
				os.push(i, c);
			}
			sA.push(os);
			for (size_t i = 0; i < sA.size(); i++)
			{
				assert(sA[i] == os[i].second);
			}
			std::cout << "A: MixStack()" << std::endl;
			tmcg->TMCG_CreateStackSecret(ssA, false, ring, 0, sA.size());
			tmcg->TMCG_MixStack(sA, sAB, ssA, ring);
			*pipe_out << sAB << std::endl;
			std::cout << "A: ProveStackEquality()" << std::endl;
			tmcg->TMCG_ProveStackEquality(sA, sAB, ssA, false, ring, 0,
				*pipe_in, *pipe_out);
			*pipe_in >> sB;
			assert(pipe_in->good());
			std::cout << "A: VerifyStackEquality()" << std::endl;
			assert(tmcg->TMCG_VerifyStackEquality(sAB, sB, false, ring,
				*pipe_in, *pipe_out));
			std::cout << "A: TypeOfCard() = " << std::flush;
			std::vector<size_t> typesA;
			for (size_t i = 0; i < sB.size(); i++)
			{
				size_t typeA = TMCG_MAX_CARDS;
				TMCG_CardSecret cs;
				tmcg->TMCG_SelfCardSecret(sB[i], cs, secA, 0);
				assert(tmcg->TMCG_VerifyCardSecret(sB[i], cs, pubB, 1,
					*pipe_in, *pipe_out));
				typeA = tmcg->TMCG_TypeOfCard(cs);
				std::cout << typeA << " " << std::flush;
				assert((typeA < TMCG_MAX_CARDS));
				assert(std::find(typesA.begin(), typesA.end(), typeA)
					== typesA.end());
				typesA.push_back(typeA);
			}
			std::cout << std::endl;
			delete tmcg;
						
			delete pipe_in, delete pipe_out;
		}
		if (waitpid(pid, NULL, 0) != pid)
			perror("t-tmcg (waitpid)");
	}
	close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);	
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());
	try
	{
		start_clock();
		check();
		stop_clock();
		std::cout << elapsed_time() << std::endl;
	
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() << std::endl;
		return -1;
	}
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

