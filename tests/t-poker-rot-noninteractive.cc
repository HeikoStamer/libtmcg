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
#define PLAYERS 9
#define DECKSIZE 52
#define FLOPSIZE 5

int pipefd[PLAYERS][PLAYERS][2];
pid_t pid[PLAYERS];

void start_instance
	(std::istream& vtmf_str, size_t player)
{
	if ((pid[player] = fork()) < 0)
		perror("t-poker-rot-noninteractive (fork)");
	else
	{
		if (pid[player] == 0)
		{
			try
			{
				/* BEGIN child code: participant P_i */
			
				// create pipe streams between all players
				ipipestream *P_in[PLAYERS];
				opipestream *P_out[PLAYERS];
				for (size_t i = 0; i < PLAYERS; i++)
				{
					P_in[i] = new ipipestream(pipefd[i][player][0]);
					P_out[i] = new opipestream(pipefd[player][i][1]);
				}
			
				// create TMCG and VTMF instances
				start_clock();
				SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(64, PLAYERS, 6);
				BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(vtmf_str);
				if (!vtmf->CheckGroup())
				{
					std::cout << "P_" << player << ": " <<
						"Group G was not correctly generated!" << std::endl;
					exit(-1);
				}
				stop_clock();
				std::cout << "P_" << player << ": " << elapsed_time() <<
					std::endl;
			
				// create and exchange VTMF keys
				start_clock();
				vtmf->KeyGenerationProtocol_GenerateKey();
				for (size_t i = 0; i < PLAYERS; i++)
				{
					if (i != player)
						vtmf->KeyGenerationProtocol_PublishKey(*P_out[i]);
				}
				for (size_t i = 0; i < PLAYERS; i++)
				{
					if (i != player)
					{
						if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in[i]))
						{
							std::cout << "P_" << player << ": Public key of" <<
								" P_" << i << " was not correctly generated!" <<
								std::endl;
							exit(-1);
						}
					}
				}
				vtmf->KeyGenerationProtocol_Finalize();
				stop_clock();
				std::cout << "P_" << player << ": " << elapsed_time() <<
					std::endl;
			
				// VRHE
				HooghSchoenmakersSkoricVillegasVRHE *vrhe;
				if (player == 0)
				{
					// create and publish VRHE instance as leader
					start_clock();
					vrhe = new HooghSchoenmakersSkoricVillegasVRHE( 
						vtmf->p, vtmf->q, vtmf->g, vtmf->h);
					if (!vrhe->CheckGroup())
					{
						std::cout << "P_" << player << ": VRHE instance" <<
							" was not correctly generated!" << std::endl;
						exit(-1);
					}
					for (size_t i = 1; i < PLAYERS; i++)
						vrhe->PublishGroup(*P_out[i]);
					stop_clock();
					std::cout << "P_" << player << ": " << elapsed_time() <<
						std::endl;
				}
				else
				{
					// receive and create VRHE instance as non-leader
					start_clock();
					vrhe = new HooghSchoenmakersSkoricVillegasVRHE(*P_in[0]);
					if (!vrhe->CheckGroup())
					{
						std::cout << "P_" << player << ": VRHE instance" <<
							" was not correctly generated!" << std::endl;
						exit(-1);
					}
					if (mpz_cmp(vtmf->p, vrhe->p) ||
						mpz_cmp(vtmf->q, vrhe->q) || 
						mpz_cmp(vtmf->g, vrhe->g) ||
						mpz_cmp(vtmf->h, vrhe->h))
					{
						std::cout << "VRHE: encryption scheme does not" <<
							" match!" << std::endl;
						exit(-1);
					}
					stop_clock();
					std::cout << "P_" << player << ": " << elapsed_time() <<
						std::endl;
				}
			
				// create and shuffle the deck
				start_clock();
				TMCG_OpenStack<VTMF_Card> deck;
				for (size_t type = 0; type < DECKSIZE; type++)
				{
					VTMF_Card c;
					tmcg->TMCG_CreateOpenCard(c, vtmf, type);
					deck.push(type, c);
				}
				TMCG_Stack<VTMF_Card> s;
				s.push(deck);
				for (size_t i = 0; i < PLAYERS; i++)
				{
					TMCG_Stack<VTMF_Card> s2;
					if (i == player)
					{
						TMCG_StackSecret<VTMF_CardSecret> ss;
						std::stringstream lej;
						tmcg->TMCG_CreateStackSecret(ss, true, s.size(), vtmf);
						tmcg->TMCG_MixStack(s, s2, ss, vtmf);
						tmcg->TMCG_ProveStackEquality_Hoogh_noninteractive(s,
							s2, ss, vtmf, vrhe, lej);
						for (size_t i2 = 0; i2 < PLAYERS; i2++)
						{
							if (i2 == player)
								continue;
							*P_out[i2] << s2 << std::endl;
							*P_out[i2] << lej.str();
						}
					}
					else
					{
						*P_in[i] >> s2;
						if (!P_in[i]->good())
						{
							std::cout << "Read or parse error!" << std::endl;
							exit(-1);
						}
						if (!tmcg->TMCG_VerifyStackEquality_Hoogh_noninteractive(s,
							s2, vtmf, vrhe, *P_in[i]))
						{
							std::cout << "Rotation verification failed!" <<
								std::endl;
							exit(-1);
						}
					}
					s = s2;
				}
				stop_clock();
				std::cout << "P_" << player << ": " << elapsed_time() <<
					std::endl;
			
				// drawing two cards for each player
				start_clock();
				TMCG_Stack<VTMF_Card> hand[PLAYERS];
				for (size_t i = 0; i < PLAYERS; i++)
				{
					VTMF_Card c1, c2;
					s.pop(c1), s.pop(c2);
					hand[i].push(c1), hand[i].push(c2);
				}
				TMCG_OpenStack<VTMF_Card> private_hand;
				for (size_t i = 0; i < PLAYERS; i++)
				{
					if (i == player)
					{
						for (size_t k = 0; k < hand[i].size(); k++)
						{
							tmcg->TMCG_SelfCardSecret(hand[i][k], vtmf);
							for (size_t i2 = 0; i2 < PLAYERS; i2++)
							{
								if (i2 == player)
									continue;
								if (!tmcg->TMCG_VerifyCardSecret(hand[i][k],
									vtmf, *P_in[i2], *P_out[i2]))
								{
									std::cout << "Card verification failed!" <<
										std::endl;
									exit(-1);
								}
							}
							size_t type = tmcg->TMCG_TypeOfCard(hand[i][k],
								vtmf);
							private_hand.push(type, hand[i][k]);
						}
					}
					else
					{
						for (size_t k = 0; k < hand[i].size(); k++)
						{
							tmcg->TMCG_ProveCardSecret(hand[i][k], vtmf,
								*P_in[i], *P_out[i]);
						}
					}
				}
				stop_clock();
				std::cout << "P_" << player << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << player << ": my cards are " <<
					private_hand[0].first << " and " <<
					private_hand[1].first << std::endl;
			
				// drawing the flop
				start_clock();
				TMCG_Stack<VTMF_Card> flop;
				VTMF_Card c;
				for (size_t i = 0; i < FLOPSIZE; i++)
				{
					s.pop(c), flop.push(c);
				}
				TMCG_OpenStack<VTMF_Card> open_flop;
				for (size_t i = 0; i < PLAYERS; i++)
				{
					if (i == player)
					{
						for (size_t k = 0; k < flop.size(); k++)
						{
							tmcg->TMCG_SelfCardSecret(flop[k], vtmf);
							for (size_t i2 = 0; i2 < PLAYERS; i2++)
							{
								if (i2 == player)
									continue;
								if (!tmcg->TMCG_VerifyCardSecret(flop[k], vtmf,
									*P_in[i2], *P_out[i2]))
								{
									std::cout << "Card verification failed!" <<
										std::endl;
									exit(-1);
								}
							}
							size_t type = tmcg->TMCG_TypeOfCard(flop[k], vtmf);
							open_flop.push(type, flop[k]);
						}
					}
					else
					{
						for (size_t k = 0; k < flop.size(); k++)
						{
							tmcg->TMCG_ProveCardSecret(flop[k], vtmf,
								*P_in[i], *P_out[i]);
						}
					}
				}
				stop_clock();
				std::cout << "P_" << player << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << player << ": flop cards are ";
				for (size_t i = 0; i < FLOPSIZE; i++)
					std::cout << open_flop[i].first << " ";
				std::cout << std::endl;
			
			
				// release TMCG, VTMF, and VRHE instances
				delete tmcg, delete vtmf, delete vrhe;
			
				// release pipe streams
				size_t numRead = 0, numWrite = 0;
				for (size_t i = 0; i < PLAYERS; i++)
				{
					numRead += P_in[i]->get_numRead() + P_out[i]->get_numRead();
					numWrite += P_in[i]->get_numWrite() + P_out[i]->get_numWrite();
					delete P_in[i], delete P_out[i];
				}
				std::cout << "P_" << player << ": numRead = " << numRead <<
					" numWrite = " << numWrite << std::endl;
			
				std::cout << "P_" << player << ": exit(0)" << std::endl;
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
			std::cout << "fork() = " << pid[player] << std::endl;
	}
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());

	try
	{
		BarnettSmartVTMF_dlog *vtmf;
		std::stringstream vtmf_str;

		// create and check VTMF instance
		std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog();
		std::cout << "vtmf.CheckGroup()" << std::endl;
		start_clock();
		assert(vtmf->CheckGroup());
		stop_clock();
		std::cout << elapsed_time() << std::endl;
	
		// publish VTMF instance as string stream
		std::cout << "vtmf.PublishGroup(vtmf_str)" << std::endl;
		vtmf->PublishGroup(vtmf_str);
	
		// open pipes
		for (size_t i = 0; i < PLAYERS; i++)
		{
			for (size_t j = 0; j < PLAYERS; j++)
			{
				if (pipe(pipefd[i][j]) < 0)
					perror("t-poker-rot-noninteractive (pipe)");
			}
		}
	
		// start poker childs
		for (size_t i = 0; i < PLAYERS; i++)
			start_instance(vtmf_str, i);
	
		// wait for poker childs and close pipes
		bool result = true;
		for (size_t i = 0; i < PLAYERS; i++)
		{
			int wstatus = 0;
			std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
			if (waitpid(pid[i], &wstatus, 0) != pid[i])
				perror("t-poker-rot-noninteractive (waitpid)");
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
			for (size_t j = 0; j < PLAYERS; j++)
			{
				if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
					perror("t-poker-rot-noninteractive (close)");
			}
		}
	
		// release VTMF instance
		delete vtmf;
	
		if (result)
			return 0;
		else
			return 1;
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

