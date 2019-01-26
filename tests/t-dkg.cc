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
#include "pipestream.hh"

#undef NDEBUG
#define N 7
#define T 2

int pipefd[N][N][2], broadcast_pipefd[N][N][2];
pid_t pid[N];

void start_instance
	(std::istream& crs_in, size_t whoami, bool corrupted)
{
	if ((pid[whoami] = fork()) < 0)
		perror("t-dkg (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			try
			{
				/* BEGIN child code: participant P_i */
			
				// create pipe streams and handles between all players
				std::vector<ipipestream*> P_in;
				std::vector<opipestream*> P_out;
				std::vector<int> uP_in, uP_out, bP_in, bP_out;
				std::vector<std::string> uP_key, bP_key;
				for (size_t i = 0; i < N; i++)
				{
					std::stringstream key;
					key << "t-dkg::P_" << (i + whoami);
					P_in.push_back(new ipipestream(pipefd[i][whoami][0]));
					P_out.push_back(new opipestream(pipefd[whoami][i][1]));
					uP_in.push_back(pipefd[i][whoami][0]);
					uP_out.push_back(pipefd[whoami][i][1]);
					uP_key.push_back(key.str());
					bP_in.push_back(broadcast_pipefd[i][whoami][0]);
					bP_out.push_back(broadcast_pipefd[whoami][i][1]);
					bP_key.push_back(key.str());
				}
			
				// create VTMF instance
				std::cout << "P_" << whoami <<
					": BarnettSmartVTMF_dlog(crs_in)" << std::endl;
				std::cout << "P_" << whoami << ": vtmf.CheckGroup()" << std::endl;
				start_clock();
				BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crs_in);
				if (!vtmf->CheckGroup())
				{
					std::cout << "P_" << whoami << ": " <<
						"Group G was not correctly generated!" << std::endl;
					exit(-1);
				}
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
			
				// create and exchange VTMF keys in order to create a
				// common value $h$ for DKG (i.e. $h$-generation protocol)
				std::cout << "P_" << whoami <<
					": vtmf.KeyGenerationProtocol_*()" << std::endl;
				start_clock();
				vtmf->KeyGenerationProtocol_GenerateKey();
				for (size_t i = 0; i < N; i++)
				{
					if (i != whoami)
						vtmf->KeyGenerationProtocol_PublishKey(*P_out[i]);
				}
				for (size_t i = 0; i < N; i++)
				{
					if (i != whoami)
					{
						if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in[i]))
						{
							std::cout << "P_" << whoami << ": Public key of" <<
								" P_" << i << " was not correctly generated!" <<
								std::endl;
							exit(-1);
						}
					}
				}
				vtmf->KeyGenerationProtocol_Finalize();
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;

				// create an instance of DKG (without very strong randomness)
				GennaroJareckiKrawczykRabinDKG *dkg;
				std::cout << "P_" << whoami <<
					": GennaroJareckiKrawczykRabinDKG(" << N << ", " << T <<
					", " << whoami << ", ...)" << std::endl;
				dkg = new GennaroJareckiKrawczykRabinDKG(N, T, whoami, vtmf->p,
					vtmf->q, vtmf->g, vtmf->h, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
					true, false);
				assert(dkg->CheckGroup());

				// create asynchronous authenticated unicast channels
				aiounicast_select *aiou = new aiounicast_select(N, whoami,
					uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin,
					aiounicast::aio_timeout_long);

				// create asynchronous authenticated broadcast channels
				aiounicast_select *aiou2 = new aiounicast_select(N, whoami,
					bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin,
					aiounicast::aio_timeout_long);
			
				// create an instance of a reliable broadcast protocol (RBC)
				std::string myID = "t-dkg";
				CachinKursawePetzoldShoupRBC *rbc =
					new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2,
						aiounicast::aio_scheduler_roundrobin,
						aiounicast::aio_timeout_long);
				rbc->setID(myID);
			
				// generating $x$ and extracting $y = g^x \bmod p$
				std::stringstream err_log, state_log;
				bool ret = true;
				start_clock();
				std::cout << "P_" << whoami << ": dkg.Generate() at " <<
					time(NULL) << std::endl;
				if (corrupted)
					dkg->Generate(aiou, rbc, err_log, true);
				else
					ret = dkg->Generate(aiou, rbc, err_log);
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl <<
					err_log.str() << std::flush;
				if (!corrupted)
					assert(ret);

				// check the generated key share and publish state
				start_clock();
				std::cout << "P_" << whoami << ": dkg.CheckKey() at " <<
					time(NULL) << std::endl;
				if (corrupted)
					dkg->CheckKey();
				else
					assert(dkg->CheckKey());
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << whoami << ": dkg.PublishState() at " <<
					time(NULL) << std::endl;
				dkg->PublishState(state_log);

				// now: sync for waiting parties
				rbc->Sync(aiounicast::aio_timeout_long, "step 1");

				// create an instance of the threshold signature protocol
				// new-TSch (NTS) (without using very strong randomness)
				GennaroJareckiKrawczykRabinNTS *nts;
				std::cout << "P_" << whoami <<
					": GennaroJareckiKrawczykRabinNTS(" << N << ", " << T <<
					", " << whoami << ", ...)" << std::endl;
				nts = new GennaroJareckiKrawczykRabinNTS(N, T, whoami, vtmf->p,
					vtmf->q, vtmf->g, vtmf->h, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
					true, false);
				assert(nts->CheckGroup());

				// generate distributed key shares
				std::stringstream err_log2;
				start_clock();
				std::cout << "P_" << whoami << ": nts.Generate() at " <<
					time(NULL) << std::endl;
				if (corrupted)
					nts->Generate(aiou, rbc, err_log2, true);
				else
					ret = nts->Generate(aiou, rbc, err_log2);
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl <<
					err_log2.str() << std::flush;
				if (!corrupted)
					assert(ret);

				// now: sync for waiting parties
				rbc->Sync(aiounicast::aio_timeout_long, "step 2");

				// sign a message (create a signature share for m = 1UL)
				std::stringstream err_log3;
				mpz_t m, c, s;
				mpz_init_set_ui(m, 1UL);
				mpz_init_set_ui(c, 0L), mpz_init_set_ui(s, 0L);
				start_clock();
				std::cout << "P_" << whoami << ": nts.Sign() at " <<
					time(NULL) << std::endl;
				if (corrupted)
					nts->Sign(m, c, s, aiou, rbc, err_log3, true);
				else
					ret = nts->Sign(m, c, s, aiou, rbc, err_log3);
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl <<
					err_log3.str() << std::flush;
				if (!corrupted)
					assert(ret);

				// verify signature
				start_clock();
				std::cout << "P_" << whoami << ": nts.Verify() at " <<
					time(NULL) << std::endl;
				if (corrupted)
					nts->Verify(m, c, s);
				else
					assert(nts->Verify(m, c, s));
				stop_clock();
				mpz_clear(m), mpz_clear(c), mpz_clear(s);
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl <<
					err_log3.str() << std::flush;
			
				// release NTS
				delete nts;
			
				// release DKG
				delete dkg;

				// at the end: sync for waiting parties
				rbc->Sync(aiounicast::aio_timeout_long, "step 3");

				// create a copied instance of DKG from state log
				std::cout << "P_" << whoami <<
					": GennaroJareckiKrawczykRabinDKG(state_log)" << std::endl;
				dkg = new GennaroJareckiKrawczykRabinDKG(state_log);

				// compare state log and check the generated key share again
				std::stringstream state_log2;
				dkg->PublishState(state_log2);
				assert(state_log.str() == state_log2.str());
				start_clock();
				std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
				if (corrupted)
					dkg->CheckKey();
				else
					assert(dkg->CheckKey());
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() <<
					std::endl;
			
				// release DKG
				delete dkg;

				// release RBC			
				delete rbc;

				// release VTMF instances
				delete vtmf;
			
				// release pipe streams (private channels)
				size_t numRead = 0, numWrite = 0;
				for (size_t i = 0; i < N; i++)
				{
					numRead += P_in[i]->get_numRead() + P_out[i]->get_numRead();
					numWrite += P_in[i]->get_numWrite() + P_out[i]->get_numWrite();
					delete P_in[i], delete P_out[i];
				}
				std::cout << "P_" << whoami << ": numRead = " << numRead <<
					" numWrite = " << numWrite << std::endl;

				// release handles (unicast channel)
				uP_in.clear(), uP_out.clear(), uP_key.clear();
				std::cout << "P_" << whoami << ": aiou.numRead = " <<
					aiou->numRead << " aiou.numWrite = " << aiou->numWrite <<
					std::endl;

				// release handles (broadcast channel)
				bP_in.clear(), bP_out.clear(), bP_key.clear();
				std::cout << "P_" << whoami << ": aiou2.numRead = " <<
					aiou2->numRead << " aiou2.numWrite = " << aiou2->numWrite <<
					std::endl;

				// release asynchronous unicast and broadcast
				delete aiou, delete aiou2;
			
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

void init
	()
{
	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("t-dkg (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("t-dkg (pipe)");
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
			perror("t-dkg (waitpid)");
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
				perror("t-dkg (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("t-dkg (close)");
			}
		}
	}
	return result;
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	try
	{
		assert(init_libTMCG());

		BarnettSmartVTMF_dlog 	*vtmf;
		std::stringstream 	crs;

		// create and check VTMF instance
		std::cout << "BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE," <<
			" true)" << std::endl;
		// ... with verifiable generation of $g$
		vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true);
		std::cout << "vtmf.CheckGroup()" << std::endl;
		start_clock();
		assert(vtmf->CheckGroup());
		stop_clock();
		std::cout << elapsed_time() << std::endl;
	
		// publish VTMF instance as string stream (common reference string)
		std::cout << "vtmf.PublishGroup(crs)" << std::endl;
		vtmf->PublishGroup(crs);
	
		// test case #1: all correct
		init();
		for (size_t i = 0; i < N; i++)
			start_instance(crs, i, false);
		if (!done())
			return 1;
/*		
		// test case #2: two corrupted parties
		init();
		for (size_t i = 0; i < N; i++)
		{
			if ((i == (N - 1)) || (i == (N - 2)))
				start_instance(crs, i, true); // corrupted
			else
				start_instance(crs, i, false);
		}
		if (!done())
			return 1;
*/	
		// release VTMF instance
		delete vtmf;
	
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
