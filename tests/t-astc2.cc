/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
int pipefd_nm1[N-1][N-1][2], broadcast_pipefd_nm1[N-1][N-1][2];
pid_t pid[N];

void start_instance
	(std::istream& crs_in, size_t whoami, bool corrupted)
{
	if ((pid[whoami] = fork()) < 0)
		perror("t-astc2 (fork)");
	else
	{
		if (pid[whoami] == 0)
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
				key << "t-astc2::P_" << (i + whoami);
				P_in.push_back(new ipipestream(pipefd[i][whoami][0]));
				P_out.push_back(new opipestream(pipefd[whoami][i][1]));
				uP_in.push_back(pipefd[i][whoami][0]);
				uP_out.push_back(pipefd[whoami][i][1]);
				uP_key.push_back(key.str());
				bP_in.push_back(broadcast_pipefd[i][whoami][0]);
				bP_out.push_back(broadcast_pipefd[whoami][i][1]);
				bP_key.push_back(key.str());
			}
			std::vector<int> uP_in_nm1, uP_out_nm1, bP_in_nm1, bP_out_nm1;
			std::vector<std::string> uP_key_nm1, bP_key_nm1;
			for (size_t i = 0; i < (N-1); i++)
			{
				std::stringstream key;
				size_t idx = (whoami==0)?0:whoami-1;
				key << "t-astc2_nm1::P_" << (i + idx);
				uP_in_nm1.push_back(pipefd_nm1[i][idx][0]);
				uP_out_nm1.push_back(pipefd_nm1[idx][i][1]);
				uP_key_nm1.push_back(key.str());
				bP_in_nm1.push_back(broadcast_pipefd_nm1[i][idx][0]);
				bP_out_nm1.push_back(broadcast_pipefd_nm1[idx][i][1]);
				bP_key_nm1.push_back(key.str());
			}
			
			// create VTMF instance
			std::cout << "P_" << whoami << ": BarnettSmartVTMF_dlog(crs_in)" << std::endl;
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
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			
			// create and exchange VTMF keys
			std::cout << "P_" << whoami << ": vtmf.KeyGenerationProtocol_*()" << std::endl;
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
						std::cout << "P_" << whoami << ": " << "Public key of P_" <<
							i << " was not correctly generated!" << std::endl;
						exit(-1);
					}
				}
			}
			vtmf->KeyGenerationProtocol_Finalize();
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;

			// create asynchronous authenticated unicast channels
			aiounicast_select *aiou = new aiounicast_select(N, whoami, uP_in, uP_out, uP_key,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_short);
			aiounicast_select *aiou_nm1 = new aiounicast_select(N-1, (whoami==0)?0:whoami-1, uP_in_nm1, uP_out_nm1, uP_key_nm1,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_short);

			// create asynchronous authenticated broadcast channels
			aiounicast_select *aiou2 = new aiounicast_select(N, whoami, bP_in, bP_out, bP_key,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
			aiounicast_select *aiou2_nm1 = new aiounicast_select(N-1, (whoami==0)?0:whoami-1, bP_in_nm1, bP_out_nm1, bP_key_nm1,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
			
			// create two instances of a reliable broadcast protocol (RBC)
			std::string myID = "t-astc2", myID_nm1 = "t-astc2_nm1";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
			rbc->setID(myID);
			CachinKursawePetzoldShoupRBC *rbc_nm1 = new CachinKursawePetzoldShoupRBC(N-1, T-1, (whoami==0)?0:whoami-1, aiou2_nm1,
				aiounicast::aio_scheduler_roundrobin, aiounicast::aio_timeout_long);
			rbc_nm1->setID(myID_nm1);

			// create an instance of DKG (without using very strong randomness)
			CanettiGennaroJareckiKrawczykRabinDKG *dkg;
			std::cout << "P_" << whoami << ": CanettiGennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
			dkg = new CanettiGennaroJareckiKrawczykRabinDKG(N, T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false);
			assert(dkg->CheckGroup());
			
			// generating $x$ and extracting $y = g^x \bmod p$
			std::stringstream err_log, state_log;
			bool ret = true;
			start_clock();
			std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
			if (corrupted)
				dkg->Generate(aiou, rbc, err_log, true);
			else
				ret = dkg->Generate(aiou, rbc, err_log);
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();
			if (!corrupted)
				assert(ret);

			// publish state
			std::cout << "P_" << whoami << ": dkg.PublishState()" << std::endl;
			dkg->PublishState(state_log);

			// create an instance of DSS (without using very strong randomness)
			CanettiGennaroJareckiKrawczykRabinDSS *dss;
			std::cout << "P_" << whoami << ": CanettiGennaroJareckiKrawczykRabinDSS(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
			dss = new CanettiGennaroJareckiKrawczykRabinDSS(N, T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false);
			assert(dss->CheckGroup());

			// generate distributed key shares
			std::stringstream err_log_dss;
			start_clock();
			std::cout << "P_" << whoami << ": dss.Generate()" << std::endl;
			if (corrupted)
				dss->Generate(aiou, rbc, err_log_dss, true);
			else
				ret = dss->Generate(aiou, rbc, err_log_dss);
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log_dss.str();
			if (!corrupted)
				assert(ret);

			// signing and verifying messages
			std::stringstream err_log_sign, err_log_sign_nm1;
			mpz_t m, r, s;
			mpz_init(m), mpz_init(r), mpz_init(s);
			// check signing and verifying of a message with N signers
			mpz_set_ui(m, 42L), mpz_set_ui(r, 0L), mpz_set_ui(s, 0L);
			start_clock();
			std::cout << "P_" << whoami << ": dss.Sign(42, ...)" << std::endl;
			if (corrupted)
				dss->Sign(N, whoami, m, r, s, aiou, rbc, err_log_sign, true);
			else
				ret = dss->Sign(N, whoami, m, r, s, aiou, rbc, err_log_sign);
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
			if (!corrupted)
				assert(ret);
			start_clock();
			std::cout << "P_" << whoami << ": dss.Verify(42, ...)" << std::endl;
			if (corrupted)
				dss->Verify(m, r, s);
			else
				ret = dss->Verify(m, r, s);
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			if (!corrupted)
				assert(ret);
			std::cout << "P_" << whoami << ": !dss.Verify(43, ...)" << std::endl;
			mpz_add_ui(m, m, 1L);
			if (corrupted)
				dss->Verify(m, r, s);
			else
				ret = dss->Verify(m, r, s);
			stop_clock();
			std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
			if (!corrupted)
				assert(!ret);
			// now: sync for waiting parties
			rbc->Sync(aiounicast::aio_timeout_middle);
			// check signing and verifying of a message with N-1 signers = P_1, P_2, ...
			if (whoami > 0)
			{
				std::map<size_t, size_t> idx2dkg, dkg2idx;
				for (size_t i = 0; i < (N-1); i++)
					idx2dkg[i] = i + 1, dkg2idx[i + 1] = i; // create one-to-one mapping
				mpz_set_ui(m, 23L), mpz_set_ui(r, 0L), mpz_set_ui(s, 0L);
				start_clock();
				std::cout << "P_" << whoami << ": dss.Sign(23, ...)" << std::endl;
				if ((corrupted) && (whoami == (N-1)))
					dss->Sign(N-1, whoami-1, m, r, s, idx2dkg, dkg2idx, aiou_nm1, rbc_nm1, err_log_sign_nm1, true);
				else
					ret = dss->Sign(N-1, whoami-1, m, r, s, idx2dkg, dkg2idx, aiou_nm1, rbc_nm1, err_log_sign_nm1);
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl << err_log_sign_nm1.str();
				if (!corrupted)
					assert(ret);
				start_clock();
				std::cout << "P_" << whoami << ": dss.Verify(23, ...)" << std::endl;
				if (corrupted)
					dss->Verify(m, r, s);
				else
					ret = dss->Verify(m, r, s);
				stop_clock();
				std::cout << "P_" << whoami << ": " << elapsed_time() << std::endl;
				if (!corrupted)
					assert(ret);
				// at the end: sync for waiting parties
				rbc_nm1->Sync(aiounicast::aio_timeout_middle);
			}
			mpz_clear(m), mpz_clear(r), mpz_clear(s);

			// release DSS
			delete dss;
			
			// release DKG
			delete dkg;

			// create a copied instance of DKG from state log
			std::cout << "P_" << whoami << ": CanettiGennaroJareckiKrawczykRabinDKG(state_log)" << std::endl;
			dkg = new CanettiGennaroJareckiKrawczykRabinDKG(state_log);

			// compare state log and check the generated key share again
			std::stringstream state_log2;
			dkg->PublishState(state_log2);
			assert(state_log.str() == state_log2.str());

			// release DKG
			delete dkg;

			// release RBCs		
			delete rbc, delete rbc_nm1;
			
			// release pipe streams (private channels)
			size_t numRead = 0, numWrite = 0;
			for (size_t i = 0; i < N; i++)
			{
				numRead += P_in[i]->get_numRead() + P_out[i]->get_numRead();
				numWrite += P_in[i]->get_numWrite() + P_out[i]->get_numWrite();
				delete P_in[i], delete P_out[i];
			}
			std::cout << "P_" << whoami << ": numRead = " << numRead << " numWrite = " << numWrite << std::endl;

			// release handles (unicast channel)
			uP_in.clear(), uP_out.clear(), uP_key.clear();
			std::cout << "P_" << whoami << ": aiou.numRead = " << aiou->numRead << " aiou.numWrite = " << aiou->numWrite << std::endl;
			std::cout << "P_" << whoami << ": aiou.numDecrypted = " << aiou->numDecrypted << " aiou.numEncrypted = " << aiou->numEncrypted << std::endl;
			std::cout << "P_" << whoami << ": aiou.numAuthenticated = " << aiou->numAuthenticated << std::endl;
			std::cout << "P_" << whoami << ": aiou_nm1.numRead = " << aiou_nm1->numRead << " aiou_nm1.numWrite = " << aiou_nm1->numWrite << std::endl;
			std::cout << "P_" << whoami << ": aiou_nm1.numDecrypted = " << aiou_nm1->numDecrypted <<
				" aiou_nm1.numEncrypted = " << aiou_nm1->numEncrypted << std::endl;
			std::cout << "P_" << whoami << ": aiou_nm1.numAuthenticated = " << aiou_nm1->numAuthenticated << std::endl;

			// release handles (broadcast channel)
			bP_in.clear(), bP_out.clear(), bP_key.clear();
			std::cout << "P_" << whoami << ": aiou2.numRead = " << aiou2->numRead << " aiou2.numWrite = " << aiou2->numWrite << std::endl;
			std::cout << "P_" << whoami << ": aiou2.numDecrypted = " << aiou2->numDecrypted << " aiou2.numEncrypted = " << aiou2->numEncrypted << std::endl;
			std::cout << "P_" << whoami << ": aiou2.numAuthenticated = " << aiou2->numAuthenticated << std::endl;
			std::cout << "P_" << whoami << ": aiou2_nm1.numRead = " << aiou2_nm1->numRead << " aiou2_nm1.numWrite = " << aiou2_nm1->numWrite << std::endl;
			std::cout << "P_" << whoami << ": aiou2_nm1.numDecrypted = " << aiou2_nm1->numDecrypted <<
				" aiou2_nm1.numEncrypted = " << aiou2_nm1->numEncrypted << std::endl;
			std::cout << "P_" << whoami << ": aiou2_nm1.numAuthenticated = " << aiou2_nm1->numAuthenticated << std::endl;

			// release asynchronous unicast and broadcast
			delete aiou, delete aiou2, delete aiou_nm1, delete aiou2_nm1;

			// release VTMF instance
			delete vtmf;
			
			std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
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
				perror("t-astc2 (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("t-astc2 (pipe)");
		}
	}
	for (size_t i = 0; i < (N-1); i++)
	{
		for (size_t j = 0; j < (N-1); j++)
		{
			if (pipe(pipefd_nm1[i][j]) < 0)
				perror("t-astc2 (pipe)");
			if (pipe(broadcast_pipefd_nm1[i][j]) < 0)
				perror("t-astc2 (pipe)");
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
			perror("t-astc2 (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " << WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			result = false;
		}
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("t-astc2 (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("t-astc2 (close)");
		}
	}
	for (size_t i = 0; i < (N-1); i++)
	{
		for (size_t j = 0; j < (N-1); j++)
		{
			if ((close(pipefd_nm1[i][j][0]) < 0) || (close(pipefd_nm1[i][j][1]) < 0))
				perror("t-astc2 (close)");
			if ((close(broadcast_pipefd_nm1[i][j][0]) < 0) || (close(broadcast_pipefd_nm1[i][j][1]) < 0))
				perror("t-astc2 (close)");
		}
	}
	return result;
}

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());

	BarnettSmartVTMF_dlog 	*vtmf;
	std::stringstream 	crs;

	// create and check VTMF instance (with verifiable generation of $g$)
	std::cout << "BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true)" << std::endl;
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
	
	// release VTMF instance
	delete vtmf;
	
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
