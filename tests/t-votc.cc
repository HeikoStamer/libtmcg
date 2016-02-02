/*******************************************************************************
   (K-out-of-N) |V|erifiable |O|blivious |T|ransfer with |C|ards

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

#include <libTMCG.hh>

#ifdef FORKING

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
#define N 32
#define K 2

int pipefd_sr[2], pipefd_rs[2];
pid_t pid_s, pid_r;

/* sender */
void start_instance_sender
	(std::istream& vtmf_str)
{
	if ((pid_s = fork()) < 0)
		perror("t-votc (fork)");
	else
	{
		if (pid_s == 0)
		{
			/* BEGIN child code: sender */
			
			// create pipe streams
			ipipestream *P_in = new ipipestream(pipefd_rs[0]);
			opipestream *P_out = new opipestream(pipefd_sr[1]);
			
			// create TMCG and VTMF instances
			start_clock();
			SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(64, 2, 8);
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(vtmf_str);
			if (!vtmf->CheckGroup())
			{
				std::cout << "S: VTMF was not correctly generated" << std::endl;
				exit(-1);
			}
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;
			
			// create and exchange VTMF keys
			start_clock();
			vtmf->KeyGenerationProtocol_GenerateKey();
			vtmf->KeyGenerationProtocol_PublishKey(*P_out);
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in))
			{
				std::cout << "S: key of R is not correct" << std::endl;
				exit(-1);
			}
			vtmf->KeyGenerationProtocol_Finalize();
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;
			
			// VSSHE
			start_clock();
			GrothVSSHE *vsshe = new GrothVSSHE(N, *P_in);
			if (!vsshe->CheckGroup())
			{
				std::cout << "S: VSSHE was not correctly generated" << std::endl;
				exit(-1);
			}
			if (mpz_cmp(vtmf->h, vsshe->com->h))
			{
				std::cout << "S: common public key does not match" << std::endl;
				exit(-1);
			}
			if (mpz_cmp(vtmf->q, vsshe->com->q))
			{
				std::cout << "S: subgroup order does not match" << std::endl;
				exit(-1);
			}
			if (mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
				mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h))
			{
				std::cout << "S: encryption scheme does not match" << std::endl;
				exit(-1);
			}
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;

			// this is the transfer phase
			start_clock();			
			// (1) create a stack that contains the messages for transfer
			TMCG_Stack<VTMF_Card> s;
			TMCG_StackSecret<VTMF_CardSecret> ss;
			for (size_t type = 0; type < N; type++)
			{
				VTMF_Card c;
				VTMF_CardSecret cs;
				tmcg->TMCG_CreatePrivateCard(c, cs, vtmf, type);
				s.push(c);
				ss.push(type, cs);
			}
			// (2) send the stack to the receiver
			*P_out << s << std::endl;
			// (TODO?) prove the knowledge of the messages to receiver
			// (3) receiver shuffles and sends the resulting stack back
			TMCG_Stack<VTMF_Card> s2;
			*P_in >> s2;
			if (!P_in->good())
			{
				std::cout << "S: read error or bad parse" << std::endl;
				exit(-1);
			}
			// (4) verify the correctness of the shuffle			
			if (!tmcg->TMCG_VerifyStackEquality_Groth(s, s2, vtmf, vsshe, *P_in, *P_out))
			{
				std::cout << "S: shuffle verification failed" << std::endl;
				exit(-1);
			}
			// (5) open the topmost K cards for the receiver
			for (size_t k = 0; k < K; k++)
				tmcg->TMCG_ProveCardSecret(s2[k], vtmf, *P_in, *P_out);
			stop_clock();
			std::cout << "S: " << elapsed_time() << std::endl;
			
			// release TMCG, VTMF, and VSSHE instances
			delete tmcg, delete vtmf, delete vsshe;
			
			// release pipe streams
			size_t numRead = 0, numWrite = 0;
			numRead += P_in->get_numRead() + P_out->get_numRead();
			numWrite += P_in->get_numWrite() + P_out->get_numWrite();
			delete P_in, delete P_out;
			std::cout << "S: numRead = " << numRead <<
				" numWrite = " << numWrite << std::endl;
			
			exit(0);
			/* END child code: sender */
		}
		else
			std::cout << "fork() = " << pid_s << std::endl;
	}
}

/* receiver */
void start_instance_receiver
	(std::istream& vtmf_str)
{
	if ((pid_r = fork()) < 0)
		perror("t-votc (fork)");
	else
	{
		if (pid_r == 0)
		{
			/* BEGIN child code: receiver */
			
			// create pipe streams to the sender
			ipipestream *P_in = new ipipestream(pipefd_sr[0]);
			opipestream *P_out = new opipestream(pipefd_rs[1]);
			
			// create TMCG and VTMF instances
			start_clock();
			SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(64, 2, 8);
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(vtmf_str);
			if (!vtmf->CheckGroup())
			{
				std::cout << "R: VTMF was not correctly generated" << std::endl;
				exit(-1);
			}
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			
			// create and exchange VTMF keys
			start_clock();
			vtmf->KeyGenerationProtocol_GenerateKey();
			vtmf->KeyGenerationProtocol_PublishKey(*P_out);
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in))
			{
				std::cout << "R: key of S is not correct" << std::endl;
				exit(-1);
			}
			vtmf->KeyGenerationProtocol_Finalize();
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			
			// VSSHE: create scheme and publish parameters to the sender
			start_clock();			
			GrothVSSHE *vsshe = new GrothVSSHE(N, vtmf->p, vtmf->q, vtmf->k, vtmf->g, vtmf->h);
			if (!vsshe->CheckGroup())
			{
				std::cout << "R: VSSHE was not correctly generated" << std::endl;
				exit(-1);
			}
			vsshe->PublishGroup(*P_out);
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;
			
			// this is the transfer phase
			start_clock();
			// (1) receive the original stack from the sender
			TMCG_Stack<VTMF_Card> s;
			*P_in >> s;
			if (!P_in->good())
			{
				std::cout << "R: read error or bad parse" << std::endl;
				exit(-1);
			}
			// (2) shuffle the stack in order to hide and determine the choice
			TMCG_Stack<VTMF_Card> s2;
			TMCG_StackSecret<VTMF_CardSecret> ss;
			tmcg->TMCG_CreateStackSecret(ss, false, s.size(), vtmf);
			tmcg->TMCG_MixStack(s, s2, ss, vtmf);
			// (3) send the result back to the sender
			*P_out << s2 << std::endl;
			// (4) prove the correctness of the shuffle
			tmcg->TMCG_ProveStackEquality_Groth(s, s2, ss, vtmf, vsshe, *P_in, *P_out);
			// (5) open the topmost K cards		
			for (size_t k = 0; k < K; k++)
			{
				tmcg->TMCG_SelfCardSecret(s2[k], vtmf);
				if (!tmcg->TMCG_VerifyCardSecret(s2[k], vtmf, *P_in, *P_out))
				{
					std::cout << "R: card verification failed" << std::endl;
					exit(-1);
				}
				size_t type = tmcg->TMCG_TypeOfCard(s2[k], vtmf);
				std::cout << "R: message received = " << type << std::endl;
			}
			stop_clock();
			std::cout << "R: " << elapsed_time() << std::endl;			
			
			// release TMCG, VTMF, and VSSHE instances
			delete tmcg, delete vtmf, delete vsshe;
			
			// release pipe streams
			size_t numRead = 0, numWrite = 0;
			numRead += P_in->get_numRead() + P_out->get_numRead();
			numWrite += P_in->get_numWrite() + P_out->get_numWrite();
			delete P_in, delete P_out;
			std::cout << "R: numRead = " << numRead <<
				" numWrite = " << numWrite << std::endl;
			
			exit(0);
			/* END child code: receiver */
		}
		else
			std::cout << "fork() = " << pid_r << std::endl;
	}
}

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());
	
	BarnettSmartVTMF_dlog	*vtmf;
	std::stringstream	vtmf_str;

	// create and check the common VTMF instance
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
	if ((pipe(pipefd_sr) < 0) || (pipe(pipefd_rs) < 0)) 
		perror("t-votc (pipe)");
	
	// start transfer childs
	start_instance_sender(vtmf_str);
	start_instance_receiver(vtmf_str);
	
	// wait for transfer childs and close pipes
	std::cerr << "waitpid(" << pid_s << ")" << std::endl;
	if (waitpid(pid_s, NULL, 0) != pid_s)
		perror("t-votc (waitpid)");
	std::cerr << "waitpid(" << pid_r << ")" << std::endl;
	if (waitpid(pid_r, NULL, 0) != pid_r)
		perror("t-votc (waitpid)");
	if ((close(pipefd_sr[0]) < 0) || (close(pipefd_sr[1]) < 0))
		perror("t-votc (close)");
	if ((close(pipefd_rs[0]) < 0) || (close(pipefd_rs[1]) < 0))
		perror("t-votc (close)");

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
