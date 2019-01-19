/*******************************************************************************
   adaptive (K-out-of-N) |V|erifiable |O|blivious |T|ransfer with |C|ards

   The implementation follows the idea presented in the following paper:

     [KNP11] Kaoru Kurosawa, Ryo Nojima, and Le Trieu Phong:
	 'Generic Fully Simulatable Adaptive Oblivious Transfer',
     Applied Cryptography and Network Security (ACNS) 2011,
     LNCS 6715, pp. 274--291, Springer 2011.

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
#define N 32
#define K 5

int pipefd_sr[2], pipefd_rs[2];
pid_t pid_s, pid_r;

// create a random permutation (Knuth or Fisher-Yates algorithm)
void random_permutation_fast
	(size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
		pi.push_back(i);
	
	for (size_t i = 0; i < (n - 1); i++)
	{
		size_t tmp = pi[i], rnd = i + (size_t)tmcg_mpz_srandom_mod(n - i);
		pi[i] = pi[rnd];
		pi[rnd] = tmp;
	}
}

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
			try
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
					std::cout << "S: VTMF was not correctly generated" <<
						std::endl;
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
					std::cout << "S: VSSHE was not correctly generated" <<
						std::endl;
					exit(-1);
				}
				if (mpz_cmp(vtmf->h, vsshe->com->h))
				{
					std::cout << "S: common public key does not match" <<
						std::endl;
					exit(-1);
				}
				if (mpz_cmp(vtmf->q, vsshe->com->q))
				{
					std::cout << "S: subgroup order does not match" <<
						std::endl;
					exit(-1);
				}
				if (mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
					mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h))
				{
					std::cout << "S: encryption scheme does not match" <<
						std::endl;
					exit(-1);
				}
				stop_clock();
				std::cout << "S: " << elapsed_time() << std::endl;

				// this is the initialization phase
				start_clock();			
				// (1) create a stack that contains the messages for transfer;
				//     the messages are hidden for the receiver by masking and
				//     the resulting stack is send to the receiver
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
				*P_out << s << std::endl;
				// (2) prove the knowledge of randomizers $\hat{r}$ to receiver
				for (size_t i = 0; i < ss.size(); i++)
				{
					mpz_t v, t, c, r;
					// proof of knowledge [CaS97] for a discrete logarithm
					mpz_init(v), mpz_init(t), mpz_init(c), mpz_init(r);	
					// commitment
					tmcg_mpz_srandomm(v, vtmf->q);
					tmcg_mpz_spowm(t, vtmf->g, v, vtmf->p);
					// challenge
					// Here we use the well-known "Fiat-Shamir heuristic" to
					// make the PoK non-interactive, i.e. we turn it into a
					// statistically zero-knowledge (Schnorr signature scheme
					// style) proof of knowledge (SPK) in random oracle model.
					// Note that $c_1 = g^{\hat{r}}$ holds.
					tmcg_mpz_shash(c, 3, vtmf->g, s[i].c_1, t);
					// response
					mpz_mul(r, c, ss[i].second.r); // multiply with secret value
					mpz_neg(r, r);
					mpz_add(r, r, v);
					mpz_mod(r, r, vtmf->q);
					*P_out << c << std::endl << r << std::endl;
					mpz_clear(v), mpz_clear(t), mpz_clear(c), mpz_clear(r);
				}
				// (3) receiver shuffles and sends the resulting stack back
				TMCG_Stack<VTMF_Card> s2;
				*P_in >> s2;
				if (!P_in->good())
				{
					std::cout << "S: read error or bad parse" << std::endl;
					exit(-1);
				}
				// (4) verify the correctness of the shuffle			
				if (!tmcg->TMCG_VerifyStackEquality_Groth(s, s2, vtmf, vsshe,
					*P_in, *P_out))
				{
					std::cout << "S: shuffle verification failed" << std::endl;
					exit(-1);
				}

				// this is the transfer phase
				// (5) let the receiver adaptively open K cards from the stack
				for (size_t k = 0; k < K; k++)
				{
					size_t i;
					*P_in >> i;
					if (i < N)
					{
						std::cout << "S: receiver requests to open i = " <<
							i << std::endl;
						tmcg->TMCG_ProveCardSecret(s2[i], vtmf, *P_in, *P_out);
					}
					else
					{
						std::cout << "S: index out of range" << std::endl;
						exit(-1);
					}
				}
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
			catch (std::exception& e)
			{
				std::cerr << "exception catched with what = " << e.what() <<
					std::endl;
				exit(-1);
			}
		}
		else
			std::cout << "fork() = " << pid_s << std::endl;
	}
}

/* receiver */
void start_instance_receiver
	(std::istream& vtmf_str, const std::vector<size_t>& sigma)
{
	if ((pid_r = fork()) < 0)
		perror("t-votc (fork)");
	else
	{
		if (pid_r == 0)
		{
			try
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
					std::cout << "R: VTMF was not correctly generated" <<
						std::endl;
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
				GrothVSSHE *vsshe = new GrothVSSHE(N, vtmf->p, vtmf->q, vtmf->k,
					vtmf->g, vtmf->h);
				if (!vsshe->CheckGroup())
				{
					std::cout << "R: VSSHE was not correctly generated" <<
						std::endl;
					exit(-1);
				}
				vsshe->PublishGroup(*P_out);
				stop_clock();
				std::cout << "R: " << elapsed_time() << std::endl;
			
				// this is the initialization phase
				start_clock();
				// (1) receive the masked stack from the sender
				TMCG_Stack<VTMF_Card> s;
				*P_in >> s;
				if (!P_in->good())
				{
					std::cout << "R: read error or bad parse" << std::endl;
					exit(-1);
				}
				// (2) verify the knowledge of randomizers $\hat{r}$ from sender
				for (size_t i = 0; i < s.size(); i++)
				{
					mpz_t t, c, r;
					mpz_init(t), mpz_init(c), mpz_init(r);
					*P_in >> c >> r;
					// check the size of $\hat{r}$
					if (mpz_cmpabs(r, vtmf->q) >= 0)
					{
						std::cout << "R: wrong size of $\\hat{r}$" << std::endl;
						exit(-1);
					}
					// verify the proof of knowledge [CaS97]
					mpz_powm(t, vtmf->g, r, vtmf->p);
					mpz_powm(r, s[i].c_1, c, vtmf->p);
					mpz_mul(t, t, r);
					mpz_mod(t, t, vtmf->p);
					tmcg_mpz_shash(r, 3, vtmf->g, s[i].c_1, t);
					if (mpz_cmp(c, r))
					{
						std::cout << "R: SPK for $\\hat{r}$ failed" << std::endl;
						exit(-1);
					}
					mpz_clear(t), mpz_clear(c), mpz_clear(r);
				}
				// (3) shuffle the stack in order to hide and commit to the
				//     choice; messages are choosen by constructing an
				//     appropriate permutation
				std::vector<size_t> pi;
				random_permutation_fast(N, pi);
				TMCG_Stack<VTMF_Card> s2;
				TMCG_StackSecret<VTMF_CardSecret> ss;
				tmcg->TMCG_CreateStackSecret(ss, pi, s.size(), vtmf);
				tmcg->TMCG_MixStack(s, s2, ss, vtmf);
				*P_out << s2 << std::endl;
				std::cout << "R: secret permutation pi = ";
				for (size_t i = 0; i < N; i++)
					std::cout << pi[i] << " ";
				std::cout << std::endl;
				// (4) prove the correctness of the shuffle
				tmcg->TMCG_ProveStackEquality_Groth(s, s2, ss, vtmf, vsshe,
					*P_in, *P_out);

				// this is the transfer phase
				// (5) request the opening of K cards based on the permutation		
				for (size_t k = 0; k < K; k++)
				{
					size_t i = std::distance(pi.begin(), std::find(pi.begin(),
						pi.end(), sigma[k]));
					*P_out << i << std::endl;
					tmcg->TMCG_SelfCardSecret(s2[i], vtmf);
					if (!tmcg->TMCG_VerifyCardSecret(s2[i], vtmf, *P_in, *P_out))
					{
						std::cout << "R: card verification failed" << std::endl;
						exit(-1);
					}
					size_t type = tmcg->TMCG_TypeOfCard(s2[i], vtmf);
					std::cout << "R: message " << k << " received = " <<
						type << std::endl;
					assert(sigma[k] == type);
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
			catch (std::exception& e)
			{
				std::cerr << "exception catched with what = " << e.what() <<
					std::endl;
				exit(-1);
			}
		}
		else
			std::cout << "fork() = " << pid_r << std::endl;
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
		std::vector<size_t>	sigma;

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

		// randomize the choices of the receiver
		std::cout << "sigma = ";
		for (size_t i = 0; i < K; i++)
		{
			size_t c = 0;
			do
			{
				c = tmcg_mpz_srandom_mod(N);
			}
			while (std::find(sigma.begin(), sigma.end(), c) != sigma.end());
			sigma.push_back(c);
			std::cout << c << " ";
		}
		std::cout << std::endl;
	
		// start transfer childs
		start_instance_sender(vtmf_str);
		start_instance_receiver(vtmf_str, sigma);
	
		// wait for transfer childs and close pipes
		bool result = true;
		int wstatus_s = 0, wstatus_r = 0;
		std::cerr << "waitpid(" << pid_s << ")" << std::endl;
		if (waitpid(pid_s, &wstatus_s, 0) != pid_s)
			perror("t-votc (waitpid)");
		std::cerr << "waitpid(" << pid_r << ")" << std::endl;
		if (waitpid(pid_r, &wstatus_r, 0) != pid_r)
			perror("t-votc (waitpid)");
		if ((close(pipefd_sr[0]) < 0) || (close(pipefd_sr[1]) < 0))
			perror("t-votc (close)");
		if ((close(pipefd_rs[0]) < 0) || (close(pipefd_rs[1]) < 0))
			perror("t-votc (close)");
		if (!WIFEXITED(wstatus_s) || !WIFEXITED(wstatus_r))
		{
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus_s))
			{
				std::cerr << pid_s << " terminated by signal " <<
					WTERMSIG(wstatus_s) << std::endl;
			}
			if (WCOREDUMP(wstatus_s))
				std::cerr << pid_s << " dumped core" << std::endl;
			std::cerr << "ERROR: ";
			if (WIFSIGNALED(wstatus_r))
			{
				std::cerr << pid_r << " terminated by signal " <<
					WTERMSIG(wstatus_r) << std::endl;
			}
			if (WCOREDUMP(wstatus_r))
				std::cerr << pid_r << " dumped core" << std::endl;
			result = false;
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

