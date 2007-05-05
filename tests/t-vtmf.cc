/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include <libTMCG.hh>
#include "pipestream.hh"

#undef NDEBUG

void check
	(BarnettSmartVTMF_dlog *vtmf, BarnettSmartVTMF_dlog *vtmf2)
{
	mpz_t a, b, c, d, e;
	mpz_t *array;
	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
	
	// RandomElement(), IndexElement(), CheckElement()
	std::cout << "vtmf.RandomElement(a), vtmf.CheckElement(a)" << std::endl;
	vtmf->RandomElement(a);
	assert(mpz_cmp(a, vtmf->p) < 0);
	assert(vtmf->CheckElement(a));
	mpz_powm(b, a, vtmf->q, vtmf->p);
	assert(!mpz_cmp_ui(b, 1L));
	std::cout << "vtmf.RandomElement(b), vtmf.CheckElement(b)" << std::endl;
	vtmf->RandomElement(b);
	assert(mpz_cmp(b, a));
	assert(vtmf->CheckElement(b));
	mpz_set_ui(b, 0L);
	std::cout << "vtmf.IndexElement(a, ...), vtmf.CheckElement(a)" << std::endl;
	array = new mpz_t[TMCG_MAX_CARDS]();
	for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
	{
		vtmf->IndexElement(a, i);
		mpz_init_set(array[i], a);
		std::cout << a << " ";
		for (size_t j = 0; j < i; j++)
			assert(mpz_cmp(array[i], array[j]));
		assert(vtmf->CheckElement(a));
	}
	for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
		mpz_clear(array[i]);
	delete [] array;
	std::cout << std::endl;
	
	pid_t pid = 0;
	int pipe1fd[2], pipe2fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
		perror("t-vtmf (pipe)");
	else if ((pid = fork()) < 0)
		perror("t-vtmf (fork)");
	else
	{
		if (pid == 0)
		{
			/* BEGIN child code: participant B */
			ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
			opipestream *pipe_out = new opipestream(pipe2fd[1]);
			
			// key generation protocol
			vtmf2->KeyGenerationProtocol_GenerateKey();
			vtmf2->KeyGenerationProtocol_PublishKey(*pipe_out);
			assert(vtmf2->KeyGenerationProtocol_UpdateKey(*pipe_in));
			vtmf2->KeyGenerationProtocol_Finalize();
			
			SchindelhauerTMCG *tmcg = 
				new SchindelhauerTMCG(16, 2, TMCG_MAX_TYPEBITS);
			TMCG_OpenStack<VTMF_Card> os;
			TMCG_Stack<VTMF_Card> sA, sAB, sB;
			TMCG_StackSecret<VTMF_CardSecret> ssB;
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				VTMF_Card c;
				tmcg->TMCG_CreateOpenCard(c, vtmf2, i);
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
			assert(tmcg->TMCG_VerifyStackEquality(sA, sAB, false, vtmf2,
				*pipe_in, *pipe_out));
			
			std::cout << "B: MixStack()" << std::endl;
			tmcg->TMCG_CreateStackSecret(ssB, false, sAB.size(), vtmf2);
			tmcg->TMCG_MixStack(sAB, sB, ssB, vtmf2);
			*pipe_out << sB << std::endl;
			
			std::cout << "B: ProveStackEquality()" << std::endl;
			tmcg->TMCG_ProveStackEquality(sAB, sB, ssB, false, vtmf2,
				*pipe_in, *pipe_out);
			
			for (size_t i = 0; i < sB.size(); i++)
				tmcg->TMCG_ProveCardSecret(sB[i], vtmf2, *pipe_in, *pipe_out);
			
			delete tmcg;
			
			// key generation protocol
			vtmf2->KeyGenerationProtocol_PublishKey(*pipe_out);
			
			delete pipe_in, delete pipe_out;
			exit(0);
			/* END child code: participant B */
		}
		else
		{
			std::cout << "fork() = " << pid << std::endl;
			/* participant A */
			ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
			opipestream *pipe_out = new opipestream(pipe1fd[1]);
			
			// key generation protocol
			std::cout << "*.KeyGenerationProtocol_GenerateKey()" << std::endl;
			vtmf->KeyGenerationProtocol_GenerateKey();
			vtmf->KeyGenerationProtocol_PublishKey(*pipe_out);
			std::cout << "*.KeyGenerationProtocol_UpdateKey()" << std::endl;
			assert(vtmf->KeyGenerationProtocol_UpdateKey(*pipe_in));
			std::cout << "*.KeyGenerationProtocol_Finalize()" << std::endl;
			vtmf->KeyGenerationProtocol_Finalize();
			
			// TMCG/VTMF
			std::cout << "TMCG/VTMF Encryption and decryption of cards" << std::endl;
			SchindelhauerTMCG *tmcg = 
				new SchindelhauerTMCG(16, 2, TMCG_MAX_TYPEBITS);
			
			TMCG_OpenStack<VTMF_Card> os;
			TMCG_Stack<VTMF_Card> sA, sAB, sB;
			TMCG_StackSecret<VTMF_CardSecret> ssA;
			std::cout << "A: CreateOpenCard()" << std::endl;
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				VTMF_Card c;
				tmcg->TMCG_CreateOpenCard(c, vtmf, i);
				os.push(i, c);
			}
			sA.push(os);
			for (size_t i = 0; i < sA.size(); i++)
			{
				assert(sA[i] == os[i].second);
			}
			
			std::cout << "A: MixStack()" << std::endl;
			tmcg->TMCG_CreateStackSecret(ssA, false, sA.size(), vtmf);
			tmcg->TMCG_MixStack(sA, sAB, ssA, vtmf);
			*pipe_out << sAB << std::endl;
			
			std::cout << "A: ProveStackEquality()" << std::endl;
			tmcg->TMCG_ProveStackEquality(sA, sAB, ssA, false, vtmf,
				*pipe_in, *pipe_out);
			
			*pipe_in >> sB;
			assert(pipe_in->good());
			std::cout << "A: VerifyStackEquality()" << std::endl;
			assert(tmcg->TMCG_VerifyStackEquality(sAB, sB, false, vtmf,
				*pipe_in, *pipe_out));
			
			std::cout << "A: TypeOfCard() = " << std::flush;
			std::vector<size_t> typesA;
			for (size_t i = 0; i < sB.size(); i++)
			{
				size_t typeA = TMCG_MAX_CARDS;
				
				tmcg->TMCG_SelfCardSecret(sB[i], vtmf);
				assert(tmcg->TMCG_VerifyCardSecret(sB[i], vtmf, *pipe_in, *pipe_out));
				typeA = tmcg->TMCG_TypeOfCard(sB[i], vtmf);
				
				std::cout << typeA << " " << std::flush;
				assert((typeA >= 0) && (typeA < TMCG_MAX_CARDS));
				
				assert(std::find(typesA.begin(), typesA.end(), typeA) == typesA.end());
				typesA.push_back(typeA);
			}
			std::cout << std::endl;
			
			delete tmcg;
			
			// key generation protocol
			std::cout << "*.KeyGenerationProtocol_RemoveKey()" << std::endl;
			assert(vtmf->KeyGenerationProtocol_RemoveKey(*pipe_in));
			
			delete pipe_in, delete pipe_out;
		}
		if (waitpid(pid, NULL, 0) != pid)
			perror("t-vtmf (waitpid)");
	}
	close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);	
	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
}

int main
	(int argc, char **argv)
{
	std::stringstream oak, lej, lej2, foo, foo2, bar;
	std::string v;
	mpz_t fooo;
	
	assert(init_libTMCG());
	
	BarnettSmartVTMF_dlog *vtmf, *vtmf2;
	BarnettSmartVTMF_dlog_GroupQR *vtmf_qr, *vtmf2_qr;
	
	// create and check the common instance
	oak << "1a1e4vngailcvh7j2tur8zts6fbkrcac6d3g0jdfvdggl9r7cr2v6zllf6b3z6xb6w0\
nix8jsjlecgt8lwx1huihghkvqnbbgviiz0vg6ntckohpeac84n0co9czkw174ic47ifwd2189x26\
609ce63xm5vddxvsbbevn4bxaiv2784d9335o38na680ay8apygtmnz" << std::endl;
	oak << "n0p2ftq59aofqlrjexdmhww37nsdo5636jq09opxoq8amvlodjflhsspl5jzlgnlg0b\
rgm9w9sp68emaygiqx98q8sfvbnnqfr9hifq3bwoac8up5642bi6c4ohsg0lk9623r7y6j0m4yj33\
04o731yt2xooyxw5npftk5yn9fj3m26mjjku1mbn3405h45cz8etbz" << std::endl;
	oak << "2" << std::endl << "2" << std::endl;
	std::cout << "BarnettSmartVTMF_dlog_GroupQR(<Oakley Group 2>)" << std::endl;
	vtmf_qr = new BarnettSmartVTMF_dlog_GroupQR(oak);
	std::cout << "vtmf_qr.CheckGroup()" << std::endl;
	assert(vtmf_qr->CheckGroup());
	delete vtmf_qr;
	
	// create and check the instance
	std::cout << "BarnettSmartVTMF_dlog_GroupQR()" << std::endl;
	vtmf_qr = new BarnettSmartVTMF_dlog_GroupQR();
	std::cout << "vtmf_qr.CheckGroup()" << std::endl;
	assert(vtmf_qr->CheckGroup());
	
	// publish the instance
	std::cout << "vtmf_qr.PublishGroup(foo)" << std::endl;
	vtmf_qr->PublishGroup(foo);
	
	// create a clone of the instance
	std::cout << "BarnettSmartVTMF_dlog_GroupQR(foo)" << std::endl;
	vtmf2_qr = new BarnettSmartVTMF_dlog_GroupQR(foo);
	
	// publish the cloned instance
	std::cout << "vtmf2_qr.PublishGroup(foo2)" << std::endl;
	vtmf2_qr->PublishGroup(foo2);
	std::cout << foo.str() << std::endl;
	std::cout << "versus" << std::endl;
	std::cout << foo2.str() << std::endl;
	assert(foo.str() == foo2.str());
	
	// check the instances
	start_clock();
	check(vtmf_qr, vtmf2_qr);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	
	// release the instances
	delete vtmf_qr, delete vtmf2_qr;
	
	// create and check the instance
	std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
	vtmf = new BarnettSmartVTMF_dlog();
	std::cout << "vtmf.CheckGroup()" << std::endl;
	assert(vtmf->CheckGroup());
	
	// trivial generator attack
	mpz_init(fooo);
	mpz_set(fooo, vtmf->g);
	mpz_set_ui(vtmf->g, 1L);
	assert(!vtmf->CheckGroup());
	mpz_set(vtmf->g, vtmf->p);
	mpz_add_ui(vtmf->g, vtmf->g, 1L);
	assert(!vtmf->CheckGroup());
	mpz_set(vtmf->g, fooo);
	mpz_clear(fooo);
	
	// publish the instance
	std::cout << "vtmf.PublishGroup(lej)" << std::endl;
	vtmf->PublishGroup(lej);
	
	// create a clone of the instance
	std::cout << "BarnettSmartVTMF_dlog(lej)" << std::endl;
	vtmf2 = new BarnettSmartVTMF_dlog(lej);
	
	// publish the cloned instance
	std::cout << "vtmf2.PublishGroup(lej2)" << std::endl;
	vtmf2->PublishGroup(lej2);
	std::cout << lej.str() << std::endl;
	std::cout << "versus" << std::endl;
	std::cout << lej2.str() << std::endl;
	assert(lej.str() == lej2.str());
	
	// check the instances
	start_clock();
	check(vtmf, vtmf2);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	
	// release the instances
	delete vtmf, delete vtmf2;
	
	return 0;
}
