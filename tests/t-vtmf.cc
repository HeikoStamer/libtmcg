/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007, 2009,
               2015, 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
			try
			{
				/* BEGIN child code: participant B */
				ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
				opipestream *pipe_out = new opipestream(pipe2fd[1]);
			
				// key generation protocol
				vtmf2->KeyGenerationProtocol_GenerateKey();
				vtmf2->KeyGenerationProtocol_PublishKey(*pipe_out);
				assert(vtmf2->KeyGenerationProtocol_UpdateKey(*pipe_in));
				vtmf2->KeyGenerationProtocol_Finalize();
				assert((vtmf2->KeyGenerationProtocol_NumberOfKeys() == 1));
				*pipe_out << vtmf2->h_i << std::endl;
				assert(vtmf2->KeyGenerationProtocol_ProveKey_interactive(
					*pipe_in, *pipe_out));
				JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2, 0,
					vtmf2->p, vtmf2->q, vtmf2->g, vtmf2->h);
				assert(vtmf2->KeyGenerationProtocol_ProveKey_interactive_publiccoin(
					edcf, *pipe_in, *pipe_out));
				delete edcf;
			
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
				{
					tmcg->TMCG_ProveCardSecret(sB[i], vtmf2,
						*pipe_in, *pipe_out);
				}
			
				delete tmcg;
			
				// key generation protocol: test remove key
				vtmf2->KeyGenerationProtocol_PublishKey(*pipe_out);
			
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
			
			// key generation protocol
			std::cout << "*.KeyGenerationProtocol_GenerateKey()" << std::endl;
			vtmf->KeyGenerationProtocol_GenerateKey();
			vtmf->KeyGenerationProtocol_PublishKey(*pipe_out);
			std::cout << "*.KeyGenerationProtocol_UpdateKey()" << std::endl;
			assert(vtmf->KeyGenerationProtocol_UpdateKey(*pipe_in));
			std::cout << "*.KeyGenerationProtocol_Finalize()" << std::endl;
			vtmf->KeyGenerationProtocol_Finalize();
			std::cout << "*.KeyGenerationProtocol_NumberOfKeys()" << std::endl;
			assert((vtmf->KeyGenerationProtocol_NumberOfKeys() == 1));
			std::cout << "*.KeyGenerationProtocol_VerifyKey_interactive()" << std::endl;
			mpz_t h_j;
			mpz_init(h_j);
			*pipe_in >> h_j;
			std::cout << "h_j = " << h_j << std::endl;
			assert(vtmf->KeyGenerationProtocol_VerifyKey_interactive(h_j,
				*pipe_in, *pipe_out));
			JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2, 0,
				vtmf->p, vtmf->q, vtmf->g, vtmf->h);
			std::cout << "*.KeyGenerationProtocol_VerifyKey_interactive" <<
				"_publiccoin()" << std::endl;
			assert(vtmf->KeyGenerationProtocol_VerifyKey_interactive_publiccoin(
				h_j, edcf, *pipe_in, *pipe_out));
			delete edcf;
			mpz_clear(h_j);
			
			// TMCG/VTMF
			std::cout << "TMCG/VTMF Encryption and decryption of cards" <<
				std::endl;
			SchindelhauerTMCG *tmcg = 
				new SchindelhauerTMCG(16, 2, TMCG_MAX_TYPEBITS);
			
			TMCG_OpenStack<VTMF_Card> os;
			TMCG_Stack<VTMF_Card> sA, sAB, sB;
			std::cout << "A: test basic stack operations" << std::endl;
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				VTMF_Card c;
				os.push(i, c);
			}
			assert(os.size() == TMCG_MAX_CARDS);
			size_t j = (TMCG_MAX_CARDS - 1);
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++, j--)
			{
				VTMF_Card c;
				size_t idx = TMCG_MAX_CARDS;
				bool notempty = os.pop(idx, c);
				assert(notempty);
				assert(idx == j);
			}
			assert(os.empty());
			for (size_t i = 0; i < TMCG_MAX_CARDS; i++)
			{
				VTMF_Card c;
				os.push(i, c);
			}
			os.clear();
			assert(os.empty());
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
				assert(tmcg->TMCG_VerifyCardSecret(sB[i], vtmf,
					*pipe_in, *pipe_out));
				typeA = tmcg->TMCG_TypeOfCard(sB[i], vtmf);
				
				std::cout << typeA << " " << std::flush;
				assert((typeA < TMCG_MAX_CARDS));
				
				assert(std::find(typesA.begin(), typesA.end(), typeA)
					== typesA.end());
				typesA.push_back(typeA);
			}
			std::cout << std::endl;
			
			delete tmcg;
			
			// key generation protocol: test remove key
			std::cout << "*.KeyGenerationProtocol_RemoveKey()" << std::endl;
			assert(vtmf->KeyGenerationProtocol_RemoveKey(*pipe_in));
			std::cout << "*.KeyGenerationProtocol_NumberOfKeys()" << std::endl;
			assert((vtmf->KeyGenerationProtocol_NumberOfKeys() == 0));
			
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
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());
	try
	{
		std::stringstream oak, lej, lej2, foo, foo2, bar;
		std::string v;
		mpz_t fooo, barr, lejj;
		BarnettSmartVTMF_dlog *vtmf, *vtmf2;
		BarnettSmartVTMF_dlog_GroupQR *vtmf_qr, *vtmf2_qr;

		// create and check a common instance <2048-bit MODP Group [RFC3526]>
		mpz_init(barr);
		mpz_set_str(barr, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
		oak << barr << std::endl; // p
		mpz_sub_ui(barr, barr, 1L);
		mpz_fdiv_q_2exp(barr, barr, 1L);
		oak << barr << std::endl; // q
		oak << "2" << std::endl << "2" << std::endl; // g and k
		std::cout << "BarnettSmartVTMF_dlog_GroupQR(<2048-bit MODP" <<
			" Group [RFC3526]>)" << std::endl;
		vtmf_qr = new BarnettSmartVTMF_dlog_GroupQR(oak);
		std::cout << "vtmf_qr.CheckGroup()" << std::endl;
		assert(vtmf_qr->CheckGroup());
		delete vtmf_qr;
		mpz_clear(barr);
	
		// create and check a random QR-instance
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

		// create and check a random instance
		std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog();
		std::cout << "vtmf.CheckGroup()" << std::endl;
		assert(vtmf->CheckGroup());
	
		// trivial generator attack, i.e., g = 1
		mpz_init(fooo);
		mpz_set(fooo, vtmf->g);
		mpz_set_ui(vtmf->g, 1L);
		assert(!vtmf->CheckGroup());
		mpz_set(vtmf->g, vtmf->p);
		mpz_add_ui(vtmf->g, vtmf->g, 1L);
		assert(!vtmf->CheckGroup());
		mpz_set(vtmf->g, fooo);
		mpz_clear(fooo);

		// check basic protocols (CP and OR)
		std::stringstream cp_ack, cp_nak, or_ack1, or_ack2, or_nak;
		mpz_init(fooo), mpz_init(barr), mpz_init(lejj);
		tmcg_mpz_srandomm(fooo, vtmf->q); 
		tmcg_mpz_spowm(vtmf->h, vtmf->g, fooo, vtmf->p);
		std::cout << "CP protocol" << std::endl;
		tmcg_mpz_wrandomm(fooo, vtmf->q);
		mpz_powm(barr, vtmf->g, fooo, vtmf->p);
		mpz_powm(lejj, vtmf->h, fooo, vtmf->p); 
		vtmf->CP_Prove(barr, lejj, vtmf->g, vtmf->h, fooo, cp_ack);
		std::cout << "CP_Verify(g^z, h^z, ...)" << std::endl;
		std::cout << cp_ack.str() << std::endl;
		assert(vtmf->CP_Verify(barr, lejj, vtmf->g, vtmf->h, cp_ack));
		mpz_add_ui(fooo, fooo, 1L); // z' = z + 1
		mpz_powm(lejj, vtmf->h, fooo, vtmf->p); 
		vtmf->CP_Prove(barr, lejj, vtmf->g, vtmf->h, fooo, cp_nak);
		std::cout << "!CP_Verify(g^z, h^z', ...)" << std::endl;
		std::cout << cp_nak.str() << std::endl;
		assert(!vtmf->CP_Verify(barr, lejj, vtmf->g, vtmf->h, cp_nak));
		std::cout << "OR protocol" << std::endl;
		tmcg_mpz_wrandomm(fooo, vtmf->q);
		mpz_powm(barr, vtmf->g, fooo, vtmf->p);
		mpz_powm_ui(lejj, vtmf->h, 42L, vtmf->p);
		std::cout << "OR_ProveFirst(...)" << std::endl;
		vtmf->OR_ProveFirst(barr, lejj, vtmf->g, vtmf->h, fooo, or_ack1);
		std::cout << "OR_Verify(...)" << std::endl;
		std::cout << or_ack1.str() << std::endl;
		assert(vtmf->OR_Verify(barr, lejj, vtmf->g, vtmf->h, or_ack1));
		tmcg_mpz_wrandomm(fooo, vtmf->q);
		mpz_powm_ui(barr, vtmf->g, 42L, vtmf->p);
		mpz_powm(lejj, vtmf->h, fooo, vtmf->p);
		std::cout << "OR_ProveSecond(...)" << std::endl;
		vtmf->OR_ProveSecond(barr, lejj, vtmf->g, vtmf->h, fooo, or_ack2);
		std::cout << "OR_Verify(...)" << std::endl;
		std::cout << or_ack2.str() << std::endl;
		assert(vtmf->OR_Verify(barr, lejj, vtmf->g, vtmf->h, or_ack2));
		tmcg_mpz_wrandomm(fooo, vtmf->q);
		mpz_powm_ui(barr, vtmf->g, 42L, vtmf->p);
		mpz_powm_ui(lejj, vtmf->h, 42L, vtmf->p);
		vtmf->OR_ProveFirst(barr, lejj, vtmf->g, vtmf->h, fooo, or_nak);
		std::cout << "!OR_Verify(...)" << std::endl;
		std::cout << or_nak.str() << std::endl;
		assert(!vtmf->OR_Verify(barr, lejj, vtmf->g, vtmf->h, or_nak));
		mpz_clear(fooo), mpz_clear(barr), mpz_clear(lejj);

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

		// create and check an instance with canonical generator
		std::cout << "BarnettSmartVTMF_dlog(canonical_g == true)" << std::endl;
		vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true);
		std::cout << "vtmf.CheckGroup()" << std::endl;
		assert(vtmf->CheckGroup());
	
		// large generator check
		mpz_init(fooo), mpz_init(barr);
		mpz_set(fooo, vtmf->g);
		tmcg_mpz_wrandomm(barr, vtmf->p);
		mpz_powm(vtmf->g, barr, vtmf->k, vtmf->p);
		assert(!vtmf->CheckGroup());
		mpz_set(vtmf->g, fooo);
		mpz_clear(fooo), mpz_clear(barr);
	
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

