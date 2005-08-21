/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include <sstream>
#include <vector>
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
	std::stringstream foo, foo2, bar;
	mpz_t a, b, c, d, e;
	mpz_t *array;
	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
	
	// RandomElement(), IndexElement(), CheckElement()
	std::cout << "vtmf.RandomElement(a)" << std::endl;
	vtmf->RandomElement(a);
	assert(mpz_cmp(a, vtmf->p) < 0);
	assert(vtmf->CheckElement(a));
	mpz_powm(b, a, vtmf->q, vtmf->p);
	assert(!mpz_cmp_ui(b, 1L));
	std::cout << "vtmf.RandomElement(b)" << std::endl;
	vtmf->RandomElement(b);
	assert(mpz_cmp(b, a));
	assert(vtmf->CheckElement(b));
	mpz_set_ui(b, 0L);
	std::cout << "vtmf.IndexElement(a, [0, 127])" << std::endl;
	array = new mpz_t[128]();
	for (size_t i = 0; i < 128; i++)
	{
		vtmf->IndexElement(a, i);
		mpz_init_set(array[i], a);
		std::cout << a << " ";
		for (size_t j = 0; j < i; j++)
			assert(mpz_cmp(array[i], array[j]));
	}
	for (size_t i = 0; i < 128; i++)
		mpz_clear(array[i]);
	delete [] array;
	std::cout << std::endl;
	
	// key generation protocol
	std::cout << "*.KeyGenerationProtocol_GenerateKey()" << std::endl;
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf2->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_PublishKey(foo);
	vtmf2->KeyGenerationProtocol_PublishKey(foo2);
	std::cout << "*.KeyGenerationProtocol_UpdateKey()" << std::endl;
	assert(vtmf->KeyGenerationProtocol_UpdateKey(foo2));
	assert(vtmf2->KeyGenerationProtocol_UpdateKey(foo));
	std::cout << "*.KeyGenerationProtocol_Finalize()" << std::endl;
	vtmf->KeyGenerationProtocol_Finalize();
	vtmf2->KeyGenerationProtocol_Finalize();
	
	// TMCG/VTMF
	std::cout << "TMCG/VTMF Encryption and decryption of cards" << std::endl;
	SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(16, 2, 8);
	
	TMCG_OpenStack<VTMF_Card> os, os2;
	TMCG_Stack<VTMF_Card> sA, sAB, sB;
	TMCG_StackSecret<VTMF_CardSecret> ssA, ssB;
	std::cout << " CreateOpenCard()" << std::endl;
	for (size_t i = 0; i < 256; i++)
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
	std::cout << " MixStack()" << std::endl;
	tmcg->TMCG_CreateStackSecret(ssA, false, sA.size(), vtmf);
	tmcg->TMCG_MixStack(sA, sAB, ssA, vtmf);
	std::cout << " MixStack()" << std::endl;
	tmcg->TMCG_CreateStackSecret(ssB, false, sAB.size(), vtmf2);
	tmcg->TMCG_MixStack(sAB, sB, ssB, vtmf2);
	std::cout << " TypeOfCard() = " << std::flush;
	for (size_t i = 0; i < sB.size(); i++)
	{
		std::stringstream proofA, proofB;
		size_t typeA = 256, typeB = 256;
		
		tmcg->TMCG_SelfCardSecret(sB[i], vtmf);
		tmcg->TMCG_ProveCardSecret(sB[i], vtmf2, proofB, proofB);
		assert(tmcg->TMCG_VerifyCardSecret(sB[i], vtmf, proofB, proofB));
		typeA = tmcg->TMCG_TypeOfCard(sB[i], vtmf);
		
		tmcg->TMCG_SelfCardSecret(sB[i], vtmf2);
		tmcg->TMCG_ProveCardSecret(sB[i], vtmf, proofA, proofA);
		assert(tmcg->TMCG_VerifyCardSecret(sB[i], vtmf2, proofA, proofA));
		typeB = tmcg->TMCG_TypeOfCard(sB[i], vtmf2);
		
		std::cout << typeA << " " << std::flush;
		
		assert(typeA == typeB);
		assert((typeA >= 0) && (typeA < 256));
	}
	std::cout << std::endl;
	
	delete tmcg;
	
	std::cout << "*.KeyGenerationProtocol_RemoveKey()" << std::endl;
	vtmf2->KeyGenerationProtocol_PublishKey(bar);
	assert(vtmf->KeyGenerationProtocol_RemoveKey(bar));
	assert(!mpz_cmp(vtmf->h, vtmf->h_i));
	
	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
}

int main
	(int argc, char **argv)
{
	std::stringstream oak, lej, lej2, foo, foo2, bar;
	std::string v;
	
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
	std::cout << "vtmf.CheckGroup()" << std::endl;
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
