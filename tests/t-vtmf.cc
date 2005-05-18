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
#include <cassert>

#include <libTMCG.hh>

#undef NDEBUG

int main
	(int argc, char **argv)
{
	std::stringstream lej, lej2, foo, foo2;
	std::string v;
	mpz_t a, b, c, d, e;
	assert(init_libTMCG());
	
	BarnettSmartVTMF_dlog *vtmf, *vtmf2;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
	
	// create and check the instance
	std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
	vtmf = new BarnettSmartVTMF_dlog();
	std::cout << "vtmf.CheckGroup()" << std::endl;
	assert(vtmf->CheckGroup());
	
	// publish the instance
	std::cout << "vtmf.PublishGroup(lej)" << std::endl;
	vtmf->PublishGroup(lej);
	
	// create a cloned instance
	std::cout << "BarnettSmartVTMF_dlog(lej)" << std::endl;
	vtmf2 = new BarnettSmartVTMF_dlog(lej);
	
	// publish the cloned instance
	std::cout << "vtmf2.PublishGroup(lej2)" << std::endl;
	vtmf2->PublishGroup(lej2);
	assert(lej.str() == lej2.str());
	
	// RandomElement(), NextElement(), IndexElement()
	std::cout << "vtmf.RandomElement(a)" << std::endl;
	vtmf->RandomElement(a);
	assert(mpz_cmp(a, vtmf->p) < 0);
	assert(mpz_jacobi(a, vtmf->p) == 1L);
	mpz_powm(b, a, vtmf->q, vtmf->p);
	assert(!mpz_cmp_ui(b, 1L));
	std::cout << "vtmf.RandomElement(b)" << std::endl;
	vtmf->RandomElement(b);
	assert(mpz_cmp(a, b));
	mpz_set(b, a);
	std::cout << "vtmf.NextElement(a)" << std::endl;
	vtmf->NextElement(a);
	assert(mpz_cmp(b, a) < 0);
	mpz_set_ui(b, 0L);
	std::cout << "vtmf.IndexElement(a, 0...63)" << std::endl;
	for (size_t i = 0; i < 64; i++)
	{
		vtmf->IndexElement(a, i);
		std::cout << a << " ";
		assert(mpz_cmp(b, a) < 0);
		mpz_set(b, a);
	}
	std::cout << std::endl;

	// key generation protocol
	std::cout << "*.KeyGenerationProtocol_GenerateKey()" << std::endl;
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf2->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_PublishKey(foo);
	vtmf2->KeyGenerationProtocol_PublishKey(foo2);
	assert(vtmf->KeyGenerationProtocol_UpdateKey(foo2));
	assert(vtmf2->KeyGenerationProtocol_UpdateKey(foo));
	
	// TMCG/VTMF
	std::cout << "TMCG/VTMF Encryption and decryption of cards" << std::endl;
	SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(16, 2, 8);
	
	TMCG_OpenStack<VTMF_Card> os, os2;
	TMCG_Stack<VTMF_Card> sA, sAB, sB;
	TMCG_StackSecret<VTMF_CardSecret> ssA, ssB;
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
	tmcg->TMCG_CreateStackSecret(ssA, false, sA.size(), vtmf);
	tmcg->TMCG_MixStack(sA, sAB, ssA, vtmf);
	tmcg->TMCG_CreateStackSecret(ssB, false, sAB.size(), vtmf2);
	tmcg->TMCG_MixStack(sAB, sB, ssB, vtmf2);
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
		
		std::cout << typeA << " ";
		
		assert(typeA == typeB);
		assert((typeA >= 0) && (typeA < 256));
	}
	std::cout << std::endl;
	
	delete tmcg;
	
	// release the instances
	delete vtmf, delete vtmf2;

	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
	return 0;
}
