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
	
	
	
	// release the instances
	delete vtmf, delete vtmf2;

	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
	return 0;
}
