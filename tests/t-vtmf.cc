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
	std::stringstream lej, lej2;
	std::string v;
	mpz_t a, b, c, d, e;
	assert(init_libTMCG());
	
	BarnettSmartVTMF_dlog *vtmf, *vtmf2;
	
	// create and check the instance
	std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
	vtmf = new BarnettSmartVTMF_dlog();
	std::cout << "vtmf.CheckGroup()" << std::endl;
	assert(vtmf->CheckGroup());
	
	// publish the instance
	std::cout << "vtmf.PublishGroup(lej)" << std::endl;
	vtmf->PublishGroup(lej);
	std::cout << lej.str();
	
	// create a cloned instance
	std::cout << "BarnettSmartVTMF_dlog(lej)" << std::endl;
	vtmf2 = new BarnettSmartVTMF_dlog(lej);
	
	// publish the cloned instance
	std::cout << "vtmf2.PublishGroup(lej2)" << std::endl;
	vtmf2->PublishGroup(lej2);
	std::cout << lej2.str();
	assert(lej.str() == lej2.str());
	
	// RandomElement(), NextElement(), IndexElement()
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
		std::cout << "vtmf.RandomElement(a)" << std::endl;
		vtmf->RandomElement(a);
		std::cout << a << std::endl;
		assert(mpz_cmp(a, vtmf->p) < 0);
		assert(mpz_jacobi(a, vtmf->p) == 1L);
		mpz_powm(b, a, vtmf->q, vtmf->p);
		assert(!mpz_cmp_ui(b, 1L));
		std::cout << "vtmf.RandomElement(b)" << std::endl;
		vtmf->RandomElement(b);
		std::cout << b << std::endl;
		assert(mpz_cmp(a, b));
	mpz_set(b, a);
		std::cout << "vtmf.NextElement(a)" << std::endl;
		vtmf->NextElement(a);
		std::cout << a << std::endl;
	
	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
	
	// release the instances
	delete vtmf, delete vtmf2;
	
	return 0;
}
