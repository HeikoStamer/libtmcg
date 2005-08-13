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

#include <libTMCG.hh>

#undef NDEBUG

int main
	(int argc, char **argv)
{
	mpz_t a, b, c, d, e;
	assert(init_libTMCG());
	
	nWay_PedersenCommitmentScheme *com, *com2;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
	
	for (size_t n = 1; n <= 32; n++)
	{
		std::stringstream foo;
		std::vector<mpz_ptr> m;
		
		std::cout << "nWay_PedersenCommitmentScheme(" << n << ")" << std::endl;
		com = new nWay_PedersenCommitmentScheme(n);
		std::cout << "*.CheckGroup()" << std::endl;
		assert(com->CheckGroup());
		
		// create a clone instance
		std::cout << "*.PublishGroup(foo)" << std::endl;
		com->PublishGroup(foo);
		std::cout << "nWay_PedersenCommitmentScheme(" << n << ", foo)" << std::endl;
		com2 = new nWay_PedersenCommitmentScheme(n, foo);
		std::cout << "*.CheckGroup()" << std::endl;
		assert(com2->CheckGroup());
		
		// create messages
		for (size_t i = 0; i < n; i++)
		{
			mpz_ptr tmp = new mpz_t();
			mpz_init_set_ui(tmp, i);
			m.push_back(tmp);
		}
		
		// commit
		std::cout << "*.Commit(...)" << std::endl;
		com->Commit(a, b, m);
		
		// verify
		std::cout << "*.Verify(...)" << std::endl;
		assert(com->Verify(a, b, m));
		assert(com2->Verify(a, b, m));
		mpz_add_ui(m[0], m[0], 1L);
		assert(!com->Verify(a, b, m));
		assert(!com2->Verify(a, b, m));
		
		// release
		for (size_t i = 0; i < n; i++)
		{
			mpz_clear(m[i]);
			delete m[i];
		}
		m.clear();
		delete com, delete com2;
	}
	
	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
	return 0;
}
