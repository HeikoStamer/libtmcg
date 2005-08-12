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
	std::stringstream oak, lej, lej2, foo, foo2, bar;
	mpz_t a, b, c, d, e;
	assert(init_libTMCG());
	
	nWay_PedersenCommitmentScheme *com;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(d), mpz_init(e);
	
	std::cout << "nWay_PedersenCommitmentScheme(32)" << std::endl;
	com = new nWay_PedersenCommitmentScheme(32);
	assert(com->CheckGroup());
	
	delete com;
	
	mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(d), mpz_clear(e);
	return 0;
}
