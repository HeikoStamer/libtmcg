/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2005 Heiko Stamer, <stamer@gaos.org>

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

#include <mpz_helper.hh>
#include <mpz_srandom.h>
#include <mpz_sprime.h>

void init_libgcrypt
	()
{
	// initalize libgcrypt
	if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
	{
		std::cerr << "libgcrypt: need library version >= " <<
			TMCG_LIBGCRYPT_VERSION << std::endl;
		exit(-1);
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO))
	{
		std::cerr << "libgcrypt: algorithm " << TMCG_GCRY_MD_ALGO <<
			" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
			"] not available" << std::endl;
		exit(-1);
	}
}

int main
	(int argc, char **argv)
{
	size_t step = 1;
	mpz_t foo, bar;
	std::stringstream lej;
	
	mpz_init(foo), mpz_init(bar);
	std::cout << "TMCG_MPZ_IO_BASE = " << TMCG_MPZ_IO_BASE << std::endl;
	std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	mpz_set_ui(foo, 42L), mpz_set_ui(bar, 0L);
	std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 0L));
	lej << foo << std::endl, lej >> bar;
	std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 42L));
	
	std::cout << "TMCG_LIBGCRYPT_VERSION = " <<
		TMCG_LIBGCRYPT_VERSION << std::endl;
	std::cout << "TMCG_GCRY_MD_ALGO = " << TMCG_GCRY_MD_ALGO <<
		" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) << "]" << std::endl;
	init_libgcrypt();
	for (size_t i = 0; i < 5; i++)
	{
		mpz_set_ui(foo, mpz_srandom_ui()), mpz_set_ui(bar, mpz_ssrandom_ui());
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	}
	for (size_t i = 0; i < 100; i++)
	{
		mpz_srandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		std::cout << "log_2(foo) = " << mpz_sizeinbase(foo, 2L) << std::endl;
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		assert(!mpz_cmp(foo, bar));
	}
	for (size_t i = 0; i < 5; i++)
	{
		mpz_ssrandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		std::cout << "log_2(foo) = " << mpz_sizeinbase(foo, 2L) << std::endl;
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		assert(!mpz_cmp(foo, bar));
	}
	for (size_t i = 0; i < 100; i++)
	{
		mpz_srandomm(foo, bar);
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		assert(mpz_cmp(foo, bar) < 0);
	}
	for (size_t i = 0; i < 5; i++)
	{
		mpz_ssrandomm(foo, bar);
		std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
		assert(mpz_cmp(foo, bar) < 0);
	}
	
	mpz_sprime(foo, bar, 1023);
	std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	assert(mpz_probab_prime_p(foo, 25) && mpz_probab_prime_p(bar, 25));
	
	mpz_sprime2g(foo, bar, 1023);
	std::cout << step++ << ". foo = " << foo << ", bar = " << bar << std::endl;
	assert(mpz_probab_prime_p(foo, 25) && mpz_probab_prime_p(bar, 25) &&
		mpz_congruent_ui_p(foo, 7L, 8L));
	
	
	mpz_clear(foo), mpz_clear(bar);
	
	return 0;
}
