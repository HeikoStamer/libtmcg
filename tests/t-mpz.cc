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
	mpz_t foo, bar, foo2, bar2, root;
	char tmp_ar1[1024], tmp_ar2[1024];
	char *dig1, *dig2;
	unsigned long int tmp_ui = 0L;
	std::stringstream lej;
	std::string s;
	assert(init_libTMCG());
	
	mpz_init(foo), mpz_init(bar), mpz_init(foo2), mpz_init(bar2), mpz_init(root);
	std::cout << "TMCG_MPZ_IO_BASE = " << TMCG_MPZ_IO_BASE << std::endl;
	mpz_set_ui(foo, 42L), mpz_set_ui(bar, 0L);
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 0L));
	lej << foo << std::endl, lej >> bar;
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 42L));
	
	std::cout << "TMCG_LIBGCRYPT_VERSION = " <<
		TMCG_LIBGCRYPT_VERSION << std::endl;
	std::cout << "TMCG_GCRY_MD_ALGO = " << TMCG_GCRY_MD_ALGO <<
		" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) << "]" << std::endl;
	
	// mpz_srandom_ui, mpz_srandomb, mpz_ssrandomb, mpz_srandomm, mpz_ssrandomm
	std::cout << "mpz_srandom_ui(), mpz_ssrandom_ui()" << std::endl;
	for (size_t i = 0; i < 50; i++)
	{
		tmp_ui = mpz_srandom_ui();
		mpz_set_ui(foo, tmp_ui);
		assert(mpz_get_ui(foo) == tmp_ui);
		assert(tmp_ui != mpz_srandom_ui());
	}
	for (size_t i = 0; i < 3; i++)
	{
		tmp_ui = mpz_ssrandom_ui();
		mpz_set_ui(foo, tmp_ui);
		assert(mpz_get_ui(foo) == tmp_ui);
		assert(tmp_ui != mpz_srandom_ui());
	}
	std::cout << "mpz_srandomb()" << std::endl;
	for (size_t i = 0; i < 50; i++)
	{
		mpz_set(foo2, foo);
		mpz_srandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		assert(!mpz_cmp(foo, bar));
		assert(mpz_cmp(foo, foo2));
	}
	std::cout << "mpz_ssrandomb()" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		mpz_set(foo2, foo);
		mpz_ssrandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		assert(!mpz_cmp(foo, bar));
		assert(mpz_cmp(foo, foo2));
	}
	std::cout << "mpz_srandomm()" << std::endl;
	for (size_t i = 0; i < 50; i++)
	{
		mpz_set(foo2, foo);
		mpz_srandomm(foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		assert(mpz_cmp(foo, foo2));
	}
	std::cout << "mpz_ssrandomm()" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		mpz_set(foo2, foo);
		mpz_ssrandomm(foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		assert(mpz_cmp(foo, foo2));
	}
	
	// mpz_sprime, mpz_sprime2g
	std::cout << "mpz_sprime(), mpz_sprime2g(), mpz_sprime3mod4()" << std::endl;
	for (size_t i = 0; i < 2; i++)
	{
		mpz_sprime(foo, bar, 1024);
		assert(mpz_probab_prime_p(foo, 25) && mpz_probab_prime_p(bar, 25));
		
		mpz_sprime2g(foo, bar, 1024);
		assert(mpz_probab_prime_p(foo, 25) && mpz_probab_prime_p(bar, 25) &&
			mpz_congruent_ui_p(foo, 7L, 8L));
		
		mpz_sprime3mod4(foo, 1024);
		assert(mpz_probab_prime_p(foo, 25) && mpz_congruent_ui_p(foo, 3L, 4L));
	}
	
	// mpz_spowm, mpz_spowm_init, mpz_spowm_calc, mpz_spowm_clear
	std::cout << "mpz_spowm()" << std::endl;
	for (size_t i = 0; i < 5; i++)
	{
		mpz_srandomm(bar, foo), mpz_srandomm(bar2, foo);
		mpz_spowm(foo2, bar, bar2, foo);
		mpz_powm(bar, bar, bar2, foo);
		assert(!mpz_cmp(foo2, bar));
	}
	std::cout << "mpz_spowm_init(), mpz_spowm_calc(), mpz_spowm_done()" <<
		std::endl;
	for (size_t i = 0; i < 5; i++)
	{
		mpz_srandomm(bar2, foo);
		mpz_spowm_init(bar2, foo);
		for (size_t j = 0; j < 5; j++)
		{
			mpz_srandomm(bar, foo);
			mpz_spowm_calc(foo2, bar);
			mpz_powm(bar, bar, bar2, foo);
			assert(!mpz_cmp(foo2, bar));
		}
		mpz_spowm_clear();
	}
	
	// h, g, mpz_shash
	std::cout << "h()" << std::endl;
	dig1 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
	dig2 = new char[gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)];
	for (size_t i = 0; i < 5; i++)
	{
		gcry_randomize((unsigned char *)&tmp_ar1, sizeof(tmp_ar1),
			GCRY_STRONG_RANDOM);
		h(dig1, tmp_ar1, sizeof(tmp_ar1));
		h(dig2, tmp_ar2, sizeof(tmp_ar2));
		assert(memcmp(dig1, dig2, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)));
		memcpy(tmp_ar2, tmp_ar1, sizeof(tmp_ar1));
		h(dig2, tmp_ar2, sizeof(tmp_ar2));
		assert(!memcmp(dig1, dig2, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)));
	}
	delete [] dig1, delete [] dig2;
	std::cout << "g()" << std::endl;
	dig1 = new char[1024], dig2 = new char[1024];
	for (size_t i = 0; i < 5; i++)
	{
		gcry_randomize((unsigned char *)&tmp_ar1, sizeof(tmp_ar1),
			GCRY_STRONG_RANDOM);
		g(dig1, 1024, tmp_ar1, sizeof(tmp_ar1));
		g(dig2, 1024, tmp_ar2, sizeof(tmp_ar2));
		assert(memcmp(dig1, dig2, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)));
		memcpy(tmp_ar2, tmp_ar1, sizeof(tmp_ar1));
		g(dig2, 1024, tmp_ar2, sizeof(tmp_ar2));
		assert(!memcmp(dig1, dig2, gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO)));
	}
	delete [] dig1, delete [] dig2;
	std::cout << "mpz_shash()" << std::endl;
	mpz_set_str(bar, "d2uipbaz3k3o4irzhyhfj5pfzjl7nvs", 36);
	mpz_set_ui(foo2, 23L), mpz_set_ui(bar2, 42L);
	mpz_shash(foo, 2, foo2, bar2);
	assert(!mpz_cmp(foo, bar));
	mpz_set_str(bar, "e0mlbyryzvl4ho7glw6166ow8faqegj", 36);
	s = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	mpz_shash(foo, s);
	assert(!mpz_cmp(foo, bar));
	
	// mpz_qrmn_p, mpz_sqrtmn_r
	std::cout << "mpz_qrmn_p(), mpz_sqrtmn_r()" << std::endl;
	mpz_sprime(foo, bar, 512), mpz_sprime(foo2, bar2, 512);
	mpz_mul(bar, foo, foo2);
	for (size_t i = 0; i < 5; i++)
	{
		do
			mpz_srandomm(bar2, bar);
		while (!mpz_qrmn_p(bar2, foo, foo2, bar));
		mpz_sqrtmn_r(root, bar2, foo, foo2, bar);
		mpz_powm_ui(root, root, 2L, bar);
		assert(!mpz_cmp(root, bar2));
	}
	
	mpz_clear(foo), mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2),
		mpz_clear(root);
	
	return 0;
}
