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

#include <string>
#include <sstream>
#include <cassert>

#include "test_helper.h"
#include <libTMCG.hh>

#undef NDEBUG

#define MOD_BIAS_WIDTH 3

int main
	(int argc, char **argv)
{
	mpz_t foo, bar, foo2, bar2, root, t1, t2;
	mpz_t fpowm_table_1[TMCG_MAX_FPOWM_T], fpowm_table_2[TMCG_MAX_FPOWM_T];
	char tmp_ar1[1024], tmp_ar2[1024];
	char *dig1, *dig2;
	unsigned long int tmp_ui = 0L, cnt[MOD_BIAS_WIDTH];
	std::stringstream lej;
	std::string s;
	assert(init_libTMCG());
	
	std::cout << "version_libTMCG() = " << version_libTMCG() << std::endl;
	std::cout << "gmp_version = " << gmp_version << ", " << 
		"gcry_check_version() = " << gcry_check_version("0.0.0") << std::endl;
	
	mpz_init(foo), mpz_init(bar), mpz_init(foo2), mpz_init(bar2),
		mpz_init(root), mpz_init(t1), mpz_init(t2);
	std::cout << "TMCG_MPZ_IO_BASE = " << TMCG_MPZ_IO_BASE << std::endl;
	mpz_set_ui(foo, 42L), mpz_set_ui(bar, 0L);
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 0L));
	lej << foo << std::endl, lej >> bar;
	assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 42L));
	
	std::cout << "TMCG_LIBGMP_VERSION = " << TMCG_LIBGMP_VERSION << std::endl;
	std::cout << "TMCG_LIBGCRYPT_VERSION = " <<
		TMCG_LIBGCRYPT_VERSION << std::endl;
	std::cout << "TMCG_GCRY_MD_ALGO = " << TMCG_GCRY_MD_ALGO <<
		" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) << "]" << std::endl;
	
	// convert (prime p of the Oakley Group 2)
	mpz_set_str(foo, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB\
5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
	mpz_set_str(bar, "179769313486231590770839156793787453197860296048756011706\
444423684197180216158519368947833795864925541502180565485980503646440548\
199239100050792877003355816639229553136239076508735759914822574862575007\
425302077447712589550957937778424442426617334727629299387668709205606050\
270810842907692932019128194467627007", 10);
	assert(!mpz_cmp(foo, bar));
	mpz_set_str(bar, "n0p2ftq59aofqlrjexdmhww37nsdo5636jq09opxoq8amvlodjflhsspl\
5jzlgnlg0brgm9w9sp68emaygiqx98q8sfvbnnqfr9hifq3bwoac8up5642bi6c4ohsg0lk9\
623r7y6j0m4yj3304o731yt2xooyxw5npftk5yn9fj3m26mjjku1mbn3405h45cz8etbz", 
		TMCG_MPZ_IO_BASE);
	mpz_sub_ui(foo, foo, 1L);
	mpz_fdiv_q_2exp(foo, foo, 1L);
	assert(!mpz_cmp(foo, bar));
	
	// mpz_wrandom_ui vs. mpz_wrandom_mod
	std::cout << "mpz_wrandom_ui() uniformity check / modulo bias" << std::endl;
	for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
	    cnt[i] = 0;
	start_clock();
	for (size_t j = 0; j < 10; j++)
	{
	    for (size_t i = 0; i < (1000000 * MOD_BIAS_WIDTH); i++)
		cnt[mpz_wrandom_ui() % MOD_BIAS_WIDTH]++;
	    for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
		std::cout << cnt[i] << " ";
	    std::cout << std::endl;
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_wrandom_mod() uniformity check / modulo bias" << std::endl;
	for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
	    cnt[i] = 0;
	start_clock();
	for (size_t j = 0; j < 10; j++)
	{
	    for (size_t i = 0; i < (1000000 * MOD_BIAS_WIDTH); i++)
		cnt[mpz_wrandom_mod(MOD_BIAS_WIDTH)]++;
	    for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
		std::cout << cnt[i] << " ";
	    std::cout << std::endl;
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	
	// mpz_*random_ui, mpz_*randomb, mpz_*randomm
	std::cout << "mpz_wrandom_ui()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		tmp_ui = mpz_wrandom_ui();
		mpz_set_ui(foo, tmp_ui);
		assert(mpz_get_ui(foo) == tmp_ui);
		assert(tmp_ui != mpz_wrandom_ui());
	}
	std::cout << "mpz_srandom_ui()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		tmp_ui = mpz_srandom_ui();
		mpz_set_ui(foo, tmp_ui);
		assert(mpz_get_ui(foo) == tmp_ui);
		assert(tmp_ui != mpz_wrandom_ui());
	}
#ifdef TEST_SSRANDOM
	std::cout << "mpz_ssrandom_ui()" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		tmp_ui = mpz_ssrandom_ui();
		mpz_set_ui(foo, tmp_ui);
		assert(mpz_get_ui(foo) == tmp_ui);
		assert(tmp_ui != mpz_wrandom_ui());
	}
#endif
	std::cout << "mpz_wrandomb()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		mpz_set(foo2, foo);
		mpz_wrandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		assert(!mpz_cmp(foo, bar));
		assert(mpz_cmp(foo, foo2));
	}
	std::cout << "mpz_srandomb()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		mpz_set(foo2, foo);
		mpz_srandomb(foo, 1024L), mpz_set_ui(bar, 0L);
		assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
			(mpz_sizeinbase(foo, 2L) <= 1024L));
		lej << foo << std::endl, lej >> bar;
		assert(!mpz_cmp(foo, bar));
		assert(mpz_cmp(foo, foo2));
	}
#ifdef TEST_SSRANDOM
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
#endif
	std::cout << "bar = " << bar << std::endl;
	std::cout << "mpz_wrandomm()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		mpz_set(foo2, foo);
		mpz_wrandomm(foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		assert(mpz_cmp(foo, foo2));
	}
	std::cout << "mpz_srandomm()" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		mpz_set(foo2, foo);
		mpz_srandomm(foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		assert(mpz_cmp(foo, foo2));
	}
#ifdef TEST_SSRANDOM
	std::cout << "mpz_ssrandomm()" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		mpz_set(foo2, foo);
		mpz_ssrandomm(foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		assert(mpz_cmp(foo, foo2));
	}
#endif
	
	// mpz_sprime, mpz_sprime2g, mpz_sprime3mod4
	std::cout << "mpz_sprime(), mpz_sprime2g(), mpz_sprime3mod4()" << std::endl;
	for (size_t i = 0; i < 2; i++)
	{
		mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64));
		mpz_mul_2exp(foo2, bar, 1L);
		mpz_add_ui(foo2, foo2, 1L);
		assert(!mpz_cmp(foo, foo2));
		
		mpz_sprime2g(foo, bar, 1024, TMCG_MR_ITERATIONS);
		assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64) &&
			mpz_congruent_ui_p(foo, 7L, 8L));
		mpz_mul_2exp(foo2, bar, 1L);
		mpz_add_ui(foo2, foo2, 1L);
		assert(!mpz_cmp(foo, foo2));
		
		mpz_sprime3mod4(foo, 1024, TMCG_MR_ITERATIONS);
		assert(mpz_probab_prime_p(foo, 64) && mpz_congruent_ui_p(foo, 3L, 4L));
	}
	
	// mpz_lprime
	std::cout << "mpz_lprime()" << std::endl;
	for (size_t i = 0; i < 5; i++)
	{
		mpz_lprime(foo, bar, bar2, 1024, 160, TMCG_MR_ITERATIONS);
		assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64));
		mpz_mul(foo2, bar, bar2);
		mpz_add_ui(foo2, foo2, 1L);
		assert(!mpz_cmp(foo, foo2));
		mpz_gcd(foo2, bar, bar2);
		assert(!mpz_cmp_ui(foo2, 1L));
	}
	
	// mpz_oprime
	std::cout << "mpz_oprime()" << std::endl;
	for (size_t i = 0; i < 5; i++)
	{
		mpz_oprime(foo, 1024, TMCG_MR_ITERATIONS);
		assert(mpz_probab_prime_p(foo, 64));
	}
	
	// mpz_sprime vs. mpz_sprime_naive benchmark
	std::cout << "mpz_sprime() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 50; i++)
		mpz_sprime(foo, bar, 512, TMCG_MR_ITERATIONS);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_sprime_naive() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 50; i++)
		mpz_sprime_naive(foo, bar, 512, TMCG_MR_ITERATIONS);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	
	// mpz_sqrtmp_r vs. mpz_sqrtmp benchmark
	do
		mpz_oprime(foo, 512, TMCG_MR_ITERATIONS);
	while (!mpz_congruent_ui_p(foo, 1L, 8L));
	mpz_wrandomb(bar, 512);
	mpz_mod(bar, bar, foo);
	std::cout << "mpz_sqrtmp_r() benchmark" << std::endl;
	start_clock();
	mpz_set(bar2, bar);
	for (size_t i = 0; i < 1000; i++)
	{
		if (mpz_jacobi(bar2, foo) == 1)
			mpz_sqrtmp_r(foo2, bar2, foo);
		mpz_add_ui(bar2, bar2, 1L);
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_sqrtmp() benchmark" << std::endl;
	start_clock();
	mpz_set(bar2, bar);
	for (size_t i = 0; i < 1000; i++)
	{
		if (mpz_jacobi(bar2, foo) == 1)
			mpz_sqrtmp(foo2, bar2, foo);
		mpz_add_ui(bar2, bar2, 1L);
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	
	// mpz_spowm, mpz_spowm_init, mpz_spowm_calc, mpz_spowm_clear
	std::cout << "mpz_spowm()" << std::endl;
	mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
	for (size_t i = 0; i < 5; i++)
	{
		mpz_srandomm(bar, foo), mpz_srandomm(bar2, foo);
		mpz_spowm(foo2, bar, bar2, foo);
		mpz_powm(bar, bar, bar2, foo);
		assert(!mpz_cmp(foo2, bar));
	}
	for (size_t i = 0; i < 5; i++)
	{
		// test negative exponents
		mpz_srandomm(bar, foo), mpz_srandomm(bar2, foo);
		mpz_neg(bar2, bar2);
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
	
	// mpz_fpowm_init, mpz_fpowm_precompute, mpz_f(s)powm, mpz_fpowm_done
	std::cout << "mpz_fpowm_init()" << std::endl;
	mpz_fpowm_init(fpowm_table_1), mpz_fpowm_init(fpowm_table_2);
	std::cout << "mpz_fpowm_precompute()" << std::endl;
	mpz_set_ui(bar, 2L);
	mpz_fpowm_precompute(fpowm_table_1, bar, foo, 1024);
	mpz_srandomb(bar2, 1024);
	mpz_fpowm_precompute(fpowm_table_2, bar2, foo, 1024);
	std::cout << "mpz_fpowm(), mpz_fspowm()" << std::endl;
	for (size_t i = 0; i < 15; i++)
	{
		mpz_srandomb(foo2, 1024);
		mpz_powm(t1, bar, foo2, foo);
		mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
		mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
		assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
		mpz_powm(t1, bar2, foo2, foo);
		mpz_fpowm(fpowm_table_2, t2, bar2, foo2, foo);
		mpz_fspowm(fpowm_table_2, root, bar2, foo2, foo);
		assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
	}
	for (size_t i = 0; i < 15; i++)
	{
		// test negative exponents
		mpz_srandomb(foo2, 1024);
		mpz_neg(foo2, foo2);
		mpz_powm(t1, bar, foo2, foo);
		mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
		mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
		assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
		mpz_powm(t1, bar2, foo2, foo);
		mpz_fpowm(fpowm_table_2, t2, bar2, foo2, foo);
		mpz_fspowm(fpowm_table_2, root, bar2, foo2, foo);
		assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
	}
	std::cout << "mpz_fpowm_done()" << std::endl;
	mpz_fpowm_done(fpowm_table_1), mpz_fpowm_done(fpowm_table_2);
	
	// mpz_powm vs. mpz_fpowm vs. mpz_fspowm benchmark
	std::cout << "mpz_powm() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 1000; i++)
	{
		mpz_srandomb(foo2, 160);
		mpz_powm(t1, bar, foo2, foo);
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_fpowm() benchmark" << std::endl;
	mpz_fpowm_init(fpowm_table_1);
	mpz_fpowm_precompute(fpowm_table_1, bar, foo, 160);
	start_clock();
	for (size_t i = 0; i < 1000; i++)
	{
		mpz_srandomb(foo2, 160);
		mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_spowm() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 1000; i++)
	{
		mpz_srandomb(foo2, 160);
		mpz_spowm(t1, bar, foo2, foo);
	}
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	std::cout << "mpz_fspowm() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 1000; i++)
	{
		mpz_srandomb(foo2, 160);
		mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
	}
	stop_clock();
	mpz_fpowm_done(fpowm_table_1);
	std::cout << elapsed_time() << std::endl;
	
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
	
	// mpz_qrmn_p, mpz_sqrtmn_r, mpz_sqrtmn
	std::cout << "mpz_qrmn_p(), mpz_sqrtmn_r(), mpz_sqrtmn()" << std::endl;
	mpz_sprime(foo, bar, 512, TMCG_MR_ITERATIONS);
	mpz_sprime(foo2, bar2, 512, TMCG_MR_ITERATIONS);
	mpz_mul(bar, foo, foo2);
	for (size_t i = 0; i < 5; i++)
	{
		do
			mpz_srandomm(bar2, bar);
		while (!mpz_qrmn_p(bar2, foo, foo2, bar));
		mpz_sqrtmn_r(root, bar2, foo, foo2, bar);
		mpz_powm_ui(root, root, 2L, bar);
		assert(!mpz_cmp(root, bar2));
		mpz_sqrtmn(root, bar2, foo, foo2, bar);
		mpz_powm_ui(root, root, 2L, bar);
		assert(!mpz_cmp(root, bar2));
	}
	
	mpz_clear(foo), mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2),
		mpz_clear(root), mpz_clear(t1), mpz_clear(t2);
	
	return 0;
}
