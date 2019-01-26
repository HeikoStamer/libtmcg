/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007, 
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

#include <exception>
#include <string>
#include <sstream>
#include <cassert>

#include "test_helper.h"

#ifdef BOTAN
	#include <botan/version.h>
#endif

#undef NDEBUG

#define MOD_BIAS_WIDTH 3
#define TEST_SSRANDOM

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	try
	{
		mpz_t foo, bar, foo2, bar2, root, t1, t2;
		mpz_t fpowm_table_1[TMCG_MAX_FPOWM_T], fpowm_table_2[TMCG_MAX_FPOWM_T];
		unsigned long int tmp_ui = 0L, cnt[MOD_BIAS_WIDTH];
		size_t cnt_zero = 0, cnt_one = 0;
		std::stringstream lej;
		std::string s;
		assert(init_libTMCG());
	
		std::cout << "version_libTMCG() = " << version_libTMCG() << std::endl;
		std::cout << "identifier_libTMCG() = " << identifier_libTMCG() <<
			std::endl;
		std::cout << "gmp_version = " << gmp_version << ", " << 
			"gcry_check_version() = " << gcry_check_version("0.0.0") <<
			std::endl;
#ifdef BOTAN
		std::cout << "Botan::version_string() = " << Botan::version_string() <<
			std::endl;
#endif
	
		mpz_init(foo), mpz_init(bar), mpz_init(foo2), mpz_init(bar2),
			mpz_init(root), mpz_init(t1), mpz_init(t2);
		std::cout << "TMCG_MPZ_IO_BASE = " << TMCG_MPZ_IO_BASE << std::endl;
		mpz_set_ui(foo, 42L), mpz_set_ui(bar, 0L);
		assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 0L));
		lej << foo << std::endl, lej >> bar;
		assert(!mpz_cmp_ui(foo, 42L) && !mpz_cmp_ui(bar, 42L));
	
		std::cout << "TMCG_LIBGMP_VERSION = " << TMCG_LIBGMP_VERSION <<
			std::endl;
		std::cout << "TMCG_LIBGCRYPT_VERSION = " <<
			TMCG_LIBGCRYPT_VERSION << std::endl;
		std::cout << "TMCG_GCRY_MD_ALGO = " << TMCG_GCRY_MD_ALGO <<
			" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) << "]" << std::endl;
	
		// convert (prime p of the Oakley Group 2) and check q = (p - 1) / 2;
		mpz_set_str(foo, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1C\
D129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A\
6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7\
EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
		mpz_set_str(bar, "1797693134862315907708391567937874531978602960\
487560117064444236841971802161585193689478337958649255415021805654859805\
036464405481992391000507928770033558166392295531362390765087357599148225\
748625750074253020774477125895509579377784244424266173347276292993876687\
09205606050270810842907692932019128194467627007", 10);
		assert(!mpz_cmp(foo, bar));
		assert(mpz_probab_prime_p(foo, 500));
		mpz_set_str(bar, "n0p2ftq59aofqlrjexdmhww37nsdo5636jq09opxoq8amv\
lodjflhsspl5jzlgnlg0brgm9w9sp68emaygiqx98q8sfvbnnqfr9hifq3bwoac8up5642bi\
6c4ohsg0lk9623r7y6j0m4yj3304o731yt2xooyxw5npftk5yn9fj3m26mjjku1mbn3405h4\
5cz8etbz", 36);
		mpz_sub_ui(foo, foo, 1L);
		mpz_fdiv_q_2exp(foo, foo, 1L);
		assert(!mpz_cmp(foo, bar));
		mpz_set_str(bar, "SUR8tvw7NPjVX77MA4wyYQcCRKLZetHWGRakKjG235flby\
eV3obS6ZdAliyTIVNwGjZ3pM73jsUA2RxCMfjHntG81euIBZgn8evIJRNvimC8aRh7ITAuU3\
soQSdQiIld2d9zstmKjMMpHgpyIK1yyfCO0C85WpMqUIUc368kdlRH", TMCG_MPZ_IO_BASE);
		assert(!mpz_cmp(foo, bar));
		assert(mpz_probab_prime_p(foo, 500));

		// print the diff and the LSB bias within mpz_srandomm
		size_t diffcnt[mpz_sizeinbase(bar, 2UL)];
		size_t lsbcnt[mpz_sizeinbase(bar, 2UL)];
		for (size_t i = 0; i < mpz_sizeinbase(bar, 2UL); i++)
			diffcnt[i] = 0, lsbcnt[i] = 0;
		for (size_t i = 0; i < 100000; i++)
		{
			size_t diffbf = 0;
			tmcg_mpz_srandomm(foo, bar);
			diffbf = mpz_sizeinbase(bar, 2UL) - mpz_sizeinbase(foo, 2UL);
			diffcnt[diffbf]++;
			for (size_t j = 0; j < mpz_sizeinbase(bar, 2UL); j++)
			{
				if (mpz_tstbit(foo, j))
					lsbcnt[j]++;
			}
		}
		std::cout << "tmcg_mpz_srandomm diffcnt = |";
		for (size_t i = 0; i < mpz_sizeinbase(bar, 2UL); i++)
			std::cout << diffcnt[i] << "|";
		std::cout << std::endl;
		std::cout << "tmcg_mpz_srandomm lsbcnt = |";
		for (size_t i = 0; i < mpz_sizeinbase(bar, 2UL); i++)
			std::cout << lsbcnt[i] << "|";
		std::cout << std::endl;
	
		// mpz_wrandom_ui vs. mpz_wrandom_mod
		std::cout << "tmcg_mpz_wrandom_ui() uniformity check / modulo bias" <<
			std::endl;
		for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
		    cnt[i] = 0;
		start_clock();
		for (size_t j = 0; j < 10; j++)
		{
		    for (size_t i = 0; i < (1000000 * MOD_BIAS_WIDTH); i++)
			cnt[tmcg_mpz_wrandom_ui() % MOD_BIAS_WIDTH]++;
		    for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
			std::cout << cnt[i] << " ";
		    std::cout << std::endl;
		}
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_wrandom_mod() uniformity check / modulo bias" <<
			std::endl;
		for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
		    cnt[i] = 0;
		start_clock();
		for (size_t j = 0; j < 10; j++)
		{
		    for (size_t i = 0; i < (1000000 * MOD_BIAS_WIDTH); i++)
			cnt[tmcg_mpz_wrandom_mod(MOD_BIAS_WIDTH)]++;
		    for (size_t i = 0; i < MOD_BIAS_WIDTH; i++)
			std::cout << cnt[i] << " ";
		    std::cout << std::endl;
		}
		stop_clock();
		std::cout << elapsed_time() << std::endl;
	
		// tmcg_mpz_*random_ui, tmcg_mpz_*randomb, tmcg_mpz_*randomm
		std::cout << "tmcg_mpz_wrandom_ui()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			tmp_ui = tmcg_mpz_wrandom_ui();
			mpz_set_ui(foo, tmp_ui);
			assert(mpz_get_ui(foo) == tmp_ui);
			assert(tmp_ui != tmcg_mpz_wrandom_ui());
		}
		std::cout << "tmcg_mpz_srandom_ui()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			tmp_ui = tmcg_mpz_srandom_ui();
			mpz_set_ui(foo, tmp_ui);
			assert(mpz_get_ui(foo) == tmp_ui);
			assert(tmp_ui != tmcg_mpz_wrandom_ui());
		}
#ifdef TEST_SSRANDOM
		std::cout << "tmcg_mpz_ssrandom_ui()" << std::endl;
		for (size_t i = 0; i < 3; i++)
		{
			tmp_ui = tmcg_mpz_ssrandom_ui();
			mpz_set_ui(foo, tmp_ui);
			assert(mpz_get_ui(foo) == tmp_ui);
			assert(tmp_ui != tmcg_mpz_wrandom_ui());
		}
#endif
		std::cout << "tmcg_mpz_wrandomb(..., 1L)" << std::endl;
		cnt_zero = 0, cnt_one = 0;
		for (size_t i = 0; i < 25; i++)
		{
			tmcg_mpz_wrandomb(foo, 1L), mpz_set_ui(bar, 0L);
			assert((mpz_sizeinbase(foo, 2L) == 1L));
			lej << foo << std::endl, lej >> bar;
			assert(!mpz_cmp(foo, bar));
			if (!mpz_cmp_ui(foo, 0L))
				cnt_zero++;
			if (!mpz_cmp_ui(foo, 1L))
				cnt_one++;
		}
		assert(cnt_zero > 0);
		assert(cnt_one > 0);
		std::cout << "tmcg_mpz_wrandomb()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_wrandomb(foo, 1024L), mpz_set_ui(bar, 0L);
			assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
				(mpz_sizeinbase(foo, 2L) <= 1024L));
			lej << foo << std::endl, lej >> bar;
			assert(!mpz_cmp(foo, bar));
			assert(mpz_cmp(foo, foo2));
		}
		std::cout << "tmcg_mpz_srandomb(..., 1L)" << std::endl;
		cnt_zero = 0, cnt_one = 0;
		for (size_t i = 0; i < 25; i++)
		{
			tmcg_mpz_srandomb(foo, 1L), mpz_set_ui(bar, 0L);
			assert((mpz_sizeinbase(foo, 2L) == 1L));
			lej << foo << std::endl, lej >> bar;
			assert(!mpz_cmp(foo, bar));
			if (!mpz_cmp_ui(foo, 0L))
				cnt_zero++;
			if (!mpz_cmp_ui(foo, 1L))
				cnt_one++;
		}
		assert(cnt_zero > 0);
		assert(cnt_one > 0);
		std::cout << "tmcg_mpz_srandomb()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_srandomb(foo, 1024L), mpz_set_ui(bar, 0L);
			assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
				(mpz_sizeinbase(foo, 2L) <= 1024L));
			lej << foo << std::endl, lej >> bar;
			assert(!mpz_cmp(foo, bar));
			assert(mpz_cmp(foo, foo2));
		}
#ifdef TEST_SSRANDOM
		std::cout << "tmcg_mpz_ssrandomb()" << std::endl;
		for (size_t i = 0; i < 3; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_ssrandomb(foo, 1024L), mpz_set_ui(bar, 0L);
			assert((mpz_sizeinbase(foo, 2L) >= 1008L) &&
				(mpz_sizeinbase(foo, 2L) <= 1024L));
			lej << foo << std::endl, lej >> bar;
			assert(!mpz_cmp(foo, bar));
			assert(mpz_cmp(foo, foo2));
		}
#endif
		std::cout << "bar = " << bar << std::endl;
		std::cout << "tmcg_mpz_wrandomm()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_wrandomm(foo, bar);
			assert(mpz_cmp(foo, bar) < 0);
			assert(mpz_cmp(foo, foo2));
		}
		std::cout << "tmcg_mpz_srandomm()" << std::endl;
		for (size_t i = 0; i < 25; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_srandomm(foo, bar);
			assert(mpz_cmp(foo, bar) < 0);
			assert(mpz_cmp(foo, foo2));
		}
#ifdef TEST_SSRANDOM
		std::cout << "tmcg_mpz_ssrandomm()" << std::endl;
		for (size_t i = 0; i < 3; i++)
		{
			mpz_set(foo2, foo);
			tmcg_mpz_ssrandomm(foo, bar);
			assert(mpz_cmp(foo, bar) < 0);
			assert(mpz_cmp(foo, foo2));
		}
#endif

		// mpz_ssrandomm_cache_init, mpz_ssrandomm_cache, mpz_ssrandomm_cache_done
		mpz_t cache[TMCG_MAX_SSRANDOMM_CACHE];
		mpz_t cache_mod;
		size_t cache_avail = 0, cache_n = 25;
#ifdef TEST_SSRANDOM
		std::cout << "tmcg_mpz_ssrandomm_cache_init()" << std::endl;
		tmcg_mpz_ssrandomm_cache_init(cache, cache_mod, cache_avail, cache_n, bar);
		assert(cache_avail == cache_n);
		std::cout << "tmcg_mpz_ssrandomm_cache()" << std::endl;
		for (size_t i = 0; i < cache_n; i++)
		{
			tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, foo, bar);
			assert(mpz_cmp(foo, bar) < 0);
			std::cout << foo << " (cached)" << std::endl;
		}
		assert(!cache_avail);
		tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, foo, bar);
		assert(mpz_cmp(foo, bar) < 0);
		std::cout << foo << " (not cached)" << std::endl;
		std::cout << "tmcg_mpz_ssrandomm_cache_done()" << std::endl;
		tmcg_mpz_ssrandomm_cache_done(cache, cache_mod, cache_avail);
		assert(!cache_avail);
#endif
	
		// tmcg_mpz_sprime, tmcg_mpz_sprime2g, tmcg_mpz_sprime3mod4
		std::cout << "tmcg_mpz_sprime(), tmcg_mpz_sprime2g()," <<
			" tmcg_mpz_sprime3mod4()" << std::endl;
		for (size_t i = 0; i < 2; i++)
		{
			tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64));
			mpz_mul_2exp(foo2, bar, 1L);
			mpz_add_ui(foo2, foo2, 1L);
			assert(!mpz_cmp(foo, foo2));
		
			tmcg_mpz_sprime2g(foo, bar, 1024, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64) &&
				mpz_congruent_ui_p(foo, 7L, 8L));
			mpz_mul_2exp(foo2, bar, 1L);
			mpz_add_ui(foo2, foo2, 1L);
			assert(!mpz_cmp(foo, foo2));
		
			tmcg_mpz_sprime3mod4(foo, 1024, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64) && mpz_congruent_ui_p(foo, 3L, 4L));
		}
	
		// tmcg_mpz_lprime
		std::cout << "tmcg_mpz_lprime()" << std::endl;
		for (size_t i = 0; i < 5; i++)
		{
			tmcg_mpz_lprime(foo, bar, bar2, 2048, 256, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64) && mpz_probab_prime_p(bar, 64));
			mpz_mul(foo2, bar, bar2);
			mpz_add_ui(foo2, foo2, 1L);
			assert(!mpz_cmp(foo, foo2));
			mpz_gcd(foo2, bar, bar2);
			assert(!mpz_cmp_ui(foo2, 1L));
		}
	
		// tmcg_mpz_oprime
		std::cout << "tmcg_mpz_oprime()" << std::endl;
		for (size_t i = 0; i < 5; i++)
		{
			tmcg_mpz_oprime(foo, 1024, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64));
		}

		// tmcg_mpz_oprime_noninc
		std::cout << "tmcg_mpz_oprime_noninc()" << std::endl;
		for (size_t i = 0; i < 5; i++)
		{
			tmcg_mpz_oprime_noninc(foo, 1024, TMCG_MR_ITERATIONS);
			assert(mpz_probab_prime_p(foo, 64));
		}

		// tmcg_mpz_s[m]prime[_naive|noninc] benchmark
		std::cout << "tmcg_mpz_sprime() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 25; i++)
			tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_smprime() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 25; i++)
			tmcg_mpz_smprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_sprime_naive() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 25; i++)
			tmcg_mpz_sprime_naive(foo, bar, 1024, TMCG_MR_ITERATIONS);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_sprime_noninc() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 25; i++)
		{
			tmcg_mpz_sprime_noninc(foo, bar, 1024, TMCG_MR_ITERATIONS);
			std::cout << "." << std::flush;
		}
		stop_clock();
		std::cout << std::endl << elapsed_time() << std::endl;

		// tmcg_mpz_sqrtmp_r vs. tmcg_mpz_sqrtmp benchmark
		do
			tmcg_mpz_oprime(foo, 1024, TMCG_MR_ITERATIONS);
		while (!mpz_congruent_ui_p(foo, 1L, 8L));
		tmcg_mpz_wrandomb(bar, 1024);
		mpz_mod(bar, bar, foo);
		std::cout << "tmcg_mpz_sqrtmp_r() benchmark" << std::endl;
		start_clock();
		mpz_set(bar2, bar);
		for (size_t i = 0; i < 1000; i++)
		{
			if (mpz_jacobi(bar2, foo) == 1)
				tmcg_mpz_sqrtmp_r(foo2, bar2, foo);
			mpz_add_ui(bar2, bar2, 1L);
		}
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_sqrtmp() benchmark" << std::endl;
		start_clock();
		mpz_set(bar2, bar);
		for (size_t i = 0; i < 1000; i++)
		{
			if (mpz_jacobi(bar2, foo) == 1)
				tmcg_mpz_sqrtmp(foo2, bar2, foo);
			mpz_add_ui(bar2, bar2, 1L);
		}
		stop_clock();
		std::cout << elapsed_time() << std::endl;
	
		// tmcg_mpz_spowm, tmcg_mpz_spowm_baseblind,
		// tmcg_mpz_spowm_init, tmcg_mpz_spowm_calc, tmcg_mpz_spowm_clear
		std::cout << "tmcg_mpz_spowm()" << std::endl;
		tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		for (size_t i = 0; i < 500; i++)
		{
			tmcg_mpz_srandomm(bar, foo), tmcg_mpz_srandomm(bar2, foo);
			tmcg_mpz_spowm(foo2, bar, bar2, foo);
			mpz_powm(bar, bar, bar2, foo);
			assert(!mpz_cmp(foo2, bar));
		}
		for (size_t i = 0; i < 500; i++)
		{
			// test negative exponents
			tmcg_mpz_srandomm(bar, foo), tmcg_mpz_srandomm(bar2, foo);
			mpz_neg(bar2, bar2);
			tmcg_mpz_spowm(foo2, bar, bar2, foo);
			mpz_powm(bar, bar, bar2, foo);
			assert(!mpz_cmp(foo2, bar));
		}
		std::cout << "tmcg_mpz_spowm_baseblind()" << std::endl;
		tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		for (size_t i = 0; i < 500; i++)
		{
			tmcg_mpz_srandomm(bar, foo), tmcg_mpz_srandomm(bar2, foo);
			tmcg_mpz_spowm_baseblind(foo2, bar, bar2, foo);
			mpz_powm(bar, bar, bar2, foo);
			assert(!mpz_cmp(foo2, bar));
		}
		for (size_t i = 0; i < 500; i++)
		{
			// test negative exponents
			tmcg_mpz_srandomm(bar, foo), tmcg_mpz_srandomm(bar2, foo);
			mpz_neg(bar2, bar2);
			tmcg_mpz_spowm_baseblind(foo2, bar, bar2, foo);
			mpz_powm(bar, bar, bar2, foo);
			assert(!mpz_cmp(foo2, bar));
		}
		std::cout << "tmcg_mpz_spowm_init(), tmcg_mpz_spowm_calc()," <<
			" tmcg_mpz_spowm_done()" << std::endl;
		for (size_t i = 0; i < 50; i++)
		{
			tmcg_mpz_srandomm(bar2, foo);
			tmcg_mpz_spowm_init(bar2, foo);
			for (size_t j = 0; j < 50; j++)
			{
				tmcg_mpz_srandomm(bar, foo);
				tmcg_mpz_spowm_calc(foo2, bar);
				mpz_powm(bar, bar, bar2, foo);
				assert(!mpz_cmp(foo2, bar));
			}
			tmcg_mpz_spowm_clear();
		}
	
		// tmcg_mpz_fpowm_init, tmcg_mpz_fpowm_precompute, tmcg_mpz_f(s)powm,
		// tmcg_mpz_fpowm_done
		std::cout << "tmcg_mpz_fpowm_init()" << std::endl;
		tmcg_mpz_fpowm_init(fpowm_table_1), tmcg_mpz_fpowm_init(fpowm_table_2);
		std::cout << "tmcg_mpz_fpowm_precompute()" << std::endl;
		mpz_set_ui(bar, 2L);
		tmcg_mpz_fpowm_precompute(fpowm_table_1, bar, foo, 1024);
		tmcg_mpz_srandomb(bar2, 1024);
		tmcg_mpz_fpowm_precompute(fpowm_table_2, bar2, foo, 1024);
		std::cout << "tmcg_mpz_fpowm(), tmcg_mpz_fspowm()" << std::endl;
		for (size_t i = 0; i < 150; i++)
		{
			tmcg_mpz_srandomb(foo2, 1024);
			mpz_powm(t1, bar, foo2, foo);
			tmcg_mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
			tmcg_mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
			assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
			mpz_powm(t1, bar2, foo2, foo);
			tmcg_mpz_fpowm(fpowm_table_2, t2, bar2, foo2, foo);
			tmcg_mpz_fspowm(fpowm_table_2, root, bar2, foo2, foo);
			assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
		}
		for (size_t i = 0; i < 150; i++)
		{
			// test negative exponents
			tmcg_mpz_srandomb(foo2, 1024);
			mpz_neg(foo2, foo2);
			mpz_powm(t1, bar, foo2, foo);
			tmcg_mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
			tmcg_mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
			assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
			mpz_powm(t1, bar2, foo2, foo);
			tmcg_mpz_fpowm(fpowm_table_2, t2, bar2, foo2, foo);
			tmcg_mpz_fspowm(fpowm_table_2, root, bar2, foo2, foo);
			assert(!mpz_cmp(t1, t2) && !mpz_cmp(t1, root));
		}
		std::cout << "tmcg_mpz_fpowm_done()" << std::endl;
		tmcg_mpz_fpowm_done(fpowm_table_1), tmcg_mpz_fpowm_done(fpowm_table_2);

		// mpz_powm vs. mpz_spowm vs. mpz_fpowm vs. mpz_fspowm benchmark
		std::cout << "mpz_powm() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 10000; i++)
		{
			tmcg_mpz_srandomb(foo2, 160);
			mpz_powm(t1, bar, foo2, foo);
		}
		stop_clock();
		save_clock();
		std::cout << elapsed_time() << std::endl;
		std::cout << "tmcg_mpz_spowm() benchmark" << std::endl;
		start_clock();
		for (size_t i = 0; i < 10000; i++)
		{
			tmcg_mpz_srandomb(foo2, 160);
			tmcg_mpz_spowm(t1, bar, foo2, foo);
		}
		stop_clock();
		std::cout << elapsed_time() << std::endl;

		// check whether spowm() is slower than powm()
		assert((compare_elapsed_time_saved(0) < 0));
		size_t bad_cnt = 0; 
		std::cout << "tmcg_mpz_fpowm() vs. tmcg_mpz_fspowm() benchmark" <<
			std::endl;
		for (size_t j = 0; j < 30; j++)
		{
			tmcg_mpz_fpowm_init(fpowm_table_1);
			tmcg_mpz_fpowm_precompute(fpowm_table_1, bar, foo, 160);
			start_clock();
			for (size_t i = 0; i < 10000; i++)
			{
				tmcg_mpz_srandomb(foo2, 160);
				tmcg_mpz_fpowm(fpowm_table_1, t2, bar, foo2, foo);
			}
			stop_clock();
			save_clock();
			std::cout << elapsed_time() << " vs. ";
			start_clock();
			for (size_t i = 0; i < 10000; i++)
			{
				tmcg_mpz_srandomb(foo2, 160);
				tmcg_mpz_fspowm(fpowm_table_1, root, bar, foo2, foo);
			}
			stop_clock();
			tmcg_mpz_fpowm_done(fpowm_table_1);
			std::cout << elapsed_time() << std::endl;
			if (compare_elapsed_time_saved(0) >= 0)
			{
				bad_cnt++;
				std::cout << "bad run - fspowm() is faster!" << std::endl;
			} 
		}
		// check whether fspowm() is slower than fpowm() for at least 2/3 runs
		assert(bad_cnt < 10);
	
		// tmcg_h, tmcg_g, tmcg_mpz_shash
		size_t dlen = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
		unsigned char tmp_ar1[1024], tmp_ar2[1024];
		std::cout << "tmcg_h()" << std::endl;
		unsigned char *dig1 = new unsigned char[dlen];
		unsigned char *dig2 = new unsigned char[dlen];
		for (size_t i = 0; i < 50; i++)
		{
			gcry_randomize(&tmp_ar1, sizeof(tmp_ar1), GCRY_STRONG_RANDOM);
			gcry_randomize(&tmp_ar2, sizeof(tmp_ar2), GCRY_STRONG_RANDOM);
			tmcg_h(dig1, tmp_ar1, sizeof(tmp_ar1));
			tmcg_h(dig2, tmp_ar2, sizeof(tmp_ar2));
			assert(memcmp(dig1, dig2, dlen));
			memcpy(tmp_ar2, tmp_ar1, sizeof(tmp_ar1));
			tmcg_h(dig2, tmp_ar2, sizeof(tmp_ar2));
			assert(!memcmp(dig1, dig2, dlen));
		}
		delete [] dig1, delete [] dig2;
		std::cout << "tmcg_g()" << std::endl;
		dig1 = new unsigned char[1024], dig2 = new unsigned char[1024];
		for (size_t i = 0; i < 50; i++)
		{
			gcry_randomize(&tmp_ar1, sizeof(tmp_ar1), GCRY_STRONG_RANDOM);
			tmcg_g(dig1, 1024, tmp_ar1, sizeof(tmp_ar1));
			tmcg_g(dig2, 1024, tmp_ar2, sizeof(tmp_ar2));
			assert(memcmp(dig1, dig2, dlen));
			memcpy(tmp_ar2, tmp_ar1, sizeof(tmp_ar1));
			tmcg_g(dig2, 1024, tmp_ar2, sizeof(tmp_ar2));
			assert(!memcmp(dig1, dig2, dlen));
		}
		delete [] dig1, delete [] dig2;
		std::cout << "tmcg_mpz_shash()" << std::endl;
		mpz_set_str(bar, "KlGMM70snzDNYXwufIkOkLZzs91jPNPe7QYT9Agfeg0",
			TMCG_MPZ_IO_BASE);
		mpz_set_ui(foo2, 23L), mpz_set_ui(bar2, 42L);
		tmcg_mpz_shash(foo, 2, foo2, bar2);
		assert(!mpz_cmp(foo, bar));
		mpz_set_str(bar, "caQFcUSBfXMGxXaZMMXp26QwN1vGcBYkhOz2DPgN6S8",
			TMCG_MPZ_IO_BASE);
		s = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		tmcg_mpz_shash(foo, s);
		assert(!mpz_cmp(foo, bar));
	
		// tmcg_mpz_qrmn_p, tmcg_mpz_sqrtmn_r, tmcg_mpz_sqrtmn
		std::cout << "tmcg_mpz_qrmn_p(), tmcg_mpz_sqrtmn_r()," <<
			" tmcg_mpz_sqrtmn()" << std::endl;
		tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
		tmcg_mpz_sprime(foo2, bar2, 1024, TMCG_MR_ITERATIONS);
		mpz_mul(bar, foo, foo2);
		for (size_t i = 0; i < 50; i++)
		{
			do
				tmcg_mpz_srandomm(bar2, bar);
			while (!tmcg_mpz_qrmn_p(bar2, foo, foo2));
			tmcg_mpz_sqrtmn_r(root, bar2, foo, foo2, bar);
			mpz_powm_ui(root, root, 2L, bar);
			assert(!mpz_cmp(root, bar2));
			tmcg_mpz_sqrtmn(root, bar2, foo, foo2, bar);
			mpz_powm_ui(root, root, 2L, bar);
			assert(!mpz_cmp(root, bar2));
		}

		// tmcg_mpz_get_gcry_mpi, tmcg_mpz_set_gcry_mpi
		std::cout << "tmcg_mpz_get_gcry_mpi(), tmcg_mpz_set_gcry_mpi()" <<
			std::endl;
		gcry_mpi_t a = gcry_mpi_new(256);
		tmcg_mpz_wrandomb(foo, 256L);
		assert(tmcg_mpz_get_gcry_mpi(a, foo));
		assert(tmcg_mpz_set_gcry_mpi(a, bar));
		gcry_mpi_release(a);
		assert(!mpz_cmp(foo, bar));
	
		// tmcg_interpolate_polynom
		std::cout << "tmcg_interpolate_polynom()" << std::endl;
		std::vector<mpz_ptr> aa, bb, ff;
		for (size_t k = 0; k < 8; k++)
		{
			mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
			mpz_init_set_ui(tmp1, k+5), mpz_init_set_ui(tmp2, (2*k)+3);
			mpz_init(tmp3);
			aa.push_back(tmp1), bb.push_back(tmp2), ff.push_back(tmp3);
		}
		mpz_set_ui(foo, 257L);
		mpz_set_str(bar, "42", TMCG_MPZ_IO_BASE);
		assert(tmcg_interpolate_polynom(aa, bb, foo, ff));
		for (size_t k = 0; k < ff.size(); k++)
			std::cout << "ff[" << k <<"]=" << ff[k] << " ";
		std::cout << std::endl;
		assert(!mpz_cmp(ff[0], bar));
		for (size_t k = 0; k < 8; k++)
		{
			mpz_clear(aa[k]), mpz_clear(bb[k]), mpz_clear(ff[k]);
			delete [] aa[k], delete [] bb[k], delete [] ff[k];
		}

		// release
		mpz_clear(foo), mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2),
			mpz_clear(root), mpz_clear(t1), mpz_clear(t2);
	
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() <<
			std::endl;
		return -1;
	}
}

