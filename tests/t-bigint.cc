/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

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
	assert(init_libTMCG(true));
	std::cout << "version_libTMCG() = " << version_libTMCG() << std::endl;
	std::cout << "identifier_libTMCG() = " << identifier_libTMCG() << std::endl;
	std::cout << "gmp_version = " << gmp_version << ", " << 
		"gcry_check_version() = " << gcry_check_version("0.0.0") << std::endl;
#ifdef BOTAN
	std::cout << "Botan::version_string() = " << Botan::version_string() <<
		std::endl;
#endif
	std::cout << "TMCG_MPZ_IO_BASE = " << TMCG_MPZ_IO_BASE << std::endl;
	std::cout << "TMCG_LIBGMP_VERSION = " << TMCG_LIBGMP_VERSION << std::endl;
	std::cout << "TMCG_LIBGCRYPT_VERSION = " <<
		TMCG_LIBGCRYPT_VERSION << std::endl;
	std::cout << "TMCG_GCRY_MD_ALGO = " << TMCG_GCRY_MD_ALGO <<
		" [" << gcry_md_algo_name(TMCG_GCRY_MD_ALGO) << "]" << std::endl;

	// test basic operators of TMCG_Bigint()
	TMCG_Bigint foo, bar, baz;
	std::stringstream lej;
	std::cout << "TMCG_Bigint()" << std::endl;
	foo = 42UL, bar = -42L;
	std::cout << " ::operator <<" << std::endl;
	lej << foo << std::endl, lej >> baz;
	std::cout << " ::operator ==" << std::endl;
	assert((foo == baz) && !(foo == bar));
	std::cout << " ::operator == (unsigned long int)" << std::endl;
	assert((foo == 42UL));
	std::cout << " ::operator == (signed long int)" << std::endl;
	assert((bar == -42L));
	std::cout << " ::operator !=" << std::endl;
	assert((foo != bar) && !(foo != baz));
	std::cout << " ::operator != (sigend long int)" << std::endl;
	assert((bar != 42L) && (baz != -42L));
	std::cout << " ::operator >" << std::endl;
	assert ((foo > bar));
	std::cout << " ::operator > (unsigned long int)" << std::endl;
	assert ((foo > 41UL) && !(foo > 42UL));
	std::cout << " ::operator <" << std::endl;
	assert ((bar < foo));
	std::cout << " ::operator < (unsigned long int)" << std::endl;
	assert ((foo < 43UL) && !(foo < 42UL));
	std::cout << " ::operator >=" << std::endl;
	assert ((foo >= bar));
	std::cout << " ::operator >= (unsigned long int)" << std::endl;
	assert ((foo >= 42UL) && !(foo >= 43UL));
	std::cout << " ::operator <=" << std::endl;
	assert ((bar <= foo));
	std::cout << " ::operator <= (unsigned long int)" << std::endl;
	assert ((foo <= 42UL) && !(foo <= 41UL));
	std::cout << " ::operator +=" << std::endl;
	baz += bar;
	assert((baz == 0L));
	std::cout << " ::operator += (unsigned long int)" << std::endl;
	baz += 7UL;
	assert((baz == 7L));
	std::cout << " ::operator -=" << std::endl;
	foo -= bar;
	assert((foo == 84L));
	std::cout << " ::operator -= (unsigned long int)" << std::endl;
	foo -= 1UL;
	assert((foo == 83L));
	std::cout << " ::operator *=" << std::endl;
	baz *= foo;
	assert((baz == 581L));
	std::cout << " ::operator *= (unsigned long int)" << std::endl;
	baz *= 3UL;
	assert((baz == 1743L));
	std::cout << " ::operator /=" << std::endl;
	bar = 83UL;
	baz /= bar;
	assert((baz == 21L));
	baz = 1743UL;
	std::cout << " ::operator /= (unsigned long int)" << std::endl;
	baz /= 7UL;
	assert((baz == 249L));
	std::cout << " ::operator %=" << std::endl;
	bar = 248L;
	baz %= bar;
	assert((baz == 1L));
	std::cout << " ::operator %= (unsigned long int)" << std::endl;
	baz = 1743UL;
	baz %= 42UL;
	assert((baz == 21L));
	std::cout << " ::operator - (negation)" << std::endl;
	-foo;
	assert((foo == -83L));
	std::cout << " ::abs()" << std::endl;
	foo.abs();
	assert((foo == 83L));
	std::cout << " ::mul2exp()" << std::endl;
	foo.mul2exp(2UL);
	assert((foo == 332L));
	std::cout << " ::get_ui()" << std::endl;
	assert((foo.get_ui() == 332));
	std::cout << " ::size(10)" << std::endl;
	assert((foo.size(10) == 3));
	// convert (prime p of the Oakley Group 2) and check q = (p - 1) / 2;
	std::cout << " ::set_str(), ::probab_prime(), ::div2exp()" << std::endl;
	foo.set_str("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB\
5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
	bar.set_str("179769313486231590770839156793787453197860296048756011706\
444423684197180216158519368947833795864925541502180565485980503646440548\
199239100050792877003355816639229553136239076508735759914822574862575007\
425302077447712589550957937778424442426617334727629299387668709205606050\
270810842907692932019128194467627007", 10);
	assert((foo == bar));
	assert(foo.probab_prime());
	bar.set_str("n0p2ftq59aofqlrjexdmhww37nsdo5636jq09opxoq8amvlodjflhsspl\
5jzlgnlg0brgm9w9sp68emaygiqx98q8sfvbnnqfr9hifq3bwoac8up5642bi6c4ohsg0lk9\
623r7y6j0m4yj3304o731yt2xooyxw5npftk5yn9fj3m26mjjku1mbn3405h45cz8etbz", 36);
	foo -= 1UL;
	foo.div2exp(1UL);
	assert((foo == bar));
	bar.set_str("SUR8tvw7NPjVX77MA4wyYQcCRKLZetHWGRakKjG235flbyeV3obS6ZdAl\
iyTIVNwGjZ3pM73jsUA2RxCMfjHntG81euIBZgn8evIJRNvimC8aRh7ITAuU3soQSdQiIld2d\
9zstmKjMMpHgpyIK1yyfCO0C85WpMqUIUc368kdlRH", TMCG_MPZ_IO_BASE);
	assert((foo == bar));
	assert(foo.probab_prime());

	// test basic operators of TMCG_Bigint(true)
	TMCG_Bigint sfoo(true, true), sbar(true, true), sbaz(true, true);
	std::cout << "TMCG_Bigint(true)" << std::endl;
	sbar = sfoo; // == 0
	sbaz += 42UL;
	std::cout << " ::operator ==" << std::endl;
	assert((sfoo == sbar) && !(sfoo == sbaz));
	std::cout << " ::operator !=" << std::endl;
	assert((sfoo != sbaz) && !(sfoo != sbar));
	std::cout << " ::operator >" << std::endl;
	assert((sbaz > sfoo) && !(sfoo > sbar));
	std::cout << " ::operator <" << std::endl;
	assert((sfoo < sbaz) && !(sfoo < sbar));
	std::cout << " ::operator >=" << std::endl;
	assert((sbaz >= sfoo) && (sfoo >= sbar) && !(sfoo >= sbaz));
	std::cout << " ::operator <=" << std::endl;
	assert((sfoo <= sbaz) && (sfoo <= sbar) && !(sbaz <= sfoo));
	std::cout << " ::operator +=" << std::endl;
	sfoo += sbar;
	assert((sfoo == sbar));
	sfoo += sbaz;
	assert((sfoo > sbar) && (sfoo == sbaz));
	std::cout << " ::operator += (unsigned long int)" << std::endl;
	sfoo = 0UL;
	sfoo += 7UL;
	assert((sfoo != sbar) && (sfoo < sbaz));
	std::cout << " ::operator - (negation)" << std::endl;
	-sfoo; // == -7
	assert((sfoo < sbar));
	std::cout << " ::operator -=" << std::endl;
	sbaz = sfoo; // == -7
	sfoo -= sbaz; // == -0
	-sfoo; // == 0;
#if GCRYPT_VERSION_NUMBER < 0x010806
std::cerr << "libgcrypt BUG: negative zero -- remove if fixed" << std::endl;
gcry_mpi_t a = gcry_mpi_new(1), b = gcry_mpi_new(1);
gcry_mpi_set_ui(a, 42UL), gcry_mpi_set_ui(b, 42UL); // a = +42, b = +42
gcry_mpi_neg(a, a), gcry_mpi_neg(b, b); // a = -42, b = -42
gcry_mpi_sub(a, a, b); // a = -0, b = -42
gcry_mpi_set_ui(b, 0UL); // a = -0, b = +0 
assert(gcry_mpi_cmp(a, b)); // SHOULD fail
gcry_mpi_release(a), gcry_mpi_release(b);
std::cerr << "sfoo = " << sfoo << " sbar = " << sbar << " sbaz = " << sbaz << std::endl;
#endif
	assert((sfoo == sbar) && (sfoo > sbaz));
	std::cout << " ::operator -= (unsigned long int)" << std::endl;
	sfoo -= 7UL;
	assert((sfoo < sbar) && (sfoo == sbaz));
	std::cout << " ::abs()" << std::endl;
	sfoo.abs();
	assert((sfoo > sbar));
	sbar = sfoo;
	std::cout << " ::mul2exp()" << std::endl;
	sfoo.mul2exp(2UL);
	assert(sfoo > sbar);
	sfoo = 7UL;
	std::cout << " ::get_ui()" << std::endl;
	assert((sfoo.get_ui() == 7));
	std::cout << " ::probab_prime()" << std::endl;
	assert(sfoo.probab_prime());
	sfoo += 1UL;
	assert(!sfoo.probab_prime());
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.srandomb(1024);
		if (gcry_prime_check(sfoo.secret_bigint, 64) == 0)
			assert(sfoo.probab_prime());
		else
			assert(!sfoo.probab_prime());
	}

	// tmcg_mpz_*randomb, tmcg_mpz_*randomm
	std::cout << "TMCG_Bigint()" << std::endl;
	unsigned long int tmp_ui = 0UL;
	size_t cnt_zero = 0, cnt_one = 0;
	std::cout << " ::wrandomb(32)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		foo.wrandomb(32);
		assert((tmp_ui != foo.get_ui()));
		tmp_ui = foo.get_ui();
	}
	std::cout << " ::srandomb(32)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		foo.srandomb(32);
		assert((tmp_ui != foo.get_ui()));
		tmp_ui = foo.get_ui();
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomb(32)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		foo.ssrandomb(32);
		assert((tmp_ui != foo.get_ui()));
		tmp_ui = foo.get_ui();
	}
#endif
	std::cout << " ::wrandomb(1)" << std::endl;
	cnt_zero = 0, cnt_one = 0;
	for (size_t i = 0; i < 25; i++)
	{
		foo.wrandomb(1), bar = 0UL;
		assert((foo.size(2) == 1));
		lej << foo << std::endl, lej >> bar;
		assert((foo == bar));
		if (foo == 0L)
			cnt_zero++;
		if (foo == 1L)
			cnt_one++;
	}
	assert((cnt_zero > 0));
	assert((cnt_one > 0));
	std::cout << " ::wrandomb(1024)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		baz = foo;
		foo.wrandomb(1024), bar = 0UL;
		assert((foo.size(2) >= 1008) && (foo.size(2) <= 1024));
		lej << foo << std::endl, lej >> bar;
		assert((foo == bar));
		assert((foo != baz));
	}
	std::cout << " ::srandomb(1)" << std::endl;
	cnt_zero = 0, cnt_one = 0;
	for (size_t i = 0; i < 25; i++)
	{
		foo.srandomb(1), bar = 0UL;
		assert((foo.size(2) == 1));
		lej << foo << std::endl, lej >> bar;
		assert((foo == bar));
		if (foo == 0L)
			cnt_zero++;
		if (foo == 1L)
			cnt_one++;
	}
	assert((cnt_zero > 0));
	assert((cnt_one > 0));
	std::cout << " ::srandomb(1024)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		baz = foo;
		foo.srandomb(1024), bar = 0UL;
		assert((foo.size(2) >= 1008) && (foo.size(2) <= 1024));
		lej << foo << std::endl, lej >> bar;
		assert((foo == bar));
		assert((foo != baz));
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomb(1024)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		baz = foo;
		foo.ssrandomb(1024), bar = 0UL;
		assert((foo.size(2) >= 1008) && (foo.size(2) <= 1024));
		lej << foo << std::endl, lej >> bar;
		assert((foo == bar));
		assert((foo != baz));
	}
#endif
	std::cout << " ::wrandomm(bar)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		baz = foo;
		foo.wrandomm(bar);
		assert((foo < bar));
		assert((foo != baz));
	}
	std::cout << " ::srandomm(bar)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		baz = foo;
		foo.srandomm(bar);
		assert((foo < bar));
		assert((foo != baz));
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomm(bar)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		baz = foo;
		foo.ssrandomm(bar);
		assert((foo < bar));
		assert((foo != baz));
	}
#endif
	std::cout << "TMCG_Bigint(true)" << std::endl;
	std::cout << " ::wrandomb(32)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.wrandomb(32);
		sbar.wrandomb(32);
		assert((sfoo != sbar));
	}
	std::cout << " ::srandomb(32)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.srandomb(32);
		sbar.srandomb(32);
		assert((sfoo != sbar));
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomb(32)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		sfoo.ssrandomb(32);
		sbar.ssrandomb(32);
		assert((sfoo != sbar));
	}
#endif
	std::cout << " ::wrandomb(1)" << std::endl;
	sbaz = 0UL;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.wrandomb(1);
		assert((sfoo.size(2) < 2));
		sbaz += sfoo;
	}
	assert((sbaz > 0UL));
	assert((sbaz < 25UL));
	std::cout << " ::wrandomb(1024)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.wrandomb(1024);
		assert((sfoo.size(2) >= 1008) && (sfoo.size(2) <= 1024));
	}
	std::cout << " ::srandomb(1)" << std::endl;
	sbaz = 0UL;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.srandomb(1);
		assert((sfoo.size(2) < 2));
		sbaz += sfoo;
	}
	assert((sbaz > 0UL));
	assert((sbaz < 25UL));
	std::cout << " ::srandomb(1024)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.srandomb(1024);
		assert((sfoo.size(2) >= 1008) && (sfoo.size(2) <= 1024));
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomb(1024)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		sfoo.ssrandomb(1024);
		assert((sfoo.size(2) >= 1008) && (sfoo.size(2) <= 1024));
	}
#endif
	sbaz = bar;
	std::cout << " ::wrandomm(bar)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.wrandomm(sbaz);
		sbar.wrandomm(sbaz);
		assert((sfoo < sbaz) && (sbar < sbaz));
		assert((sfoo != sbar));
	}
	std::cout << " ::srandomm(bar)" << std::endl;
	for (size_t i = 0; i < 25; i++)
	{
		sfoo.srandomm(bar);
		sbar.srandomm(bar);
		assert((sfoo < sbaz) && (sbar < sbaz));
		assert((sfoo != sbar));
	}
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomm(bar)" << std::endl;
	for (size_t i = 0; i < 3; i++)
	{
		sfoo.ssrandomm(bar);
		sbar.ssrandomm(bar);
		assert((sfoo < sbaz) && (sbar < sbaz));
		assert((sfoo != sbar));
	}
#endif

	// mpz_ssrandomm_cache_init, mpz_ssrandomm_cache, mpz_ssrandomm_cache_done
	size_t cache_n = 5;
	bar = 42UL;
	std::cout << "TMCG_Bigint()" << std::endl;
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomm_cache_init()" << std::endl;
	foo.ssrandomm_cache_init(bar, cache_n);
	std::cout << " ::ssrandomm_cache()" << std::endl;
	for (size_t i = 0; i < cache_n; i++)
	{
		foo.ssrandomm_cache();
		assert((foo < bar));
		std::cout << "   " << foo << " (cached)" << std::endl;
	}
	assert((foo.ssrandomm_cache_avail == 0));
	foo.ssrandomm_cache();
	assert((foo < bar));
	std::cout << "   " << foo << " (not cached)" << std::endl;
	std::cout << " ::ssrandomm_cache_done()" << std::endl;
	foo.ssrandomm_cache_done();
	assert((foo.ssrandomm_cache_avail == 0));
#endif
	sbar = 42UL;
	std::cout << "TMCG_Bigint(true)" << std::endl;
#ifdef TEST_SSRANDOM
	std::cout << " ::ssrandomm_cache_init()" << std::endl;
	sfoo.ssrandomm_cache_init(bar, cache_n);
	std::cout << " ::ssrandomm_cache()" << std::endl;
	for (size_t i = 0; i < cache_n; i++)
	{
		sfoo.ssrandomm_cache();
		assert((sfoo < sbar));
		std::cout << "   " << sfoo << " (cached)" << std::endl;
	}
	assert((sfoo.ssrandomm_cache_avail == 0));
	sfoo.ssrandomm_cache();
	assert((sfoo < sbar));
	std::cout << "   " << sfoo << " (not cached)" << std::endl;
	std::cout << " ::ssrandomm_cache_done()" << std::endl;
	sfoo.ssrandomm_cache_done();
	assert((sfoo.ssrandomm_cache_avail == 0));
#endif


/*
	mpz_t foo, bar, foo2, bar2, root, t1, t2;
	mpz_t fpowm_table_1[TMCG_MAX_FPOWM_T], fpowm_table_2[TMCG_MAX_FPOWM_T];
	unsigned long int tmp_ui = 0L, cnt[MOD_BIAS_WIDTH];
	size_t cnt_zero = 0, cnt_one = 0;
	std::string s;
	


	
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

	// tmcg_mpz_sprime vs. tmcg_mpz_sprime_naive vs. tmcg_mpz_sprime_noninc
	std::cout << "tmcg_mpz_sprime() benchmark" << std::endl;
	start_clock();
	for (size_t i = 0; i < 25; i++)
		tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
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
	std::cout << "tmcg_mpz_fpowm() vs. tmcg_mpz_fspowm() benchmark" << std::endl;
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
	// check whether fspowm() is slower than fpowm() for at least 2/3 of runs
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
	mpz_set_str(bar, "KlGMM70snzDNYXwufIkOkLZzs91jPNPe7QYT9Agfeg0", TMCG_MPZ_IO_BASE);
	mpz_set_ui(foo2, 23L), mpz_set_ui(bar2, 42L);
	tmcg_mpz_shash(foo, 2, foo2, bar2);
	assert(!mpz_cmp(foo, bar));
	mpz_set_str(bar, "caQFcUSBfXMGxXaZMMXp26QwN1vGcBYkhOz2DPgN6S8", TMCG_MPZ_IO_BASE);
	s = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	tmcg_mpz_shash(foo, s);
	assert(!mpz_cmp(foo, bar));
	
	// tmcg_mpz_qrmn_p, tmcg_mpz_sqrtmn_r, tmcg_mpz_sqrtmn
	std::cout << "tmcg_mpz_qrmn_p(), tmcg_mpz_sqrtmn_r(), tmcg_mpz_sqrtmn()" << std::endl;
	tmcg_mpz_sprime(foo, bar, 1024, TMCG_MR_ITERATIONS);
	tmcg_mpz_sprime(foo2, bar2, 1024, TMCG_MR_ITERATIONS);
	mpz_mul(bar, foo, foo2);
	for (size_t i = 0; i < 50; i++)
	{
		do
			tmcg_mpz_srandomm(bar2, bar);
		while (!tmcg_mpz_qrmn_p(bar2, foo, foo2, bar));
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
		mpz_init_set_ui(tmp1, k+5), mpz_init_set_ui(tmp2, (2*k)+3), mpz_init(tmp3);
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

*/	
	return 0;
}

