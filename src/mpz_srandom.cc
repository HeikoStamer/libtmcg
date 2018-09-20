/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2002, 2004, 2005, 2007, 
               2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "mpz_srandom.hh"

// additional headers
#include <cstring>
#include <cassert>
#include <climits>
#include <iostream>
#include <stdexcept>

// GNU crypto library
#include <gcrypt.h>

#ifdef BOTAN
	// Random number generators from Botan cryptographic library
	#include <botan/auto_rng.h>
	#include <botan/rng.h>
#endif


unsigned long int tmcg_mpz_grandom_ui
	(enum gcry_random_level level)
{
	unsigned long int tmp = 0;
	if (level == GCRY_WEAK_RANDOM)
		gcry_create_nonce((unsigned char*)&tmp, sizeof(tmp));
	else
		gcry_randomize((unsigned char*)&tmp, sizeof(tmp), level);
#ifdef BOTAN
	std::unique_ptr<Botan::RandomNumberGenerator>
		rng(new Botan::AutoSeeded_RNG);
	unsigned long int botan_tmp = 0;
	rng->randomize((uint8_t*)&botan_tmp, sizeof(botan_tmp));
	if (tmp != botan_tmp)
		tmp ^= botan_tmp; // XOR both random sources
#endif
	return tmp;
}

unsigned long int tmcg_mpz_grandom_ui_nomodbias
	(enum gcry_random_level level, const unsigned long int modulo)
{
	unsigned long int div, max, rnd = 0;
	
	if ((modulo == 0) || (modulo == 1))
		throw std::invalid_argument("tmcg_mpz_grandom_ui_nomodbias: bad modulo");
	
	// Remove ``modulo bias'' by limiting the return values
	div = (ULONG_MAX - modulo + 1) / modulo;
	max = ((div + 1) * modulo) - 1;
	do
		rnd = tmcg_mpz_grandom_ui(level);
	while (rnd > max);

	return rnd;
}

unsigned long int tmcg_mpz_ssrandom_ui
	()
{
	return tmcg_mpz_grandom_ui(GCRY_VERY_STRONG_RANDOM);
}

unsigned long int tmcg_mpz_srandom_ui
	()
{
	return tmcg_mpz_grandom_ui(GCRY_STRONG_RANDOM);
}

unsigned long int tmcg_mpz_wrandom_ui
	()
{
	return tmcg_mpz_grandom_ui(GCRY_WEAK_RANDOM);
}

unsigned long int tmcg_mpz_ssrandom_mod
	(const unsigned long int modulo)
{
	unsigned long int t = 0;
	t = tmcg_mpz_grandom_ui_nomodbias(GCRY_VERY_STRONG_RANDOM, modulo) % modulo;
	return t;
}

unsigned long int tmcg_mpz_srandom_mod
	(const unsigned long int modulo)
{
	return tmcg_mpz_grandom_ui_nomodbias(GCRY_STRONG_RANDOM, modulo) % modulo;
}

unsigned long int tmcg_mpz_wrandom_mod
	(const unsigned long int modulo)
{
	return tmcg_mpz_grandom_ui_nomodbias(GCRY_WEAK_RANDOM, modulo) % modulo;
}

void tmcg_mpz_grandomb
	(mpz_ptr r, const unsigned long int size, enum gcry_random_level level)
{
	unsigned char *rtmp;
	size_t hlen = 0;
	gcry_mpi_t rr;
	gcry_error_t ret;
	assert(size <= UINT_MAX);

	rr = gcry_mpi_new((unsigned int)size);
	gcry_mpi_randomize(rr, (unsigned int)size, level);
	ret = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, &hlen, rr);
	gcry_mpi_release(rr);
	if (ret || (hlen == 0))
	{
		std::cerr << "tmcg_mpz_grandomb(): gcry_mpi_aprint() failed: " <<
			gcry_strerror(ret) << std::endl;
		throw std::invalid_argument("gcry_mpi_aprint() failed");
	}
	else
	{
		char htmp[size + 3]; // at least two characters + delimiter
		memset(htmp, 0, size + 3);
		memcpy(htmp, rtmp, hlen);
		gcry_free(rtmp);
		mpz_set_str(r, htmp, 16);
#ifdef BOTAN
		memset(htmp, 0, size + 3);
		std::unique_ptr<Botan::RandomNumberGenerator>
			rng(new Botan::AutoSeeded_RNG);
		uint8_t botan_tmp[hlen];
		rng->randomize(botan_tmp, sizeof(botan_tmp));
		for (size_t i = 0; i < hlen; i++)
		{
			switch (botan_tmp[i] % 16)
			{
				case 0:
					htmp[i] = '0';
					break;
				case 1:
					htmp[i] = '1';
					break;
				case 2:
					htmp[i] = '2';
					break;
				case 3:
					htmp[i] = '3';
					break;
				case 4:
					htmp[i] = '4';
					break;
				case 5:
					htmp[i] = '5';
					break;
				case 6:
					htmp[i] = '6';
					break;
				case 7:
					htmp[i] = '7';
					break;
				case 8:
					htmp[i] = '8';
					break;
				case 9:
					htmp[i] = '9';
					break;
				case 10:
					htmp[i] = 'a';
					break;
				case 11:
					htmp[i] = 'b';
					break;
				case 12:
					htmp[i] = 'c';
					break;
				case 13:
					htmp[i] = 'd';
					break;
				case 14:
					htmp[i] = 'e';
					break;
				case 15:
					htmp[i] = 'f';
					break;
			}
		}
		mpz_t rrr;
		mpz_init(rrr);
		mpz_set_str(rrr, htmp, 16);
		mpz_add(r, r, rrr); // ADD number from other random source
		mpz_clear(rrr);
#endif
		// r mod 2^size, i.e. shift right and bit mask
		mpz_tdiv_r_2exp(r, r, size);
	}
}

void tmcg_mpz_ssrandomb
	(mpz_ptr r, const unsigned long int size)
{
	FILE *fhd = fopen("/proc/sys/kernel/random/entropy_avail", "r");
	if (fhd != NULL)
	{
		unsigned long int entropy_avail = 0;
		if (fscanf(fhd, "%lu", &entropy_avail) != 1)
			entropy_avail = 0;
		fclose(fhd);
		if (entropy_avail < size)
		{
			std::cerr << "tmcg_mpz_ssrandomb(): too few entropy (" <<
				entropy_avail << " bits) available; blocking" << std::endl;
		}
	}
	tmcg_mpz_grandomb(r, size, GCRY_VERY_STRONG_RANDOM);
}

void tmcg_mpz_srandomb
	(mpz_ptr r, const unsigned long int size)
{
	tmcg_mpz_grandomb(r, size, GCRY_STRONG_RANDOM);
}

void tmcg_mpz_wrandomb
	(mpz_ptr r, const unsigned long int size)
{
	tmcg_mpz_grandomb(r, size, GCRY_WEAK_RANDOM);
}

void tmcg_mpz_grandomm
	(mpz_ptr r, mpz_srcptr m, enum gcry_random_level level)
{
	// make bias negligible cf. BSI TR-02102-1, B.4 Verfahren 2
	unsigned long int size = mpz_sizeinbase(m, 2UL) + 64;
	unsigned char *rtmp;
	char htmp[size + 3]; // at least two characters + delimiter
	size_t hlen = 0;
	gcry_mpi_t rr;
	gcry_error_t ret;
	assert(size <= UINT_MAX);
	
	rr = gcry_mpi_new((unsigned int)size);
	gcry_mpi_randomize(rr, (unsigned int)size, level);
	ret = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, &hlen, rr);
	gcry_mpi_release(rr);
	if (ret || (hlen == 0))
	{
		std::cerr << "tmcg_mpz_grandomm(): gcry_mpi_aprint() failed: " <<
			gcry_strerror(ret) << std::endl;
		throw std::invalid_argument("gcry_mpi_aprint() failed");
	}
	else
	{
		memset(htmp, 0, size + 3);
		memcpy(htmp, rtmp, hlen);
		gcry_free(rtmp);
		mpz_set_str(r, htmp, 16);
#ifdef BOTAN
		memset(htmp, 0, size + 3);
		std::unique_ptr<Botan::RandomNumberGenerator>
			rng(new Botan::AutoSeeded_RNG);
		uint8_t botan_tmp[hlen];
		rng->randomize(botan_tmp, sizeof(botan_tmp));
		for (size_t i = 0; i < hlen; i++)
		{
			switch (botan_tmp[i] % 16)
			{
				case 0:
					htmp[i] = '0';
					break;
				case 1:
					htmp[i] = '1';
					break;
				case 2:
					htmp[i] = '2';
					break;
				case 3:
					htmp[i] = '3';
					break;
				case 4:
					htmp[i] = '4';
					break;
				case 5:
					htmp[i] = '5';
					break;
				case 6:
					htmp[i] = '6';
					break;
				case 7:
					htmp[i] = '7';
					break;
				case 8:
					htmp[i] = '8';
					break;
				case 9:
					htmp[i] = '9';
					break;
				case 10:
					htmp[i] = 'a';
					break;
				case 11:
					htmp[i] = 'b';
					break;
				case 12:
					htmp[i] = 'c';
					break;
				case 13:
					htmp[i] = 'd';
					break;
				case 14:
					htmp[i] = 'e';
					break;
				case 15:
					htmp[i] = 'f';
					break;
			}
		}
		mpz_t rrr;
		mpz_init(rrr);
		mpz_set_str(rrr, htmp, 16);
		mpz_add(r, r, rrr); // ADD number from other random source
		mpz_clear(rrr);
#endif
		mpz_mod(r, r, m); // bias is negligible due to increased size of r
	}
}

void tmcg_mpz_ssrandomm
	(mpz_ptr r, mpz_srcptr m)
{
	FILE *fhd = fopen("/proc/sys/kernel/random/entropy_avail", "r");
	if (fhd != NULL)
	{
		unsigned long int entropy_avail = 0;
		if (fscanf(fhd, "%lu", &entropy_avail) != 1)
			entropy_avail = 0;
		fclose(fhd);
		if (entropy_avail < mpz_sizeinbase(m, 2UL))
		{
			std::cerr << "tmcg_mpz_ssrandomm(): too few entropy (" <<
				entropy_avail << " bits) available; blocking" << std::endl;
		}
	}
	tmcg_mpz_grandomm(r, m, GCRY_VERY_STRONG_RANDOM);
}

void tmcg_mpz_srandomm
	(mpz_ptr r, mpz_srcptr m)
{
	tmcg_mpz_grandomm(r, m, GCRY_STRONG_RANDOM);
}

void tmcg_mpz_wrandomm
	(mpz_ptr r, mpz_srcptr m)
{
	tmcg_mpz_grandomm(r, m, GCRY_WEAK_RANDOM);
}

void tmcg_mpz_ssrandomm_cache_init
	(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	mpz_ptr ssrandomm_cache_mod,
	size_t *ssrandomm_cache_avail,
	size_t n, mpz_srcptr m)
{
	size_t i = 0;
	if ((n == 0) || (n > TMCG_MAX_SSRANDOMM_CACHE))
		throw std::invalid_argument("tmcg_mpz_ssrandomm_cache_init: bad n");
	for (i = 0; i < TMCG_MAX_SSRANDOMM_CACHE; i++)
		mpz_init(ssrandomm_cache[i]);
	for (i = 0; i < n; i++)
		tmcg_mpz_ssrandomm(ssrandomm_cache[i], m);
	mpz_init_set(ssrandomm_cache_mod, m);
	*ssrandomm_cache_avail = n;
}

void tmcg_mpz_ssrandomm_cache
	(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	mpz_srcptr ssrandomm_cache_mod,
	size_t *ssrandomm_cache_avail,
	mpz_ptr r, mpz_srcptr m)
{
	if (!mpz_cmp(m, ssrandomm_cache_mod) && *ssrandomm_cache_avail)
	{
		(*ssrandomm_cache_avail)--; // next cached random value
		mpz_set(r, ssrandomm_cache[*ssrandomm_cache_avail]);
	}
	else
		tmcg_mpz_ssrandomm(r, m);
}

void tmcg_mpz_ssrandomm_cache_done
	(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	mpz_ptr ssrandomm_cache_mod,
	size_t *ssrandomm_cache_avail)
{
	size_t i = 0;
	*ssrandomm_cache_avail = 0;
	mpz_clear(ssrandomm_cache_mod);
	for (i = 0; i < TMCG_MAX_SSRANDOMM_CACHE; i++)
		mpz_clear(ssrandomm_cache[i]);
}

