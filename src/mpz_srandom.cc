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
	unsigned char tmp[(size+7)/8];
	gcry_randomize(tmp, (size+7)/8, level);
	mpz_import(r, (size+7)/8, 1, 1, 1, 0, (const void*)tmp);
#ifdef BOTAN
	std::unique_ptr<Botan::RandomNumberGenerator>
		rng(new Botan::AutoSeeded_RNG);
	rng->randomize((uint8_t*)tmp, (size+7)/8);
	mpz_t rrr;
	mpz_init(rrr);
	mpz_import(rrr, (size+7)/8, 1, 1, 1, 0, (const void*)tmp);
	mpz_add(r, r, rrr); // ADD number from other random source
	mpz_clear(rrr);
#endif
	// r mod 2^size, i.e. shift right and bit mask
	mpz_tdiv_r_2exp(r, r, size);
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
	unsigned long int nbytes = (mpz_sizeinbase(m, 2UL) + 64 + 7) / 8;
	unsigned char tmp[nbytes];
	gcry_randomize(tmp, nbytes, level);
	mpz_import(r, nbytes, 1, 1, 1, 0, (const void*)tmp);
#ifdef BOTAN
	std::unique_ptr<Botan::RandomNumberGenerator>
		rng(new Botan::AutoSeeded_RNG);
	rng->randomize((uint8_t*)tmp, nbytes);
	mpz_t rrr;
	mpz_init(rrr);
	mpz_import(rrr, nbytes, 1, 1, 1, 0, (const void*)tmp);
	mpz_add(r, r, rrr); // ADD number from other random source
	mpz_clear(rrr);
#endif
	mpz_mod(r, r, m); // bias is negligible due to increased size of r
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
	 size_t &ssrandomm_cache_avail,
	 const size_t n,
	 mpz_srcptr m)
{
	size_t i = 0;
	if ((n == 0) || (n > TMCG_MAX_SSRANDOMM_CACHE))
		throw std::invalid_argument("tmcg_mpz_ssrandomm_cache_init: bad n");
	for (i = 0; i < TMCG_MAX_SSRANDOMM_CACHE; i++)
		mpz_init(ssrandomm_cache[i]);
	for (i = 0; i < n; i++)
		tmcg_mpz_ssrandomm(ssrandomm_cache[i], m);
	mpz_init_set(ssrandomm_cache_mod, m);
	ssrandomm_cache_avail = n;
}

void tmcg_mpz_ssrandomm_cache
	(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	 mpz_srcptr ssrandomm_cache_mod,
	 size_t &ssrandomm_cache_avail,
	 mpz_ptr r,
	 mpz_srcptr m)
{
	if (!mpz_cmp(m, ssrandomm_cache_mod) && (ssrandomm_cache_avail > 0))
	{
		ssrandomm_cache_avail--; // next cached random value
		mpz_set(r, ssrandomm_cache[ssrandomm_cache_avail]);
	}
	else
		tmcg_mpz_ssrandomm(r, m);
}

void tmcg_mpz_ssrandomm_cache_done
	(mpz_t ssrandomm_cache[TMCG_MAX_SSRANDOMM_CACHE],
	 mpz_ptr ssrandomm_cache_mod,
	 size_t &ssrandomm_cache_avail)
{
	size_t i = 0;
	ssrandomm_cache_avail = 0;
	mpz_clear(ssrandomm_cache_mod);
	for (i = 0; i < TMCG_MAX_SSRANDOMM_CACHE; i++)
		mpz_clear(ssrandomm_cache[i]);
}

