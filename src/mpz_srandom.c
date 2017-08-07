/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2002, 2004, 2005, 2007, 
                           2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

/* include headers */
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "mpz_srandom.h"

unsigned long int mpz_grandom_ui
	(enum gcry_random_level level)
{
	unsigned long int tmp = 0;
	if (level == GCRY_WEAK_RANDOM)
		gcry_create_nonce((unsigned char*)&tmp, sizeof(tmp));
	else
		gcry_randomize((unsigned char*)&tmp, sizeof(tmp), level);
	return tmp;
}

unsigned long int mpz_grandom_ui_nomodbias
	(enum gcry_random_level level, const unsigned long int modulo)
{
	unsigned long int div, max, rnd = 0;
	
	if ((modulo == 0) || (modulo == 1))
	    return 0; /* indicates an error */
	
	/* Remove ``modulo bias'' by limiting the return values */
	div = (ULONG_MAX - modulo + 1) / modulo;
	max = ((div + 1) * modulo) - 1;
	do
		rnd = mpz_grandom_ui(level);
	while (rnd > max);

	return rnd;
}

unsigned long int mpz_ssrandom_ui
	()
{
	return mpz_grandom_ui(GCRY_VERY_STRONG_RANDOM);
}

unsigned long int mpz_srandom_ui
	()
{
	return mpz_grandom_ui(GCRY_STRONG_RANDOM);
}

unsigned long int mpz_wrandom_ui
	()
{
	return mpz_grandom_ui(GCRY_WEAK_RANDOM);
}

unsigned long int mpz_ssrandom_mod
	(const unsigned long int modulo)
{
	return mpz_grandom_ui_nomodbias(GCRY_VERY_STRONG_RANDOM, modulo) % modulo;
}

unsigned long int mpz_srandom_mod
	(const unsigned long int modulo)
{
	return mpz_grandom_ui_nomodbias(GCRY_STRONG_RANDOM, modulo) % modulo;
}

unsigned long int mpz_wrandom_mod
	(const unsigned long int modulo)
{
	return mpz_grandom_ui_nomodbias(GCRY_WEAK_RANDOM, modulo) % modulo;
}

void mpz_grandomb
	(mpz_ptr r, const unsigned long int size, enum gcry_random_level level)
{
	unsigned char *rtmp;
	char htmp[size + 3]; // at least two characters + delimiter
	size_t hlen;
	gcry_mpi_t rr;
	gcry_error_t ret;
	assert(size <= UINT_MAX);
	
	rr = gcry_mpi_new((unsigned int)size);
	gcry_mpi_randomize(rr, (unsigned int)size, level);
	ret = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, &hlen, rr);
	if (ret)
	{
		mpz_set_ui(r, 0L); /* indicates an error */
	}
	else
	{
		memset(htmp, 0, size + 3);
		memcpy(htmp, rtmp, hlen);
		gcry_free(rtmp);
		mpz_set_str(r, htmp, 16);
		mpz_tdiv_r_2exp(r, r, size); /* r mod 2^size, i.e. shift right and bit mask */
	}
	gcry_mpi_release(rr);
}

void mpz_ssrandomb
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
			fprintf(stderr, "mpz_ssrandomb(): too few entropy (%lu bits) available; blocking\n", entropy_avail);
	}
	mpz_grandomb(r, size, GCRY_VERY_STRONG_RANDOM);
}

void mpz_srandomb
	(mpz_ptr r, const unsigned long int size)
{
	mpz_grandomb(r, size, GCRY_STRONG_RANDOM);
}

void mpz_wrandomb
	(mpz_ptr r, const unsigned long int size)
{
	mpz_grandomb(r, size, GCRY_WEAK_RANDOM);
}

void mpz_grandomm
	(mpz_ptr r, mpz_srcptr m, enum gcry_random_level level)
{
	unsigned long int size = mpz_sizeinbase(m, 2L);
	unsigned char *rtmp;
	char htmp[size + 3]; // at least two characters + delimiter
	size_t hlen;
	gcry_mpi_t rr;
	gcry_error_t ret;
	assert(size <= UINT_MAX);
	
	rr = gcry_mpi_new((unsigned int)size);
	gcry_mpi_randomize(rr, (unsigned int)size, level);
	ret = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, &hlen, rr);
	if (ret)
	{
		mpz_set_ui(r, 0L); /* indicates an error */
	}
	else
	{
		memset(htmp, 0, size + 3);
		memcpy(htmp, rtmp, hlen);
		gcry_free(rtmp);
		mpz_set_str(r, htmp, 16);
		mpz_mod(r, r, m); /* modulo bias is negligible here */
	}
	gcry_mpi_release(rr);
}

void mpz_ssrandomm
	(mpz_ptr r, mpz_srcptr m)
{
	FILE *fhd = fopen("/proc/sys/kernel/random/entropy_avail", "r");
	if (fhd != NULL)
	{
		unsigned long int entropy_avail = 0;
		if (fscanf(fhd, "%lu", &entropy_avail) != 1)
			entropy_avail = 0;
		fclose(fhd);
		if (entropy_avail < mpz_sizeinbase(m, 2L))
			fprintf(stderr, "mpz_ssrandomm(): too few entropy (%lu bits) available; blocking\n", entropy_avail);
	}
	mpz_grandomm(r, m, GCRY_VERY_STRONG_RANDOM);
}

void mpz_srandomm
	(mpz_ptr r, mpz_srcptr m)
{
	mpz_grandomm(r, m, GCRY_STRONG_RANDOM);
}

void mpz_wrandomm
	(mpz_ptr r, mpz_srcptr m)
{
	mpz_grandomm(r, m, GCRY_WEAK_RANDOM);
}
