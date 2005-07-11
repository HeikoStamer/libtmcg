/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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

#include "mpz_spowm.h"

/* Kocher's efficient blinding technique for modular exponentiation */

mpz_t		bvi, bvf, bx, bp;

void mpz_spowm_init
	(mpz_srcptr x, mpz_srcptr p)
{
	int ret;
	
	/* initalize the seed variables */
	mpz_init(bvi), mpz_init(bvf), mpz_init_set(bx, x), mpz_init_set(bp, p);
	
	/* choose a random blinding value and compute the seed */
	do
	{
		mpz_srandomm(bvi, bp);
		ret = mpz_invert(bvf, bvi, bp);
	}
	while (!ret);
	mpz_powm(bvf, bvf, bx, bp);
}

void mpz_spowm_calc
	(mpz_ptr res, mpz_srcptr m)
{
	/* modular exponentiation (res = m^x mod p) */
	mpz_mul(res, m, bvi);
	mpz_mod(res, res, bp);
	mpz_powm(res, res, bx, bp);
	mpz_mul(res, res, bvf);
	mpz_mod(res, res, bp);
	
	/* compute the new seed */
	mpz_powm_ui(bvi, bvi, 2L, bp);
	mpz_powm_ui(bvf, bvf, 2L, bp);
}

void mpz_spowm_clear
	()
{
	mpz_clear(bvi), mpz_clear(bvf), mpz_clear(bx), mpz_clear(bp);
}

/* Chaum's blinding technique for modular exponentiation */

void mpz_spowm
	(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	int ret;
	mpz_t r, r1;
	
	mpz_init(r), mpz_init(r1);
	
	/* choose random blinding value */
	do
	{
		mpz_srandomm(r, p);
		ret = mpz_invert(r1, r, p);
	}
	while (!ret);
	mpz_powm(r1, r1, x, p);
	
	/* blind the message */
	mpz_mul(res, m, r);
	mpz_mod(res, res, p);
	
	/* modular exponentiation (res = m^x mod p) */
	mpz_powm(res, res, x, p);

	/* unblind the result */
	mpz_mul(res, res, r1);
	mpz_mod(res, res, p);
	
	mpz_clear(r), mpz_clear(r1);
}

/* Fast modular exponentiation using precomputed tables */

mpz_t	fpowm_table[TMCG_MAX_FPOWM_N][TMCG_MAX_FPOWM_T];

void mpz_fpowm_init
	()
{
	size_t i, j;
	for (i = 0; i < TMCG_MAX_FPOWM_N; i++)
	{
		for (j = 0; j < TMCG_MAX_FPOWM_T; j++)
			mpz_init(fpowm_table[i][j]);
	}
}

void mpz_fpowm_precompute_table
	(mpz_srcptr m, mpz_srcptr p, size_t n, size_t t)
{
	size_t j;
	mpz_t e;
	
	assert((n <= TMCG_MAX_FPOWM_N) && (t <= TMCG_MAX_FPOWM_T));
	mpz_init_set_ui(e, 1L);
	for (j = 0; j < t; j++)
	{
		mpz_powm(fpowm_table[n][j], m, e, p);
		mpz_mul_ui(e, e, 2L);
	}
	mpz_clear(e);
}

void mpz_fpowm
	(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p, size_t n)
{
	size_t j;
	
	assert((n <= TMCG_MAX_FPOWM_N) &&
		(mpz_sizeinbase(x, 2L) <= TMCG_MAX_FPOWM_T));
	mpz_set_ui(res, 1L);
	for (j = 0; j < mpz_sizeinbase(x, 2L); j++)
	{
		if (mpz_tstbit(x, j))
		{
			mpz_mul(res, res, fpowm_table[n][j]);
			mpz_mod(res, res, p);
		}
	}
}

void mpz_fpowm_done
	()
{
	size_t i, j;
	for (i = 0; i < TMCG_MAX_FPOWM_N; i++)
	{
		for (j = 0; j < TMCG_MAX_FPOWM_T; j++)
			mpz_clear(fpowm_table[i][j]);
	}
}
