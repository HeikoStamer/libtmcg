/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

void mpz_fpowm_init
	(mpz_t fpowm_table[])
{
	size_t i;
	
	for (i = 0; i < TMCG_MAX_FPOWM_T; i++)
		mpz_init(fpowm_table[i]);
}

void mpz_fpowm_precompute
	(mpz_t fpowm_table[],
	mpz_srcptr m, mpz_srcptr p, size_t t)
{
	size_t i;
	
	mpz_set(fpowm_table[0], m);
	for (i = 1; ((i < t) && (i < TMCG_MAX_FPOWM_T)); i++)
	{
		mpz_mul(fpowm_table[i], fpowm_table[i-1], fpowm_table[i-1]);
		mpz_mod(fpowm_table[i], fpowm_table[i], p);
	}
}

void mpz_fpowm
	(mpz_t fpowm_table[],
	mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	size_t i;
	mpz_t xx;
	
	mpz_init_set(xx, x);
	if (mpz_sgn(x) == -1)
		mpz_neg(xx, x);
	
	if (mpz_sizeinbase(xx, 2L) <= TMCG_MAX_FPOWM_T)
	{
		mpz_set_ui(res, 1L);
		for (i = 0; i < mpz_sizeinbase(xx, 2L); i++)
		{
			if (mpz_tstbit(xx, i))
			{
				mpz_mul(res, res, fpowm_table[i]);
				mpz_mod(res, res, p);
			}
		}
		/* invert the result, if x was negative */
		if (mpz_sgn(x) == -1)
		{
			if (!mpz_invert(res, res, p))
				mpz_set_ui(res, 0L);
		}
	}
	else
		mpz_set_ui(res, 0L);
	mpz_clear(xx);
}

void mpz_fpowm_ui
	(mpz_t fpowm_table[],
	mpz_ptr res, mpz_srcptr m, unsigned long int x_ui, mpz_srcptr p)
{
	size_t i;
	mpz_t x;
	
	mpz_init_set_ui(x, x_ui);
	if (mpz_sizeinbase(x, 2L) <= TMCG_MAX_FPOWM_T)
	{
		mpz_set_ui(res, 1L);
		for (i = 0; i < mpz_sizeinbase(x, 2L); i++)
		{
			if (mpz_tstbit(x, i))
			{
				mpz_mul(res, res, fpowm_table[i]);
				mpz_mod(res, res, p);
			}
		}
	}
	else
		mpz_set_ui(res, 0L);
	mpz_clear(x);
}

void mpz_fspowm
	(mpz_t fpowm_table[],
	mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	size_t i;
	mpz_t tmp, xx;
	
	mpz_init(tmp), mpz_init_set(xx, x);
	if (mpz_sgn(x) == -1)
		mpz_neg(xx, x);
	else
		mpz_neg(tmp, x);
	
	if (mpz_sizeinbase(xx, 2L) <= TMCG_MAX_FPOWM_T)
	{
		mpz_set_ui(res, 1L);
		for (i = 0; i < mpz_sizeinbase(xx, 2L); i++)
		{
			if (mpz_tstbit(xx, i))
			{
				mpz_mul(res, res, fpowm_table[i]);
				mpz_mod(res, res, p);
			}
			else
			{
				/* Timing attack protection */
				mpz_mul(tmp, res, fpowm_table[i]);
				mpz_mod(tmp, tmp, p);
			}
		}
		/* invert the input, if x was negative */
		if (mpz_sgn(x) == -1)
		{
			if (!mpz_invert(res, res, p))
				mpz_set_ui(res, 0L);
		}
		else
		{
			/* Timing attack protection */
			if (!mpz_invert(tmp, res, p))
				mpz_set_ui(tmp, 0L);
		}
	}
	else
		mpz_set_ui(res, 0L);
	mpz_clear(tmp), mpz_clear(xx);
}

void mpz_fpowm_done
	(mpz_t fpowm_table[])
{
	size_t i;
	
	for (i = 0; i < TMCG_MAX_FPOWM_T; i++)
		mpz_clear(fpowm_table[i]);
}
