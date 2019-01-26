/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007, 
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "mpz_spowm.hh"

// additional headers
#include <stdexcept>
#include "mpz_srandom.hh"

/* Kocher's efficient blinding technique for modular exponentiation [Ko96] */
mpz_t bvi, bvf, bx, bp;

void tmcg_mpz_spowm_init
	(mpz_srcptr x, mpz_srcptr p)
{
	int ret;
	
	/* initalize the seed variables */
	mpz_init(bvi), mpz_init(bvf), mpz_init_set(bx, x), mpz_init_set(bp, p);
	
	/* choose a random blinding value and compute the seed */
	do
	{
		tmcg_mpz_srandomm(bvi, bp);
		ret = mpz_invert(bvf, bvi, bp);
	}
	while (!ret);
	mpz_powm(bvf, bvf, bx, bp);
}

void tmcg_mpz_spowm_calc
	(mpz_ptr res, mpz_srcptr m)
{
	/* modular exponentiation (res = m^x mod p) */
	mpz_mul(res, m, bvi);
	mpz_mod(res, res, bp);
	mpz_powm(res, res, bx, bp);
	mpz_mul(res, res, bvf);
	mpz_mod(res, res, bp);
	
	/* compute the new seed */
	mpz_powm_ui(bvi, bvi, 2UL, bp);
	mpz_powm_ui(bvf, bvf, 2UL, bp);
}

void tmcg_mpz_spowm_clear
	()
{
	mpz_clear(bvi), mpz_clear(bvf), mpz_clear(bx), mpz_clear(bp);
}

/* Chaum's blinding technique for modular exponentiation */
void tmcg_mpz_spowm_baseblind
	(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	int ret;
	mpz_t r, r1;
	
	mpz_init(r), mpz_init(r1);
	
	/* choose random blinding value */
	do
	{
		tmcg_mpz_srandomm(r, p);
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

/* Use constant-time function mpz_powm_sec() from libgmp, if available. 
   Otherwise Chaum's blinding technique for modular exponentiation is 
   applied. */

void tmcg_mpz_spowm
	(mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
#ifdef HAVE_POWMSEC
	mpz_t foo, bar, baz, xx;
	mpz_set_ui(res, 0UL);
	if (!mpz_odd_p(p))
		throw std::invalid_argument("tmcg_mpz_spowm: p is even");
	mpz_init(foo), mpz_init_set_si(bar, -1L), mpz_init(baz);
	mpz_init_set(xx, x);
	int sign = mpz_sgn(x);
	if (sign == -1)
		mpz_neg(xx, xx);
	else if (sign == 1)
		mpz_neg(bar, xx);
	else
		mpz_neg(xx, bar);
	/* compute baz = m^x mod p in constant-time */
	mpz_powm_sec(baz, m, xx, p);
	/* compute the inverse of result */
	if (!mpz_invert(foo, baz, p))
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
		throw std::runtime_error("tmcg_mpz_spowm: mpz_invert failed");
	}
	/* invert the input, if x was negative */
	if (sign == -1)
		mpz_add(res, res, foo);
	else if (sign == 1)
		mpz_add(res, res, baz);
	else
		mpz_add(res, res, xx);

	/* additional dummy to prevent compiler optimizations */
	mpz_mul(res, res, foo);
	mpz_mod(res, res, p);
	if (!mpz_invert(xx, foo, p))
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
		throw std::runtime_error("tmcg_mpz_spowm: mpz_invert failed");
	}
	mpz_mul(res, res, xx); /* res = res * foo * foo^{-1} mod p */
	mpz_mod(res, res, p);
	mpz_mul(res, res, bar);
	mpz_mod(res, res, p);
	if (!mpz_invert(xx, bar, p))
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
		throw std::runtime_error("tmcg_mpz_spowm: mpz_invert failed");
	}
	mpz_mul(res, res, xx); /* res = res * bar * bar^{-1} mod p */
	mpz_mod(res, res, p);
	mpz_mul(res, res, baz);
	mpz_mod(res, res, p);
	if (!mpz_invert(xx, baz, p))
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
		throw std::runtime_error("tmcg_mpz_spowm: mpz_invert failed");
	}
	mpz_mul(res, res, xx); /* res = res * baz * baz^{-1} mod p */
	mpz_mod(res, res, p);
	mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
#else
	mpz_spowm_baseblind(res, m, x, p);
#endif
}

/* Fast modular exponentiation using precomputed tables */

void tmcg_mpz_fpowm_init
	(mpz_t fpowm_table[])
{
	for (size_t i = 0; i < TMCG_MAX_FPOWM_T; i++)
		mpz_init(fpowm_table[i]);
}

void tmcg_mpz_fpowm_precompute
	(mpz_t fpowm_table[],
	 mpz_srcptr m, mpz_srcptr p, const size_t t)
{
	mpz_set(fpowm_table[0], m);
	for (size_t i = 1; ((i < t) && (i < TMCG_MAX_FPOWM_T)); i++)
	{
		mpz_mul(fpowm_table[i], fpowm_table[i-1], fpowm_table[i-1]);
		mpz_mod(fpowm_table[i], fpowm_table[i], p);
	}
}

void tmcg_mpz_fpowm
	(mpz_t fpowm_table[],
	 mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	mpz_t xx;

	if (mpz_cmp(m, fpowm_table[0]))
		throw std::invalid_argument("tmcg_mpz_fpowm: wrong base");
	mpz_init_set(xx, x);
	if (mpz_sgn(x) == -1)
		mpz_neg(xx, x);
	
	if (mpz_sizeinbase(xx, 2UL) <= TMCG_MAX_FPOWM_T)
	{
		mpz_set_ui(res, 1UL);
		for (size_t i = 0; i < mpz_sizeinbase(xx, 2UL); i++)
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
			{
				mpz_clear(xx);
				throw std::runtime_error("tmcg_mpz_fpowm: mpz_invert failed");
			}
		}
	}
	else
	{
		mpz_clear(xx);
		throw std::invalid_argument("tmcg_mpz_fpowm: exponent too large");
	}
	mpz_clear(xx);
}

void tmcg_mpz_fpowm_ui
	(mpz_t fpowm_table[],
	mpz_ptr res, mpz_srcptr m, const unsigned long int x_ui, mpz_srcptr p)
{
	mpz_t x;

	if (mpz_cmp(m, fpowm_table[0]))
		throw std::invalid_argument("tmcg_mpz_fpowm_ui: wrong base");
	mpz_init_set_ui(x, x_ui);
	if (mpz_sizeinbase(x, 2UL) <= TMCG_MAX_FPOWM_T)
	{
		mpz_set_ui(res, 1UL);
		for (size_t i = 0; i < mpz_sizeinbase(x, 2UL); i++)
		{
			if (mpz_tstbit(x, i))
			{
				mpz_mul(res, res, fpowm_table[i]);
				mpz_mod(res, res, p);
			}
		}
	}
	else
	{
		mpz_clear(x);
		throw std::invalid_argument("tmcg_mpz_fpowm_ui: exponent too large");
	}
	mpz_clear(x);
}

void tmcg_mpz_fspowm
	(mpz_t fpowm_table[],
	mpz_ptr res, mpz_srcptr m, mpz_srcptr x, mpz_srcptr p)
{
	mpz_t foo, bar, baz, xx;

	if (mpz_cmp(m, fpowm_table[0]))
		throw std::invalid_argument("tmcg_mpz_fspowm: wrong base");
	mpz_init(foo), mpz_init(bar), mpz_init(baz), mpz_init_set(xx, x);
	if (mpz_sgn(x) == -1)
		mpz_neg(xx, x);
	else
		mpz_neg(bar, x);
	if (mpz_sizeinbase(xx, 2UL) <= TMCG_MAX_FPOWM_T)
	{
		/* compute result by multiplying precomputed values */
		mpz_set_ui(res, 1UL);
		for (size_t i = 0; i < mpz_sizeinbase(xx, 2UL); i++)
		{
			mpz_mul(foo, res, fpowm_table[i]);
			mpz_mod(foo, foo, p);
			mpz_add(bar, bar, foo); /* dummy bar usage */
			if (mpz_tstbit(xx, i))
				mpz_set(res, foo);
			else
				mpz_set(bar, foo);
		}
		/* invert the input, if x was negative */
		mpz_set(baz, res);
		if (!mpz_invert(foo, res, p))
		{
			mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
			throw std::runtime_error("tmcg_mpz_fspowm: mpz_invert failed");
		}
		if (mpz_sgn(x) == -1)
			mpz_set(res, foo);
		else
			mpz_set(baz, foo);
		/* additional dummy to prevent compiler optimizations */
		if (!mpz_invert(foo, bar, p))
			mpz_set_ui(foo, 1UL), mpz_set_ui(bar, 1UL);
		mpz_mul(res, bar, res); /* res = bar * res * bar^{-1} mod p */
		mpz_mod(res, res, p);
		mpz_mul(res, res, foo);
		mpz_mod(res, res, p);
		if (!mpz_invert(foo, baz, p))
			mpz_set_ui(foo, 1UL), mpz_set_ui(baz, 1UL);
		mpz_mul(res, baz, res); /* res = baz * res * baz^{-1} mod p */
		mpz_mod(res, res, p);
		mpz_mul(res, res, foo);
		mpz_mod(res, res, p);
	}
	else
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
		throw std::invalid_argument("tmcg_mpz_fspowm: exponent too large");
	}
	mpz_clear(foo), mpz_clear(bar), mpz_clear(baz), mpz_clear(xx);
}

void tmcg_mpz_fpowm_done
	(mpz_t fpowm_table[])
{
	for (size_t i = 0; i < TMCG_MAX_FPOWM_T; i++)
		mpz_clear(fpowm_table[i]);
}


