/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2002, 2004, 2007,
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

    (tmcg_mpz_sqrtmp_r)  1. square roots mod p, with p prime (randomized)
                          [algorithm of Adleman, Manders, and Miller, 1977]

    (tmcg_mpz_sqrtmp)    1a. square roots mod p, like 1. but non-randomized

    (tmcg_mpz_sqrtmp_fast)   faster version, needs some pre-computations

    (tmcg_mpz_sqrtmn_r)  2. square roots mod n, with n = p * q (distinct primes)

    (tmcg_mpz_sqrtmn)    2a. square roots mod n, like 2. but non-randomized

    (tmcg_mpz_sqrtmn_r_all)  get all four square roots (randomized variant)

    (tmcg_mpz_sqrtmn_all)    get all four square roots (non-randomized)

    (tmcg_mpz_sqrtmn_fast)   faster version, needed some pre-computations
                          ONLY FOR p, q \cong 3 (mod 4) [n is Blum Integer]

    (tmcg_mpz_sqrtmn_fast_all) faster version, get all four square roots
                          ONLY FOR p, q \cong 3 (mod 4) [n is Blum Integer]

    (tmcg_mpz_qrmn_p)    3. test quadratic residiosity mod n, with n = p * q

*******************************************************************************/

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "mpz_sqrtm.hh"

// additional headers
#include <stdexcept>
#include "mpz_srandom.hh"

int tmcg_mpz_qrmn_p
	(mpz_srcptr a, mpz_srcptr p, mpz_srcptr q)
{
	return ((mpz_jacobi(a, p) == 1) && (mpz_jacobi(a, q) == 1));
}

void tmcg_mpz_sqrtmp_r
	(mpz_ptr root, mpz_srcptr a, mpz_srcptr p)
{
	/* ? a \neq 0 */
	if (mpz_cmp_ui(a, 0UL))
	{
		if (mpz_congruent_ui_p(p, 3UL, 4UL))
		{
			/* p = 3 (mod 4) */
			mpz_t foo;
			mpz_init_set(foo, p);
			mpz_add_ui(foo, foo, 1UL);
			mpz_fdiv_q_2exp(foo, foo, 2UL);
			mpz_powm(root, a, foo, p);
			mpz_clear(foo);
			return;
		}
		else
		{
			/* p = 1 (mod 4) */
			mpz_t s;
			mpz_init_set(s, p);
			mpz_sub_ui(s, s, 1UL);
			mpz_fdiv_q_2exp(s, s, 2UL); /* s = (p-1)/4 */
			if (mpz_congruent_ui_p(p, 5UL, 8UL))
			{
				/* p = 5 (mod 8) */
				mpz_t foo, b;
				mpz_init(foo);
				mpz_powm(foo, a, s, p);
				mpz_init_set(b, p);
				mpz_add_ui(b, b, 3UL);
				mpz_fdiv_q_2exp(b, b, 3UL);
				mpz_powm(root, a, b, p);
				if (mpz_cmp_ui(foo, 1UL) == 0)
				{
					/* a^{(p-1)/4} = 1 (mod p) */
					mpz_clear(foo), mpz_clear(s), mpz_clear(b);
					return;
				}
				else
				{
					/* a^{(p-1)/4} = -1 (mod p) */
					do
						tmcg_mpz_wrandomm(b, p);
					while (mpz_jacobi(b, p) != -1);
					mpz_powm(b, b, s, p);
					mpz_mul(root, root, b);
					mpz_mod(root, root, p);
					mpz_clear(foo), mpz_clear(s), mpz_clear(b);
					return;
				}
			}
			else
			{
				/* p = 1 (mod 8) */
				mpz_t foo, bar, b, t;
				mpz_init(foo), mpz_init(bar);
				mpz_powm(foo, a, s, p);
				/* while a^s = 1 (mod p) */
				while (mpz_cmp_ui(foo, 1UL) == 0)
				{
					if (mpz_odd_p(s))
					{
						/* s is odd */
						mpz_add_ui(s, s, 1UL);
						mpz_fdiv_q_2exp(s, s, 1UL);
						mpz_powm(root, a, s, p);
						mpz_clear(foo), mpz_clear(bar), mpz_clear(s);
						return;
					}
					else
					{
						/* s is even */
						mpz_fdiv_q_2exp(s, s, 1UL);
					}
					mpz_powm(foo, a, s, p);
				}
				/* a^s = -1 (mod p) */
				mpz_init(b);
				do
					tmcg_mpz_wrandomm(b, p);
				while (mpz_jacobi(b, p) != -1);
				mpz_init_set(t, p);
				mpz_sub_ui(t, t, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				/* while s even */
				while (mpz_even_p(s))
				{
					mpz_fdiv_q_2exp(s, s, 1UL);
					mpz_fdiv_q_2exp(t, t, 1UL);
					mpz_powm(foo, a, s, p);
					mpz_powm(bar, b, t, p);
					mpz_mul(foo, foo, bar);
					mpz_mod(foo, foo, p);
					mpz_set_si(bar, -1L);
					if (mpz_congruent_p(foo, bar, p))
					{
						/* a^s * b^t = -1 (mod p) */
						mpz_set(bar, p);
						mpz_sub_ui(bar, bar, 1UL);
						mpz_fdiv_q_2exp(bar, bar, 1UL);
						mpz_add(t, t, bar);
					}
				}
				mpz_add_ui(s, s, 1UL);
				mpz_fdiv_q_2exp(s, s, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				mpz_powm(foo, a, s, p);
				mpz_powm(bar, b, t, p);
				mpz_mul(root, foo, bar);
				mpz_mod(root, root, p);
				mpz_clear(foo), mpz_clear(bar);
				mpz_clear(s), mpz_clear(b), mpz_clear(t);
				return;
			}
		}
	}
	else
		throw std::invalid_argument("tmcg_mpz_sqrtmp_r: a is zero");
}

void tmcg_mpz_sqrtmp
	(mpz_ptr root, mpz_srcptr a, mpz_srcptr p)
{
	/* ? a \neq 0 */
	if (mpz_cmp_ui(a, 0UL))
	{
		if (mpz_congruent_ui_p(p, 3UL, 4UL))
		{
			/* p = 3 (mod 4) */
			mpz_t foo;
			mpz_init_set(foo, p);
			mpz_add_ui(foo, foo, 1UL);
			mpz_fdiv_q_2exp(foo, foo, 2UL);
			mpz_powm(root, a, foo, p);
			mpz_clear(foo);
			return;
		}
		else
		{
			/* p = 1 (mod 4) */
			mpz_t s;
			mpz_init_set(s, p);
			mpz_sub_ui(s, s, 1UL);
			mpz_fdiv_q_2exp(s, s, 2UL); /* s = (p-1)/4 */
			if (mpz_congruent_ui_p(p, 5UL, 8UL))
			{
				/* p = 5 (mod 8) */
				mpz_t foo, b;
				mpz_init(foo);
				mpz_powm(foo, a, s, p);
				mpz_init_set(b, p);
				mpz_add_ui(b, b, 3UL);
				mpz_fdiv_q_2exp(b, b, 3UL);
				mpz_powm(root, a, b, p);
				if (mpz_cmp_ui(foo, 1UL) == 0)
				{
					/* a^{(p-1)/4} = 1 (mod p) */
					mpz_clear(foo), mpz_clear(s), mpz_clear(b);
					return;
				}
				else
				{
					/* a^{(p-1)/4} = -1 (mod p) */
					mpz_set_ui(b, 2UL);
					while (mpz_jacobi(b, p) != -1)
						mpz_add_ui(b, b, 1UL);
					mpz_powm(b, b, s, p);
					mpz_mul(root, root, b);
					mpz_mod(root, root, p);
					mpz_clear(foo), mpz_clear(s), mpz_clear(b);
					return;
				}
			}
			else
			{
				/* p = 1 (mod 8) */
				mpz_t foo, bar, b, t;
				mpz_init(foo), mpz_init(bar);
				mpz_powm(foo, a, s, p);
				/* while a^s = 1 (mod p) */
				while (mpz_cmp_ui(foo, 1UL) == 0)
				{
					if (mpz_odd_p(s))
					{
						/* s is odd */
						mpz_add_ui(s, s, 1UL);
						mpz_fdiv_q_2exp(s, s, 1UL);
						mpz_powm(root, a, s, p);
						mpz_clear(foo), mpz_clear(bar), mpz_clear(s);
						return;
					}
					else
					{
						/* s is even */
						mpz_fdiv_q_2exp(s, s, 1UL);
					}
					mpz_powm(foo, a, s, p);
				}
				/* a^s = -1 (mod p) */
				mpz_init_set_ui(b, 2UL);
				while (mpz_jacobi(b, p) != -1)
					mpz_add_ui(b, b, 1UL);
				mpz_init_set(t, p);
				mpz_sub_ui(t, t, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				/* while s even */
				while (mpz_even_p(s))
				{
					mpz_fdiv_q_2exp(s, s, 1UL);
					mpz_fdiv_q_2exp(t, t, 1UL);
					mpz_powm(foo, a, s, p);
					mpz_powm(bar, b, t, p);
					mpz_mul(foo, foo, bar);
					mpz_mod(foo, foo, p);
					mpz_set_si(bar, -1L);
					if (mpz_congruent_p(foo, bar, p))
					{
						/* a^s * b^t = -1 (mod p) */
						mpz_set(bar, p);
						mpz_sub_ui(bar, bar, 1UL);
						mpz_fdiv_q_2exp(bar, bar, 1UL);
						mpz_add(t, t, bar);
					}
				}
				mpz_add_ui(s, s, 1UL);
				mpz_fdiv_q_2exp(s, s, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				mpz_powm(foo, a, s, p);
				mpz_powm(bar, b, t, p);
				mpz_mul(root, foo, bar);
				mpz_mod(root, root, p);
				mpz_clear(foo), mpz_clear(bar);
				mpz_clear(s), mpz_clear(b), mpz_clear(t);
				return;
			}
		}
	}
	else
		throw std::invalid_argument("tmcg_mpz_sqrtmp: a is zero");
}

void tmcg_mpz_sqrtmp_fast
	(mpz_ptr root, mpz_srcptr a, mpz_srcptr p, mpz_srcptr nqr,
	mpz_srcptr pa1d4, mpz_srcptr ps1d4, mpz_srcptr pa3d8,
	mpz_srcptr nqr_ps1d4)
{
	/* ? a \neq 0 */
	if (mpz_cmp_ui(a, 0UL))
	{
		if (mpz_congruent_ui_p(p, 3UL, 4UL))
		{
			/* p = 3 (mod 4) */
			mpz_powm(root, a, pa1d4, p);
			return;
		}
		else
		{
			/* p = 1 (mod 4) */
			mpz_t s;
			mpz_init_set(s, ps1d4); /* s = (p-1)/4 */
			if (mpz_congruent_ui_p(p, 5UL, 8UL))
			{
				/* p = 5 (mod 8) */
				mpz_t foo;
				mpz_init(foo);
				mpz_powm(foo, a, s, p);
				mpz_powm(root, a, pa3d8, p);
				if (mpz_cmp_ui(foo, 1UL) == 0)
				{
					/* a^{(p-1)/4} = 1 (mod p) */
					mpz_clear(foo), mpz_clear(s);
					return;
				}
				else
				{
					/* a^{(p-1)/4} = -1 (mod p) */
					mpz_mul(root, root, nqr_ps1d4);
					mpz_mod(root, root, p);
					mpz_clear(foo), mpz_clear(s);
					return;
				}
			}
			else
			{
				/* p = 1 (mod 8) */
				mpz_t foo, bar, b, t;
				mpz_init(foo), mpz_init(bar);
				mpz_powm(foo, a, s, p);
				/* while a^s = 1 (mod p) */
				while (mpz_cmp_ui(foo, 1UL) == 0)
				{
					if (mpz_odd_p(s))
					{
						/* s is odd */
						mpz_add_ui(s, s, 1UL);
						mpz_fdiv_q_2exp(s, s, 1UL);
						mpz_powm(root, a, s, p);
						mpz_clear(foo);
						mpz_clear(bar);
						mpz_clear(s);
						return;
					}
					else
					{
						/* s is even */
						mpz_fdiv_q_2exp(s, s, 1UL);
					}
					mpz_powm(foo, a, s, p);
				}
				/* a^s = -1 (mod p) */
				mpz_init_set(b, nqr);
				mpz_init_set(t, p);
				mpz_sub_ui(t, t, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				/* while s even */
				while (mpz_even_p(s))
				{
					mpz_fdiv_q_2exp(s, s, 1UL);
					mpz_fdiv_q_2exp(t, t, 1UL);
					mpz_powm(foo, a, s, p);
					mpz_powm(bar, b, t, p);
					mpz_mul(foo, foo, bar);
					mpz_mod(foo, foo, p);
					mpz_set_si(bar, -1L);
					if (mpz_congruent_p(foo, bar, p))
					{
						/* a^s * b^t = -1 (mod p) */
						mpz_set(bar, p);
						mpz_sub_ui(bar, bar, 1UL);
						mpz_fdiv_q_2exp(bar, bar, 1UL);
						mpz_add(t, t, bar);
					}
				}
				mpz_add_ui(s, s, 1UL);
				mpz_fdiv_q_2exp(s, s, 1UL);
				mpz_fdiv_q_2exp(t, t, 1UL);
				mpz_powm(foo, a, s, p);
				mpz_powm(bar, b, t, p);
				mpz_mul(root, foo, bar);
				mpz_mod(root, root, p);
				mpz_clear(foo), mpz_clear(bar);
				mpz_clear(s), mpz_clear(b), mpz_clear(t);
				return;
			}
		}
	}
	else
		throw std::invalid_argument("tmcg_mpz_sqrtmp_fast: a is zero");
}

void tmcg_mpz_sqrtmn_2
	(mpz_ptr root2, mpz_srcptr root, mpz_srcptr n)
{
	mpz_sub(root2, n, root);
}

void tmcg_mpz_sqrtmn_r
	(mpz_ptr root, mpz_srcptr a, 
	mpz_srcptr p, mpz_srcptr q, mpz_srcptr n)
{
	mpz_t g, u, v;
	mpz_init(g), mpz_init(u), mpz_init(v);
	mpz_gcdext(g, u, v, p, q);
	if (mpz_cmp_ui(g, 1UL) == 0)
	{
		mpz_t root_p, root_q, root1, root2, root3, root4;
		/* single square roots */
		mpz_init(root_p), mpz_init(root_q);
		tmcg_mpz_sqrtmp_r(root_p, a, p);
		tmcg_mpz_sqrtmp_r(root_q, a, q);
		/* construct common square root */
		mpz_init_set(root1, root_q);
		mpz_init_set(root2, root_p);
		mpz_init_set(root3, root_q);
		mpz_init_set(root4, root_p);
		mpz_mul(root1, root1, u);
		mpz_mul(root1, root1, p);
		mpz_mul(root2, root2, v);
		mpz_mul(root2, root2, q);
		mpz_add(root1, root1, root2);
		mpz_mod(root1, root1, n);
		tmcg_mpz_sqrtmn_2(root2, root1, n);
		mpz_neg(root3, root3);
		mpz_mul(root3, root3, u);
		mpz_mul(root3, root3, p);
		mpz_mul(root4, root4, v);
		mpz_mul(root4, root4, q);
		mpz_add(root3, root3, root4);
		mpz_mod(root3, root3, n);
		tmcg_mpz_sqrtmn_2 (root4, root3, n);
		/* choose smallest root */
		mpz_set(root, root1);
		if (mpz_cmpabs(root2, root) < 0)
			mpz_set(root, root2);
		if (mpz_cmpabs(root3, root) < 0)
			mpz_set(root, root3);
		if (mpz_cmpabs(root4, root) < 0)
			mpz_set(root, root4);
		mpz_clear(root_p), mpz_clear(root_q);
		mpz_clear(root1), mpz_clear(root2);
		mpz_clear(root3), mpz_clear(root4);
		mpz_clear(g), mpz_clear(u), mpz_clear(v);
		return;
	}
	mpz_clear(g), mpz_clear(u), mpz_clear(v);
	throw std::runtime_error("tmcg_mpz_sqrtmn_r: gcd(p,q) not equal 1");
}

void tmcg_mpz_sqrtmn
	(mpz_ptr root, mpz_srcptr a, 
	mpz_srcptr p, mpz_srcptr q, mpz_srcptr n)
{
	mpz_t g, u, v;
	mpz_init(g), mpz_init(u), mpz_init(v);
	mpz_gcdext(g, u, v, p, q);
	if (mpz_cmp_ui(g, 1UL) == 0)
	{
		mpz_t root_p, root_q, root1, root2, root3, root4;
		/* single square roots */
		mpz_init(root_p), mpz_init(root_q);
		tmcg_mpz_sqrtmp(root_p, a, p);
		tmcg_mpz_sqrtmp(root_q, a, q);
		/* construct common square root */
		mpz_init_set(root1, root_q);
		mpz_init_set(root2, root_p);
		mpz_init_set(root3, root_q);
		mpz_init_set(root4, root_p);
		mpz_mul(root1, root1, u);
		mpz_mul(root1, root1, p);
		mpz_mul(root2, root2, v);
		mpz_mul(root2, root2, q);
		mpz_add(root1, root1, root2);
		mpz_mod(root1, root1, n);
		tmcg_mpz_sqrtmn_2(root2, root1, n);
		mpz_neg(root3, root3);
		mpz_mul(root3, root3, u);
		mpz_mul(root3, root3, p);
		mpz_mul(root4, root4, v);
		mpz_mul(root4, root4, q);
		mpz_add(root3, root3, root4);
		mpz_mod(root3, root3, n);
		tmcg_mpz_sqrtmn_2 (root4, root3, n);
		/* choose smallest root as result */
		mpz_set(root, root1);
		if (mpz_cmpabs(root2, root) < 0)
			mpz_set(root, root2);
		if (mpz_cmpabs(root3, root) < 0)
			mpz_set(root, root3);
		if (mpz_cmpabs(root4, root) < 0)
			mpz_set(root, root4);
		mpz_clear(root_p), mpz_clear(root_q);
		mpz_clear(root1), mpz_clear(root2);
		mpz_clear(root3), mpz_clear(root4);
		mpz_clear(g), mpz_clear(u), mpz_clear(v);
		return;
	}
	mpz_clear(g), mpz_clear(u), mpz_clear(v);
	throw std::runtime_error("tmcg_mpz_sqrtmn: gcd(p,q) not equal 1");
}

void tmcg_mpz_sqrtmn_r_all
	(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
	mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n)
{
	mpz_t g, u, v;
	
	mpz_init(g), mpz_init(u), mpz_init(v);
	mpz_gcdext(g, u, v, p, q);
	if (mpz_cmp_ui(g, 1UL) == 0)
	{
		mpz_t root_p, root_q;
		/* single square roots */
		mpz_init(root_p), mpz_init(root_q);
		tmcg_mpz_sqrtmp_r(root_p, a, p);
		tmcg_mpz_sqrtmp_r(root_q, a, q);
		/* construct common square root */
		mpz_set(root1, root_q);
		mpz_set(root2, root_p);
		mpz_set(root3, root_q);
		mpz_set(root4, root_p);
		mpz_mul(root1, root1, u);
		mpz_mul(root1, root1, p);
		mpz_mul(root2, root2, v);
		mpz_mul(root2, root2, q);
		mpz_add(root1, root1, root2);
		mpz_mod(root1, root1, n);
		tmcg_mpz_sqrtmn_2(root2, root1, n);
		mpz_neg(root3, root3);
		mpz_mul(root3, root3, u);
		mpz_mul(root3, root3, p);
		mpz_mul(root4, root4, v);
		mpz_mul(root4, root4, q);
		mpz_add(root3, root3, root4);
		mpz_mod(root3, root3, n);
		tmcg_mpz_sqrtmn_2(root4, root3, n);
		mpz_clear(root_p), mpz_clear(root_q);
		mpz_clear(g), mpz_clear(u), mpz_clear(v);
		return;
	}
	mpz_clear(g), mpz_clear(u), mpz_clear(v);
	throw std::runtime_error("tmcg_mpz_sqrtmn_r_all: gcd(p,q) not equal 1");
}

void tmcg_mpz_sqrtmn_all
	(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
	mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n)
{
	mpz_t g, u, v;
	
	mpz_init(g), mpz_init(u), mpz_init(v);
	mpz_gcdext(g, u, v, p, q);
	if (mpz_cmp_ui(g, 1UL) == 0)
	{
		mpz_t root_p, root_q;
		/* single square roots */
		mpz_init(root_p), mpz_init(root_q);
		tmcg_mpz_sqrtmp(root_p, a, p);
		tmcg_mpz_sqrtmp(root_q, a, q);
		/* construct common square root */
		mpz_set(root1, root_q);
		mpz_set(root2, root_p);
		mpz_set(root3, root_q);
		mpz_set(root4, root_p);
		mpz_mul(root1, root1, u);
		mpz_mul(root1, root1, p);
		mpz_mul(root2, root2, v);
		mpz_mul(root2, root2, q);
		mpz_add(root1, root1, root2);
		mpz_mod(root1, root1, n);
		tmcg_mpz_sqrtmn_2(root2, root1, n);
		mpz_neg(root3, root3);
		mpz_mul(root3, root3, u);
		mpz_mul(root3, root3, p);
		mpz_mul(root4, root4, v);
		mpz_mul(root4, root4, q);
		mpz_add(root3, root3, root4);
		mpz_mod(root3, root3, n);
		tmcg_mpz_sqrtmn_2(root4, root3, n);
		mpz_clear(root_p), mpz_clear(root_q);
		mpz_clear(g), mpz_clear(u), mpz_clear(v);
		return;
	}
	mpz_clear(g), mpz_clear(u), mpz_clear(v);
	throw std::runtime_error("tmcg_mpz_sqrtmn_all: gcd(p,q) not equal 1");
}

void tmcg_mpz_sqrtmn_fast
	(mpz_ptr root, mpz_srcptr a,
	mpz_srcptr p, mpz_srcptr q, mpz_srcptr n,
	mpz_srcptr up, mpz_srcptr vq, mpz_srcptr pa1d4, mpz_srcptr qa1d4)
{
	mpz_t root_p, root_q;
	
	/* fast single square roots for Blum Integer */
	mpz_init(root_p), mpz_init(root_q);
	mpz_powm(root_p, a, pa1d4, p);
	mpz_powm(root_q, a, qa1d4, q);
	
	/* construct common square root */
	mpz_mul(root_q, root_q, up);
	mpz_mul(root_p, root_p, vq);
	mpz_add(root, root_q, root_p);
	mpz_mod(root, root, n);
	mpz_clear(root_p), mpz_clear(root_q);
}

void tmcg_mpz_sqrtmn_fast_all
	(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
	mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n,
	mpz_srcptr up, mpz_srcptr vq, mpz_srcptr pa1d4, mpz_srcptr qa1d4)
{
	mpz_t root_p, root_q;
	
	/* fast single square roots for Blum Integer */
	mpz_init(root_p), mpz_init(root_q);
	mpz_powm(root_p, a, pa1d4, p);
	mpz_powm(root_q, a, qa1d4, q);
	
	/* construct common square root */
	mpz_set(root1, root_q);
	mpz_set(root2, root_p);
	mpz_set(root3, root_q);
	mpz_set(root4, root_p);
	mpz_mul(root1, root1, up);
	mpz_mul(root2, root2, vq);
	mpz_add(root1, root1, root2);
	mpz_mod(root1, root1, n);
	mpz_sub(root2, n, root1);
	mpz_neg(root3, root3);
	mpz_mul(root3, root3, up);
	mpz_mul(root4, root4, vq);
	mpz_add(root3, root3, root4);
	mpz_mod(root3, root3, n);
	mpz_sub(root4, n, root3);
	mpz_clear(root_p), mpz_clear(root_q);
}

