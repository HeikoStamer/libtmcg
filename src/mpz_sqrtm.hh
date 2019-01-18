/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2002, 2004, 2016, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_mpz_sqrtm_HH
	#define INCLUDED_mpz_sqrtm_HH
	
	/* GNU multiple precision library */
	#include <gmp.h>
	
	int tmcg_mpz_qrmn_p
		(mpz_srcptr a, mpz_srcptr p, mpz_srcptr q);

	void tmcg_mpz_sqrtmp_r
		(mpz_ptr root, mpz_srcptr a, mpz_srcptr p);
	void tmcg_mpz_sqrtmp
		(mpz_ptr root, mpz_srcptr a, mpz_srcptr p);
	void tmcg_mpz_sqrtmp_fast
		(mpz_ptr root, mpz_srcptr a, mpz_srcptr p, mpz_srcptr nqr,
		mpz_srcptr pa1d4, mpz_srcptr ps1d4, mpz_srcptr pa3d8,
		mpz_srcptr nqr_ps1d4);

	void tmcg_mpz_sqrtmn_2
		(mpz_ptr root2, mpz_srcptr root, mpz_srcptr n);
	void tmcg_mpz_sqrtmn_r
		(mpz_ptr root, mpz_srcptr a,
		mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
	void tmcg_mpz_sqrtmn
		(mpz_ptr root, mpz_srcptr a,
		mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
	void tmcg_mpz_sqrtmn_r_all
		(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
		mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
	void tmcg_mpz_sqrtmn_all
		(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
		mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
	void tmcg_mpz_sqrtmn_fast
		(mpz_ptr root, mpz_srcptr a, mpz_srcptr p, mpz_srcptr q,
		mpz_srcptr n, mpz_srcptr up, mpz_srcptr vq,
		mpz_srcptr pa1d4, mpz_srcptr qa1d4);
	void tmcg_mpz_sqrtmn_fast_all
		(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
		mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n,
		mpz_srcptr up, mpz_srcptr vq,
		mpz_srcptr pa1d4, mpz_srcptr qa1d4);
#endif

