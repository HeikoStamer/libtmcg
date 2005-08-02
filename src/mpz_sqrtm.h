/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2002, 2004  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_mpz_sqrtm_H
	#define INCLUDED_mpz_sqrtm_H
	
	// GNU multiple precision library
	#include <gmp.h>
	#include "mpz_srandom.h"
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
			
			int mpz_qrmn_p
				(mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
			
			void mpz_sqrtmp_r
				(mpz_ptr root, mpz_srcptr a, mpz_srcptr p);
			
			void mpz_sqrtmp_fast
				(mpz_ptr root, mpz_srcptr a, mpz_srcptr p, mpz_srcptr nqr,
				mpz_srcptr pa1d4, mpz_srcptr ps1d4, mpz_srcptr pa3d8,
				mpz_srcptr nqr_ps1d4);
			
			void mpz_sqrtmn_2
				(mpz_ptr root2, mpz_srcptr root, mpz_srcptr n);
			
			void mpz_sqrtmn_r
				(mpz_ptr root, mpz_srcptr a,
				mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
			
			void mpz_sqrtmn_r_all
				(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
				mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n);
			
			void mpz_sqrtmn_fast
				(mpz_ptr root, mpz_srcptr a, mpz_srcptr p, mpz_srcptr q,
				mpz_srcptr n, mpz_srcptr up, mpz_srcptr vq,
				mpz_srcptr pa1d4, mpz_srcptr qa1d4);
			
			void mpz_sqrtmn_fast_all
				(mpz_ptr root1, mpz_ptr root2, mpz_ptr root3, mpz_ptr root4,
				mpz_srcptr a, mpz_srcptr p, mpz_srcptr q, mpz_srcptr n,
				mpz_srcptr up, mpz_srcptr vq,
				mpz_srcptr pa1d4, mpz_srcptr qa1d4);
			
	#if defined(__cplusplus)
		}
	#endif
#endif
