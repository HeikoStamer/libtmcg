/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2002, 2004 Heiko Stamer, <stamer@gaos.org>

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

#include "mpz_srandom.h"

size_t mpz_srandom
	()
{
	size_t tmp;
	gcry_randomize((unsigned char *)&tmp, sizeof(tmp), GCRY_STRONG_RANDOM);
	return tmp;
}

void mpz_ssrandomb
	(mpz_ptr r, unsigned long int size)
{
	unsigned char *rtmp;
	gcry_mpi_t rr = gcry_mpi_new((unsigned int)size);
	
	gcry_mpi_randomize(rr, (unsigned int)size, GCRY_VERY_STRONG_RANDOM);
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, NULL, rr);
	mpz_set_str(r, (char*)rtmp, 16);
	mpz_tdiv_r_2exp(r, r, size);
	gcry_mpi_release(rr);
	gcry_free(rtmp);
}

void mpz_srandomb
	(mpz_ptr r, unsigned long int size)
{
	unsigned char *rtmp;
	gcry_mpi_t rr = gcry_mpi_new((unsigned int)size);
	
	gcry_mpi_randomize(rr, (unsigned int)size, GCRY_STRONG_RANDOM);
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, NULL, rr);
	mpz_set_str(r, (char*)rtmp, 16);
	mpz_tdiv_r_2exp(r, r, size);
	gcry_mpi_release(rr);
	gcry_free(rtmp);
}

void mpz_ssrandomm
	(mpz_ptr r, mpz_srcptr m)
{
	unsigned char *rtmp;
	gcry_mpi_t rr = gcry_mpi_new((unsigned int)mpz_sizeinbase(m, 2));
	
	gcry_mpi_randomize(rr, (unsigned int)mpz_sizeinbase(m, 2),
		GCRY_VERY_STRONG_RANDOM);
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, NULL, rr);
	mpz_set_str(r, (char*)rtmp, 16);
	mpz_mod(r, r, m);
	gcry_mpi_release(rr);
	gcry_free(rtmp);
}

void mpz_srandomm
	(mpz_ptr r, mpz_srcptr m)
{
	unsigned char *rtmp;
	gcry_mpi_t rr = gcry_mpi_new((unsigned int)mpz_sizeinbase(m, 2));
	
	gcry_mpi_randomize(rr, (unsigned int)mpz_sizeinbase(m, 2),
		GCRY_STRONG_RANDOM);
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &rtmp, NULL, rr);
	mpz_set_str(r, (char*)rtmp, 16);
	mpz_mod(r, r, m);
	gcry_mpi_release(rr);
	gcry_free(rtmp);
}
