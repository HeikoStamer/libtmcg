/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2005 Heiko Stamer, <stamer@gaos.org>

     [BR95] Mihir Bellare, Phillip Rogaway. Random Oracles are Practical:
            A Paradigm for Designing Efficient Protocols.
            Proceedings First Annual Conference on Computer and
            Communications Security, ACM, 1993.

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

#include "mpz_shash.hh"

/* hash function h() (collision-resistant?) */
void h
	(char *output, const char *input, size_t size)
{
	gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, output, input, size);
}

/* hash function g() (The design is based on the ideas of [BR95].) */
void g
	(char *output, size_t osize, const char *input, size_t isize)
{
	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	size_t usesize = mdsize / 4;
	size_t times = (osize / usesize) + 1;
	char *out = new char[times * mdsize];
	for (size_t i = 0; i < times; i++)
	{
		/* construct the expanded input y = x || TMCG<i> || x */
		char *data = new char[9 + (2 * isize)];
		memcpy(data, input, isize);
		snprintf(data + isize, 9, "libTMCG%02x", (unsigned int)i);
		memcpy(data + isize + 9, input, isize);
		
		/* using h(y) "in some nonstandard way" with "output truncated" [BR95] */
		h(out + (i * usesize), data, 9 + (2 * isize));
		delete [] data;
	}
	memcpy(output, out, osize);
	delete [] out;
}

/* Hashing of the public inputs (aka Fiat-Shamir heuristic) with h() to
   make the proofs of knowledge non-interactive. */
void mpz_shash
	(mpz_ptr r, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string c_tmp;
	char *vtmp = NULL, *digest = NULL, *hex_digest = NULL;
	unsigned int hash_size = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	digest = new char[hash_size];
	hex_digest = new char[2 * hash_size + 1];
	
	/* concatenate all the arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		vtmp = new char[2 * mpz_sizeinbase(a, 16) + 1];
		c_tmp += mpz_get_str(vtmp, 16, a);
		c_tmp += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	h(digest, c_tmp.c_str(), c_tmp.length());
	
	/* convert the digest to a hexadecimal encoded string */
	for (unsigned int i = 0; i < hash_size; i++)
		snprintf(hex_digest + (2 * i), 3, "%02x", (unsigned char)digest[i]);
	
	/* convert the hexadecimal encoded string to an mpz-integer */
	mpz_set_str(r, hex_digest, 16);
	
	delete [] digest, delete [] hex_digest;
}
