/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

     [BR95] Mihir Bellare, Phillip Rogaway: 'Random Oracles are Practical:
             A Paradigm for Designing Efficient Protocols',
            Proceedings First Annual Conference on Computer and
             Communications Security, ACM, 1993.

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
#include "mpz_shash.hh"

/* hash function h() (assumption: collision-resistant) */
void h
	(unsigned char *output,
	const unsigned char *input, const size_t size)
{
	gcry_md_hash_buffer(TMCG_GCRY_MD_ALGO, output, input, size);
}

/* hash function g() (The design is based on the ideas of [BR95].) */
void g
	(unsigned char *output, const size_t osize,
	const unsigned char *input, const size_t isize)
{
	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	// hopefully this truncation size does not match the border
	// of chaining variables in the compression function of h
	size_t usesize = (mdsize / 4) + 1;
	size_t times = (osize / usesize) + 1;
	unsigned char *out = new unsigned char[(times + 1) * mdsize];
	memset(out, 0, (times + 1) * mdsize);
	for (size_t i = 0; i < times; i++)
	{
		/* construct the expanded input y = x || libTMCG<i> || x */
		unsigned char *data = new unsigned char[9 + (2 * isize)];
		memcpy(data, input, isize);
		snprintf((char*)data + isize, 9, "libTMCG%02x", (unsigned int)i);
		memcpy(data + isize + 9, input, isize);
		
		/* using h(y) "in some nonstandard way" with "output truncated" [BR95] */
		h(out + (i * (usesize + 2)), data, 9 + (2 * isize));
		delete [] data;

		/* using h on parts of the whole result again with "output truncated" */
		h(out + (i * usesize), out, ((i + 1) * (mdsize - 1)));
	}
	memcpy(output, out, osize);
	delete [] out;
}

void mpz_shash
	(mpz_ptr r, std::string input)
{
	size_t hash_size = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	unsigned char *digest = new unsigned char[hash_size];
	unsigned char *hex_digest = new unsigned char[(2 * hash_size) + 1];
	
	/* hash the input */
	g(digest, hash_size, (unsigned char*)input.c_str(), input.length());
	
	/* convert the digest to a hexadecimal encoded string */
	for (size_t i = 0; i < hash_size; i++)
		snprintf((char*)hex_digest + (2 * i), 3, "%02x", digest[i]);
	
	/* convert the hexadecimal encoded string to an mpz-integer */
	mpz_set_str(r, (char*)hex_digest, 16);
	
	delete [] digest, delete [] hex_digest;
}

/* Hashing of the public inputs (aka Fiat-Shamir heuristic) with g(),
   e.g. to make some proofs of knowledge (PoK) non-interactive. */
void mpz_shash
	(mpz_ptr r, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;
	
	/* concatenate all the arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		size_t vlen = (2 * mpz_sizeinbase(a, 16)) + 1;
		char *vtmp = new char[vlen];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_1vec
	(mpz_ptr r, const std::vector<mpz_ptr>& v, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the vector */
	for (size_t i = 0; i < v.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(v[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, v[i]);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_2vec
	(mpz_ptr r, const std::vector<mpz_ptr>& v,
	const std::vector<mpz_ptr>& w, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the vectors */
	for (size_t i = 0; i < v.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(v[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, v[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < w.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(w[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, w[i]);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_4vec
	(mpz_ptr r, const std::vector<mpz_ptr>& v,
	const std::vector<mpz_ptr>& w, const std::vector<mpz_ptr>& x,
	const std::vector<mpz_ptr>& y, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the vectors */
	for (size_t i = 0; i < v.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(v[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, v[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < w.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(w[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, w[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < x.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(x[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, x[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < y.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(y[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, y[i]);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_2pairvec
	(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp, size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the pair vectors */
	for (size_t i = 0; i < vp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(vp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(vp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].second);
		acc += "|";
		delete [] vtmp;

	}
	for (size_t i = 0; i < wp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(wp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(wp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].second);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_2pairvec2vec
	(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
	const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
	size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the pair vectors */
	for (size_t i = 0; i < vp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(vp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(vp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].second);
		acc += "|";
		delete [] vtmp;

	}
	for (size_t i = 0; i < wp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(wp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(wp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].second);
		acc += "|";
		delete [] vtmp;
	}

	/* concatenate the elements of the vectors */
	for (size_t i = 0; i < v.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(v[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, v[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < w.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(w[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, w[i]);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}

void mpz_shash_4pairvec2vec
	(mpz_ptr r, const std::vector<std::pair<mpz_ptr, mpz_ptr> >& vp,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& wp,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& xp,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& yp,
	const std::vector<mpz_ptr>& v, const std::vector<mpz_ptr>& w,
	size_t n, ...)
{
	va_list ap;
	mpz_srcptr a;
	std::string acc;

	/* concatenate the elements of the pair vectors */
	for (size_t i = 0; i < vp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(vp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(vp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, vp[i].second);
		acc += "|";
		delete [] vtmp;

	}
	for (size_t i = 0; i < wp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(wp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(wp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, wp[i].second);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < xp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(xp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, xp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(xp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, xp[i].second);
		acc += "|";
		delete [] vtmp;

	}
	for (size_t i = 0; i < yp.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(yp[i].first, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, yp[i].first);
		acc += "|";
		delete [] vtmp;
		vtmp = new char[(2 * mpz_sizeinbase(yp[i].second, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, yp[i].second);
		acc += "|";
		delete [] vtmp;
	}

	/* concatenate the elements of the vectors */
	for (size_t i = 0; i < v.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(v[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, v[i]);
		acc += "|";
		delete [] vtmp;
	}
	for (size_t i = 0; i < w.size(); i++)
	{
		char *vtmp = new char[(2 * mpz_sizeinbase(w[i], 16)) + 1];
		acc += mpz_get_str(vtmp, 16, w[i]);
		acc += "|";
		delete [] vtmp;
	}
	
	/* concatenate all the remaining arguments */
	va_start(ap, n);
	for (size_t i = 0; i < n; i++)
	{
		a = (mpz_srcptr) va_arg(ap, mpz_srcptr);
		char *vtmp = new char[(2 * mpz_sizeinbase(a, 16)) + 1];
		acc += mpz_get_str(vtmp, 16, a);
		acc += "|";
		delete [] vtmp;
	}
	va_end(ap);
	
	/* hash arguments */
	mpz_shash(r, acc);
}
