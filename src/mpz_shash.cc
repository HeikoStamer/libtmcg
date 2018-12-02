/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

// emulate SHA-3 by public domain code from https://github.com/brainhub/SHA3IUF
#include "sha3.c"
void sha3
	(unsigned char *output,
	const unsigned char *input, const size_t size, int algo)
{
	sha3_context c;
	const uint8_t *hash;

	switch (algo)
	{
		case GCRY_MD_SHA256:
			gcry_md_hash_buffer(algo, output, input, size);
			break;
		case 313: // SHA-3 256 bit output
			sha3_Init256(&c);
			sha3_Update(&c, input, size);
			hash = sha3_Finalize(&c);
			memcpy(output, hash, 32);
			break;
		case 314: // SHA-3 384 bit output
			sha3_Init384(&c);
			sha3_Update(&c, input, size);
			hash = sha3_Finalize(&c);
			memcpy(output, hash, 48);
			break;
		case 315: // SHA-3 512 bit output
			sha3_Init512(&c);
			sha3_Update(&c, input, size);
			hash = sha3_Finalize(&c);
			memcpy(output, hash, 64);
			break;
		default:
			break;
	}
}

/* hash function h() (assumption: collision-resistant cryptographic hash) */
void tmcg_h
	(unsigned char *output,
	const unsigned char *input, const size_t size, int algo)
{
	gcry_md_hash_buffer(algo, output, input, size);
}

/* hash function g() (The design is based on ideas from [BR95].) */
void tmcg_g
	(unsigned char *output, const size_t osize,
	const unsigned char *input, const size_t isize)
{
	bool emulate = false; // emulate GCRY_MD_SHA3_256 (gcry algo constant 313)
	int second_algo = (TMCG_GCRY_MD_ALGO != 313) ? 313 : GCRY_MD_SHA256;
	if (gcry_md_test_algo(second_algo)) // check for SHA3-256 in libgcrypt
		emulate = true;
	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
	size_t mdsize2 = emulate ? 32 : gcry_md_get_algo_dlen(second_algo);
	// hopefully, size of truncation does not match the border
	// of chaining variables in the compression function of h
	size_t usesize = (mdsize / 4) + 1;
	size_t usesize2 = (mdsize2 / 4) + 1;
	size_t times = (osize / usesize) + 1;
	size_t times2 = (osize / usesize2) + 1;
	unsigned char *out = new unsigned char[(times + 1) * mdsize];
	unsigned char *out2 = new unsigned char[(times2 + 1) * mdsize2];
	memset(out, 0, (times + 1) * mdsize);
	memset(out2, 0, (times2 + 1) * mdsize2);
	for (size_t i = 0; i < times; i++)
	{
		// construct the expanded input y = x || libTMCG<i> || x
		size_t dsize = 9 + (2 * isize);
		unsigned char *data = new unsigned char[dsize + 1];
		memcpy(data, input, isize);
		snprintf((char*)data + isize, 10, "libTMCG%02x", (uint8_t)i);
		memcpy(data + isize + 9, input, isize);
		
		// using h(y) "in some nonstandard way" with "output truncated" [BR95]
		tmcg_h(out + (i * (usesize + 2)), data, dsize);
		if (emulate)
			sha3(out2 + (i * (usesize2 + 2)), data, dsize, second_algo);
		else
			tmcg_h(out2 + (i * (usesize2 + 2)), data, dsize, second_algo);
		delete [] data;

		// using h on parts of the whole result again with "output truncated"
		size_t psize2 = ((i + 1) * (mdsize2 - 1));
		tmcg_h(out + (i * usesize), out, ((i + 1) * (mdsize - 1)));
		if (emulate)
			sha3(out2 + (i * usesize2), out2, psize2, second_algo);
		else
			tmcg_h(out2 + (i * usesize2), out2, psize2, second_algo);
	}
	// final output is the XOR of both results
	for (size_t i = 0; i < osize; i++)
		output[i] = out[i] ^ out2[i];
	delete [] out;
	delete [] out2;
}

size_t tmcg_mpz_shash_len
	()
{
	return gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
}

size_t tmcg_mpz_fhash_len
	(int algo)
{
	return gcry_md_get_algo_dlen(algo);
}

void tmcg_mpz_fhash
	(mpz_ptr r, int algo, mpz_srcptr input)
{
	size_t input_size = (mpz_sizeinbase(input, 2UL) + 7) / 8;
	size_t hash_size = tmcg_mpz_fhash_len(algo);
	unsigned char *buffer = new unsigned char[input_size];
	unsigned char *digest = new unsigned char[hash_size];
	char *hex_digest = new char[(2 * hash_size) + 1];

	/* construct and hash the input with default hash function */
	memset(buffer, 0, input_size);
	mpz_export(buffer, NULL, 1, 1, 1, 0, input);
	tmcg_h(digest, buffer, input_size, algo);
	
	/* convert the digest to a hexadecimal encoded string */
	for (size_t i = 0; i < hash_size; i++)
		snprintf(hex_digest + (2 * i), 3, "%02x", digest[i]);
	
	/* convert the hexadecimal encoded string to an mpz-integer */
	mpz_set_str(r, hex_digest, 16);
	
	/* release buffers */
	delete [] buffer, delete [] digest, delete [] hex_digest;
}

void tmcg_mpz_fhash_ggen
	(mpz_ptr r, int algo,
	mpz_srcptr input1, const std::string &input2,
	mpz_srcptr input3, mpz_srcptr input4)
{
	size_t input1_size = ((mpz_sizeinbase(input1, 2UL) + 7) / 8);
	size_t input12_size = input1_size + input2.length();
	size_t input3_size = ((mpz_sizeinbase(input3, 2UL) + 7) / 8);
	size_t input123_size = input12_size + input3_size;
	size_t input4_size = ((mpz_sizeinbase(input4, 2UL) + 7) / 8);
	size_t input_size = input123_size + input4_size;
	size_t hash_size = tmcg_mpz_fhash_len(algo);
	unsigned char *buffer = new unsigned char[input_size];
	unsigned char *digest = new unsigned char[hash_size];
	char *hex_digest = new char[(2 * hash_size) + 1];

	/* construct and hash the input with default hash function */
	memset(buffer, 0, input_size);
	mpz_export(buffer, NULL, 1, 1, 1, 0, input1);
	memcpy(buffer + input1_size, input2.c_str(), input2.length());
	mpz_export(buffer + input12_size, NULL, 1, 1, 1, 0, input3);
	mpz_export(buffer + input123_size, NULL, 1, 1, 1, 0, input4);
	tmcg_h(digest, buffer, input_size, algo);
	
	/* convert the digest to a hexadecimal encoded string */
	for (size_t i = 0; i < hash_size; i++)
		snprintf(hex_digest + (2 * i), 3, "%02x", digest[i]);
	
	/* convert the hexadecimal encoded string to an mpz-integer */
	mpz_set_str(r, hex_digest, 16);
	
	/* release buffers */
	delete [] buffer, delete [] digest, delete [] hex_digest;
}

void tmcg_mpz_shash
	(mpz_ptr r, const std::string &input)
{
	size_t hash_size = tmcg_mpz_shash_len();
	unsigned char *digest = new unsigned char[hash_size];
	char *hex_digest = new char[(2 * hash_size) + 1];
	
	/* hash the input */
	tmcg_g(digest, hash_size, (unsigned char*)input.c_str(), input.length());
	
	/* convert the digest to a hexadecimal encoded string */
	for (size_t i = 0; i < hash_size; i++)
		snprintf(hex_digest + (2 * i), 3, "%02x", digest[i]);
	
	/* convert the hexadecimal encoded string to an mpz-integer */
	mpz_set_str(r, hex_digest, 16);
	
	/* release buffers */
	delete [] digest, delete [] hex_digest;
}

/* Hashing of the public inputs (aka Fiat-Shamir heuristic) with g(),
   e.g. to make some proofs of knowledge (PoK) non-interactive (NIZK). */
void tmcg_mpz_shash
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_1vec
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_2vec
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_4vec
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_2pairvec
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_2pairvec2vec
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
	tmcg_mpz_shash(r, acc);
}

void tmcg_mpz_shash_4pairvec2vec
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
	tmcg_mpz_shash(r, acc);
}

