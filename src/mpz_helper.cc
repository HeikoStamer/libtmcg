/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005,
               2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "mpz_helper.hh"

// additional headers
#include <stdexcept>

// get content of mpz_t into gcry_mpi_t
bool tmcg_mpz_get_gcry_mpi
	(gcry_mpi_t &out, mpz_srcptr value)
{
	// two extra bytes are for a possible minus sign, and the null-terminator
	size_t bufsize = mpz_sizeinbase(value, 16) + 2;
	char *buf = new char[bufsize];
	memset(buf, 0, bufsize);
	mpz_get_str(buf, 16, value);
	size_t erroff;
	gcry_mpi_release(out);
	gcry_error_t ret = gcry_mpi_scan(&out, GCRYMPI_FMT_HEX, buf, 0, &erroff);
	delete [] buf;
	if (ret)
		return false;
	else
		return true;
}

// set content of mpz_t from gcry_mpi_t
bool tmcg_mpz_set_gcry_mpi
	(const gcry_mpi_t in, mpz_ptr value)
{
	char *buf = new char[TMCG_MAX_VALUE_CHARS];
	memset(buf, 0, TMCG_MAX_VALUE_CHARS);
	size_t buflen;
	gcry_error_t ret = gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buf,
		TMCG_MAX_VALUE_CHARS - 1, &buflen, in);
	if (ret)
	{
		mpz_set_ui(value, 0L);
		delete [] buf;
		return false;
	}
	else
	{
		mpz_set_str(value, buf, 16);
		delete [] buf;
		return true;
	}
}

// get small values from gcry_mpi_t
size_t tmcg_get_gcry_mpi_ui
	(const gcry_mpi_t in)
{
	char *buf = new char[TMCG_MAX_VALUE_CHARS];
	memset(buf, 0, TMCG_MAX_VALUE_CHARS);
	size_t buflen, result;
	mpz_t value;
	mpz_init(value);
	gcry_error_t ret = gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buf,
		TMCG_MAX_VALUE_CHARS - 1, &buflen, in);
	if (ret)
		mpz_set_ui(value, 0L);
	else
		mpz_set_str(value, buf, 16);
	result = mpz_get_ui(value);
	delete [] buf;
	mpz_clear(value);
	return result;
}

// iostream operators for mpz_t
std::ostream& operator <<
	(std::ostream &out, mpz_srcptr value)
{
	// two extra bytes are for a possible minus sign, and the null-terminator
	size_t bufsize = mpz_sizeinbase(value, TMCG_MPZ_IO_BASE) + 2;
	char *buf = new char[bufsize];
	memset(buf, 0, bufsize);
	out << mpz_get_str(buf, TMCG_MPZ_IO_BASE, value);
	delete [] buf;
	return out;
}

std::istream& operator >>
	(std::istream &in, mpz_ptr value)
{
	char *buf = new char[TMCG_MAX_VALUE_CHARS];
	in.getline(buf, TMCG_MAX_VALUE_CHARS - 1);
	if (mpz_set_str(value, buf, TMCG_MPZ_IO_BASE) < 0)
	{
		mpz_set_ui(value, 0L);
		delete [] buf;
		in.setstate(std::istream::iostate(std::istream::failbit));
		throw std::runtime_error("operator >>: mpz_set_str failed");
	}
	delete [] buf;
	return in;
}

// iostream operators for gcry_mpi_t
std::ostream& operator <<
	(std::ostream &out, const gcry_mpi_t value)
{
	mpz_t tmp;
	mpz_init(tmp);
	if (tmcg_mpz_set_gcry_mpi(value, tmp))
	{
		out << tmp;
	}
	else
	{
		mpz_clear(tmp);
		out.setstate(std::ostream::iostate(std::ostream::failbit));
		throw std::runtime_error("operator <<: tmcg_mpz_set_gcry_mpi failed");
	}
	mpz_clear(tmp);
	return out;
}

// algorithm for polynomial interpolation adapted from Victor Shoup's NTL 10.3.0
bool tmcg_interpolate_polynom
	(const std::vector<mpz_ptr> &a, const std::vector<mpz_ptr> &b,
	mpz_srcptr q, std::vector<mpz_ptr> &f)
{
	size_t m = a.size();
	if ((b.size() != m) || (m == 0) || (f.size() != m) || !mpz_cmp_ui(q, 0UL))
		throw std::invalid_argument("tmcg_interpolate_polynom: bad m or q");
	std::vector<mpz_ptr> prod, res;
	for (size_t k = 0; k < m; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		prod.push_back(tmp1), res.push_back(tmp2);
	}
	for (size_t k = 0; k < m; k++)
		mpz_set(prod[k], a[k]), mpz_set_ui(res[k], 0L);
	mpz_t t1, t2;
	mpz_init(t1), mpz_init(t2);

	try
	{
		for (size_t k = 0; k < m; k++)
		{
			mpz_set_ui(t1, 1L);
			for (long i = k-1; i >= 0; i--)
			{
				mpz_mul(t1, t1, a[k]);
				mpz_mod(t1, t1, q);
				mpz_add(t1, t1, prod[i]);
				mpz_mod(t1, t1, q);
			}
			mpz_set_ui(t2, 0L);
			for (long i = k-1; i >= 0; i--)
			{
				mpz_mul(t2, t2, a[k]);
				mpz_mod(t2, t2, q);
				mpz_add(t2, t2, res[i]);
				mpz_mod(t2, t2, q);
			}
			if (!mpz_invert(t1, t1, q))
				throw false;
			mpz_sub(t2, b[k], t2);
			mpz_mod(t2, t2, q);
			mpz_mul(t1, t1, t2);
			mpz_mod(t1, t1, q);
			for (size_t i = 0; i < k; i++)
			{
				mpz_mul(t2, prod[i], t1);
				mpz_mod(t2, t2, q);
				mpz_add(res[i], res[i], t2);
				mpz_mod(res[i], res[i], q);
			}
			mpz_set(res[k], t1);
			if (k < (m - 1))
			{
				if (k == 0)
					mpz_neg(prod[0], prod[0]);
				else
				{
					mpz_neg(t1, a[k]);
					mpz_add(prod[k], t1, prod[k-1]);
					mpz_mod(prod[k], prod[k], q);
					for (long i = k-1; i >= 1; i--)
					{
						mpz_mul(t2, prod[i], t1);
						mpz_mod(t2, t2, q);
						mpz_add(prod[i], t2, prod[i-1]);
						mpz_mod(prod[i], prod[i], q);
					}
					mpz_mul(prod[0], prod[0], t1);
					mpz_mod(prod[0], prod[0], q);
				}
			}
		}
		for (size_t k = 0; k < m; k++)
			mpz_set(f[k], res[k]);

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		for (size_t k = 0; k < m; k++)
		{
			mpz_clear(prod[k]), mpz_clear(res[k]);
			delete [] prod[k], delete [] res[k];
		}
		prod.clear(), res.clear();
		mpz_clear(t1), mpz_clear(t2);
		// return
		return return_value;
	}
}

