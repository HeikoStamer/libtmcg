/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

// iostream operators for mpz_t
std::ostream& operator <<
	(std::ostream &out, mpz_srcptr value)
{
	char *tmp = new char[TMCG_MAX_VALUE_CHARS];
	if (mpz_sizeinbase(value, TMCG_MPZ_IO_BASE) < TMCG_MAX_VALUE_CHARS)
		out << mpz_get_str(tmp, TMCG_MPZ_IO_BASE, value);
	delete [] tmp;
	return out;
}

std::istream& operator >>
	(std::istream &in, mpz_ptr value)
{
	char *tmp = new char[TMCG_MAX_VALUE_CHARS];
	in.getline(tmp, TMCG_MAX_VALUE_CHARS);
	if (mpz_set_str(value, tmp, TMCG_MPZ_IO_BASE) < 0)
	{
		mpz_set_ui(value, 0L);
		in.setstate(std::istream::iostate(std::istream::failbit));
	}
	delete [] tmp;
	return in;
}

/* The algorithm for polynomial interpolation is adapted from Victor Shoup's NTL 10.3.0. */
bool interpolate_polynom
	(const std::vector<mpz_ptr> &a, const std::vector<mpz_ptr> &b,
	mpz_srcptr q, std::vector<mpz_ptr> &f)
{
	size_t m = a.size();
	if ((b.size() != m) || (m == 0) || (f.size() != m)) 
		return false;
	std::vector<mpz_ptr> prod, res;
	for (size_t k = 0; k < m; k++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		prod.push_back(tmp1), res.push_back(tmp2);
	}
	for (size_t k = 0; k < m; k++)
		mpz_set(prod[k], a[k]), mpz_set_ui(res[k], 0L);
	mpz_t t1, t2, aa;
	mpz_init(t1), mpz_init(t2), mpz_init(aa);

	try
	{
		for (size_t k = 0; k < m; k++)
		{
			mpz_set(aa, a[k]);
			mpz_set_ui(t1, 1L);
			for (long i = k-1; i >= 0; i--)
			{
				mpz_mul(t1, t1, aa);
				mpz_mod(t1, t1, q);
				mpz_add(t1, t1, prod[i]);
				mpz_mod(t1, t1, q);
			}
			mpz_set_ui(t2, 0L);
			for (long i = k-1; i >= 0; i--)
			{
				mpz_mul(t2, t2, aa);
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
		mpz_clear(t1), mpz_clear(t2), mpz_clear(aa);
		// return
		return return_value;
	}
}
