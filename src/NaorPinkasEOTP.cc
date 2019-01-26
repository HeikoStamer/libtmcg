/*******************************************************************************
  NaorPinkasEOTP.cc,
                                 |E|fficient |O|blivious |T|ransfer |P|rotocols

     Moni Naor and Benny Pinkas: 'Efficient Oblivious Transfer Protocols',
     Symposium on Discrete Algorithms (SODA) 2001, pp. 448--457, ACM/SIAM 2001.

   This file is part of LibTMCG.

 Copyright (C) 2016, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "NaorPinkasEOTP.hh"

// additional headers
#include <cassert>
#include <sstream>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

NaorPinkasEOTP::NaorPinkasEOTP
	(unsigned long int fieldsize,
	 unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t k, foo;

	// Initialize and choose the parameters of the scheme.
	mpz_init(p), mpz_init(q), mpz_init(g);
	mpz_init(k);
	tmcg_mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	// choose uniformly at random the element $g$ of order $q$
	do
	{
		tmcg_mpz_wrandomm(g, p);
		mpz_powm(g, g, k, p);
	}
	while (!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
		!mpz_cmp(g, foo)); // check, whether $1 < g < p-1$
	mpz_clear(foo);
	mpz_clear(k);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

NaorPinkasEOTP::NaorPinkasEOTP
	(mpz_srcptr p_ENC,
	 mpz_srcptr q_ENC,
	 mpz_srcptr g_ENC,
	 unsigned long int fieldsize,
	 unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC);
		
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

NaorPinkasEOTP::NaorPinkasEOTP
	(std::istream &in,
	 unsigned long int fieldsize,
	 unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	std::stringstream lej;
	
	mpz_init(p), mpz_init(q), mpz_init(g);
	in >> p >> q >> g;
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

bool NaorPinkasEOTP::CheckGroup
	() const
{
	mpz_t foo, k;
	
	mpz_init(foo), mpz_init(k);
	try
	{
		// Compute $k := (p - 1) / q$
		mpz_set(k, p);
		mpz_sub_ui(k, k, 1L);
		if (!mpz_cmp_ui(q, 0L))
			throw false;
		mpz_div(k, k, q);
		
		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) || 
			(mpz_sizeinbase(q, 2L) < G_size))
				throw false;
		
		// Check whether $p$ has the correct form, i.e. $p = kq + 1$.
		mpz_mul(foo, q, k);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;
		
		// Check whether $p$ and $q$ are both (probable) prime with
		// a soundness error probability ${} \le 4^{-TMCG_MR_ITERATIONS}$.
		if (!mpz_probab_prime_p(p, TMCG_MR_ITERATIONS) || 
			!mpz_probab_prime_p(q, TMCG_MR_ITERATIONS))
				throw false;
		
		// Check whether $k$ is not divisible by $q$, i.e. $q, k$ are coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether $g$ are of order $q$.
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether $g$ is non-trivial, i.e., $1 < g < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, foo) >= 0))
			throw false;
		
		// everything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(k);
		return return_value;
	}
}

void NaorPinkasEOTP::PublishGroup
	(std::ostream& out) const
{
	out << p << std::endl << q << std::endl << g << std::endl;
}

bool NaorPinkasEOTP::CheckElement
	(mpz_srcptr a) const
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// Check whether $0 < a < p$.
		if ((mpz_cmp_ui(a, 0L) <= 0) || (mpz_cmp(a, p) >= 0))
			throw false;
		
		// Check whether $a^q \equiv 1 \pmod{p}$.
		mpz_powm(foo, a, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

/* Sender; see Protocol 4.1 of [NP01] */
bool NaorPinkasEOTP::Send_interactive_OneOutOfTwo
	(mpz_srcptr M0,
	 mpz_srcptr M1,
	 std::istream &in,
	 std::ostream &out) const
{
	// initialize
	mpz_t x, y, foo, bar, z0, z1, s0, s1, r0, r1, w0, w1;
	
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar), mpz_init(z0),
	mpz_init(z1), mpz_init(s0), mpz_init(s1), mpz_init(r0), mpz_init(r1),
	mpz_init(w0), mpz_init(w1);

	try
	{	
		// sender: first move
		in >> x >> y >> z0 >> z1;
		// additionally to [NP01] check, whether the received
		// values are elements of the used order-$q$ subgroup
		if (!CheckElement(x) || !CheckElement(y))
			throw false;
		if (!CheckElement(z0) || !CheckElement(z1))
			throw false;
	
		// sender: second move
		if (!mpz_cmp(z0, z1))
			throw false;
		// generate random $(r_0, s_0)$ and $(r_1, s_1)$
		tmcg_mpz_srandomm(r0, q), tmcg_mpz_srandomm(s0, q);
		tmcg_mpz_srandomm(r1, q), tmcg_mpz_srandomm(s1, q);
		// (a) compute $w_0 = x^{s_0} \cdot g^{r_0}$
		tmcg_mpz_spowm(foo, x, s0, p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, r0, p);
		mpz_mul(w0, foo, bar);
		mpz_mod(w0, w0, p);
		// (a) encrypt $M_0$ using key $z_0^{s_0} \cdot y^{r_0}$
		tmcg_mpz_spowm(foo, z0, s0, p);
		tmcg_mpz_spowm(bar, y, r0, p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, p);
		mpz_mul(foo, foo, M0);
		mpz_mod(foo, foo, p);		
		out << w0 << std::endl << foo << std::endl;
		// (b) compute $w_1 = x^{s_1} \cdot g^{r_1}$
		tmcg_mpz_spowm(foo, x, s1, p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, r1, p);
		mpz_mul(w1, foo, bar);
		mpz_mod(w1, w1, p);
		// (b) encrypt $M_1$ using key $z_1^{s_1} \cdot y^{r_1}$
		tmcg_mpz_spowm(foo, z1, s1, p);
		tmcg_mpz_spowm(bar, y, r1, p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, p);
		mpz_mul(foo, foo, M1);
		mpz_mod(foo, foo, p);		
		out << w1 << std::endl << foo << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar),
		mpz_clear(z0), mpz_clear(z1), mpz_clear(s0), mpz_clear(s1),
		mpz_clear(r0), mpz_clear(r1), mpz_clear(w0), mpz_clear(w1);
		// return
		return return_value;
	}
}

/* Receiver; see Protocol 4.1 of [NP01] */
bool NaorPinkasEOTP::Choose_interactive_OneOutOfTwo
	(const size_t sigma,
	 mpz_ptr M,
	 std::istream &in,
	 std::ostream &out) const
{
	assert(sigma < 2);
	
	// initialize
	mpz_t a, b, c0, c1, x, y, foo, bar, z0, z1, w0, w1;
	
	mpz_init(a), mpz_init(b), mpz_init(c0), mpz_init(c1);
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar);
	mpz_init(z0), mpz_init(z1), mpz_init(w0), mpz_init(w1);

	try
	{	
		// receiver: first move
		tmcg_mpz_srandomm(a, q);
		tmcg_mpz_fspowm(fpowm_table_g, x, g, a, p);
		tmcg_mpz_srandomm(b, q);
		tmcg_mpz_fspowm(fpowm_table_g, y, g, b, p);
		if (sigma == 0)
		{
			tmcg_mpz_srandomm(c1, q);
			mpz_mul(c0, a, b);
			mpz_mod(c0, c0, q);
		}
		else if (sigma == 1)
		{
			tmcg_mpz_srandomm(c0, q);
			mpz_mul(c1, a, b);
			mpz_mod(c1, c1, q);
		}
		tmcg_mpz_fspowm(fpowm_table_g, z0, g, c0, p);
		tmcg_mpz_fspowm(fpowm_table_g, z1, g, c1, p);
		out << x << std::endl << y << std::endl;
		out << z0 << std::endl << z1 << std::endl;
	
		// receiver: second move
		in >> w0 >> c0 >> w1 >> c1;
		if (!CheckElement(w0) || !CheckElement(w1))
			throw false;	// check in-subgroup property
		if (sigma == 0)
		{		
			mpz_powm(foo, w0, b, p);
			if (!mpz_invert(bar, foo, p))
				throw false;
			mpz_mul(M, c0, bar);
			mpz_mod(M, M, p);
		}
		else if (sigma == 1)
		{
			mpz_powm(foo, w1, b, p);
			if (!mpz_invert(bar, foo, p))
				throw false;
			mpz_mul(M, c1, bar);
			mpz_mod(M, M, p);
		}

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c0), mpz_clear(c1);
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar);
		mpz_clear(z0), mpz_clear(z1), mpz_clear(w0), mpz_clear(w1);
		// return
		return return_value;
	}
}

/* Sender; see Protocol 4.1 of [NP01] with remarks in section 4.1 */
bool NaorPinkasEOTP::Send_interactive_OneOutOfN
	(const std::vector<mpz_ptr> &M,
	 std::istream &in,
	 std::ostream &out) const
{
	assert(M.size() >= 2);
	
	// initialize
	mpz_t x, y, foo, bar;
	std::vector<mpz_ptr> z, s, r, w, ENC;
	
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar);
	for (size_t i = 0; i < M.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(),
			tmp3 = new mpz_t(), tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		z.push_back(tmp1), s.push_back(tmp2), r.push_back(tmp3),
			w.push_back(tmp4);
		mpz_ptr tmp7 = new mpz_t();
		mpz_init(tmp7);
		ENC.push_back(tmp7);
	}

	try
	{	
		// sender: first move
		in >> x >> y;
		for (size_t i = 0; i < z.size(); i++)
			in >> z[i];
		// additionally to [NP01] check, whether the received
		// values are elements of the used order-$q$ subgroup
		if (!CheckElement(x) || !CheckElement(y))
			throw false;
		for (size_t i = 0; i < z.size(); i++)
		{
			if (!CheckElement(z[i]))
				throw false;
		}
	
		// sender: second move
		for (size_t i = 0; i < z.size(); i++)
		{
			for (size_t j = 0; j < i; j++)
			{
				if (!mpz_cmp(z[i], z[j]))
					throw false;
			}
		}
		for (size_t i = 0; i < M.size(); i++)
		{
			// choose random $(r_i, s_i)$
			tmcg_mpz_srandomm(s[i], q);
			tmcg_mpz_srandomm(r[i], q);
			// compute $w_i = x^{s_i} \cdot g^{r_i}$
			tmcg_mpz_spowm(foo, x, s[i], p);
			tmcg_mpz_fspowm(fpowm_table_g, bar, g, r[i], p);
			mpz_mul(w[i], foo, bar);
			mpz_mod(w[i], w[i], p);
			// encrypt $M_i$ using key $z_i^{s_i} \cdot y^{r_i}$
			tmcg_mpz_spowm(foo, z[i], s[i], p);
			tmcg_mpz_spowm(bar, y, r[i], p);
			mpz_mul(ENC[i], foo, bar);
			mpz_mod(ENC[i], ENC[i], p);
			mpz_mul(ENC[i], ENC[i], M[i]);
			mpz_mod(ENC[i], ENC[i], p);		
		}
		for (size_t i = 0; i < M.size(); i++)
			out << w[i] << std::endl << ENC[i] << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar);
		for (size_t i = 0; i < M.size(); i++)
		{
			mpz_clear(z[i]), mpz_clear(s[i]), mpz_clear(r[i]), mpz_clear(w[i]);
			delete [] z[i], delete [] s[i], delete [] r[i], delete [] w[i];
			mpz_clear(ENC[i]);
			delete [] ENC[i];
		}
		z.clear(), s.clear(), r.clear(), w.clear(), ENC.clear();
		// return
		return return_value;
	}
}

/* Receiver; see Protocol 4.1 of [NP01] with remarks in section 4.1 */
bool NaorPinkasEOTP::Choose_interactive_OneOutOfN
	(const size_t sigma,
	 const size_t N,
	 mpz_ptr M,
	 std::istream &in,
	 std::ostream &out) const
{
	assert(N >= 2);
	assert(sigma < N);
	
	// initialize
	mpz_t a, b, c, x, y, foo, bar;
	std::vector<mpz_ptr> z, w, ENC;
	
	mpz_init(a), mpz_init(b), mpz_init(c);
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar);
	for (size_t i = 0; i < N; i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(),
			tmp3 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3);
		z.push_back(tmp1), w.push_back(tmp2), ENC.push_back(tmp3);
	}

	try
	{	
		// receiver: first move
		tmcg_mpz_srandomm(a, q);
		tmcg_mpz_fspowm(fpowm_table_g, x, g, a, p);
		tmcg_mpz_srandomm(b, q);
		tmcg_mpz_fspowm(fpowm_table_g, y, g, b, p);
		for (size_t i = 0; i < z.size(); i++)
		{
			tmcg_mpz_srandomm(c, q);
			if (i == sigma)
			{
				mpz_mul(c, a, b);
				mpz_mod(c, c, q);
			}
			tmcg_mpz_fspowm(fpowm_table_g, z[i], g, c, p);
		}
		out << x << std::endl << y << std::endl;
		for (size_t i = 0; i < z.size(); i++)
			out << z[i] << std::endl;
	
		// receiver: second move
		for (size_t i = 0; i < N; i++)
			in >> w[i] >> ENC[i];
		for (size_t i = 0; i < N; i++)
		{
			if (!CheckElement(w[i]))
				throw false;	// check in-subgroup property
		}
		mpz_powm(foo, w[sigma], b, p);
		if (!mpz_invert(bar, foo, p))
			throw false;
		mpz_mul(M, ENC[sigma], bar);
		mpz_mod(M, M, p);

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c);
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar);
		for (size_t i = 0; i < N; i++)
		{
			mpz_clear(z[i]), mpz_clear(w[i]);
			delete [] z[i], delete [] w[i];
			mpz_clear(ENC[i]);
			delete [] ENC[i];
		}
		z.clear(), w.clear(), ENC.clear();
		// return
		return return_value;
	}
}

/* Sender; see Protocol 4.1 of [NP01] with remarks in section 4.1 */
bool NaorPinkasEOTP::Send_interactive_OneOutOfN_optimized
	(const std::vector<mpz_ptr> &M,
	 std::istream &in,
	 std::ostream &out) const
{
	assert(M.size() >= 2);
	
	// initialize
	mpz_t x, y, foo, bar, z0;
	std::vector<mpz_ptr> s, r, w, ENC;
	
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar), mpz_init(z0);
	for (size_t i = 0; i < M.size(); i++)
	{
		mpz_ptr tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		s.push_back(tmp2), r.push_back(tmp3), w.push_back(tmp4);
		mpz_ptr tmp7 = new mpz_t();
		mpz_init(tmp7);
		ENC.push_back(tmp7);
	}

	try
	{	
		// sender: first move
		in >> x >> y >> z0;
		// additionally to [NP01] check, whether the received
		// values are elements of the used order-$q$ subgroup
		if (!CheckElement(x) || !CheckElement(y) || !CheckElement (z0))
			throw false;
	
		// sender: second move
		for (size_t i = 0; i < M.size(); i++)
		{
			// choose random $(r_i, s_i)$
			tmcg_mpz_srandomm(s[i], q);
			tmcg_mpz_srandomm(r[i], q);
			// compute $w_i = x^{s_i} \cdot g^{r_i}$
			tmcg_mpz_spowm(foo, x, s[i], p);
			tmcg_mpz_fspowm(fpowm_table_g, bar, g, r[i], p);
			mpz_mul(w[i], foo, bar);
			mpz_mod(w[i], w[i], p);
			// encrypt $M_i$ using key $z_i^{s_i} \cdot y^{r_i}$
			if (i > 0)
			{
				mpz_mul(z0, z0, g); // $z_i = z_0 \cdot g^i$
				mpz_mod(z0, z0, p);
			}			
			tmcg_mpz_spowm(foo, z0, s[i], p);
			tmcg_mpz_spowm(bar, y, r[i], p);
			mpz_mul(ENC[i], foo, bar);
			mpz_mod(ENC[i], ENC[i], p);
			mpz_mul(ENC[i], ENC[i], M[i]);
			mpz_mod(ENC[i], ENC[i], p);		
		}
		for (size_t i = 0; i < M.size(); i++)
			out << w[i] << std::endl << ENC[i] << std::endl;

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar),
		mpz_clear(z0);
		for (size_t i = 0; i < M.size(); i++)
		{
			mpz_clear(s[i]), mpz_clear(r[i]), mpz_clear(w[i]);
			delete [] s[i], delete [] r[i], delete [] w[i];
			mpz_clear(ENC[i]);
			delete [] ENC[i];
		}
		s.clear(), r.clear(), w.clear(), ENC.clear();
		// return
		return return_value;
	}
}

/* Receiver; see Protocol 4.1 of [NP01] with remarks in section 4.1 */
bool NaorPinkasEOTP::Choose_interactive_OneOutOfN_optimized
	(const size_t sigma,
	 const size_t N,
	 mpz_ptr M,
	 std::istream &in,
	 std::ostream &out) const
{
	assert(N >= 2);
	assert(sigma < N);
	
	// initialize
	mpz_t a, b, c, x, y, foo, bar, z0;
	std::vector<mpz_ptr> w, ENC;
	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(z0);
	mpz_init(x), mpz_init(y), mpz_init(foo), mpz_init(bar);
	for (size_t i = 0; i < N; i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2);
		w.push_back(tmp1), ENC.push_back(tmp2);
	}

	try
	{	
		// receiver: first move
		tmcg_mpz_srandomm(a, q);
		tmcg_mpz_fspowm(fpowm_table_g, x, g, a, p);
		tmcg_mpz_srandomm(b, q);
		tmcg_mpz_fspowm(fpowm_table_g, y, g, b, p);
		mpz_mul(c, a, b);
		mpz_mod(c, c, q);
		tmcg_mpz_fspowm(fpowm_table_g, z0, g, c, p);
		mpz_set_ui(foo, sigma);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, foo, p);
		assert(mpz_invert(foo, bar, p));
		mpz_mul(z0, z0, foo); // $z_0 = g^c / g^i$
		mpz_mod(z0, z0, p);
		out << x << std::endl << y << std::endl << z0 << std::endl;
	
		// receiver: second move
		for (size_t i = 0; i < N; i++)
			in >> w[i] >> ENC[i];
		for (size_t i = 0; i < N; i++)
		{
			if (!CheckElement(w[i]))
				throw false;	// check in-subgroup property
		}
		mpz_powm(foo, w[sigma], b, p);
		if (!mpz_invert(bar, foo, p))
			throw false;
		mpz_mul(M, ENC[sigma], bar);
		mpz_mod(M, M, p);

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(z0);
		mpz_clear(x), mpz_clear(y), mpz_clear(foo), mpz_clear(bar);
		for (size_t i = 0; i < N; i++)
		{
			mpz_clear(w[i]);
			delete [] w[i];
			mpz_clear(ENC[i]);
			delete [] ENC[i];
		}
		w.clear(), ENC.clear();
		// return
		return return_value;
	}
}

NaorPinkasEOTP::~NaorPinkasEOTP
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g);
	
	tmcg_mpz_fpowm_done(fpowm_table_g);
	delete [] fpowm_table_g;
}

