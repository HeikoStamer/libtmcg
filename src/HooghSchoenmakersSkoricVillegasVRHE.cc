/*******************************************************************************
  HooghSchoenmakersSkoricVillegasVRHE.cc,
                         |V|erifiable |R|otation of |H|omomorphic |E|ncryptions

     Sebastiaan de Hoogh, Berry Schoenmakers, Boris Skoric, and Jose Villegas:
       'Verifiable Rotation of Homomorphic Encryptions',
     Public Key Cryptography 2009, LNCS 5443, pp. 393--410, Springer 2009.

   This file is part of LibTMCG.

 Copyright (C) 2009,
               2015, 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "HooghSchoenmakersSkoricVillegasVRHE.hh"

// additional headers
#include <cassert>
#include <string>
#include <sstream>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

HooghSchoenmakersSkoricVillegasPUBROTZK::HooghSchoenmakersSkoricVillegasPUBROTZK
	(mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC)
{
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool HooghSchoenmakersSkoricVillegasPUBROTZK::CheckElement
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

void HooghSchoenmakersSkoricVillegasPUBROTZK::Prove_interactive
	(size_t r, const std::vector<mpz_ptr> &s, 
	const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	std::istream &in, std::ostream &out) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	assert(r < alpha.size());
	assert(s.size() == alpha.size());
	
	// initialize
	mpz_t u, G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(u), mpz_init(G), mpz_init(lambda), mpz_init(foo),
		mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}

	// prover: first move
	for (size_t i = 0; i < beta.size(); i++)
	{
		in >> beta[i];
		// reduce $\beta_i$'s modulo $q$
		mpz_mod(beta[i], beta[i], q);
	}

	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	tmcg_mpz_srandomm(u, q);
	// compute $G$
	mpz_set_ui(G, 1L);
	for (size_t j = 0; j < c.size(); j++) {
		mpz_powm(foo, c[j], beta[j], p);
		mpz_mul(G, G, foo);
		mpz_mod(G, G, p);
	}
	for (size_t j = 0; j < alpha.size(); j++)
	{
		if (j != r)
		{
			tmcg_mpz_srandomm(lambdak[j], q);
			tmcg_mpz_srandomm(tk[j], q);

			// compute $\gamma_j = \sum_i \alpha_{i-j}\beta_i
			mpz_set_ui(bar, 0L);
			for (size_t i = 0; i < alpha.size(); i++)
			{
				size_t ij = (i >= j) ? i-j : alpha.size() - (j-i) ; // compute $i - j (mod n)$
				mpz_mul(foo, alpha[ij], beta[i]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}
			// compute $f_j = g^{\lambda_j \gamma_j} \tilde{h}^{t_j} G^{-\lambda_j}$
			mpz_mul(foo, lambdak[j], bar);
			mpz_mod(foo, foo, q);
			tmcg_mpz_fspowm(fpowm_table_g, f[j], g, foo, p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[j], p);
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
			tmcg_mpz_spowm(foo, G, lambdak[j], p);
			if (!mpz_invert(bar, foo, p))
				mpz_set_ui(bar, 0L); // indicates an error
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
		}
	}
	tmcg_mpz_fspowm(fpowm_table_h, f[r], h, u, p);
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;

	// prover: third move
	in >> lambda;
	// reduce $\lambda$ modulo $q$
	mpz_mod(lambda, lambda, q);
	// compute $\lambda_r = \lambda - \sum_{j \neq r} \lambda_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < lambdak.size(); j++)
	{
		if (j != r)
		{
			mpz_add(foo, foo, lambdak[j]);
			mpz_mod(foo, foo, q);
		}
	}
	mpz_sub(lambdak[r], lambda, foo);
	mpz_add(lambdak[r], lambdak[r], q); // add q to stay in the group
	mpz_mod(lambdak[r], lambdak[r], q);
	// compute $t_r = u + \lambda_r \sum_j s_j \beta_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < s.size(); j++)
	{
		mpz_mul(bar, s[j], beta[j]);
		mpz_mod(bar, bar, q);
		mpz_add(foo, foo, bar);
		mpz_mod(foo, foo, q);
	}
	mpz_mul(foo, foo, lambdak[r]);
	mpz_mod(foo, foo, q);
	mpz_add(tk[r], u, foo);
	mpz_mod(tk[r], tk[r], q);
	for (size_t i = 0; i < lambdak.size(); i++)
		out << lambdak[i] << std::endl;
	for (size_t i = 0; i < tk.size(); i++)
		out << tk[i] << std::endl;
	
	// release
	mpz_clear(u), mpz_clear(G), mpz_clear(lambda), mpz_clear(foo),
		mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
			mpz_clear(lambdak[i]);
		delete [] beta[i], delete [] f[i], delete [] tk[i],
			delete [] lambdak[i];
	}
	beta.clear(), f.clear(), tk.clear(), lambdak.clear();
}

void HooghSchoenmakersSkoricVillegasPUBROTZK::Prove_interactive_publiccoin
	(size_t r, const std::vector<mpz_ptr> &s, 
	const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	JareckiLysyanskayaEDCF *edcf,
	std::istream &in, std::ostream &out) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	assert(r < alpha.size());
	assert(s.size() == alpha.size());
	
	// initialize
	mpz_t u, G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(u), mpz_init(G), mpz_init(lambda), mpz_init(foo),
		mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}

	// prover: first move
	for (size_t i = 0; i < beta.size(); i++)
	{
		std::stringstream err;
		edcf->Flip_twoparty(0, beta[i], in, out, err); // flip coins with verifier to get $\beta_i$
		// reduce $\beta_i$'s modulo $q$
		mpz_mod(beta[i], beta[i], q);
	}

	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	tmcg_mpz_srandomm(u, q);
	// compute $G$
	mpz_set_ui(G, 1L);
	for (size_t j = 0; j < c.size(); j++) {
		mpz_powm(foo, c[j], beta[j], p);
		mpz_mul(G, G, foo);
		mpz_mod(G, G, p);
	}
	for (size_t j = 0; j < alpha.size(); j++)
	{
		if (j != r)
		{
			tmcg_mpz_srandomm(lambdak[j], q);
			tmcg_mpz_srandomm(tk[j], q);

			// compute $\gamma_j = \sum_i \alpha_{i-j}\beta_i
			mpz_set_ui(bar, 0L);
			for (size_t i = 0; i < alpha.size(); i++)
			{
				size_t ij = (i >= j) ? i-j : alpha.size() - (j-i) ; // compute $i - j (mod n)$
				mpz_mul(foo, alpha[ij], beta[i]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}
			// compute $f_j = g^{\lambda_j \gamma_j} \tilde{h}^{t_j} G^{-\lambda_j}$
			mpz_mul(foo, lambdak[j], bar);
			mpz_mod(foo, foo, q);
			tmcg_mpz_fspowm(fpowm_table_g, f[j], g, foo, p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[j], p);
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
			tmcg_mpz_spowm(foo, G, lambdak[j], p);
			if (!mpz_invert(bar, foo, p))
				mpz_set_ui(bar, 0L); // indicates an error
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
		}
	}
	tmcg_mpz_fspowm(fpowm_table_h, f[r], h, u, p);
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;

	// prover: third move
	std::stringstream err;
	edcf->Flip_twoparty(0, lambda, in, out, err); // flip coins with verifier to get $\lambda$
	// reduce $\lambda$ modulo $q$
	mpz_mod(lambda, lambda, q);
	// compute $\lambda_r = \lambda - \sum_{j \neq r} \lambda_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < lambdak.size(); j++)
	{
		if (j != r)
		{
			mpz_add(foo, foo, lambdak[j]);
			mpz_mod(foo, foo, q);
		}
	}
	mpz_sub(lambdak[r], lambda, foo);
	mpz_add(lambdak[r], lambdak[r], q); // add q to stay in the group
	mpz_mod(lambdak[r], lambdak[r], q);
	// compute $t_r = u + \lambda_r \sum_j s_j \beta_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < s.size(); j++)
	{
		mpz_mul(bar, s[j], beta[j]);
		mpz_mod(bar, bar, q);
		mpz_add(foo, foo, bar);
		mpz_mod(foo, foo, q);
	}
	mpz_mul(foo, foo, lambdak[r]);
	mpz_mod(foo, foo, q);
	mpz_add(tk[r], u, foo);
	mpz_mod(tk[r], tk[r], q);
	for (size_t i = 0; i < lambdak.size(); i++)
		out << lambdak[i] << std::endl;
	for (size_t i = 0; i < tk.size(); i++)
		out << tk[i] << std::endl;
	
	// release
	mpz_clear(u), mpz_clear(G), mpz_clear(lambda), mpz_clear(foo),
		mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
			mpz_clear(lambdak[i]);
		delete [] beta[i], delete [] f[i], delete [] tk[i],
			delete [] lambdak[i];
	}
	beta.clear(), f.clear(), tk.clear(), lambdak.clear();
}

void HooghSchoenmakersSkoricVillegasPUBROTZK::Prove_noninteractive
	(size_t r, const std::vector<mpz_ptr> &s, 
	const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	std::ostream &out) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	assert(r < alpha.size());
	assert(s.size() == alpha.size());
	
	// initialize
	mpz_t u, G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(u), mpz_init(G), mpz_init(lambda), mpz_init(foo),
		mpz_init(bar), mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}

	// prover: first move
	for (size_t i = 0; i < beta.size(); i++)
	{
		mpz_set_ui(bar, i);
		mpz_set_ui(foo, 0L);
		if (i > 0)
			mpz_set(foo, beta[i-1]); // make a link to previous element
		// get $\beta_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2vec(beta[i], alpha, c, 6, p, q, g, h, foo, bar);
		// reduce $\beta_i$'s modulo $q$
		mpz_mod(beta[i], beta[i], q);
	}

	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	tmcg_mpz_srandomm(u, q);
	// compute $G$
	mpz_set_ui(G, 1L);
	for (size_t j = 0; j < c.size(); j++) {
		mpz_powm(foo, c[j], beta[j], p);
		mpz_mul(G, G, foo);
		mpz_mod(G, G, p);
	}
	for (size_t j = 0; j < alpha.size(); j++)
	{
		if (j != r)
		{
			tmcg_mpz_srandomm(lambdak[j], q);
			tmcg_mpz_srandomm(tk[j], q);

			// compute $\gamma_j = \sum_i \alpha_{i-j}\beta_i
			mpz_set_ui(bar, 0L);
			for (size_t i = 0; i < alpha.size(); i++)
			{
				size_t ij = (i >= j) ? i-j : alpha.size() - (j-i) ; // compute $i - j (mod n)$
				mpz_mul(foo, alpha[ij], beta[i]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}
			// compute $f_j = g^{\lambda_j \gamma_j} \tilde{h}^{t_j} G^{-\lambda_j}$
			mpz_mul(foo, lambdak[j], bar);
			mpz_mod(foo, foo, q);
			tmcg_mpz_fspowm(fpowm_table_g, f[j], g, foo, p);
			tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[j], p);
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
			tmcg_mpz_spowm(foo, G, lambdak[j], p);
			if (!mpz_invert(bar, foo, p))
				mpz_set_ui(bar, 0L); // indicates an error
			mpz_mul(f[j], f[j], bar);
			mpz_mod(f[j], f[j], p);
		}
	}
	tmcg_mpz_fspowm(fpowm_table_h, f[r], h, u, p);
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;

	// prover: third move
		// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_4vec(lambda, alpha, c, f, beta, 4, p, q, g, h);
		// reduce $\lambda$ modulo $q$
		mpz_mod(lambda, lambda, q);

	// compute $\lambda_r = \lambda - \sum_{j \neq r} \lambda_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < lambdak.size(); j++)
	{
		if (j != r)
		{
			mpz_add(foo, foo, lambdak[j]);
			mpz_mod(foo, foo, q);
		}
	}
	mpz_sub(lambdak[r], lambda, foo);
	mpz_add(lambdak[r], lambdak[r], q); // add q to stay in the group
	mpz_mod(lambdak[r], lambdak[r], q);
	// compute $t_r = u + \lambda_r \sum_j s_j \beta_j$
	mpz_set_ui(foo, 0L);
	for (size_t j = 0; j < s.size(); j++)
	{
		mpz_mul(bar, s[j], beta[j]);
		mpz_mod(bar, bar, q);
		mpz_add(foo, foo, bar);
		mpz_mod(foo, foo, q);
	}
	mpz_mul(foo, foo, lambdak[r]);
	mpz_mod(foo, foo, q);
	mpz_add(tk[r], u, foo);
	mpz_mod(tk[r], tk[r], q);
	for (size_t i = 0; i < lambdak.size(); i++)
		out << lambdak[i] << std::endl;
	for (size_t i = 0; i < tk.size(); i++)
		out << tk[i] << std::endl;
	
	// release
	mpz_clear(u), mpz_clear(G), mpz_clear(lambda), mpz_clear(foo),
		mpz_clear(bar), mpz_clear(lhs), mpz_clear(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
			mpz_clear(lambdak[i]);
		delete [] beta[i], delete [] f[i], delete [] tk[i],
			delete [] lambdak[i];
	}
	beta.clear(), f.clear(), tk.clear(), lambdak.clear();
}

bool HooghSchoenmakersSkoricVillegasPUBROTZK::Verify_interactive
	(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	std::istream &in, std::ostream &out) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	
	// initialize
	mpz_t G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(G), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < beta.size(); i++)
		{
			tmcg_mpz_srandomm(beta[i], q);
			out << beta[i] << std::endl;
		}
		
		// verifier: second move
		for (size_t i = 0; i < f.size(); i++)
		{
			in >> f[i];
			if (!CheckElement(f[i]))
				throw false;
		}
		if (!in.good())
			throw false;
		tmcg_mpz_srandomm(lambda, q);
		out << lambda << std::endl;
		
		// verifier: third move
		for (size_t i = 0; i < lambdak.size(); i++)
		{
			in >> lambdak[i];
			if (mpz_cmpabs(lambdak[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < tk.size(); i++)
		{
			in >> tk[i];
			if (mpz_cmpabs(tk[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $\lambda = \sum_j \lambda_j$
		mpz_set_ui(rhs, 0L);
		for (size_t j = 0; j < lambdak.size(); j++)
		{
			mpz_add(rhs, rhs, lambdak[j]);
			mpz_mod(rhs, rhs, q);
		}
		if (mpz_cmp(lambda, rhs))
			throw false;

		// compute $G$
		mpz_set_ui(G, 1L);
		for (size_t j = 0; j < c.size(); j++) {
			mpz_powm(foo, c[j], beta[j], p);
			mpz_mul(G, G, foo);
			mpz_mod(G, G, p);
		}
		// check whether $\tilde{h}^{t_k} = 
		// 	a_k(G/g^{\gamma_k})^{\lambda_k}$
		for (size_t k = 0; k < alpha.size(); k++)
		{
			// compute $\gamma_k = \sum_j \alpha_{j-k}\beta_j
			mpz_set_ui(bar, 0L);
			for (size_t j = 0; j < alpha.size(); j++)
			{
				size_t jk = (j >= k) ? j-k : alpha.size() - (k-j) ; // compute $j - k (mod n)$
				mpz_mul(foo, alpha[jk], beta[j]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}

			// compute the left hand side $\tilde{h}^{t_k}$
			tmcg_mpz_fpowm(fpowm_table_h, lhs, h, tk[k], p);

			// compute the right hand side $a_k(G/g^{\gamma_k})^{\lambda_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, bar, p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo, foo, G);
			mpz_mod(foo, foo, p);
			mpz_powm(rhs, foo, lambdak[k], p);
			mpz_mul(rhs, rhs, f[k]); // Note: $f_k$ is in the paper mistakenly written as $a_k$
			mpz_mod(rhs, rhs, p);
			// compare
			if (mpz_cmp(lhs, rhs))
				throw false;
		}

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(G), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		for (size_t i = 0; i < alpha.size(); i++)
		{
			mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
				mpz_clear(lambdak[i]);
			delete [] beta[i], delete [] f[i], delete [] tk[i],
				delete [] lambdak[i];
		}
		beta.clear(), f.clear(), tk.clear(), lambdak.clear();
		// return
		return return_value;
	}
}

bool HooghSchoenmakersSkoricVillegasPUBROTZK::Verify_interactive_publiccoin
	(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	JareckiLysyanskayaEDCF *edcf,
	std::istream &in, std::ostream &out) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	
	// initialize
	mpz_t G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(G), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < beta.size(); i++)
		{
			std::stringstream err;
			if (!edcf->Flip_twoparty(1, beta[i], in, out, err)) // flip coins with prover to get $\beta_i$
				throw false;
			// reduce $\beta_i$'s modulo $q$
			mpz_mod(beta[i], beta[i], q);
		}
		
		// verifier: second move
		for (size_t i = 0; i < f.size(); i++)
		{
			in >> f[i];
			if (!CheckElement(f[i]))
				throw false;
		}
		if (!in.good())
			throw false;
		std::stringstream err;
		if (!edcf->Flip_twoparty(1, lambda, in, out, err)) // flip coins with prover to get $\lambda$
			throw false;
		// reduce $\lambda$ modulo $q$
		mpz_mod(lambda, lambda, q);
		
		// verifier: third move
		for (size_t i = 0; i < lambdak.size(); i++)
		{
			in >> lambdak[i];
			if (mpz_cmpabs(lambdak[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < tk.size(); i++)
		{
			in >> tk[i];
			if (mpz_cmpabs(tk[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $\lambda = \sum_j \lambda_j$
		mpz_set_ui(rhs, 0L);
		for (size_t j = 0; j < lambdak.size(); j++)
		{
			mpz_add(rhs, rhs, lambdak[j]);
			mpz_mod(rhs, rhs, q);
		}
		if (mpz_cmp(lambda, rhs))
			throw false;

		// compute $G$
		mpz_set_ui(G, 1L);
		for (size_t j = 0; j < c.size(); j++) {
			mpz_powm(foo, c[j], beta[j], p);
			mpz_mul(G, G, foo);
			mpz_mod(G, G, p);
		}
		// check whether $\tilde{h}^{t_k} = 
		// 	a_k(G/g^{\gamma_k})^{\lambda_k}$
		for (size_t k = 0; k < alpha.size(); k++)
		{
			// compute $\gamma_k = \sum_j \alpha_{j-k}\beta_j
			mpz_set_ui(bar, 0L);
			for (size_t j = 0; j < alpha.size(); j++)
			{
				size_t jk = (j >= k) ? j-k : alpha.size() - (k-j) ; // compute $j - k (mod n)$
				mpz_mul(foo, alpha[jk], beta[j]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}

			// compute the left hand side $\tilde{h}^{t_k}$
			tmcg_mpz_fpowm(fpowm_table_h, lhs, h, tk[k], p);

			// compute the right hand side $a_k(G/g^{\gamma_k})^{\lambda_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, bar, p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo, foo, G);
			mpz_mod(foo, foo, p);
			mpz_powm(rhs, foo, lambdak[k], p);
			mpz_mul(rhs, rhs, f[k]); // Note: $f_k$ is in the paper mistakenly written as $a_k$
			mpz_mod(rhs, rhs, p);
			// compare
			if (mpz_cmp(lhs, rhs))
				throw false;
		}

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(G), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		for (size_t i = 0; i < alpha.size(); i++)
		{
			mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
				mpz_clear(lambdak[i]);
			delete [] beta[i], delete [] f[i], delete [] tk[i],
				delete [] lambdak[i];
		}
		beta.clear(), f.clear(), tk.clear(), lambdak.clear();
		// return
		return return_value;
	}
}

bool HooghSchoenmakersSkoricVillegasPUBROTZK::Verify_noninteractive
	(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
	std::istream &in) const
{
	assert(alpha.size() >= 2);
	assert(alpha.size() == c.size());
	
	// initialize
	mpz_t G, lambda, foo, bar, lhs, rhs;
	std::vector<mpz_ptr> beta, f, lambdak, tk;
	
	mpz_init(G), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		beta.push_back(tmp1), f.push_back(tmp2), tk.push_back(tmp3),
			lambdak.push_back(tmp4);
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < beta.size(); i++)
		{
			mpz_set_ui(bar, i);
			mpz_set_ui(foo, 0L);
			if (i > 0)
				mpz_set(foo, beta[i-1]); // make a link to previous element
			// get $\beta_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2vec(beta[i], alpha, c, 6, p, q, g, h, foo, bar);
			// reduce $\beta_i$'s modulo $q$
			mpz_mod(beta[i], beta[i], q);
		}
		
		// verifier: second move
		for (size_t i = 0; i < f.size(); i++)
		{
			in >> f[i];
			if (!CheckElement(f[i]))
				throw false;
		}
		if (!in.good())
			throw false;
		// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_4vec(lambda, alpha, c, f, beta, 4, p, q, g, h);
		// reduce $\lambda$ modulo $q$
		mpz_mod(lambda, lambda, q);
		
		// verifier: third move
		for (size_t i = 0; i < lambdak.size(); i++)
		{
			in >> lambdak[i];
			if (mpz_cmpabs(lambdak[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < tk.size(); i++)
		{
			in >> tk[i];
			if (mpz_cmpabs(tk[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $\lambda = \sum_j \lambda_j$
		mpz_set_ui(rhs, 0L);
		for (size_t j = 0; j < lambdak.size(); j++)
		{
			mpz_add(rhs, rhs, lambdak[j]);
			mpz_mod(rhs, rhs, q);
		}
		if (mpz_cmp(lambda, rhs))
			throw false;

		// compute $G$
		mpz_set_ui(G, 1L);
		for (size_t j = 0; j < c.size(); j++)
		{
			mpz_powm(foo, c[j], beta[j], p);
			mpz_mul(G, G, foo);
			mpz_mod(G, G, p);
		}
		// check whether $\tilde{h}^{t_k} = 
		// 	a_k(G/g^{\gamma_k})^{\lambda_k}$
		for (size_t k = 0; k < alpha.size(); k++)
		{
			// compute $\gamma_k = \sum_j \alpha_{j-k}\beta_j
			mpz_set_ui(bar, 0L);
			for (size_t j = 0; j < alpha.size(); j++)
			{
				size_t jk = (j >= k) ? j-k : alpha.size() - (k-j) ; // compute $j - k (mod n)$
				mpz_mul(foo, alpha[jk], beta[j]);
				mpz_mod(foo, foo, q);
				mpz_add(bar, bar, foo);
				mpz_mod(bar, bar, q);
			}

			// compute the left hand side $\tilde{h}^{t_k}$
			tmcg_mpz_fpowm(fpowm_table_h, lhs, h, tk[k], p);

			// compute the right hand side $a_k(G/g^{\gamma_k})^{\lambda_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, bar, p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo, foo, G);
			mpz_mod(foo, foo, p);
			mpz_powm(rhs, foo, lambdak[k], p);
			mpz_mul(rhs, rhs, f[k]); // Note: $f_k$ is in the paper mistakenly written as $a_k$
			mpz_mod(rhs, rhs, p);
			// compare
			if (mpz_cmp(lhs, rhs))
				throw false;
		}

		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(G), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		for (size_t i = 0; i < alpha.size(); i++)
		{
			mpz_clear(beta[i]), mpz_clear(f[i]), mpz_clear(tk[i]),
				mpz_clear(lambdak[i]);
			delete [] beta[i], delete [] f[i], delete [] tk[i],
				delete [] lambdak[i];
		}
		beta.clear(), f.clear(), tk.clear(), lambdak.clear();
		// return
		return return_value;
	}
}

HooghSchoenmakersSkoricVillegasPUBROTZK::~HooghSchoenmakersSkoricVillegasPUBROTZK
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	
	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}

// =============================================================================

HooghSchoenmakersSkoricVillegasVRHE::HooghSchoenmakersSkoricVillegasVRHE
	(unsigned long int fieldsize, unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t k, foo;

	// Initialize and choose the parameters of the scheme.
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
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
	// choose uniformly at random the element $h$ of order $q$
	do
	{
		tmcg_mpz_wrandomm(h, p);
		mpz_powm(h, h, k, p);
	}
	while (!mpz_cmp_ui(h, 0L) || !mpz_cmp_ui(h, 1L) || 
		!mpz_cmp(h, foo)); // check, whether $1 < h < p-1$
	mpz_clear(foo);
	mpz_clear(k);

	// Initialize the PUB-ROT-ZK argument
	pub_rot_zk = new HooghSchoenmakersSkoricVillegasPUBROTZK(p, q, g, h);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

HooghSchoenmakersSkoricVillegasVRHE::HooghSchoenmakersSkoricVillegasVRHE
	(mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC,
	unsigned long int fieldsize, unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	
	// Initialize the PUB-ROT-ZK argument
	pub_rot_zk = new HooghSchoenmakersSkoricVillegasPUBROTZK(p, q, g, h);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

HooghSchoenmakersSkoricVillegasVRHE::HooghSchoenmakersSkoricVillegasVRHE
	(std::istream &in,
	unsigned long int fieldsize, unsigned long int subgroupsize):
			F_size(fieldsize), G_size(subgroupsize)
{
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;

	// Initialize the PUB-ROT-ZK argument
	pub_rot_zk = new HooghSchoenmakersSkoricVillegasPUBROTZK(p, q, g, h);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool HooghSchoenmakersSkoricVillegasVRHE::CheckGroup
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
		
		// Check whether the elements $h$ and $g$ are of order $q$.
		mpz_powm(foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether the elements $h$ and $g$ are different and non-trivial,
		// i.e., $1 < h, g < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(h, 1L) <= 0) || (mpz_cmp(h, foo) >= 0))
			throw false;
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, foo) >= 0))
			throw false;
		if (!mpz_cmp(g, h))
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

bool HooghSchoenmakersSkoricVillegasVRHE::CheckElement
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

void HooghSchoenmakersSkoricVillegasVRHE::PublishGroup
	(std::ostream& out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
}

void HooghSchoenmakersSkoricVillegasVRHE::Prove_interactive
	(size_t r, const std::vector<mpz_ptr> &s,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	std::istream &in, std::ostream &out) const
{
	assert(s.size() >= 2);
	assert(r < s.size());
	assert(s.size() == X.size());
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, uk, tk, hk, ok, pk, mk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t(),
			tmpA = new mpz_t(), tmpB = new mpz_t(), tmpC = new mpz_t(),
			tmpD = new mpz_t(), tmpE = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6), mpz_init(tmpA), mpz_init(tmpB),
			mpz_init(tmpC), mpz_init(tmpD), mpz_init(tmpE);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6),
			uk.push_back(tmpA), tk.push_back(tmpB), ok.push_back(tmpC),
			pk.push_back(tmpD), mk.push_back(tmpE);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	// prover: first move
	for (size_t i = 0; i < alpha.size(); i++)
	{
		in >> alpha[i];
		// reduce $\alpha_i$ modulo $q$
		mpz_mod(alpha[i], alpha[i], q);
	}
	
	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
	mpz_set_ui(v, 0L); // v acts like an additive accumulator
	for (size_t i = 0; i < hk.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$
		
		// $u_k, t_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(uk[i], q), tmcg_mpz_srandomm(tk[i], q);
		// compute $h_k = g^{\alpha_{k-r}} h^{u_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, uk[i], p);
		mpz_mul(hk[i], foo, bar);
		mpz_mod(hk[i], hk[i], p);
		// compute $A_k = (d_k^{\alpha_{k-r}}, e_k^{\alpha_{k-r}})
		//                (g^{t_k},h^{t_k})$
		tmcg_mpz_spowm(foo, Y[i].first, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, tk[i], p);
		mpz_mul(Ak[i].first, foo, bar);
		mpz_mod(Ak[i].first, Ak[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[i], p);
		mpz_mul(Ak[i].second, foo, bar);
		mpz_mod(Ak[i].second, Ak[i].second, p);
		// compute $v = \sum_{k=0}^{n-1} (\alpha_{k-r} s_k + t_k)$
		mpz_mul(foo, alpha[kr], s[i]);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, tk[i]);
		mpz_mod(foo, foo, q);
		mpz_add(v, v, foo);
		mpz_mod(v, v, q);
	}
	for (size_t i = 0; i < hk.size(); i++)
			out << hk[i] << std::endl;
	for (size_t i = 0; i < Ak.size(); i++)
			out << Ak[i].first << std::endl << Ak[i].second << std::endl;
	out << v << std::endl;
	
	// prover: second move (first move of EXP-ZK)
	for (size_t i = 0; i < fk.size(); i++)
	{	
		// $o_k, p_k, m_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(ok[i], q);
		tmcg_mpz_srandomm(pk[i], q);
		tmcg_mpz_srandomm(mk[i], q);
		// compute $f_k = g^{o_k} h^{p_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, pk[i], p);
		mpz_mul(fk[i], foo, bar);
		mpz_mod(fk[i], fk[i], p);
		// compute $F_k = (d_k^{o_k}, e_k^{o_k})(g^{m_k}, h^{m_k})$
		tmcg_mpz_spowm(foo, Y[i].first, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, mk[i], p);
		mpz_mul(Fk[i].first, foo, bar);
		mpz_mod(Fk[i].first, Fk[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, mk[i], p);
		mpz_mul(Fk[i].second, foo, bar);
		mpz_mod(Fk[i].second, Fk[i].second, p);
	}
	for (size_t i = 0; i < fk.size(); i++)
		out << fk[i] << std::endl;
	for (size_t i = 0; i < Fk.size(); i++)
		out << Fk[i].first << std::endl << Fk[i].second << std::endl;

	// prover: third move (second move of EXP-ZK)
	in >> lambda;
	// reduce $\lambda$ modulo $q$
	mpz_mod(lambda, lambda, q);

	// prover: fourth move (third move of EXP-ZK)
	for (size_t i = 0; i < tau.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$

		// compute $\tau_k = o_k + \lambda \alpha_{k-r}$
		mpz_mul(tau[i], lambda, alpha[kr]);
		mpz_mod(tau[i], tau[i], q);
		mpz_add(tau[i], tau[i], ok[i]);
		mpz_mod(tau[i], tau[i], q);
		// compute $\rho_k = p_k + \lambda u_k$
		mpz_mul(rho[i], lambda, uk[i]);
		mpz_mod(rho[i], rho[i], q);
		mpz_add(rho[i], rho[i], pk[i]);
		mpz_mod(rho[i], rho[i], q);
		// compute $\mu_k = m_k + \lambda t_k$
		mpz_mul(mu[i], lambda, tk[i]);
		mpz_mod(mu[i], mu[i], q);
		mpz_add(mu[i], mu[i], mk[i]);
		mpz_mod(mu[i], mu[i], q);
	}
	for (size_t i = 0; i < tau.size(); i++)
		out << tau[i] << std::endl;
	for (size_t i = 0; i < rho.size(); i++)
		out << rho[i] << std::endl;
	for (size_t i = 0; i < mu.size(); i++)
		out << mu[i] << std::endl;
		
	// perform and prove PUB-ROT-ZK
	pub_rot_zk->Prove_interactive(r, uk, alpha, hk, in, out);
	
	// release
	mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
		mpz_clear(lhs), mpz_clear(rhs);
	mpz_clear(LHS.first), mpz_clear(LHS.second),
		mpz_clear(RHS.first), mpz_clear(RHS.second);
	delete [] LHS.first, delete [] LHS.second, delete [] RHS.first, delete [] RHS.second;
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
			mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]),
			mpz_clear(uk[i]), mpz_clear(tk[i]), mpz_clear(ok[i]),
			mpz_clear(pk[i]), mpz_clear(mk[i]);
		delete [] alpha[i], delete [] hk[i], delete [] fk[i],
			delete [] tau[i], delete [] rho[i], delete [] mu[i],
			delete [] uk[i], delete [] tk[i], delete [] ok[i],
			delete [] pk[i], delete [] mk[i];
		mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
			mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
		delete [] Ak[i].first, delete [] Ak[i].second,
			delete [] Fk[i].first, delete [] Fk[i].second;
	}
	alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
		mu.clear(), Ak.clear(), Fk.clear(), uk.clear(), tk.clear(),
		ok.clear(), pk.clear(), mk.clear();
}

void HooghSchoenmakersSkoricVillegasVRHE::Prove_interactive_publiccoin
	(size_t r, const std::vector<mpz_ptr> &s,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	JareckiLysyanskayaEDCF *edcf,
	std::istream &in, std::ostream &out) const
{
	assert(s.size() >= 2);
	assert(r < s.size());
	assert(s.size() == X.size());
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, uk, tk, hk, ok, pk, mk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t(),
			tmpA = new mpz_t(), tmpB = new mpz_t(), tmpC = new mpz_t(),
			tmpD = new mpz_t(), tmpE = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6), mpz_init(tmpA), mpz_init(tmpB),
			mpz_init(tmpC), mpz_init(tmpD), mpz_init(tmpE);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6),
			uk.push_back(tmpA), tk.push_back(tmpB), ok.push_back(tmpC),
			pk.push_back(tmpD), mk.push_back(tmpE);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	// prover: first move
	for (size_t i = 0; i < alpha.size(); i++)
	{
		std::stringstream err;
		edcf->Flip_twoparty(0, alpha[i], in, out, err); // flip coins with verifier to get $\alpha_i$
		// reduce $\alpha_i$ modulo $q$
		mpz_mod(alpha[i], alpha[i], q);
	}
	
	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
	mpz_set_ui(v, 0L); // v acts like an additive accumulator
	for (size_t i = 0; i < hk.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$
		
		// $u_k, t_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(uk[i], q);
		tmcg_mpz_srandomm(tk[i], q);
		// compute $h_k = g^{\alpha_{k-r}} h^{u_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, uk[i], p);
		mpz_mul(hk[i], foo, bar);
		mpz_mod(hk[i], hk[i], p);
		// compute $A_k = (d_k^{\alpha_{k-r}}, e_k^{\alpha_{k-r}})
		//                (g^{t_k},h^{t_k})$
		tmcg_mpz_spowm(foo, Y[i].first, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, tk[i], p);
		mpz_mul(Ak[i].first, foo, bar);
		mpz_mod(Ak[i].first, Ak[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[i], p);
		mpz_mul(Ak[i].second, foo, bar);
		mpz_mod(Ak[i].second, Ak[i].second, p);
		// compute $v = \sum_{k=0}^{n-1} (\alpha_{k-r} s_k + t_k)$
		mpz_mul(foo, alpha[kr], s[i]);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, tk[i]);
		mpz_mod(foo, foo, q);
		mpz_add(v, v, foo);
		mpz_mod(v, v, q);
	}
	for (size_t i = 0; i < hk.size(); i++)
			out << hk[i] << std::endl;
	for (size_t i = 0; i < Ak.size(); i++)
			out << Ak[i].first << std::endl << Ak[i].second << std::endl;
	out << v << std::endl;
	
	// prover: second move (first move of EXP-ZK)
	for (size_t i = 0; i < fk.size(); i++)
	{	
		// $o_k, p_k, m_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(ok[i], q);
		tmcg_mpz_srandomm(pk[i], q);
		tmcg_mpz_srandomm(mk[i], q);
		// compute $f_k = g^{o_k} h^{p_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, pk[i], p);
		mpz_mul(fk[i], foo, bar);
		mpz_mod(fk[i], fk[i], p);
		// compute $F_k = (d_k^{o_k}, e_k^{o_k})(g^{m_k}, h^{m_k})$
		tmcg_mpz_spowm(foo, Y[i].first, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, mk[i], p);
		mpz_mul(Fk[i].first, foo, bar);
		mpz_mod(Fk[i].first, Fk[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, mk[i], p);
		mpz_mul(Fk[i].second, foo, bar);
		mpz_mod(Fk[i].second, Fk[i].second, p);
	}
	for (size_t i = 0; i < fk.size(); i++)
		out << fk[i] << std::endl;
	for (size_t i = 0; i < Fk.size(); i++)
		out << Fk[i].first << std::endl << Fk[i].second << std::endl;

	// prover: third move (second move of EXP-ZK)
	std::stringstream err;
	edcf->Flip_twoparty(0, lambda, in, out, err); // flip coins with verifier to get $\lambda$
	// reduce $\lambda$ modulo $q$
	mpz_mod(lambda, lambda, q);

	// prover: fourth move (third move of EXP-ZK)
	for (size_t i = 0; i < tau.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$

		// compute $\tau_k = o_k + \lambda \alpha_{k-r}$
		mpz_mul(tau[i], lambda, alpha[kr]);
		mpz_mod(tau[i], tau[i], q);
		mpz_add(tau[i], tau[i], ok[i]);
		mpz_mod(tau[i], tau[i], q);
		// compute $\rho_k = p_k + \lambda u_k$
		mpz_mul(rho[i], lambda, uk[i]);
		mpz_mod(rho[i], rho[i], q);
		mpz_add(rho[i], rho[i], pk[i]);
		mpz_mod(rho[i], rho[i], q);
		// compute $\mu_k = m_k + \lambda t_k$
		mpz_mul(mu[i], lambda, tk[i]);
		mpz_mod(mu[i], mu[i], q);
		mpz_add(mu[i], mu[i], mk[i]);
		mpz_mod(mu[i], mu[i], q);
	}
	for (size_t i = 0; i < tau.size(); i++)
		out << tau[i] << std::endl;
	for (size_t i = 0; i < rho.size(); i++)
		out << rho[i] << std::endl;
	for (size_t i = 0; i < mu.size(); i++)
		out << mu[i] << std::endl;
		
	// perform and prove PUB-ROT-ZK
	pub_rot_zk->Prove_interactive_publiccoin(r, uk, alpha, hk, edcf, in, out);
	
	// release
	mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
		mpz_clear(lhs), mpz_clear(rhs);
	mpz_clear(LHS.first), mpz_clear(LHS.second),
		mpz_clear(RHS.first), mpz_clear(RHS.second);
	delete [] LHS.first, delete [] LHS.second, delete [] RHS.first, delete [] RHS.second;
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
			mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]),
			mpz_clear(uk[i]), mpz_clear(tk[i]), mpz_clear(ok[i]),
			mpz_clear(pk[i]), mpz_clear(mk[i]);
		delete [] alpha[i], delete [] hk[i], delete [] fk[i],
			delete [] tau[i], delete [] rho[i], delete [] mu[i],
			delete [] uk[i], delete [] tk[i], delete [] ok[i],
			delete [] pk[i], delete [] mk[i];
		mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
			mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
		delete [] Ak[i].first, delete [] Ak[i].second,
			delete [] Fk[i].first, delete [] Fk[i].second;
	}
	alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
		mu.clear(), Ak.clear(), Fk.clear(), uk.clear(), tk.clear(),
		ok.clear(), pk.clear(), mk.clear();
}

void HooghSchoenmakersSkoricVillegasVRHE::Prove_noninteractive
	(size_t r, const std::vector<mpz_ptr> &s,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	std::ostream &out) const
{
	assert(s.size() >= 2);
	assert(r < s.size());
	assert(s.size() == X.size());
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, uk, tk, hk, ok, pk, mk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t(),
			tmpA = new mpz_t(), tmpB = new mpz_t(), tmpC = new mpz_t(),
			tmpD = new mpz_t(), tmpE = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6), mpz_init(tmpA), mpz_init(tmpB),
			mpz_init(tmpC), mpz_init(tmpD), mpz_init(tmpE);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6),
			uk.push_back(tmpA), tk.push_back(tmpB), ok.push_back(tmpC),
			pk.push_back(tmpD), mk.push_back(tmpE);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	// prover: first move
	for (size_t i = 0; i < alpha.size(); i++)
	{
		mpz_set_ui(bar, i);
		mpz_set_ui(foo, 0L);
		if (i > 0)
			mpz_set(foo, alpha[i-1]); // make a link to previous element
		// get $\alpha_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2pairvec(alpha[i], X, Y, 6, p, q, g, h, foo, bar);		
		// reduce $\alpha_i$ modulo $q$
		mpz_mod(alpha[i], alpha[i], q);
	}
	
	// prover: second move
	// Note that we throughout assume that $h = \tilde{h}$ holds.
	// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
	mpz_set_ui(v, 0L); // v acts like an additive accumulator
	for (size_t i = 0; i < hk.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$
		
		// $u_k, t_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(uk[i], q);
		tmcg_mpz_srandomm(tk[i], q);
		// compute $h_k = g^{\alpha_{k-r}} h^{u_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, uk[i], p);
		mpz_mul(hk[i], foo, bar);
		mpz_mod(hk[i], hk[i], p);
		// compute $A_k = (d_k^{\alpha_{k-r}}, e_k^{\alpha_{k-r}})
		//                (g^{t_k},h^{t_k})$
		tmcg_mpz_spowm(foo, Y[i].first, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, tk[i], p);
		mpz_mul(Ak[i].first, foo, bar);
		mpz_mod(Ak[i].first, Ak[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, alpha[kr], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, tk[i], p);
		mpz_mul(Ak[i].second, foo, bar);
		mpz_mod(Ak[i].second, Ak[i].second, p);
		// compute $v = \sum_{k=0}^{n-1} (\alpha_{k-r} s_k + t_k)$
		mpz_mul(foo, alpha[kr], s[i]);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, tk[i]);
		mpz_mod(foo, foo, q);
		mpz_add(v, v, foo);
		mpz_mod(v, v, q);
	}
	for (size_t i = 0; i < hk.size(); i++)
			out << hk[i] << std::endl;
	for (size_t i = 0; i < Ak.size(); i++)
			out << Ak[i].first << std::endl << Ak[i].second << std::endl;
	out << v << std::endl;
	
	// prover: second move (first move of EXP-ZK)
	for (size_t i = 0; i < fk.size(); i++)
	{	
		// $o_k, p_k, m_k \in_R \mathbb{Z}_q$
		tmcg_mpz_srandomm(ok[i], q);
		tmcg_mpz_srandomm(pk[i], q);
		tmcg_mpz_srandomm(mk[i], q);
		// compute $f_k = g^{o_k} h^{p_k}$
		tmcg_mpz_fspowm(fpowm_table_g, foo, g, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, pk[i], p);
		mpz_mul(fk[i], foo, bar);
		mpz_mod(fk[i], fk[i], p);
		// compute $F_k = (d_k^{o_k}, e_k^{o_k})(g^{m_k}, h^{m_k})$
		tmcg_mpz_spowm(foo, Y[i].first, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_g, bar, g, mk[i], p);
		mpz_mul(Fk[i].first, foo, bar);
		mpz_mod(Fk[i].first, Fk[i].first, p);
		tmcg_mpz_spowm(foo, Y[i].second, ok[i], p);
		tmcg_mpz_fspowm(fpowm_table_h, bar, h, mk[i], p);
		mpz_mul(Fk[i].second, foo, bar);
		mpz_mod(Fk[i].second, Fk[i].second, p);
	}
	for (size_t i = 0; i < fk.size(); i++)
		out << fk[i] << std::endl;
	for (size_t i = 0; i < Fk.size(); i++)
		out << Fk[i].first << std::endl << Fk[i].second << std::endl;

	// prover: third move (second move of EXP-ZK)
	// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
	tmcg_mpz_shash_4pairvec2vec(lambda, X, Y, Ak, Fk, hk, fk, 5, p, q, g, h, v);		
	// reduce $\lambda$ modulo $q$
	mpz_mod(lambda, lambda, q);

	// prover: fourth move (third move of EXP-ZK)
	for (size_t i = 0; i < tau.size(); i++)
	{
		size_t kr = (i >= r) ? i-r : s.size() - (r-i) ; // compute $k - r (mod n)$

		// compute $\tau_k = o_k + \lambda \alpha_{k-r}$
		mpz_mul(tau[i], lambda, alpha[kr]);
		mpz_mod(tau[i], tau[i], q);
		mpz_add(tau[i], tau[i], ok[i]);
		mpz_mod(tau[i], tau[i], q);
		// compute $\rho_k = p_k + \lambda u_k$
		mpz_mul(rho[i], lambda, uk[i]);
		mpz_mod(rho[i], rho[i], q);
		mpz_add(rho[i], rho[i], pk[i]);
		mpz_mod(rho[i], rho[i], q);
		// compute $\mu_k = m_k + \lambda t_k$
		mpz_mul(mu[i], lambda, tk[i]);
		mpz_mod(mu[i], mu[i], q);
		mpz_add(mu[i], mu[i], mk[i]);
		mpz_mod(mu[i], mu[i], q);
	}
	for (size_t i = 0; i < tau.size(); i++)
		out << tau[i] << std::endl;
	for (size_t i = 0; i < rho.size(); i++)
		out << rho[i] << std::endl;
	for (size_t i = 0; i < mu.size(); i++)
		out << mu[i] << std::endl;
		
	// perform and prove PUB-ROT-ZK
	pub_rot_zk->Prove_noninteractive(r, uk, alpha, hk, out);
	
	// release
	mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
		mpz_clear(lhs), mpz_clear(rhs);
	mpz_clear(LHS.first), mpz_clear(LHS.second),
		mpz_clear(RHS.first), mpz_clear(RHS.second);
	delete [] LHS.first, delete [] LHS.second, delete [] RHS.first, delete [] RHS.second;
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
			mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]),
			mpz_clear(uk[i]), mpz_clear(tk[i]), mpz_clear(ok[i]),
			mpz_clear(pk[i]), mpz_clear(mk[i]);
		delete [] alpha[i], delete [] hk[i], delete [] fk[i],
			delete [] tau[i], delete [] rho[i], delete [] mu[i],
			delete [] uk[i], delete [] tk[i], delete [] ok[i],
			delete [] pk[i], delete [] mk[i];
		mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
			mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
		delete [] Ak[i].first, delete [] Ak[i].second,
			delete [] Fk[i].first, delete [] Fk[i].second;
	}
	alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
		mu.clear(), Ak.clear(), Fk.clear(), uk.clear(), tk.clear(),
		ok.clear(), pk.clear(), mk.clear();
}

bool HooghSchoenmakersSkoricVillegasVRHE::Verify_interactive
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	std::istream &in, std::ostream &out) const
{
	assert(X.size() >= 2);
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, hk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < X.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < alpha.size(); i++)
		{
			tmcg_mpz_srandomm(alpha[i], q);
			out << alpha[i] << std::endl;
		}

		// verifier: second move
		for (size_t i = 0; i < hk.size(); i++)
		{
			in >> hk[i];
			if (!CheckElement(hk[i]))
				throw false;
		}
		for (size_t i = 0; i < Ak.size(); i++)
		{
			in >> Ak[i].first >> Ak[i].second;
			if (!CheckElement(Ak[i].first) || !CheckElement(Ak[i].second))
				throw false;
		}
		in >> v;
		if (mpz_cmpabs(v, q) >= 0)
			throw false;
		if (!in.good())
			throw false;

		// verifier: second move (first move of EXP-ZK)
		for (size_t i = 0; i < fk.size(); i++)
		{
			in >> fk[i];
			if (!CheckElement(fk[i]))
				throw false;
		}
		for (size_t i = 0; i < Fk.size(); i++)
		{
			in >> Fk[i].first >> Fk[i].second;
			if (!CheckElement(Fk[i].first) || !CheckElement(Fk[i].second))
				throw false;
		}
		if (!in.good())
			throw false;

		// verifier: third move (second move of EXP-ZK)
		tmcg_mpz_srandomm(lambda, q);
		out << lambda << std::endl;

		// verifier: fourth move (third move of EXP-ZK)
		for (size_t i = 0; i < tau.size(); i++)
		{
			in >> tau[i];
			if (mpz_cmpabs(tau[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < rho.size(); i++)
		{
			in >> rho[i];
			if (mpz_cmpabs(rho[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < mu.size(); i++)
		{
			in >> mu[i];
			if (mpz_cmpabs(mu[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $g^{\tau_k} h^{\rho_k} = f_k h_k^{\lambda}$
		// Note that we throughout assume that $h = \tilde{h}$ holds.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $g^{\tau_k} h^{\rho_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, rho[i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// RHS i.e. $f_k h_k^{\lambda}$
			mpz_powm(rhs, hk[i], lambda, p);
			mpz_mul(rhs, rhs, fk[i]);
			mpz_mod(rhs, rhs, p);
			// compare LHS and RHS
			if (mpz_cmp(lhs, rhs))
				throw false;
		}
		// check whether $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k}) =
		//                F_k A_k^{\lambda}$
		// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k})$
			mpz_powm(foo, Y[i].first, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_g, bar, g, mu[i], p);
			mpz_mul(LHS.first, foo, bar);
			mpz_mod(LHS.first, LHS.first, p);
			mpz_powm(foo, Y[i].second, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, mu[i], p);
			mpz_mul(LHS.second, foo, bar);
			mpz_mod(LHS.second, LHS.second, p);
			// RHS i.e. $F_k A_k^{\lambda}$
			mpz_powm(RHS.first, Ak[i].first, lambda, p);
			mpz_mul(RHS.first, RHS.first, Fk[i].first);
			mpz_mod(RHS.first, RHS.first, p);
			mpz_powm(RHS.second, Ak[i].second, lambda, p);
			mpz_mul(RHS.second, RHS.second, Fk[i].second);
			mpz_mod(RHS.second, RHS.second, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first))
				throw false;
			if (mpz_cmp(LHS.second, RHS.second))
				throw false;
		}

		// perform and verify PUB-ROT-ZK
		if (!pub_rot_zk->Verify_interactive(alpha, hk, in, out))
			throw false;

		// check whether $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j} = (g^v, h^v)$
			// LHS i.e. $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j}$
			mpz_set_ui(LHS.first, 1L), mpz_set_ui(LHS.second, 1L); // mul. accumulator
			for (size_t j = 0; j < alpha.size(); j++)
			{
				mpz_powm(bar, X[j].first, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].first);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.first, LHS.first, bar);
				mpz_mod(LHS.first, LHS.first, p);
				mpz_powm(bar, X[j].second, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].second);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.second, LHS.second, bar);
				mpz_mod(LHS.second, LHS.second, p);
			}
			// RHS i.e. $(g^v, h^v)$
			tmcg_mpz_fpowm(fpowm_table_g, RHS.first, g, v, p);
			tmcg_mpz_fpowm(fpowm_table_h, RHS.second, h, v, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first) || mpz_cmp(LHS.second, RHS.second))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(LHS.first), mpz_clear(LHS.second),
			mpz_clear(RHS.first), mpz_clear(RHS.second);
		delete [] LHS.first, delete [] LHS.second;
		delete [] RHS.first, delete [] RHS.second;
		for (size_t i = 0; i < X.size(); i++)
		{
			mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
				mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]);
			delete [] alpha[i], delete [] hk[i], delete [] fk[i],
				delete [] tau[i], delete [] rho[i], delete [] mu[i];
			mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
				mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
			delete [] Ak[i].first, delete [] Ak[i].second,
				delete [] Fk[i].first, delete [] Fk[i].second;
		}
		alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
			mu.clear(), Ak.clear(), Fk.clear();
		// return
		return return_value;
	}
}

bool HooghSchoenmakersSkoricVillegasVRHE::Verify_interactive_publiccoin
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	JareckiLysyanskayaEDCF *edcf,
	std::istream &in, std::ostream &out) const
{
	assert(X.size() >= 2);
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, hk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < X.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < alpha.size(); i++)
		{
			std::stringstream err;
			if (!edcf->Flip_twoparty(1, alpha[i], in, out, err)) // flip coins with prover to get $\alpha_i$
				throw false;
			// reduce $\alpha_i$'s modulo $q$
			mpz_mod(alpha[i], alpha[i], q);
		}

		// verifier: second move
		for (size_t i = 0; i < hk.size(); i++)
		{
			in >> hk[i];
			if (!CheckElement(hk[i]))
				throw false;
		}
		for (size_t i = 0; i < Ak.size(); i++)
		{
			in >> Ak[i].first >> Ak[i].second;
			if (!CheckElement(Ak[i].first) || !CheckElement(Ak[i].second))
				throw false;
		}
		in >> v;
		if (mpz_cmpabs(v, q) >= 0)
			throw false;
		if (!in.good())
			throw false;

		// verifier: second move (first move of EXP-ZK)
		for (size_t i = 0; i < fk.size(); i++)
		{
			in >> fk[i];
			if (!CheckElement(fk[i]))
				throw false;
		}
		for (size_t i = 0; i < Fk.size(); i++)
		{
			in >> Fk[i].first >> Fk[i].second;
			if (!CheckElement(Fk[i].first) || !CheckElement(Fk[i].second))
				throw false;
		}
		if (!in.good())
			throw false;

		// verifier: third move (second move of EXP-ZK)
		std::stringstream err;
		if (!edcf->Flip_twoparty(1, lambda, in, out, err)) // flip coins with prover to get $\lambda$
			throw false;
		// reduce $\lambda$ modulo $q$
		mpz_mod(lambda, lambda, q);

		// verifier: fourth move (third move of EXP-ZK)
		for (size_t i = 0; i < tau.size(); i++)
		{
			in >> tau[i];
			if (mpz_cmpabs(tau[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < rho.size(); i++)
		{
			in >> rho[i];
			if (mpz_cmpabs(rho[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < mu.size(); i++)
		{
			in >> mu[i];
			if (mpz_cmpabs(mu[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $g^{\tau_k} h^{\rho_k} = f_k h_k^{\lambda}$
		// Note that we throughout assume that $h = \tilde{h}$ holds.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $g^{\tau_k} h^{\rho_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, rho[i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// RHS i.e. $f_k h_k^{\lambda}$
			mpz_powm(rhs, hk[i], lambda, p);
			mpz_mul(rhs, rhs, fk[i]);
			mpz_mod(rhs, rhs, p);
			// compare LHS and RHS
			if (mpz_cmp(lhs, rhs))
				throw false;
		}
		// check whether $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k}) =
		//                F_k A_k^{\lambda}$
		// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k})$
			mpz_powm(foo, Y[i].first, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_g, bar, g, mu[i], p);
			mpz_mul(LHS.first, foo, bar);
			mpz_mod(LHS.first, LHS.first, p);
			mpz_powm(foo, Y[i].second, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, mu[i], p);
			mpz_mul(LHS.second, foo, bar);
			mpz_mod(LHS.second, LHS.second, p);
			// RHS i.e. $F_k A_k^{\lambda}$
			mpz_powm(RHS.first, Ak[i].first, lambda, p);
			mpz_mul(RHS.first, RHS.first, Fk[i].first);
			mpz_mod(RHS.first, RHS.first, p);
			mpz_powm(RHS.second, Ak[i].second, lambda, p);
			mpz_mul(RHS.second, RHS.second, Fk[i].second);
			mpz_mod(RHS.second, RHS.second, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first))
				throw false;
			if (mpz_cmp(LHS.second, RHS.second))
				throw false;
		}

		// perform and verify PUB-ROT-ZK
		if (!pub_rot_zk->Verify_interactive_publiccoin(alpha, hk, edcf, in, out))
			throw false;

		// check whether $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j} = (g^v, h^v)$
			// LHS i.e. $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j}$
			mpz_set_ui(LHS.first, 1L), mpz_set_ui(LHS.second, 1L); // mul. accumulator
			for (size_t j = 0; j < alpha.size(); j++)
			{
				mpz_powm(bar, X[j].first, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].first);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.first, LHS.first, bar);
				mpz_mod(LHS.first, LHS.first, p);
				mpz_powm(bar, X[j].second, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].second);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.second, LHS.second, bar);
				mpz_mod(LHS.second, LHS.second, p);
			}
			// RHS i.e. $(g^v, h^v)$
			tmcg_mpz_fpowm(fpowm_table_g, RHS.first, g, v, p);
			tmcg_mpz_fpowm(fpowm_table_h, RHS.second, h, v, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first) || mpz_cmp(LHS.second, RHS.second))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(LHS.first), mpz_clear(LHS.second),
			mpz_clear(RHS.first), mpz_clear(RHS.second);
		delete [] LHS.first, delete [] LHS.second;
		delete [] RHS.first, delete [] RHS.second;
		for (size_t i = 0; i < X.size(); i++)
		{
			mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
				mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]);
			delete [] alpha[i], delete [] hk[i], delete [] fk[i],
				delete [] tau[i], delete [] rho[i], delete [] mu[i];
			mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
				mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
			delete [] Ak[i].first, delete [] Ak[i].second,
				delete [] Fk[i].first, delete [] Fk[i].second;
		}
		alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
			mu.clear(), Ak.clear(), Fk.clear();
		// return
		return return_value;
	}
}

bool HooghSchoenmakersSkoricVillegasVRHE::Verify_noninteractive
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
	std::istream &in) const
{
	assert(X.size() >= 2);
	assert(X.size() == Y.size());
	
	// initialize
	mpz_t v, lambda, foo, bar, lhs, rhs;
	std::pair<mpz_ptr, mpz_ptr> LHS, RHS;
	std::vector<mpz_ptr> alpha, hk, fk, tau, rho, mu;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > Ak, Fk;
	
	mpz_init(v), mpz_init(lambda), mpz_init(foo), mpz_init(bar),
		mpz_init(lhs), mpz_init(rhs);
	LHS.first = new mpz_t(), LHS.second = new mpz_t(),
		RHS.first = new mpz_t(), RHS.second = new mpz_t();
	mpz_init(LHS.first), mpz_init(LHS.second),
		mpz_init(RHS.first), mpz_init(RHS.second);
	for (size_t i = 0; i < X.size(); i++)
	{
		mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t();
		mpz_init(tmp1), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6);
		alpha.push_back(tmp1), hk.push_back(tmp2), fk.push_back(tmp3),
			tau.push_back(tmp4), rho.push_back(tmp5), mu.push_back(tmp6);
		mpz_ptr tmp7 = new mpz_t(), tmp8 = new mpz_t(),
			tmp9 = new mpz_t(), tmp0 = new mpz_t();
		mpz_init(tmp7), mpz_init(tmp8), mpz_init(tmp9), mpz_init(tmp0);
		Ak.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp7, tmp8)),
			Fk.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp9, tmp0));
	}
	
	try
	{
		// verifier: first move
		for (size_t i = 0; i < alpha.size(); i++)
		{
			mpz_set_ui(bar, i);
			mpz_set_ui(foo, 0L);
			if (i > 0)
				mpz_set(foo, alpha[i-1]); // make a link to previous element
			// get $\alpha_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2pairvec(alpha[i], X, Y, 6, p, q, g, h, foo, bar);		
			// reduce $\alpha_i$ modulo $q$
			mpz_mod(alpha[i], alpha[i], q);
		}

		// verifier: second move
		for (size_t i = 0; i < hk.size(); i++)
		{
			in >> hk[i];
			if (!CheckElement(hk[i]))
				throw false;
		}
		for (size_t i = 0; i < Ak.size(); i++)
		{
			in >> Ak[i].first >> Ak[i].second;
			if (!CheckElement(Ak[i].first) || !CheckElement(Ak[i].second))
				throw false;
		}
		in >> v;
		if (mpz_cmpabs(v, q) >= 0)
			throw false;
		if (!in.good())
			throw false;

		// verifier: second move (first move of EXP-ZK)
		for (size_t i = 0; i < fk.size(); i++)
		{
			in >> fk[i];
			if (!CheckElement(fk[i]))
				throw false;
		}
		for (size_t i = 0; i < Fk.size(); i++)
		{
			in >> Fk[i].first >> Fk[i].second;
			if (!CheckElement(Fk[i].first) || !CheckElement(Fk[i].second))
				throw false;
		}
		if (!in.good())
			throw false;

		// verifier: third move (second move of EXP-ZK)
		// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_4pairvec2vec(lambda, X, Y, Ak, Fk, hk, fk, 5, p, q, g, h, v);		
		// reduce $\lambda$ modulo $q$
		mpz_mod(lambda, lambda, q);

		// verifier: fourth move (third move of EXP-ZK)
		for (size_t i = 0; i < tau.size(); i++)
		{
			in >> tau[i];
			if (mpz_cmpabs(tau[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < rho.size(); i++)
		{
			in >> rho[i];
			if (mpz_cmpabs(rho[i], q) >= 0)
				throw false;
		}
		for (size_t i = 0; i < mu.size(); i++)
		{
			in >> mu[i];
			if (mpz_cmpabs(mu[i], q) >= 0)
				throw false;
		}
		if (!in.good())
			throw false;
		
		// check whether $g^{\tau_k} h^{\rho_k} = f_k h_k^{\lambda}$
		// Note that we throughout assume that $h = \tilde{h}$ holds.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $g^{\tau_k} h^{\rho_k}$
			tmcg_mpz_fpowm(fpowm_table_g, foo, g, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, rho[i], p);
			mpz_mul(lhs, foo, bar);
			mpz_mod(lhs, lhs, p);
			// RHS i.e. $f_k h_k^{\lambda}$
			mpz_powm(rhs, hk[i], lambda, p);
			mpz_mul(rhs, rhs, fk[i]);
			mpz_mod(rhs, rhs, p);
			// compare LHS and RHS
			if (mpz_cmp(lhs, rhs))
				throw false;
		}
		// check whether $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k}) =
		//                F_k A_k^{\lambda}$
		// Note that we have $Y_k = (d_k, e_k)$, for all $0 \le k \le n-1$.
		for (size_t i = 0; i < tau.size(); i++)
		{
			// LHS i.e. $(d_k^{\tau_k}, e_k^{\tau_k})(g^{\mu_k}, h^{\mu_k})$
			mpz_powm(foo, Y[i].first, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_g, bar, g, mu[i], p);
			mpz_mul(LHS.first, foo, bar);
			mpz_mod(LHS.first, LHS.first, p);
			mpz_powm(foo, Y[i].second, tau[i], p);
			tmcg_mpz_fpowm(fpowm_table_h, bar, h, mu[i], p);
			mpz_mul(LHS.second, foo, bar);
			mpz_mod(LHS.second, LHS.second, p);
			// RHS i.e. $F_k A_k^{\lambda}$
			mpz_powm(RHS.first, Ak[i].first, lambda, p);
			mpz_mul(RHS.first, RHS.first, Fk[i].first);
			mpz_mod(RHS.first, RHS.first, p);
			mpz_powm(RHS.second, Ak[i].second, lambda, p);
			mpz_mul(RHS.second, RHS.second, Fk[i].second);
			mpz_mod(RHS.second, RHS.second, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first))
				throw false;
			if (mpz_cmp(LHS.second, RHS.second))
				throw false;
		}

		// perform and verify PUB-ROT-ZK
		if (!pub_rot_zk->Verify_noninteractive(alpha, hk, in))
			throw false;

		// check whether $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j} = (g^v, h^v)$
			// LHS i.e. $\prod_{j=0}^{n-1} A_j X_j^{-\alpha_j}$
			mpz_set_ui(LHS.first, 1L), mpz_set_ui(LHS.second, 1L); // mul. accumulator
			for (size_t j = 0; j < alpha.size(); j++)
			{
				mpz_powm(bar, X[j].first, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].first);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.first, LHS.first, bar);
				mpz_mod(LHS.first, LHS.first, p);
				mpz_powm(bar, X[j].second, alpha[j], p);
				if (!mpz_invert(bar, bar, p))
					throw false;
				mpz_mul(bar, bar, Ak[j].second);
				mpz_mod(bar, bar, p);
				mpz_mul(LHS.second, LHS.second, bar);
				mpz_mod(LHS.second, LHS.second, p);
			}
			// RHS i.e. $(g^v, h^v)$
			tmcg_mpz_fpowm(fpowm_table_g, RHS.first, g, v, p);
			tmcg_mpz_fpowm(fpowm_table_h, RHS.second, h, v, p);
			// compare LHS and RHS (both components)
			if (mpz_cmp(LHS.first, RHS.first) || mpz_cmp(LHS.second, RHS.second))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(v), mpz_clear(lambda), mpz_clear(foo), mpz_clear(bar),
			mpz_clear(lhs), mpz_clear(rhs);
		mpz_clear(LHS.first), mpz_clear(LHS.second),
			mpz_clear(RHS.first), mpz_clear(RHS.second);
		delete [] LHS.first, delete [] LHS.second, delete [] RHS.first, delete [] RHS.second;
		for (size_t i = 0; i < X.size(); i++)
		{
			mpz_clear(alpha[i]), mpz_clear(hk[i]), mpz_clear(fk[i]),
				mpz_clear(tau[i]), mpz_clear(rho[i]), mpz_clear(mu[i]);
			delete [] alpha[i], delete [] hk[i], delete [] fk[i],
				delete [] tau[i], delete [] rho[i], delete [] mu[i];
			mpz_clear(Ak[i].first), mpz_clear(Ak[i].second),
				mpz_clear(Fk[i].first), mpz_clear(Fk[i].second);
			delete [] Ak[i].first, delete [] Ak[i].second,
				delete [] Fk[i].first, delete [] Fk[i].second;
		}
		alpha.clear(), hk.clear(), fk.clear(), tau.clear(), rho.clear(),
			mu.clear(), Ak.clear(), Fk.clear();
		// return
		return return_value;
	}
}

HooghSchoenmakersSkoricVillegasVRHE::~HooghSchoenmakersSkoricVillegasVRHE
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	delete pub_rot_zk;
	
	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
