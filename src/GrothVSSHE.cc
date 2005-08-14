/*******************************************************************************
  GrothVSSHE.cc, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

     Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of libTMCG.

 Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>

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

#include "GrothVSSHE.hh"

nWay_PedersenCommitmentScheme::nWay_PedersenCommitmentScheme
	(size_t n, unsigned long int fieldsize, unsigned long int subgroupsize)
{
	assert(n >= 1);
	
	// Initalize and choose the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init_set_ui(h, 1L), mpz_init(k);
	mpz_lprime(p, q, k, fieldsize, subgroupsize);
	for (size_t i = 0; i <= n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		// choose randomly elements of order $q$
		do
		{
			mpz_srandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
		}
		while (mpz_congruent_p(tmp, h, p));
		
		if (i < n)
		{
			// store the elements $g_1, \ldots, g_n$
			g.push_back(tmp);
		}
		else
		{
			// the last element is $h$
			mpz_set(h, tmp);
			mpz_clear(tmp);
			delete tmp;
		}
	}
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		mpz_fpowm_init(tmp);
		mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

nWay_PedersenCommitmentScheme::nWay_PedersenCommitmentScheme
	(size_t n, std::istream &in)
{
	assert(n >= 1);
	
	// Initalize the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init(h), mpz_init(k);
	in >> q >> k >> h;
	mpz_mul(p, q, k), mpz_add_ui(p, p, 1L); // compute p := qk + 1
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		in >> tmp;
		g.push_back(tmp);
	}
	
	// Do the precomputation for the fast exponentiation.
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_t *tmp = new mpz_t[TMCG_MAX_FPOWM_T]();
		mpz_fpowm_init(tmp);
		mpz_fpowm_precompute(tmp, g[i], p, mpz_sizeinbase(q, 2L));
		fpowm_table_g.push_back(tmp);
	}
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool nWay_PedersenCommitmentScheme::CheckGroup
	(unsigned long int fieldsize, unsigned long int subgroupsize)
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
		// Check whether $p$ and $q$ are prime.
		if (!mpz_probab_prime_p(p, 64) || !mpz_probab_prime_p(q, 64))
			throw false;
		
		// Check whether $q$ is not a divisor of $k$, i.e. $q$ and $k$ are coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are of order $q$.
		mpz_fpowm(fpowm_table_h, foo, h, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			mpz_fpowm(fpowm_table_g[i], foo, g[i], q, p);
			if (mpz_cmp_ui(foo, 1L))
				throw false;
		}
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are different and non-trivial.
		if (!mpz_cmp_ui(h, 1L))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			if (!mpz_cmp_ui(g[i], 1L) || !mpz_cmp(g[i], h))
				throw false;
			for (size_t j = (i + 1); j < g.size(); j++)
			{
				if (!mpz_cmp(g[i], g[j]))
					throw false;
			}	
		}
		
		// anything is sound
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo);
		return return_value;
	}
}

void nWay_PedersenCommitmentScheme::PublishGroup
	(std::ostream &out)
{
	out << q << std::endl << k << std::endl << h << std::endl;
	for (size_t i = 0; i < g.size(); i++)
		out << g[i] << std::endl;
}

void nWay_PedersenCommitmentScheme::Commit
	(mpz_ptr c, mpz_ptr r, std::vector<mpz_ptr> m)
{
	assert(m.size() == g.size());
	
	// Choose a randomizer from $\mathbb{Z}_q$
	mpz_srandomm(r, q);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp;
	mpz_init(tmp);
	mpz_fspowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < g.size(); i++)
	{
		mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp);
}

void nWay_PedersenCommitmentScheme::CommitBy
	(mpz_ptr c, mpz_srcptr r, std::vector<mpz_ptr> m,
	bool TimingAttackProtection)
{
	assert(m.size() == g.size());
	assert(mpz_cmp(r, q) < 0);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp;
	mpz_init(tmp);
	if (TimingAttackProtection)
		mpz_fspowm(fpowm_table_h, c, h, r, p);
	else
		mpz_fpowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < g.size(); i++)
	{
		if (TimingAttackProtection)
			mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		else
			mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp);
}

bool nWay_PedersenCommitmentScheme::Verify
	(mpz_srcptr c, mpz_srcptr r, const std::vector<mpz_ptr> &m)
{
	assert(m.size() == g.size());
	
	mpz_t tmp, c2;
	mpz_init(tmp), mpz_init(c2);
	try
	{
		// Compute the commitment $c' := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
		mpz_fpowm(fpowm_table_h, c2, h, r, p);
		for (size_t i = 0; i < g.size(); i++)
		{
			mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
			mpz_mul(c2, c2, tmp);
			mpz_mod(c2, c2, p);
		}
		
		// Verify the commitment: 1. $c\in\mathbb{Z}_p$ and 2. $c = c'$
		if ((mpz_cmp(c, p) >= 1) || mpz_cmp(c, c2))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(tmp), mpz_clear(c2);
		return return_value;
	}
}

nWay_PedersenCommitmentScheme::~nWay_PedersenCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(h), mpz_clear(k);
	for (size_t i = 0; i < g.size(); i++)
	{
			mpz_clear(g[i]);
			delete g[i];
	}
	g.clear();
	
	for (size_t i = 0; i < fpowm_table_g.size(); i++)
	{
		mpz_fpowm_done(fpowm_table_g[i]);
		delete [] fpowm_table_g[i];
	}
	fpowm_table_g.clear();
	mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_h;
}

// =============================================================================

GrothSKC::GrothSKC
	(size_t n, size_t ell_e,
	unsigned long int fieldsize, unsigned long int subgroupsize):
		l_e(ell_e)
{
	com = new nWay_PedersenCommitmentScheme(n, fieldsize, subgroupsize);
	
}

void GrothSKC::Prove_interactive
	(const std::vector<size_t> &pi, mpz_srcptr r, mpz_srcptr c,
	const std::vector<mpz_ptr> &m,
	std::istream &in, std::ostream &out)
{
}

bool GrothSKC::Verify_interactive
	(mpz_srcptr c, const std::vector<mpz_ptr> &m,
	std::istream &in, std::ostream &out)
{
	return true;
}

GrothSKC::~GrothSKC
	()
{
	delete com;
}

// =============================================================================

GrothVSSHE::GrothVSSHE
	(size_t n, size_t ell_e,
	mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC,
	unsigned long int fieldsize, unsigned long int subgroupsize):
		l_e(ell_e)
{
	com = new nWay_PedersenCommitmentScheme(n, fieldsize, subgroupsize);
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	skc = new GrothSKC(n, l_e, fieldsize, subgroupsize);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void GrothVSSHE::Prove_interactive
	(const std::vector<size_t> &pi, const std::vector<mpz_ptr> &R,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
	std::istream &in, std::ostream &out)
{
	assert(com->g.size() == pi.size());
	assert(pi.size() == R.size());
	assert(R.size() == e.size());
	assert(e.size() == E.size());
	
	// initalize
	mpz_t r, R_d, r_d, c, c_d, Z, lambda, rho, foo, bar;
	std::pair<mpz_t, mpz_t> E_d;
	std::vector<mpz_ptr> d, f, m, t;
	mpz_init(r), mpz_init(R_d), mpz_init(r_d), mpz_init(c), mpz_init(c_d),
		mpz_init_set_ui(Z, 0L), mpz_init(lambda), mpz_init(rho), mpz_init(foo),
		mpz_init(bar);
	mpz_init_set_ui(E_d.first, 1L), mpz_init_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < com->g.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		d.push_back(tmp), f.push_back(tmp2), m.push_back(tmp3), t.push_back(tmp4);
	}
	
	// prover: first move
	mpz_srandomm(r, com->q);
	mpz_srandomm(R_d, q);
	for (size_t i = 0; i < d.size(); i++)
		mpz_srandomm(d[i], com->q), mpz_neg(d[i], d[i]);
	mpz_srandomm(r_d, com->q);
	for (size_t i = 0; i < m.size(); i++)
		mpz_set_ui(m[i], pi[i] + 1L);
	com->Commit(c, r, m);
	com->Commit(c_d, r_d, d);
	for (size_t i = 0; i < d.size(); i++)
	{
		// Compute and multiply $E_i^{-d_i}$
		mpz_spowm(foo, E[i].first, d[i], p);
		mpz_spowm(bar, E[i].second, d[i], p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		mpz_mul(E_d.first, E_d.first, bar);
		mpz_mod(E_d.first, E_d.first, p);
		// Compute and multiply $E(1;R_d)$
		mpz_fspowm(fpowm_table_g, foo, g, R_d, p);
		mpz_fspowm(fpowm_table_h, bar, h, R_d, p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		mpz_mul(E_d.first, E_d.first, bar);
		mpz_mod(E_d.first, E_d.first, p);
	}
	out << c << std::endl << c_d << std::endl << E_d.first << std::endl << 
		E_d.second << std::endl;
	
	// prover: second move
	for (size_t i = 0; i < f.size(); i++)
	{
		in >> t[i];
// TODO: check whether the $t_i$'s are from $\{0, 1\}^{\ell_e}$
	}
	
	// prover: third move
	for (size_t i = 0; i < f.size(); i++)
	{
		mpz_neg(f[i], d[i]);
		mpz_add(f[i], f[i], t[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
	}
	for (size_t i = 0; i < t.size(); i++)
	{
		mpz_add(foo, t[pi[i]], R[i]);
		mpz_mod(foo, foo, q);
		mpz_add(foo, foo, R_d);
		mpz_mod(foo, foo, q);
		mpz_add(Z, Z, foo);
		mpz_mod(Z, Z, q);
	}
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;
	out << Z << std::endl;
	
	// prover: fourth move
	in >> lambda;
// TODO: check whether $\lambda$ is from $\{0, 1\}^{\ell_e}$

	// prover: fifth to seventh move (Shuffle of Known Content)
		// $\rho := \lambda r + r_d \bmod q$
		mpz_mul(rho, lambda, r);
		mpz_mod(rho, rho, com->q);
		mpz_add(rho, rho, r_d);
		mpz_mod(rho, rho, com->q);
		// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod q$
		mpz_set_ui(bar, 0L);
		com->CommitBy(foo, bar, f, false);
		mpz_mul(foo, foo, c_d);
		mpz_mod(foo, foo, com->q);
		mpz_spowm(bar, c, lambda, com->q);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, com->q);
		// SKC messages
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_mul(m[i], m[i], lambda);
			mpz_mod(m[i], m[i], com->q);
			mpz_add(m[i], m[i], t[pi[i]]);
			mpz_mod(m[i], m[i], com->q);
		}
	skc->Prove_interactive(pi, rho, foo, m, in, out);
	
	// release
	mpz_clear(r), mpz_clear(R_d), mpz_clear(r_d), mpz_clear(c), mpz_clear(c_d),
		mpz_clear(Z), mpz_clear(lambda), mpz_clear(rho), mpz_clear(foo),
		mpz_clear(bar);
	mpz_clear(E_d.first), mpz_clear(E_d.second);
	for (size_t i = 0; i < d.size(); i++)
	{
		mpz_clear(d[i]);
		delete d[i];
	}
	d.clear();
	for (size_t i = 0; i < f.size(); i++)
	{
		mpz_clear(f[i]);
		delete f[i];
	}
	f.clear();
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_clear(m[i]);
		delete m[i];
	}
	m.clear();
	for (size_t i = 0; i < t.size(); i++)
	{
		mpz_clear(t[i]);
		delete t[i];
	}
	t.clear();
}

bool GrothVSSHE::Verify_interactive
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
	std::istream &in, std::ostream &out)
{
	assert(com->g.size() == e.size());
	assert(e.size() == E.size());
	
	// initalize
	mpz_t c, c_d, Z, lambda, foo, bar, foo2, bar2, foo3, bar3;
	std::pair<mpz_t, mpz_t> E_d;
	std::vector<mpz_ptr> f, m, t;
	mpz_init(c), mpz_init(c_d),	mpz_init_set_ui(Z, 0L), mpz_init(lambda),
		mpz_init(foo), mpz_init(bar), mpz_init(foo2), mpz_init(bar2),
		mpz_init(foo3), mpz_init(bar3);
	mpz_init_set_ui(E_d.first, 1L), mpz_init_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < com->g.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3);
		f.push_back(tmp), m.push_back(tmp2), t.push_back(tmp3);
	}
	
	try
	{
		// verifier: first move
		in >> c >> c_d >> E_d.first >> E_d.second;
		
		// verifier: second move
		for (size_t i = 0; i < t.size(); i++)
		{
			mpz_srandomb(t[i], l_e);
			out << t[i] << std::endl;
		}
		
		// verifier: third move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> Z;
		
		// verifier: fourth move
		mpz_srandomb(lambda, l_e);
		out << lambda << std::endl;
		
		// verifier: fifth to seventh move (Shuffle of Known Content)
			// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod q$
			mpz_set_ui(bar, 0L);
			com->CommitBy(foo, bar, f, false);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->q);
			mpz_spowm(bar, c, lambda, com->q);
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->q);
			// SKC messages $m_i := i + \lambda t_i \bmod q$ for all $i = 1,\ldots, n$
			for (size_t i = 0; i < m.size(); i++)
			{
				mpz_set_ui(m[i], i + 1L);
				mpz_mul(m[i], m[i], lambda);
				mpz_mod(m[i], m[i], com->q);
				mpz_add(m[i], m[i], t[i]);
				mpz_mod(m[i], m[i], com->q);
			}
		// perform and verify SKC
		if (!skc->Verify_interactive(foo, m, in, out));
			throw false;
		// check whether $c, c_d \in\mathcal{C}_{\mathrm{com}}$
		if (!(mpz_cmp(c, com->q) < 0) || !(mpz_cmp(c_d, com->q)))
			throw false;
		// check whether $E_d\in\mathcal{C}$
		mpz_fpowm(fpowm_table_g, foo, E_d.first, q, p);
		mpz_fpowm(fpowm_table_h, bar, E_d.second, q, p);
		if (mpz_cmp_ui(foo, 1L) || mpz_cmp_ui(bar, 1L))
			throw false;
		// check whether $2^{\ell_e} \le f_1,\ldots,f_n < q$
		for (size_t i = 0; i < f.size(); i++)
		{
			if ((mpz_sizeinbase(f[i], 2L) < l_e) || (mpz_cmp(f[i], com->q) >= 0))
				throw false;
		}
		// check whether $Z\in\mathcal{R}$
		if (mpz_cmp(Z, q) >= 0)
			throw false;
		// check $\prod_{i=1}^n e_i^{-t_i} \prod_{i=1}^n E_i^{f_i} E_d = E(1;Z)$
		mpz_set_ui(foo2, 1L), mpz_set_ui(bar2, 1L);
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_neg(t[i], t[i]);
			mpz_powm(foo, e[i].first, t[i], p);
			mpz_powm(bar, e[i].second, t[i], p);
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, p);
			mpz_mul(bar2, bar2, bar);
			mpz_mod(bar2, bar2, p);
		}
		mpz_set_ui(foo3, 1L), mpz_set_ui(bar3, 1L);
		for (size_t i = 0; i < E.size(); i++)
		{
			mpz_powm(foo, E[i].first, f[i], p);
			mpz_powm(bar, E[i].second, f[i], p);
			mpz_mul(foo3, foo3, foo);
			mpz_mod(foo3, foo3, p);
			mpz_mul(foo3, foo3, E_d.first);
			mpz_mod(foo3, foo3, p);
			mpz_mul(bar3, bar3, bar);
			mpz_mod(bar3, bar3, p);
			mpz_mul(bar3, bar3, E_d.second);
			mpz_mod(bar3, bar3, p);
		}
		mpz_mul(foo3, foo3, foo2);
		mpz_mod(foo3, foo3, p);
		mpz_mul(bar3, bar3, bar2);
		mpz_mod(bar3, bar3, p);
		mpz_fpowm(fpowm_table_g, foo, g, Z, p);
		mpz_fpowm(fpowm_table_h, bar, h, Z, p);
		if (mpz_cmp(foo3, foo) || mpz_cmp(bar3, bar))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(c), mpz_clear(c_d), mpz_clear(Z), mpz_clear(lambda),
			mpz_clear(foo), mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2),
			mpz_clear(foo3), mpz_clear(bar3);
		mpz_clear(E_d.first), mpz_clear(E_d.second);
		for (size_t i = 0; i < f.size(); i++)
		{
			mpz_clear(f[i]);
			delete f[i];
		}
		f.clear();
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_clear(m[i]);
			delete m[i];
		}
		m.clear();
		for (size_t i = 0; i < t.size(); i++)
		{
			mpz_clear(t[i]);
			delete t[i];
		}
		t.clear();
		// return
		return return_value;
	}
}

GrothVSSHE::~GrothVSSHE
	()
{
	delete com;
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	delete skc;
	
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
