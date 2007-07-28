/*******************************************************************************
  GrothVSSHE.cc, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

     Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

TODO:
	1. non-interactive version of the shuffle proof (Random Oracle Model)

   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

PedersenCommitmentScheme::PedersenCommitmentScheme
	(size_t n, unsigned long int fieldsize, unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t foo;
	assert(n >= 1);
	
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q), mpz_init(k), mpz_init_set_ui(h, 1L);
	mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	for (size_t i = 0; i <= n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		
		// choose uniformly at random an element of order $q$
		do
		{
			mpz_wrandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
		}
		while (!mpz_cmp_ui(tmp, 0L) || !mpz_cmp_ui(tmp, 1L) || 
			!mpz_cmp(tmp, foo)); // check, whether $1 < tmp < p-1$
		
		if (i < n)
		{
			// store the elements $g_1, \ldots, g_n$
			g.push_back(tmp);
		}
		else
		{
			// the last element is called $h$
			mpz_set(h, tmp);
			mpz_clear(tmp);
			delete tmp;
		}
	}
	mpz_clear(foo);
	
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

PedersenCommitmentScheme::PedersenCommitmentScheme
	(size_t n, mpz_srcptr p_ENC, mpz_srcptr q_ENC, 
	mpz_srcptr k_ENC, mpz_srcptr h_ENC, 
	unsigned long int fieldsize, unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t foo;
	assert(n >= 1);
	
	// Initialize and choose the parameters of the commitment scheme.
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), 
		mpz_init_set(k, k_ENC), mpz_init_set(h, h_ENC);
	
	mpz_init(foo);
	mpz_sub_ui(foo, p, 1L); // compute $p-1$
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		
		// choose uniformly at random an element of order $q$
		do
		{
			mpz_wrandomm(tmp, p);
			mpz_powm(tmp, tmp, k, p);
		}
		while (!mpz_cmp_ui(tmp, 0L) || !mpz_cmp_ui(tmp, 1L) || 
			!mpz_cmp(tmp, foo)); // check, whether $1 < tmp < p-1$
		
		// store the elements $g_1, \ldots, g_n$
		g.push_back(tmp);
	}
	mpz_clear(foo);
	
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

PedersenCommitmentScheme::PedersenCommitmentScheme
	(size_t n, std::istream &in,
	unsigned long int fieldsize, unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	assert(n >= 1);
	
	// Initialize the parameters of the commitment scheme.
	mpz_init(p), mpz_init(q),mpz_init(k), mpz_init(h);
	in >> p >> q >> k >> h;
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

bool PedersenCommitmentScheme::CheckGroup
	() const
{
	mpz_t foo;
	
	mpz_init(foo);
	try
	{
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
		
		// Check whether the elements $h, g_1, \ldots, g_n$ are different
		// and non-trivial, i.e., $1 < h, g_1, \ldots, g_n < p-1$.
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if ((mpz_cmp_ui(h, 1L) <= 0) || (mpz_cmp(h, foo) >= 0))
			throw false;
		for (size_t i = 0; i < g.size(); i++)
		{
			if ((mpz_cmp_ui(g[i], 1L) <= 0) || (mpz_cmp(g[i], foo) >= 0) ||
				!mpz_cmp(g[i], h))
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

void PedersenCommitmentScheme::PublishGroup
	(std::ostream &out) const
{
	out << p << std::endl << q << std::endl << k << std::endl << h << std::endl;
	for (size_t i = 0; i < g.size(); i++)
		out << g[i] << std::endl;
}

void PedersenCommitmentScheme::Commit
	(mpz_ptr c, mpz_ptr r, std::vector<mpz_ptr> m) const
{
	assert(m.size() <= g.size());
	
	// Choose a randomizer from $\mathbb{Z}_q$
	mpz_srandomm(r, q);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp, tmp2;
	mpz_init(tmp), mpz_init(tmp2);
	mpz_fspowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_fspowm(fpowm_table_g[i], tmp, g[i], m[i], p);
		mpz_mul(c, c, tmp);
		mpz_mod(c, c, p);
	}
	mpz_clear(tmp), mpz_clear(tmp2);
}

void PedersenCommitmentScheme::CommitBy
	(mpz_ptr c, mpz_srcptr r, std::vector<mpz_ptr> m,
	bool TimingAttackProtection) const
{
	assert(m.size() <= g.size());
	assert(mpz_cmp(r, q) < 0);
	
	// Compute the commitment $c := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
	mpz_t tmp;
	mpz_init(tmp);
	if (TimingAttackProtection)
		mpz_fspowm(fpowm_table_h, c, h, r, p);
	else
		mpz_fpowm(fpowm_table_h, c, h, r, p);
	for (size_t i = 0; i < m.size(); i++)
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

bool PedersenCommitmentScheme::TestMembership
	(mpz_srcptr c) const
{
	if ((mpz_cmp_ui(c, 0L) > 0) && (mpz_cmp(c, p) < 0))
		return true;
	else
		return false;
}

bool PedersenCommitmentScheme::Verify
	(mpz_srcptr c, mpz_srcptr r, const std::vector<mpz_ptr> &m) const
{
	assert(m.size() <= g.size());
	
	mpz_t tmp, c2;
	mpz_init(tmp), mpz_init(c2);
	try
	{
		// Compute the commitment $c' := g_1^{m_1} \cdots g_n^{m_n} h^r \bmod p$
		mpz_fpowm(fpowm_table_h, c2, h, r, p);
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_fpowm(fpowm_table_g[i], tmp, g[i], m[i], p);
			mpz_mul(c2, c2, tmp);
			mpz_mod(c2, c2, p);
		}
		
		// Verify the commitment: 1. $c\in\mathbb{Z}_p$ and 2. $c = c'$
		if ((mpz_cmp_ui(c, 0L) < 0) || (mpz_cmp(c, p) >= 0) || mpz_cmp(c, c2))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(tmp), mpz_clear(c2);
		return return_value;
	}
}

PedersenCommitmentScheme::~PedersenCommitmentScheme
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(k), mpz_clear(h);
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
	(size_t n,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e)
{
	com = new PedersenCommitmentScheme(n, fieldsize, subgroupsize);
	
	// Compute $2^{\ell_e}$ for the input reduction.
	mpz_init(exp2l_e);
	mpz_ui_pow_ui(exp2l_e, 2L, ell_e);
}

GrothSKC::GrothSKC
	(size_t n, std::istream &in,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e)
{
	com = new PedersenCommitmentScheme(n, in, fieldsize, subgroupsize);
	
	// Compute $2^{\ell_e}$ for the input reduction.
	mpz_init(exp2l_e);
	mpz_ui_pow_ui(exp2l_e, 2L, ell_e);
}

bool GrothSKC::CheckGroup
	() const
{
	return com->CheckGroup();
}

void GrothSKC::PublishGroup
	(std::ostream &out) const
{
	com->PublishGroup(out);
}

void GrothSKC::Prove_interactive
	(const std::vector<size_t> &pi, mpz_srcptr r,
	const std::vector<mpz_ptr> &m,
	std::istream &in, std::ostream &out) const
{
	assert(com->g.size() >= pi.size());
	assert(pi.size() == m.size());
	assert(m.size() >= 2);
	
	mpz_t x, r_d, r_Delta, r_a, c_d, c_Delta, c_a, e, z, z_Delta, foo, bar;
	std::vector<mpz_ptr> d, Delta, a, f, f_Delta, lej;
	
	// initialize
	mpz_init(x), mpz_init(r_d), mpz_init(r_Delta), mpz_init(r_a), mpz_init(c_d),
		mpz_init(c_Delta), mpz_init(c_a), mpz_init(e), mpz_init(z),
		mpz_init(z_Delta), mpz_init(foo), mpz_init(bar);
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4),
			mpz_init(tmp5), mpz_init(tmp6);
		d.push_back(tmp), Delta.push_back(tmp2), a.push_back(tmp3),
			f.push_back(tmp4), f_Delta.push_back(tmp5), lej.push_back(tmp6);
	}
	
	// prover: first move
	in >> x; // get $x$ from the verifier
	// check whether $x$ is from $\{0, 1\}^{\ell_e}$, otherwise reduce
	if (mpz_sizeinbase(x, 2L) > l_e)
		mpz_mod(x, x, exp2l_e);
	
	// prover: second move
	mpz_srandomm(r_d, com->q); // $r_d \gets \mathbb{Z}_q$
	mpz_srandomm(r_Delta, com->q); // $r_{\Delta} \gets \mathbb{Z}_q$
	for (size_t i = 0; i < d.size(); i++)
		mpz_srandomm(d[i], com->q); // $d_1,\ldots,d_n \gets \mathbb{Z}_q$
	mpz_set(Delta[0], d[0]); // $\Delta_1 := d_1$
	for (size_t i = 1; i < (Delta.size() - 1); i++)
		mpz_srandomm(Delta[i], com->q);	// $\Delta_2,\ldots,\Delta_{n-1}
										//           \gets \mathbb{Z}_q$
	mpz_set_ui(Delta[Delta.size() - 1], 0L); // $\Delta_n := 0$
	for (size_t i = 0; i < a.size(); i++)
	{
		mpz_set_ui(a[i], 1L);
		// compute a_i = \prod_{j=1}^i (m_{\pi(j)} - x)
		for (size_t j = 0; j <= i; j++)
		{
			mpz_sub(foo, m[pi[j]], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(a[i], a[i], foo);
			mpz_mod(a[i], a[i], com->q);
		}
	}
	mpz_srandomm(r_a, com->q); // $r_a \gets \mathbb{Z}_q$
	// $c_d = \mathrm{com}_{ck}(d_1,\ldots,d_n;r_d)$
	com->CommitBy(c_d, r_d, d);
	for (size_t i = 0; i < lej.size(); i++)
	{
		if (i < (lej.size() - 1))
		{
			mpz_set(foo, Delta[i]);
			mpz_neg(foo, foo);
			mpz_mul(lej[i], foo, d[i + 1]);
			mpz_mod(lej[i], lej[i], com->q);
		}
		else
			mpz_set_ui(lej[i], 0L);
	}
	// $c_{\Delta} = \mathrm{com}_{ck}(-\Delta_1 d_2,\ldots,
	//                                 -\Delta_{n-1} d_n;r_{\Delta})$
	com->CommitBy(c_Delta, r_Delta, lej);
	for (size_t i = 0; i < lej.size(); i++)
	{
		if (i < (lej.size() - 1))
		{
			mpz_set(foo, Delta[i + 1]);
			mpz_sub(bar, m[pi[i + 1]], x);
			mpz_mod(bar, bar, com->q);
			mpz_mul(bar, bar, Delta[i]);
			mpz_mod(bar, bar, com->q);
			mpz_sub(foo, foo, bar);
			mpz_mod(foo, foo, com->q);
			mpz_mul(bar, a[i], d[i + 1]);
			mpz_mod(bar, bar, com->q);
			mpz_sub(foo, foo, bar);
			mpz_mod(foo, foo, com->q);
			mpz_set(lej[i], foo);
		}
		else
			mpz_set_ui(lej[i], 0L);
	}
	// $c_a = \mathrm{com}_{ck}(\Delta_2 - (m_{\pi(2)} - x)\Delta_1 - a_1 d_2,
	//                          \ldots,\Delta_n - (m_{\pi(n)} - x)\Delta_{n-1}
	//                                  - a_{n-1} d_n;r_a)$
	com->CommitBy(c_a, r_a, lej);
	// send $c_d$, $c_\Delta$, and $c_a$ to the verifier
	out << c_d << std::endl << c_Delta << std::endl << c_a << std::endl;
	
	// prover: third move
	in >> e; // get $e$ from the verifier
	// check whether $x$ is from $\{0, 1\}^{\ell_e}$, otherwise reduce
	if (mpz_sizeinbase(e, 2L) > l_e)
		mpz_mod(e, e, exp2l_e);
	
	// prover: fourth move
	// compute $f_i = e m_{\pi(i)} + d_i$
	for (size_t i = 0; i < f.size(); i++)
	{
		mpz_mul(f[i], e, m[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
		mpz_add(f[i], f[i], d[i]);
		mpz_mod(f[i], f[i], com->q);
	}
	// compute $z = e r + r_d$
	mpz_mul(z, e, r);
	mpz_mod(z, z, com->q);
	mpz_add(z, z, r_d);
	mpz_mod(z, z, com->q);
	// compute $f_{\Delta_i} = e (\Delta_{i+1} - (m_{\pi(i+1)} - x)\Delta_i
	//                            - a_i d_{i+1}) - \Delta_i d_{i+1}$
	for (size_t i = 0; i < (f_Delta.size() - 1); i++)
	{
		mpz_set(foo, Delta[i + 1]);
		mpz_sub(bar, m[pi[i + 1]], x);
		mpz_mod(bar, bar, com->q);
		mpz_mul(bar, bar, Delta[i]);
		mpz_mod(bar, bar, com->q);
		mpz_sub(foo, foo, bar);
		mpz_mod(foo, foo, com->q);
		mpz_mul(bar, a[i], d[i + 1]);
		mpz_mod(bar, bar, com->q);
		mpz_sub(foo, foo, bar);
		mpz_mod(foo, foo, com->q);
		mpz_mul(foo, foo, e);
		mpz_mod(foo, foo, com->q);
		mpz_mul(bar, Delta[i], d[i + 1]);
		mpz_mod(bar, bar, com->q);
		mpz_sub(foo, foo, bar);
		mpz_mod(foo, foo, com->q);
		mpz_set(f_Delta[i], foo);
	}
	// compute $z_{\Delta} = e r_a + r_{\Delta}$
	mpz_mul(z_Delta, e, r_a);
	mpz_mod(z_Delta, z_Delta, com->q);
	mpz_add(z_Delta, z_Delta, r_Delta);
	mpz_mod(z_Delta, z_Delta, com->q);
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl; // send $f_1,\ldots,f_n$ to the verifier
	out << z << std::endl; // send $z$ to the verifier
	for (size_t i = 0; i < (f_Delta.size() - 1); i++)
		out << f_Delta[i] << std::endl; // send $f_{\Delta_1},\ldots,
		                                //      f_{\Delta_{n-1}}$ to verifier
	out << z_Delta << std::endl; // send $z_{\Delta}$ to the verifier
	
	// release
	mpz_clear(x), mpz_clear(r_d), mpz_clear(r_Delta), mpz_clear(r_a),
		mpz_clear(c_d), mpz_clear(c_Delta), mpz_clear(c_a), mpz_clear(e),
		mpz_clear(z), mpz_clear(z_Delta), mpz_clear(foo), mpz_clear(bar);
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_clear(d[i]), mpz_clear(Delta[i]), mpz_clear(a[i]), 
			mpz_clear(f[i]), mpz_clear(f_Delta[i]), mpz_clear(lej[i]);
		delete d[i], delete Delta[i], delete a[i], delete f[i], 
			delete f_Delta[i], delete lej[i];
	}
	d.clear(), Delta.clear(), a.clear(), f.clear(), f_Delta.clear(), 
		lej.clear();
}

bool GrothSKC::Verify_interactive
	(mpz_srcptr c, const std::vector<mpz_ptr> &m,
	std::istream &in, std::ostream &out, bool optimizations) const
{
	assert(com->g.size() >= m.size());
	assert(m.size() >= 2);
	
	// initialize
	mpz_t x, c_d, c_Delta, c_a, e, z, z_Delta, foo, bar, foo2, bar2;
	std::vector<mpz_ptr> f, f_Delta, lej;
	mpz_init(x), mpz_init(c_d), mpz_init(c_Delta), mpz_init(c_a), mpz_init(e),
		mpz_init(z), mpz_init(z_Delta), mpz_init(foo), mpz_init(bar),
		mpz_init(foo2), mpz_init(bar2);
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3);
		f.push_back(tmp), f_Delta.push_back(tmp2), lej.push_back(tmp3);
	}
	mpz_set_ui(f_Delta[f_Delta.size() - 1], 0L);
	
	try
	{
		// verifier: first move
		mpz_srandomb(x, l_e);
		out << x << std::endl; // send $x\in\{0,1\}^{\ell_e}$ to the prover
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a; // get $c_d$, $c_{\Delta}$, and $c_a$
		                             // from the prover
		
		// verifier: third move
		mpz_srandomb(e, l_e);
		out << e << std::endl; // send $e\in\{0,1\}^{\ell_e}$ to prover
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i]; // get $f_1,\ldots,f_n$ from the prover
		in >> z; // get $z$ from the prover
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i]; // get $f_{\Delta_1},\ldots,f_{\Delta_{n-1}}$
			                  // from the prover
		in >> z_Delta; // get $z_{\Delta}$ from the prover
		
		// check whether $c_d, c_a, c_{\Delta} \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c_d) && com->TestMembership(c_a) &&
			com->TestMembership(c_Delta)))
				throw false;
		
		// check whether $f_1, \ldots, f_n, z \in\mathbb{Z}_q$
		if (!(mpz_cmp(z, com->q) < 0))
			throw false;
		for (size_t i = 0; i < f.size(); i++)
		{
			if (!(mpz_cmp(f[i], com->q) < 0))
				throw false;
		}
		
		// check whether $f_{\Delta_1}, \ldots, f_{\Delta_{n-1}}$
		// and $z_{\Delta}$ are from $\mathbb{Z}_q$
		if (!(mpz_cmp(z_Delta, com->q) < 0))
			throw false;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
		{
			if (!(mpz_cmp(f_Delta[i], com->q) < 0))
				throw false;
		}
		
		if (optimizations)
		{
			// randomization technique from section 6,
			// paragraph 'Batch verification' [Gr05]
			mpz_t alpha;
			mpz_init(alpha);
			// pick $\alpha\in_R\{0, 1\}^{\ell_e}$ at random
			mpz_srandomb(alpha, l_e);
			// compute $(c^e c_d)^{\alpha}$
			mpz_powm(foo, c, e, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(foo, foo, alpha, com->p);
			// compute $c_a^e c_{\Delta}$
			mpz_powm(bar, c_a, e, com->p);
			mpz_mul(bar, bar, c_Delta);
			mpz_mod(bar, bar, com->p);
			// compute the product
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);
			// compute the messages for the commitment
			for (size_t i = 0; i < f.size(); i++)
			{
				mpz_mul(lej[i], alpha, f[i]);
				mpz_mod(lej[i], lej[i], com->q);
				mpz_add(lej[i], lej[i], f_Delta[i]);
				mpz_mod(lej[i], lej[i], com->q);
			}
			mpz_mul(bar, alpha, z);
			mpz_mod(bar, bar, com->q);
			mpz_add(bar, bar, z_Delta);
			mpz_mod(bar, bar, com->q);
			mpz_clear(alpha);
			// check the randomized commitments
			if (!com->Verify(foo, bar, lej))
				throw false;
		}
		else
		{
			// check whether $c^e c_d = \mathrm{com}_{ck}(f_1,\ldots,f_n; z)$
			mpz_powm(foo, c, e, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			if (!com->Verify(foo, z, f))
				throw false;
			// check whether $c_a^e c_{\Delta} = \mathrm{com}_{ck}
			//            (f_{\Delta_1},\ldots,f_{\Delta_{n-1}}; z_{\Delta})$
			mpz_powm(foo, c_a, e, com->p);
			mpz_mul(foo, foo, c_Delta);
			mpz_mod(foo, foo, com->p);
			if (!com->Verify(foo, z_Delta, f_Delta))
				throw false;
		}
		// check $F_n  = e \prod_{i=1}^n (m_i - x)$
		mpz_mul(foo, e, x);
		mpz_mod(foo, foo, com->q);
		assert(mpz_invert(bar, e, com->q));
		mpz_invert(bar, e, com->q);
		mpz_set_ui(foo2, 1L);
		for (size_t i = 0; i < f.size(); i++)
		{
			mpz_sub(bar2, f[i], foo);
			mpz_mod(bar2, bar2, com->q);
			
			mpz_mul(bar2, bar2, foo2);
			mpz_mod(bar2, bar2, com->q);
			if (i > 0)
			{
				mpz_add(bar2, bar2, f_Delta[i - 1]);
				mpz_mod(bar2, bar2, com->q);
				
				mpz_mul(bar2, bar2, bar);
				mpz_mod(bar2, bar2, com->q);
			}
			mpz_set(foo2, bar2);
		}
		mpz_set_ui(foo2, 1L);
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_sub(foo, m[i], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, com->q);
		}
		mpz_mul(foo2, foo2, e);
		mpz_mod(foo2, foo2, com->q);
		if (mpz_cmp(foo2, bar2))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(x), mpz_clear(c_d), mpz_clear(c_Delta), mpz_clear(c_a),
			mpz_clear(e), mpz_clear(z), mpz_clear(z_Delta), mpz_clear(foo),
			mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2);
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(f_Delta[i]), mpz_clear(lej[i]);
			delete f[i], delete f_Delta[i], delete lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

bool GrothSKC::Verify_interactive
	(mpz_srcptr c, const std::vector<mpz_ptr> &f_prime,
	const std::vector<mpz_ptr> &m,
	std::istream &in, std::ostream &out, bool optimizations) const
{
	assert(com->g.size() >= m.size());
	assert(m.size() == f_prime.size());
	assert(m.size() >= 2);
	
	// initialize
	mpz_t x, c_d, c_Delta, c_a, e, z, z_Delta, foo, bar, foo2, bar2;
	std::vector<mpz_ptr> f, f_Delta, lej;
	mpz_init(x), mpz_init(c_d), mpz_init(c_Delta), mpz_init(c_a), mpz_init(e),
		mpz_init(z), mpz_init(z_Delta), mpz_init(foo), mpz_init(bar),
		mpz_init(foo2), mpz_init(bar2);
	for (size_t i = 0; i < m.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3);
		f.push_back(tmp), f_Delta.push_back(tmp2), lej.push_back(tmp3);
	}
	mpz_set_ui(f_Delta[f_Delta.size() - 1], 0L);
	
	try
	{
		// verifier: first move
		mpz_srandomb(x, l_e);
		out << x << std::endl;
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a;
		
		// verifier: third move
		mpz_srandomb(e, l_e);
		out << e << std::endl;
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> z;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i];
		in >> z_Delta;
		
		// check whether $c_d, c_a, c_{\Delta} \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c_d) && com->TestMembership(c_a) &&
			com->TestMembership(c_Delta)))
				throw false;
		
		// check whether $f_1, \ldots, f_n, z \in\mathbb{Z}_q$
		if (!(mpz_cmp(z, com->q) < 0))
			throw false;
		for (size_t i = 0; i < f.size(); i++)
		{
			if (!(mpz_cmp(f[i], com->q) < 0))
				throw false;
		}
		
		// check whether $f_{\Delta_1}, \ldots, f_{\Delta_{n-1}}$
		// and $z_{\Delta}$ are from $\mathbb{Z}_q$
		if (!(mpz_cmp(z_Delta, com->q) < 0))
			throw false;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
		{
			if (!(mpz_cmp(f_Delta[i], com->q) < 0))
				throw false;
		}
		
		if (optimizations)
		{
			// randomization technique from section 6,
			// paragraph 'Batch verification'
			mpz_t alpha;
			mpz_init(alpha);
			// pick $\alpha\in_R\{0, 1\}^{\ell_e}$ at random
			mpz_srandomb(alpha, l_e);
			// compute $(c^e c_d)^{\alpha}$
			mpz_powm(foo, c, e, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(foo, foo, alpha, com->p);
			// compute $c_a^e c_{\Delta}$
			mpz_powm(bar, c_a, e, com->p);
			mpz_mul(bar, bar, c_Delta);
			mpz_mod(bar, bar, com->p);
			// compute the product
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);
			// compute the messages for the commitment
			for (size_t i = 0; i < f.size(); i++)
			{
				mpz_mul(lej[i], alpha, f[i]);
				mpz_mod(lej[i], lej[i], com->q);
				mpz_add(lej[i], lej[i], f_Delta[i]);
				mpz_mod(lej[i], lej[i], com->q);
				
				// compute $f'_i e \alpha$ (optimized commitment)
				mpz_mul(bar, alpha, f_prime[i]);
				mpz_mod(bar, bar, com->q);
				mpz_mul(bar, bar, e);
				mpz_mod(bar, bar, com->q);
				mpz_neg(bar, bar);
				
				mpz_add(lej[i], lej[i], bar);
				mpz_mod(lej[i], lej[i], com->q);
			}
			mpz_mul(bar, alpha, z);
			mpz_mod(bar, bar, com->q);
			mpz_add(bar, bar, z_Delta);
			mpz_mod(bar, bar, com->q);
			mpz_clear(alpha);
			// check the randomized commitments
			if (!com->Verify(foo, bar, lej))
				throw false;
		}
		else
		{
			// check whether $c^e c_d = \mathrm{com}(f''_1, \ldots, f''_n; z)$
			mpz_powm(foo, c, e, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
				// compute $f''_i = f_i - f'_i e$
				for (size_t i = 0; i < f.size(); i++)
				{
					mpz_mul(lej[i], f_prime[i], e);
					mpz_mod(lej[i], lej[i], com->q);
					mpz_neg(lej[i], lej[i]);
					mpz_add(lej[i], lej[i], f[i]);
					mpz_mod(lej[i], lej[i], com->q);
				}
			if (!com->Verify(foo, z, lej))
				throw false;
			// check whether $c_a^e c_{\Delta} = \mathrm{com}(f_{\Delta_1},
			// \ldots, f_{\Delta_{n-1}}; z_{\Delta})$
			mpz_powm(foo, c_a, e, com->p);
			mpz_mul(foo, foo, c_Delta);
			mpz_mod(foo, foo, com->p);
			if (!com->Verify(foo, z_Delta, f_Delta))
				throw false;
		}
		
		// check $F_n  = e \prod_{i=1}^n (m_i - x)$
		mpz_mul(foo, e, x);
		mpz_mod(foo, foo, com->q);
		assert(mpz_invert(bar, e, com->q));
		mpz_invert(bar, e, com->q);
		mpz_set_ui(foo2, 1L);
		for (size_t i = 0; i < f.size(); i++)
		{
			mpz_sub(bar2, f[i], foo);
			mpz_mod(bar2, bar2, com->q);
			
			mpz_mul(bar2, bar2, foo2);
			mpz_mod(bar2, bar2, com->q);
			if (i > 0)
			{
				mpz_add(bar2, bar2, f_Delta[i - 1]);
				mpz_mod(bar2, bar2, com->q);
				
				mpz_mul(bar2, bar2, bar);
				mpz_mod(bar2, bar2, com->q);
			}
			mpz_set(foo2, bar2);
		}
		mpz_set_ui(foo2, 1L);
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_sub(foo, m[i], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, com->q);
		}
		mpz_mul(foo2, foo2, e);
		mpz_mod(foo2, foo2, com->q);
		if (mpz_cmp(foo2, bar2))
			throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(x), mpz_clear(c_d), mpz_clear(c_Delta), mpz_clear(c_a),
			mpz_clear(e), mpz_clear(z), mpz_clear(z_Delta), mpz_clear(foo),
			mpz_clear(bar), mpz_clear(foo2), mpz_clear(bar2);
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(f_Delta[i]), mpz_clear(lej[i]);
			delete f[i], delete f_Delta[i], delete lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

GrothSKC::~GrothSKC
	()
{
	mpz_clear(exp2l_e);
	delete com;
}

// =============================================================================

GrothVSSHE::GrothVSSHE
	(size_t n,
	mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e)
{
	std::stringstream lej;
	
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	
	// Initialize the commitment scheme and Groth's SKC argument
	com = new PedersenCommitmentScheme(n, fieldsize, subgroupsize);
	com->PublishGroup(lej);
	skc = new GrothSKC(n, lej, ell_e);
	
	// Compute $2^{\ell_e}$ for the input reduction.
	mpz_init(exp2l_e);
	mpz_ui_pow_ui(exp2l_e, 2L, ell_e);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

GrothVSSHE::GrothVSSHE
	(size_t n,
	mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr k_ENC,
	mpz_srcptr g_ENC, mpz_srcptr h_ENC,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e)
{
	std::stringstream lej;
	
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	
	// Initialize the commitment scheme and Groth's SKC argument
	com = new PedersenCommitmentScheme(n, p_ENC, q_ENC, k_ENC, h_ENC, 
		fieldsize, subgroupsize);
	com->PublishGroup(lej);
	skc = new GrothSKC(n, lej, ell_e, fieldsize, subgroupsize);
	
	// Compute $2^{\ell_e}$ for the input reduction.
	mpz_init(exp2l_e);
	mpz_ui_pow_ui(exp2l_e, 2L, ell_e);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

GrothVSSHE::GrothVSSHE
	(size_t n, std::istream& in,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e)
{
	std::stringstream lej;
	
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	
	// Initialize the commitment scheme and Groth's SKC argument
	com = new PedersenCommitmentScheme(n, in, fieldsize, subgroupsize);
	com->PublishGroup(lej);
	skc = new GrothSKC(n, lej, ell_e, fieldsize, subgroupsize);
	
	// Compute $2^{\ell_e}$ for the input reduction.
	mpz_init(exp2l_e);
	mpz_ui_pow_ui(exp2l_e, 2L, ell_e);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

bool GrothVSSHE::CheckGroup
	() const
{
	// the commitment scheme is checked by the SKC class
	return skc->CheckGroup();
}

void GrothVSSHE::PublishGroup
	(std::ostream& out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << h << std::endl;
	com->PublishGroup(out);
}

void GrothVSSHE::Prove_interactive
	(const std::vector<size_t>& pi, const std::vector<mpz_ptr>& R,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	std::istream& in, std::ostream& out) const
{
	assert(com->g.size() >= pi.size());
	assert(pi.size() == R.size());
	assert(R.size() == e.size());
	assert(e.size() == E.size());
	assert(E.size() >= 2);
	
	// initialize
	mpz_t r, R_d, r_d, c, c_d, Z, lambda, rho, foo, bar;
	std::pair<mpz_ptr, mpz_ptr> E_d;
	std::vector<mpz_ptr> d, f, m, t;
	E_d.first = new mpz_t(), E_d.second = new mpz_t();
	mpz_init(r), mpz_init(R_d), mpz_init(r_d), mpz_init(c), mpz_init(c_d),
		mpz_init(Z), mpz_init(lambda), mpz_init(rho), mpz_init(foo),
		mpz_init(bar), mpz_init(E_d.first), mpz_init(E_d.second);
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
			tmp4 = new mpz_t();
		mpz_init(tmp), mpz_init(tmp2), mpz_init(tmp3), mpz_init(tmp4);
		d.push_back(tmp), f.push_back(tmp2), m.push_back(tmp3),
			t.push_back(tmp4);
	}
	
	// prover: first move
	mpz_srandomm(r, com->q);
	mpz_srandomm(R_d, q);
	for (size_t i = 0; i < d.size(); i++)
	{
		mpz_srandomm(d[i], com->q);
		mpz_neg(d[i], d[i]);
	}
	mpz_srandomm(r_d, com->q);
	for (size_t i = 0; i < m.size(); i++)
		mpz_set_ui(m[i], pi[i] + 1L);
	com->CommitBy(c, r, m);
	com->CommitBy(c_d, r_d, d);
	mpz_set_ui(E_d.first, 1L), mpz_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < d.size(); i++)
	{
		// Compute and multiply $E_i^{-d_i}$
		mpz_spowm(foo, E[i].first, d[i], p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		mpz_spowm(bar, E[i].second, d[i], p);
		mpz_mul(E_d.second, E_d.second, bar);
		mpz_mod(E_d.second, E_d.second, p);
	}
	// Compute and multiply $E(1;R_d)$
	mpz_fspowm(fpowm_table_g, foo, g, R_d, p);
	mpz_mul(E_d.first, E_d.first, foo);
	mpz_mod(E_d.first, E_d.first, p);
	mpz_fspowm(fpowm_table_h, bar, h, R_d, p);
	mpz_mul(E_d.second, E_d.second, bar);
	mpz_mod(E_d.second, E_d.second, p);
	
	out << c << std::endl << c_d << std::endl << E_d.first << std::endl << 
		E_d.second << std::endl;
	
	// prover: second move
	for (size_t i = 0; i < f.size(); i++)
	{
		in >> t[i];
		// check whether the $t_i$'s are from $\{0, 1\}^{\ell_e}$
		if (mpz_sizeinbase(t[i], 2L) > l_e)
			mpz_mod(t[i], t[i], exp2l_e);
	}
	
	// prover: third move
	for (size_t i = 0; i < f.size(); i++)
	{
		mpz_neg(f[i], d[i]);
		mpz_add(f[i], f[i], t[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
	}
	mpz_set_ui(Z, 0L);
	for (size_t i = 0; i < t.size(); i++)
	{
		mpz_mul(foo, t[pi[i]], R[i]);
		mpz_mod(foo, foo, q);
		mpz_add(Z, Z, foo);
		mpz_mod(Z, Z, q);
	}
	mpz_add(Z, Z, R_d);
	mpz_mod(Z, Z, q);
	
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;
	out << Z << std::endl;
	
	// prover: fourth move
	in >> lambda;
	// check whether $\lambda$ is from $\{0, 1\}^{\ell_e}$, otherwise reduce
	if (mpz_sizeinbase(lambda, 2L) > l_e)
		mpz_mod(lambda, lambda, exp2l_e);
	
	// prover: fifth to seventh move (Shuffle of Known Content)
		// $\rho := \lambda r + r_d \bmod q$
		mpz_mul(rho, lambda, r);
		mpz_mod(rho, rho, com->q);
		mpz_add(rho, rho, r_d);
		mpz_mod(rho, rho, com->q);
/* This part is not necessary: see personal communication with Jens Groth
		// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
		mpz_set_ui(bar, 0L);
		com->CommitBy(foo, bar, f, false);
		mpz_mul(foo, foo, c_d);
		mpz_mod(foo, foo, com->p);
		mpz_powm(bar, c, lambda, com->p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, com->p);
*/
		// SKC messages $m_i := i \lambda + t_i \bmod q$ for all $i = 1,\ldots, n$
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_set_ui(m[i], i + 1L);
			mpz_mul(m[i], m[i], lambda);
			mpz_mod(m[i], m[i], com->q);
			mpz_add(m[i], m[i], t[i]);
			mpz_mod(m[i], m[i], com->q);
		}
	skc->Prove_interactive(pi, rho, m, in, out);
	
	// release
	mpz_clear(r), mpz_clear(R_d), mpz_clear(r_d), mpz_clear(c), mpz_clear(c_d),
		mpz_clear(Z), mpz_clear(lambda), mpz_clear(rho), mpz_clear(foo),
		mpz_clear(bar);
	mpz_clear(E_d.first), mpz_clear(E_d.second);
	delete E_d.first, delete E_d.second;
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_clear(d[i]), mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
		delete d[i], delete f[i], delete m[i], delete t[i];
	}
	d.clear(), f.clear(), m.clear(), t.clear();
}

bool GrothVSSHE::Verify_interactive
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	std::istream& in, std::ostream& out) const
{
	assert(com->g.size() >= e.size());
	assert(e.size() == E.size());
	assert(E.size() >= 2);
	
	// initialize
	mpz_t c, c_d, Z, lambda, foo, bar, foo2, bar2, foo3, bar3;
	std::pair<mpz_ptr, mpz_ptr> E_d;
	std::vector<mpz_ptr> f, m, t;
	E_d.first = new mpz_t(), E_d.second = new mpz_t();
	mpz_init(c), mpz_init(c_d), mpz_init_set_ui(Z, 0L), mpz_init(lambda),
		mpz_init(foo), mpz_init(bar), mpz_init(foo2), mpz_init(bar2),
		mpz_init(foo3), mpz_init(bar3);
	mpz_init_set_ui(E_d.first, 1L), mpz_init_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < e.size(); i++)
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
/* This part is not necessary: see personal communication with Jens Groth
			// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
			mpz_set_ui(bar, 0L);
			com->CommitBy(foo, bar, f, false);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(bar, c, lambda, com->p);
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);
*/
			// SKC (optimized homomorphic) commitment $c^{\lambda} c_d \bmod p$
			mpz_powm(foo, c, lambda, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			// SKC messages
			// $m_i := i \lambda + t_i \bmod q$ for all $i = 1,\ldots, n$
			for (size_t i = 0; i < m.size(); i++)
			{
				mpz_set_ui(m[i], i + 1L);
				mpz_mul(m[i], m[i], lambda);
				mpz_mod(m[i], m[i], com->q);
				mpz_add(m[i], m[i], t[i]);
				mpz_mod(m[i], m[i], com->q);
			}
		
		// perform and verify SKC
		if (!skc->Verify_interactive(foo, f, m, in, out))
			throw false;
		
		// check whether $c, c_d \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c) && com->TestMembership(c_d)))
			throw false;
		
		// check whether $E_d\in\mathcal{C}_{pk}$
		mpz_fpowm(fpowm_table_g, foo, E_d.first, q, p);
		mpz_fpowm(fpowm_table_h, bar, E_d.second, q, p);
		if (mpz_cmp_ui(foo, 1L) || mpz_cmp_ui(bar, 1L))
			throw false;
		
		// check whether $2^{\ell_e} \le f_1,\ldots,f_n < q$
		for (size_t i = 0; i < f.size(); i++)
		{
			if ((mpz_sizeinbase(f[i], 2L) < l_e) || 
				(mpz_cmp(f[i], com->q) >= 0))
					throw false;
		}
		
		// check whether $Z\in\mathcal{R}_{pk}$
		if ((mpz_cmp_ui(Z, 0L) <= 0) || (mpz_cmp(Z, q) >= 0))
			throw false;
		
		// check whether
		// $\prod_{i=1}^n e_i^{-t_i} \prod_{i=1}^n E_i^{f_i} E_d = E(1;Z)$
		mpz_set_ui(foo2, 1L), mpz_set_ui(bar2, 1L);
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_neg(t[i], t[i]);
			mpz_powm(foo, e[i].first, t[i], p);
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, p);
			mpz_powm(bar, e[i].second, t[i], p);
			mpz_mul(bar2, bar2, bar);
			mpz_mod(bar2, bar2, p);
		}
		mpz_set_ui(foo3, 1L), mpz_set_ui(bar3, 1L);
		for (size_t i = 0; i < E.size(); i++)
		{
			mpz_powm(foo, E[i].first, f[i], p);
			mpz_mul(foo3, foo3, foo);
			mpz_mod(foo3, foo3, p);
			mpz_powm(bar, E[i].second, f[i], p);
			mpz_mul(bar3, bar3, bar);
			mpz_mod(bar3, bar3, p);
		}
		mpz_mul(foo3, foo3, E_d.first);
		mpz_mod(foo3, foo3, p);
		mpz_mul(bar3, bar3, E_d.second);
		mpz_mod(bar3, bar3, p);
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
		delete E_d.first, delete E_d.second;
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
			delete f[i], delete m[i], delete t[i];
		}
		f.clear(), m.clear(), t.clear();
		// return
		return return_value;
	}
}

GrothVSSHE::~GrothVSSHE
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(h);
	delete com;
	delete skc;
	
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
