/*******************************************************************************
  GrothVSSHE.cc, |V|erifiable |S|ecret |S|huffle of |H|omomorphic |E|ncryptions

     [Gr05] Jens Groth: 'A Verifiable Secret Shuffle of Homomorphic Encryptions',
     Cryptology ePrint Archive, Report 2005/246, 2005.

   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007, 2009, 
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "GrothVSSHE.hh"

// additional headers
#include <cassert>
#include <string>
#include <sstream>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

GrothSKC::GrothSKC
	(size_t n,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e), l_e_nizk(ell_e * 2L)
{
	com = new PedersenCommitmentScheme(n, fieldsize, subgroupsize);
}

GrothSKC::GrothSKC
	(size_t n, std::istream &in,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e), l_e_nizk(ell_e * 2L)
{
	com = new PedersenCommitmentScheme(n, in, fieldsize, subgroupsize);
}

void GrothSKC::SetupGenerators_publiccoin
	(mpz_srcptr a)
{
	com->SetupGenerators_publiccoin(a);
}

bool GrothSKC::SetupGenerators_publiccoin
	(const size_t whoami, aiounicast *aiou,
	CachinKursawePetzoldShoupRBC *rbc,
	JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	return com->SetupGenerators_publiccoin(whoami, aiou, rbc, edcf, err);
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
	// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
	mpz_tdiv_r_2exp(x, x, l_e);
	
	// prover: second move
	tmcg_mpz_srandomm(r_d, com->q); // $r_d \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(r_Delta, com->q); // $r_{\Delta} \gets \mathbb{Z}_q$
	for (size_t i = 0; i < d.size(); i++)
		tmcg_mpz_srandomm(d[i], com->q); // $d_1,\ldots,d_n \gets \mathbb{Z}_q$
	mpz_set(Delta[0], d[0]); // $\Delta_1 := d_1$
	for (size_t i = 1; i < (Delta.size() - 1); i++)
		tmcg_mpz_srandomm(Delta[i], com->q);	// $\Delta_2,\ldots,\Delta_{n-1}
						//           \gets \mathbb{Z}_q$
	mpz_set_ui(Delta[Delta.size() - 1], 0L); // $\Delta_n := 0$
	for (size_t i = 0; i < a.size(); i++)
	{
		mpz_set_ui(a[i], 1L);
		// compute $a_i = \prod_{j=1}^i (m_{\pi(j)} - x)$
		for (size_t j = 0; j <= i; j++)
		{
			mpz_sub(foo, m[pi[j]], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(a[i], a[i], foo);
			mpz_mod(a[i], a[i], com->q);
		}
	}
	tmcg_mpz_srandomm(r_a, com->q); // $r_a \gets \mathbb{Z}_q$
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
	// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
	mpz_tdiv_r_2exp(e, e, l_e);
	
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
		delete [] d[i], delete [] Delta[i], delete [] a[i], delete [] f[i], 
			delete [] f_Delta[i], delete [] lej[i];
	}
	d.clear(), Delta.clear(), a.clear(), f.clear(), f_Delta.clear(), 
		lej.clear();
}

void GrothSKC::Prove_interactive_publiccoin
	(const std::vector<size_t> &pi, mpz_srcptr r,
	const std::vector<mpz_ptr> &m,
	JareckiLysyanskayaEDCF *edcf,
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
	std::stringstream err;
	edcf->Flip_twoparty(0, x, in, out, err); // flip coins with verifier to get $x$
	// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
	mpz_tdiv_r_2exp(x, x, l_e);
	
	// prover: second move
	tmcg_mpz_srandomm(r_d, com->q); // $r_d \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(r_Delta, com->q); // $r_{\Delta} \gets \mathbb{Z}_q$
	for (size_t i = 0; i < d.size(); i++)
		tmcg_mpz_srandomm(d[i], com->q); // $d_1,\ldots,d_n \gets \mathbb{Z}_q$
	mpz_set(Delta[0], d[0]); // $\Delta_1 := d_1$
	for (size_t i = 1; i < (Delta.size() - 1); i++)
		tmcg_mpz_srandomm(Delta[i], com->q);	// $\Delta_2,\ldots,\Delta_{n-1}
						//           \gets \mathbb{Z}_q$
	mpz_set_ui(Delta[Delta.size() - 1], 0L); // $\Delta_n := 0$
	for (size_t i = 0; i < a.size(); i++)
	{
		mpz_set_ui(a[i], 1L);
		// compute $a_i = \prod_{j=1}^i (m_{\pi(j)} - x)$
		for (size_t j = 0; j <= i; j++)
		{
			mpz_sub(foo, m[pi[j]], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(a[i], a[i], foo);
			mpz_mod(a[i], a[i], com->q);
		}
	}
	tmcg_mpz_srandomm(r_a, com->q); // $r_a \gets \mathbb{Z}_q$
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
	edcf->Flip_twoparty(0, e, in, out, err); // flip coins with verifier to get $e$
	// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
	mpz_tdiv_r_2exp(e, e, l_e);
	
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
		delete [] d[i], delete [] Delta[i], delete [] a[i], delete [] f[i], 
			delete [] f_Delta[i], delete [] lej[i];
	}
	d.clear(), Delta.clear(), a.clear(), f.clear(), f_Delta.clear(), 
		lej.clear();
}

void GrothSKC::Prove_noninteractive
	(const std::vector<size_t> &pi, mpz_srcptr r,
	const std::vector<mpz_ptr> &m, std::ostream &out) const
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
		// get $x$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2vec(x, com->g, m, 3, com->p, com->q, com->h);
		// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
		// note that we follow the advice of section 2.5 [Gr05] by increasing the
		// value of $\ell_e$ for the non-interactive protocol version
		mpz_tdiv_r_2exp(x, x, l_e_nizk);
	
	// prover: second move
	tmcg_mpz_srandomm(r_d, com->q); // $r_d \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(r_Delta, com->q); // $r_{\Delta} \gets \mathbb{Z}_q$
	for (size_t i = 0; i < d.size(); i++)
		tmcg_mpz_srandomm(d[i], com->q); // $d_1,\ldots,d_n \gets \mathbb{Z}_q$
	mpz_set(Delta[0], d[0]); // $\Delta_1 := d_1$
	for (size_t i = 1; i < (Delta.size() - 1); i++)
		tmcg_mpz_srandomm(Delta[i], com->q);	// $\Delta_2,\ldots,\Delta_{n-1}
												//           \gets \mathbb{Z}_q$
	mpz_set_ui(Delta[Delta.size() - 1], 0L); // $\Delta_n := 0$
	for (size_t i = 0; i < a.size(); i++)
	{
		mpz_set_ui(a[i], 1L);
		// compute $a_i = \prod_{j=1}^i (m_{\pi(j)} - x)$
		for (size_t j = 0; j <= i; j++)
		{
			mpz_sub(foo, m[pi[j]], x);
			mpz_mod(foo, foo, com->q);
			mpz_mul(a[i], a[i], foo);
			mpz_mod(a[i], a[i], com->q);
		}
	}
	tmcg_mpz_srandomm(r_a, com->q); // $r_a \gets \mathbb{Z}_q$
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
		// get $e$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2vec(e, com->g, m, 4, x, c_d, c_Delta, c_a);
		// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
		// note that we follow the advice of section 2.5 [Gr05] by increasing the
		// value of $\ell_e$ for the non-interactive protocol version
		mpz_tdiv_r_2exp(e, e, l_e_nizk);

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
		delete [] d[i], delete [] Delta[i], delete [] a[i], delete [] f[i], 
			delete [] f_Delta[i], delete [] lej[i];
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
		tmcg_mpz_srandomb(x, l_e);
		out << x << std::endl; // send $x\in\{0,1\}^{\ell_e}$ to the prover
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a; // get $c_d$, $c_{\Delta}$, and $c_a$ from prover
		if (!in.good())
			throw false;
		
		// verifier: third move
		do
		{
			tmcg_mpz_srandomb(e, l_e);
		}
		while (!mpz_cmp_ui(e, 0L)); // ensure that $e$ is invertable mod $q$
		out << e << std::endl; // send $e\in\{0,1\}^{\ell_e}$ to prover
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i]; // get $f_1,\ldots,f_n$ from the prover
		in >> z; // get $z$ from the prover
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i]; // get $f_{\Delta_1},\ldots,f_{\Delta_{n-1}}$
			                  // from the prover
		in >> z_Delta; // get $z_{\Delta}$ from the prover
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e);
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
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
		mpz_set_ui(foo2, 1L); // foo2 stores $F_{n-1}$
		for (size_t i = 0; i < f.size(); i++)
		{ // compute left-hand side $F_n$, for $i = 1, \ldots, n$
			mpz_sub(bar2, f[i], foo);
			mpz_mod(bar2, bar2, com->q);
			
			mpz_mul(bar2, bar2, foo2);
			mpz_mod(bar2, bar2, com->q);
			if (i > 0)
			{ // add $f_{\Delta_j}$, for $j = 1, \ldots, n-1$
				mpz_add(bar2, bar2, f_Delta[i - 1]);
				mpz_mod(bar2, bar2, com->q);
				
				mpz_mul(bar2, bar2, bar);
				mpz_mod(bar2, bar2, com->q);
			}
			mpz_set(foo2, bar2);
		}
		mpz_set_ui(foo2, 1L); // foo2 is right-hand side here
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

bool GrothSKC::Verify_interactive_publiccoin
	(mpz_srcptr c, const std::vector<mpz_ptr> &m,
	JareckiLysyanskayaEDCF *edcf,
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
		std::stringstream err;
		if (!edcf->Flip_twoparty(1, x, in, out, err)) // flip coins with prover to get $x$
			throw false;
		// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(x, x, l_e);
		// verifier: second move
		in >> c_d >> c_Delta >> c_a; // get $c_d$, $c_{\Delta}$, and $c_a$ from prover
		if (!in.good())
			throw false;
		
		// verifier: third move
		if (!edcf->Flip_twoparty(1, e, in, out, err)) // flip coins with prover to get $e$
			throw false;
		// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(e, e, l_e);
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i]; // get $f_1,\ldots,f_n$ from the prover
		in >> z; // get $z$ from the prover
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i]; // get $f_{\Delta_1},\ldots,f_{\Delta_{n-1}}$
			                  // from the prover
		in >> z_Delta; // get $z_{\Delta}$ from the prover
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e);
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
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
		mpz_set_ui(foo2, 1L); // foo2 stores $F_{n-1}$
		for (size_t i = 0; i < f.size(); i++)
		{ // compute left-hand side $F_n$, for $i = 1, \ldots, n$
			mpz_sub(bar2, f[i], foo);
			mpz_mod(bar2, bar2, com->q);
			
			mpz_mul(bar2, bar2, foo2);
			mpz_mod(bar2, bar2, com->q);
			if (i > 0)
			{ // add $f_{\Delta_j}$, for $j = 1, \ldots, n-1$
				mpz_add(bar2, bar2, f_Delta[i - 1]);
				mpz_mod(bar2, bar2, com->q);
				
				mpz_mul(bar2, bar2, bar);
				mpz_mod(bar2, bar2, com->q);
			}
			mpz_set(foo2, bar2);
		}
		mpz_set_ui(foo2, 1L); // foo2 is right-hand side here
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

bool GrothSKC::Verify_noninteractive
	(mpz_srcptr c, const std::vector<mpz_ptr> &m,
	std::istream &in, bool optimizations) const
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
			// get $x$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2vec(x, com->g, m, 3, com->p, com->q, com->h);
			// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(x, x, l_e_nizk);
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a; // get $c_d$, $c_{\Delta}$, and $c_a$ from prover
		if (!in.good())
			throw false;
		
		// verifier: third move
			// get $e$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2vec(e, com->g, m, 4, x, c_d, c_Delta, c_a);
			// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(e, e, l_e_nizk);
	
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i]; // get $f_1,\ldots,f_n$ from the prover
		in >> z; // get $z$ from the prover
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i]; // get $f_{\Delta_1},\ldots,f_{\Delta_{n-1}}$
			                  // from the prover
		in >> z_Delta; // get $z_{\Delta}$ from the prover
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e);
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
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
		mpz_set_ui(foo2, 1L); // foo2 stores $F_{n-1}$
		for (size_t i = 0; i < f.size(); i++)
		{ // compute left-hand side $F_n$, for $i = 1, \ldots, n$
			mpz_sub(bar2, f[i], foo);
			mpz_mod(bar2, bar2, com->q);
			
			mpz_mul(bar2, bar2, foo2);
			mpz_mod(bar2, bar2, com->q);
			if (i > 0)
			{ // add $f_{\Delta_j}$, for $j = 1, \ldots, n-1$
				mpz_add(bar2, bar2, f_Delta[i - 1]);
				mpz_mod(bar2, bar2, com->q);
				
				mpz_mul(bar2, bar2, bar);
				mpz_mod(bar2, bar2, com->q);
			}
			mpz_set(foo2, bar2);
		}
		mpz_set_ui(foo2, 1L); // foo2 is right-hand side here
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

/* This function uses somehow optimized commitments when called from VSSHE. */
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
		tmcg_mpz_srandomb(x, l_e);
		out << x << std::endl;
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a;
		if (!in.good())
			throw false;
		
		// verifier: third move
		do
		{
			tmcg_mpz_srandomb(e, l_e);
		}
		while (!mpz_cmp_ui(e, 0L)); // ensure that $e$ is invertable mod $q$
		out << e << std::endl;
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> z;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i];
		in >> z_Delta;
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e);
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
		
		// check $F_n = e \prod_{i=1}^n (m_i - x)$
		mpz_mul(foo, e, x);
		mpz_mod(foo, foo, com->q);
		assert(mpz_invert(bar, e, com->q));
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

/* This function uses somehow optimized commitments when called from VSSHE. */
bool GrothSKC::Verify_interactive_publiccoin
	(mpz_srcptr c, const std::vector<mpz_ptr> &f_prime,
	const std::vector<mpz_ptr> &m,
	JareckiLysyanskayaEDCF *edcf,
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
		std::stringstream err;
		if (!edcf->Flip_twoparty(1, x, in, out, err)) // flip coins with prover to get $x$
			throw false;
		// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(x, x, l_e);
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a;
		if (!in.good())
			throw false;
		
		// verifier: third move
		if (!edcf->Flip_twoparty(1, e, in, out, err)) // flip coins with prover to get $e$
			throw false;
		// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(e, e, l_e);
		
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> z;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i];
		in >> z_Delta;
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e);
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
		
		// check $F_n = e \prod_{i=1}^n (m_i - x)$
		mpz_mul(foo, e, x);
		mpz_mod(foo, foo, com->q);
		assert(mpz_invert(bar, e, com->q));
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

/* This function uses somehow optimized commitments when called from VSSHE. */
bool GrothSKC::Verify_noninteractive
	(mpz_srcptr c, const std::vector<mpz_ptr> &f_prime,
	const std::vector<mpz_ptr> &m,
	std::istream &in, bool optimizations) const
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
			// get $x$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2vec(x, com->g, m, 3, com->p, com->q, com->h);
			// reduce such that $x$ is from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(x, x, l_e_nizk);
		
		// verifier: second move
		in >> c_d >> c_Delta >> c_a;
		if (!in.good())
			throw false;
		
		// verifier: third move
			// get $e$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2vec(e, com->g, m, 4, x, c_d, c_Delta, c_a);
			// reduce such that $e$ is from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(e, e, l_e_nizk);
	
		// verifier: fourth move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> z;
		for (size_t i = 0; i < (f_Delta.size() - 1); i++)
			in >> f_Delta[i];
		in >> z_Delta;
		if (!in.good())
			throw false;
		
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
			tmcg_mpz_srandomb(alpha, l_e_nizk);
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
		
		// check $F_n = e \prod_{i=1}^n (m_i - x)$
		mpz_mul(foo, e, x);
		mpz_mod(foo, foo, com->q);
		assert(mpz_invert(bar, e, com->q));
		if (!mpz_invert(bar, e, com->q))
			mpz_set_ui(bar, 0L); // indicates an error
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
			delete [] f[i], delete [] f_Delta[i], delete [] lej[i];
		}
		f.clear(), f_Delta.clear(), lej.clear();
		
		// return
		return return_value;
	}
}

GrothSKC::~GrothSKC
	()
{
	delete com;
}

// =============================================================================

GrothVSSHE::GrothVSSHE
	(size_t n,
	mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr k_ENC,
	mpz_srcptr g_ENC, mpz_srcptr h_ENC,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e), l_e_nizk(ell_e * 2L), F_size(fieldsize), G_size(subgroupsize)
{
	std::stringstream lej;
	
	mpz_init_set(p, p_ENC), mpz_init_set(q, q_ENC), mpz_init_set(g, g_ENC),
		mpz_init_set(h, h_ENC);
	
	// Initialize the commitment scheme and Groth's SKC argument
	com = new PedersenCommitmentScheme(n, p_ENC, q_ENC, k_ENC, h_ENC, 
		fieldsize, subgroupsize);
	com->PublishGroup(lej);
	skc = new GrothSKC(n, lej, ell_e, fieldsize, subgroupsize);

	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

GrothVSSHE::GrothVSSHE
	(size_t n, std::istream& in,
	unsigned long int ell_e, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		l_e(ell_e), l_e_nizk(ell_e * 2L), F_size(fieldsize), G_size(subgroupsize)
{
	std::stringstream lej;
	
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(h);
	in >> p >> q >> g >> h;
	
	// Initialize the commitment scheme and Groth's SKC argument
	com = new PedersenCommitmentScheme(n, in, fieldsize, subgroupsize);
	com->PublishGroup(lej);
	skc = new GrothSKC(n, lej, ell_e, fieldsize, subgroupsize);
	
	// Do the precomputation for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void GrothVSSHE::SetupGenerators_publiccoin
	(mpz_srcptr a)
{
	com->SetupGenerators_publiccoin(a);
	// reinitialization of Groth's SKC argument
	std::stringstream lej;
	com->PublishGroup(lej);
	delete skc;
	skc = new GrothSKC(com->g.size(), lej, l_e, F_size, G_size);
}

bool GrothVSSHE::SetupGenerators_publiccoin
			(const size_t whoami, aiounicast *aiou,
			CachinKursawePetzoldShoupRBC *rbc,
			JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	if (!com->SetupGenerators_publiccoin(whoami, aiou, rbc, edcf, err))
		return false;
	// reinitialization of Groth's SKC argument
	std::stringstream lej;
	com->PublishGroup(lej);
	delete skc;
	skc = new GrothSKC(com->g.size(), lej, l_e, F_size, G_size);

	return true;
}

bool GrothVSSHE::CheckGroup
	() const
{
	// check, whether $|q| > 2^{\ell_e}$ (see proof of Theorem 5 [Gr05])
	if ((mpz_sizeinbase(q, 2L) < l_e) || (mpz_sizeinbase(q, 2L) < l_e_nizk))
		return false;
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
	tmcg_mpz_srandomm(r, com->q);	// $r \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(R_d, q);		// $R_d \gets \mathcal{R}_{pk}
	for (size_t i = 0; i < d.size(); i++)
	{
		// see note in [Gr05] for omitting $\ell_s$ here
		tmcg_mpz_srandomm(d[i], com->q);
		// store $d_i$ as negative value for convenience
		mpz_neg(d[i], d[i]);
	}
	tmcg_mpz_srandomm(r_d, com->q);	// $r_d \gets \mathbb{Z}_q$
	for (size_t i = 0; i < m.size(); i++)
		mpz_set_ui(m[i], pi[i] + 1L); // adjust shifted index
	com->CommitBy(c, r, m);
	com->CommitBy(c_d, r_d, d);
	mpz_set_ui(E_d.first, 1L), mpz_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < d.size(); i++)
	{
		// Compute and multiply $E_i^{-d_i}$
		tmcg_mpz_spowm(foo, E[i].first, d[i], p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		tmcg_mpz_spowm(bar, E[i].second, d[i], p);
		mpz_mul(E_d.second, E_d.second, bar);
		mpz_mod(E_d.second, E_d.second, p);
	}
	// Compute and multiply $E(1;R_d)$
	tmcg_mpz_fspowm(fpowm_table_g, foo, g, R_d, p);
	mpz_mul(E_d.first, E_d.first, foo);
	mpz_mod(E_d.first, E_d.first, p);
	tmcg_mpz_fspowm(fpowm_table_h, bar, h, R_d, p);
	mpz_mul(E_d.second, E_d.second, bar);
	mpz_mod(E_d.second, E_d.second, p);

	out << c << std::endl << c_d << std::endl << E_d.first << std::endl << 
		E_d.second << std::endl;
	
	// prover: second move
	for (size_t i = 0; i < t.size(); i++)
	{
		in >> t[i];
		// reduce such that $t_i$'s are from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(t[i], t[i], l_e);
	}
	
	// prover: third move
	for (size_t i = 0; i < f.size(); i++)
	{ // compute $f_i = t_{\pi(i)} + d_i$
		mpz_neg(f[i], d[i]);	// turn $d_i$ into positive values 
		mpz_add(f[i], f[i], t[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
	}
	mpz_set_ui(Z, 0L);
	for (size_t i = 0; i < t.size(); i++)
	{ // compute $Z = \sum_{i=1}^n t_{\pi(i)} R_i
		mpz_mul(foo, t[pi[i]], R[i]);
		mpz_mod(foo, foo, q);
		mpz_add(Z, Z, foo);
		mpz_mod(Z, Z, q);
	}
	mpz_add(Z, Z, R_d); // and add $R_d$
	mpz_mod(Z, Z, q);
	
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;
	out << Z << std::endl;
	
	// prover: fourth move
	in >> lambda;
		// reduce such that $\lambda$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(lambda, lambda, l_e);
	
	// prover: fifth to seventh move (Shuffle of Known Content)
		// $\rho := \lambda r + r_d \bmod q$
		mpz_mul(rho, lambda, r);
		mpz_mod(rho, rho, com->q);
		mpz_add(rho, rho, r_d);
		mpz_mod(rho, rho, com->q);
/* This part is not necessary: see personal communication with Jens Groth or the journal version of the paper, because
   $c^{\lambda} c_d \mathrm{com}_{ck}(f_1,\ldots,f_n;0) = \mathrm{com}_{ck}(\lambda\pi(1)+t_i,\ldots,\lambda\pi(n)+t_{\pi(n)})$
		// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
		mpz_set_ui(bar, 0L);
		com->CommitBy(foo, bar, f, false);
		mpz_mul(foo, foo, c_d);
		mpz_mod(foo, foo, com->p);
		mpz_powm(bar, c, lambda, com->p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, com->p);
*/
		// SKC messages $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_set_ui(m[i], i + 1L); // adjust shifted index
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
	delete [] E_d.first, delete [] E_d.second;
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_clear(d[i]), mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
		delete [] d[i], delete [] f[i], delete [] m[i], delete [] t[i];
	}
	d.clear(), f.clear(), m.clear(), t.clear();
}

void GrothVSSHE::Prove_interactive_publiccoin
	(const std::vector<size_t>& pi, const std::vector<mpz_ptr>& R,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	JareckiLysyanskayaEDCF *edcf,
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
	tmcg_mpz_srandomm(r, com->q);	// $r \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(R_d, q);		// $R_d \gets \mathcal{R}_{pk}
	for (size_t i = 0; i < d.size(); i++)
	{
		// see note in [Gr05] for omitting $\ell_s$ here
		tmcg_mpz_srandomm(d[i], com->q);
		// store $d_i$ as negative value for convenience
		mpz_neg(d[i], d[i]);
	}
	tmcg_mpz_srandomm(r_d, com->q);	// $r_d \gets \mathbb{Z}_q$
	for (size_t i = 0; i < m.size(); i++)
		mpz_set_ui(m[i], pi[i] + 1L); // adjust shifted index
	com->CommitBy(c, r, m);
	com->CommitBy(c_d, r_d, d);
	mpz_set_ui(E_d.first, 1L), mpz_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < d.size(); i++)
	{
		// Compute and multiply $E_i^{-d_i}$
		tmcg_mpz_spowm(foo, E[i].first, d[i], p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		tmcg_mpz_spowm(bar, E[i].second, d[i], p);
		mpz_mul(E_d.second, E_d.second, bar);
		mpz_mod(E_d.second, E_d.second, p);
	}
	// Compute and multiply $E(1;R_d)$
	tmcg_mpz_fspowm(fpowm_table_g, foo, g, R_d, p);
	mpz_mul(E_d.first, E_d.first, foo);
	mpz_mod(E_d.first, E_d.first, p);
	tmcg_mpz_fspowm(fpowm_table_h, bar, h, R_d, p);
	mpz_mul(E_d.second, E_d.second, bar);
	mpz_mod(E_d.second, E_d.second, p);
	
	out << c << std::endl << c_d << std::endl << E_d.first << std::endl << 
		E_d.second << std::endl;
	
	// prover: second move
	std::stringstream err;
	for (size_t i = 0; i < t.size(); i++)
	{
		edcf->Flip_twoparty(0, t[i], in, out, err); // flip coins with verifier to get $t_i$
		// reduce such that $t_i$'s are from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(t[i], t[i], l_e);
	}
	
	// prover: third move
	for (size_t i = 0; i < f.size(); i++)
	{ // compute $f_i = t_{\pi(i)} + d_i$
		mpz_neg(f[i], d[i]);	// turn $d_i$ into positive values 
		mpz_add(f[i], f[i], t[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
	}
	mpz_set_ui(Z, 0L);
	for (size_t i = 0; i < t.size(); i++)
	{ // compute $Z = \sum_{i=1}^n t_{\pi(i)} R_i
		mpz_mul(foo, t[pi[i]], R[i]);
		mpz_mod(foo, foo, q);
		mpz_add(Z, Z, foo);
		mpz_mod(Z, Z, q);
	}
	mpz_add(Z, Z, R_d); // and add $R_d$
	mpz_mod(Z, Z, q);
	
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;
	out << Z << std::endl;
	
	// prover: fourth move
	edcf->Flip_twoparty(0, lambda, in, out, err); // flip coins with verifier to get $\lambda$
	// reduce such that $\lambda$ is from $\{0, 1\}^{\ell_e}$
	mpz_tdiv_r_2exp(lambda, lambda, l_e);
	
	// prover: fifth to seventh move (Shuffle of Known Content)
		// $\rho := \lambda r + r_d \bmod q$
		mpz_mul(rho, lambda, r);
		mpz_mod(rho, rho, com->q);
		mpz_add(rho, rho, r_d);
		mpz_mod(rho, rho, com->q);
/* This part is not necessary: see personal communication with Jens Groth or the journal version of the paper, because
   $c^{\lambda} c_d \mathrm{com}_{ck}(f_1,\ldots,f_n;0) = \mathrm{com}_{ck}(\lambda\pi(1)+t_i,\ldots,\lambda\pi(n)+t_{\pi(n)})$
		// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
		mpz_set_ui(bar, 0L);
		com->CommitBy(foo, bar, f, false);
		mpz_mul(foo, foo, c_d);
		mpz_mod(foo, foo, com->p);
		mpz_powm(bar, c, lambda, com->p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, com->p);
*/
		// SKC messages $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_set_ui(m[i], i + 1L); // adjust shifted index
			mpz_mul(m[i], m[i], lambda);
			mpz_mod(m[i], m[i], com->q);
			mpz_add(m[i], m[i], t[i]);
			mpz_mod(m[i], m[i], com->q);
		}
	skc->Prove_interactive_publiccoin(pi, rho, m, edcf, in, out);
	
	// release
	mpz_clear(r), mpz_clear(R_d), mpz_clear(r_d), mpz_clear(c), mpz_clear(c_d),
		mpz_clear(Z), mpz_clear(lambda), mpz_clear(rho), mpz_clear(foo),
		mpz_clear(bar);
	mpz_clear(E_d.first), mpz_clear(E_d.second);
	delete [] E_d.first, delete [] E_d.second;
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_clear(d[i]), mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
		delete [] d[i], delete [] f[i], delete [] m[i], delete [] t[i];
	}
	d.clear(), f.clear(), m.clear(), t.clear();
}

void GrothVSSHE::Prove_noninteractive
	(const std::vector<size_t>& pi, const std::vector<mpz_ptr>& R,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	std::ostream& out) const
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
	tmcg_mpz_srandomm(r, com->q);	// $r \gets \mathbb{Z}_q$
	tmcg_mpz_srandomm(R_d, q);		// $R_d \gets \mathcal{R}_{pk}
	for (size_t i = 0; i < d.size(); i++)
	{
		// see note in [Gr05] for omitting $\ell_s$ here
		tmcg_mpz_srandomm(d[i], com->q);
		// store $d_i$ as negative value for convenience
		mpz_neg(d[i], d[i]);
	}
	tmcg_mpz_srandomm(r_d, com->q);	// $r_d \gets \mathbb{Z}_q$
	for (size_t i = 0; i < m.size(); i++)
		mpz_set_ui(m[i], pi[i] + 1L); // adjust shifted index
	com->CommitBy(c, r, m);
	com->CommitBy(c_d, r_d, d);
	mpz_set_ui(E_d.first, 1L), mpz_set_ui(E_d.second, 1L);
	for (size_t i = 0; i < d.size(); i++)
	{
		// Compute and multiply $E_i^{-d_i}$
		tmcg_mpz_spowm(foo, E[i].first, d[i], p);
		mpz_mul(E_d.first, E_d.first, foo);
		mpz_mod(E_d.first, E_d.first, p);
		tmcg_mpz_spowm(bar, E[i].second, d[i], p);
		mpz_mul(E_d.second, E_d.second, bar);
		mpz_mod(E_d.second, E_d.second, p);
	}
	// Compute and multiply $E(1;R_d)$
	tmcg_mpz_fspowm(fpowm_table_g, foo, g, R_d, p);
	mpz_mul(E_d.first, E_d.first, foo);
	mpz_mod(E_d.first, E_d.first, p);
	tmcg_mpz_fspowm(fpowm_table_h, bar, h, R_d, p);
	mpz_mul(E_d.second, E_d.second, bar);
	mpz_mod(E_d.second, E_d.second, p);
	
	out << c << std::endl << c_d << std::endl << E_d.first << std::endl << 
		E_d.second << std::endl;
	
	// prover: second move
	for (size_t i = 0; i < t.size(); i++)
	{
		mpz_set_ui(bar, i);
		mpz_set_ui(foo, l_e_nizk);
		if (i > 0)
			mpz_set(foo, t[i-1]); // make a link to previous element
		// get $t_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2pairvec(t[i], e, E, 14, p, q, g, h, com->p, com->q,
			com->g[i], com->h, c, c_d, E_d.first, E_d.second, foo, bar);
		// reduce such that $t_i$'s are from $\{0, 1\}^{\ell_e}$
		// note that we follow the advice of section 2.5 [Gr05] by increasing the
		// value of $\ell_e$ for the non-interactive protocol version
		mpz_tdiv_r_2exp(t[i], t[i], l_e_nizk);
	}
	
	// prover: third move
	for (size_t i = 0; i < f.size(); i++)
	{ // compute $f_i = t_{\pi(i)} + d_i$
		mpz_neg(f[i], d[i]);	// turn $d_i$ into positive values 
		mpz_add(f[i], f[i], t[pi[i]]);
		mpz_mod(f[i], f[i], com->q);
	}
	mpz_set_ui(Z, 0L);
	for (size_t i = 0; i < t.size(); i++)
	{ // compute $Z = \sum_{i=1}^n t_{\pi(i)} R_i
		mpz_mul(foo, t[pi[i]], R[i]);
		mpz_mod(foo, foo, q);
		mpz_add(Z, Z, foo);
		mpz_mod(Z, Z, q);
	}
	mpz_add(Z, Z, R_d); // and add $R_d$
	mpz_mod(Z, Z, q);
	
	for (size_t i = 0; i < f.size(); i++)
		out << f[i] << std::endl;
	out << Z << std::endl;
	
	// prover: fourth move
		// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
		tmcg_mpz_shash_2pairvec2vec(lambda, e, E, t, f, 5, g, h, com->q, q, Z);
		// reduce such that $\lambda$ is from $\{0, 1\}^{\ell_e}$
		// note that we follow the advice of section 2.5 [Gr05] by increasing the
		// value of $\ell_e$ for the non-interactive protocol version
		mpz_tdiv_r_2exp(lambda, lambda, l_e_nizk);
	
	// prover: fifth to seventh move (Shuffle of Known Content)
		// $\rho := \lambda r + r_d \bmod q$
		mpz_mul(rho, lambda, r);
		mpz_mod(rho, rho, com->q);
		mpz_add(rho, rho, r_d);
		mpz_mod(rho, rho, com->q);
/* This part is not necessary: see personal communication with Jens Groth or the journal version of the paper, because
   $c^{\lambda} c_d \mathrm{com}_{ck}(f_1,\ldots,f_n;0) = \mathrm{com}_{ck}(\lambda\pi(1)+t_i,\ldots,\lambda\pi(n)+t_{\pi(n)})$
		// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
		mpz_set_ui(bar, 0L);
		com->CommitBy(foo, bar, f, false);
		mpz_mul(foo, foo, c_d);
		mpz_mod(foo, foo, com->p);
		mpz_powm(bar, c, lambda, com->p);
		mpz_mul(foo, foo, bar);
		mpz_mod(foo, foo, com->p);
*/
		// SKC messages $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
		for (size_t i = 0; i < m.size(); i++)
		{
			mpz_set_ui(m[i], i + 1L); // adjust shifted index
			mpz_mul(m[i], m[i], lambda);
			mpz_mod(m[i], m[i], com->q);
			mpz_add(m[i], m[i], t[i]);
			mpz_mod(m[i], m[i], com->q);
		}
	skc->Prove_noninteractive(pi, rho, m, out);
	
	// release
	mpz_clear(r), mpz_clear(R_d), mpz_clear(r_d), mpz_clear(c), mpz_clear(c_d),
		mpz_clear(Z), mpz_clear(lambda), mpz_clear(rho), mpz_clear(foo),
		mpz_clear(bar);
	mpz_clear(E_d.first), mpz_clear(E_d.second);
	delete [] E_d.first, delete [] E_d.second;
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_clear(d[i]), mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
		delete [] d[i], delete [] f[i], delete [] m[i], delete [] t[i];
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
		if (!in.good())
			throw false;
		
		// verifier: second move
		for (size_t i = 0; i < t.size(); i++)
		{
			tmcg_mpz_srandomb(t[i], l_e);
			out << t[i] << std::endl;
		}
		
		// verifier: third move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> Z;
		if (!in.good())
			throw false;
		
		// verifier: fourth move
		tmcg_mpz_srandomb(lambda, l_e);
		out << lambda << std::endl;
		
		// verifier: fifth to seventh move (Shuffle of Known Content)
		// check whether $c, c_d \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c) && com->TestMembership(c_d)))
			throw false;
	
		// check whether $E_d\in\mathcal{C}_{pk}$
		mpz_powm(foo, E_d.first, q, p);
		mpz_powm(bar, E_d.second, q, p);
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

/* This part is not necessary: see personal communication with Jens Groth and the notes above
			// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
			mpz_set_ui(bar, 0L);
			com->CommitBy(foo, bar, f, false);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(bar, c, lambda, com->p);
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);*/

			// SKC (optimized homomorphic) commitment $c^{\lambda} c_d \bmod p$
			mpz_powm(foo, c, lambda, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			// SKC messages
			// $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
			for (size_t i = 0; i < m.size(); i++)
			{
				mpz_set_ui(m[i], i + 1L); // adjust shifted index
				mpz_mul(m[i], m[i], lambda);
				mpz_mod(m[i], m[i], com->q);
				mpz_add(m[i], m[i], t[i]);
				mpz_mod(m[i], m[i], com->q);
			}
		
		// perform and verify SKC
		if (!skc->Verify_interactive(foo, f, m, in, out))
			throw false;
		
		// check whether
		// $\prod_{i=1}^n e_i^{-t_i} \prod_{i=1}^n E_i^{f_i} E_d = E(1;Z)$
		mpz_set_ui(foo2, 1L), mpz_set_ui(bar2, 1L);
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_powm(foo, e[i].first, t[i], p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, p);
			mpz_powm(bar, e[i].second, t[i], p);
			if (!mpz_invert(bar, bar, p))
				throw false;
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
		mpz_mul(foo3, foo3, foo2); // LHS, first component
		mpz_mod(foo3, foo3, p);
		mpz_mul(bar3, bar3, bar2); // LHS, second component
		mpz_mod(bar3, bar3, p);
		tmcg_mpz_fpowm(fpowm_table_g, foo, g, Z, p); // RHS, first component
		tmcg_mpz_fpowm(fpowm_table_h, bar, h, Z, p); // RHS, second component
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
		delete [] E_d.first, delete [] E_d.second;
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
			delete [] f[i], delete [] m[i], delete [] t[i];
		}
		f.clear(), m.clear(), t.clear();
		// return
		return return_value;
	}
}

bool GrothVSSHE::Verify_interactive_publiccoin
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	JareckiLysyanskayaEDCF *edcf,
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
		if (!in.good())
			throw false;
		
		// verifier: second move
		std::stringstream err;
		for (size_t i = 0; i < t.size(); i++)
		{
			if (!edcf->Flip_twoparty(1, t[i], in, out, err)) // flip coins with prover to get $t_i$
				throw false;
			// reduce such that $t_i$'s are from $\{0, 1\}^{\ell_e}$
			mpz_tdiv_r_2exp(t[i], t[i], l_e);
		}
		
		// verifier: third move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> Z;
		if (!in.good())
			throw false;
		
		// verifier: fourth move
		if (!edcf->Flip_twoparty(1, lambda, in, out, err)) // flip coins with prover to get $\lambda$
			throw false;
		// reduce such that $\lambda$ is from $\{0, 1\}^{\ell_e}$
		mpz_tdiv_r_2exp(lambda, lambda, l_e);
		
		// verifier: fifth to seventh move (Shuffle of Known Content)
		// check whether $c, c_d \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c) && com->TestMembership(c_d)))
			throw false;
	
		// check whether $E_d\in\mathcal{C}_{pk}$
		mpz_powm(foo, E_d.first, q, p);
		mpz_powm(bar, E_d.second, q, p);
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

/* This part is not necessary: see personal communication with Jens Groth and the notes above
			// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
			mpz_set_ui(bar, 0L);
			com->CommitBy(foo, bar, f, false);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(bar, c, lambda, com->p);
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);*/

			// SKC (optimized homomorphic) commitment $c^{\lambda} c_d \bmod p$
			mpz_powm(foo, c, lambda, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			// SKC messages
			// $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
			for (size_t i = 0; i < m.size(); i++)
			{
				mpz_set_ui(m[i], i + 1L); // adjust shifted index
				mpz_mul(m[i], m[i], lambda);
				mpz_mod(m[i], m[i], com->q);
				mpz_add(m[i], m[i], t[i]);
				mpz_mod(m[i], m[i], com->q);
			}
		
		// perform and verify SKC
		if (!skc->Verify_interactive_publiccoin(foo, f, m, edcf, in, out))
			throw false;
		
		// check whether
		// $\prod_{i=1}^n e_i^{-t_i} \prod_{i=1}^n E_i^{f_i} E_d = E(1;Z)$
		mpz_set_ui(foo2, 1L), mpz_set_ui(bar2, 1L);
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_powm(foo, e[i].first, t[i], p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, p);
			mpz_powm(bar, e[i].second, t[i], p);
			if (!mpz_invert(bar, bar, p))
				throw false;
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
		mpz_mul(foo3, foo3, foo2); // LHS, first component
		mpz_mod(foo3, foo3, p);
		mpz_mul(bar3, bar3, bar2); // LHS, second component
		mpz_mod(bar3, bar3, p);
		tmcg_mpz_fpowm(fpowm_table_g, foo, g, Z, p); // RHS, first component
		tmcg_mpz_fpowm(fpowm_table_h, bar, h, Z, p); // RHS, second component
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
		delete [] E_d.first, delete [] E_d.second;
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
			delete [] f[i], delete [] m[i], delete [] t[i];
		}
		f.clear(), m.clear(), t.clear();
		// return
		return return_value;
	}
}

bool GrothVSSHE::Verify_noninteractive
	(const std::vector<std::pair<mpz_ptr, mpz_ptr> >& e,
	const std::vector<std::pair<mpz_ptr, mpz_ptr> >& E,
	std::istream& in) const
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
		if (!in.good())
			throw false;
		
		// verifier: second move
		for (size_t i = 0; i < t.size(); i++)
		{
			mpz_set_ui(bar, i);
			mpz_set_ui(foo, l_e_nizk);
			if (i > 0)
				mpz_set(foo, t[i-1]);
			// get $t_i$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2pairvec(t[i], e, E, 14, p, q, g, h, com->p, com->q,
				com->g[i], com->h, c, c_d, E_d.first, E_d.second, foo, bar);
			// reduce such that $t_i$'s are from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(t[i], t[i], l_e_nizk);
		}
		
		// verifier: third move
		for (size_t i = 0; i < f.size(); i++)
			in >> f[i];
		in >> Z;
		if (!in.good())
			throw false;
		
		// verifier: fourth move
			// get $\lambda$ from the 'random oracle', i.e. Fiat-Shamir heuristic
			tmcg_mpz_shash_2pairvec2vec(lambda, e, E, t, f, 5, g, h, com->q, q, Z);
			// reduce such that $\lambda$ is from $\{0, 1\}^{\ell_e}$
			// note that we follow the advice of section 2.5 [Gr05] by increasing the
			// value of $\ell_e$ for the non-interactive protocol version
			mpz_tdiv_r_2exp(lambda, lambda, l_e_nizk);
		
		// verifier: fifth to seventh move (Shuffle of Known Content)
		// check whether $c, c_d \in\mathcal{C}_{ck}$
		if (!(com->TestMembership(c) && com->TestMembership(c_d)))
			throw false;
	
		// check whether $E_d\in\mathcal{C}_{pk}$
		mpz_powm(foo, E_d.first, q, p);
		mpz_powm(bar, E_d.second, q, p);
		if (mpz_cmp_ui(foo, 1L) || mpz_cmp_ui(bar, 1L))
			throw false;
	
		// check whether $2^{\ell_e} \le f_1,\ldots,f_n < q$
		for (size_t i = 0; i < f.size(); i++)
		{
			if ((mpz_sizeinbase(f[i], 2L) < l_e_nizk) || 
				(mpz_cmp(f[i], com->q) >= 0))
					throw false;
		}
	
		// check whether $Z\in\mathcal{R}_{pk}$
		if ((mpz_cmp_ui(Z, 0L) <= 0) || (mpz_cmp(Z, q) >= 0))
			throw false;

/* This part is not necessary: see personal communication with Jens Groth and the notes above
			// SKC commitment $c^{\lambda} c_d \mathrm{com}(f_1,\ldots,f_n;0) \bmod p$
			mpz_set_ui(bar, 0L);
			com->CommitBy(foo, bar, f, false);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			mpz_powm(bar, c, lambda, com->p);
			mpz_mul(foo, foo, bar);
			mpz_mod(foo, foo, com->p);*/

			// SKC (optimized homomorphic) commitment $c^{\lambda} c_d \bmod p$
			mpz_powm(foo, c, lambda, com->p);
			mpz_mul(foo, foo, c_d);
			mpz_mod(foo, foo, com->p);
			// SKC messages
			// $m_i := i \lambda + t_i \bmod q$, for all $i = 1,\ldots, n$
			for (size_t i = 0; i < m.size(); i++)
			{
				mpz_set_ui(m[i], i + 1L); // adjust shifted index
				mpz_mul(m[i], m[i], lambda);
				mpz_mod(m[i], m[i], com->q);
				mpz_add(m[i], m[i], t[i]);
				mpz_mod(m[i], m[i], com->q);
			}
		
		// perform and verify SKC
		if (!skc->Verify_noninteractive(foo, f, m, in))
			throw false;
		
		// check whether
		// $\prod_{i=1}^n e_i^{-t_i} \prod_{i=1}^n E_i^{f_i} E_d = E(1;Z)$
		mpz_set_ui(foo2, 1L), mpz_set_ui(bar2, 1L);
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_powm(foo, e[i].first, t[i], p);
			if (!mpz_invert(foo, foo, p))
				throw false;
			mpz_mul(foo2, foo2, foo);
			mpz_mod(foo2, foo2, p);
			mpz_powm(bar, e[i].second, t[i], p);
			if (!mpz_invert(bar, bar, p))
				throw false;
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
		mpz_mul(foo3, foo3, foo2); // LHS, first component
		mpz_mod(foo3, foo3, p);
		mpz_mul(bar3, bar3, bar2); // LHS, second component
		mpz_mod(bar3, bar3, p);
		tmcg_mpz_fpowm(fpowm_table_g, foo, g, Z, p); // RHS, first component
		tmcg_mpz_fpowm(fpowm_table_h, bar, h, Z, p); // RHS, second component
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
		delete [] E_d.first, delete [] E_d.second;
		for (size_t i = 0; i < e.size(); i++)
		{
			mpz_clear(f[i]), mpz_clear(m[i]), mpz_clear(t[i]);
			delete [] f[i], delete [] m[i], delete [] t[i];
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
	
	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
