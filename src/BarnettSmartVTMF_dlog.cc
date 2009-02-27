/*******************************************************************************
   BarnettSmartVTMF_dlog.cc, Verifiable k-out-of-k Threshold Masking Function

     Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
              Statements about Discrete Logarithms', Technical Report, 1997

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007, 2009  Heiko Stamer <stamer@gaos.org>

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

#include "BarnettSmartVTMF_dlog.hh"

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(unsigned long int fieldsize, unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	mpz_t foo;
	
	// Create a finite abelian group $G$ where the DDH problem is hard:
	// We use the unique subgroup of prime order $q$ where $p = kq + 1$.
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
	if (subgroupsize)
		mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
	// Initialize all members of the key.
	mpz_init(x_i), mpz_init(h_i), mpz_init_set_ui(h, 1L), mpz_init(d);
	mpz_init(h_i_fp);
	
	// Choose randomly a generator $g$ of the unique subgroup of order $q$.
	if (subgroupsize)
	{
		mpz_init(foo);
		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		do
		{
			mpz_wrandomm(d, p);
			mpz_powm(g, d, k, p); // compute $g := d^k \bmod p$
		}
		while ((!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
			!mpz_cmp(g, foo))); // check, whether $1 < g < p-1$
		mpz_clear(foo);
	}
	
	// Initialize the tables for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	if (subgroupsize)
		mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(std::istream& in, unsigned long int fieldsize,
	unsigned long int subgroupsize):
		F_size(fieldsize), G_size(subgroupsize)
{
	// Initialize the members for the finite abelian group $G$.
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
	in >> p >> q >> g >> k;
	
	// Initialize all members for the key.
	mpz_init(x_i), mpz_init(h_i), mpz_init_set_ui(h, 1L), mpz_init(d);
	mpz_init(h_i_fp);
	
	// Initialize the tables for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	if (subgroupsize)
		mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

bool BarnettSmartVTMF_dlog::CheckGroup
	() const
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init_set_ui(bar, 1L);
	try
	{
		// Check whether $p$ and $q$ have appropriate sizes.
		if ((mpz_sizeinbase(p, 2L) < F_size) || 
			(mpz_sizeinbase(q, 2L) < G_size))
				throw false;
		
		// Check whether $p$ has the correct form, i.e. $p = qk + 1$.
		mpz_mul(foo, q, k);
		mpz_add_ui(foo, foo, 1L);
		if (mpz_cmp(foo, p))
			throw false;
		
		// Check whether $p$ and $q$ are both (probable) prime with
		// a soundness error probability ${} \le 4^{-TMCG_MR_ITERATIONS}$.
		if (!mpz_probab_prime_p(p, TMCG_MR_ITERATIONS) || 
			!mpz_probab_prime_p(q, TMCG_MR_ITERATIONS))
				throw false;
		
		// Check whether $k$ is not divisible by $q$, i.e. $q$ and $k$ are
		// coprime.
		mpz_gcd(foo, q, k);
		if (mpz_cmp_ui(foo, 1L))
			throw false;
		
		// Check whether $g$ is a generator for the subgroup $G$ of prime
		// order $q$. We have to assert that $g^q \equiv 1 \pmod{p}$,
		// which means that the order of $g$ is $q$. Of course, we must
		// ensure that $g$ is not trivial, i.e., $1 < g < p-1$.
		mpz_sub_ui(bar, p, 1L);
		mpz_fpowm(fpowm_table_g, foo, g, q, p);
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, bar) >= 0) || 
			mpz_cmp_ui(foo, 1L))
				throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::PublishGroup
	(std::ostream& out) const
{
	out << p << std::endl << q << std::endl << g << std::endl << k << std::endl;
}

bool BarnettSmartVTMF_dlog::CheckElement
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

void BarnettSmartVTMF_dlog::RandomElement
	(mpz_ptr a) const
{
	mpz_t b;
	
	// Choose randomly and uniformly an element $b$ from
	// $\mathbb{Z}_q \setminus \{ 0 \}$.
	mpz_init(b);
	do
		mpz_srandomm(b, q);
	while (!mpz_cmp_ui(b, 0L));
	
	// Compute $a := g^b \bmod p$.
	mpz_fspowm(fpowm_table_g, a, g, b, p);
	mpz_clear(b);
}

void BarnettSmartVTMF_dlog::IndexElement
	(mpz_ptr a, std::size_t index) const
{
	// Simply compute $a := g^i \bmod p$.
	mpz_fpowm_ui(fpowm_table_g, a, g, index, p);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_GenerateKey
	()
{
	// generate the private key $x_i \in \mathbb{Z}_q$ randomly
	mpz_srandomm(x_i, q);
	
	// compute $h_i = g^{x_i} \bmod p$ (with timing attack protection)
	mpz_fspowm(fpowm_table_g, h_i, g, x_i, p);
	
	// compute the fingerprint of the public key
	mpz_shash(h_i_fp, 1, h_i);
	
	// set the initial value of the global key $h$
	mpz_set(h, h_i);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_PublishKey
	(std::ostream& out) const
{
	mpz_t v, t, c, r;
	
	// proof of knowledge [CaS97] for the public key
	mpz_init(v), mpz_init(t), mpz_init(c), mpz_init(r);
		
		// commitment
		mpz_srandomm(v, q);
		mpz_fspowm(fpowm_table_g, t, g, v, p);
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof of
		// knowledge (SPK) in the random oracle model.
		mpz_shash(c, 3, g, h_i, t);
		// response
		mpz_mul(r, c, x_i);
		mpz_neg(r, r);
		mpz_add(r, r, v);
		mpz_mod(r, r, q);
		
	out << h_i << std::endl << c << std::endl << r << std::endl;
	mpz_clear(v), mpz_clear(t), mpz_clear(c), mpz_clear(r);
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_UpdateKey
	(std::istream& in)
{
	mpz_t foo, t, c, r;
	
	mpz_init(foo), mpz_init(t), mpz_init(c), mpz_init(r);
	in >> foo >> c >> r;
	
	try
	{
		// verify the in-group property
		if (!CheckElement(foo))
			throw false;
		
		// check the size of $r$
		if (mpz_cmpabs(r, q) >= 0)
			throw false;
		
		// verify the proof of knowledge [CaS97]
		mpz_fpowm(fpowm_table_g, t, g, r, p);
		mpz_powm(r, foo, c, p);
		mpz_mul(t, t, r);
		mpz_mod(t, t, p);
		mpz_shash(r, 3, g, foo, t);
		if (mpz_cmp(c, r))
			throw false;
		
		// update the global key h
		mpz_mul(h, h, foo);
		mpz_mod(h, h, p);
		
		// store the public key
		mpz_ptr tmp = new mpz_t();
		std::ostringstream fp;
		mpz_init_set(tmp, foo);
		mpz_shash(t, 1, foo);
		fp << t;
		h_j[fp.str()] = tmp;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(t), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_RemoveKey
	(std::istream& in)
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init(bar);
	in >> foo >> bar >> bar;
	
	try
	{
		std::ostringstream fp;
		
		// compute the fingerprint
		mpz_shash(bar, 1, foo);
		fp << bar;
		
		// public key with this fingerprint stored?
		if (h_j.find(fp.str()) != h_j.end())
		{
			// update the global key
			if (!mpz_invert(foo, h_j[fp.str()], p))
				throw false;
			mpz_invert(foo, h_j[fp.str()], p);
			mpz_mul(h, h, foo);
			mpz_mod(h, h, p);
			
			// release the public key
			mpz_clear(h_j[fp.str()]);
			h_j.erase(fp.str());
			
			// finish
			throw true;
		}
		else
			throw false;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_Finalize
	()
{
	// Precompute the values $h^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

void BarnettSmartVTMF_dlog::CP_Prove
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, mpz_srcptr alpha,
	std::ostream& out, bool fpowm_usage) const
{
	mpz_t a, b, omega, c, r;
	
	// proof of knowledge (equality of discrete logarithms) [CaS97]
	mpz_init(c), mpz_init(r), mpz_init(a), mpz_init(b), mpz_init(omega);
		
		// commitment
		mpz_srandomm(omega, q);
		if (fpowm_usage)
		{
			assert(!mpz_cmp(g, gg) && !mpz_cmp(h, hh));
			mpz_fspowm(fpowm_table_g, a, gg, omega, p);
			mpz_fspowm(fpowm_table_h, b, hh, omega, p);
		}
		else
		{
			mpz_spowm(a, gg, omega, p);
			mpz_spowm(b, hh, omega, p);
		}
		
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof of
		// knowledge (SPK) in the random oracle model.
		mpz_shash(c, 6, a, b, x, y, gg, hh);
		
		// response
		mpz_mul(r, c, alpha);
		mpz_neg(r, r);
		mpz_add(r, r, omega);
		mpz_mod(r, r, q);
		
	out << c << std::endl << r << std::endl;
	mpz_clear(c), mpz_clear(r), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
}

bool BarnettSmartVTMF_dlog::CP_Verify
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
	std::istream& in, bool fpowm_usage) const
{
	mpz_t a, b, c, r;
	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r);
	in >> c >> r;
	
	try
	{
		// check the size of $r$
		if (mpz_cmpabs(r, q) >= 0)
			throw false;
		
		// verify proof of knowledge (equality of discrete logarithms) [CaS97]
		if (fpowm_usage)
		{
			if (!mpz_cmp(g, gg))
				throw false;
			mpz_fpowm(fpowm_table_g, a, gg, r, p);
		}
		else
			mpz_powm(a, gg, r, p);
		mpz_powm(b, x, c, p);
		mpz_mul(a, a, b);
		mpz_mod(a, a, p);
		if (fpowm_usage)
		{
			if (!mpz_cmp(h, hh))
				throw false;
			mpz_fpowm(fpowm_table_h, b, hh, r, p);
		}
		else
			mpz_powm(b, hh, r, p);
		mpz_powm(r, y, c, p);
		mpz_mul(b, b, r);
		mpz_mod(b, b, p);
		mpz_shash(r, 6, a, b, x, y, gg, hh);
		if (mpz_cmp(r, c))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::OR_ProveFirst
	(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
		mpz_srcptr alpha, std::ostream& out) const
{
	mpz_t v_1, v_2, w, t_1, t_2, c_1, c_2, r_1, r_2, c, tmp;
	
	// proof of knowledge ($y_1 = g_1^\alpha \vee y_2 = g_2^\beta$) [CaS97]
	mpz_init(v_1), mpz_init(v_2), mpz_init(w), mpz_init(t_1), mpz_init(t_2);
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(c), mpz_init(tmp);
	
		// 1. choose $v_1, v_2$ and $w\in_R\mathbb{Z}_q$ and compute
		//    $t_2 = y_2^w g_2^{v_2}$ and $t_1 = g_1^{v_1}$ 
		mpz_srandomm(v_1, q), mpz_srandomm(v_2, q), mpz_srandomm(w, q);
		mpz_spowm(t_2, y_2, w, p);
		mpz_spowm(tmp, g_2, v_2, p);
		mpz_mul(t_2, t_2, tmp), mpz_mod(t_2, t_2, p);
		mpz_spowm(t_1, g_1, v_1, p);
		
		// 2. compute $c = \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		mpz_shash(c, 6, g_1, y_1, g_2, y_2, t_1, t_2), mpz_mod(c, c, q);
		
		// 3. split the challenge: $c_2 = w$ and $c_1 = c - c_2$
		mpz_set(c_2, w);
		mpz_sub(c_1, c, c_2), mpz_mod(c_1, c_1, q);
		
		// 4. forge $r_2 = v_2$ and set $r_1 = v_1 - c_1\alpha$
		mpz_set(r_2, v_2), mpz_mod(r_2, r_2, q);
		mpz_mul(tmp, c_1, alpha), mpz_mod(tmp, tmp, q);
		mpz_sub(r_1, v_1, tmp), mpz_mod(r_1, r_1, q);
		
	out << c_1 << std::endl << c_2 << std::endl <<
		r_1 << std::endl << r_2 << std::endl;
	mpz_clear(v_1), mpz_clear(v_2), mpz_clear(w), mpz_clear(t_1), mpz_clear(t_2);
	mpz_clear(c_1), mpz_clear(c_2), mpz_clear(r_1), mpz_clear(r_2);
	mpz_clear(c), mpz_clear(tmp);
}

void BarnettSmartVTMF_dlog::OR_ProveSecond
	(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
		mpz_srcptr alpha, std::ostream& out) const
{
	mpz_t v_1, v_2, w, t_1, t_2, c_1, c_2, r_1, r_2, c, tmp;
	
	// proof of knowledge ($y_1 = g_1^\beta \vee y_2 = g_2^\alpha$) [CaS97]
	mpz_init(v_1), mpz_init(v_2), mpz_init(w), mpz_init(t_1), mpz_init(t_2);
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(c), mpz_init(tmp);
	
		// 1. choose $v_1, v_2$ and $w\in_R\mathbb{Z}_q$ and compute
		//    $t_1 = y_1^w g_1^{v_1}$ and $t_2 = g_2^{v_2}$
		mpz_srandomm(v_1, q), mpz_srandomm(v_2, q), mpz_srandomm(w, q);
		mpz_spowm(t_1, y_1, w, p);
		mpz_spowm(tmp, g_1, v_1, p);
		mpz_mul(t_1, t_1, tmp), mpz_mod(t_1, t_1, p);
		mpz_spowm(t_2, g_2, v_2, p);
		
		// 2. compute $c = \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		mpz_shash(c, 6, g_1, y_1, g_2, y_2, t_1, t_2), mpz_mod(c, c, q);
		
		// 3. split the challenge: $c_1 = w$ and $c_2 = c - c_1$
		mpz_set(c_1, w);
		mpz_sub(c_2, c, c_1), mpz_mod(c_2, c_2, q);
		
		// 4. forge $r_1 = v_1$ and set $r_2 = v_2 - c_2\alpha$
		mpz_set(r_1, v_1), mpz_mod(r_1, r_1, q);
		mpz_mul(tmp, c_2, alpha), mpz_mod(tmp, tmp, q);
		mpz_sub(r_2, v_2, tmp), mpz_mod(r_2, r_2, q);
		
	out << c_1 << std::endl << c_2 << std::endl <<
		r_1 << std::endl << r_2 << std::endl;
	mpz_clear(v_1), mpz_clear(v_2), mpz_clear(w), mpz_clear(t_1), mpz_clear(t_2);
	mpz_clear(c_1), mpz_clear(c_2), mpz_clear(r_1), mpz_clear(r_2);
	mpz_clear(c), mpz_clear(tmp);
}

bool BarnettSmartVTMF_dlog::OR_Verify
	(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
		std::istream& in) const
{
	mpz_t c_1, c_2, r_1, r_2, t_1, t_2, c, tmp;
	
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(t_1), mpz_init(t_2), mpz_init(c), mpz_init(tmp);
	in >> c_1 >> c_2 >> r_1 >> r_2;
	
	try
	{
		// check the size of $r_1$ and $r_2$
		if ((mpz_cmpabs(r_1, q) >= 0L) || (mpz_cmpabs(r_2, q) >= 0L))
			throw false;
		
		// verify (S)PK ($y_1 = g_1^\alpha \vee y_2 = g_2^\beta$) [CaS97]
		mpz_powm(t_1, y_1, c_1, p);
		mpz_powm(tmp, g_1, r_1, p);
		mpz_mul(t_1, t_1, tmp), mpz_mod(t_1, t_1, p);
		
		mpz_powm(t_2, y_2, c_2, p);
		mpz_powm(tmp, g_2, r_2, p);
		mpz_mul(t_2, t_2, tmp), mpz_mod(t_2, t_2, p);
		
		// check the equation
		// $c_1 + c_2 \stackrel{?}{=} \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		mpz_add(tmp, c_1, c_2), mpz_mod(c, c, q);
		mpz_shash(c, 6, g_1, y_1, g_2, y_2, t_1, t_2), mpz_mod(c, c, q);
		if (mpz_cmp(tmp, c))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(c_1), mpz_clear(c_2), mpz_clear(r_1), mpz_clear(r_2);
		mpz_clear(t_1), mpz_clear(t_2), mpz_clear(c), mpz_clear(tmp);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::MaskingValue
	(mpz_ptr r) const
{
	// Choose randomly and uniformly an element from
	// $\mathbb{Z}_q \setminus \{0, 1\}$.
	do
		mpz_srandomm(r, q);
	while (!mpz_cmp_ui(r, 0L) || !mpz_cmp_ui(r, 1L));
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Mask
	(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r) const
{
	MaskingValue(r);
	
	// compute $c_1 = g^r \bmod p$
	mpz_fspowm(fpowm_table_g, c_1, g, r, p);
	
	// compute $c_2 = m \cdot h^r \bmod p$
	mpz_fspowm(fpowm_table_h, c_2, h, r, p);
	mpz_mul(c_2, c_2, m);
	mpz_mod(c_2, c_2, p);
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Prove
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r,
	std::ostream& out) const
{
	mpz_t foo;
	
	// invoke CP(c_1, c_2/m, g, h; r) as prover
	mpz_init(foo);
	assert(mpz_invert(foo, m, p));
	mpz_invert(foo, m, p);
	mpz_mul(foo, foo, c_2);
	mpz_mod(foo, foo, p);
	CP_Prove(c_1, foo, g, h, r, out, true);
	mpz_clear(foo);
}

bool BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Verify
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, std::istream& in) const
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init_set_ui(bar, 1L);
	try
	{
		// verify the in-group properties
		if (!CheckElement(c_1) || !CheckElement(c_2))
			throw false;
		
		// invoke CP(c_1, c_2/m, g, h; r) as verifier
		if (!mpz_invert(foo, m, p))
			throw false;
		mpz_mul(foo, foo, c_2);
		mpz_mod(foo, foo, p);
		if (!CP_Verify(c_1, foo, g, h, in, true))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Mask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, mpz_ptr r) const
{
	MaskingValue(r);
	
	// compute $c'_1 = c_1 \cdot g^r \bmod p$
	mpz_fspowm(fpowm_table_g, c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute $c'_2 = c_2 \cdot h^r \bmod p$
	mpz_fspowm(fpowm_table_h, c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Remask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2,
	mpz_srcptr r, bool TimingAttackProtection) const
{
	// compute $c'_1 = c_1 \cdot g^r \bmod p$
	if (TimingAttackProtection)
		mpz_fspowm(fpowm_table_g, c__1, g, r, p);
	else
		mpz_fpowm(fpowm_table_g, c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute $c'_2 = c_2 \cdot h^r \bmod p$
	if (TimingAttackProtection)
		mpz_fspowm(fpowm_table_h, c__2, h, r, p);
	else
		mpz_fpowm(fpowm_table_h, c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Prove
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	mpz_srcptr r, std::ostream& out) const
{
	mpz_t foo, bar;
	
	// invoke CP(c'_1/c_1, c'_2/c_2, g, h; r) as prover
	mpz_init(foo), mpz_init(bar);
	assert(mpz_invert(foo, c_1, p));
	mpz_invert(foo, c_1, p);
	mpz_mul(foo, foo, c__1);
	mpz_mod(foo, foo, p);
	assert(mpz_invert(bar, c_2, p));
	mpz_invert(bar, c_2, p);
	mpz_mul(bar, bar, c__2);
	mpz_mod(bar, bar, p);
	CP_Prove(foo, bar, g, h, r, out, true);
	mpz_clear(foo), mpz_clear(bar);
}

bool BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Verify
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	std::istream& in) const
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init_set_ui(bar, 1L);
	try
	{
		// verify the in-group properties
		if (!CheckElement(c__1) || !CheckElement(c__2))
			throw false;
		
		// invoke CP(c'_1/c_1, c'_2/c_2, g, h; r) as verifier
		if (!mpz_invert(foo, c_1, p))
			throw false;
		mpz_mul(foo, foo, c__1);
		mpz_mod(foo, foo, p);
		if (!mpz_invert(bar, c_2, p))
			throw false;
		mpz_mul(bar, bar, c__2);
		mpz_mod(bar, bar, p);
		if (!CP_Verify(foo, bar, g, h, in, true))
			throw false;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Prove
	(mpz_srcptr c_1, std::ostream& out) const
{
	mpz_t d_i;
	
	mpz_init(d_i);
	
	// compute $d_i = {c_1}^{x_i} \bmod p$
	mpz_spowm(d_i, c_1, x_i, p);
	out << d_i << std::endl << h_i_fp << std::endl;
	
	// invoke CP(d_i, h_i, c_1, g; x_i) as prover
	CP_Prove(d_i, h_i, c_1, g, x_i, out, false);
	
	mpz_clear(d_i);
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Initialize
	(mpz_srcptr c_1)
{
	// compute $d = d_i = {c_1}^{x_i} \bmod p$
	mpz_spowm(d, c_1, x_i, p);
}

bool BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Update
	(mpz_srcptr c_1, std::istream& in)
{
	mpz_t d_j, h_j_fp, foo, bar;
	std::ostringstream fp;
	
	mpz_init(d_j), mpz_init(h_j_fp), mpz_init(foo), mpz_init_set_ui(bar, 1L);
	in >> d_j >> h_j_fp;
	
	try
	{
		// public key stored?
		fp << h_j_fp;
		if (h_j.find(fp.str()) == h_j.end())
			throw false;
		
		// verify the in-group property
		if (!CheckElement(d_j))
			throw false;
		
		// invoke CP(d_j, h_j, c_1, g; x_j) as verifier
		if (!CP_Verify(d_j, h_j[fp.str()], c_1, g, in, false))
			throw false;
		
		// update the value of $d$
		mpz_mul(d, d, d_j);
		mpz_mod(d, d, p);
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(d_j), mpz_clear(h_j_fp), mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Finalize
	(mpz_srcptr c_2, mpz_ptr m) const
{
	assert(mpz_invert(m, d, p));
	
	// finalize the decryption
	mpz_invert(m, d, p);
	mpz_mul(m, m, c_2);
	mpz_mod(m, m, p);
}

BarnettSmartVTMF_dlog::~BarnettSmartVTMF_dlog
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);
	mpz_clear(x_i), mpz_clear(h_i), mpz_clear(h), mpz_clear(d);
	for (std::map<std::string, mpz_ptr>::const_iterator
		j = h_j.begin(); j != h_j.end(); j++)
	{
		mpz_clear(j->second);
		delete j->second;
	}
	h_j.clear();
	
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
