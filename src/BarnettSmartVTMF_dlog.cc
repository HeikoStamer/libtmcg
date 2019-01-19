/*******************************************************************************
   BarnettSmartVTMF_dlog.cc, Verifiable k-out-of-k Threshold Masking Function

     [BS03] Adam Barnett, Nigel P. Smart: 'Mental Poker Revisited',
     Cryptography and Coding 2003, LNCS 2898, pp. 370--383, 2003.

     [CaS97] Jan Camenisch, Markus Stadler: 'Proof Systems for General
       Statements about Discrete Logarithms', Technical Report, 1997.

     [Bo98] Dan Boneh: 'The Decision Diffie-Hellman Problem',
     Proceedings of the 3rd Algorithmic Number Theory Symposium,
     LNCS 1423, pp. 48--63, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007, 2009,
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
#include "BarnettSmartVTMF_dlog.hh"

// additional headers
#include <cstdio>
#include <cassert>
#include <string>
#include <sstream>
#include <vector>
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"
#include "mpz_sprime.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(const unsigned long int fieldsize, const unsigned long int subgroupsize,
	 const bool canonical_g_usage, const bool initialize_group):
		F_size(fieldsize), G_size(subgroupsize), 
		canonical_g(canonical_g_usage)
{
	// Initialize all members of the class
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
	mpz_init(x_i), mpz_init(h_i), mpz_init_set_ui(h, 1L), mpz_init(d);
	mpz_init(h_i_fp);

	// Create a finite abelian group $G$ where the DDH problem is hard:
	// We use the unique subgroup of prime order $q$ where $p = kq + 1$.
	// Sometimes such groups are called Schnorr groups. [Bo98]	
	if (initialize_group)
		tmcg_mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
	// Choose the generator $g$ of the group $G$. 
	if (initialize_group)
	{
		mpz_t foo, bar;
		mpz_init(foo), mpz_init(bar);

		mpz_sub_ui(foo, p, 1L); // compute $p-1$
		if (canonical_g)
		{
			// We use a procedure similar to FIPS 186-3 A.2.3;
			// it is supposed as verifiable generation of $g$.
			std::stringstream U;
			U << "LibTMCG|" << p << "|" << q << "|ggen|";
			do
			{
				tmcg_mpz_shash(bar, U.str());
				mpz_powm(g, bar, k, p); // $g := [bar]^k \bmod p$
				U << g << "|";
				mpz_powm(bar, g, q, p);
				// check $1 < g < p-1$ and $g^q \equiv 1 \pmod{p}$
			}
			while (!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
				!mpz_cmp(g, foo) || mpz_cmp_ui(bar, 1L));
		}
		else
		{
			// Here we randomly create a generator $g$ of the
			// unique subgroup $G$ of order $q$.
			mpz_sub_ui(foo, p, 1L); // compute $p-1$
			do
			{
				tmcg_mpz_wrandomm(bar, p); // choose [bar] randomly
				mpz_powm(g, bar, k, p); // $g := [bar]^k \bmod p$
			}
			while (!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
				!mpz_cmp(g, foo)); // check $1 < g < p-1$
			
		}

		mpz_clear(foo), mpz_clear(bar);
	}
	
	// Initialize the tables for the fast exponentiation.
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	if (initialize_group)
		tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

BarnettSmartVTMF_dlog::BarnettSmartVTMF_dlog
	(std::istream& in, 
	 const unsigned long int fieldsize, const unsigned long int subgroupsize,
	 const bool canonical_g_usage, const bool precompute):
		F_size(fieldsize), G_size(subgroupsize),
		canonical_g(canonical_g_usage)
{
	// Initialize all members of the class
	mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
	mpz_init(x_i), mpz_init(h_i), mpz_init_set_ui(h, 1L), mpz_init(d);
	mpz_init(h_i_fp);

	// Read parameters of group $G$ from input stream
	in >> p >> q >> g >> k;
	
	// Initialize the tables for the fast exponentiation
	fpowm_table_g = new mpz_t[TMCG_MAX_FPOWM_T]();
	fpowm_table_h = new mpz_t[TMCG_MAX_FPOWM_T]();
	tmcg_mpz_fpowm_init(fpowm_table_g), tmcg_mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$
	if (precompute)
		tmcg_mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

bool BarnettSmartVTMF_dlog::CheckGroup
	() const
{
	mpz_t foo, bar, g2;
	mpz_init(foo), mpz_init(bar), mpz_init(g2);

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
		if ((mpz_cmp_ui(g, 1L) <= 0) || (mpz_cmp(g, bar) >= 0))
			throw false;
		mpz_powm(foo, g, q, p);
		if (mpz_cmp_ui(foo, 1L))
			throw false;

		// If we use a canonical value for $g$, further checks are needed.
		if (canonical_g)
		{
			// We use a procedure similar to FIPS 186-3 A.2.3;
			// it is supposed as verifiable generation of $g$.
			std::stringstream U;
			U << "LibTMCG|" << p << "|" << q << "|ggen|";
			do
			{
				tmcg_mpz_shash(foo, U.str());
				mpz_powm(g2, foo, k, p);
				U << g2 << "|";
				mpz_powm(foo, g2, q, p);
				// check $1 < g < p-1$ and $g^q \equiv 1 \pmod{p}$
			}
			while (!mpz_cmp_ui(g2, 0L) || !mpz_cmp_ui(g2, 1L) || 
				!mpz_cmp(g2, bar) || mpz_cmp_ui(foo, 1L));
			// Check that the 1st verifiable $g$ is used.
			if (mpz_cmp(g, g2))
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(g2);
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
	mpz_init(b);
	
	// Choose randomly and uniformly an element $b$ from
	// $\mathbb{Z}_q \setminus \{ 0 \}$.
	do
		tmcg_mpz_srandomm(b, q);
	while (!mpz_cmp_ui(b, 0L));
	
	// Compute $a := g^b \bmod p$.
	tmcg_mpz_fspowm(fpowm_table_g, a, g, b, p);

	mpz_clear(b);
}

void BarnettSmartVTMF_dlog::IndexElement
	(mpz_ptr a, const size_t index) const
{
	// Simply compute $a := g^i \bmod p$.
	tmcg_mpz_fpowm_ui(fpowm_table_g, a, g, index, p);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_GenerateKey
	()
{
	// generate the private key $x_i \in \mathbb{Z}_q$ randomly
	tmcg_mpz_srandomm(x_i, q);
	
	// compute $h_i = g^{x_i} \bmod p$ (with timing attack protection)
	tmcg_mpz_fspowm(fpowm_table_g, h_i, g, x_i, p);
	
	// compute the fingerprint of the public key $h_i$
	tmcg_mpz_shash(h_i_fp, 1, h_i);
	
	// set the initial value of the common public key $h$
	mpz_set(h, h_i);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_ComputeNIZK
	(mpz_ptr c, mpz_ptr r) const
{
	mpz_t v, t;
	mpz_init(v), mpz_init(t);

	// proof of knowledge $(c, r)$ [CaS97] for the private key $x_i$
	
		// commitment $t = g^v \bmod p$
		tmcg_mpz_srandomm(v, q);
		tmcg_mpz_fspowm(fpowm_table_g, t, g, v, p);
		// challenge $c = h(p || q || g || k || h_i || t)$
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PoK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof
		// of knowledge (SPK) in the random oracle model.
		tmcg_mpz_shash(c, 5, p, q, g, h_i, t);
		// response $r = v - c x_i \bmod q$
		mpz_mul(r, c, x_i);
		mpz_neg(r, r);
		mpz_add(r, r, v);
		mpz_mod(r, r, q);

	mpz_clear(v), mpz_clear(t);
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_PublishKey
	(std::ostream& out) const
{
	mpz_t c, r;
	mpz_init(c), mpz_init(r);

	KeyGenerationProtocol_ComputeNIZK(c, r);
	// the output is $h_i$ appended by SPK $(c, r)$	
	out << h_i << std::endl << c << std::endl << r << std::endl;

	mpz_clear(c), mpz_clear(r);
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_VerifyNIZK
	(mpz_srcptr foo, mpz_srcptr c, mpz_srcptr r) const
{
	mpz_t t2, c2;
	mpz_init(t2), mpz_init(c2);

	try
	{
		// verify the in-group property
		if (!CheckElement(foo))
			throw false;

		// check size of $c$
		if (mpz_sizeinbase(c, 2L) > (tmcg_mpz_shash_len() * 8))
			throw false;

		// check size of $r$
		if (mpz_cmpabs(r, q) >= 0)
			throw false;

		// verify the proof of knowledge [CaS97]
		tmcg_mpz_fpowm(fpowm_table_g, t2, g, r, p);
		mpz_powm(c2, foo, c, p);
		mpz_mul(t2, t2, c2);
		mpz_mod(t2, t2, p);
		tmcg_mpz_shash(c2, 5, p, q, g, foo, t2);
		if (mpz_cmp(c, c2))
			throw false;

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(t2), mpz_clear(c2);
		return return_value;
	}
	
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_UpdateKey
	(std::istream& in)
{
	mpz_t foo, c, r;
	mpz_init(foo), mpz_init(c), mpz_init(r);
	
	try
	{
		in >> foo >> c >> r;
		if (!in.good())
			throw false;

		// verify the proof of knowledge
		if (!KeyGenerationProtocol_VerifyNIZK(foo, c, r))
			throw false;
		
		// update the common public key $h$
		mpz_mul(h, h, foo);
		mpz_mod(h, h, p);
		
		// store public key $h_j$ indexed with fingerprint
		mpz_ptr tmp = new mpz_t();
		std::ostringstream fp;
		mpz_init_set(tmp, foo);
		tmcg_mpz_shash(c, 1, foo);
		fp << c;
		h_j[fp.str()] = tmp;
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(c), mpz_clear(r);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_RemoveKey
	(std::istream& in)
{
	mpz_t foo, bar;
	mpz_init(foo), mpz_init(bar);
	
	try
	{
		in >> foo >> bar >> bar; // we need only the public key
		if (!in.good())
			throw false;
		
		// compute the fingerprint of $h_j$
		tmcg_mpz_shash(bar, 1, foo);
		std::ostringstream fp;
		fp << bar;
		std::string fpstr = fp.str();
		
		// public key with this fingerprint stored?
		if (h_j.count(fpstr))
		{
			// update the common public key
			if (!mpz_invert(foo, h_j[fpstr], p))
				throw false;
			mpz_mul(h, h, foo);
			mpz_mod(h, h, p);
			
			// release the given public key
			mpz_clear(h_j[fpstr]);
			delete [] h_j[fpstr];
			h_j.erase(fpstr);
			
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

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_ProveKey_interactive
	(std::istream& in, std::ostream& out)
{
	mpz_t r, c, m;
	mpz_init(r), mpz_init(c), mpz_init(m);

	try
	{
		// compute and send commitment $m_1 = g^r \bmod p$
		tmcg_mpz_srandomm(r, q);
		tmcg_mpz_fspowm(fpowm_table_g, m, g, r, p);
		out << m << std::endl;

		// receive challenge $c$
		in >> c;
		if (!in.good())
			throw false;

		// check size of $c$
		if (mpz_cmpabs(c, q) >= 0)
			throw false;
		
		// compute response $m_2 = r + x \cdot c$
		mpz_mul(m, c, x_i);
		mpz_mod(m, m, q);
		mpz_add(m, m, r);
		mpz_mod(m, m, q);

		// send response $m_2$
		out << m << std::endl;

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(r), mpz_clear(c), mpz_clear(m);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_ProveKey_interactive_publiccoin
	(JareckiLysyanskayaEDCF *edcf, std::istream& in, std::ostream& out)
{
	mpz_t r, c, m;
	mpz_init(r), mpz_init(c), mpz_init(m);

	try
	{
		// compute and send commitment $m_1 = g^r \bmod p$
		tmcg_mpz_srandomm(r, q);
		tmcg_mpz_fspowm(fpowm_table_g, m, g, r, p);
		out << m << std::endl;

		// flip coins with verifier to get $c \in \mathbb{Z}_q$
		std::stringstream err_log;
		if (!edcf->Flip_twoparty(0, c, in, out, err_log))
			throw false;
		mpz_mod(c, c, q);

		// check size of $c$
		if (mpz_cmpabs(c, q) >= 0)
			throw false;
		
		// compute response $m_2 = r + x \cdot c$
		mpz_mul(m, c, x_i);
		mpz_mod(m, m, q);
		mpz_add(m, m, r);
		mpz_mod(m, m, q);

		// send response $m_2$
		out << m << std::endl;

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(r), mpz_clear(c), mpz_clear(m);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_VerifyKey_interactive
	(mpz_srcptr key, std::istream& in, std::ostream& out)
{
	mpz_t c, m_1, m_2;
	mpz_init(c), mpz_init(m_1), mpz_init(m_2);

	try
	{
		// receive commitment $m_1$
		in >> m_1;
		if (!in.good())
			throw false;

		// verify in-group property of $m_1$
		if (!CheckElement(m_1))
			throw false;

		// choose challenge $c$ randomly
		tmcg_mpz_srandomm(c, q);

		// send challenge $c$ and receive response $m_2$ 
		out << c << std::endl;
		in >> m_2;
		if (!in.good())
			throw false;

		// check size of $m_2$
		if (mpz_cmpabs(m_2, q) >= 0)
			throw false;

		// compute verify $m_1 = g^{m_2} \cdot key^{-c}$
		tmcg_mpz_fpowm(fpowm_table_g, m_2, g, m_2, p);
		mpz_powm(c, key, c, p);
		if (!mpz_invert(c, c, p))
			throw false;
		mpz_mul(m_2, m_2, c);
		mpz_mod(m_2, m_2, p);
		if (mpz_cmp(m_1, m_2))
			throw false;

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(c), mpz_clear(m_1), mpz_clear(m_2);
		return return_value;
	}
}

bool BarnettSmartVTMF_dlog::KeyGenerationProtocol_VerifyKey_interactive_publiccoin
	(mpz_srcptr key, JareckiLysyanskayaEDCF *edcf, 
	 std::istream& in, std::ostream& out)
{
	mpz_t c, m_1, m_2;
	mpz_init(c), mpz_init(m_1), mpz_init(m_2);

	try
	{
		// receive commitment $m_1$
		in >> m_1;
		if (!in.good())
			throw false;

		// verify in-group property of $m_1$
		if (!CheckElement(m_1))
			throw false;

		// flip coins with prover to get $c \in \mathbb{Z}_q$
		std::stringstream err_log;
		if (!edcf->Flip_twoparty(1, c, in, out, err_log))
			throw false;
		mpz_mod(c, c, q);

		// receive response $m_2$ 
		in >> m_2;
		if (!in.good())
			throw false;

		// check size of $m_2$
		if (mpz_cmpabs(m_2, q) >= 0)
			throw false;

		// compute verify $m_1 = g^{m_2} \cdot key^{-c}$
		tmcg_mpz_fpowm(fpowm_table_g, m_2, g, m_2, p);
		mpz_powm(c, key, c, p);
		if (!mpz_invert(c, c, p))
			throw false;
		mpz_mul(m_2, m_2, c);
		mpz_mod(m_2, m_2, p);
		if (mpz_cmp(m_1, m_2))
			throw false;

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(c), mpz_clear(m_1), mpz_clear(m_2);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::KeyGenerationProtocol_Finalize
	()
{
	// Precompute the values $h^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	tmcg_mpz_fpowm_precompute(fpowm_table_h, h, p, mpz_sizeinbase(q, 2L));
}

size_t BarnettSmartVTMF_dlog::KeyGenerationProtocol_NumberOfKeys
	()
{
	return h_j.size();
}

void BarnettSmartVTMF_dlog::CP_Prove
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh, mpz_srcptr alpha,
	 std::ostream& out, const bool fpowm_usage) const
{
	mpz_t a, b, omega, c, r;
	mpz_init(c), mpz_init(r), mpz_init(a), mpz_init(b), mpz_init(omega);

	// proof of knowledge (equality of discrete logarithms) [CaS97]
	// the original technique is due to Chaum and Pedersen, see e.g.,
	// David Chaum and Torben Pryds Pedersen: 'Wallet Databases with Observers'
	// Advances in Cryptology - CRYPTO'92, LNCS 740, pp. 89--105, 1992.
	// 1. commitment
	tmcg_mpz_srandomm(omega, q);
	if (fpowm_usage)
	{
		assert(!mpz_cmp(g, gg) && !mpz_cmp(h, hh));
		tmcg_mpz_fspowm(fpowm_table_g, a, gg, omega, p);
		tmcg_mpz_fspowm(fpowm_table_h, b, hh, omega, p);
	}
	else
	{
		tmcg_mpz_spowm(a, gg, omega, p);
		tmcg_mpz_spowm(b, hh, omega, p);
	}
	// 2. challenge
	// Here we use the well-known "Fiat-Shamir heuristic" to make
	// the PoK non-interactive, i.e. we turn it into a statistically
	// zero-knowledge (Schnorr signature scheme style) proof of
	// knowledge (SPK) in the random oracle model.
	tmcg_mpz_shash(c, 10, p, q, g, h, a, b, x, y, gg, hh);
	// 3. response
	mpz_mul(r, c, alpha);
	mpz_neg(r, r);
	mpz_add(r, r, omega);
	mpz_mod(r, r, q);

	// write SPK to output stream 
	out << c << std::endl << r << std::endl;

	mpz_clear(c), mpz_clear(r), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
}

bool BarnettSmartVTMF_dlog::CP_Verify
	(mpz_srcptr x, mpz_srcptr y, mpz_srcptr gg, mpz_srcptr hh,
	 std::istream& in, const bool fpowm_usage) const
{
	mpz_t a, b, c, r;	
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r);
	
	try
	{
		in >> c >> r;
		if (!in.good())
			throw false;

		// check size of $c$
		if (mpz_sizeinbase(c, 2L) > (tmcg_mpz_shash_len() * 8))
			throw false;

		// check size of $r$
		if (mpz_cmpabs(r, q) >= 0)
			throw false;

		// verify the proof of knowledge (equality of discrete logarithms) [CaS97]
		if (fpowm_usage)
		{
			if (!mpz_cmp(g, gg))
				throw false;
			tmcg_mpz_fpowm(fpowm_table_g, a, gg, r, p);
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
			tmcg_mpz_fpowm(fpowm_table_h, b, hh, r, p);
		}
		else
			mpz_powm(b, hh, r, p);
		mpz_powm(r, y, c, p);
		mpz_mul(b, b, r);
		mpz_mod(b, b, p);
		tmcg_mpz_shash(r, 10, p, q, g, h, a, b, x, y, gg, hh);
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
	mpz_init(v_1), mpz_init(v_2), mpz_init(w), mpz_init(t_1), mpz_init(t_2);
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(c), mpz_init(tmp);
	
	// proof of knowledge ($y_1 = g_1^\alpha \vee y_2 = g_2^\beta$) [CaS97]	
	
		// 1. choose $v_1, v_2$ and $w\in_R\mathbb{Z}_q$ and compute
		//    $t_2 = y_2^w g_2^{v_2}$ and $t_1 = g_1^{v_1}$ 
		tmcg_mpz_srandomm(v_1, q);
		tmcg_mpz_srandomm(v_2, q);
		tmcg_mpz_srandomm(w, q);
		tmcg_mpz_spowm(t_2, y_2, w, p);
		tmcg_mpz_spowm(tmp, g_2, v_2, p);
		mpz_mul(t_2, t_2, tmp), mpz_mod(t_2, t_2, p);
		tmcg_mpz_spowm(t_1, g_1, v_1, p);
		
		// 2. compute $c = \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		// additionally, we hash the group parameters
		tmcg_mpz_shash(c, 10, p, q, g, h, g_1, y_1, g_2, y_2, t_1, t_2);
		mpz_mod(c, c, q);
		
		// 3. split the challenge: $c_2 = w$ and $c_1 = c - c_2$
		mpz_set(c_2, w);
		mpz_sub(c_1, c, c_2), mpz_mod(c_1, c_1, q);
		
		// 4. forge $r_2 = v_2$ and set $r_1 = v_1 - c_1\alpha$
		mpz_set(r_2, v_2), mpz_mod(r_2, r_2, q);
		mpz_mul(tmp, c_1, alpha), mpz_mod(tmp, tmp, q);
		mpz_sub(r_1, v_1, tmp), mpz_mod(r_1, r_1, q);
		
	out << c_1 << std::endl << c_2 << std::endl <<
		r_1 << std::endl << r_2 << std::endl;

	mpz_clear(v_1), mpz_clear(v_2), mpz_clear(w), mpz_clear(t_1);
	mpz_clear(t_2), mpz_clear(c_1), mpz_clear(c_2), mpz_clear(r_1);
 	mpz_clear(r_2), mpz_clear(c), mpz_clear(tmp);
}

void BarnettSmartVTMF_dlog::OR_ProveSecond
	(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
	 mpz_srcptr alpha, std::ostream& out) const
{
	mpz_t v_1, v_2, w, t_1, t_2, c_1, c_2, r_1, r_2, c, tmp;
	mpz_init(v_1), mpz_init(v_2), mpz_init(w), mpz_init(t_1), mpz_init(t_2);
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(c), mpz_init(tmp);
	
	// proof of knowledge ($y_1 = g_1^\beta \vee y_2 = g_2^\alpha$) [CaS97]

		// 1. choose $v_1, v_2$ and $w\in_R\mathbb{Z}_q$ and compute
		//    $t_1 = y_1^w g_1^{v_1}$ and $t_2 = g_2^{v_2}$
		tmcg_mpz_srandomm(v_1, q);
		tmcg_mpz_srandomm(v_2, q);
		tmcg_mpz_srandomm(w, q);
		tmcg_mpz_spowm(t_1, y_1, w, p);
		tmcg_mpz_spowm(tmp, g_1, v_1, p);
		mpz_mul(t_1, t_1, tmp), mpz_mod(t_1, t_1, p);
		tmcg_mpz_spowm(t_2, g_2, v_2, p);
		
		// 2. compute $c = \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		// additionally, we hash the group parameters
		tmcg_mpz_shash(c, 10, p, q, g, h, g_1, y_1, g_2, y_2, t_1, t_2);
		mpz_mod(c, c, q);
		
		// 3. split the challenge: $c_1 = w$ and $c_2 = c - c_1$
		mpz_set(c_1, w);
		mpz_sub(c_2, c, c_1), mpz_mod(c_2, c_2, q);
		
		// 4. forge $r_1 = v_1$ and set $r_2 = v_2 - c_2\alpha$
		mpz_set(r_1, v_1), mpz_mod(r_1, r_1, q);
		mpz_mul(tmp, c_2, alpha), mpz_mod(tmp, tmp, q);
		mpz_sub(r_2, v_2, tmp), mpz_mod(r_2, r_2, q);
		
	out << c_1 << std::endl << c_2 << std::endl <<
		r_1 << std::endl << r_2 << std::endl;

	mpz_clear(v_1), mpz_clear(v_2), mpz_clear(w), mpz_clear(t_1);
	mpz_clear(t_2), mpz_clear(c_1), mpz_clear(c_2), mpz_clear(r_1);
	mpz_clear(r_2), mpz_clear(c), mpz_clear(tmp);
}

bool BarnettSmartVTMF_dlog::OR_Verify
	(mpz_srcptr y_1, mpz_srcptr y_2, mpz_srcptr g_1, mpz_srcptr g_2,
	 std::istream& in) const
{
	mpz_t c_1, c_2, r_1, r_2, t_1, t_2, c, tmp;
	mpz_init(c_1), mpz_init(c_2), mpz_init(r_1), mpz_init(r_2);
	mpz_init(t_1), mpz_init(t_2), mpz_init(c), mpz_init(tmp);
	
	try
	{
		in >> c_1 >> c_2 >> r_1 >> r_2;
		if (!in.good())
			throw false;

		// check the size of $r_1$ and $r_2$
		if ((mpz_cmpabs(r_1, q) >= 0L) || (mpz_cmpabs(r_2, q) >= 0L))
			throw false;
		
		// verify ($y_1 = g_1^\alpha \vee y_2 = g_2^\beta$) [CaS97]
		mpz_powm(t_1, y_1, c_1, p);
		mpz_powm(tmp, g_1, r_1, p);
		mpz_mul(t_1, t_1, tmp), mpz_mod(t_1, t_1, p);
		
		mpz_powm(t_2, y_2, c_2, p);
		mpz_powm(tmp, g_2, r_2, p);
		mpz_mul(t_2, t_2, tmp), mpz_mod(t_2, t_2, p);
		
		// check the equation
		// $c_1 + c_2 \stackrel{?}{=} 
		//                   \mathcal{H}(g_1, y_1, g_2, y_2, t_1, t_2)$
		// additionally, we hash the group parameters
		mpz_add(tmp, c_1, c_2), mpz_mod(tmp, tmp, q);
		tmcg_mpz_shash(c, 10, p, q, g, h, g_1, y_1, g_2, y_2, t_1, t_2);
		mpz_mod(c, c, q);
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
		tmcg_mpz_srandomm(r, q);
	while (!mpz_cmp_ui(r, 0L) || !mpz_cmp_ui(r, 1L));
}

// this is basically an ElGamal encryption using the common public key $h$
void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Mask
	(mpz_srcptr m, mpz_ptr c_1, mpz_ptr c_2, mpz_ptr r) const
{
	MaskingValue(r);
	
	// compute $c_1 = g^r \bmod p$
	tmcg_mpz_fspowm(fpowm_table_g, c_1, g, r, p);
	
	// compute $c_2 = m \cdot h^r \bmod p$
	tmcg_mpz_fspowm(fpowm_table_h, c_2, h, r, p);
	mpz_mul(c_2, c_2, m);
	mpz_mod(c_2, c_2, p);
}

void BarnettSmartVTMF_dlog::VerifiableMaskingProtocol_Prove
	(mpz_srcptr m, mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr r,
	 std::ostream& out) const
{
	mpz_t foo;
	mpz_init(foo);
	assert(mpz_invert(foo, m, p));

	// invoke CP(c_1, c_2/m, g, h; r) as prover
	if (!mpz_invert(foo, m, p))
		mpz_set_ui(foo, 0L); // indicates an error
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

// again this is basically an ElGamal encryption of 1 using public key $h$
void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Mask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2, 
	 mpz_ptr r) const
{
	MaskingValue(r);
	
	// compute $c'_1 = c_1 \cdot g^r \bmod p$
	tmcg_mpz_fspowm(fpowm_table_g, c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute $c'_2 = c_2 \cdot h^r \bmod p$
	tmcg_mpz_fspowm(fpowm_table_h, c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Remask
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_ptr c__1, mpz_ptr c__2,
	 mpz_srcptr r, const bool TimingAttackProtection) const
{
	// compute $c'_1 = c_1 \cdot g^r \bmod p$
	if (TimingAttackProtection)
		tmcg_mpz_fspowm(fpowm_table_g, c__1, g, r, p);
	else
		tmcg_mpz_fpowm(fpowm_table_g, c__1, g, r, p);
	mpz_mul(c__1, c__1, c_1);
	mpz_mod(c__1, c__1, p);
	
	// compute $c'_2 = c_2 \cdot h^r \bmod p$
	if (TimingAttackProtection)
		tmcg_mpz_fspowm(fpowm_table_h, c__2, h, r, p);
	else
		tmcg_mpz_fpowm(fpowm_table_h, c__2, h, r, p);
	mpz_mul(c__2, c__2, c_2);
	mpz_mod(c__2, c__2, p);
}

void BarnettSmartVTMF_dlog::VerifiableRemaskingProtocol_Prove
	(mpz_srcptr c_1, mpz_srcptr c_2, mpz_srcptr c__1, mpz_srcptr c__2,
	 mpz_srcptr r, std::ostream& out) const
{
	mpz_t foo, bar;
	mpz_init(foo), mpz_init(bar);
	assert(mpz_invert(foo, c_1, p));
	assert(mpz_invert(bar, c_2, p));

	// invoke CP(c'_1/c_1, c'_2/c_2, g, h; r) as prover
	if (!mpz_invert(foo, c_1, p))
		mpz_set_ui(foo, 0L);  // indicates an error
	mpz_mul(foo, foo, c__1);
	mpz_mod(foo, foo, p);
	if (!mpz_invert(bar, c_2, p))
		mpz_set_ui(bar, 0L);  // indicates an error
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
	assert(CheckElement(c_1));
	
	// compute $d_i = {c_1}^{x_i} \bmod p$
	tmcg_mpz_spowm(d_i, c_1, x_i, p);
	out << d_i << std::endl << h_i_fp << std::endl;
	
	// invoke CP(d_i, h_i, c_1, g; x_i) as prover
	CP_Prove(d_i, h_i, c_1, g, x_i, out, false);
	
	mpz_clear(d_i);
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Initialize
	(mpz_srcptr c_1)
{
	assert(CheckElement(c_1));

	// compute $d = d_i = {c_1}^{x_i} \bmod p$
	tmcg_mpz_spowm(d, c_1, x_i, p);
}

bool BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Update
	(mpz_srcptr c_1, std::istream& in)
{
	mpz_t d_j, h_j_fp;
	mpz_init(d_j), mpz_init(h_j_fp);
	
	try
	{
		in >> d_j >> h_j_fp;
		if (!in.good())
			throw false;

		// public key stored?
		std::ostringstream fp;
		fp << h_j_fp;
		std::string fpstr = fp.str();
		if (!h_j.count(fpstr))
			throw false;
		
		// verify the in-group property
		if (!CheckElement(d_j))
			throw false;
		
		// invoke CP(d_j, h_j, c_1, g; x_j) as verifier
		if (!CP_Verify(d_j, h_j[fpstr], c_1, g, in, false))
			throw false;
		
		// update the value of $d$
		mpz_mul(d, d, d_j);
		mpz_mod(d, d, p);
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(d_j), mpz_clear(h_j_fp);
		return return_value;
	}
}

void BarnettSmartVTMF_dlog::VerifiableDecryptionProtocol_Verify_Finalize
	(mpz_srcptr c_2, mpz_ptr m) const
{
	assert(mpz_invert(m, d, p));
	
	// finalize the decryption
	if (!mpz_invert(m, d, p))
		mpz_set_ui(m, 0L); // indicates an error
	mpz_mul(m, m, c_2);
	mpz_mod(m, m, p);
}

BarnettSmartVTMF_dlog::~BarnettSmartVTMF_dlog
	()
{
	mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);
	mpz_clear(x_i), mpz_clear(h_i), mpz_clear(h), mpz_clear(d);
	mpz_clear(h_i_fp);
	for (std::map<std::string, mpz_ptr>::const_iterator
		j = h_j.begin(); j != h_j.end(); j++)
	{
		mpz_clear(j->second);
		delete [] j->second;
	}
	h_j.clear();
	
	tmcg_mpz_fpowm_done(fpowm_table_g), tmcg_mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
