/*******************************************************************************
   GolleDCPG_elgamal.cc, |D|ealing |C|ards in |P|oker |G|ames, ElGamal variant

     [Go03] Philippe Golle: 'Dealing Cards in Poker Games',
     Proceedings of the International Conference on Information Technology:
     Coding and Computing (ITCC ’05), volume 1, pp. 506--511. IEEE, 2005.

     [JJ99] Markus Jakobsson and Ari Juels: 'Millimix: Mixing in Small Batches',
     DIMACS Technical Report 99-33, 1999.

     [JS99] Markus Jakobsson and Claus Peter Schnorr: 'Efficient Oblivious
       Proofs of Correct Exponentiation',
     Proceedings of Communications and Multimedia Security, pp. 71--86, 1999.

   This file is part of LibTMCG.

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "GolleDCPG_elgamal.hh"

GolleDCPG_elgamal::GolleDCPG_elgamal
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
		mpz_lprime(p, q, k, fieldsize, subgroupsize, TMCG_MR_ITERATIONS);
	
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
				mpz_shash(bar, U.str());
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
				mpz_wrandomm(bar, p); // choose [bar] randomly
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
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$.
	if (initialize_group)
		mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

GolleDCPG_elgamal::GolleDCPG_elgamal
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
	mpz_fpowm_init(fpowm_table_g), mpz_fpowm_init(fpowm_table_h);
	
	// Precompute the values $g^{2^i} \bmod p$ for all $0 \le i \le |q|$
	if (precompute)
		mpz_fpowm_precompute(fpowm_table_g, g, p, mpz_sizeinbase(q, 2L));
}

GolleDCPG_elgamal::~GolleDCPG_elgamal
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
	
	mpz_fpowm_done(fpowm_table_g), mpz_fpowm_done(fpowm_table_h);
	delete [] fpowm_table_g, delete [] fpowm_table_h;
}
