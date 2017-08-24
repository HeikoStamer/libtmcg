/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
#include <libTMCG.hh>

#include <sstream>
#include <vector>

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-gencrs [OPTIONS] [ARGS]; number of ARGS determines security level";
	static const char *about = "domain parameter generation (only for Dlog-based cryptosystems)";
	size_t factor = 0;
	std::string fips;
	int opt_verbose = 0;

	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-f") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-f") == 0) && (idx < (size_t)(argc - 1)) && (!fips.length()))
				fips = argv[i+1];
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -f SEED        generate domain parameters according to FIPS 186-4 with SEED" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-gencrs " << VERSION << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose = 1; // verbose output
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		factor++;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}

	if (fips.length()) // generate primes and generator according to FIPS 186-4?
	{
		// 1. Check that the $(L, N)$ pair is in the list of acceptable $(L, N)$ pairs.
		//    If the pair is not in the list, the return INVALID.
		size_t L = 0, N = 0;
		if (factor > 0)
		{
			if (opt_verbose)
				std::cout << "Generating primes p and q according to FIPS 186-4 with factor = " << factor << std::endl;
			L = TMCG_DDH_SIZE + (factor * 1024), N = TMCG_DLSE_SIZE + ((factor - 1) * 128);
		}
		else
		{
			if (opt_verbose)
				std::cout << "Generating primes p and q according to FIPS 186-4 with default sizes" << std::endl;
			L = TMCG_DDH_SIZE, N = TMCG_DLSE_SIZE;
		}
		int hash_algo = 0, mr_iterations = 0;
		if (N == 256)
			hash_algo = GCRY_MD_SHA256, mr_iterations = 56;
		else if (N == 384)
			hash_algo = GCRY_MD_SHA384, mr_iterations = 64;
		else if (N == 512)
			hash_algo = GCRY_MD_SHA512, mr_iterations = 72;
		else
		{
			std::cerr << "ERROR: no FIPS approved hash function defined for N = " << N << std::endl;
			return -1;
		}
		// 5. Get an arbitrary sequence of $seedlen$ bits as the $domain\_parameter\_seed$.
		mpz_t domain_parameter_seed;
		mpz_init(domain_parameter_seed);
		if (mpz_set_str(domain_parameter_seed, fips.c_str(), TMCG_MPZ_IO_BASE) < 0)
		{
			std::cerr << "ERROR: FIPS domain parameter SEED is not a valid integer of base " << TMCG_MPZ_IO_BASE << std::endl;
			mpz_clear(domain_parameter_seed);
			return -1;
		}
		// 2. If $(seedlen < N)$, then return INVALID.
		size_t seedlen = mpz_sizeinbase(domain_parameter_seed, 2L);
		if (seedlen < N)
		{
			std::cerr << "ERROR: FIPS domain parameter SEED (seedlen = " << seedlen << ") too short for N = " << N << std::endl;
			mpz_clear(domain_parameter_seed);
			return -1;
		}
		// 3. $n = \lceil L / outlen \rceil - 1$.
		size_t n = (L / (mpz_fhash_len(hash_algo) * 8)) - 1;
		// 4. $b = L - 1 - (n * outlen)$.
		size_t b = L - 1 - (n * mpz_fhash_len(hash_algo) * 8);
		// 5.
		size_t counter = 0;
		mpz_t U, q, q2, W, X, c, p;
		mpz_init(U), mpz_init(q), mpz_init(q2), mpz_init(W), mpz_init(X), mpz_init(c), mpz_init(p);
		std::vector<mpz_ptr> V_j;
		for (size_t j = 0; j <= n; j++)
		{
			mpz_ptr tmp = new mpz_t();
			mpz_init(tmp);
			V_j.push_back(tmp);
		}
		while (1)
		{
			while (1)
			{
				// 6. $U = \mathbf{Hash}(domain\_parameter\_seed) \bmod 2^{N-1}$.
				mpz_fhash(U, hash_algo, domain_parameter_seed);
				mpz_tdiv_r_2exp(U, U, N - 1);
				if (opt_verbose)
					std::cout << "U = " << U << std::endl;
				// 7. $q = 2^{N-1} + U + 1 - (U \bmod 2)$.
				mpz_set_ui(q, 1L);
				mpz_mul_2exp(q, q, N - 1);
				mpz_add(q, q, U);
				mpz_add_ui(q, q, 1L);
				if (mpz_odd_p(U))
					mpz_sub_ui(q, q, 1L);
				if (opt_verbose)
					std::cout << "q = " << q << std::endl;
				// 8. Test whether or not $q$ is prime as specified in Appendix C.3.
				// 9. If $q$ is not a prime, then go to step 5.
				if (!mpz_probab_prime_p(q, mr_iterations))
					mpz_add_ui(domain_parameter_seed, domain_parameter_seed, 1L);
				else
					break;
			}
			mpz_mul_2exp(q2, q, 1L);
			// 10. $offset = 1$.
			size_t offset = 1;
			// 11. For $counter = 0$ to $(4L - 1)$ do
			for (counter = 0; counter < (4 * L); counter++)
			{
				// 11.1 For $j = 0$ to $n$ do
				for (size_t j = 0; j <= n; j++)
				{
					// $V_j = \mathbf{Hash}((domain_parameter_seed + offset + j) \bmod 2^{seedlen})$.
					mpz_t tmp;
					mpz_init_set(tmp, domain_parameter_seed);
					mpz_add_ui(tmp, tmp, offset);
					mpz_add_ui(tmp, tmp, j);
					mpz_tdiv_r_2exp(tmp, tmp, seedlen);
					mpz_fhash(V_j[j], hash_algo, tmp);
					if (opt_verbose)
						std::cout << "V_j[" << j << "] = " << V_j[j] << std::endl;
					mpz_clear(tmp);
				}
				// 11.2 $W = V_0 + (V_1 * 2^{outlen}) + \cdots + (V_{n-1} * 2^{(n-1)*outlen}) + ((V_n \bmod 2^b) * 2^{n*outlen})$.
				mpz_set_ui(W, 0L);
				for (size_t j = 0; j <= n; j++)
				{
					mpz_t tmp;
					mpz_init_set(tmp, V_j[j]);
					if (j == n)
						mpz_tdiv_r_2exp(tmp, tmp, b);
					mpz_mul_2exp(tmp, tmp, (j * mpz_fhash_len(hash_algo) * 8));
					mpz_add(W, W, tmp);
					mpz_clear(tmp);
				}
				if (opt_verbose)
					std::cout << "W = " << W << std::endl;
				// 11.3 $X = W + 2^{L-1}$.
				mpz_set_ui(X, 1L);
				mpz_mul_2exp(X, X, L - 1);
				mpz_add(X, X, W);
				// 11.4 $c = X \bmod 2q$.
				mpz_mod(c, X, q2);
				// 11.5 $p = X - (c - 1)$.
				mpz_sub(p, X, c);
				mpz_add_ui(p, p, 1L);
				// 11.6 If $(p < 2^{L-1})$, then go to step 11.9.
				if (mpz_sizeinbase(p, 2L) < L)
				{
					offset += (n + 1);
					continue;
				}
				// 11.7 Test whether or not $p$ is prime as specified in Appendix C.3.
				// 11.8 If $p$ is determined to be prime, then return VALID and the values of
				//      $p$, $q$ and (optionally) the values of $domain\_parameter\_seed$ and
				//      $counter$. 
				if (mpz_probab_prime_p(p, mr_iterations))
					break;
				// 11.9 $offset = offset + n + 1$.
				offset += (n + 1);
			}
			if (mpz_probab_prime_p(p, mr_iterations))
				break;
		}
		if (opt_verbose)
			std::cout << "p = " << p << std::endl;
		if (opt_verbose)
			std::cout << "counter = " << counter << std::endl;
		if (opt_verbose)
			std::cout << "Computing generator g according to FIPS 186-4" << std::endl;
		// 1. If ($index$ is incorrect), then return INVALID.
		mpz_t index;
		mpz_init_set_ui(index, 108L); // fixed index value for DKG-tools
		// 2. $N = \mathbf{len}(q)$.
		N = mpz_sizeinbase(q, 2L);
		// 3. $e = (p - 1)/q$.
		mpz_t e;
		mpz_init_set(e, p);
		mpz_sub_ui(e, e, 1L);
		mpz_div(e, e, q);
		// 4. $count = 0$.
		mpz_t count, g;
		mpz_init_set_ui(count, 0L);
		mpz_init(g);
		while (1)
		{
			// 5. $count = count + 1$.
			mpz_add_ui(count, count, 1L);
			// 6. If $(count = 0)$, then return INVALID.
			if (!mpz_cmp_ui(count, 0L))
			{
				std::cerr << "ERROR: invalid value count = 0" << std::endl;
				mpz_clear(domain_parameter_seed);
				mpz_clear(U), mpz_clear(q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(p);
				for (size_t j = 0; j <= n; j++)
				{
					mpz_clear(V_j[j]);
					delete [] V_j[j];
				}
				V_j.clear();
				mpz_clear(index), mpz_clear(e);
				mpz_clear(count), mpz_clear(g);
				return -1;
			}
			// 7. $U = domain_parameter_seed || "ggen" || index || count$.
			// 8. $W = \mathbf{Hash}(U)$.
			mpz_fhash_ggen(W, hash_algo, domain_parameter_seed, "ggen", index, count);
			// 9. $g = W^e \bmod p$.
			mpz_powm(g, W, e, p);
			// 10. If $(g < 2)$, the go to step 5.
			if (mpz_cmp_ui(g, 2L) < 0)
				continue;
			// 11. Return VALID and the value of $g$.
			break;
		}
		if (opt_verbose)
			std::cout << "g = " << p << std::endl;		

		// export group parameters to stdout
		mpz_t hash_algo_mpz, counter_mpz;
		mpz_init_set_ui(hash_algo_mpz, hash_algo), mpz_init_set_ui(counter_mpz, counter);
		std::cout << "// setup CRS (common reference string) aka set of domain parameters" << std::endl;
		std::cout << "//           ";
		std::cout << "|p| = " << mpz_sizeinbase(p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(g, 2L) << " bit";
		std::cout << std::endl;
		std::cout << "// FIPS 186-4 A.1.1.2 generation of parameters using an approved hash function" << std::endl;
		std::cout << "//      hash_algo = " << gcry_md_algo_name(hash_algo) << std::endl; 
		std::cout << "//      domain_parameter_seed = " << domain_parameter_seed << std::endl;
		std::cout << "//      counter = " << counter << std::endl;
		std::cout << "//      index = " << index << std::endl;
		std::cout << "crs = \"fips-crs|" << p << "|" << q << "|" << g << "|" << e << "|" << hash_algo_mpz << "|" <<
			domain_parameter_seed << "|" << counter_mpz << "|" << index << "|\"" << std::endl;

		// release
		mpz_clear(domain_parameter_seed);
		mpz_clear(U), mpz_clear(q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(p);
		for (size_t j = 0; j <= n; j++)
		{
			mpz_clear(V_j[j]);
			delete [] V_j[j];
		}
		V_j.clear();
		mpz_clear(index), mpz_clear(e);
		mpz_clear(count), mpz_clear(g);
		mpz_clear(hash_algo_mpz), mpz_clear(counter_mpz);
	}
	else
	{
		// create VTMF instance as a CRS (common reference string)
		BarnettSmartVTMF_dlog *vtmf = NULL;
		if (factor > 0)
		{
			if (opt_verbose)
				std::cout << "Generating primes p and q with factor = " << factor <<
					" and canonical generator g (by VTMF)" << std::endl;
			// for each argument, sizes of underlying finite field and subgroup are increased by 1024 bit resp. 128 bit
			vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE + (factor * 1024), TMCG_DLSE_SIZE + (factor * 128), true);
		}
		else
		{
			if (opt_verbose)
				std::cout << "Generating primes p and q with default sizes" <<
					" and canonical generator g (by VTMF)" << std::endl;
			// use default security parameter from LibTMCG and verifiable generation of $g$
			vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true);
		}

		// check the instance for sanity
		if (!vtmf->CheckGroup())
		{
			std::cerr << "ERROR: Group G from CRS is incorrectly generated!" << std::endl;
			return -1;
		}

		// export group parameters to stdout
		std::cout << "// setup CRS (common reference string) aka set of domain parameters" << std::endl;
		std::cout << "//           ";
		std::cout << "|p| = " << mpz_sizeinbase(vtmf->p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(vtmf->q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(vtmf->g, 2L) << " bit";
		std::cout << std::endl;
		std::cout << "crs = \"crs|" << vtmf->p << "|" << vtmf->q << "|" << vtmf->g << "|" << vtmf->k << "|\"" << std::endl;

		// release
		delete vtmf;
	}
	
	return 0;
}
