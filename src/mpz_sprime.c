/*******************************************************************************
   This file is part of libTMCG.

     [CS00]  Ronald Cramer, Victor Shoup: 'Signature schemes based on the
              strong RSA assumption', ACM Transactions on Information and
             System Security, Vol.3(3), pp. 161--185, 2000

     [RS00]  Jean-Francois Raymond, Anton Stiglic: 'Security Issues in the
              Diffie-Hellman Key Agreement Protocol', ZKS technical report
             http://citeseer.ist.psu.edu/455251.html

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "mpz_sprime.h"

unsigned long int primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
    103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
    269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
    389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
    449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
    587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
    643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
    773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
    853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
    991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
    1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
    1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
    1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
    1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
    1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
    1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
    1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
    1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
    1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
    1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
    1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
    1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
    1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
    1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
    1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
    2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
    2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
    2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
    2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
    2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
    2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
    2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
    2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
    2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
    2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
    2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
    2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
    2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
    2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
    3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
    3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
    3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
    3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
    3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
    3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
    3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
    3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
    3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
    3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
    3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
    3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
    3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
    3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
    3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
    4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
    4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
    4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
    4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
    4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
    4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
    4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
    4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
    4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
    4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
    4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
    4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
    4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
    4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
    4957, 4967, 4969, 4973, 4987, 4993, 4999, 0
};

int notest
	(mpz_ptr p, mpz_ptr q)
{
	return 1;
}

int test2g
	(mpz_ptr p, mpz_ptr q)
{
	return mpz_congruent_ui_p(p, 7L, 8L);
}

int test3mod4
	(mpz_ptr p, mpz_ptr q)
{
	return mpz_congruent_ui_p(p, 3L, 4L);
}

/* This fast generation of safe primes is due to [CS00] and
   M.J. Wiener's "Safe Prime Generation with a Combined Sieve". */

void mpz_sprime_test
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize,
	int (*test)(mpz_ptr, mpz_ptr))
{
	mpz_t mr_y, mr_q, mr_g, mr_nm1;
	
	mpz_init(mr_y), mpz_init(mr_nm1), mpz_init(mr_q), mpz_init_set_ui(mr_g, 2L);
	
	/* Step 1. [CS00]: choose a random odd number $q$ of appropriate size */
	do
		mpz_srandomb(q, qsize);
	while ((mpz_sizeinbase(q, 2L) < qsize) || (mpz_even_p(q)));
	
	while (1)
	{
		size_t i = 0;
		unsigned long int mr_k;
		
		/* increase $q$ by 2 (incremental prime number generator) */
		mpz_add_ui(q, q, 2L);
		/* compute p = 2q + 1 */
		mpz_mul_2exp(p, q, 1L);
		mpz_add_ui(p, p, 1L);
		
		/* additional tests? */
		if (!test(p, q))
			continue;
		
		/* Step 2. [CS00]: M.J. Wiener's "Combined Sieve"
		   Test whether either $q$ or $p$ are divisable by any primes up to
		   some bound $B$. (We use the bound $B = 5000$ here.) */
		for (i = 0; primes[i]; i++)
		{
			if (mpz_congruent_ui_p(q, (primes[i] - 1L) / 2L, primes[i]) ||
				mpz_congruent_ui_p(p, (primes[i] - 1L) / 2L, primes[i]) ||
				mpz_congruent_ui_p(q, 0L, primes[i]) ||
				mpz_congruent_ui_p(p, 0L, primes[i]))
					break;
		}
		if (primes[i])
			continue;
		
		/* Step 3. [CS00]: Test whether 2 is a Miller-Rabin witness to the
		   compositeness of $q$. */
		mpz_sub_ui(mr_nm1, q, 1L);
		mr_k = mpz_scan1(mr_nm1, 0L);
		mpz_tdiv_q_2exp(mr_q, mr_nm1, mr_k);
		mpz_powm(mr_y, mr_g, mr_q, q);
		
		if (!((mpz_cmp_ui(mr_y, 1L) == 0) || (mpz_cmp(mr_y, mr_nm1) == 0)))
		{
			size_t mr_w = 0;
			unsigned long int j;
			for (j = 1; j < mr_k; j++)
			{
				mpz_powm_ui(mr_y, mr_y, 2L, q);
				if (mpz_cmp(mr_y, mr_nm1) == 0)
				{
					mr_w = 1;
					break;
				}
				if (mpz_cmp_ui(mr_y, 1L) == 0)
					break;
			}
			if (!mr_w)
				continue;
		}
		fprintf(stderr, ".");
		
		/* Step 4. [CS00]: Test if $2^q \equiv \pm 1 \pmod{p}$. */
		mpz_powm(mr_y, mr_g, q, p);
		mpz_sub_ui(mr_nm1, p, 1L);
		if (!((mpz_cmp_ui(mr_y, 1L) == 0) || (mpz_cmp(mr_y, mr_nm1) == 0)))
			continue;
		fprintf(stderr, "!");
		
		/* Step 5. [CS00]: Apply the Miller-Rabin test to $q$ a defined number
		   of times (error probability $4^{-64}$) using randomly selected bases. */
		if (mpz_probab_prime_p(q, 64))
			break;
	}
	mpz_clear(mr_y), mpz_clear(mr_nm1), mpz_clear(mr_q), mpz_clear(mr_g);
	fprintf(stderr, "\n");
	
	assert(mpz_probab_prime_p(p, 64));
	assert(mpz_probab_prime_p(q, 64));
}

void mpz_sprime
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize)
{
	mpz_sprime_test(p, q, qsize, notest);
}

void mpz_sprime2g
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize)
{
	/* The additional test is necessary because we want 2 as generator
	   of $G$. If $p$ is congruent 7 modulo 8, then 2 is a quadratic residue
	   and hence it will generate the cyclic subgroup of order $q$. [RS00] */
	mpz_sprime_test(p, q, qsize, test2g);
}

void mpz_sprime3mod4
	(mpz_ptr p, unsigned long int psize)
{
	mpz_t q;

	/* An additional test is necessary, if we want to generate a Blum integer,
	   i.e. $p, q \equiv 3 \pmod{4}$ in the product of two safe primes. */
	mpz_init(q);
	mpz_sprime_test(p, q, psize - 1L, test3mod4);
	mpz_clear(q);
}
