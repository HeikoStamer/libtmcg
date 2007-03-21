/*******************************************************************************
   This file is part of LibTMCG.

     [CS00]  Ronald Cramer, Victor Shoup: 'Signature schemes based on the
              strong RSA assumption', ACM Transactions on Information and
             System Security, Vol.3(3), pp. 161--185, 2000

     [RS00]  Jean-Francois Raymond, Anton Stiglic: 'Security Issues in the
              Diffie-Hellman Key Agreement Protocol', ZKS technical report
             http://citeseer.ist.psu.edu/455251.html

      [HAC]  Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone:
              'Handbook of Applied Cryptography', CRC Press, 1996.

 Copyright (C) 2004, 2005, 2006  Heiko Stamer <stamer@gaos.org>

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

#include "mpz_sprime.h"

#define PRIMES_SIZE 668
#define SIEVE_SIZE 8
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

unsigned long int primes_m1d2[] = {
	1, 2, 3, 5, 6, 8, 9, 11, 14, 15, 18, 20, 21, 23, 26,
	29, 30, 33, 35, 36, 39, 41, 44, 48, 50, 51, 53, 54,
	56, 63, 65, 68, 69, 74, 75, 78, 81, 83, 86, 89, 90,
	95, 96, 98, 99, 105, 111, 113, 114, 116, 119, 120, 125,
	128, 131, 134, 135, 138, 140, 141, 146, 153, 155, 156,
	158, 165, 168, 173, 174, 176, 179, 183, 186, 189, 191,
	194, 198, 200, 204, 209, 210, 215, 216, 219, 221, 224,
	228, 230, 231, 233, 239, 243, 245, 249, 251, 254, 260,
	261, 270, 273, 278, 281, 284, 285, 288, 293, 296, 299,
	300, 303, 306, 308, 309, 315, 320, 321, 323, 326, 329,
	330, 336, 338, 341, 345, 350, 354, 359, 363, 366, 369,
	371, 375, 378, 380, 384, 386, 393, 398, 404, 405, 410,
	411, 413, 414, 419, 426, 428, 429, 431, 438, 440, 441,
	443, 453, 455, 459, 464, 468, 470, 473, 476, 483, 485,
	488, 491, 495, 498, 504, 506, 509, 510, 515, 516, 519,
	524, 525, 530, 531, 534, 543, 545, 546, 548, 551, 554,
	558, 561, 564, 575, 576, 581, 585, 590, 593, 596, 600,
	606, 608, 611, 614, 615, 618, 624, 629, 638, 639, 641,
	644, 645, 648, 650, 651, 653, 659, 660, 663, 680, 683,
	686, 690, 699, 704, 711, 713, 714, 716, 719, 723, 725,
	726, 729, 735, 740, 741, 743, 744, 746, 749, 755, 761,
	765, 771, 774, 776, 779, 783, 785, 789, 791, 798, 800,
	803, 804, 806, 809, 810, 813, 818, 828, 831, 833, 834,
	846, 848, 849, 854, 860, 861, 866, 870, 873, 876, 879,
	888, 891, 893, 894, 900, 905, 911, 915, 923, 930, 933,
	935, 936, 938, 939, 944, 950, 953, 956, 965, 966, 974,
	975, 986, 989, 993, 996, 998, 999, 1001, 1005, 1008,
	1013, 1014, 1019, 1026, 1031, 1034, 1040, 1041, 1043,
	1044, 1049, 1055, 1056, 1064, 1065, 1068, 1070, 1071,
	1076, 1080, 1089, 1101, 1103, 1106, 1110, 1118, 1119,
	1121, 1125, 1133, 1134, 1136, 1140, 1143, 1146, 1148,
	1154, 1155, 1166, 1169, 1170, 1173, 1175, 1178, 1185,
	1188, 1190, 1191, 1194, 1196, 1199, 1205, 1208, 1211,
	1218, 1220, 1223, 1229, 1233, 1236, 1238, 1251, 1260,
	1265, 1269, 1271, 1274, 1275, 1278, 1289, 1295, 1296,
	1304, 1308, 1310, 1316, 1323, 1328, 1329, 1331, 1335,
	1338, 1341, 1343, 1344, 1346, 1349, 1353, 1355, 1356,
	1359, 1364, 1365, 1370, 1374, 1376, 1383, 1388, 1394,
	1395, 1398, 1400, 1401, 1409, 1416, 1418, 1421, 1425,
	1428, 1430, 1439, 1443, 1448, 1451, 1454, 1458, 1463,
	1469, 1476, 1478, 1481, 1484, 1485, 1499, 1500, 1505,
	1509, 1511, 1518, 1520, 1524, 1530, 1533, 1539, 1541,
	1544, 1554, 1559, 1560, 1568, 1581, 1583, 1584, 1590,
	1593, 1595, 1601, 1604, 1608, 1610, 1614, 1625, 1626,
	1628, 1629, 1635, 1649, 1650, 1653, 1656, 1659, 1661,
	1664, 1665, 1671, 1673, 1679, 1680, 1685, 1686, 1694,
	1695, 1703, 1706, 1716, 1724, 1728, 1730, 1731, 1733,
	1734, 1745, 1749, 1755, 1758, 1763, 1764, 1766, 1769,
	1770, 1773, 1778, 1779, 1785, 1790, 1791, 1796, 1803,
	1806, 1808, 1811, 1815, 1818, 1821, 1829, 1835, 1836,
	1838, 1845, 1848, 1850, 1854, 1859, 1863, 1866, 1869,
	1880, 1883, 1884, 1889, 1896, 1898, 1901, 1910, 1911,
	1916, 1923, 1925, 1926, 1931, 1938, 1940, 1944, 1953,
	1955, 1958, 1959, 1961, 1964, 1965, 1971, 1973, 1983,
	1994, 2000, 2001, 2003, 2006, 2009, 2010, 2013, 2024,
	2025, 2028, 2036, 2039, 2045, 2046, 2049, 2055, 2063,
	2064, 2066, 2069, 2076, 2078, 2079, 2088, 2100, 2105,
	2108, 2109, 2114, 2115, 2120, 2121, 2126, 2129, 2130,
	2135, 2136, 2141, 2144, 2148, 2163, 2168, 2169, 2174,
	2178, 2181, 2186, 2195, 2198, 2204, 2210, 2211, 2220,
	2223, 2225, 2228, 2231, 2240, 2241, 2246, 2253, 2256,
	2258, 2259, 2261, 2273, 2274, 2280, 2283, 2291, 2295,
	2298, 2301, 2310, 2318, 2319, 2321, 2324, 2325, 2328,
	2331, 2336, 2339, 2345, 2351, 2360, 2361, 2364, 2366,
	2375, 2379, 2391, 2393, 2394, 2396, 2399, 2400, 2406,
	2408, 2415, 2430, 2435, 2438, 2444, 2451, 2454, 2459,
	2465, 2466, 2468, 2471, 2475, 2478, 2483, 2484, 2486,
	2493, 2496, 2499, 0
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

/** Miller-Rabin witness test, basically algorithm 4.24 [HAC], for a
    fixed base.

    @returns 1, if the number @a base is a Miller-Rabin witness to the
                compositness of @a n.
    @returns 0, otherwise. */

int mpz_mr_witness
	(mpz_srcptr n, mpz_srcptr base)
{
	size_t result = 1;
	mpz_t y, r, nm1;
	unsigned long int s;
	
	mpz_init(y), mpz_init(nm1), mpz_init(r);
	
	/* 1. Write $\mathtt{n} - 1 = 2^s r$ such that $r$ is odd. */
	mpz_sub_ui(nm1, n, 1L);
	s = mpz_scan1(nm1, 0L);
	mpz_tdiv_q_2exp(r, nm1, s);
	if (mpz_odd_p(r))
	{
		/* 2.2 Compute $y = \mathtt{base}^r \bmod \mathtt{n}$. */
		mpz_powm(y, base, r, n);
		result = 0;
		
		/* 2.3 If $y \neq 1$ and $y \neq \mathtt{n} - 1$ then do the following: */
		if ((mpz_cmp_ui(y, 1L) != 0) && (mpz_cmp(y, nm1) != 0))
		{
			unsigned long int j;
			for (j = 1; j < s; j++)
			{
				mpz_mul(y, y, y);
				mpz_mod(y, y, n);
				if (mpz_cmp_ui(y, 1L) == 0)
				{
					result = 1;
					break;
				}
				if (mpz_cmp(y, nm1) == 0)
					break;
			}
			/* strong witness? */
			if (mpz_cmp(y, nm1) != 0)
				result = 1;
		}
	}
	
	mpz_clear(y), mpz_clear(nm1), mpz_clear(r);
	return result;
}

/** The fast generation of safe primes is implemented according to [CS00]
    and M.J. Wiener's "Safe Prime Generation with a Combined Sieve". */

void mpz_sprime_test
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize,
	int (*test)(mpz_ptr, mpz_ptr), unsigned long int mr_iterations)
{
	unsigned long int R_q[SIEVE_SIZE], R_p[SIEVE_SIZE];
	size_t i = 0, fail = 0;
	mpz_t tmp, y, pm1, a;
	
	mpz_init(tmp), mpz_init(y), mpz_init(pm1), mpz_init_set_ui(a, 2L);
	
	/* Step 1. [CS00]: choose randomly an odd number $q$ of appropriate size */
	do
		mpz_srandomb(q, qsize);
	while ((mpz_sizeinbase(q, 2L) < qsize) || (mpz_even_p(q)));
	
	/* Compute $p = 2q + 1$. */
	mpz_mul_2exp(pm1, q, 1L),	mpz_add_ui(p, pm1, 1L);
	
	/* Initalize the sieves for testing divisability by small primes. */
	for (i = 0; i < SIEVE_SIZE; i++)
	{
		mpz_set_ui(tmp, primes[i]);
		/* R_q[i] = q mod primes[i] */
		mpz_mod(y, q, tmp);
		R_q[i] = mpz_get_ui(y);
		/* R_p[i] = (2q+1) mod primes[i] */
		mpz_mod(y, p, tmp);
		R_p[i] = mpz_get_ui(y);
	}
	
	while (1)
	{
		/* Increase $q$ by 2 (incremental prime number generator). */
		mpz_add_ui(q, q, 2L);
		
		/* Increase $p$ by 4 (actually compute $p = 2q + 1$). */
		mpz_add_ui(p, p, 4L), mpz_add_ui(pm1, pm1, 4L);
		
		/* Use the sieve optimization procedure of Note 4.51(ii) [HAC]. */
		for (i = 0, fail = 0; i < SIEVE_SIZE; i++)
		{
			/* Update the sieves. */
			R_q[i] += 2, R_q[i] %= primes[i], R_p[i] += 4, R_p[i] %= primes[i];
			/* Check whether R_q[i] or R_p[i] is zero. We cannot break this loop,
			   because we have to update our sieves completely for the next try. */
			if (!(R_q[i] && R_p[i]))
				fail = 1;
		}
		if (fail)
			continue;
		
		/* Additional tests? */
		if (!test(p, q))
			continue;
		
		/* Step 2. [CS00]: M.J. Wiener's "Combined Sieve"
		   Test whether either $q$ or $p$ are not divisable by any primes up to
		   some bound $B$. (We use the bound $B = 5000$ here.) */
		for (i = 0; i < PRIMES_SIZE; i++)
		{
			if (mpz_congruent_ui_p(q, primes_m1d2[i], primes[i]) ||
				mpz_congruent_ui_p(p, primes_m1d2[i], primes[i]))
					break;
			if (i >= SIEVE_SIZE)
			{
				if (mpz_congruent_ui_p(q, 0L, primes[i]) ||
					mpz_congruent_ui_p(p, 0L, primes[i]))
						break;
			}
			else
			{
				assert(!mpz_congruent_ui_p(q, 0L, primes[i]));
				assert(!mpz_congruent_ui_p(p, 0L, primes[i]));
			}
		}
		if (i < PRIMES_SIZE)
			continue;
		
		/* Optimization: do a single test for $q$ first */
		if (!mpz_probab_prime_p(q, 1))
			continue;
		fprintf(stderr, ".");
		
		/* Step 3. [CS00]: Test whether 2 is not a Miller-Rabin witness to the
		   compositeness of $q$. */
		if (mpz_mr_witness(q, a))
			continue;
		
		/* Step 4. [CS00]: Test whether $2^q \equiv \pm 1 \pmod{p}$. */
		mpz_powm(y, a, q, p);
		if ((mpz_cmp_ui(y, 1L) != 0) && (mpz_cmp(y, pm1) != 0))
			continue;
		
		/* Step 5. [CS00]: Apply the Miller-Rabin test to $q$ a defined number
		   of times (maximum error probability $4^{-mr_iterations}$) using
		   randomly selected bases. */
		if (mpz_probab_prime_p(q, mr_iterations - 1))
			break;
	}
	mpz_clear(tmp), mpz_clear(y), mpz_clear(pm1), mpz_clear(a);
	fprintf(stderr, "\n");
	
	assert(mpz_probab_prime_p(p, mr_iterations));
	assert(mpz_probab_prime_p(q, mr_iterations));
}

/** A naive generator for safe primes (slow for $\log_2 p \ge 1024$). */

void mpz_sprime_test_naive
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize,
	int (*test)(mpz_ptr, mpz_ptr), unsigned long int mr_iterations)
{
	size_t i = 0;
	
	/* Choose randomly an odd number $q$ of appropriate size. */
	do
		mpz_srandomb(q, qsize);
	while ((mpz_sizeinbase(q, 2L) < qsize) || (mpz_even_p(q)));
	
	while (1)
	{
		/* Increase $q$ by 2 (incremental prime number generator). */
		mpz_add_ui(q, q, 2L);
		/* Compute $p = 2q + 1$. */
		mpz_mul_2exp(p, q, 1L);
		mpz_add_ui(p, p, 1L);
		
		/* Additional tests? */
		if (!test(p, q))
			continue;
		
		/* Check whether either $q$ or $p$ are not divisable by any primes up to
		   some bound $B$. (We use the bound $B = 5000$ here.) */
		for (i = 0; i < PRIMES_SIZE; i++)
		{
			if (mpz_congruent_ui_p(q, primes_m1d2[i], primes[i]) ||
				mpz_congruent_ui_p(p, primes_m1d2[i], primes[i]) ||
				mpz_congruent_ui_p(q, 0L, primes[i]) ||
				mpz_congruent_ui_p(p, 0L, primes[i]))
					break;
		}
		if (i < PRIMES_SIZE)
			continue;
		
		if (!mpz_probab_prime_p(p, 1))
			continue;
		fprintf(stderr, ".");
		
		if (!mpz_probab_prime_p(q, mr_iterations))
			continue;
		
		if (mpz_probab_prime_p(p, mr_iterations - 1))
			break;
	}
	fprintf(stderr, "\n");
	
	assert(mpz_probab_prime_p(p, mr_iterations));
	assert(mpz_probab_prime_p(q, mr_iterations));
}

void mpz_sprime
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
	 unsigned long int mr_iterations)
{
	mpz_sprime_test(p, q, qsize, notest, mr_iterations);
}

void mpz_sprime_naive
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
	 unsigned long int mr_iterations)
{
	mpz_sprime_test_naive(p, q, qsize, notest, mr_iterations);
}

void mpz_sprime2g
	(mpz_ptr p, mpz_ptr q, unsigned long int qsize, 
	 unsigned long int mr_iterations)
{
	/* The additional test is e.g. necessary, if we want 2 as generator
	   of $\mathbb{QR}_p$. If $p$ is congruent 7 modulo 8, then 2 is a
	   quadratic residue and hence it will generate the cyclic subgroup
	   of prime order $q = (p-1)/2$. [RS00] */
	mpz_sprime_test(p, q, qsize, test2g, mr_iterations);
}

void mpz_sprime3mod4
	(mpz_ptr p, unsigned long int psize, unsigned long int mr_iterations)
{
	mpz_t q;

	/* This test is necessary, if we want to construct a Blum integer $n$,
	   i.e. a number where both factors are primes congruent 3 modulo 4. */
	mpz_init(q);
	mpz_sprime_test(p, q, psize - 1L, test3mod4, mr_iterations);
	mpz_clear(q);
}

void mpz_lprime
	(mpz_ptr p, mpz_ptr q, mpz_ptr k, 
	 unsigned long int psize, unsigned long int qsize, 
	 unsigned long int mr_iterations)
{
	mpz_t foo;
	unsigned long int cnt = 0;
	
	assert(psize > qsize);
	
	/* Choose randomly a prime number $q$ of appropriate size.
	   Primes of this type are only for public usage, because
	   we use weak random numbers here! */
	do
		mpz_wrandomb(q, qsize);
	while ((mpz_sizeinbase(q, 2L) < qsize) || 
		!mpz_probab_prime_p(q, mr_iterations));
	
	mpz_init(foo);
	do
	{
		/* Choose randomly an even number $k$ and compute $p:= qk + 1$. */
		do
			mpz_wrandomb(k, psize - qsize);
		while (mpz_sizeinbase(k, 2L) < (psize - qsize));
		if (mpz_odd_p(k))
			mpz_add_ui(k, k, 1L);
		mpz_mul(p, q, k);
		mpz_add_ui(p, p, 1L);
		/* Check wether $k$ and $q$ are coprime, i.e. $gcd(k, q) = 1$. */
		mpz_gcd(foo, k, q);
		if ((cnt++ % 100) == 0)
			fprintf(stderr, ".");
	}
	while (mpz_cmp_ui(foo, 1L) || (mpz_sizeinbase(p, 2L) < psize) || 
		!mpz_probab_prime_p(p, mr_iterations));
	mpz_clear(foo);
	fprintf(stderr, "\n");
	
	assert(mpz_probab_prime_p(p, mr_iterations));
	assert(mpz_probab_prime_p(q, mr_iterations));
}

void mpz_oprime
	(mpz_ptr p, unsigned long int psize, unsigned long int mr_iterations)
{
	unsigned long int cnt = 0;
	
	/* Choose randomly an odd number $p$ of appropriate size. */
	do
		mpz_srandomb(p, psize);
	while ((mpz_sizeinbase(p, 2L) < psize) || (mpz_even_p(p)));
	
	/* Add two as long as $p$ is not probable prime. */
	while (!mpz_probab_prime_p(p, mr_iterations))
	{
		mpz_add_ui(p, p, 2L);
		if ((cnt++ % 100) == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
}
