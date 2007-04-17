/*******************************************************************************
   SchindelhauerTMCG.cc, cryptographic |T|oolbox for |M|ental |C|ard |G|ames

     Christian Schindelhauer: 'A Toolbox for Mental Card Games',
     Technical Report A-98-14, University of L{\"u}beck, 1998.

   This file is part of LibTMCG.

 Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 
               Heiko Stamer <stamer@gaos.org>

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

#include "SchindelhauerTMCG.hh"

SchindelhauerTMCG::SchindelhauerTMCG
	(unsigned long int security, size_t k, size_t w):
		TMCG_SecurityLevel(security), TMCG_Players(k), TMCG_TypeBits(w)
{
	assert(TMCG_Players <= TMCG_MAX_PLAYERS);
	assert(TMCG_TypeBits <= TMCG_MAX_TYPEBITS);
	
	TMCG_MaxCardType = 1;
	for (size_t i = 0; i < TMCG_TypeBits; i++)
		TMCG_MaxCardType *= 2; // TMCG_MaxCardType = 2^{TMCG_TypeBits}
	
	// initialize the message space for the VTMF scheme
	message_space = new mpz_t[TMCG_MaxCardType]();
	for (size_t i = 0; i < TMCG_MaxCardType; i++)
		mpz_init_set_ui(message_space[i], 0L); // values are set later
}

void SchindelhauerTMCG::TMCG_ProveQuadraticResidue
	(const TMCG_SecretKey &key, mpz_srcptr t,
		std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> rr, ss;
	mpz_t foo, bar, lej, t_sqrt;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init(foo), mpz_init(bar), mpz_init(lej), mpz_init(t_sqrt);
	
	// compute mpz_sqrtmn (modular square root) of t
	assert(mpz_qrmn_p(t, key.p, key.q, key.m));
	mpz_sqrtmn_fast(t_sqrt, t, key.p, key.q, key.m,
		key.gcdext_up, key.gcdext_vq, key.pa1d4, key.qa1d4);
	
	// phase (P2)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		mpz_ptr r = new mpz_t(), s = new mpz_t();
		mpz_init(r), mpz_init(s);
		
		// choose uniformly at random a number $r \in Z^*_m$
		do
		{
			mpz_srandomm(r, key.m);
			mpz_gcd(lej, r, key.m);
		}
		while (mpz_cmp_ui(lej, 1L) || !mpz_cmp_ui(r, 1L));
		
		// compute $s := t_sqrt \cdot r_i^{-1} \bmod m$
		ret = mpz_invert(s, r, key.m);
		assert(ret);
		mpz_mul(s, s, t_sqrt);
		mpz_mod(s, s, key.m);
		assert(mpz_cmp_ui(s, 1L));
		
		// compute $R_i = r_i^2 \bmod m,\; S_i = s_i^2 \bmod m$
		mpz_mul(foo, r, r);
		mpz_mod(foo, foo, key.m);
		mpz_mul(bar, s, s);
		mpz_mod(bar, bar, key.m);
		
		// check the congruence $R_i \cdot S_i \equiv t \pmod{m}$
		#ifndef NDEBUG
			mpz_mul(lej, foo, bar);
			mpz_mod(lej, lej, key.m);
			assert(mpz_congruent_p(t, lej, key.m));
		#endif
		
		// store $r_i$, $s_i$ and send $R_i$, $S_i$ to the verifier
		rr.push_back(r), ss.push_back(s);
		out << foo << std::endl, out << bar << std::endl;
	}
	
	// phase (P4)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		// receive R/S-question from the verifier
		in >> foo;
		
		// send proof to the verifier
		if (mpz_get_ui(foo) & 1L)
			out << rr[i] << std::endl;
		else
			out << ss[i] << std::endl;
	}
	
	mpz_clear(foo), mpz_clear(bar), mpz_clear(lej), mpz_clear(t_sqrt);
	for (std::vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
		mpz_clear(*ri), delete *ri;
	for (std::vector<mpz_ptr>::iterator si = ss.begin(); si != ss.end(); si++)
		mpz_clear(*si), delete *si;
}

bool SchindelhauerTMCG::TMCG_VerifyQuadraticResidue
	(const TMCG_PublicKey &key, mpz_srcptr t, std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> RR, SS;
	mpz_t foo, bar, lej;
	out << TMCG_SecurityLevel << std::endl;
	
	// check whether $t \in Z^\circ_m$
	if (mpz_jacobi(t, key.m) != 1)
		return false;
	
	mpz_init(foo), mpz_init(bar), mpz_init(lej);
	try
	{
		// phase (V3)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr R = new mpz_t(), S = new mpz_t();
			mpz_init(R), mpz_init(S);
			
			// receive $R_i$, $S_i$ from the prover and store these values
			in >> R, in >> S;
			RR.push_back(R), SS.push_back(S);
			
			// check the congruence $R_i \cdot S_i \equiv t \pmod{m}$
			mpz_mul(foo, S, R);
			mpz_mod(foo, foo, key.m);
			if (!mpz_congruent_p(t, foo, key.m))
				throw false;
		}
		
		// phase (V4)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send R/S-question to the prover
			mpz_srandomb(foo, 1L);
			out << foo << std::endl;
			
			// receive the proof
			in >> bar;
			
			// verify either $R_i\equiv r_i^2\pmod{m}$ or $S_i\equiv s_i^2\pmod{m}$
			mpz_mul(lej, bar, bar);
			mpz_mod(lej, lej, key.m);
			
			if (((mpz_get_ui(foo) & 1L) && 
				(mpz_cmp(lej, RR[i]) || !mpz_cmp_ui(bar, 1L))) ||
				(!(mpz_get_ui(foo) & 1L) && 
				(mpz_cmp(lej, SS[i]) || !mpz_cmp_ui(bar, 1L))))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lej);
		for (std::vector<mpz_ptr>::iterator ri = RR.begin(); ri != RR.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (std::vector<mpz_ptr>::iterator si = SS.begin(); si != SS.end(); si++)
			mpz_clear(*si), delete *si;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProveNonQuadraticResidue
	(const TMCG_SecretKey &key, mpz_srcptr t, std::istream &in, std::ostream &out)
{
	mpz_t bar;
	mpz_init(bar);
	
	// compute bar = t * y^{-1} (mod m) and send it to verifier
	mpz_set(bar, t);
	mpz_mul(bar, bar, key.y1);
	mpz_mod(bar, bar, key.m);
	out << bar << std::endl;
	
	// QR-proof
	TMCG_ProveQuadraticResidue(key, bar, in, out);
	
	mpz_clear(bar);
	return;
}

bool SchindelhauerTMCG::TMCG_VerifyNonQuadraticResidue
	(const TMCG_PublicKey &key, mpz_srcptr t, std::istream &in, std::ostream &out)
{
	mpz_t foo, bar;
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// receive bar from prover
		in >> bar;
		
		// check congruence bar * y \cong t (mod m)
		mpz_mul(foo, bar, key.y);
		mpz_mod(foo, foo, key.m); 
		if (!mpz_congruent_p(t, foo, key.m))
			throw false;
		
		// verify QR-proof
		if (!TMCG_VerifyQuadraticResidue(key, bar, in, out))
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

void SchindelhauerTMCG::TMCG_MaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_ptr zz,
		mpz_srcptr r, mpz_srcptr b, bool TimingAttackProtection)
{
	if (TimingAttackProtection)
	{
		mpz_t tim;
		
		mpz_init(tim);
		// compute zz = z * r^2 * y^b (mod m)
		mpz_mul(zz, r, r);
		mpz_mod(zz, zz, key.m);
		mpz_mul(zz, zz, z);
		mpz_mod(zz, zz, key.m);
		if (mpz_get_ui(b) & 1L)
		{
			mpz_mul(zz, zz, key.y);
			mpz_mod(zz, zz, key.m);
		}
		else
		{
			// compute dummy value to prevent timing attacks
			mpz_mul(tim, zz, key.y);
			mpz_mod(tim, tim, key.m);
		}
		mpz_clear(tim);
	}
	else
	{
		// compute zz = z * r^2 * y^b (mod m)
		mpz_mul(zz, r, r);
		mpz_mod(zz, zz, key.m);
		mpz_mul(zz, zz, z);
		mpz_mod(zz, zz, key.m);
		if (mpz_get_ui(b) & 1L)
		{
			mpz_mul(zz, zz, key.y);
			mpz_mod(zz, zz, key.m);
		}
	}
}

void SchindelhauerTMCG::TMCG_ProveMaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
		mpz_srcptr r, mpz_srcptr b, std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> rr, bb;
	mpz_t foo, bar;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// phase (P2)
		for (unsigned long int i = 0; i < security_desire; i++)
		{
			mpz_ptr r2 = new mpz_t(), b2 = new mpz_t();
			mpz_init(r2), mpz_init(b2);
			
			// choose uniformly at random a number r_i \in Z^*_m and b_i \in {0,1}
			mpz_srandomb(b2, 1L);
			do
			{
				mpz_srandomm(r2, key.m);
				mpz_gcd(bar, r2, key.m);
			}
			while (mpz_cmp_ui(bar, 1L) || !mpz_cmp_ui(r2, 1L));
			rr.push_back(r2), bb.push_back(b2);
			
			// compute foo = zz * r2^2 * y^b2 (mod m)
			mpz_mul(foo, r2, r2);
			mpz_mod(foo, foo, key.m);
			mpz_mul(foo, foo, zz);
			mpz_mod(foo, foo, key.m);
			if (mpz_get_ui(b2) & 1L)
			{
				mpz_mul(foo, foo, key.y);
				mpz_mod(foo, foo, key.m);
			}
			else
			{
				// compute dummy value to prevent timing attacks
				mpz_mul(bar, foo, key.y);
				mpz_mod(bar, bar, key.m);
			}
			
			// send foo to verifier
			out << foo << std::endl;
		}
		
		// phase (P4)
		for (unsigned long int i = 0; i < security_desire; i++)
		{
			// receive Z/Z'-question from verifier
			in >> foo;
			
			// send proof to verifier
			if (mpz_get_ui(foo) & 1L)
			{
				out << rr[i] << std::endl, out << bb[i] << std::endl;
			}
			else
			{
				mpz_mul(foo, r, rr[i]);
				mpz_mod(foo, foo, key.m);
				if ((mpz_get_ui(b) & 1L) && (mpz_get_ui(bb[i]) & 1L))
				{
					mpz_mul(foo, foo, key.y);
					mpz_mod(foo, foo, key.m);
				}
				else
				{
					// compute dummy value to prevent timing attacks
					mpz_mul(bar, bar, key.y);
					mpz_mod(bar, bar, key.m);
				}
				mpz_add(bar, b, bb[i]);
				if (!(mpz_get_ui(bar) & 1L))
					mpz_set_ui(bar, 0L);
				out << foo << std::endl, out << bar << std::endl;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool excpetion)
	{
		mpz_clear(foo), mpz_clear(bar);
		for (std::vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (std::vector<mpz_ptr>::iterator bi = bb.begin(); bi != bb.end(); bi++)
			mpz_clear(*bi), delete *bi;
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyMaskValue
	(const TMCG_PublicKey &key, mpz_srcptr z, mpz_srcptr zz,
		std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> T;
	mpz_t foo, bar, lej;
	
	// send security parameter
	out << TMCG_SecurityLevel << std::endl;
	
	mpz_init(foo), mpz_init(bar), mpz_init(lej);
	try
	{
		// phase (V3)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr t = new mpz_t();
			mpz_init(t);
			
			// receive t_i from prover and store value
			in >> t;
			T.push_back(t);
		}
		
		// phase (V4)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send Z/Z'-question to prover
			mpz_srandomb(foo, 1L);
			out << foo << std::endl;
			
			// receive proof (r, b)
			in >> bar, in >> lej;
			
			// verify proof, store result of TMCG_MaskValue() in foo
			if (mpz_get_ui(foo) & 1L)
				TMCG_MaskValue(key, zz, foo, bar, lej);
			else
				TMCG_MaskValue(key, z, foo, bar, lej);
			if (mpz_cmp(foo, T[i]) || !mpz_cmp_ui(bar, 1L))
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lej);
		for (std::vector<mpz_ptr>::iterator ti = T.begin(); ti != T.end(); ti++)
			mpz_clear(*ti), delete *ti;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProveMaskOne
	(const TMCG_PublicKey &key, mpz_srcptr r, mpz_srcptr b,
		std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> rr, ss, bb, cc;
	mpz_t y1m, foo, bar, tim;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	// compute y1m = y^{-1} mod m
	mpz_init(y1m);
	ret = mpz_invert(y1m, key.y, key.m);
	assert(ret);
	
	mpz_init(foo), mpz_init(bar), mpz_init(tim);
	
	// phase (P2)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		mpz_ptr r3 = new mpz_t(), s = new mpz_t(),
			b3 = new mpz_t(), c = new mpz_t();
		mpz_init(r3), mpz_init(s), mpz_init(b3), mpz_init(c);
		
		// choose uniformly at random a number r_i \in Z*m and b \in {0,1}
		mpz_srandomb(b3, 1L);
		do
		{
			mpz_srandomm(r3, key.m);
			mpz_gcd(foo, r3, key.m);
		}
		while (mpz_cmp_ui(foo, 1L) || !mpz_cmp_ui(r3, 1L));
		rr.push_back(r3), bb.push_back(b3);
		
		// compute c_i
		if (mpz_cmp(b, b3) == 0)
			mpz_set_ui(c, 0L);
		else
			mpz_set_ui(c, 1L);
		
		// compute s_i
		ret = mpz_invert(s, r3, key.m);
		assert(ret);
		mpz_mul(s, s, r);
		mpz_mod(s, s, key.m);
		if ((mpz_cmp_ui(b, 0L) == 0) && (mpz_cmp_ui(b3, 1L) == 0))
		{
			mpz_mul(s, s, y1m);
			mpz_mod(s, s, key.m);
		}
		else
		{
			// compute dummy value to prevent timing attacks
			mpz_mul(tim, s, y1m);
			mpz_mod(tim, tim, key.m);
		}
		
		// store s_i, c_i
		ss.push_back(s), cc.push_back(c);
		
		// compute R_i = {r_i}^2 * y^b (mod m), S_i = {s_i}^2 * y^{c_i} (mod m)
		mpz_mul(foo, r3, r3);
		mpz_mod(foo, foo, key.m);
		if (mpz_get_ui(b3) & 1L)
		{
			mpz_mul(foo, foo, key.y);
			mpz_mod(foo, foo, key.m);
		}
		else
		{
			// compute dummy value to prevent timing attacks
			mpz_mul(tim, foo, key.y);
			mpz_mod(tim, tim, key.m);
		}
		mpz_mul(bar, s, s);
		mpz_mod(bar, bar, key.m);
		if (mpz_get_ui(c) & 1L)
		{
			mpz_mul(bar, bar, key.y);
			mpz_mod(bar, bar, key.m);
		}
		else
		{
			// compute dummy value to prevent timing attacks
			mpz_mul(tim, bar, key.y);
			mpz_mod(tim, tim, key.m);
		}
		
		// check congruence R_i * S_i \cong t (mod m)
		#ifndef NDEBUG
			mpz_t lej, t;
			mpz_init(lej), mpz_init(t);
			mpz_mul(t, r, r);
			mpz_mod(t, t, key.m);
			if (mpz_get_ui(b) & 1L)
			{
				mpz_mul(t, t, key.y);
				mpz_mod(t, t, key.m);
			}
			else
			{
				// compute dummy value to prevent timing attacks
				mpz_mul(tim, t, key.y);
				mpz_mod(tim, tim, key.m);
			}
			mpz_mul(lej, foo, bar);
			mpz_mod(lej, lej, key.m);
			assert(mpz_congruent_p(t, lej, key.m));
			mpz_clear(lej), mpz_clear(t);
		#endif
		
		// send R_i, S_i to verifier
		out << foo << std::endl, out << bar << std::endl;
	}
	
	// phase (P4)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		// receive R/S-question from verifier
		in >> foo;
		
		// send proof to verifier
		if (mpz_get_ui(foo) & 1L)
			out << rr[i] << std::endl, out << bb[i] << std::endl;
		else
			out << ss[i] << std::endl, out << cc[i] << std::endl;
	}
	
	mpz_clear(y1m), mpz_clear(foo), mpz_clear(bar), mpz_clear(tim);
	for (std::vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
		mpz_clear(*ri), delete *ri;
	for (std::vector<mpz_ptr>::iterator bi = bb.begin(); bi != bb.end(); bi++)
		mpz_clear(*bi), delete *bi;
	for (std::vector<mpz_ptr>::iterator si = ss.begin(); si != ss.end(); si++)
		mpz_clear(*si), delete *si;
	for (std::vector<mpz_ptr>::iterator ci = cc.begin(); ci != cc.end(); ci++)
		mpz_clear(*ci), delete *ci;
}

bool SchindelhauerTMCG::TMCG_VerifyMaskOne
	(const TMCG_PublicKey &key, mpz_srcptr t, std::istream &in, std::ostream &out)
{
	std::vector<mpz_ptr> RR, SS;
	mpz_t foo, bar, lej;
	
	// send security parameter
	out << TMCG_SecurityLevel << std::endl;
	
	mpz_init(foo), mpz_init(bar), mpz_init(lej);
	try
	{
		// phase (V3)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			mpz_ptr R = new mpz_t(), S = new mpz_t();
			mpz_init(R), mpz_init(S);
			
			// receive R_i, S_i from prover and store values
			in >> R, in >> S;
			RR.push_back(R), SS.push_back(S);
			
			// check congruence R_i * S_i \cong t (mod m)
			mpz_mul(foo, R, S);
			mpz_mod(foo, foo, key.m);
			if (!mpz_congruent_p(t, foo, key.m))
				throw false;
		}
		
		// phase (V4)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			// send R/S-question to prover
			mpz_srandomb(foo, 1L);
			out << foo << std::endl;
			
			// receive proof (r, b)
			in >> bar, in >> lej;
			
			// verify proof
			mpz_mul(lej, bar, bar);
			mpz_mod(lej, lej, key.m);
			if (mpz_get_ui(lej) & 1L)
			{
				mpz_mul(lej, lej, key.y);
				mpz_mod(lej, lej, key.m);
			}
			if (((mpz_get_ui(foo) & 1L) && 
				(mpz_cmp(lej, RR[i]) || !mpz_cmp_ui(bar, 1L))) ||
				(!(mpz_get_ui(foo) & 1L) && 
				(mpz_cmp(lej, SS[i]) || !mpz_cmp_ui(bar, 1L))))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{	
		mpz_clear(foo), mpz_clear(bar), mpz_clear(lej);
		for (std::vector<mpz_ptr>::iterator ri = RR.begin(); ri != RR.end(); ri++)
			mpz_clear(*ri), delete *ri;
		for (std::vector<mpz_ptr>::iterator si = SS.begin(); si != SS.end(); si++)
			mpz_clear(*si), delete *si;
		return return_value;
	}
}

void SchindelhauerTMCG::TMCG_ProveNonQuadraticResidue_PerfectZeroKnowledge
	(const TMCG_SecretKey &key, std::istream &in, std::ostream &out)
{
	TMCG_PublicKey key2(key);
	mpz_t foo, bar;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// phase (P2) and (P3)
		for (unsigned long int i = 0; i < security_desire; i++)
		{
			// receive question
			in >> foo;
			
			// verify proof of mask knowledge 1->foo
			if (TMCG_VerifyMaskOne(key2, foo, in, out))
			{
				if (mpz_qrmn_p(foo, key.p, key.q, key.m))
					mpz_set_ui(bar, 1L);
				else
					mpz_set_ui(bar, 0L);
				
				// send proof
				out << bar << std::endl;
			}
			else
				throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyNonQuadraticResidue_PerfectZeroKnowledge
	(const TMCG_PublicKey &key, std::istream &in, std::ostream &out)
{
	mpz_t foo, bar, r, b;
	
	// send security parameter
	out << TMCG_SecurityLevel << std::endl;
	
	mpz_init(foo), mpz_init(bar), mpz_init(r), mpz_init(b);
	try
	{
		// phase (V2) and (V3)
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			// choose uniformly at random a number r \in Z*m and b \in {0,1}
			mpz_srandomb(b, 1L);
			do
			{
				mpz_srandomm(r, key.m);
				mpz_gcd(foo, r, key.m);
			}
			while (mpz_cmp_ui(foo, 1L));
			
			// compute foo = r^2 * y^b (mod m)
			mpz_mul(foo, r, r);
			mpz_mod(foo, foo, key.m);
			if (mpz_get_ui(b) & 1L)
			{
				mpz_mul(foo, foo, key.y);
				mpz_mod(foo, foo, key.m);
			}
			else
			{
				// compute dummy value to prevent timing attacks
				mpz_mul(bar, foo, key.y);
				mpz_mod(bar, bar, key.m);
			}
			
			// send question to prover
			out << foo << std::endl;
			
			// proof of mask knowledge 1->foo
			TMCG_ProveMaskOne(key, r, b, in, out);
			
			// receive proof
			in >> bar;
			
			// verify proof
			if (((mpz_get_ui(b) & 1L) && (mpz_get_ui(bar) & 1L)) ||
				(!(mpz_get_ui(b) & 1L) && !(mpz_get_ui(bar) & 1L)))
					throw false;
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(r), mpz_clear(b);
		return return_value;
	}
}

// ============================================================================

void SchindelhauerTMCG::TMCG_CreateOpenCard
	(TMCG_Card &c, const TMCG_PublicKeyRing &ring, size_t type)
{
	assert(type < TMCG_MaxCardType);
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	
	for (size_t w = 0; w < c.z[0].size(); w++)
	{
		if (type & 1)
		{
			mpz_set(&c.z[0][w], ring.keys[0].y);
			--type, type /= 2;
		}
		else
		{
			mpz_set_ui(&c.z[0][w], 1L);
			type /= 2;
		}
	}
	
	for (size_t k = 1; k < c.z.size(); k++)
		for (size_t w = 0; w < c.z[k].size(); w++)
			mpz_set_ui(&c.z[k][w], 1L);
}

void SchindelhauerTMCG::TMCG_CreateOpenCard
	(VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf, size_t type)
{
	assert(type < TMCG_MaxCardType);
	
	if (type < TMCG_MaxCardType)
	{
		mpz_set_ui(c.c_1, 1L);
		// set the message space to an element from group G
		if (!mpz_cmp_ui(message_space[type], 0L))
			vtmf->IndexElement(message_space[type], type);
		mpz_set(c.c_2, message_space[type]);
	}
}

void SchindelhauerTMCG::TMCG_CreateCardSecret
	(TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring, size_t index)
{
	assert(cs.r.size() == ring.keys.size());
	assert(index < cs.r.size());
	
	mpz_t foo;
	
	mpz_init(foo);
	for (size_t k = 0; k < cs.r.size(); k++)
	{
		for (size_t w = 0; w < cs.r[k].size(); w++)
		{
			// choose uniformly at random a number r \in Z^*_m
			do
			{
				mpz_srandomm(&cs.r[k][w], ring.keys[k].m);
				mpz_gcd(foo, &cs.r[k][w], ring.keys[k].m);
			}
			while (mpz_cmp_ui(foo, 1L));
			
			// choose uniformly at random a bit b \in {0, 1}
			// or set it initially to zero in the index-th row
			if (k != index)
				mpz_srandomb(&cs.b[k][w], 1L);
			else
				mpz_set_ui(&cs.b[index][w], 0L);
		}
	}
	mpz_clear(foo);
	
	// XOR b_{ij} with i \neq index (keep type of this card)
	for (size_t k = 0; k < cs.r.size(); k++)
	{
		for (size_t w = 0; (k != index) && (w < cs.r[k].size()); w++)
		{
			if (mpz_get_ui(&cs.b[index][w]) & 1L)
			{
				if (mpz_get_ui(&cs.b[k][w]) & 1L)
					mpz_set_ui(&cs.b[index][w], 0L);
				else
					mpz_set_ui(&cs.b[index][w], 1L);
			}
			else
			{
				if (mpz_get_ui(&cs.b[k][w]) & 1L)
					mpz_set_ui(&cs.b[index][w], 1L);
				else
					mpz_set_ui(&cs.b[index][w], 0L);
			}
		}
	}
}

void SchindelhauerTMCG::TMCG_CreateCardSecret
	(VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf)
{
	vtmf->MaskingValue(cs.r);
}

void SchindelhauerTMCG::TMCG_CreatePrivateCard
	(TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
	size_t index, size_t type)
{
	assert(type < TMCG_MaxCardType);
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	assert(c.z.size() == cs.r.size());
	assert(c.z[0].size() == cs.r[0].size());
	assert(cs.r.size() == ring.keys.size());
	assert(index < cs.r.size());
	
	TMCG_Card oc(TMCG_Players, TMCG_TypeBits);
	TMCG_CreateOpenCard(oc, ring, type);
	TMCG_CreateCardSecret(cs, ring, index);
	TMCG_MaskCard(oc, c, cs, ring);
}

void SchindelhauerTMCG::TMCG_CreatePrivateCard
	(VTMF_Card &c, VTMF_CardSecret &cs, BarnettSmartVTMF_dlog *vtmf,
	size_t type)
{
	assert(type < TMCG_MaxCardType);
	
	// set message space to an element from group G
	if (!mpz_cmp_ui(message_space[type], 0L))
		vtmf->IndexElement(message_space[type], type);
	vtmf->VerifiableMaskingProtocol_Mask(message_space[type],
		c.c_1, c.c_2, cs.r);
}

void SchindelhauerTMCG::TMCG_MaskCard
	(const TMCG_Card &c, TMCG_Card &cc, const TMCG_CardSecret &cs,
	const TMCG_PublicKeyRing &ring, bool TimingAttackProtection)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	assert((c.z.size() == cc.z.size()) && (c.z[0].size() == cc.z[0].size()));
	assert((c.z.size() == cs.r.size()) && (c.z[0].size() == cs.r[0].size()));
	
	for (size_t k = 0; k < c.z.size(); k++)
		for (size_t w = 0; w < c.z[k].size(); w++)
			TMCG_MaskValue(ring.keys[k], &c.z[k][w], &cc.z[k][w],
				&cs.r[k][w], &cs.b[k][w], TimingAttackProtection);
}

void SchindelhauerTMCG::TMCG_MaskCard
	(const VTMF_Card &c, VTMF_Card &cc, const VTMF_CardSecret &cs,
	BarnettSmartVTMF_dlog *vtmf, bool TimingAttackProtection)
{
	vtmf->VerifiableRemaskingProtocol_Remask(c.c_1, c.c_2, cc.c_1, cc.c_2,
		cs.r, TimingAttackProtection);
}

void SchindelhauerTMCG::TMCG_ProveMaskCard
	(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_CardSecret &cs,
	const TMCG_PublicKeyRing &ring, std::istream &in, std::ostream &out)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	assert((c.z.size() == cc.z.size()) && (c.z[0].size() == cc.z[0].size()));
	assert((c.z.size() == cs.r.size()) && (c.z[0].size() == cs.r[0].size()));
	
	for (size_t k = 0; k < c.z.size(); k++)
		for (size_t w = 0; w < c.z[k].size(); w++)
			TMCG_ProveMaskValue(ring.keys[k], &c.z[k][w], &cc.z[k][w],
				&cs.r[k][w], &cs.b[k][w], in, out);
}

void SchindelhauerTMCG::TMCG_ProveMaskCard
	(const VTMF_Card &c, const VTMF_Card &cc, const VTMF_CardSecret &cs,
	BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out)
{
	vtmf->VerifiableRemaskingProtocol_Prove(c.c_1, c.c_2, cc.c_1, cc.c_2,
		cs.r, out);
}

bool SchindelhauerTMCG::TMCG_VerifyMaskCard
	(const TMCG_Card &c, const TMCG_Card &cc, const TMCG_PublicKeyRing &ring,
		std::istream &in, std::ostream &out)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	assert((c.z.size() == cc.z.size()) && (c.z[0].size() == cc.z[0].size()));
	
	for (size_t k = 0; k < c.z.size(); k++)
		for (size_t w = 0; w < c.z[k].size(); w++)
			if (!TMCG_VerifyMaskValue(ring.keys[k], &c.z[k][w], &cc.z[k][w], in, out))
				return false;
	return true;
}

bool SchindelhauerTMCG::TMCG_VerifyMaskCard
	(const VTMF_Card &c, const VTMF_Card &cc, BarnettSmartVTMF_dlog *vtmf,
	std::istream &in, std::ostream &out)
{
	if (!vtmf->VerifiableRemaskingProtocol_Verify(c.c_1, c.c_2, cc.c_1,
		cc.c_2, in))
			return false;
	return true;
}

void SchindelhauerTMCG::TMCG_ProvePrivateCard
	(const TMCG_CardSecret &cs, const TMCG_PublicKeyRing &ring,
	std::istream &in, std::ostream &out)
{
	assert(cs.r.size() == TMCG_Players);
	assert(cs.r[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	
	for (size_t k = 0; k < cs.r.size(); k++)
		for (size_t w = 0; w < cs.r[k].size(); w++)
			TMCG_ProveMaskOne(ring.keys[k], &cs.r[k][w], &cs.b[k][w], in, out);
}

bool SchindelhauerTMCG::TMCG_VerifyPrivateCard
	(const TMCG_Card &c, const TMCG_PublicKeyRing &ring,
	std::istream &in, std::ostream &out)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(ring.keys.size() == TMCG_Players);
	
	for (size_t k = 0; k < c.z.size(); k++)
		for (size_t w = 0; w < c.z[k].size(); w++)
			if (!TMCG_VerifyMaskOne(ring.keys[k], &c.z[k][w], in, out))
				return false;
	return true;
}

void SchindelhauerTMCG::TMCG_ProveCardSecret
	(const TMCG_Card &c, const TMCG_SecretKey &key, size_t index,
		std::istream &in, std::ostream &out)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert(c.z.size() > index);
	
	for (size_t w = 0; w < c.z[0].size(); w++)
	{
		if (mpz_qrmn_p(&c.z[index][w], key.p, key.q, key.m))
		{
			out << "0" << std::endl;
			TMCG_ProveQuadraticResidue(key, &c.z[index][w], in, out);
		}
		else
		{
			out << "1" << std::endl;
			TMCG_ProveNonQuadraticResidue(key, &c.z[index][w], in, out);
		}
	}
}

void SchindelhauerTMCG::TMCG_ProveCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
	std::istream &in, std::ostream &out)
{
	vtmf->VerifiableDecryptionProtocol_Prove(c.c_1, out);
}

bool SchindelhauerTMCG::TMCG_VerifyCardSecret
	(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_PublicKey &key,
	size_t index, std::istream &in, std::ostream &out)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert((c.z.size() == cs.r.size()) && (c.z[0].size() == cs.r[0].size()));
	assert(c.z.size() > index);
	
	try
	{
		for (size_t w = 0; w < c.z[0].size(); w++)
		{
			in >> &cs.b[index][w];
			mpz_set_ui(&cs.r[index][w], 0L);
			if (mpz_get_ui(&cs.b[index][w]) & 1L)
			{
				if (!TMCG_VerifyNonQuadraticResidue(key, &c.z[index][w], in, out))
					throw false;
			}
			else
			{
				if (!TMCG_VerifyQuadraticResidue(key, &c.z[index][w], in, out))
					throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf,
		std::istream &in, std::ostream &out)
{
	if (!vtmf->VerifiableDecryptionProtocol_Verify_Update(c.c_1, in))
		return false;
	return true;
}

void SchindelhauerTMCG::TMCG_SelfCardSecret
	(const TMCG_Card &c, TMCG_CardSecret &cs, const TMCG_SecretKey &key,
		size_t index)
{
	assert(c.z.size() == TMCG_Players);
	assert(c.z[0].size() == TMCG_TypeBits);
	assert((c.z.size() == cs.r.size()) && (c.z[0].size() == cs.r[0].size()));
	assert(c.z.size() > index);
	
	for (size_t w = 0; w < c.z[0].size(); w++)
	{
		mpz_set_ui(&cs.r[index][w], 0L);
		if (mpz_qrmn_p(&c.z[index][w], key.p, key.q, key.m))
			mpz_set_ui(&cs.b[index][w], 0L);
		else
			mpz_set_ui(&cs.b[index][w], 1L);
	}
}

void SchindelhauerTMCG::TMCG_SelfCardSecret
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf)
{
	vtmf->VerifiableDecryptionProtocol_Verify_Initialize(c.c_1);
}

size_t SchindelhauerTMCG::TMCG_TypeOfCard
	(const TMCG_CardSecret &cs)
{
	assert(cs.r.size() == TMCG_Players);
	assert(cs.r[0].size() == TMCG_TypeBits);
	
	size_t type = 0, p2 = 1;
	
	for (size_t w = 0; w < cs.r[0].size(); w++)
	{
		bool bit = false;
		for (size_t k = 0; k < cs.r.size(); k++)
		{
			if (mpz_get_ui(&cs.b[k][w]) & 1L)
				bit = !bit;
		}
		if (bit)
			type += p2;
		p2 *= 2;
	}
	return type;
}

size_t SchindelhauerTMCG::TMCG_TypeOfCard
	(const VTMF_Card &c, BarnettSmartVTMF_dlog *vtmf)
{
	size_t type = TMCG_MaxCardType;
	mpz_t m;
	
	mpz_init_set_ui(m, 0L);
	vtmf->VerifiableDecryptionProtocol_Verify_Finalize(c.c_2, m);
	
	for (size_t t = 0; t < TMCG_MaxCardType; t++)
	{
		// set message space to an element from group G
		if (!mpz_cmp_ui(message_space[t], 0L))
			vtmf->IndexElement(message_space[t], t);
		if (!mpz_cmp(m, message_space[t]))
		{
			type = t;
			break;
		}
	}
	mpz_clear(m);
	return type;
}

// ============================================================================

// create a random permutation (Knuth or Fisher-Yates algorithm)
void random_permutation_fast
	(size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
		pi.push_back(i);
	
	for (size_t i = 0; i < (n - 1); i++)
	{
		size_t tmp = pi[i], rnd = i + mpz_srandom_mod(n - i);
		pi[i] = pi[rnd];
		pi[rnd] = tmp;
	}
}

size_t SchindelhauerTMCG::TMCG_CreateStackSecret
	(TMCG_StackSecret<TMCG_CardSecret> &ss, bool cyclic,
		const TMCG_PublicKeyRing &ring, size_t index, size_t size)
{
	assert(ring.keys.size() == TMCG_Players);
	assert(ring.keys.size() > index);
	assert(size <= TMCG_MAX_CARDS);
	
	size_t cyc = 0;
	std::vector<size_t> pi;
	
	ss.clear();
	if (cyclic)
		cyc = (size_t)mpz_srandom_mod(size);
	else
		random_permutation_fast(size, pi); // Knuth's algorithm

	for (size_t i = 0; i < size; i++)
	{
		TMCG_CardSecret cs(TMCG_Players, TMCG_TypeBits);
		TMCG_CreateCardSecret(cs, ring, index);
		
		ss.push(((cyclic) ? (cyc + i) % size : pi[i]), cs);
	}
	return cyc;
}

size_t SchindelhauerTMCG::TMCG_CreateStackSecret
	(TMCG_StackSecret<VTMF_CardSecret> &ss, bool cyclic, size_t size,
	BarnettSmartVTMF_dlog *vtmf)
{
	assert(size <= TMCG_MAX_CARDS);
	
	size_t cyc = 0;
	std::vector<size_t> pi;
	
	ss.clear();
	if (cyclic)
		cyc = (size_t)mpz_srandom_mod(size);
	else
		random_permutation_fast(size, pi); // Knuth's algorithm
	
	for (size_t i = 0; i < size; i++)
	{
		VTMF_CardSecret cs;
		TMCG_CreateCardSecret(cs, vtmf);
		
		ss.push(((cyclic) ? (cyc + i) % size : pi[i]), cs);
	}
	return cyc;
}

void SchindelhauerTMCG::TMCG_MixStack
	(const TMCG_Stack<TMCG_Card> &s, TMCG_Stack<TMCG_Card> &s2,
	const TMCG_StackSecret<TMCG_CardSecret> &ss,
	const TMCG_PublicKeyRing &ring, bool TimingAttackProtection)
{
	assert(ring.keys.size() == TMCG_Players);
	assert(s.size() == ss.size());
	
	// mask all cards, permutate, and build a new stack
	s2.clear();
	for (size_t i = 0; i < s.size(); i++)
	{
		TMCG_Card c(TMCG_Players, TMCG_TypeBits);
		TMCG_MaskCard(s[ss[i].first], c, ss[ss[i].first].second, ring,
			TimingAttackProtection);
		s2.push(c);
	}
}

void SchindelhauerTMCG::TMCG_MixStack
	(const TMCG_Stack<VTMF_Card> &s, TMCG_Stack<VTMF_Card> &s2,
	const TMCG_StackSecret<VTMF_CardSecret> &ss, BarnettSmartVTMF_dlog *vtmf,
	bool TimingAttackProtection)
{
	assert(s.size() == ss.size());
	
	// mask all cards, permutate, and build a new stack
	s2.clear();
	for (size_t i = 0; i < s.size(); i++)
	{
		VTMF_Card c;
		TMCG_MaskCard(s[ss[i].first], c, ss[ss[i].first].second, vtmf,
			TimingAttackProtection);
		s2.push(c);
	}
}

void SchindelhauerTMCG::TMCG_GlueStackSecret
	(const TMCG_StackSecret<TMCG_CardSecret> &sigma,
	TMCG_StackSecret<TMCG_CardSecret> &pi, const TMCG_PublicKeyRing &ring)
{
	assert(sigma.size() == pi.size());
	
	mpz_t tim;
	TMCG_StackSecret<TMCG_CardSecret> ss3;
	
	mpz_init(tim);
	for (size_t i = 0; i < sigma.size(); i++)
	{
		TMCG_CardSecret cs(TMCG_Players, TMCG_TypeBits);
		TMCG_CreateCardSecret(cs, ring, 0);
		size_t sigma_idx = i, pi_idx = sigma.find_position(i);
		
		assert(pi_idx < sigma.size());
		
		for (size_t k = 0; k < TMCG_Players; k++)
		{
			for (size_t w = 0; w < TMCG_TypeBits; w++)
			{
				// compute r
				mpz_mul(&cs.r[k][w], &(sigma[sigma_idx].second).r[k][w],
					&(pi[pi_idx].second).r[k][w]);
				mpz_mod(&cs.r[k][w], &cs.r[k][w], ring.keys[k].m);
				if ((mpz_get_ui(&(sigma[sigma_idx].second).b[k][w]) & 1L) &&
					(mpz_get_ui(&(pi[pi_idx].second).b[k][w]) & 1L))
				{
					mpz_mul(&cs.r[k][w], &cs.r[k][w], ring.keys[k].y);
					mpz_mod(&cs.r[k][w], &cs.r[k][w], ring.keys[k].m);
				}
				else
				{
					// compute dummy value to prevent timing attacks
					mpz_mul(tim, &cs.r[k][w], ring.keys[k].y);
					mpz_mod(tim, tim, ring.keys[k].m);
				}
				
				// XOR
				if (mpz_get_ui(&(sigma[sigma_idx].second).b[k][w]) & 1L)
				{
					if (mpz_get_ui(&(pi[pi_idx].second).b[k][w]) & 1L)
						mpz_set_ui(&cs.b[k][w], 0L);
					else
						mpz_set_ui(&cs.b[k][w], 1L);
				}
				else
				{
					if (mpz_get_ui(&(pi[pi_idx].second).b[k][w]) & 1L)
						mpz_set_ui(&cs.b[k][w], 1L);
					else
						mpz_set_ui(&cs.b[k][w], 0L);
				}
			}
		}
		ss3.push(sigma[pi[i].first].first, cs);
	}
	pi.clear();
	for (size_t i = 0; i < ss3.size(); i++)
		pi.push(ss3[i].first, ss3[i].second);
	mpz_clear(tim);
}

void SchindelhauerTMCG::TMCG_GlueStackSecret
	(const TMCG_StackSecret<VTMF_CardSecret> &sigma,
	TMCG_StackSecret<VTMF_CardSecret> &pi, BarnettSmartVTMF_dlog *vtmf)
{
	assert(sigma.size() == pi.size());
	
	TMCG_StackSecret<VTMF_CardSecret> ss3;
	for (size_t i = 0; i < sigma.size(); i++)
	{
		VTMF_CardSecret cs;
		size_t sigma_idx = i, pi_idx = sigma.find_position(i);
		
		assert(pi_idx < sigma.size());
		
		mpz_add(cs.r, (sigma[sigma_idx].second).r, (pi[pi_idx].second).r);
		mpz_mod(cs.r, cs.r, vtmf->q);
		ss3.push(sigma[pi[i].first].first, cs);
	}
	pi.clear();
	for (size_t i = 0; i < ss3.size(); i++)
		pi.push(ss3[i].first, ss3[i].second);
}

void SchindelhauerTMCG::TMCG_ProveStackEquality
	(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2,
	const TMCG_StackSecret<TMCG_CardSecret> &ss, bool cyclic,
	const TMCG_PublicKeyRing &ring, size_t index,
	std::istream &in, std::ostream &out)
{
	assert(ring.keys.size() == TMCG_Players);
	assert((s.size() == s2.size()) && (s.size() == ss.size()));
	
	mpz_t foo;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init(foo);
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		TMCG_Stack<TMCG_Card> s3;
		TMCG_StackSecret<TMCG_CardSecret> ss2;
		
		// create and mix the stack
		TMCG_CreateStackSecret(ss2, cyclic, ring, index, s.size());
		TMCG_MixStack(s2, s3, ss2, ring);
		
		if (TMCG_HASH_COMMITMENT)
		{
			// send only the hash value (instead of the whole stack)
			std::ostringstream ost;
			ost << s3 << std::endl;
			mpz_shash(foo, ost.str());
			out << foo << std::endl;
		}
		else
		{
			// send the whole stack (commitment)
			out << s3 << std::endl;
		}
		
		// receive question
		in >> foo;
		
		// send proof
		if (!(mpz_get_ui(foo) & 1L))
			TMCG_GlueStackSecret(ss, ss2, ring);
		out << ss2 << std::endl;
	}
	mpz_clear(foo);
}

void SchindelhauerTMCG::TMCG_ProveStackEquality
	(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
	const TMCG_StackSecret<VTMF_CardSecret> &ss, bool cyclic,
	BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out)
{
	assert((s.size() == s2.size()) && (s.size() == ss.size()));
	
	mpz_t foo;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');
	
	mpz_init(foo);
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		TMCG_Stack<VTMF_Card> s3;
		TMCG_StackSecret<VTMF_CardSecret> ss2;
		
		// create and mix stack
		TMCG_CreateStackSecret(ss2, cyclic, s.size(), vtmf);
		TMCG_MixStack(s2, s3, ss2, vtmf);
		
		if (TMCG_HASH_COMMITMENT)
		{
			// send hash value (instead of the whole stack)
			std::ostringstream ost;
			ost << s3 << std::endl;
			mpz_shash(foo, ost.str());
			out << foo << std::endl;
		}
		else
		{
			// send the whole stack (commitment)
			out << s3 << std::endl;
		}
		
		// receive question
		in >> foo;
		
		// send proof
		if (!(mpz_get_ui(foo) & 1L))
			TMCG_GlueStackSecret(ss, ss2, vtmf);
		out << ss2 << std::endl;
	}
	mpz_clear(foo);
}

void SchindelhauerTMCG::TMCG_InitializeStackEquality_Groth
	(std::vector<size_t> &pi, std::vector<mpz_ptr> &R,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
	const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
	const TMCG_StackSecret<VTMF_CardSecret> &ss)
{
	for (size_t i = 0; i < s.size(); i++)
	{
		pi.push_back(ss[i].first);
		mpz_ptr tmp = new mpz_t(), tmp4 = new mpz_t(), tmp5 = new mpz_t(),
			tmp6 = new mpz_t(), tmp7 = new mpz_t();
		mpz_init_set(tmp, ss[ss[i].first].second.r),
			mpz_init_set(tmp4, s[i].c_1), mpz_init_set(tmp5, s[i].c_2),
			mpz_init_set(tmp6, s2[i].c_1), mpz_init_set(tmp7, s2[i].c_2);
		R.push_back(tmp),
			e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5)),
			E.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp6, tmp7));
	}
}

void SchindelhauerTMCG::TMCG_InitializeStackEquality_Groth
	(std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &E,
	const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2)
{
	for (size_t i = 0; i < s.size(); i++)
	{
		mpz_ptr tmp4 = new mpz_t(), tmp5 = new mpz_t(),
			tmp6 = new mpz_t(), tmp7 = new mpz_t();
		mpz_init_set(tmp4, s[i].c_1), mpz_init_set(tmp5, s[i].c_2),
			mpz_init_set(tmp6, s2[i].c_1), mpz_init_set(tmp7, s2[i].c_2);
		e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5)),
			E.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp6, tmp7));
	}
}

void SchindelhauerTMCG::TMCG_ReleaseStackEquality_Groth
	(std::vector<size_t> &pi, std::vector<mpz_ptr> &R,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &E)
{
	for (size_t i = 0; i < pi.size(); i++)
	{
		mpz_clear(R[i]), delete R[i];
		mpz_clear(e[i].first), mpz_clear(e[i].second);
		delete e[i].first, delete e[i].second;
		mpz_clear(E[i].first), mpz_clear(E[i].second);
		delete E[i].first, delete E[i].second;
	}
	pi.clear(), R.clear(), e.clear(), E.clear();
}

void SchindelhauerTMCG::TMCG_ReleaseStackEquality_Groth
	(std::vector<std::pair<mpz_ptr, mpz_ptr> > &e,
	std::vector<std::pair<mpz_ptr, mpz_ptr> > &E)
{
	for (size_t i = 0; i < e.size(); i++)
	{
		mpz_clear(e[i].first), mpz_clear(e[i].second);
		delete e[i].first, delete e[i].second;
		mpz_clear(E[i].first), mpz_clear(E[i].second);
		delete E[i].first, delete E[i].second;
	}
	e.clear(), E.clear();
}

void SchindelhauerTMCG::TMCG_ProveStackEquality_Groth
	(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
	const TMCG_StackSecret<VTMF_CardSecret> &ss,
	BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
	std::istream &in, std::ostream &out)
{
	assert((s.size() == s2.size()) && (s.size() == ss.size()));
	assert(!mpz_cmp(vtmf->h, vsshe->com->h));
	assert(!mpz_cmp(vtmf->q, vsshe->com->q));
	assert(!mpz_cmp(vtmf->p, vsshe->p));
	assert(!mpz_cmp(vtmf->q, vsshe->q));
	assert(!mpz_cmp(vtmf->g, vsshe->g));
	assert(!mpz_cmp(vtmf->h, vsshe->h));
	assert((s.size() <= vsshe->com->g.size()));
	
	std::vector<mpz_ptr> R;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
	std::vector<size_t> pi;
	
	TMCG_InitializeStackEquality_Groth(pi, R, e, E, s, s2, ss);
	vsshe->Prove_interactive(pi, R, e, E, in, out);
	TMCG_ReleaseStackEquality_Groth(pi, R, e, E);
}

bool SchindelhauerTMCG::TMCG_VerifyStackEquality
	(const TMCG_Stack<TMCG_Card> &s, const TMCG_Stack<TMCG_Card> &s2, bool cyclic,
	const TMCG_PublicKeyRing &ring, std::istream &in, std::ostream &out)
{
	mpz_t foo, bar;
	
	out << TMCG_SecurityLevel << std::endl;
	
	if (s.size() != s2.size())
		return false;
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			TMCG_Stack<TMCG_Card> s3, s4;
			TMCG_StackSecret<TMCG_CardSecret> ss;
			mpz_srandomb(foo, 1L);
			
			if (TMCG_HASH_COMMITMENT)
			{
				// receive commitment
				in >> bar;
			}
			else
			{
				// receive stack
				in >> s3;
				if (!in.good())
					throw false;
			}
			
			// send challenge to prover
			out << foo << std::endl;
			
			// receive equality proof
			in >> ss;
			if (!in.good())
				throw false;
			
			// verify equality proof
			if (mpz_get_ui(foo) & 1L)
				TMCG_MixStack(s2, s4, ss, ring, false);
			else
				TMCG_MixStack(s, s4, ss, ring, false);
			if (TMCG_HASH_COMMITMENT)
			{
				std::ostringstream ost;
				ost << s4 << std::endl;
				mpz_shash(foo, ost.str());
				if (mpz_cmp(foo, bar))
					throw false;
			}
			else
			{
				if (s3 != s4)
					throw false;
			}
			
			// verify cyclic shift
			if (cyclic)
			{
				size_t cy = ss[0].first;
				for (size_t j = 1; j < ss.size(); j++)
					if (((++cy) % ss.size()) != ss[j].first)
						throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyStackEquality
	(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2, bool cyclic,
	BarnettSmartVTMF_dlog *vtmf, std::istream &in, std::ostream &out)
{
	mpz_t foo, bar;
	
	out << TMCG_SecurityLevel << std::endl;
	
	if (s.size() != s2.size())
		return false;
	
	mpz_init(foo), mpz_init(bar);
	try
	{
		// check whether the elements of the shuffled stack belong to the group
		for (size_t i = 0; i < s2.size(); i++)
		{
			if (!vtmf->CheckElement(s2[i].c_1) || !vtmf->CheckElement(s2[i].c_2))
				throw false;
		}
		
		for (unsigned long int i = 0; i < TMCG_SecurityLevel; i++)
		{
			TMCG_Stack<VTMF_Card> s3, s4;
			TMCG_StackSecret<VTMF_CardSecret> ss;
			mpz_srandomb(foo, 1L);
			
			if (TMCG_HASH_COMMITMENT)
			{
				// receive commitment
				in >> bar;
			}
			else
			{
				// receive stack
				in >> s3;
				if (!in.good())
					throw false;
			}
			
			// send R/S-question to prover (challenge)
			out << foo << std::endl;
			
			// receive equality proof (response)
			in >> ss;
			if (!in.good())
				throw false;
			
			// verify equality proof
			if (mpz_get_ui(foo) & 1L)
				TMCG_MixStack(s2, s4, ss, vtmf, false);
			else
				TMCG_MixStack(s, s4, ss, vtmf, false);
			if (TMCG_HASH_COMMITMENT)
			{
				std::ostringstream ost;
				ost << s4 << std::endl;
				mpz_shash(foo, ost.str());
				if (mpz_cmp(foo, bar))
					throw false;
			}
			else
			{
				if (s3 != s4)
					throw false;
			}
			
			// verify cyclic shift
			if (cyclic)
			{
				size_t cy = ss[0].first;
				for (size_t j = 1; j < ss.size(); j++)
					if (((++cy) % ss.size()) != ss[j].first)
						throw false;
			}
		}
		
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		mpz_clear(foo), mpz_clear(bar);
		return return_value;
	}
}

bool SchindelhauerTMCG::TMCG_VerifyStackEquality_Groth
	(const TMCG_Stack<VTMF_Card> &s, const TMCG_Stack<VTMF_Card> &s2,
	BarnettSmartVTMF_dlog *vtmf, GrothVSSHE *vsshe,
	std::istream &in, std::ostream &out)
{
	// check whether the parameters of VSSHE and VTMF match
	if (mpz_cmp(vtmf->h, vsshe->com->h) || mpz_cmp(vtmf->q, vsshe->com->q) || 
		mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
		mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h) || 
		(s.size() > vsshe->com->g.size()))
			return false;
	
	if (s.size() != s2.size())
		return false;
	
	// check whether the elements of the shuffled stack belong to the group
	for (size_t i = 0; i < s2.size(); i++)
	{
		if (!vtmf->CheckElement(s2[i].c_1) || !vtmf->CheckElement(s2[i].c_2))
			return false;
	}
	
	std::vector<mpz_ptr> R;
	std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
	std::vector<size_t> pi;
	
	TMCG_InitializeStackEquality_Groth(e, E, s, s2);
	bool return_value = vsshe->Verify_interactive(e, E, in, out);
	TMCG_ReleaseStackEquality_Groth(e, E);
	
	return return_value;
}

void SchindelhauerTMCG::TMCG_MixOpenStack
	(const TMCG_OpenStack<TMCG_Card> &os, TMCG_OpenStack<TMCG_Card> &os2,
	const TMCG_StackSecret<TMCG_CardSecret> &ss, const TMCG_PublicKeyRing &ring)
{
	assert((os.size() != 0) && (os.size() == ss.size()));
	
	// mask all cards, mix, and build new open stack
	os2.clear();
	for (size_t i = 0; i < os.size(); i++)
	{
		TMCG_Card c(TMCG_Players, TMCG_TypeBits);
		TMCG_MaskCard((os[ss[i].first].second), c, (ss[ss[i].first].second), ring);
		os2.push(os[ss[i].first].first, c);
	}
}

void SchindelhauerTMCG::TMCG_MixOpenStack
	(const TMCG_OpenStack<VTMF_Card> &os, TMCG_OpenStack<VTMF_Card> &os2,
	const TMCG_StackSecret<VTMF_CardSecret> &ss, BarnettSmartVTMF_dlog *vtmf)
{
	assert((os.size() != 0) && (os.size() == ss.size()));
	
	// mask all cards, mix, and build new open stack
	os2.clear();
	for (size_t i = 0; i < os.size(); i++)
	{
		VTMF_Card c;
		TMCG_MaskCard((os[ss[i].first].second), c, (ss[ss[i].first].second), vtmf);
		os2.push(os[ss[i].first].first, c);
	}
}

SchindelhauerTMCG::~SchindelhauerTMCG
	()
{
	for (size_t i = 0; i < TMCG_MaxCardType; i++)
		mpz_clear(message_space[i]);
	delete [] message_space;
}
