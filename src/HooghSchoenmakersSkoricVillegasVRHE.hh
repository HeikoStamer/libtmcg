/*******************************************************************************
  HooghSchoenmakersSkoricVillegasVRHE.hh,
                         |V|erifiable |R|otation of |H|omomorphic |E|ncryptions

     Sebastiaan de Hoogh, Berry Schoenmakers, Boris Skoric, and Jose Villegas:
       'Verifiable Rotation of Homomorphic Encryptions',
     Public Key Cryptography 2009, LNCS 5443, pp. 393--410, Springer 2009.

   This file is part of LibTMCG.

 Copyright (C) 2009, 2015, 2016, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_HooghSchoenmakersSkoricVillegasVRHE_HH
	#define INCLUDED_HooghSchoenmakersSkoricVillegasVRHE_HH
	
// C and STL header
#include <cstdlib>
#include <iostream>
#include <vector>

// GNU multiple precision library
#include <gmp.h>
	
// erasure-free distributed coinflip protocol
#include "JareckiLysyanskayaASTC.hh"	

class HooghSchoenmakersSkoricVillegasPUBROTZK
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
	
	public:
		mpz_t						p, q, g, h;
		
		HooghSchoenmakersSkoricVillegasPUBROTZK
			(mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC);
		bool CheckElement
			(mpz_srcptr a) const;
		void Prove_interactive
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			std::istream &in, std::ostream &out) const;
		void Prove_interactive_publiccoin
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			JareckiLysyanskayaEDCF *edcf,
			std::istream &in, std::ostream &out) const;
		void Prove_noninteractive
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			std::ostream &out) const;
		bool Verify_interactive
			(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			std::istream &in, std::ostream &out) const;
		bool Verify_interactive_publiccoin
			(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			JareckiLysyanskayaEDCF *edcf,
			std::istream &in, std::ostream &out) const;
		bool Verify_noninteractive
			(const std::vector<mpz_ptr> &alpha, const std::vector<mpz_ptr> &c,
			std::istream &in) const;
		~HooghSchoenmakersSkoricVillegasPUBROTZK
			();
};

// =============================================================================

class HooghSchoenmakersSkoricVillegasVRHE
{
	private:
		mpz_t						*fpowm_table_g, *fpowm_table_h;
		HooghSchoenmakersSkoricVillegasPUBROTZK		*pub_rot_zk;
		const unsigned long int				F_size, G_size;
	
	public:
		mpz_t						p, q, g, h;
		
		HooghSchoenmakersSkoricVillegasVRHE
			(unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		HooghSchoenmakersSkoricVillegasVRHE
			(mpz_srcptr p_ENC, mpz_srcptr q_ENC, mpz_srcptr g_ENC, mpz_srcptr h_ENC,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		HooghSchoenmakersSkoricVillegasVRHE
			(std::istream &in,
			unsigned long int fieldsize = TMCG_DDH_SIZE,
			unsigned long int subgroupsize = TMCG_DLSE_SIZE);
		bool CheckGroup
			() const;
		bool CheckElement
			(mpz_srcptr a) const;
		void PublishGroup
			(std::ostream &out) const;
		void Prove_interactive
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			std::istream &in, std::ostream &out) const;
		void Prove_interactive_publiccoin
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			JareckiLysyanskayaEDCF *edcf,
			std::istream &in, std::ostream &out) const;
		void Prove_noninteractive
			(size_t r, const std::vector<mpz_ptr> &s,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			std::ostream &out) const;
		bool Verify_interactive
			(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			std::istream &in, std::ostream &out) const;
		bool Verify_interactive_publiccoin
			(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			JareckiLysyanskayaEDCF *edcf,
			std::istream &in, std::ostream &out) const;
		bool Verify_noninteractive
			(const std::vector<std::pair<mpz_ptr, mpz_ptr> > &X,
			const std::vector<std::pair<mpz_ptr, mpz_ptr> > &Y,
			std::istream &in) const;
		~HooghSchoenmakersSkoricVillegasVRHE
			();
};

#endif
