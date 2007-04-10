/*******************************************************************************
   Data structure for the secrets of a card. This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_VTMF_CardSecret_HH
	#define INCLUDED_VTMF_CardSecret_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C and STL header
	#include <cassert>
	#include <string>
	#include <iostream>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "parse_helper.hh"

/** @brief Data structure for secrets of the masking operation.
    
    This struct represents the secrets of the masking operation in the
    discrete logarithm instantiation of the general cryptographic
    primitive "Verifiable-k-out-of-k Threshold Masking Function" by
    Barnett and Smart [BS03]. */
struct VTMF_CardSecret
{
	/** @f$r\in\mathcal{R}@f$ is the randomizer of the masking operation.
	    It should be chosen uniformly and randomly from @f$\mathbb{Z}_q@f$
	    where @f$q@f$ is the order of the finite abelian group @f$G@f$ for
	    which the DDH assumption holds.
	
	    According to the results of Koshiba and Kurosawa [KK04] the length
	    of @f$r@f$ can be shorten to a reasonable value (e.g. 160 bit).
	    Under the additional DLSE assumption the necessary DDH problem in
	    @f$G@f$ seems to be still hard enough. Thus we can gain a great
	    performance advantage by using such short exponents. */
	mpz_t r;
	
	/** This constructor initializes all necessary resources. */
	VTMF_CardSecret
		();
	
	/** A simple copy-constructor.
	    @param that is the secret to be copied. */
	VTMF_CardSecret
		(const VTMF_CardSecret& that);
	
	/** A simple assignment-operator.
	    @param that is the secret to be assigned. */
	VTMF_CardSecret& operator =
		(const VTMF_CardSecret& that);
	
	/** This function imports the secret.
	    @param s is correctly formated input string.
	    @returns True, if the import was successful. */
	bool import
		(std::string s);
	
	/** This destructor releases all occupied resources. */
	~VTMF_CardSecret
		();
};

/** @relates VTMF_CardSecret
    This operator prints a secret to an output stream.
    @param out is the output stream.
    @param cardsecret is the secret to be printed. */
std::ostream& operator <<
	(std::ostream& out, const VTMF_CardSecret& cardsecret);

/** @relates VTMF_CardSecret
    This operator imports a secret from an input stream. It has to
    be delimited by a newline character.
    The failbit of the stream is set, if any parse error occured.
    @param in is the input stream.
    @param cardsecret is the secret to be imported. */
std::istream& operator >>
	(std::istream& in, VTMF_CardSecret& cardsecret);
#endif
