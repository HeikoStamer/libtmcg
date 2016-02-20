/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.hh,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_CachinKursawePetzoldShoupSEABP_HH
	#define INCLUDED_CachinKursawePetzoldShoupSEABP_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <algorithm>

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_spowm.h"
	#include "mpz_sprime.h"
	#include "mpz_helper.hh"
	#include "mpz_shash.hh"

	#include "aiounicast.hh"
	#include "aiobroadcast.hh"

class CachinKursawePetzoldShoupRBC : public aiobroadcast
{
	private:
		mpz_t		ID, whoami, s;
		mpz_t		r_send, r_echo, r_ready, r_request, r_answer;
	
	public:
		CachinKursawePetzoldShoupRBC
			(size_t n_in, size_t t_in, size_t j_in,
			aiounicast *aiou_in, size_t timeout_in,
			std::string ID_in);
		virtual void Broadcast
			(mpz_srcptr m);
		virtual bool Deliver
			(mpz_ptr m, size_t &i_out);
		virtual bool DeliverFrom
			(mpz_ptr m, size_t i_in);
		virtual ~CachinKursawePetzoldShoupRBC
			();
};

#endif
