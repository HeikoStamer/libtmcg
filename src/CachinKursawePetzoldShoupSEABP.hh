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
	#include <map>
	#include <list>
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

/* The following class implements an optimized version of Bracha's protocol described in [CKPS01].
   Additionally, a FIFO-ordered delivery based on sequence numbers has been implemented. 
   Original paper cited: G. Bracha: 'An asynchronous [(n - 1)/3]-resilient consensus protocol',
   Proc. 3rd ACM Symposium on Principles of Distributed Computing (PODC), pp. 154–162, 1984. */
class CachinKursawePetzoldShoupRBC
{
	private:
		mpz_t								ID, whoami, s;
		std::list<mpz_ptr>						last_IDs;
		mpz_t								r_send, r_echo, r_ready, r_request, r_answer;
		std::vector< std::map<std::string, bool> >			send, echo, ready, request, answer;
		std::map<std::string, mpz_ptr>					mbar, dbar;
		std::map<std::string, std::map<std::string, size_t> >		e_d, r_d;
		std::vector< std::list<mpz_ptr> >				buf_mpz, buf_msg;
		std::vector<bool>						deliver_error;
		std::list< std::vector<mpz_ptr> >				deliver_buf;
		std::vector<mpz_ptr>						deliver_s;
	
	public:
		size_t								n, t, j;
		aiounicast							*aiou;

		CachinKursawePetzoldShoupRBC
			(const size_t n_in, const size_t t_in, const size_t j_in,
			aiounicast *aiou_in);
		void setID
			(const std::string ID_in);
		void unsetID
			();
		void Broadcast
			(mpz_srcptr m, const bool simulate_faulty_behaviour = false);
		bool Deliver
			(mpz_ptr m, size_t &i_out);
		bool DeliverFrom
			(mpz_ptr m, const size_t i_in);
		~CachinKursawePetzoldShoupRBC
			();
};

#endif
