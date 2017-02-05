/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.hh,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     [CKPS01] Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

   This file is part of LibTMCG.

 Copyright (C) 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
	#include <unistd.h>

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

	// define some internal types
	typedef std::map<std::string, bool>	RBC_TagCheck;
	typedef std::map<std::string, size_t>	RBC_TagCount;
	typedef std::map<std::string, mpz_ptr>	RBC_TagMpz;
	typedef std::list<mpz_ptr>		RBC_BufferList;
	typedef std::vector<mpz_ptr>		RBC_Message;
	typedef std::vector<mpz_srcptr>		RBC_ConstMessage;

/* The following class implements an optimized version of Bracha's protocol described in [CKPS01].
   Additionally, a FIFO-ordered delivery based on sequence numbers has been implemented. 
   Original paper cited: G. Bracha: 'An asynchronous [(n - 1)/3]-resilient consensus protocol',
   Proc. 3rd ACM Symposium on Principles of Distributed Computing (PODC), pp. 154–162, 1984. */
class CachinKursawePetzoldShoupRBC
{
	private:
		size_t					aio_default_scheduler;
		time_t					aio_default_timeout;
		mpz_t					ID, whoami, s;
		RBC_BufferList				last_IDs;
		mpz_t					r_send, r_echo, r_ready, r_request, r_answer;
		std::vector<RBC_TagCheck>		send, echo, ready, request, answer;
		RBC_TagMpz				mbar, dbar;
		std::map<std::string, RBC_TagCount>	e_d, r_d;
		std::vector<RBC_BufferList>		buf_mpz, buf_msg;
		std::vector<bool>			deliver_error;
		std::list<RBC_Message>			deliver_buf;
		std::vector<mpz_ptr>			deliver_s;
	
	public:
		size_t					n, t, j;
		aiounicast				*aiou;

		CachinKursawePetzoldShoupRBC
			(const size_t n_in, const size_t t_in, const size_t j_in,
			aiounicast *aiou_in,
			const size_t aio_default_scheduler_in = aiounicast::aio_scheduler_roundrobin,
			const time_t aio_default_timeout_in = aiounicast::aio_timeout_very_long);
		void setID
			(const std::string ID_in);
		void unsetID
			();
		void Broadcast
			(mpz_srcptr m, const bool simulate_faulty_behaviour = false);
		bool Deliver
			(mpz_ptr m, size_t &i_out,
			size_t scheduler = aiounicast::aio_scheduler_default,
			time_t timeout = aiounicast::aio_timeout_default);
		bool DeliverFrom
			(mpz_ptr m, const size_t i_in,
			size_t scheduler = aiounicast::aio_scheduler_default,
			time_t timeout = aiounicast::aio_timeout_default);
		void Sync
			(time_t timeout = aiounicast::aio_timeout_default);
		~CachinKursawePetzoldShoupRBC
			();
};

#endif
