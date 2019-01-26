/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.hh,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     [CKPS01] Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <map>
#include <list>

// GNU multiple precision library
#include <gmp.h>
	
// asynchronous unicast transmission of mpz_t
#include "aiounicast.hh"

// define some internal types for convenience
typedef std::map<std::string, bool>			RBC_TagCheck;
typedef std::map<std::string, size_t>		RBC_TagCount;
typedef std::map<std::string, mpz_ptr>		RBC_TagMpz;
typedef std::list<mpz_ptr>					RBC_BufferList;
typedef std::vector<mpz_ptr>				RBC_Message;
typedef std::vector<mpz_srcptr>				RBC_ConstMessage;
typedef std::list< RBC_Message >			RBC_VectorList;

/* The following class implements an optimized version of Bracha's protocol 
   described in [CKPS01]. Additionally, a FIFO-order deliver mechanism based on
   sequence numbers has been implemented. Original paper cited: G. Bracha: 'An
   asynchronous [(n-1)/3]-resilient consensus protocol', Proc. 3rd ACM Symposium
   on Principles of Distributed Computing (PODC), pp. 154–162, 1984.

   Note that Bracha's consensus algorithm is not implemented yet.*/
class CachinKursawePetzoldShoupRBC
{
	private:
		size_t									aio_default_scheduler;
		time_t									aio_default_timeout;
		const time_t							aio_timeout_vs;
		mpz_t									ID, whoami, s;
		RBC_BufferList							last_IDs, last_s;
		RBC_VectorList							last_deliver_s;
		mpz_t									r_send, r_echo, r_ready;
		mpz_t									r_request, r_answer;
		std::vector<RBC_TagCheck>				send, echo, ready;
		std::vector<RBC_TagCheck>				request, answer;
		RBC_TagMpz								mbar, dbar;
		std::map<std::string, RBC_TagCount>		e_d, r_d;
		std::vector<RBC_BufferList>				buf_mpz, buf_id, buf_msg;
		std::vector<bool>						deliver_error;
		std::list<RBC_Message>					deliver_buf;
		std::vector<mpz_ptr>					deliver_s;
		aiounicast*								aiou;
		static const size_t						sync_slices = 10;

		void InitializeMessage
			(RBC_Message &message);
		void InitializeMessage
			(RBC_Message &message,
			 const RBC_ConstMessage &source);
		void InitializeMessage
			(RBC_Message &message,
			 const RBC_Message &source);
		void AssignMessage
			(RBC_ConstMessage &message,
			 const RBC_Message &source);
		void TagMessage
			(std::string &tag,
			 const RBC_Message &message);
		void ReleaseMessage
			(RBC_Message &message);
	
	public:
		size_t									n, t, j;

		CachinKursawePetzoldShoupRBC
			(const size_t n_in,
			 const size_t t_in,
			 const size_t j_in,
			 aiounicast* aiou_in,
			 const size_t scheduler_in = aiounicast::aio_scheduler_roundrobin,
			 const time_t timeout_in = aiounicast::aio_timeout_extremely_long);
		void setID
			(const std::string &ID_in);
		void unsetID
			();
		void Broadcast
			(mpz_srcptr m,
			 const bool simulate_faulty_behaviour = false);
		bool Deliver
			(mpz_ptr m,
			 size_t &i_out,
			 size_t scheduler = aiounicast::aio_scheduler_default,
			 time_t timeout = aiounicast::aio_timeout_default);
		bool DeliverFrom
			(mpz_ptr m,
			 const size_t i_in,
			 size_t scheduler = aiounicast::aio_scheduler_default,
			 time_t timeout = aiounicast::aio_timeout_default);
		bool Sync
			(time_t timeout = aiounicast::aio_timeout_default,
			 const std::string tag = "");
		~CachinKursawePetzoldShoupRBC
			();
};

#endif

