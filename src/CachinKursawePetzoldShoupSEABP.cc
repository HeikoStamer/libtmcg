/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.cc,
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

#include "CachinKursawePetzoldShoupSEABP.hh"

CachinKursawePetzoldShoupRBC::CachinKursawePetzoldShoupRBC
	(size_t n_in, size_t t_in, size_t j_in,
	aiounicast *aiou_in, size_t timeout_in,
	std::string ID_in): aiobroadcast(n_in, t_in, j_in, aiou_in, timeout_in)
{
	assert(t_in <= n_in);
	assert(j_in < n_in);
	assert(n_in == aiou_in->in.size());
	assert(aiou_in->in.size() == aiou_in->out.size());

	// initialize basic parameters
	n = n_in, t = t_in, j = j_in, timeout = timeout_in;

	// initialize asynchonous unicast
	aiou = aiou_in;

	// initialize ID
	mpz_shash(ID, ID_in);

	// initialize whoami (called $j$ in the paper)
	mpz_init_set_ui(whoami, j);

	// initialize sequence counter
	mpz_init_set_ui(s, 0L);

	// initialize character counters
	numWrite = 0, numRead = 0;

	// initialize action tags
	mpz_init_set_ui(r_send, 1L);
	mpz_init_set_ui(r_echo, 2L);
	mpz_init_set_ui(r_ready, 3L);
	mpz_init_set_ui(r_request, 4L);
	mpz_init_set_ui(r_answer, 5L);	
}

void CachinKursawePetzoldShoupRBC::Broadcast
	(mpz_srcptr m)
{
	mpz_add_ui(s, s, 1L); // increase sequence counter

	// prepare message = (ID.j.s, r-send, m)
	std::vector<mpz_srcptr> message;
	message.push_back(ID);
	message.push_back(whoami);
	message.push_back(s);
	message.push_back(r_send);
	message.push_back(m);

	// broadcast message
	aiobroadcast::Broadcast(message);
}

bool CachinKursawePetzoldShoupRBC::Deliver
	(mpz_ptr m, size_t &i_out)
{
	return false;
}

bool CachinKursawePetzoldShoupRBC::DeliverFrom
	(mpz_ptr m, size_t i_in)
{
	return false;
}

CachinKursawePetzoldShoupRBC::~CachinKursawePetzoldShoupRBC
	()
{
	mpz_clear(ID), mpz_clear(whoami), mpz_clear(s);
	mpz_clear(r_send);
	mpz_clear(r_echo);
	mpz_clear(r_ready);
	mpz_clear(r_request);
	mpz_clear(r_answer);
}

