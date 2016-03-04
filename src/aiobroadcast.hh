/*******************************************************************************
  aiobrodcast.hh, basic class for asynchronous broadcast

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

#ifndef INCLUDED_aiobroadcast_HH
	#define INCLUDED_aiobroadcast_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <vector>
	
	// GNU multiple precision library
	#include <gmp.h>

	#include "aiounicast.hh"

class aiobroadcast
{
	public:
		size_t			n, t, j;
		size_t			numWrite, numRead;
		size_t			timeout;
		aiounicast		*aiou;

		aiobroadcast
			(size_t n_in, size_t t_in, size_t j_in, aiounicast *aiou_in,
			size_t timeout_in):
				n(n_in), t(t_in), j(j_in), timeout(timeout_in)
		{
			assert(t_in <= n_in);
			assert(j_in < n_in);
			assert(n_in == aiou_in->in.size());
			assert(aiou_in->in.size() == aiou_in->out.size());

			// initialize asynchonous unicast
			aiou = aiou_in;

			// initialize character counters
			numWrite = 0, numRead = 0;
		}

		void Broadcast
			(mpz_srcptr m)
		{
			// broadcast
			for (size_t i = 0; i < n; i++)
				aiou->Send(m, i);
		}

		void Broadcast
			(const std::vector<mpz_srcptr> &m)
		{
			for (size_t mm = 0; mm < m.size(); mm++)
				Broadcast(m[mm]);
		}

		bool Deliver
			(mpz_ptr m, size_t &i_out)
		{
			for (size_t round = 0; round < timeout; round++)
			{
				if (aiou->Receive(m, i_out))
				{
					return true;
				}
				else
				{
					// error reported for some party?
					if (i_out < n)
						return false;
				}
				sleep(1);
			}
			i_out = n; // timeout for all parties
			return false;
		}

		bool Deliver
			(std::vector<mpz_ptr> &m, size_t &i_out)
		{
			for (size_t round = 0; round < timeout; round++)
			{
				if (aiou->Receive(m, i_out))
				{
					return true;
				}
				else
				{
					// error reported for some party?
					if (i_out < n)
						return false;
				}
				sleep(1);
			}
			i_out = n; // timeout for all parties
			return false;				
		}

		bool DeliverFrom
			(mpz_ptr m, size_t i_in)
		{
			for (size_t round = 0; round < timeout; round++)
			{
				if (aiou->ReceiveFrom(m, i_in))
					return true;
				sleep(1);
			}
			return false; // error or timeout
		}

		bool DeliverFrom
			(std::vector<mpz_ptr> &m, size_t i_in)
		{
			for (size_t mm = 0; mm < m.size(); mm++)
			{
				if (!DeliverFrom(m[mm], i_in))
					return false;
			}
			return true;
		}

		~aiobroadcast
			()
		{
		}
};

#endif
