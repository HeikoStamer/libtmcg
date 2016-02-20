/*******************************************************************************
  aiobrodcast.hh, basic class for asynchronous broadcast protocols

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
	private:
		mpz_t			s;
	
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

			// initialize sequence counter
			mpz_init_set_ui(s, 0L);

			// initialize character counters
			numWrite = 0, numRead = 0;
		}

		void Broadcast
			(mpz_srcptr m)
		{
			mpz_add_ui(s, s, 1L); // increase sequence counter

			// broadcast
			for (size_t i = 0; i < n; i++)
			{
				if (i != j)
					aiou->Send(m, i);
			}
		}

		bool Deliver
			(mpz_ptr m, size_t &i_out)
		{
			for (size_t round = 0; round < timeout; round++)
			{
				for (size_t i = 0; i < n; i++)
				{
					if (i == j)
						continue;

					i_out = i;
					if (aiou->Receive(m, i))
					{
						return true;
					}
					else
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
				if (aiou->Receive(m, i_in))
				{
					return true;
				}
				else
					return false;
				sleep(1);
			}
			return false;
		}

		~aiobroadcast
			()
		{
			mpz_clear(s);
		}
};

#endif
