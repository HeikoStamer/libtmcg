/*******************************************************************************
  iobroadcast.hh, basic class for broadcast protocols

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

#ifndef INCLUDED_iobroadcast_HH
	#define INCLUDED_iobroadcast_HH

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

	// GNU crypto library
	#include <gcrypt.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
	#include "mpz_srandom.h"
	#include "mpz_spowm.h"
	#include "mpz_sprime.h"
	#include "mpz_helper.hh"
	#include "mpz_shash.hh"

class iobroadcast
{
	private:
		size_t					n, t, j;
		mpz_t					s;
		std::vector<std::istream*>		in;
		std::vector<std::ostream*>		out;
	
	public:		
		iobroadcast
			(size_t n_in, size_t t_in, size_t j_in,
			std::vector<std::istream*> &in_in, std::vector<std::ostream*> &out_in):
				n(n_in), t(t_in), j(j_in)
		{
			assert(t_in <= n_in);
			assert(j_in < n_in);
			assert(n_in == in_in.size());
			assert(in_in.size() == out_in.size());

			// initialize input and output streams
			for (size_t i = 0; i < n_in; i++)
			{
				in.push_back(in_in[i]);
				out.push_back(out_in[i]);
			}

			// initialize sequence counter
			mpz_init_set_ui(s, 0L);
		}

		void Broadcast
			(mpz_srcptr m)
		{
			mpz_add_ui(s, s, 1L); // increase sequence counter
			for (size_t i = 0; i < n; i++)
			{
				if (i != j)
					*out[i] << m << std::endl;
			}
		}

		bool Deliver
			(mpz_ptr m, size_t &i_out)
		{
			for (size_t i = 0; i < n; i++)
			{
				if (i != j)
				{
					i_out = i;
					if (!in[i]->good())
					{
						return false;
					}
					else
					{
						*in[i] >> m;
						return true;
					}
				}
			}
			return false;
		}

		bool DeliverFrom
			(mpz_ptr m, size_t i_in)
		{
			std::streambuf *buf = in[i_in]->rdbuf();
			bool newline_received = false;
			char mbuf[4096];
			size_t mptr = 0;

			while (1)
			{
				if (!in[i_in]->good())
				{
					return false;
				}
				std::streamsize size = buf->in_avail();
				if (size > 0)
				{
std::cerr << "size = " << size << std::endl;
					char c = buf->sgetc();
					if (c == '\n')
					{
						c = 0;
						newline_received = true;
					}
					mbuf[mptr++] = c;
					if (mptr == sizeof(mbuf))
						return false;
				}
				if (newline_received)
				{
					if (mpz_set_str(m, mbuf, TMCG_MPZ_IO_BASE) < 0)
					{
						mpz_set_ui(m, 0L);
						return false;
					}
					return true;
				}
			}
			return false;
		}

		~iobroadcast
			()
		{
			mpz_clear(s);
			in.clear(), out.clear();
		}
};

#endif
