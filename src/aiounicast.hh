/*******************************************************************************
  aiounicast.hh, base class for asynchronous unicast transmission of mpz_t

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

#ifndef INCLUDED_aiounicast_HH
	#define INCLUDED_aiounicast_HH
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <ctime>
	#include <cassert>
	#include <string>
	#include <vector>

	// GNU multiple precision library
	#include <gmp.h>

class aiounicast
{
	public:
		static const time_t	aio_timeout_none		= 0;
		static const time_t	aio_timeout_very_short		= 1;
		static const time_t	aio_timeout_short		= 15;
		static const time_t	aio_timeout_middle		= 30;
		static const time_t	aio_timeout_long		= 90;
		static const time_t	aio_timeout_very_long		= 180;
		static const size_t	aio_scheduler_none		= 0;
		static const size_t	aio_scheduler_roundrobin	= 1;
		static const size_t	aio_scheduler_random		= 2;
		static const size_t	aio_scheduler_direct		= 3;

		aiounicast
			()
		{
		}

		virtual bool Send
			(mpz_srcptr m, const size_t i_in) = 0;
		virtual bool Send
			(const std::vector<mpz_srcptr> &m, const size_t i_in) = 0;
		virtual bool Receive
			(mpz_ptr m, size_t &i_out,
			const size_t scheduler = aio_scheduler_roundrobin,
			const time_t timeout = aio_timeout_long) = 0;
		virtual bool Receive
			(std::vector<mpz_ptr> &m, size_t &i_out,
			const size_t scheduler = aio_scheduler_roundrobin,
			const time_t timeout = aio_timeout_long) = 0;

		virtual ~aiounicast
			()
		{
		}
};

#endif
