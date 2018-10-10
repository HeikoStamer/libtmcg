/*******************************************************************************
  aiounicast.hh, base class for asynchronous unicast transmission of mpz_t

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

#ifndef INCLUDED_aiounicast_HH
	#define INCLUDED_aiounicast_HH
	
// C and STL header
#include <cstdlib>
#include <ctime>
#include <vector>
#include <map>
#include <iostream>

// GNU multiple precision library
#include <gmp.h>

class aiounicast
{
	protected:
		const size_t				aio_default_scheduler;
		const time_t				aio_default_timeout;
		const bool					aio_is_authenticated;
		const bool					aio_is_encrypted;
		bool						aio_is_initialized;
		mpz_t						aio_hide_length;

	public:
		static const time_t			aio_timeout_none			= 0;
		static const time_t			aio_timeout_extremely_short	= 1;
		static const time_t			aio_timeout_very_short		= 5;
		static const time_t			aio_timeout_short			= 15;
		static const time_t			aio_timeout_middle			= 30;
		static const time_t			aio_timeout_long			= 90;
		static const time_t			aio_timeout_very_long		= 180;
		static const time_t			aio_timeout_extremely_long	= 300;
		static const time_t			aio_timeout_default			= 42424242;
		static const size_t			aio_scheduler_none			= 0;
		static const size_t			aio_scheduler_roundrobin	= 1;
		static const size_t			aio_scheduler_random		= 2;
		static const size_t			aio_scheduler_direct		= 3;
		static const size_t			aio_scheduler_default		= 42424242;

		const size_t				n;
		const size_t				j;

		std::map<size_t, int>		fd_in, fd_out;
		size_t						numWrite, numRead;
		size_t						numEncrypted, numDecrypted;
		size_t						numAuthenticated;

		aiounicast
			(const size_t n_in,
			 const size_t j_in,
			 const size_t aio_default_scheduler_in = aio_scheduler_roundrobin,
			 const time_t aio_default_timeout_in = aio_timeout_very_long,
			 const bool aio_is_authenticated_in = true,
			 const bool aio_is_encrypted_in = true):
				aio_default_scheduler(aio_default_scheduler_in),
				aio_default_timeout(aio_default_timeout_in),
				aio_is_authenticated(aio_is_authenticated_in),
				aio_is_encrypted(aio_is_encrypted_in),
				aio_is_initialized(true),
				n(n_in), j(j_in), numWrite(0), numRead(0), numEncrypted(0),
				numDecrypted(0), numAuthenticated(0)
		{
			mpz_init_set_ui(aio_hide_length, 1L);
			mpz_mul_2exp(aio_hide_length, aio_hide_length, TMCG_AIO_HIDE_SIZE);
		}

		virtual bool Send
			(mpz_srcptr m,
			 const size_t i_in,
			 const time_t timeout = aio_timeout_default) = 0;
		virtual bool Send
			(const std::vector<mpz_srcptr> &m,
			 const size_t i_in,
			 const time_t timeout = aio_timeout_default) = 0;
		virtual bool Receive
			(mpz_ptr m,
			 size_t &i_out,
			 const size_t scheduler = aio_scheduler_default,
			 const time_t timeout = aio_timeout_default) = 0;
		virtual bool Receive
			(std::vector<mpz_ptr> &m,
			 size_t &i_out,
			 const size_t scheduler = aio_scheduler_default,
			 const time_t timeout = aio_timeout_default) = 0;

		void PrintStatistics
			(std::ostream &ost)
		{
			ost << " numRead = " << numRead << " numWrite = " << numWrite <<
				" numEncrypted = " << numEncrypted <<
				" numDecrypted = " << numDecrypted <<
				" numAuthenticated = " << numAuthenticated;
		}

		virtual ~aiounicast
			()
		{
			mpz_clear(aio_hide_length);
		}
};

#endif

