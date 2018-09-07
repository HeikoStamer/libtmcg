/*******************************************************************************
  aiounicast_nonblock.hh, asynchronous unicast with nonblocking file descriptors 

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

#ifndef INCLUDED_aiounicast_nonblock_HH
	#define INCLUDED_aiounicast_nonblock_HH
	
// C and STL header
#include <cstdlib>
#include <ctime>
#include <vector>
#include <list>
	
// GNU multiple precision library
#include <gmp.h>

// GNU crypto library
#include <gcrypt.h>

// abstract base class
#include "aiounicast.hh"

class aiounicast_nonblock : public aiounicast
{
	private:
		size_t								aio_schedule_current;
		size_t								aio_schedule_buffer;
		size_t								buf_in_size;
		std::vector<unsigned char*>			buf_in, iv_out;
		std::vector<size_t>					buf_ptr;
		std::vector<bool>					buf_flag, iv_flag_out, iv_flag_in;
		std::vector< std::list<mpz_ptr> >	buf_mpz;
		size_t								maclen, keylen, blklen;
		std::vector<gcry_mac_hd_t*>			mac_in, mac_out;
		std::vector<gcry_cipher_hd_t*>		enc_in, enc_out;

	public:
		aiounicast_nonblock
			(const size_t n_in,
			 const size_t j_in,
			 const std::vector<int> &fd_in_in,
			 const std::vector<int> &fd_out_in,
			 const std::vector<std::string> &key_in,
			 const size_t aio_default_scheduler_in = aio_scheduler_roundrobin,
			 const time_t aio_default_timeout_in = aio_timeout_very_long,
			 const bool aio_is_authenticated_in = true,
			 const bool aio_is_encrypted_in = true);
		bool Send
			(mpz_srcptr m,
			 const size_t i_in,
			 time_t timeout = aio_timeout_default);
		bool Send
			(const std::vector<mpz_srcptr> &m,
			 const size_t i_in,
			 time_t timeout = aio_timeout_default);
		bool Receive
			(mpz_ptr m,
			 size_t &i_out,
			 size_t scheduler = aio_scheduler_default,
			 time_t timeout = aio_timeout_default);
		bool Receive
			(std::vector<mpz_ptr> &m,
			 size_t &i_out,
			 size_t scheduler = aio_scheduler_default,
			 time_t timeout = aio_timeout_default);
		~aiounicast_nonblock
			();
};

#endif
