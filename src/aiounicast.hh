/*******************************************************************************
  aiounicast.hh, basic class for asynchronous unicast

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
	#include <list>

	// C header for asynchronous I/O
	#include <unistd.h>
	#include <errno.h>
	#include <string.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
class aiounicast
{
	private:
		size_t					aio_schedule_current;
		size_t					aio_schedule_buffer;
		size_t					buf_in_size;
		std::vector<char*>			buf_in;
		std::vector<size_t>			buf_ptr;
		std::vector<bool>			buf_flag;
		std::vector< std::list<mpz_ptr> > 	buf_mpz;
	
	public:
		static const size_t			aio_scheduler_none		= 0;
		static const size_t			aio_scheduler_roundrobin	= 1;
		static const size_t			aio_scheduler_random		= 2;
		static const size_t			aio_scheduler_direct		= 3;
		size_t					n, t, j;
		std::vector<int>			in, out;
		size_t					numWrite, numRead;
		size_t					timeout;

		aiounicast
			(size_t n_in, size_t t_in, size_t j_in,
			std::vector<int> &in_in, std::vector<int> &out_in,
			size_t timeout_in):
				n(n_in), t(t_in), j(j_in), timeout(timeout_in)
		{
			assert(t_in <= n_in);
			assert(j_in < n_in);
			assert(n_in == in_in.size());
			assert(in_in.size() == out_in.size());
			assert(timeout_in > 0);

			// initialize scheduler
			aio_schedule_current = 0, aio_schedule_buffer = 0;

			// initialize buffers for read(2)
			buf_in_size = TMCG_MAX_VALUE_CHARS;
			for (size_t i = 0; i < n_in; i++)
			{
				in.push_back(in_in[i]);
				char *buf = new char[buf_in_size];
				buf_in.push_back(buf), buf_ptr.push_back(0);
				buf_flag.push_back(false);
				out.push_back(out_in[i]);
			}

			// initialize ordered buffer for receiving mpz_t
			for (size_t i = 0; i < n_in; i++)
			{
				std::list<mpz_ptr> *ltmp = new std::list<mpz_ptr>;
				buf_mpz.push_back(*ltmp);
			}

			// initialize character counters
			numWrite = 0, numRead = 0;
		}

		void Send
			(mpz_srcptr m, size_t i_in)
		{
			// prepare write buffer with m
			size_t size = mpz_sizeinbase(m, TMCG_MPZ_IO_BASE);
			char *buf = new char[size + 2];
			memset(buf, 0, size + 2);
               		mpz_get_str(buf, TMCG_MPZ_IO_BASE, m);
			// determine the real size of the string, because
			// mpz_sizeinbase(m, TMCG_MPZ_IO_BASE) does not
			// work in all cases correctly
			size_t realsize = strnlen(buf, size + 2);
			if (realsize < (size + 2))
			{
				buf[realsize] = '\n'; // set newline as delimiter
			}
			else
			{
				buf[0] = '\001'; // set a faulty value
				buf[1] = '\n'; // set newline as delimiter
				realsize = 1;
			}
			// send content of write buffer to party i_in
			size_t realnum = 0;
			do
			{
				ssize_t num = write(out[i_in], buf + realnum, realsize - realnum + 1);
				if (num < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || 
						(errno == EINTR))
					{
						sleep(1);
						continue;
					}
					else
					{
						delete [] buf;
						perror("aiounicast (write)");
						return;
					}
				}
				numWrite += num;
				realnum += num;
			}
			while (realnum < (realsize + 1));
			delete [] buf;
		}

		void Send
			(const std::vector<mpz_srcptr> &m, size_t i_in)
		{
			for (size_t mm = 0; mm < m.size(); mm++)
				Send(m[mm], i_in);
		}

		bool Receive
			(mpz_ptr m, size_t &i_out, size_t scheduler = aio_scheduler_roundrobin)
		{
			for (size_t round = 0; round < timeout; round++)
			{
				// scheduler
				switch (scheduler)
				{
					case aio_scheduler_none:
						i_out = n;
						return false;
					case aio_scheduler_roundrobin:
						i_out = aio_schedule_current++;
						if (aio_schedule_current == n)
							aio_schedule_current = 0;
						break;
					case aio_scheduler_random:
						i_out = mpz_wrandom_mod(n);
						break;
					case aio_scheduler_direct:
						if (i_out >= n)
							return false;
						break;
					default:
						aio_schedule_current = 0;
				}
				// anything buffered from previous rounds?
				if (buf_flag[i_out])
				{
					// search for delimiter
					bool newline_found = false;
					size_t newline_ptr = 0;
					for (size_t ptr = 0; ptr < buf_ptr[i_out]; ptr++)
					{
						if (buf_in[i_out][ptr] == '\n')
						{
							newline_found = true;
							newline_ptr = ptr;
							break;
						}
					}
					// extract value of m and adjust buffer
					if (newline_found)
					{
						char *tmp = new char[newline_ptr + 1];
						memset(tmp, 0, newline_ptr + 1);
						if (newline_ptr > 0)
							memcpy(tmp, buf_in[i_out], newline_ptr);
						char *wptr = buf_in[i_out] + newline_ptr + 1;
						size_t wnum = buf_ptr[i_out] - newline_ptr - 1;
						if (wnum > 0)
							memmove(buf_in[i_out], wptr, wnum);
						else
							buf_flag[i_out] = false;
						buf_ptr[i_out] = wnum;
						if (mpz_set_str(m, tmp, TMCG_MPZ_IO_BASE) < 0)
						{
							delete [] tmp;
							return false;
						}
						delete [] tmp;
						return true;
					}
					// no delimiter found; invalidate buffer flag
					buf_flag[i_out] = false;
				}
				// read(2) -- do everything with asynchronous I/O
				size_t max = buf_in_size - buf_ptr[i_out];
				if (max > 0)
				{
					char *rptr = buf_in[i_out] + buf_ptr[i_out];
					ssize_t num = read(in[i_out], rptr, max);
					if (num < 0)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || 
							(errno == EINTR))
						{
							if (scheduler == aio_scheduler_direct)
								sleep(1);
							continue;
						}
						else
						{
							perror("aiounicast (read)");
							return false;
						}
					}
					if (num == 0)
						continue;
					numRead += num;
					buf_ptr[i_out] += num;
					buf_flag[i_out] = true;
				}
			}
			if (scheduler != aio_scheduler_direct)
				i_out = n; // timeout for some parties
			return false;
		}

		bool Receive
			(std::vector<mpz_ptr> &m, size_t &i_out, size_t scheduler = aio_scheduler_roundrobin)
		{
			// determine maximum number of rounds based on scheduler
			size_t max_rounds = 0; 
			switch (scheduler)
			{
				case aio_scheduler_none:
					max_rounds = 0;
					break;
				case aio_scheduler_roundrobin:
					max_rounds = (m.size() * n);
					break;
				case aio_scheduler_random:
					max_rounds = (m.size() * n * n);
					break;
				case aio_scheduler_direct:
					max_rounds = m.size();
					break;
			}
			for (size_t round = 0; round < max_rounds; round++)
			{
				// scheduler for reading from buffer
				switch (scheduler)
				{
					case aio_scheduler_none:
						i_out = n;
						return false;
					case aio_scheduler_roundrobin:
						i_out = aio_schedule_buffer++;
						if (aio_schedule_buffer == n)
							aio_schedule_buffer = 0;
						break;
					case aio_scheduler_random:
						i_out = mpz_wrandom_mod(n);
						break;
					case aio_scheduler_direct:
						if (i_out >= n)
							return false;
						break;
					default:
						aio_schedule_buffer = 0;
				}
				// return, if enough messages are received from i_out
				if (buf_mpz[i_out].size() >= m.size())
				{
					// copy results and release buffer
					for (size_t mm = 0; mm < m.size(); mm++)
					{
						mpz_set(m[mm], buf_mpz[i_out].front());
						mpz_clear(buf_mpz[i_out].front());
						delete buf_mpz[i_out].front();
						buf_mpz[i_out].pop_front();
					}
					return true;
				}
				// receive a message according to the given scheduler
				size_t i = n;
				if (scheduler == aio_scheduler_direct)
					i = i_out;
				mpz_ptr tmp = new mpz_t();
				mpz_init(tmp);
				if (Receive(tmp, i, scheduler))
				{
					buf_mpz[i].push_back(tmp);
				}
				else
				{
					if (i < n)
					{
						i_out = i;
						mpz_clear(tmp);
						delete tmp;
						return false;
					}
				}
			}
			i_out = n; // timeout for all parties
			return false;			
		}

		~aiounicast
			()
		{
			in.clear(), out.clear();
			for (size_t i = 0; i < n; i++)
			{
				delete [] buf_in[i];
				for (size_t mm = 0; mm < buf_mpz[i].size(); mm++)
				{
					mpz_clear(buf_mpz[i].front());
					delete buf_mpz[i].front();
					buf_mpz[i].pop_front();
				}
				buf_mpz[i].clear();
			}
			buf_in.clear(), buf_ptr.clear(), buf_flag.clear();
			buf_mpz.clear();
		}
};

#endif
