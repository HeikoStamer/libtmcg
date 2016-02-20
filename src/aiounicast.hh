/*******************************************************************************
  aiounicast.hh, basic class for asynchronous unicast protocols

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

	// C header for asynchronous I/O
	#include <unistd.h>
	#include <errno.h>
	#include <string.h>
	
	// GNU multiple precision library
	#include <gmp.h>
	
class aiounicast
{
	private:
		mpz_t			s;
		size_t			buf_in_size;
		std::vector<char*>	buf_in;
		std::vector<size_t>	buf_ptr;
		std::vector<bool>	buf_flag;
	
	public:
		size_t			n, t, j;
		std::vector<int>	in, out;
		size_t			numWrite, numRead;
		size_t			timeout;

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

			// initialize sequence counter
			mpz_init_set_ui(s, 0L);

			// initialize character counters
			numWrite = 0, numRead = 0;
		}

		void Send
			(mpz_srcptr m, size_t i_in)
		{
			mpz_add_ui(s, s, 1L); // increase sequence counter

			// prepare write buffer
			char *buf = new char[TMCG_MAX_VALUE_CHARS];
			memset(buf, 0, TMCG_MAX_VALUE_CHARS);
			size_t size = mpz_sizeinbase(m, TMCG_MPZ_IO_BASE);
			if (size < TMCG_MAX_VALUE_CHARS)
			{
                		mpz_get_str(buf, TMCG_MPZ_IO_BASE, m);
			}
			else
			{
				buf[0] = '\001'; // faulty value
				buf[1] = '\000'; // set string terminator
			}
			// determine the real size of the string, because
			// mpz_sizeinbase(m, TMCG_MPZ_IO_BASE) does not
			// work in all cases correctly
			size = strlen(buf);
			buf[size] = '\n'; // set delimiter

			// send to party i
			size_t num = write(out[i_in], buf, size + 1);
			numWrite += num;
//std::cerr << "send(" << j << ") i = " << i << " num = " << num << " m = " << m << std::endl;
			delete [] buf;
		}

		bool Receive
			(mpz_ptr m, size_t i_in)
		{
//std::cerr << "receive(" << j << ") for i = " << i_in << " ptr = " << buf_ptr[i_in] << std::endl;
			for (size_t round = 0; round < timeout; round++)
			{
				// anything buffered from previous rounds?
				if (buf_flag[i_in])
				{
					// search for delimiter
					bool newline_found = false;
					size_t newline_ptr = 0;
					for (size_t ptr = 0; ptr < buf_ptr[i_in]; ptr++)
					{
						if (buf_in[i_in][ptr] == '\n')
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
						memcpy(tmp, buf_in[i_in], newline_ptr);
						char *wptr = buf_in[i_in] + newline_ptr + 1;
						size_t wnum = buf_ptr[i_in] - newline_ptr - 1;
						if (wnum > 0)
							memmove(buf_in[i_in], wptr, wnum);
						else
							buf_flag[i_in] = false;
						buf_ptr[i_in] = wnum;
						if (mpz_set_str(m, tmp, TMCG_MPZ_IO_BASE) < 0)
						{
							delete [] tmp;
							return false;
						}
						delete [] tmp;
//std::cerr << "receive(" << j << ") from " << i_in << " = " << m << std::endl;
						return true;
					}
					// no delimiter found; invalidate buffer flag
					buf_flag[i_in] = false;
				}
				// read(2) -- do everything with asynchronous I/O
				size_t max = buf_in_size - buf_ptr[i_in];
				if (max > 0)
				{
					char *rptr = buf_in[i_in] + buf_ptr[i_in];
//std::cerr << "read(" << j << ") i = " << i_in << " max = " << max << std::endl;
					ssize_t num = read(in[i_in], rptr, max);
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
							perror("aiounicast (read)");
							return false;
						}
					}
					if (num == 0)
						continue;
					numRead += num;
					buf_ptr[i_in] += num;
					buf_flag[i_in] = true;
				}
			}
			return false;
		}

		~aiounicast
			()
		{
			mpz_clear(s);
			in.clear(), out.clear();
			for (size_t i = 0; i < n; i++)
			{
				delete [] buf_in[i];
			}
			buf_in.clear(), buf_ptr.clear(), buf_flag.clear();
		}
};

#endif
