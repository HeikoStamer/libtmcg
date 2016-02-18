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

	// C header for asynchronous io (TODO: add configure-checks)
	#include <sys/select.h>
	#include <sys/time.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <errno.h>
	#include <string.h>
	// define helper macro for select(2)
	#define MFD_IN_SET(fd, where) { FD_SET(fd, where); mfds_in = (fd > mfds_in) ? fd : mfds_in; }
	#define MFD_OUT_SET(fd, where) { FD_SET(fd, where); mfds_out = (fd > mfds_out) ? fd : mfds_out; }

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
		size_t			n, t, j;
		mpz_t			s;
		std::vector<int>	in, out;
		size_t			buf_in_size;
		std::vector<char*>	buf_in;
		std::vector<size_t>	buf_ptr;
		std::vector<bool>	buf_flag;
		int			mfds_in, mfds_out;
		fd_set			fds_in, fds_out;
		struct timeval 		tv;
	
	public:
		size_t			numWrite, numRead;

		iobroadcast
			(size_t n_in, size_t t_in, size_t j_in,
			std::vector<int> &in_in, std::vector<int> &out_in):
				n(n_in), t(t_in), j(j_in)
		{
			assert(t_in <= n_in);
			assert(j_in < n_in);
			assert(n_in == in_in.size());
			assert(in_in.size() == out_in.size());

			// initialize buffers for select(2)
			buf_in_size = TMCG_MAX_VALUE_CHARS;
			for (size_t i = 0; i < n_in; i++)
			{
				in.push_back(in_in[i]);
				char *buf = new char[buf_in_size];
				buf_in.push_back(buf), buf_ptr.push_back(0);
				buf_flag.push_back(false);
				out.push_back(out_in[i]);
			}
			// initialize timeout for select (2)
			tv.tv_sec = 10L;		// seconds
			tv.tv_usec = 0L;		// microseconds

			// initialize sequence counter
			mpz_init_set_ui(s, 0L);

			// initialize character counters
			numWrite = 0, numRead = 0;
		}

		void Broadcast
			(mpz_srcptr m)
		{
			mpz_add_ui(s, s, 1L); // increase sequence counter

			// prepare write buffer
			char *buf = new char[TMCG_MAX_VALUE_CHARS];
			size_t size = mpz_sizeinbase(m, TMCG_MPZ_IO_BASE);
			if (size < TMCG_MAX_VALUE_CHARS)
			{
                		mpz_get_str(buf, TMCG_MPZ_IO_BASE, m);
			}
			else
			{
				buf[0] = '\001'; // faulty value
				size = 1;
			}
			buf[size] = '\n';	
			// broadcast
			for (size_t i = 0; i < n; i++)
			{
				if (i != j)
				{
                        		size_t num = write(out[i], buf, size + 1);
					numWrite += num;
//std::cerr << "out(" << j << ") i = " << i << " num = " << num << " m = " << m << std::endl;
				}
			}
			delete [] buf;
		}

		bool Deliver
			(mpz_ptr m, size_t &i_out)
		{
			return false;
		}

		bool DeliverFrom
			(mpz_ptr m, size_t i_in)
		{
//std::cerr << "select(" << j << ") for i = " << i_in << " ptr = " << buf_ptr[i_in] << std::endl;
			while (1)
			{
				// anything buffered from previous calls?
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
						if (wnum)
							memcpy(buf_in[i_in], wptr, wnum);
						else
							buf_flag[i_in] = false;
						buf_ptr[i_in] -= newline_ptr + 1;
						if (mpz_set_str(m, tmp, TMCG_MPZ_IO_BASE) < 0)
						{
							delete [] tmp;
							return false;
						}
						delete [] tmp;
//std::cerr << "deliver(" << j << ") from " << i_in << " = " << m << std::endl;
						return true;
					}
					// no delimiter found; invalidate buffer flag
					buf_flag[i_in] = false;
				}
				// initialize file descriptors for select(2)
				mfds_in = 0;
				FD_ZERO(&fds_in);
				for (size_t i = 0; i < n; i++)
					MFD_IN_SET(in[i], &fds_in);
				// select(2) -- do everything with asynchronous I/O
				int ret = select(mfds_in + 1, &fds_in, NULL, NULL, &tv);
		                // error occured
				if (ret < 0)
				{
					if (errno != EINTR)
					{
						perror("iobroadcast (select)");	
						return false;
					}
					else
						continue;
				}
				// timeout occured
				if (ret == 0)
					return false;
				// anything happend in file descriptor set
				for (size_t i = 0; i < n; i++)
				{
					if ((i != j) && (FD_ISSET(in[i], &fds_in)))
					{
						// read characters
						size_t max = buf_in_size - buf_ptr[i];
						if (max > 0)
						{
							char *rptr = buf_in[i] + buf_ptr[i];
//std::cerr << "read(" << j << ") i = " << i << " max = " << max << std::endl;
							size_t num = read(in[i], rptr, max);
							numRead += num;
							buf_ptr[i] += num;
							buf_flag[i] = true;
//std::cerr << "ready(" << j << ") i = " << i << " num = " << num << std::endl;
						}
					}
				}
//FIXME				// no characters received from i_in
//				if (!buf_flag[i_in])
//					return false;
			}
		}

		~iobroadcast
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
