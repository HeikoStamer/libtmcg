/*******************************************************************************
  aiounicast.hh, derived class for unicast transmission with file descriptors 

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

#ifndef INCLUDED_aiounicast_fd_HH
	#define INCLUDED_aiounicast_fd_HH
	
	// C and STL header
	#include <cstdio>
	#include <cstdlib>
	#include <ctime>
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

	// GNU crypto library
	#include <gcrypt.h>

	// abstract base class
	#include "aiounicast.hh"

class aiounicast_fd : public aiounicast
{
	private:
		size_t					aio_schedule_current;
		size_t					aio_schedule_buffer;
		size_t					buf_in_size;
		std::vector<char*>			buf_in;
		std::vector<size_t>			buf_ptr;
		std::vector<bool>			buf_flag;
		std::vector< std::list<mpz_ptr> >	buf_mpz;
		std::vector<gcry_mac_hd_t*>		buf_mac_in, buf_mac_out;

	public:
		size_t					n, j;
		std::vector<int>			fd_in, fd_out;
		size_t					numWrite, numRead;

		aiounicast_fd
			(const size_t n_in, const size_t j_in,
			const std::vector<int> &fd_in_in,
			const std::vector<int> &fd_out_in,
			const std::vector<std::string> &key_in):
				n(n_in), j(j_in)
		{
			assert(j_in < n_in);
			assert(n_in == fd_in_in.size());
			assert(fd_in_in.size() == fd_out_in.size());

			// initialize scheduler
			aio_schedule_current = 0, aio_schedule_buffer = 0;

			// initialize buffers for read(2)
			buf_in_size = TMCG_MAX_VALUE_CHARS;
			for (size_t i = 0; i < n_in; i++)
			{
				fd_in.push_back(fd_in_in[i]);
				char *buf = new char[buf_in_size];
				buf_in.push_back(buf), buf_ptr.push_back(0);
				buf_flag.push_back(false);
				fd_out.push_back(fd_out_in[i]);
			}

			// initialize ordered buffer for receiving mpz_t
			for (size_t i = 0; i < n_in; i++)
			{
				std::list<mpz_ptr> *ltmp = new std::list<mpz_ptr>;
				buf_mpz.push_back(*ltmp);
			}

			// initialize character counters
			numWrite = 0, numRead = 0;

			// initialize MACs
			for (size_t i = 0; i < n_in; i++)
			{
				gcry_error_t err;
				gcry_mac_hd_t *mac_in = new gcry_mac_hd_t(), *mac_out = new gcry_mac_hd_t();
				buf_mac_in.push_back(mac_in), buf_mac_out.push_back(mac_out);
				err = gcry_mac_open(buf_mac_in[i], TMCG_GCRY_MAC_ALGO, 0, NULL); 				
				if (err)
				{
					std::cerr << "libgcrypt: gcry_mac_open() failed" << std::endl;
					std::cerr << gcry_strerror(err) << std::endl;
				}
				err = gcry_mac_setkey(*buf_mac_in[i], key_in[i].c_str(), key_in[i].length());
				if (err)
				{
					std::cerr << "libgcrypt: gcry_mac_setkey() failed" << std::endl;
					std::cerr << gcry_strerror(err) << std::endl;
				}
				err = gcry_mac_open(buf_mac_out[i], TMCG_GCRY_MAC_ALGO, 0, NULL); 				
				if (err)
				{
					std::cerr << "libgcrypt: gcry_mac_open() failed" << std::endl;
					std::cerr << gcry_strerror(err) << std::endl;
				}
				err = gcry_mac_setkey(*buf_mac_out[i], key_in[i].c_str(), key_in[i].length());
				if (err)
				{
					std::cerr << "libgcrypt: gcry_mac_setkey() failed" << std::endl;
					std::cerr << gcry_strerror(err) << std::endl;
				}
			}
		}

		bool Send
			(mpz_srcptr m, const size_t i_in)
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
			// calculate MAC
			gcry_error_t err;
			err = gcry_mac_write(*buf_mac_out[i_in], buf, realsize);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_mac_write() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				delete [] buf;
				return false;
			}
			size_t maclen = gcry_mac_get_algo_maclen(TMCG_GCRY_MAC_ALGO);
			if (maclen == 0)
			{
				std::cerr << "libgcrypt: gcry_mac_get_algo_maclen() failed" << std::endl;
				delete [] buf;
				return false;
			}
			char *macbuf = new char[maclen];
			err = gcry_mac_read(*buf_mac_out[i_in], macbuf, &maclen);
			if (err)
			{
				std::cerr << "libgcrypt: gcry_mac_read() failed" << std::endl;
				std::cerr << gcry_strerror(err) << std::endl;
				delete [] buf, delete [] macbuf;
				return false;
			}
			// send content of write buffer to party i_in
			size_t realnum = 0;
			do
			{
				ssize_t num = write(fd_out[i_in], buf + realnum, realsize - realnum + 1);
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
						delete [] buf, delete [] macbuf;
						perror("aiounicast_fd (write)");
						return false;
					}
				}
				numWrite += num;
				realnum += num;
			}
			while (realnum < (realsize + 1));
			// send content of MAC buffer to party i_in
			realnum = 0;
			do
			{
				ssize_t num = write(fd_out[i_in], macbuf + realnum, maclen - realnum);
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
						delete [] buf, delete [] macbuf;
						perror("aiounicast_fd (write)");
						return false;
					}
				}
				numWrite += num;
				realnum += num;
			}
			while (realnum < maclen);
			delete [] buf, delete [] macbuf;
			return true;
		}

		bool Send
			(const std::vector<mpz_srcptr> &m, const size_t i_in)
		{
			for (size_t mm = 0; mm < m.size(); mm++)
			{
				if (!Send(m[mm], i_in))
					return false;
			}
			return true;
		}

		bool Receive
			(mpz_ptr m, size_t &i_out,
			const size_t scheduler = aio_scheduler_roundrobin,
			const time_t timeout = aio_timeout_short)
		{
			size_t maclen = gcry_mac_get_algo_maclen(TMCG_GCRY_MAC_ALGO);
			if (maclen == 0)
			{
				std::cerr << "libgcrypt: gcry_mac_get_algo_maclen() failed" << std::endl;
				i_out = n;
				return false;
			}
			for (size_t round = 0; (round < n); round++)
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
					// search for line delimiter
					bool newline_found = false;
					size_t newline_ptr = 0;
					for (size_t ptr = 0; ptr < buf_ptr[i_out]; ptr++)
					{
						if (buf_in[i_out][ptr] == '\n')
						{
							newline_ptr = ptr;
							newline_found = true;
							break;
						}
					}
					// process the buffer
					if (newline_found && ((buf_ptr[i_out] - newline_ptr - 1) >= maclen))
					{
						char *tmp = new char[newline_ptr + 1];
						char *mac = new char[maclen];
						memset(tmp, 0, newline_ptr + 1);
						memset(mac, 0, maclen);
						if (newline_ptr > 0)
							memcpy(tmp, buf_in[i_out], newline_ptr);
						memcpy(mac, buf_in[i_out] + newline_ptr + 1, maclen);
						// adjust buffer (copy remaining characters)
						char *wptr = buf_in[i_out] + newline_ptr + 1 + maclen;
						size_t wnum = buf_ptr[i_out] - newline_ptr - 1 - maclen;
						if (wnum > 0)
							memmove(buf_in[i_out], wptr, wnum);
						else
							buf_flag[i_out] = false;
						buf_ptr[i_out] = wnum;
						// calculate and check MAC
						gcry_error_t err;
						err = gcry_mac_write(*buf_mac_in[i_out], tmp, newline_ptr);
						if (err)
						{
							std::cerr << "libgcrypt: gcry_mac_write() failed" << std::endl;
							std::cerr << gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						err = gcry_mac_verify(*buf_mac_in[i_out], mac, maclen);
						if (err)
						{
							std::cerr << "libgcrypt: gcry_mac_verify() failed" << std::endl;
							std::cerr << gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						// extract value of m
						if (mpz_set_str(m, tmp, TMCG_MPZ_IO_BASE) < 0)
						{
							std::cerr << "libgmp: mpz_set_str() failed" << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						delete [] tmp, delete [] mac;
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
					ssize_t num = read(fd_in[i_out], rptr, max);
					if (num < 0)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || 
							(errno == EINTR))
						{
							if (scheduler == aio_scheduler_direct)
								sleep(timeout);
							continue;
						}
						else
						{
							perror("aiounicast_fd (read)");
							return false;
						}
					}
					if (num == 0)
						continue;
					numRead += num;
					buf_ptr[i_out] += num;
					buf_flag[i_out] = true;
				}
				else
				{
					std::cerr << "WARNING: aiounicast_fd: read buffer exceeded" << std::endl;
				}
			}
			if (scheduler != aio_scheduler_direct)
				i_out = n; // timeout for some (unknown) parties
			return false;
		}

		bool Receive
			(std::vector<mpz_ptr> &m, size_t &i_out,
			const size_t scheduler = aio_scheduler_roundrobin,
			const time_t timeout = aio_timeout_short)
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
			for (size_t round = 0; (round < max_rounds); round++)
			{
				// scheduler
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
				if (Receive(tmp, i, scheduler, timeout))
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

		~aiounicast_fd
			()
		{
			fd_in.clear(), fd_out.clear();
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
				// release MACs
				gcry_mac_close(*buf_mac_in[i]), gcry_mac_close(*buf_mac_out[i]);
				delete buf_mac_in[i], delete buf_mac_out[i];
			}
			buf_in.clear(), buf_ptr.clear(), buf_flag.clear();
			buf_mpz.clear(), buf_mac_in.clear(), buf_mac_out.clear();
		}
};

#endif
