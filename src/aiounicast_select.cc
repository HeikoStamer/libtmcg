/*******************************************************************************
  aiounicast_select.hh, asynchronous unicast with select on file descriptors 

   This file is part of LibTMCG.

 Copyright (C) 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "aiounicast_select.hh"

// additional headers
#include <cassert>
#include <stdexcept>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "mpz_srandom.hh"

aiounicast_select::aiounicast_select
	(const size_t n_in,
	 const size_t j_in,
	 const std::vector<int> &fd_in_in,
	 const std::vector<int> &fd_out_in,
	 const std::vector<std::string> &key_in,
	 const size_t aio_default_scheduler_in,
	 const time_t aio_default_timeout_in,
	 const bool aio_is_authenticated_in,
	 const bool aio_is_encrypted_in):
		aiounicast(n_in, j_in, aio_default_scheduler_in, aio_default_timeout_in,
			aio_is_authenticated_in, aio_is_encrypted_in)
{
	if (j_in >= n_in)
		throw std::invalid_argument("aiounicast_select: j >= n");
	if (fd_in_in.size() != n_in)
		throw std::invalid_argument("aiounicast_select: |fd_in| != n");
	if (fd_in_in.size() != fd_out_in.size())
		throw std::invalid_argument("aiounicast_select: |fd_in| != |fd_out|");

	// initialize scheduler
	aio_schedule_current = 0, aio_schedule_buffer = 0;

	// initialize buffers
	buf_in_size = TMCG_MAX_VALUE_CHARS;
	for (size_t i = 0; i < n_in; i++)
	{
		fd_in[i] = fd_in_in[i];
		unsigned char *buf = new unsigned char[buf_in_size];
		buf_in.push_back(buf), buf_ptr.push_back(0);
		buf_flag.push_back(false);
		fd_out[i] = fd_out_in[i];
	}

	// initialize ordered buffer for receiving mpz_t
	buf_mpz.resize(n);

	// initialize MACs
	if (aio_is_authenticated)
	{
		maclen = gcry_mac_get_algo_maclen(TMCG_GCRY_MAC_ALGO);
		if (maclen == 0)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_mac_get_algo_maclen()" <<
				" failed" << std::endl;
			throw std::invalid_argument("aiounicast_select: bad MAC algo");
		}
	}
	else
		maclen = 0;
	for (size_t i = 0; aio_is_authenticated && (i < n_in); i++)
	{
		unsigned char salt[maclen];
		unsigned char key[maclen];
		gcry_error_t err;
		gcry_mac_hd_t *mac_in_hd = new gcry_mac_hd_t();
		gcry_mac_hd_t *mac_out_hd = new gcry_mac_hd_t();
		mac_in.push_back(mac_in_hd), mac_out.push_back(mac_out_hd);
		err = gcry_mac_open(mac_in[i], TMCG_GCRY_MAC_ALGO, 0, NULL); 				
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_mac_open() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		memset(salt, 0, sizeof(salt));
		err = gcry_kdf_derive(key_in[i].c_str(), key_in[i].length(),
			GCRY_KDF_PBKDF2, TMCG_GCRY_MD_ALGO, salt, sizeof(salt), 25000,
			sizeof(key), key);
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_kdf_derive() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		err = gcry_mac_setkey(*mac_in[i], key, sizeof(key));
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_mac_setkey() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		err = gcry_mac_open(mac_out[i], TMCG_GCRY_MAC_ALGO, 0, NULL); 				
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_mac_open() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		err = gcry_mac_setkey(*mac_out[i], key, sizeof(key));
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_mac_setkey() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
	}

	// initialize ciphers
	if (aio_is_encrypted)
	{
		keylen = gcry_cipher_get_algo_keylen(TMCG_GCRY_ENC_ALGO);
		if (keylen == 0)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_get_algo_keylen()" <<
				" failed" << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		blklen = gcry_cipher_get_algo_blklen(TMCG_GCRY_ENC_ALGO);
		if (blklen == 0)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_get_algo_blklen()" <<
				" failed" << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
	}
	else
	{
		keylen = 0, blklen = 0;
	}
	for (size_t i = 0; aio_is_encrypted && (i < n_in); i++)
	{
		unsigned char salt[keylen];
		unsigned char key[keylen];
		unsigned char iv[blklen];
		gcry_error_t err;
		gcry_cipher_hd_t *enc_in_hd = new gcry_cipher_hd_t();
		gcry_cipher_hd_t *enc_out_hd = new gcry_cipher_hd_t();
		enc_in.push_back(enc_in_hd), enc_out.push_back(enc_out_hd);
		err = gcry_cipher_open(enc_in[i], TMCG_GCRY_ENC_ALGO,
			GCRY_CIPHER_MODE_CFB, 0); 				
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_open() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		// use a different salt to derive encryption key
		memset(salt, 1, sizeof(salt));
		err = gcry_kdf_derive(key_in[i].c_str(), key_in[i].length(),
			GCRY_KDF_PBKDF2, TMCG_GCRY_MD_ALGO, salt, sizeof(salt), 25000,
			sizeof(key), key);
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_kdf_derive() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		err = gcry_cipher_setkey(*enc_in[i], key, sizeof(key));
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_setkey() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		iv_flag_in.push_back(false); // flag means: IV not yet received
		err = gcry_cipher_open(enc_out[i], TMCG_GCRY_ENC_ALGO,
			GCRY_CIPHER_MODE_CFB, 0); 				
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_open() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		err = gcry_cipher_setkey(*enc_out[i], key, sizeof(key));
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_setkey() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		gcry_create_nonce(iv, blklen); // unpredictable IV is sufficient
		err = gcry_cipher_setiv(*enc_out[i], iv, sizeof(iv));
		if (err)
		{
			aio_is_initialized = false;
			std::cerr << "aiounicast_select: gcry_cipher_setiv() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			throw std::invalid_argument("aiounicast_select: libgcrypt failed");
		}
		iv_flag_out.push_back(false); // flag means: IV not yet sent
		unsigned char *ivcopy = new unsigned char[blklen];
		memcpy(ivcopy, iv, blklen);
		iv_out.push_back(ivcopy); // store a copy of the used IV for Send()
	}
}

bool aiounicast_select::Send
	(mpz_srcptr m,
	 const size_t i_in,
	 time_t timeout)
{
	if (!aio_is_initialized)
		return false;
	if (timeout == aio_timeout_default)
		timeout = aio_default_timeout;
	// check whether output file descriptor exists
	if (!fd_out.count(i_in))
		return false;
	// prepare write buffer from the message m
	mpz_t tmp;
	mpz_init_set(tmp, m);
	if (aio_is_encrypted)
		mpz_add(tmp, tmp, aio_hide_length); // add $2^c$ to hide length
	size_t size = mpz_sizeinbase(tmp, TMCG_MPZ_IO_BASE);
	if ((size * 2) >= buf_in_size)
	{
		std::cerr << "aiounicast_select: big integer too large" << std::endl;
		return false;
	}
	size_t bufsize = size + 2;
	char *buf = new char[bufsize];
	memset(buf, 0, bufsize);
	mpz_get_str(buf, TMCG_MPZ_IO_BASE, tmp);
	mpz_clear(tmp);
	// additionally, determine the real size of the corresponding string
	// because mpz_sizeinbase() sometimes does not work correctly
	size_t realsize = strnlen(buf, bufsize);
	if ((realsize > 0) && (realsize < bufsize))
	{
		buf[realsize] = '\n'; // set newline as delimiter
		realsize++;
	}
	else
	{
		std::cerr << "aiounicast_select(" << j << "):" <<
			" realsize does not fit" << std::endl;
		delete [] buf;
		return false;
	}
	// We follow the Encrypt-then-Authenticate (EtA) paradigm, because it
	// provides the best security properties with respect to the required
	// 'secure channel'. Please note the scientific discussion on that topic,
	// e.g., Mihir Bellare and Chanathip Namprempre: 'Authenticated Encryption:
	//       Relations among notions and analysis of the generic composition
	//       paradigm', Advances in Cryptology - ASIACRYPT 2000, LNCS 1976,
	//       pp. 531--545, 2000.
	gcry_error_t err;
	// encrypt the content of write buffer (without delimiter) and send the
	// IV to the receiver
	if (aio_is_encrypted)
	{
		memmove(buf + 1, buf, realsize - 1);
		buf[0] = '+'; // use plus-character as a non-zero prefix
		err = gcry_cipher_encrypt(*enc_out[i_in], buf + 1, realsize - 1,
			NULL, 0);
		if (err)
		{
			std::cerr << "aiounicast_select: gcry_cipher_encrypt() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			delete [] buf;
			return false;
		}
		numEncrypted += (realsize - 1);
		// convert encrypted content to mpz and adjust write buffer accordingly
		mpz_t encval;
		mpz_init(encval);
		mpz_import(encval, realsize, 1, 1, 1, 0, buf);
		delete [] buf;
		size = mpz_sizeinbase(encval, TMCG_MPZ_IO_BASE);
		bufsize = size + 2;
		buf = new char[bufsize];
		memset(buf, 0, bufsize); // clear write buffer
		mpz_get_str(buf, TMCG_MPZ_IO_BASE, encval);
		mpz_clear(encval);
		realsize = strnlen(buf, bufsize);
		if ((realsize > 0) && (realsize < bufsize))
		{
			buf[realsize] = '\n'; // set newline as delimiter
			realsize++;
		}
		else
		{
			std::cerr << "aiounicast_select(" << j << "):" <<
				" realsize does not fit" << std::endl;
			delete [] buf;
			return false;
		}
		// first, send the plain IV to the receiver
		if (!iv_flag_out[i_in])
		{
			time_t entry_time = time(NULL);
			size_t realnum = 0;
			do
			{
				// select(2) -- do everything with asynchronous I/O
				fd_set wfds;
				struct timeval tv;
				int retval;
				FD_ZERO(&wfds);
				FD_SET(fd_out[i_in], &wfds);
				tv.tv_sec = 0;
				tv.tv_usec = 1000; // sleep only for 1000us = 1ms
				retval = select((fd_out[i_in] + 1), NULL, &wfds, NULL, &tv);
				if (retval < 0)
				{
					if (errno == EINTR)
					{
						continue;
					}
					else
					{
						perror("aiounicast_select (select)");
						delete [] buf;
						return false;
					}
				}
				if (retval == 0)
					continue;
				// write(2) -- ready for non-blocking write?
				if (FD_ISSET(fd_out[i_in], &wfds))
				{
					ssize_t num = write(fd_out[i_in], iv_out[i_in] + realnum,
						blklen - realnum);
					if (num < 0)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
							(errno == EINTR))
						{
							if (errno == EAGAIN)
								perror("aiounicast_select (write)");
							continue;
						}
						else
						{
							perror("aiounicast_select (write)");
							delete [] buf;							
							return false;
						}
					}
					numWrite += num;
					realnum += num;
				}
				else
				{
					std::cerr << "WARNING: aiounicast_select FD_ISSET" <<
						" not true" << std::endl;
				}
			}
			while ((realnum < blklen) && (time(NULL) < (entry_time + timeout)));
			// timeout occurred?
			if (realnum < blklen)
			{
				std::cerr << "aiounicast_select(" << j << "):" <<
					" IV send timeout for " << i_in << std::endl;
				delete [] buf;
				return false;
			}
			else
				iv_flag_out[i_in] = true; // IV has been sent
		}
	}
	// calculate the MAC over all data including the line delimiter
	if (aio_is_authenticated)
	{
		err = gcry_mac_write(*mac_out[i_in], buf, realsize);
		if (err)
		{
			std::cerr << "aiounicast_select: gcry_mac_write() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			delete [] buf;
			return false;
		}
	}
	// send content of write buffer to party i_in
	time_t entry_time = time(NULL);
	size_t realnum = 0;
	do
	{
		// select(2) -- do everything with asynchronous I/O
		fd_set wfds;
		struct timeval tv;
		int retval;
		FD_ZERO(&wfds);
		FD_SET(fd_out[i_in], &wfds);
		tv.tv_sec = 0;
		tv.tv_usec = 1000; // sleep only for 1000us = 1ms
		retval = select((fd_out[i_in] + 1), NULL, &wfds, NULL, &tv);
		if (retval < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				perror("aiounicast_select (select)");
				delete [] buf;
				return false;
			}
		}
		if (retval == 0)
			continue;
		// write(2) -- ready for non-blocking write?
		if (FD_ISSET(fd_out[i_in], &wfds))
		{
			ssize_t num = write(fd_out[i_in], buf + realnum, realsize - realnum);
			if (num < 0)
			{
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
					(errno == EINTR))
				{
					if (errno == EAGAIN)
						perror("aiounicast_select (write)");
					continue;
				}
				else
				{
					perror("aiounicast_select (write)");
					delete [] buf;							
					return false;
				}
			}
			numWrite += num;
			realnum += num;
		}
		else
		{
			std::cerr << "WARNING: aiounicast_select(" << j << ") FD_ISSET" <<
				" not true" << std::endl;
		}
	}
	while ((realnum < realsize) && (time(NULL) < (entry_time + timeout)));
	delete [] buf;
	// timeout occurred?
	if (realnum < realsize)
	{
		std::cerr << "aiounicast_select(" << j << "):" <<
			" send timeout for " << i_in << std::endl;
		return false;
	}
	if (aio_is_authenticated)
	{
		// get current MAC buffer and reset MAC
		size_t macbuflen = maclen;
		unsigned char *macbuf = new unsigned char[macbuflen];
		err = gcry_mac_read(*mac_out[i_in], macbuf, &macbuflen);
		if (err)
		{
			std::cerr << "aiounicast_select: gcry_mac_read() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			delete [] macbuf;
			return false;
		}
		err = gcry_mac_reset(*mac_out[i_in]);
		if (err)
		{
			std::cerr << "aiounicast_select: gcry_mac_reset() failed" <<
				std::endl << gcry_strerror(err) << std::endl;
			delete [] macbuf;
			return false;
		}
		// send content of MAC buffer (i.e. authentication tag)
		realnum = 0;
		do
		{
			// select(2) -- do everything with asynchronous I/O
			fd_set wfds;
			struct timeval tv;
			int retval;
			FD_ZERO(&wfds);
			FD_SET(fd_out[i_in], &wfds);
			tv.tv_sec = 0;
			tv.tv_usec = 1000; // sleep only for 1000us = 1ms
			retval = select((fd_out[i_in] + 1), NULL, &wfds, NULL, &tv);
			if (retval < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				{
					perror("aiounicast_select (select)");
					delete [] macbuf;
					return false;
				}
			}
			if (retval == 0)
				continue;
			// write(2) -- ready for non-blocking write?
			if (FD_ISSET(fd_out[i_in], &wfds))
			{
				ssize_t num = write(fd_out[i_in], macbuf + realnum,
					macbuflen - realnum);
				if (num < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
						(errno == EINTR))
					{
						if (errno == EAGAIN)
							perror("aiounicast_select (write)");
						continue;
					}
					else
					{
						perror("aiounicast_select (write)");
						delete [] macbuf;
						return false;
					}
				}
				numWrite += num;
				realnum += num;
			}
			else
			{
				std::cerr << "WARNING: aiounicast_select FD_ISSET not true" <<
					std::endl;
			}
		}
		while ((realnum < macbuflen) && (time(NULL) < (entry_time + timeout)));
		delete [] macbuf;
		// timeout occurred?
		if (realnum < macbuflen)
		{
			std::cerr << "aiounicast_select(" << j << "):" <<
				" MAC send timeout for " << i_in << std::endl;
			return false;
		}
	}
	return true;
}

bool aiounicast_select::Send
	(const std::vector<mpz_srcptr> &m,
	 const size_t i_in,
	 time_t timeout)
{
	if (!aio_is_initialized)
		return false;
	if (timeout == aio_timeout_default)
		timeout = aio_default_timeout;
	for (size_t mm = 0; mm < m.size(); mm++)
	{
		if (!Send(m[mm], i_in, timeout))
			return false;
	}
	return true;
}

bool aiounicast_select::Receive
	(mpz_ptr m,
	 size_t &i_out,
	 size_t scheduler,
	 time_t timeout)
{
	if (!aio_is_initialized)
		return false;
	if (scheduler == aio_scheduler_default)
		scheduler = aio_default_scheduler;
	if (timeout == aio_timeout_default)
		timeout = aio_default_timeout;
	time_t entry_time = time(NULL);
	do
	{
		for (size_t round = 0; (round < n); round++)
		{
			// scheduler
			switch (scheduler)
			{
				case aio_scheduler_roundrobin:
					i_out = aio_schedule_current++;
					if (aio_schedule_current == n)
						aio_schedule_current = 0;
					break;
				case aio_scheduler_random:
					i_out = tmcg_mpz_wrandom_mod(n);
					break;
				case aio_scheduler_direct:
					if (i_out >= n)
						return false;
					break;
				default:
					i_out = n;
					return false;
			}
			// anything buffered from previous rounds?
			if (buf_flag[i_out])
			{
				// search for the first line delimiter
				bool newline_found = false;
				size_t newline_ptr = 0;
				for (size_t ptr = 0; ptr < buf_ptr[i_out]; ++ptr)
				{
					if (buf_in[i_out][ptr] == '\n')
					{
						newline_ptr = ptr;
						newline_found = true;
						break;
					}
				}
				// process the buffer
				if (newline_found &&
					((buf_ptr[i_out] - newline_ptr - 1) >= maclen))
				{
					// allocate at least one char
					size_t tmplen = newline_ptr + 1;
					char *tmp = new char[tmplen];
					// allocate at least one char, even if maclen == 0
					unsigned char *mac = new unsigned char[maclen + 1];
					memset(tmp, 0, tmplen);
					memset(mac, 0, maclen);
					if (newline_ptr > 0)
						memcpy(tmp, buf_in[i_out], newline_ptr);
					if (maclen > 0)
						memcpy(mac, buf_in[i_out] + tmplen, maclen);
					// adjust buffer (copy remaining characters)
					unsigned char *wptr = buf_in[i_out] + tmplen + maclen;
					size_t wnum = buf_ptr[i_out] - newline_ptr - 1 - maclen;
					if (wnum > 0)
						memmove(buf_in[i_out], wptr, wnum);
					else
						buf_flag[i_out] = false;
					buf_ptr[i_out] = wnum;
					// calculate, check, and reset MAC
					if (aio_is_authenticated)
					{
						gcry_error_t err;
						err = gcry_mac_write(*mac_in[i_out], tmp, newline_ptr);
						if (err)
						{
							std::cerr << "aiounicast_select:" <<
								" gcry_mac_write() failed" << std::endl <<
								gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						numAuthenticated += newline_ptr;
						unsigned char delim = '\n'; // include line delimiter
						err = gcry_mac_write(*mac_in[i_out], &delim, 1);
						if (err)
						{
							std::cerr << "aiounicast_select:" <<
								" gcry_mac_write() failed" << std::endl <<
								gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						numAuthenticated += 1;
						err = gcry_mac_verify(*mac_in[i_out], mac, maclen);
						if (err)
						{
							std::cerr << "aiounicast_select:" <<
								" gcry_mac_verify() for " << j << " from " <<
								i_out << " failed" << std::endl <<
								gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						err = gcry_mac_reset(*mac_in[i_out]);
						if (err)
						{
							std::cerr << "aiounicast_select:" <<
								" gcry_mac_reset() failed" << std::endl <<
								gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
					}
					// convert and decrypt the corresponding part of read buffer
					if (aio_is_encrypted)
					{
						mpz_t encval;
						mpz_init(encval);
						if (mpz_set_str(encval, tmp, TMCG_MPZ_IO_BASE) < 0)
						{
							std::cerr << "aiounicast_select: mpz_set_str()" <<
								" for encval failed" << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						size_t realsize = 0;
						memset(tmp, 0, tmplen); // clear tmp buffer
						mpz_export(tmp, &realsize, 1, 1, 1, 0, encval);
						if (realsize == 0)
						{
							std::cerr << "aiounicast_select: mpz_export()" <<
								" failed for " << encval << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						mpz_clear(encval);
						if (tmp[0] != '+')
						{
							std::cerr << "aiounicast_select: no prefix" <<
								" found" << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						gcry_error_t err;
						err = gcry_cipher_decrypt(*enc_in[i_out], tmp + 1,
							realsize - 1, NULL, 0);
						if (err)
						{
							std::cerr << "aiounicast_select:" <<
								" gcry_cipher_decrypt() failed" << std::endl <<
								gcry_strerror(err) << std::endl;
							delete [] tmp, delete [] mac;
							return false;
						}
						numDecrypted += (realsize - 1);
						memmove(tmp, tmp + 1, realsize - 1); // remove prefix
						tmp[realsize-1] = 0x00; // append a c-string delimiter
					}
					// extract value of m
					if (mpz_set_str(m, tmp, TMCG_MPZ_IO_BASE) < 0)
					{
						std::cerr << "aiounicast_select: mpz_set_str() for" <<
							" m from " << i_out << " failed" << std::endl;
						delete [] tmp, delete [] mac;
						return false;
					}
					delete [] tmp, delete [] mac;
					if (aio_is_encrypted)
						mpz_sub(m, m, aio_hide_length);
					return true;
				}
				// no delimiter found; invalidate buffer flag
				buf_flag[i_out] = false;
			}
			// check whether input file descriptor exists
			if (!fd_in.count(i_out))
				continue;
			size_t maxbuf = buf_in_size - buf_ptr[i_out];
			if (maxbuf > 0)
			{
				// select(2) -- do everything with asynchronous I/O
				fd_set rfds;
				struct timeval tv;
				int retval;
				FD_ZERO(&rfds);
				FD_SET(fd_in[i_out], &rfds);
				tv.tv_sec = 0;
				tv.tv_usec = 50000; // sleep only for 50000us = 50ms
				retval = select((fd_in[i_out] + 1), &rfds, NULL, NULL, &tv);
				if (retval < 0)
				{
					if (errno == EINTR)
					{
						continue;
					}
					else
					{
						perror("aiounicast_select (select)");
						return false;
					}
				}
				if (retval == 0)
					continue;
				// read(2) -- ready for non-blocking read?
				if (FD_ISSET(fd_in[i_out], &rfds))
				{
					unsigned char *rptr = buf_in[i_out] + buf_ptr[i_out];
					ssize_t num = read(fd_in[i_out], rptr, maxbuf);
					if (num < 0)
					{
						perror("aiounicast_select (read)");
						return false;
					}
					if (num == 0)
					{
						// got EOF
						std::cerr << "aiounicast_select(" << j << "):" <<
							" got EOF for " << i_out << std::endl;
						fd_in.erase(i_out); // erase input file descriptor
						fd_out.erase(i_out); // erase output file descriptor
						continue;
					}
					buf_ptr[i_out] += num;
					numRead += num;
					if (aio_is_encrypted)
					{
						// take first blklen bytes from sender as IV for cipher
						if (!iv_flag_in[i_out] && (buf_ptr[i_out] >= blklen))
						{
							gcry_error_t err;							
							err = gcry_cipher_setiv(*enc_in[i_out],
								buf_in[i_out], blklen);
							if (err)
							{
								aio_is_initialized = false;
								std::cerr << "aiounicast_select:" <<
									" gcry_cipher_setiv() failed" << std::endl <<
									gcry_strerror(err) << std::endl;
							}
							iv_flag_in[i_out] = true; // IV is set
							num = buf_ptr[i_out] - blklen; // # of remaining bytes
							// remove IV from the read buffer
							memmove(buf_in[i_out], buf_in[i_out] + blklen, num);
							buf_ptr[i_out] = num;
						}
						if (iv_flag_in[i_out] && (num > 0))
							buf_flag[i_out] = true;
					}
					else if (num > 0)
						buf_flag[i_out] = true;
				}
				else
				{
					std::cerr << "WARNING: aiounicast_select FD_ISSET" <<
						" not true" << std::endl;
				}
			}
			else
			{
				std::cerr << "WARNING: aiounicast_select read buffer" <<
					" exceeded" << std::endl;
			}
		}
	}
	while (time(NULL) < (entry_time + timeout));
	if (scheduler != aio_scheduler_direct)
		i_out = n; // timeout for some (unknown) parties
	else
	{
		std::cerr << "aiounicast_select(" << j << "):" <<
			" timeout for " << i_out << std::endl;
	}
	return false;
}

bool aiounicast_select::Receive
	(std::vector<mpz_ptr> &m,
	 size_t &i_out,
	 size_t scheduler,
	 time_t timeout)
{
	if (!aio_is_initialized)
		return false;
	if (scheduler == aio_scheduler_default)
		scheduler = aio_default_scheduler;
	if (timeout == aio_timeout_default)
		timeout = aio_default_timeout;
	time_t entry_time = time(NULL);
	do
	{
		// scheduler
		switch (scheduler)
		{
			case aio_scheduler_roundrobin:
				i_out = aio_schedule_buffer++;
				if (aio_schedule_buffer == n)
					aio_schedule_buffer = 0;
				break;
			case aio_scheduler_random:
				i_out = tmcg_mpz_wrandom_mod(n);
				break;
			case aio_scheduler_direct:
				if (i_out >= n)
					return false;
				break;
			default:
				i_out = n;
				return false;
		}
		// return, if enough messages are received from i_out
		if (buf_mpz[i_out].size() >= m.size())
		{
			// copy results and release buffer
			for (size_t mm = 0; mm < m.size(); mm++)
			{
				mpz_set(m[mm], buf_mpz[i_out].front());
				mpz_clear(buf_mpz[i_out].front());
				delete [] buf_mpz[i_out].front();
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
		if (Receive(tmp, i, scheduler, 0))
		{
			buf_mpz[i].push_back(tmp);
		}
		else
		{
			mpz_clear(tmp);
			delete [] tmp;
			// error at Receive()?
			if (i < n)
			{
				i_out = i;
				return false;
			}
		}
	}
	while (time(NULL) < (entry_time + timeout));
	i_out = n; // timeout for all parties
	return false;			
}

aiounicast_select::~aiounicast_select
	()
{
	fd_in.clear(), fd_out.clear();
	for (size_t i = 0; i < n; i++)
	{
		delete [] buf_in[i];
		while (buf_mpz[i].size())
		{
			mpz_clear(buf_mpz[i].front());
			delete [] buf_mpz[i].front();
			buf_mpz[i].pop_front();
		}
		buf_mpz[i].clear();
		// release MACs
		if (aio_is_authenticated)
		{
			gcry_mac_close(*mac_in[i]), gcry_mac_close(*mac_out[i]);
			delete mac_in[i], delete mac_out[i];
		}
		// release ciphers
		if (aio_is_encrypted)
		{
			gcry_cipher_close(*enc_in[i]), gcry_cipher_close(*enc_out[i]);
			delete enc_in[i], delete enc_out[i];
			delete [] iv_out[i];
		}
	}
	buf_in.clear(), buf_ptr.clear(), buf_flag.clear();
	buf_mpz.clear();
	iv_out.clear(), iv_flag_in.clear(), iv_flag_out.clear();
	mac_in.clear(), mac_out.clear();
	enc_in.clear(), enc_out.clear();
}

