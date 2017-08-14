/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dkg_builtin_common_HH
	#define INCLUDED_dkg_builtin_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <list>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <aiounicast.hh>
	#include <mpz_srandom.h>

	#include <sys/types.h>
	#include <sys/wait.h>
	#include <signal.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <sys/socket.h>

	#define MAX_N 32

	RETSIGTYPE builtin_sig_handler_quit
		(int sig);
	void builtin_init
		(const std::string &hostname);
	void builtin_bindports
		(const uint16_t start, const bool broadcast);
	size_t builtin_connect
		(const uint16_t start, const bool broadcast);
	void builtin_accept
		();
	void builtin_fork
		();
	int builtin_io
		();
	void builtin_close
		();
	void builtin_done
		();

#endif

