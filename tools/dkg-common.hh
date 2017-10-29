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

#ifndef INCLUDED_dkg_common_HH
	#define INCLUDED_dkg_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <vector>
	#include <list>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <ctime>
	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <libTMCG.hh>

	bool read_key_file
		(const std::string filename, std::string &result);
	void init_mpis
		();
	bool parse_message
		(const std::string in, tmcg_octets_t &enc_out,
		bool &have_seipd_out);
	bool decrypt_message
		(const bool have_seipd, const tmcg_octets_t &in,
		tmcg_octets_t &key, tmcg_octets_t &out);
	bool parse_signature
		(const std::string in, tmcg_byte_t stype,
		time_t &sigcreationtime_out, time_t &sigexpirationtime_out,
		tmcg_byte_t &hashalgo_out, tmcg_octets_t &trailer_out);
	bool parse_public_key
		(const std::string in,
		time_t &keycreationtime_out, time_t &keyexpirationtime_out);
	bool parse_private_key
		(const std::string in,
		time_t &keycreationtime_out, time_t &keyexpirationtime_out,
		std::vector<std::string> &capl_out);
	void release_mpis
		();

#endif

