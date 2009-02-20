/*******************************************************************************
   libTMCG.cc, general functions of the library

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2007  Heiko Stamer <stamer@gaos.org>

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

#include "libTMCG.hh"

// LibTMCG identifier
std::string LibTMCG_ID = 
    "LibTMCG "VERSION"  (C) Heiko Stamer, License: GNU GPL version 2";

// LibTMCG general functions
bool init_libTMCG
	()
{
	// initialize libgmp
	if (strcmp(gmp_version, TMCG_LIBGMP_VERSION) < 0)
	{
		std::cerr << "init_libTMCG(): libgmp version >= " <<
			TMCG_LIBGMP_VERSION << " needed" << std::endl;
		return false;
	}
	
	// initialize libgcrypt
	if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
	{
		std::cerr << "init_libTMCG(): libgcrypt version >= " <<
			TMCG_LIBGCRYPT_VERSION << " needed" << std::endl;
		return false;
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // disable secure memory
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO)) // check for digest algorithm
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			TMCG_GCRY_MD_ALGO << " [" <<
			gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
			"] not available" << std::endl;
		return false;
	}
	return true;
}

std::string version_libTMCG
	()
{
	return std::string(VERSION);
}
