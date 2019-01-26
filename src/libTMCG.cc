/*******************************************************************************
   libTMCG.cc, general functions of the library

   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2007,
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "libTMCG.hh"

#ifdef BOTAN
	#include <botan/version.h>
#endif

// LibTMCG identifier
static const std::string LibTMCG_ID = 
    "LibTMCG " VERSION "  (C) Heiko Stamer, License: GNU GPL version 2";

// LibTMCG helper functions
void* tmcg_realloc
	(void* ptr, size_t old_size, size_t new_size)
{
	assert((old_size == 0) || (old_size != 0)); // to supress compiler warning
	return gcry_realloc(ptr, new_size);
}
void tmcg_free
	(void* ptr, size_t size)
{
	if (size > 0)
		gcry_free(ptr);
}

// LibTMCG general functions
bool init_libTMCG
	(const bool force_secmem, const bool gmp_secmem, const size_t max_secmem)
{
	// initialize memory guards
	CallasDonnerhackeFinneyShawThayerRFC4880::MemoryGuardReset();

	// initialize libgcrypt
	if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
	{
		std::cerr << "init_libTMCG(): libgcrypt version >= " <<
			TMCG_LIBGCRYPT_VERSION << " needed" << std::endl;
		return false;
	}
	if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
	{
		if (force_secmem)
		{
			gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
			gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);
			gcry_control(GCRYCTL_INIT_SECMEM, max_secmem, 0);
			gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
		}
		else
			gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // disable secure memory
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
	// check libgcrypt
	gcry_error_t ret = gcry_control(GCRYCTL_SELFTEST);
	if (ret)
	{
		std::cerr << "init_libTMCG(): libgcrypt self-test " <<
			"failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		return false;
	}
	if (gcry_md_test_algo(TMCG_GCRY_MD_ALGO)) // check for digest algorithm
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			TMCG_GCRY_MD_ALGO << " [" <<
			gcry_md_algo_name(TMCG_GCRY_MD_ALGO) <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_mac_test_algo(TMCG_GCRY_MAC_ALGO)) // check for MAC algorithm
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			TMCG_GCRY_MAC_ALGO << " [" <<
			gcry_mac_algo_name(TMCG_GCRY_MAC_ALGO) <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_cipher_test_algo(TMCG_GCRY_ENC_ALGO)) // check for cipher
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			TMCG_GCRY_ENC_ALGO << " [" <<
			gcry_cipher_algo_name(TMCG_GCRY_ENC_ALGO) <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_md_test_algo(GCRY_MD_SHA1)) // check for SHA-1
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_MD_SHA1 << " [" <<
			"SHA-1" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_md_test_algo(GCRY_MD_SHA256)) // check for SHA2-256
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_MD_SHA256 << " [" <<
			"SHA2-256" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_md_test_algo(GCRY_MD_SHA384)) // check for SHA2-384
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_MD_SHA384 << " [" <<
			"SHA2-384" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_md_test_algo(GCRY_MD_SHA512)) // check for SHA2-512
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_MD_SHA512 << " [" <<
			"SHA2-512" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_cipher_test_algo(GCRY_CIPHER_AES)) // check for AES128
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_CIPHER_AES << " [" <<
			"AES128" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_cipher_test_algo(GCRY_CIPHER_AES192)) // check for AES192
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_CIPHER_AES192 << " [" <<
			"AES192" <<
			"] not available" << std::endl;
		return false;
	}
	if (gcry_cipher_test_algo(GCRY_CIPHER_AES256)) // check for AES256
	{
		std::cerr << "init_libTMCG(): libgcrypt algorithm " <<
			GCRY_CIPHER_AES256 << " [" <<
			"AES256" <<
			"] not available" << std::endl;
		return false;
	}

	// initialize libgmp
	if (strcmp(gmp_version, TMCG_LIBGMP_VERSION) < 0)
	{
		std::cerr << "init_libTMCG(): libgmp version >= " <<
			TMCG_LIBGMP_VERSION << " needed" << std::endl;
		return false;
	}
	if (gmp_secmem)
		mp_set_memory_functions(gcry_malloc_secure, tmcg_realloc, tmcg_free);

#ifdef BOTAN
	// initialize libbotan-2
	std::string botan_rvc = Botan::runtime_version_check(BOTAN_VERSION_MAJOR,
		BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);
	if (botan_rvc != "")
	{
		std::cerr << "init_libTMCG(): libbotan-2 runtime version check" <<
			" failed with \"" << botan_rvc << "\"" << std::endl;
		return false;
	}
#endif
	return true;
}

const std::string version_libTMCG
	()
{
	return std::string(VERSION);
}

const std::string identifier_libTMCG
	()
{
	return LibTMCG_ID;
}


