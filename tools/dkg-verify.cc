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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

#include <fstream>
#include <vector>
#include <algorithm>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid, ifilename, kfilename;
tmcg_octets_t				keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
std::map<size_t, size_t>		idx2dkg, dkg2idx;
mpz_t					dss_p, dss_q, dss_g, dss_h, dss_x_i, dss_xprime_i, dss_y;
size_t					dss_n, dss_t, dss_i;
std::vector<size_t>			dss_qual;
std::vector< std::vector<mpz_ptr> >	dss_c_ik;
mpz_t					dkg_p, dkg_q, dkg_g, dkg_h, dkg_x_i, dkg_xprime_i, dkg_y;
size_t					dkg_n, dkg_t, dkg_i;
std::vector<size_t>			dkg_qual;
std::vector<mpz_ptr>			dkg_v_i;
std::vector< std::vector<mpz_ptr> >	dkg_c_ik;
gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_q, elg_g, elg_y, elg_x;
gcry_mpi_t 				gk, myk, sig_r, sig_s;

int 					opt_verbose = 0;
char					*opt_ifilename = NULL;

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-verify [OPTIONS] -i INPUTFILE KEYFILE";
	static const char *about = "verify a detached signature from STDIN according to OpenPGP (only DSA/DSS)";

	// parse command line arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-i") == 0)
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) && (opt_ifilename == NULL))
			{
				ifilename = argv[i+1];
				opt_ifilename = (char*)ifilename.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -i FILENAME    verify detached signature on FILENAME" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-verify " << VERSION << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		kfilename = arg;
	}
	if ((kfilename.length() == 0) || (ifilename.length() == 0))
	{
		std::cerr << "ERROR: some filename missing; usage: " << usage << std::endl;
		return -1;
	}
	else if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}

	// read and parse the public key
	std::string armored_pubkey;
	if (!read_key_file(kfilename, armored_pubkey))
		return -1;
	init_mpis();
	time_t ckeytime = 0, ekeytime = 0;
	if (!parse_public_key(armored_pubkey, ckeytime, ekeytime))
	{
		std::cerr << "ERROR: cannot parse the provided public key" << std::endl;
		release_mpis();
		return -1;
	}

	// read the signature from stdin
	std::string signature;
	char c;
	while (std::cin.get(c))
		signature += c;
	std::cin.clear();

	// parse the signature
	tmcg_octets_t trailer;
	tmcg_byte_t hashalgo = 0;
	time_t csigtime = 0, sigexptime = 0;
	if (!parse_signature(signature, 0x00, csigtime, sigexptime, hashalgo, trailer))
	{
		std::cerr << "ERROR: cannot parse the provided signature" << std::endl;
		release_mpis();
		return -1;
	}

	// compute the hash of the input file
	if (opt_verbose)
		std::cout << "INFO: hashing the input file \"" << opt_ifilename << "\"" << std::endl;
	tmcg_octets_t hash, left;
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash(opt_ifilename, trailer, hashalgo, hash, left))
	{
		std::cerr << "ERROR: BinaryDocumentHash() failed; cannot process input file \"" << opt_ifilename << "\"" << std::endl;
		release_mpis();
		return -1;
	}

	// verify the signature
	gcry_error_t ret;
	gcry_sexp_t dsakey;
	size_t erroff;
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		release_mpis();
		return ret;
	}
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, sig_r, sig_s);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricVerifyDSA() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		release_mpis();
		gcry_sexp_release(dsakey);
		return ret;
	}

	// release mpis and keys
	release_mpis();
	gcry_sexp_release(dsakey);
	
	return 0;
}
