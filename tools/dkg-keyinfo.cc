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

#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctime>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid;
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
gcry_mpi_t 				gk, myk;

int 					opt_verbose = 0;

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-keyinfo [OPTIONS] PEER";
	static const char *about = "show information about private threshold key share";

	if (argc < 2)
	{
		std::cerr << "ERROR: no peer given as argument; usage: " << usage << std::endl;
		return -1;
	}
	else
	{
		// parse argument list
		for (size_t i = 0; i < (size_t)(argc - 1); i++)
		{
			std::string arg = argv[i+1];
			if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
			{
				if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
				{
					std::cout << usage << std::endl;
					std::cout << about << std::endl;
					std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
					std::cout << "  -h, --help     print this help" << std::endl;
					std::cout << "  -v, --version  print the version number" << std::endl;
					std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
					return 0; // not continue
				}
				if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
				{
					std::cout << "dkg-keyinfo " << VERSION << std::endl;
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
			// store argument for peer list
			if (arg.length() <= 255)
			{
				peers.push_back(arg);
			}
			else
			{
				std::cerr << "ERROR: peer identity \"" << arg << "\" too long" << std::endl;
				return -1;
			}
		}
		// canonicalize peer list
		std::sort(peers.begin(), peers.end());
		std::vector<std::string>::iterator it = std::unique(peers.begin(), peers.end());
		peers.resize(std::distance(peers.begin(), it));
	}
	if (peers.size() != 1)
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}

	// read and parse the private key
	std::string armored_seckey, thispeer = peers[0];
	if (!read_private_key(thispeer + "_dkg-sec.asc", armored_seckey))
		exit(-1);
	init_mpis();
	std::vector<std::string> CAPL;
	time_t ckeytime = 0, ekeytime = 0;
	if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
	{
		keyid.clear(), pub.clear(), sub.clear(), uidsig.clear(), subsig.clear();
		dss_qual.clear(), dss_c_ik.clear();
		// protected with password
		std::cout << "Please enter the passphrase to unlock your private key: ";
		std::getline(std::cin, passphrase);
		std::cin.clear();
		if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
		{
			std::cerr << "ERROR: wrong passphrase to unlock private key" << std::endl;
			release_mpis();
			exit(-1);
		}
	}

	// create an instance of tDSS by stored parameters from private key
	std::stringstream dss_in;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl << dss_t << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl;
	dss_in << "0" << std::endl << "0" << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	assert((dss_c_ik.size() == dss_n));
	for (size_t i = 0; i < dss_c_ik.size(); i++)
	{
		for (size_t j = 0; j < dss_c_ik.size(); j++)
			dss_in << "0" << std::endl << "0" << std::endl;
		assert((dss_c_ik[i].size() == (dss_t + 1)));
		for (size_t k = 0; k < dss_c_ik[i].size(); k++)
			dss_in << dss_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cout << "CanettiGennaroJareckiKrawczykRabinDSS(in, ...)" << std::endl;
	CanettiGennaroJareckiKrawczykRabinDSS *dss = new CanettiGennaroJareckiKrawczykRabinDSS(dss_in);
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: tDSS domain parameters are not correctly generated!" << std::endl;
		delete dss;
		release_mpis();
		exit(-1);
	}

	GennaroJareckiKrawczykRabinDKG *dkg = NULL;
	if (sub.size())
	{
		// create an instance of DKG by stored parameters from private key
		std::stringstream dkg_in;
		dkg_in << dkg_p << std::endl << dkg_q << std::endl << dkg_g << std::endl << dkg_h << std::endl;
		dkg_in << dkg_n << std::endl << dkg_t << std::endl << dkg_i << std::endl;
		dkg_in << dkg_x_i << std::endl << dkg_xprime_i << std::endl << dkg_y << std::endl;
		dkg_in << dkg_qual.size() << std::endl;
		for (size_t i = 0; i < dkg_qual.size(); i++)
			dkg_in << dkg_qual[i] << std::endl;
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "1" << std::endl; // y_i not yet stored
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "0" << std::endl; // z_i not yet stored
		assert((dkg_v_i.size() == dkg_n));
		for (size_t i = 0; i < dkg_v_i.size(); i++)
			dkg_in << dkg_v_i[i] << std::endl;
		assert((dkg_c_ik.size() == dkg_n));
		for (size_t i = 0; i < dkg_n; i++)
		{
			for (size_t j = 0; j < dkg_n; j++)
				dkg_in << "0" << std::endl << "0" << std::endl; // s_ij and sprime_ij not yet stored
			assert((dkg_c_ik[i].size() == (dkg_t + 1)));
			for (size_t k = 0; k < dkg_c_ik[i].size(); k++)
				dkg_in << dkg_c_ik[i][k] << std::endl;
		}
		if (opt_verbose)
			std::cout << "GennaroJareckiKrawczykRabinDKG(in, ...)" << std::endl;
		dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
		if (!dkg->CheckGroup())
		{
			std::cerr << "ERROR: DKG domain parameters are not correctly generated!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			exit(-1);
		}
		if (!dkg->CheckKey())
		{
			std::cerr << "ERROR: DKG CheckKey() failed!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			exit(-1);
		}
	}

	// show information
	std::ios oldcoutstate(NULL);
	oldcoutstate.copyfmt(std::cout);
	std::cout << "OpenPGP V4 Key ID of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < keyid.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)keyid[i] << " ";
	std::cout << std::dec << std::endl;
	tmcg_octets_t pub_hashing, fpr;
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(pub_hashing, fpr);
	std::cout << "OpenPGP V4 fingerprint of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < fpr.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)fpr[i] << " ";
	std::cout << std::dec << std::endl;
	std::cout << "OpenPGP Key Creation Time: " << std::endl << "\t" << ctime(&ckeytime);
	std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
	if (ekeytime == 0)
		std::cout << "undefined" << std::endl;
	else
	{
		ekeytime += ckeytime; // validity period of the key after key creation time
		std::cout << ctime(&ekeytime);
	}
	std::cout << "OpenPGP User ID: " << std::endl << "\t";
	std::cout << userid << std::endl;
	std::cout << "Security level of domain parameter set: " << std::endl << "\t"; 
	std::cout << "|p| = " << mpz_sizeinbase(dss->p, 2L) << " bit, ";
	std::cout << "|q| = " << mpz_sizeinbase(dss->q, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(dss->g, 2L) << " bit, ";
	std::cout << "|h| = " << mpz_sizeinbase(dss->h, 2L) << " bit" << std::endl;
	if (dss->n != 0)
	{
		std::cout << "Threshold parameter set of primary key (tDSS): " << std::endl << "\t";
		std::cout << "n = " << dss->n << ", s = " << dss->t << std::endl;
		std::cout << "Set of non-disqualified parties of primary key (tDSS): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dss->QUAL.size(); i++)
			std::cout << "P_" << dss->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Unique identifier of this party: " << std::endl << "\t";
		std::cout << "P_" << dss->i << std::endl;
		std::cout << "Canonicalized peer list (CAPL): " << std::endl;
		assert(CAPL.size() == dss->QUAL.size());
		for (size_t i = 0; i < CAPL.size(); i++)
			std::cout << "\t" << "P_" << dss->QUAL[i] << "\t" << CAPL[i] << std::endl;
	}
	if (sub.size() && (dkg != NULL))
	{
		std::cout << "OpenPGP V4 Key ID of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < subkeyid.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)subkeyid[i] << " ";
		std::cout << std::dec << std::endl;
		tmcg_octets_t sub_hashing, sub_fpr;
		for (size_t i = 6; i < sub.size(); i++)
			sub_hashing.push_back(sub[i]);
		CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(sub_hashing, sub_fpr);
		std::cout << "OpenPGP V4 fingerprint of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < sub_fpr.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)sub_fpr[i] << " ";
		std::cout << std::dec << std::endl;
		std::cout << "Threshold parameter set of subkey: " << std::endl << "\t";
		std::cout << "n = " << dkg->n << ", t = " << dkg->t << std::endl;
		std::cout << "Set of non-disqualified parties of subkey: " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dkg->QUAL.size(); i++)
			std::cout << "P_" << dkg->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Public verification keys (v_i): " << std::endl;
		for (size_t i = 0; i < dkg->v_i.size(); i++)
			std::cout << "\t" << "P_" << i << "\t" << dkg->v_i[i] << std::endl;
	}

	// restore default formatting
	std::cout.copyfmt(oldcoutstate);

	// release
	if (sub.size() && (dkg != NULL))
		delete dkg;
	delete dss;
	release_mpis();
	
	return 0;
}

