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
#include <aiounicast_select.hh>
static const char *version = VERSION; // copy VERSION from LibTMCG before overwritten by GNUnet headers

#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "dkg-builtin-common.hh"
#include "dkg-gnunet-common.hh"
#include "dkg-common.hh"

int 					pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t 					pid[MAX_N];
std::vector<std::string>		peers;
bool					instance_forked = false;

std::string				passphrase, userid, passwords, hostname, port;
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
char					*opt_passwords = NULL;
char					*opt_hostname = NULL;
unsigned long int			opt_p = 55000;

void run_instance
	(size_t whoami, const size_t num_xtests)
{
	// read and parse the private key
	std::string armored_seckey, thispeer = peers[whoami];
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
			std::cerr << "R_" << whoami << ": wrong passphrase to unlock private key" << std::endl;
			release_mpis();
			exit(-1);
		}
	}

	// create communication handles between all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		std::stringstream key;
		if (opt_passwords != NULL)
		{
			std::string pwd;
			if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
			{
				std::cerr << "R_" << whoami << ": " << "cannot read password for protecting channel to R_" << i << std::endl;
				release_mpis();
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) && !TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "R_" << whoami << ": " << "cannot skip to next password for protecting channel to R_" << (i + 1) << std::endl;
				release_mpis();
				exit(-1);
			}
		}
		else
			key << "dkg-refresh::R_" << (i + whoami); // use simple key -- we assume that GNUnet will provide secure channels
		uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(key.str());
		bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(key.str());
	}

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou = new aiounicast_select(peers.size(), whoami, uP_in, uP_out, uP_key);

	// create asynchronous authenticated unicast channels for broadcast protocol
	aiounicast_select *aiou2 = new aiounicast_select(peers.size(), whoami, bP_in, bP_out, bP_key);
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-refresh|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	size_t T_RBC = (peers.size() - 1) / 3; // assume maximum asynchronous t-resilience for RBC
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami, aiou2);
	rbc->setID(myID);

	// perform a simple exchange test with debug output
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t xtest;
		mpz_init_set_ui(xtest, i);
		std::cout << "R_" << whoami << ": xtest = " << xtest << " <-> ";
		rbc->Broadcast(xtest);
		for (size_t ii = 0; ii < peers.size(); ii++)
		{
			if (!rbc->DeliverFrom(xtest, ii))
				std::cout << "<X> ";
			else
				std::cout << xtest << " ";
		}
		std::cout << std::endl;
		mpz_clear(xtest);
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
		std::cerr << "R_" << whoami << ": " << "tDSS domain parameters are not correctly generated!" << std::endl;
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	// update the tDSS keys (proactive security against mobile adversary)
	std::stringstream err_log;
	if (opt_verbose)
		std::cout << "R_" << whoami << ": dss.Refresh()" << std::endl;
	if (!dss->Refresh(peers.size(), whoami, idx2dkg, dkg2idx, aiou, rbc, err_log, false))
	{
		std::cerr << "R_" << whoami << ": " << "tDSS Refresh() failed" << std::endl;
		std::cerr << "R_" << whoami << ": log follows " << std::endl << err_log.str();
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (opt_verbose > 1)
		std::cout << "R_" << whoami << ": log follows " << std::endl << err_log.str();
	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_very_long;
	if (opt_verbose)
		std::cout << "R_" << whoami << ": waiting " << synctime << " seconds for stalled parties" << std::endl;
	rbc->Sync(synctime);
	// create an OpenPGP DSA-based primary key using refreshed values from tDSS
	gcry_mpi_t p, q, g, h, y, n, t, i, qualsize, x_i, xprime_i;
	std::vector<gcry_mpi_t> qual;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	if (!mpz_get_gcry_mpi(&p, dss->p))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for p" << std::endl;
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&q, dss->q))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for q" << std::endl;
		gcry_mpi_release(p);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&g, dss->g))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for g" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&h, dss->h))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for h" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&y, dss->y))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for y" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(h);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&x_i, dss->x_i))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for x_i" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(h);
		gcry_mpi_release(y);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&xprime_i, dss->xprime_i))
	{
		std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for xprime_i" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(h);
		gcry_mpi_release(y);
		gcry_mpi_release(x_i);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	n = gcry_mpi_set_ui(NULL, dss->n);
	t = gcry_mpi_set_ui(NULL, dss->t);
	i = gcry_mpi_set_ui(NULL, dss->i);
	qualsize = gcry_mpi_set_ui(NULL, dss->QUAL.size());
	for (size_t j = 0; j < dss->QUAL.size(); j++)
	{
		gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dss->QUAL[j]);
		qual.push_back(tmp);
	}
	c_ik.resize(dss->n);
	for (size_t j = 0; j < c_ik.size(); j++)
	{
		for (size_t k = 0; k <= dss->t; k++)
		{
			gcry_mpi_t tmp;
			if (!mpz_get_gcry_mpi(&tmp, dss->dkg->x_rvss->C_ik[j][k]))
			{
				std::cerr << "R_" << whoami << ": mpz_get_gcry_mpi() failed for dss->dkg->x_rvss->C_ik[j][k]" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				gcry_mpi_release(x_i);
				gcry_mpi_release(xprime_i);
				gcry_mpi_release(n);
				gcry_mpi_release(t);
				gcry_mpi_release(i);
				gcry_mpi_release(qualsize);
				for (size_t jj = 0; jj < qual.size(); jj++)
					gcry_mpi_release(qual[jj]);
				for (size_t jj = 0; jj < c_ik.size(); jj++)
					for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
						gcry_mpi_release(c_ik[jj][kk]);
				delete dss, delete rbc, delete aiou, delete aiou2;
				release_mpis();
				exit(-1); 
			}
			c_ik[j].push_back(tmp);
		}
	}
	sec.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental108(ckeytime, p, q, g, h, y, 
		n, t, i, qualsize, qual, CAPL, c_ik, x_i, xprime_i, passphrase, sec);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(h);
	gcry_mpi_release(y);
	gcry_mpi_release(x_i);
	gcry_mpi_release(xprime_i);
	gcry_mpi_release(n);
	gcry_mpi_release(t);
	gcry_mpi_release(i);
	gcry_mpi_release(qualsize);
	for (size_t j = 0; j < qual.size(); j++)
		gcry_mpi_release(qual[j]);
	for (size_t j = 0; j < c_ik.size(); j++)
		for (size_t k = 0; k < c_ik[j].size(); k++)
			gcry_mpi_release(c_ik[j][k]);
	
	// export updated private keys in OpenPGP armor format
	tmcg_octets_t all;
	std::string armor;
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	armor = "", all.clear();
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out | std::ofstream::trunc);
	if (!secofs.good())
	{
		std::cerr << "R_" << whoami << ": opening private key file failed" << std::endl;
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	secofs << armor;
	if (!secofs.good())
	{
		std::cerr << "R_" << whoami << ": writing private key file failed" << std::endl;
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	secofs.close();

	// release tDSS
	delete dss;

	// release RBC
	delete rbc;
	
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
		std::cout << "R_" << whoami << ": aiou.numRead = " << aiou->numRead <<
			" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
		std::cout << "R_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
			" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;

	// release
	release_mpis();
}

#ifdef GNUNET
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-refresh (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant R_i */
#ifdef GNUNET
			run_instance(whoami, gnunet_opt_xtests);
#else
			run_instance(whoami, 0);
#endif
			if (opt_verbose)
				std::cout << "R_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant R_i */
		}
		else
		{
			if (opt_verbose)
				std::cout << "fork() = " << pid[whoami] << std::endl;
			instance_forked = true;
		}
	}
}

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-refresh [OPTIONS] PEERS";
	static const char *about = "threshold key refresh for OpenPGP (only tDSS key)";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
		GNUNET_GETOPT_option_string('p',
			"port",
			"STRING",
			"GNUnet CADET port to listen/connect",
			&gnunet_opt_port
		),
		GNUNET_GETOPT_option_string('P',
			"passwords",
			"STRING",
			"exchanged passwords to protect private and broadcast channels",
			&gnunet_opt_passwords
		),
		GNUNET_GETOPT_option_version(version),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of refresh protocol",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
	{
		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" << std::endl;
    		return -1;
	}
	if (GNUNET_GETOPT_run(usage, options, argc, argv) == GNUNET_SYSERR)
	{
		std::cerr << "ERROR: GNUNET_GETOPT_run() failed" << std::endl;
		return -1;
	}
	if (gnunet_opt_hostname != NULL)
		opt_hostname = gnunet_opt_hostname;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
#endif

	if (argc < 2)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << usage << std::endl;
		return -1;
	}
	else
	{
		// create peer list
		for (size_t i = 0; i < (size_t)(argc - 1); i++)
		{
			std::string arg = argv[i+1];
			// ignore options
			if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-r") == 0) || (arg.find("-w") == 0) || (arg.find("-L") == 0) || 
				(arg.find("-l") == 0) || (arg.find("-x") == 0) || (arg.find("-P") == 0) || (arg.find("-H") == 0))
			{
				size_t idx = ++i;
				if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) && (opt_hostname == NULL))
				{
					hostname = argv[i+1];
					opt_hostname = (char*)hostname.c_str();
				}
				if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) && (opt_passwords == NULL))
				{
					passwords = argv[i+1];
					opt_passwords = (char*)passwords.c_str();
				}
				if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) && (port.length() == 0))
					port = argv[i+1];
				continue;
			}
			else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
			{
				if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
				{
#ifndef GNUNET
					std::cout << usage << std::endl;
					std::cout << about << std::endl;
					std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
					std::cout << "  -h, --help     print this help" << std::endl;
					std::cout << "  -H STRING      hostname (e.g. onion address) of this peer within PEERS" << std::endl;
					std::cout << "  -p INTEGER     start port for built-in TCP/IP message exchange service" << std::endl;
					std::cout << "  -P STRING      exchanged passwords to protect private and broadcast channels" << std::endl;
					std::cout << "  -v, --version  print the version number" << std::endl;
					std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
				{
#ifndef GNUNET
					std::cout << "dkg-refresh " << version << std::endl;
#endif
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
	if ((peers.size() < 3)  || (peers.size() > MAX_N))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if ((opt_hostname != NULL) && (opt_passwords == NULL))
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure network" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cout << peers[i] << std::endl;
	}
	// initialize return code
	int ret = 0;
	// create underlying point-to-point channels, if built-in TCP/IP service requested
	if (opt_hostname != NULL)
	{
		if (port.length())
			opt_p = strtoul(port.c_str(), NULL, 10); // get start port from options
		builtin_init(hostname);
		builtin_bindports((uint16_t)opt_p, false);
		builtin_bindports((uint16_t)opt_p, true);
		while (builtin_connect((uint16_t)opt_p, false) < peers.size())
			sleep(1);
		while (builtin_connect((uint16_t)opt_p, true) < peers.size())
			sleep(1);
		builtin_accept();
		builtin_fork();
		ret = builtin_io();
		builtin_close();
		builtin_done();
		return ret;
	}

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_string('p',
			"port",
			"STRING",
			"GNUnet CADET port to listen/connect",
			&gnunet_opt_port
		),
		GNUNET_GETOPT_option_string('P',
			"passwords",
			"STRING",
			"exchanged passwords to protect private and broadcast channels",
			&gnunet_opt_passwords
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of refresh protocol",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
	ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run, argv[0]);
	GNUNET_free((void *) argv);
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNUnet development files are required for message exchange of refresh protocol" << std::endl;
#endif

	std::cout << "INFO: running local test with " << peers.size() << " participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("dkg-refresh (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("dkg-refresh (pipe)");
		}
	}
	
	// start childs
	for (size_t i = 0; i < peers.size(); i++)
		fork_instance(i);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (opt_verbose)
			std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-refresh (waitpid)");
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-refresh (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-refresh (close)");
		}
	}
	
	return 0;
}

