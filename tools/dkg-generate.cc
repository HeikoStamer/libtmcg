/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifdef FORKING

#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "pipestream.hh"
#include "dkg-gnunet-common.hh"

int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t				pid[MAX_N];
size_t				N, T;
std::string			crs, u, passphrase;
std::vector<std::string>	peers;
bool				instance_forked = false;

void run_instance
	(const size_t whoami, const time_t keytime)
{
	// create pipe streams and handles for all players
	std::vector<ipipestream*> P_in;
	std::vector<opipestream*> P_out;
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < N; i++)
	{
		std::stringstream key;
		key << "dkg-generate::P_" << (i + whoami); // choose a simple HMAC key
		P_in.push_back(new ipipestream(pipefd[i][whoami][0]));
		P_out.push_back(new opipestream(pipefd[whoami][i][1]));
		uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(key.str());
		bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(key.str());
	}
			
	// create VTMF instance
	std::stringstream crss;
	crss << crs;
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss);
	// check VTMF instance constructed from CRS (common reference string)
	if (!vtmf->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " <<
			"Group G was not correctly generated!" << std::endl;
		exit(-1);
	}

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou = new aiounicast_select(N, whoami, uP_in, uP_out, uP_key);

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou2 = new aiounicast_select(N, whoami, bP_in, bP_out, bP_key);
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-generate|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	myID += T; // include t-resiliance for the ID of broadcast protocol
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2);
	rbc->setID(myID);
			
	// create and exchange VTMF keys FIXME: async. operations and broadcast needed; otherwise VTMF key could be stored in DHT 
	vtmf->KeyGenerationProtocol_GenerateKey();
	for (size_t i = 0; i < N; i++)
	{
		if (i != whoami)
			vtmf->KeyGenerationProtocol_PublishKey(*P_out[i]);
	}
	for (size_t i = 0; i < N; i++)
	{
		if (i != whoami)
		{
			if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in[i]))
			{
				std::cerr << "P_" << whoami << ": " << "Public key of P_" << i << " was not correctly generated!" << std::endl;
				exit(-1);
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();

	// create an instance of DKG
	GennaroJareckiKrawczykRabinDKG *dkg;
	std::cout << "GennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
	dkg = new GennaroJareckiKrawczykRabinDKG(N, T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h);
	if (!dkg->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " << "DKG parameters are not correctly generated!" << std::endl;
		exit(-1);
	}
			
	// generating $x$ and extracting $y = g^x \bmod p$
	std::stringstream err_log;
	std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
	if (!dkg->Generate(aiou, rbc, err_log))
	{
		std::cerr << "P_" << whoami << ": " << "DKG Generate() failed" << std::endl;
		std::cerr << "P_" << whoami << ": log follows " << std::endl << err_log.str();
		exit(-1);
	}
	std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

	// check the generated key share
	std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
	if (!dkg->CheckKey())
	{
		std::cerr << "P_" << whoami << ": " << "DKG CheckKey() failed" << std::endl;
		exit(-1);
	}

	// participants must agree on a OpenPGP key creation time, otherwise subkeyid does not match
	time_t ckeytime = 0;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, keytime);
	rbc->Broadcast(mtv);
	tvs.push_back(keytime);
	for (size_t i = 0; i < N; i++)
	{
		if (i != whoami)
		{
			if (rbc->DeliverFrom(mtv, i))
			{
				time_t utv;
				utv = mpz_get_ui(mtv);
				tvs.push_back(utv);
			}
			else
				std::cerr << "P_" << whoami << ": " << "no key creation time received from " << i << std::endl;
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	ckeytime = tvs.back(); // use the biggest value as byzantine agreement
	std::cout << "P_" << whoami << ": canonicalized key creation time = " << ckeytime << std::endl;

	// at the end: deliver some more rounds for still waiting parties
	std::cout << "P_" << whoami << ": waiting " << aiounicast::aio_timeout_very_long << " seconds for stalled parties" << std::endl;
	mpz_t m;
	mpz_init(m);
	time_t entry_time = time(NULL);
	do
	{
		rbc->DeliverFrom(m, whoami);
	}
	while (time(NULL) < (entry_time + aiounicast::aio_timeout_very_long));
	mpz_clear(m);

	// create an OpenPGP DSA-based primary key and Elgamal-based subkey based on parameters from DKG
	char buffer[2048];
	std::string out, crcout, armor;
	OCTETS all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
	OCTETS pub_hashing, sub_hashing;
	OCTETS uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
	OCTETS hash;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	size_t erroff;
	mpz_t dsa_y, dsa_x;
	mpz_init(dsa_y), mpz_init(dsa_x);
	mpz_srandomm(dsa_x, vtmf->q);
	mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
			
	p = gcry_mpi_new(2048);
	q = gcry_mpi_new(2048);
	g = gcry_mpi_new(2048);
	y = gcry_mpi_new(2048);
	x = gcry_mpi_new(2048);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	mpz_get_str(buffer, 16, vtmf->p);
	ret = gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret); 
	mpz_get_str(buffer, 16, vtmf->q);
	ret = gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret); 
	mpz_get_str(buffer, 16, vtmf->g);
	ret = gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	mpz_get_str(buffer, 16, dsa_y);
	ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	mpz_get_str(buffer, 16, dsa_x);
	ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	ret = gcry_sexp_build(&key, &erroff, "(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))", p, q, g, y, p, q, g, y, x);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ckeytime, p, q, g, y, pub);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(ckeytime, p, q, g, y, x, passphrase, sec);
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, uid);
	dsaflags.push_back(0x01 | 0x02 | 0x20);
	sigtime = time(NULL); // current time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x13, sigtime, dsaflags, keyid, uidsig_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, 8, hash, uidsig_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
	hash.clear();
	mpz_get_str(buffer, 16, dkg->y);			
	ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	mpz_get_str(buffer, 16, dkg->z_i[dkg->i]);			
	ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ckeytime, p, g, y, sub);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(ckeytime, p, g, y, x, passphrase, ssb);
	elgflags.push_back(0x04 | 0x10);
	sigtime = time(NULL); // current time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x18, sigtime, elgflags, keyid, subsig_hashing);
	for (size_t i = 6; i < sub.size(); i++)
		sub_hashing.push_back(sub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, 8, hash, subsig_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
	// export generated public key in OpenPGP armor format
	std::stringstream pubfilename;
	pubfilename << peers[whoami] << "_dkg-pub.asc";
	armor = "", all.clear();
	all.insert(all.end(), pub.begin(), pub.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), sub.begin(), sub.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, all, armor);
	std::cout << armor << std::endl;
	std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
	pubofs << armor;
	pubofs.close();
	// export generated private key in OpenPGP armor format
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	armor = "", all.clear();
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
	std::cout << armor << std::endl;
	std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
	secofs << armor;
	secofs.close();
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(x);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	gcry_sexp_release(key);
	// export state of DKG including the secret shares into a file
	std::stringstream dkgfilename;
	dkgfilename << peers[whoami] << ".dkg";
	std::ofstream dkgofs((dkgfilename.str()).c_str(), std::ofstream::out);
	dkg->PublishState(dkgofs);
	dkgofs.close();

	// release DKG
	delete dkg;

	// release RBC			
	delete rbc;

	// release VTMF instances
	delete vtmf;
			
	// release pipe streams (private channels)
	size_t numRead = 0, numWrite = 0;
	for (size_t i = 0; i < N; i++)
	{
		numRead += P_in[i]->get_numRead() + P_out[i]->get_numRead();
		numWrite += P_in[i]->get_numWrite() + P_out[i]->get_numWrite();
		delete P_in[i], delete P_out[i];
	}
	std::cout << "P_" << whoami << ": numRead = " << numRead <<
		" numWrite = " << numWrite << std::endl;

	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	std::cout << "P_" << whoami << ": aiou.numRead = " << aiou->numRead <<
		" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	std::cout << "P_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
		" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;
}

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-generate (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			time_t keytime = time(NULL);
			run_instance(whoami, keytime);

			std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
		}
		else
		{
			std::cout << "fork() = " << pid[whoami] << std::endl;
			instance_forked = true;
		}
	}
}

#ifdef GNUNET
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_t_resilience = 0;
#endif

int main
	(int argc, char *const *argv)
{
	// setup CRS (common reference string) |p| = 2048 bit, |q| = 256 bit
	crs = "W8o8gvA20jfDUDcVBS250oR0uObgSsG9Lwj7HekVkgjr0ZGOSfEqFLIUTqTXE"
		"pGbrYROsq0T0UMI4QWW89B8Xv0O8G9xoQfOn2yO1ZdqamWLMcOR0zYUSVdWh"
		"GntzQwshVR8rsqzditokxyshQTkQcZ2RSASrTXtT6J8MRqbzsjwZpCvSLh3k"
		"BwI3Gqn4d5MJeTFOEES9OnfCXJ8EBXBuKevdwF35HIB8ofPmoAuWgVupLniH"
		"xd2cdRcofthSvV5NNahjJXuVtNbiEveqrKwFh9mhJolPTleDLPb2Bz3Wqpu2"
		"RkpAKz7swD5vv2ImYtFH8d1sr1r1riyZJLjczmRu83T\n"
		"fEor5mR9DcBxVvzojzYEqiCAzuzclIysxR1jlSS10i9\n"
		"L98HZrvso7jiECZCUbqrNOlvjwJDeOfTJhOM6rl4k28XWfjC7XSOuuMuLfOt"
		"JzkkC9xU9BkhN3QZ8KPBBb8NrqmMzXdq2KX2spindKUt5qx3nnuyN2rgmyvr"
		"BoiJuQdFQ7s0iLjwesaKkfV9LmAheDIHtqrOShJS87W44cWebwSxeSMvDNsl"
		"rGBvdMM0ynEZxpeYaE7uqSHUV8IYNoKTZcLyzUneVO7idKUdHZt92LXQxUta"
		"xHP7cjdTv3eVRuipvrYxfRGqdjDlU20Z5xexzEUcG2ZATJyaBt82j9nf0boA"
		"VmYxD00mXDdHb2RWhfDCot5czPfueGK5BAfJPHcr6yLE\n"
		"mK2zCAnD2Z0WqJ22yaIOLnO1zHU0BAgpVNX3XEUloWVKpfmDs5nVEJDSSDxz"
		"gEWV6V9YNYudvt819CLDytfNwfVkYiEtL0oOPeh9spw7q1dmy2Cqr687A2rj"
		"C0HPrQV3FwP27Lb5paPvipaGRPCngedxykaBK4WB52XoDF8FyogzF475EccG"
		"DeaaTRZmotj3HdiDsVO7Nb66Q8G6Wm1zwwrtEzLOXYKQBJZlwWKRqs23021j"
		"eVQRQ2I9exPnO1GYF8nigzAexQdBsmSAX8sNZsCuEK1htM0djsb0PmeGW6eY"
		"A\n";

#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		{'p', "port", NULL, "GNUnet CADET port to listen/connect",
			GNUNET_YES, &GNUNET_GETOPT_set_string, &gnunet_opt_port},
		{'t', "t-resilience", NULL, "resilience of DKG protocol",
			GNUNET_YES, &GNUNET_GETOPT_set_uint, &gnunet_opt_t_resilience},
		GNUNET_GETOPT_OPTION_END
	};
#endif

	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (argc < 2)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << argv[0] << " [OPTIONS] PEERS" << std::endl;
		return -1;
	}
	else
	{
		// create peer list
		for (size_t i = 0; i < (size_t)(argc - 1); i++)
		{
			std::string arg = argv[i+1];
			// ignore options
			if ((arg.find("-c", 0) == 0) || (arg.find("-p", 0) == 0) || (arg.find("-t", 0) == 0) || (arg.find("-L", 0) == 0) || (arg.find("-l", 0) == 0))
			{
				i++;
				continue;
			}
			else if ((arg.find("--", 0) == 0) || (arg.find("-v", 0) == 0) || (arg.find("-h", 0) == 0))
				continue;
			else if (arg.find("-", 0) == 0)
			{
				std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
				return -1;
			}
			peers.push_back(arg);
		}
		// canonicalize peer list
		std::sort(peers.begin(), peers.end());
		std::vector<std::string>::iterator it = std::unique(peers.begin(), peers.end());
		peers.resize(std::distance(peers.begin(), it));
		N = peers.size();
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cout << peers[i] << std::endl;
	}
	if ((N < 4)  || (N > MAX_N))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	};

	T = (N / 3) - 1; // assume maximum asynchronous t-resilience
#ifdef GNUNET
	T = gnunet_opt_t_resilience; // get T from GNUnet options
#endif
	if (T == 0)
		T++; // RBC will not work with 0-resilience
	if (T >= N)
		T = N - 1; // apply a upper limit on T
	std::cout << "1. Please enter an OpenPGP-style user ID (name <email>): ";
	std::getline(std::cin, u);
	std::cout << "2. Choose a passphrase to protect your private key: ";
	std::getline(std::cin, passphrase);

#ifdef GNUNET
	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
    		return -1;
	int ret = GNUNET_PROGRAM_run(argc, argv, "dkg-generate [OPTIONS] PEERS", "distributed ElGamal key generation with OpenPGP-output",
                            options, &gnunet_run, argv[0]);

	GNUNET_free ((void *) argv);

	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#endif

	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("dkg-generate (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("dkg-generate (pipe)");
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
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-generate (waitpid)");
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
		}
	}
	
	return 0;
}

#else

int main
	(int argc, char **argv)
{
	std::cout << "configure feature --enable-forking needed" << std::endl;
	return 77;
}

#endif
