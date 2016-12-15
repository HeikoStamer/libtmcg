/*******************************************************************************
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

#include <libTMCG.hh>
#include <aiounicast_fd.hh>

#ifdef FORKING

#ifdef GNUNET
#undef HAVE_CONFIG_H
#undef PACKAGE
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION
#undef VERSION
#define HAVE_CONFIG_H 1
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_cadet_service.h>
#undef HAVE_CONFIG_H
#endif

#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "pipestream.hh"

#undef NDEBUG
#define MAX_N 1024

int pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t pid[MAX_N];

#ifdef GNUNET
static char *listen_port;
static struct GNUNET_CADET_Handle *mh;
struct GNUNET_CADET_Port *lp;
static struct GNUNET_SCHEDULER_Task *sd;
static struct GNUNET_SCHEDULER_Task *job;

static int gnunet_data_callback(void *cls, struct GNUNET_CADET_Channel *channel,
	void **channel_ctx, const struct GNUNET_MessageHeader *message)
{
	GNUNET_CADET_receive_done(channel);
	return 0;
}

static void gnunet_channel_ended(void *cls, const struct GNUNET_CADET_Channel *channel,
	void *channel_ctx)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Channel ended!\n");
	GNUNET_SCHEDULER_shutdown();
}

static void* gnunet_channel_incoming(void *cls, struct GNUNET_CADET_Channel *channel,
	const struct GNUNET_PeerIdentity *initiator, const struct GNUNET_HashCode *port,
	enum GNUNET_CADET_ChannelOption options)
{
	GNUNET_log(GNUNET_ERROR_TYPE_MESSAGE, "Connected from %s\n", GNUNET_i2s_full(initiator));
	GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Incoming channel %p on port %s\n", channel, GNUNET_h2s(port));
	if (listen_port == NULL)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Not listening to channels\n");
		return NULL;
	}
	return NULL;
}

static void gnunet_shutdown_task(void *cls)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
	if (mh != NULL)
	{
		GNUNET_CADET_disconnect(mh);
		mh = NULL;
	}
	if (job != NULL)
	{
		GNUNET_SCHEDULER_cancel(job);
		job = NULL;
	}
}

static void gnunet_generate(void *cls)
{
	std::cerr << "Hi! we will fork here later" << std::endl;
}

static void gnunet_run(void *cls, char *const *args, const char *cfgfile,
	const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	static const struct GNUNET_CADET_MessageHandler handlers[] = {
		{&gnunet_data_callback, GNUNET_MESSAGE_TYPE_CADET_CLI, 0},
		{NULL, 0, 0}
	};
	static struct GNUNET_HashCode porthash;

	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to CADET service\n");
	mh = GNUNET_CADET_connect(cfg,
                            NULL, /* cls */
                            &gnunet_channel_ended, /* cleaner */
                            handlers);
	if (mh == NULL)
		GNUNET_SCHEDULER_add_now(&gnunet_shutdown_task, NULL);
	else
		sd = GNUNET_SCHEDULER_add_shutdown(&gnunet_shutdown_task, NULL);

	if (listen_port != NULL)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opening CADET listen port\n");
		GNUNET_CRYPTO_hash(listen_port, strlen(listen_port), &porthash);
		lp = GNUNET_CADET_open_port(mh, &porthash, &gnunet_channel_incoming, NULL);
	}

	job = GNUNET_SCHEDULER_add_now(&gnunet_generate, NULL);
}
#endif

void start_instance
	(const size_t N, const size_t T, const size_t whoami, std::istream &crs_in, const std::string u, const std::string pp, const time_t keytime)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-generate (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			
			// create pipe streams and handles between all players
			std::vector<ipipestream*> P_in;
			std::vector<opipestream*> P_out;
			std::vector<int> uP_in, uP_out, bP_in, bP_out;
			std::vector<std::string> uP_key, bP_key;
			for (size_t i = 0; i < N; i++)
			{
				std::stringstream key;
				key << "dkg-generate::P_" << (i + whoami);
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
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crs_in);
			if (!vtmf->CheckGroup())
			{
				std::cout << "P_" << whoami << ": " <<
					"Group G was not correctly generated!" << std::endl;
				exit(-1);
			}
			
			// create and exchange VTMF keys
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
						std::cout << "P_" << whoami << ": " << "Public key of P_" <<
							i << " was not correctly generated!" << std::endl;
						exit(-1);
					}
				}
			}
			vtmf->KeyGenerationProtocol_Finalize();

			// create an instance of DKG
			GennaroJareckiKrawczykRabinDKG *dkg;
			std::cout << "GennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
			dkg = new GennaroJareckiKrawczykRabinDKG(N, T, whoami,
				vtmf->p, vtmf->q, vtmf->g, vtmf->h);
			if (!dkg->CheckGroup())
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG parameters are not correctly generated!" << std::endl;
				exit(-1);
			}

			// create asynchronous authenticated unicast channels
			aiounicast_fd *aiou = new aiounicast_fd(N, T, whoami, uP_in, uP_out, uP_key);

			// create asynchronous authenticated unicast channels
			aiounicast_fd *aiou2 = new aiounicast_fd(N, T, whoami, bP_in, bP_out, bP_key);
			
			// create an instance of a reliable broadcast protocol (RBC)
			std::string myID = "dkg-generate";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2);
			rbc->setID(myID);
			
			// generating $x$ and extracting $y = g^x \bmod p$
			std::stringstream err_log;
			std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
			if (!dkg->Generate(aiou, rbc, err_log))
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG Generate() failed" << std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();
				exit(-1);
			}
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

			// check the generated key share
			std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
			if (!dkg->CheckKey())
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG CheckKey() failed" << std::endl;
				exit(-1);
			}

			// at the end: deliver some more rounds for waiting parties
			mpz_t m;
			mpz_init(m);
			time_t start_time = time(NULL);
			while (time(NULL) < (start_time + 5))
				rbc->DeliverFrom(m, whoami);
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
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(keytime, p, q, g, y, pub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(keytime, p, q, g, y, x, pp, sec);
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
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(keytime, p, g, y, sub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(keytime, p, g, y, x, pp, ssb);
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
			pubfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				pubfilename << (int)keyid[i];
			pubfilename << "_dkg-pub.asc";
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
			secfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				secfilename << (int)keyid[i];
			secfilename << "_dkg-sec.asc";
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
			dkgfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				dkgfilename << (int)keyid[i];
			dkgfilename << ".dkg";
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
			
			std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
		}
		else
			std::cout << "fork() = " << pid[whoami] << std::endl;
	}
}

int main
	(int argc, char **argv)
{
	size_t N, T;
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		{'o', "open-port", NULL, "GNUnet cadet port to listen to",
			GNUNET_YES, &GNUNET_GETOPT_set_string, &listen_port},
		GNUNET_GETOPT_OPTION_END
	};

	if (argc < 2)
	{
		std::cerr << "ERROR: no GNUnet peers given as arguments" << std::endl;
		return -1;
	}
	else
		N = argc - 1;
	if ((N < 4)  || (N > MAX_N))
	{
		std::cerr << "ERROR: too few or too many GNUnet peers given" << std::endl;
		return -1;
	};
		

	int ret = GNUNET_PROGRAM_run(argc, argv, "dkg-generate [OPTIONS] PEERS", "distributed ElGamal key generation",
                            options, &gnunet_run, NULL);

	GNUNET_free ((void *) argv);

	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#endif

	assert(init_libTMCG());

	BarnettSmartVTMF_dlog 	*vtmf;
	std::stringstream 	crs;
	std::string		value, uid, passphrase;
	

	T = (N / 3) - 1; // maximum asynchronous t-resilience
	if (T == 0)
		T = 1; // RBC will not work with 0-resilience
	std::cout << "1. Please enter an OpenPGP-style user ID (name <email>): ";
	std::getline(std::cin, uid);
	std::cout << "2. Choose a passphrase to protect the private key: ";
	std::getline(std::cin, passphrase);

	// create and check VTMF instance
	time_t keytime = time(NULL); // current time
	std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
	vtmf = new BarnettSmartVTMF_dlog();
	std::cout << "vtmf.CheckGroup()" << std::endl;
	assert(vtmf->CheckGroup());
	
	// publish VTMF instance as string stream (common reference string)
	std::cout << "vtmf.PublishGroup(crs)" << std::endl;
	vtmf->PublishGroup(crs);
	
	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
		}
	}
	
	// start childs
	for (size_t i = 0; i < N; i++)
		start_instance(N, T, i, crs, uid, passphrase, keytime);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < N; i++)
	{
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-generate (waitpid)");
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
		}
	}
	
	// release VTMF instance
	delete vtmf;
	
	return 0;
}

#else

int main
	(int argc, char **argv)
{
	std::cout << "fork(2) needed" << std::endl;
	return 77;
}

#endif
