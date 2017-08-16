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
static const char *version = VERSION; // copy VERSION from LibTMCG before overwritten by GNUnet headers

#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "dkg-builtin-common.hh"
#include "dkg-gnunet-common.hh"

int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t				pid[MAX_N];
std::vector<std::string>	peers;
bool				instance_forked = false;

size_t				N, T, S;
std::string			crs, u, passphrase, passwords, hostname, port;
int 				opt_verbose = 0;
char				*opt_crs = NULL;
char				*opt_passwords = NULL;
char				*opt_hostname = NULL;
unsigned long int		opt_t = 0, opt_s = 0, opt_e = 0, opt_p = 35000;

void run_instance
	(const size_t whoami, const time_t keytime, const time_t keyexptime, const size_t num_xtests)
{
	// create communication handles for all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		std::stringstream key;
		if (opt_passwords != NULL)
		{
			key << TMCG_ParseHelper::gs(passwords, '/');
			if (TMCG_ParseHelper::gs(passwords, '/') == "ERROR")
			{
				std::cerr << "P_" << whoami << ": " << "cannot read password for protecting channel to P_" << i << std::endl;
				exit(-1);
			}
			else if (((i + 1) < peers.size()) && !TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "P_" << whoami << ": " << "cannot skip to next password for protecting channel to P_" << (i + 1) << std::endl;
				exit(-1);
			}
		}
		else
			key << "dkg-generate::P_" << (i + whoami); // use a simple key -- we assume that GNUnet provides secure channels
		uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(key.str());
		bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(key.str());
	}
			
	// create VTMF instance from CRS (common reference string)
	std::stringstream crss;
	mpz_t crsmpz;
	mpz_init(crsmpz);
	// check magic
	if (!TMCG_ParseHelper::cm(crs, "crs", '|'))
	{
		std::cerr << "P_" << whoami << ": " << "common reference string (CRS) is corrupted!" << std::endl;
		mpz_clear(crsmpz);
		exit(-1);
	}
	// parse p, q, g, k
	for (size_t i = 0; i < 4; i++)
	{
		if ((mpz_set_str(crsmpz, TMCG_ParseHelper::gs(crs, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(crs, '|')))
		{
			std::cerr << "P_" << whoami << ": " << "common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(crsmpz);
			exit(-1);
		}
		crss << crsmpz << std::endl;
	}
	mpz_clear(crsmpz);
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true); // with verifiable generation of $g$
	// check the constructed VTMF instance
	if (!vtmf->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " << "Group G was not correctly generated!" << std::endl;
		delete vtmf;
		exit(-1);
	}

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou = new aiounicast_select(N, whoami, uP_in, uP_out, uP_key);

	// create asynchronous authenticated unicast channels for broadcast protocol
	aiounicast_select *aiou2 = new aiounicast_select(N, whoami, bP_in, bP_out, bP_key);
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-generate|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	myID += T; // include parameterized t-resiliance of DKG in the ID of broadcast protocol
	size_t T_RBC = (peers.size() - 1) / 3; // assume maximum asynchronous t-resilience for RBC
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T_RBC, whoami, aiou2);
	rbc->setID(myID);

	// perform a simple exchange test with debug output
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t xtest;
		mpz_init_set_ui(xtest, i);
		std::cout << "P_" << whoami << ": xtest = " << xtest << " <-> ";
		rbc->Broadcast(xtest);
		for (size_t ii = 0; ii < N; ii++)
		{
			if (!rbc->DeliverFrom(xtest, ii))
				std::cout << "<X> ";
			else
				std::cout << xtest << " ";
		}
		std::cout << std::endl;
		mpz_clear(xtest);
	}
			
	// create and exchange temporary keys in order to bootstrap the $h$-generation for DKG/tDSS [JL00]
	// TODO: replace N-time NIZK by one interactive (distributed) zero-knowledge proof of knowledge, i.e., removes ROM assumption here
	if (opt_verbose)
		std::cout << "generate h by using VTMF key generation protocol" << std::endl;
	mpz_t nizk_c, nizk_r, h_j;
	mpz_init(nizk_c), mpz_init(nizk_r), mpz_init(h_j);
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_ComputeNIZK(nizk_c, nizk_r);
	rbc->Broadcast(vtmf->h_i);
	rbc->Broadcast(nizk_c);
	rbc->Broadcast(nizk_r);
	for (size_t i = 0; i < N; i++)
	{
		if (i != whoami)
		{
			if (!rbc->DeliverFrom(h_j, i))
			{
				std::cerr << "P_" << whoami << ": WARNING - no VTMF key received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_c, i))
			{
				std::cerr << "P_" << whoami << ": WARNING - no NIZK c received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_r, i))
			{
				std::cerr << "P_" << whoami << ": WARNING - no NIZK r received from " << i << std::endl;
			}
			std::stringstream lej;
			lej << h_j << std::endl << nizk_c << std::endl << nizk_r << std::endl;
			if (!vtmf->KeyGenerationProtocol_UpdateKey(lej))
			{
				std::cerr << "P_" << whoami << ": " << "Public key of P_" << i << " was not correctly generated!" << std::endl;
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();
	mpz_clear(nizk_c), mpz_clear(nizk_r), mpz_clear(h_j);

	// create an instance of tDSS
	CanettiGennaroJareckiKrawczykRabinDSS *dss;
	if (opt_verbose)
		std::cout << "CanettiGennaroJareckiKrawczykRabinDSS(" << N << ", " << S << ", " << whoami << ", ...)" << std::endl;
	dss = new CanettiGennaroJareckiKrawczykRabinDSS(N, S, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h);
	if (!dss->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " << "tDSS parameters are not correctly generated!" << std::endl;
		delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	// generate shared $x$ and extract $y = g^x \bmod p$, if s-resilience is not zero
	if (S > 0)
	{
		std::stringstream err_log;
		if (opt_verbose)
			std::cout << "P_" << whoami << ": dss.Generate()" << std::endl;
		if (!dss->Generate(aiou, rbc, err_log))
		{
			std::cerr << "P_" << whoami << ": " << "tDSS Generate() failed" << std::endl;
			std::cerr << "P_" << whoami << ": log follows " << std::endl << err_log.str();
			delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose)
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();
	}

	// create an instance of DKG
	GennaroJareckiKrawczykRabinDKG *dkg;
	if (opt_verbose)
		std::cout << "GennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
	dkg = new GennaroJareckiKrawczykRabinDKG(N, T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h);
	if (!dkg->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " << "DKG parameters are not correctly generated!" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
			
	// generate shared $x$ and extract $y = g^x \bmod p$
	std::stringstream err_log;
	if (opt_verbose)
		std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
	if (!dkg->Generate(aiou, rbc, err_log))
	{
		std::cerr << "P_" << whoami << ": " << "DKG Generate() failed" << std::endl;
		std::cerr << "P_" << whoami << ": log follows " << std::endl << err_log.str();
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (opt_verbose)
		std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

	// check the generated key share
	if (opt_verbose)
		std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
	if (!dkg->CheckKey())
	{
		std::cerr << "P_" << whoami << ": " << "DKG CheckKey() failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}

	// participants must agree on a common key creation time (OpenPGP), otherwise subkeyid does not match
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
				utv = (time_t)mpz_get_ui(mtv);
				tvs.push_back(utv);
			}
			else
			{
				std::cerr << "P_" << whoami << ": WARNING - no key creation time received from " << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	if (tvs.size() < (N - T))
	{
		std::cerr << "P_" << whoami << ": not enough timestamps received" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	ckeytime = tvs[tvs.size()/2]; // use a median value as some kind of gentle agreement
	if (opt_verbose)
		std::cout << "P_" << whoami << ": canonicalized key creation time = " << ckeytime << std::endl;

	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_byte_t hashalgo = 0;
	if (mpz_sizeinbase(vtmf->q, 2L) == 256)
		hashalgo = 8; // SHA256 (alg 8)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 384)
		hashalgo = 9; // SHA384 (alg 9)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 512)
		hashalgo = 10; // SHA512 (alg 10)
	else
	{
		std::cerr << "P_" << whoami << ": selecting hash algorithm failed for |q| = " << mpz_sizeinbase(vtmf->q, 2L) << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}

	// create an OpenPGP DSA-based primary key resp. ElGamal-based subkey using computed values from tDSS resp. DKG protocols
	std::string out, crcout, armor;
	tmcg_octets_t all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
	tmcg_octets_t pub_hashing, sub_hashing;
	tmcg_octets_t uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
	tmcg_octets_t hash;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	mpz_t dsa_y, dsa_x, dsa_m, dsa_r, dsa_s;
	mpz_init(dsa_y), mpz_init(dsa_x), mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	if (S > 0)
	{
		// use values of the shared DSA signing key, if s-resilience is not zero
		mpz_set(dsa_x, dss->x_i);
		mpz_set(dsa_y, dss->y);
	}
	else
	{
		// generate individual DSA signing key, if s-resilience is set to zero
		mpz_ssrandomm(dsa_x, vtmf->q); // choose private key for DSA
		mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p); // compute public key for DSA
	}
	if (!mpz_get_gcry_mpi(&p, vtmf->p))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for p" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&q, vtmf->q))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for q" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&g, vtmf->g))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for g" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&y, dsa_y))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_y" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&x, dsa_x))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_x" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	size_t erroff;
	ret = gcry_sexp_build(&key, &erroff, "(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))", p, q, g, y, p, q, g, y, x);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_sexp_build() failed" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ckeytime, 17, p, q, g, y, pub); // use common key creation time
	if (S > 0)
	{
		// create an OpenPGP private key as experimental algorithm ID 108 to store everything from tDSS
		gcry_mpi_t h, n, t, i, qualsize, x_i, xprime_i;
		std::vector<gcry_mpi_t> qual;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		if (!mpz_get_gcry_mpi(&h, dss->h))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
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
					std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->dkg->x_rvss->C_ik[j][k]" << std::endl;
					mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
					gcry_mpi_release(p);
					gcry_mpi_release(q);
					gcry_mpi_release(g);
					gcry_mpi_release(y);
					gcry_mpi_release(x);
					gcry_mpi_release(h);
					gcry_mpi_release(n);
					gcry_mpi_release(t);
					gcry_mpi_release(i);
					gcry_mpi_release(qualsize);
					for (size_t jj = 0; jj < qual.size(); jj++)
						gcry_mpi_release(qual[jj]);
					for (size_t jj = 0; jj < c_ik.size(); jj++)
						for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
							gcry_mpi_release(c_ik[jj][kk]);
					exit(-1); 
				}
				c_ik[j].push_back(tmp);
			}
		}
		if (!mpz_get_gcry_mpi(&x_i, dss->x_i))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->x_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			for (size_t j = 0; j < c_ik.size(); j++)
				for (size_t k = 0; k < c_ik[j].size(); k++)
					gcry_mpi_release(c_ik[j][k]);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_get_gcry_mpi(&xprime_i, dss->xprime_i))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->xprime_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			for (size_t j = 0; j < c_ik.size(); j++)
				for (size_t k = 0; k < c_ik[j].size(); k++)
					gcry_mpi_release(c_ik[j][k]);
			gcry_mpi_release(x_i);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental108(ckeytime, p, q, g, h, y, n, t, i, qualsize, qual, c_ik, x_i, xprime_i, passphrase, sec);
		gcry_mpi_release(h);
		gcry_mpi_release(n);
		gcry_mpi_release(t);
		gcry_mpi_release(i);
		gcry_mpi_release(qualsize);
		for (size_t j = 0; j < qual.size(); j++)
			gcry_mpi_release(qual[j]);
		for (size_t j = 0; j < c_ik.size(); j++)
			for (size_t k = 0; k < c_ik[j].size(); k++)
				gcry_mpi_release(c_ik[j][k]);
		gcry_mpi_release(x_i);
		gcry_mpi_release(xprime_i);
	}
	else
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(ckeytime, 17, p, q, g, y, x, passphrase, sec);
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, uid);
	if (S > 0)
	{
		dsaflags.push_back(0x01 | 0x02 | 0x10); // key may be used to certify other keys, to sign data, and has been split by a secret-sharing mechanism
		sigtime = ckeytime; // use common key creation time as OpenPGP signature creation time
	}
	else
	{
		dsaflags.push_back(0x01 | 0x02 | 0x20); // key may be used to certify other keys, to sign data, and for authentication
		sigtime = time(NULL); // current time
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareSelfSignature(0x13, hashalgo, sigtime, keyexptime, dsaflags, keyid, uidsig_hashing); // positive certification (0x13) of uid and pub
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, hashalgo, hash, uidsig_left);
	if (S > 0)
	{
		tmcg_byte_t buffer[1024];
		gcry_mpi_t h;
		size_t buflen = 0;
		for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
			buffer[i] = hash[i];
		h = gcry_mpi_new(2048);
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for h" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "P_" << whoami << ": mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
			std::cout << "P_" << whoami << ": dss.Sign()" << std::endl;
		if (!dss->Sign(N, whoami, dsa_m, dsa_r, dsa_s, aiou, rbc, err_log_sign))
		{
			std::cerr << "P_" << whoami << ": " << "tDSS Sign() failed" << std::endl;
			std::cerr << "P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose)
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
		if (!mpz_get_gcry_mpi(&r, dsa_r))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_get_gcry_mpi(&s, dsa_s))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	else
	{
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	if (!mpz_get_gcry_mpi(&y, dkg->y)) // computed by DKG (cf. LibTMCG source code)
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->y" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_sexp_release(key);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ckeytime, 16, p, q, g, y, sub); // use common key creation time and Elgamal algorithm id

	// create an OpenPGP private subkey as experimental algorithm ID 109 to store everything from DKG
	gcry_mpi_t h, n, t, i, qualsize, x_i, xprime_i;
	std::vector<gcry_mpi_t> qual, v_i;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	if (!mpz_get_gcry_mpi(&h, dkg->h))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->h" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_sexp_release(key);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	n = gcry_mpi_set_ui(NULL, dkg->n);
	t = gcry_mpi_set_ui(NULL, dkg->t);
	i = gcry_mpi_set_ui(NULL, dkg->i);
	qualsize = gcry_mpi_set_ui(NULL, dkg->QUAL.size());
	for (size_t j = 0; j < dkg->QUAL.size(); j++)
	{
		gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dkg->QUAL[j]);
		qual.push_back(tmp);
	}
	v_i.resize(dkg->n);
	for (size_t j = 0; j < v_i.size(); j++)
	{
		if (!mpz_get_gcry_mpi(&v_i[j], dkg->v_i[j]))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->v_i[j]" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(h);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t jj = 0; jj < qual.size(); jj++)
				gcry_mpi_release(qual[jj]);
			for (size_t j = 0; j < v_i.size(); j++)
				gcry_mpi_release(v_i[j]);
			for (size_t jj = 0; jj < c_ik.size(); jj++)
				for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
					gcry_mpi_release(c_ik[jj][kk]);
			exit(-1); 
		}
	}
	c_ik.resize(dkg->n);
	for (size_t j = 0; j < c_ik.size(); j++)
	{
		for (size_t k = 0; k <= dkg->t; k++)
		{
			gcry_mpi_t tmp;
			if (!mpz_get_gcry_mpi(&tmp, dkg->C_ik[j][k]))
			{
				std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->C_ik[j][k]" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(h);
				gcry_mpi_release(n);
				gcry_mpi_release(t);
				gcry_mpi_release(i);
				gcry_mpi_release(qualsize);
				for (size_t jj = 0; jj < qual.size(); jj++)
					gcry_mpi_release(qual[jj]);
				for (size_t j = 0; j < v_i.size(); j++)
					gcry_mpi_release(v_i[j]);
				for (size_t jj = 0; jj < c_ik.size(); jj++)
					for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
						gcry_mpi_release(c_ik[jj][kk]);
				exit(-1); 
			}
			c_ik[j].push_back(tmp);
		}
	}
	if (!mpz_get_gcry_mpi(&x_i, dkg->x_i))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->x_i" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(h);
		gcry_mpi_release(n);
		gcry_mpi_release(t);
		gcry_mpi_release(i);
		gcry_mpi_release(qualsize);
		for (size_t j = 0; j < qual.size(); j++)
			gcry_mpi_release(qual[j]);
		for (size_t j = 0; j < v_i.size(); j++)
			gcry_mpi_release(v_i[j]);
		for (size_t j = 0; j < c_ik.size(); j++)
			for (size_t k = 0; k < c_ik[j].size(); k++)
				gcry_mpi_release(c_ik[j][k]);
		gcry_sexp_release(key);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&xprime_i, dkg->xprime_i))
	{
		std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->xprime_i" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(h);
		gcry_mpi_release(n);
		gcry_mpi_release(t);
		gcry_mpi_release(i);
		gcry_mpi_release(qualsize);
		for (size_t j = 0; j < qual.size(); j++)
			gcry_mpi_release(qual[j]);
		for (size_t j = 0; j < v_i.size(); j++)
			gcry_mpi_release(v_i[j]);
		for (size_t j = 0; j < c_ik.size(); j++)
			for (size_t k = 0; k < c_ik[j].size(); k++)
				gcry_mpi_release(c_ik[j][k]);
		gcry_mpi_release(x_i);
		gcry_sexp_release(key);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncodeExperimental109(ckeytime, p, q, g, h, y, n, t, i, qualsize, qual, v_i, c_ik, x_i, xprime_i, passphrase, ssb);
	gcry_mpi_release(h);
	gcry_mpi_release(n);
	gcry_mpi_release(t);
	gcry_mpi_release(i);
	gcry_mpi_release(qualsize);
	for (size_t j = 0; j < qual.size(); j++)
		gcry_mpi_release(qual[j]);
	for (size_t j = 0; j < v_i.size(); j++)
		gcry_mpi_release(v_i[j]);
	for (size_t j = 0; j < c_ik.size(); j++)
		for (size_t k = 0; k < c_ik[j].size(); k++)
			gcry_mpi_release(c_ik[j][k]);
	gcry_mpi_release(x_i);
	gcry_mpi_release(xprime_i);
	elgflags.push_back(0x04 | 0x10); // key may be used to encrypt communications and has been split by a secret-sharing mechanism
	if (S > 0)
		sigtime = ckeytime; // use common key creation time as OpenPGP signature creation time
	else
		sigtime = time(NULL); // otherwise use current time
	// Subkey Binding Signature (0x18) of sub
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareSelfSignature(0x18, hashalgo, sigtime, keyexptime, elgflags, keyid, subsig_hashing);
	for (size_t i = 6; i < sub.size(); i++)
		sub_hashing.push_back(sub[i]);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash, subsig_left);
	if (S > 0)
	{
		tmcg_byte_t buffer[1024];
		gcry_mpi_t h;
		size_t buflen = 0;
		for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
			buffer[i] = hash[i];
		h = gcry_mpi_new(2048);
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for h" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "P_" << whoami << ": mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
			std::cout << "P_" << whoami << ": dss.Sign()" << std::endl;
		if (!dss->Sign(N, whoami, dsa_m, dsa_r, dsa_s, aiou, rbc, err_log_sign))
		{
			std::cerr << "P_" << whoami << ": " << "tDSS Sign() failed" << std::endl;
			std::cerr << "P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose)
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
		if (!mpz_get_gcry_mpi(&r, dsa_r))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_get_gcry_mpi(&s, dsa_s))
		{
			std::cerr << "P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(r);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	else
	{
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
	mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	gcry_sexp_release(key);
	
	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_very_long;
	if (opt_verbose)
		std::cout << "P_" << whoami << ": waiting " << synctime << " seconds for stalled parties" << std::endl;
	rbc->Sync(synctime);

	// export generated public keys in OpenPGP armor format
	std::stringstream pubfilename;
	pubfilename << peers[whoami] << "_dkg-pub.asc";
	armor = "", all.clear();
	all.insert(all.end(), pub.begin(), pub.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), sub.begin(), sub.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, all, armor);
	if (opt_verbose)
		std::cout << armor << std::endl;
	std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
	if (!pubofs.good())
	{
		std::cerr << "P_" << whoami << ": opening public key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	pubofs << armor;
	if (!pubofs.good())
	{
		std::cerr << "P_" << whoami << ": writing public key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	pubofs.close();

	// export generated private keys in OpenPGP armor format
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	armor = "", all.clear();
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
	if (opt_verbose)
		std::cout << armor << std::endl;
	std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
	if (!secofs.good())
	{
		std::cerr << "P_" << whoami << ": opening private key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	secofs << armor;
	if (!secofs.good())
	{
		std::cerr << "P_" << whoami << ": writing private key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	secofs.close();

	// release DKG
	delete dkg;

	// release tDSS
	delete dss;

	// release RBC			
	delete rbc;

	// release VTMF
	delete vtmf;
			
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
		std::cout << "P_" << whoami << ": aiou.numRead = " << aiou->numRead <<
			" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
		std::cout << "P_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
			" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;
}

#ifdef GNUNET
char *gnunet_opt_crs = NULL;
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_t_resilience = 0;
unsigned int gnunet_opt_s_resilience = MAX_N;
unsigned int gnunet_opt_keyexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
int gnunet_opt_verbose = 0;
#endif

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
#ifdef GNUNET
			run_instance(whoami, keytime, gnunet_opt_keyexptime, gnunet_opt_xtests);
#else
			run_instance(whoami, keytime, opt_e, 0);
#endif
			if (opt_verbose)
				std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
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
	// setup CRS (common reference string) |p| = 2048 bit, |q| = 256 bit
	// parameters of the underlying group have been generated with dkg-gencrs
	crs = "crs|Ya4kG0PQkxSNfXs0GPvNvrLqeyLc13aypAwaHZ3kxi6uYagVELARgiqVBV"
		"yBe485oVJmXAVATaJIYpQQhgBawHpzPAOyRICy7hQdBvYtmForYx5MGTK7Uf"
		"7PPIgnVDQ7csNgsFfMNkUQVKpiszcb4dVi9sGx4DiZltjdDWH8id2RRQTrEi"
		"jv6rnSVK4Fd3O3QWbEb1DLXmzEni8bSxDk3rjaRfDzhxAWXG8fTB7bcDYDtb"
		"HOdKlCmFsuYPtet475MelcOkdfeEKh2CzwzqKWN48XTl1kkpJsCvio9Kf2Tr"
		"uYTx1bJNnb0izSiTKjf6YFZZaEHxfCmPfKtEvN31yvOTOH|h7jBszmKCVvyj"
		"bosdkGmh4zBedweLDpNLG5IvYfsHZJ|OSIgkt0vUOd31qvyKLuxXbCDJO3co"
		"2tCPiVCRRGe6zXYrMopBgPQewxSSMrPSQwJEuTbIqJYvRWBlBVih723m5av5"
		"D4GewO4nQ5shtcuEY1u0pRLToLCMaheCvCEE8tT49xdYKV4UOOFZryobgYfq"
		"nZctunR82uTnlUTiFMN2STYXZhlB7Asjj5XMjfF2nsoay4785p7DibvgiHta"
		"D3A5yAavGnUhRGm5Ir279eUNMqoJNubC5g4wzSwMGvhLh2VnYsMl7m9dcWw0"
		"jOiTKBzemrawcv16EEHbV97a1gt5JyDn9MsDwIGDuUD5vi39nBmUOOdSb5xs"
		"pjr4qViYGAHRTKx|niWPateQX4M9KJ28L2k6J2izaSuyq7oDQOr3l0LQojzd"
		"TyLAxJX1NIaUl1qhO3qn71JAVFCbhlYLkFvthr2dIJVXCrmdIuJ7EXgXTWqc"
		"tNEHeqGEicuGmL4kEc98zJJCHx6d0xLPJn0fHBnge3iewZCeCaOnWHxHnQtH"
		"o3nIAXfODzZx6njMuyuVXg957FxtmKmU5ot96nA5j33kejKu10MGhvrWQMA3"
		"z86EcA4uvHdTTcYhXwaRssKfidViHKJbQxT9MPXkjbmKw1Sm93777gxSUQjt"
		"BC5EXRYiI1xSqW02e|";
	static const char *usage = "dkg-generate [OPTIONS] PEERS";
	static const char *about = "distributed key generation (DSA+ElGamal with OpenPGP-output)";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated keys in seconds",
			&gnunet_opt_keyexptime
		),
		GNUNET_GETOPT_option_string('g',
			"group",
			"STRING",
			"common reference string that defines the underlying DDH-hard group",
			&gnunet_opt_crs
		),
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
		GNUNET_GETOPT_option_uint('s',
			"s-resilience",
			"INTEGER",
			"resilience of threshold DSS protocol (signature scheme)",
			&gnunet_opt_s_resilience
		),
		GNUNET_GETOPT_option_uint('t',
			"t-resilience",
			"INTEGER",
			"resilience of DKG protocol (threshold decryption)",
			&gnunet_opt_t_resilience
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
			"minutes to wait until start of DKG/tDSS protocol",
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
	if (gnunet_opt_crs != NULL)
		opt_crs = gnunet_opt_crs;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_hostname != NULL)
		opt_hostname = gnunet_opt_hostname;
	if (gnunet_opt_crs != NULL)
		crs = gnunet_opt_crs; // get different CRS from GNUnet options
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
		// create peer list from remaining arguments
		for (size_t i = 0; i < (size_t)(argc - 1); i++)
		{
			std::string arg = argv[i+1];
			// ignore options
			if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-t") == 0) || (arg.find("-w") == 0) || 
				(arg.find("-L") == 0) || (arg.find("-l") == 0) || (arg.find("-g") == 0) || (arg.find("-x") == 0) ||
				(arg.find("-s") == 0) || (arg.find("-e") == 0) || (arg.find("-P") == 0) || (arg.find("-H") == 0))
			{
				size_t idx = ++i;
				if ((arg.find("-g") == 0) && (idx < (size_t)(argc - 1)) && (opt_crs == NULL))
				{
					crs = argv[i+1];
					opt_crs = (char*)crs.c_str();
				}
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
				if ((arg.find("-t") == 0) && (idx < (size_t)(argc - 1)) && (opt_t == 0))
					opt_t = strtoul(argv[i+1], NULL, 10);
				if ((arg.find("-s") == 0) && (idx < (size_t)(argc - 1)) && (opt_s == 0))
					opt_s = strtoul(argv[i+1], NULL, 10);
				if ((arg.find("-e") == 0) && (idx < (size_t)(argc - 1)) && (opt_e == 0))
					opt_e = strtoul(argv[i+1], NULL, 10);
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
					std::cout << "  -e TIME        expiration time of generated keys in seconds" << std::endl;
					std::cout << "  -g STRING      common reference string that defines underlying DDH-hard group" << std::endl;
					std::cout << "  -H STRING      hostname (e.g. onion address) of this peer within PEERS" << std::endl;
					std::cout << "  -p INTEGER     start port for built-in TCP/IP message exchange service" << std::endl; 
					std::cout << "  -P STRING      exchanged passwords to protect private and broadcast channels" << std::endl;
					std::cout << "  -s INTEGER     resilience of threshold DSS protocol (signature scheme)" << std::endl;
					std::cout << "  -t INTEGER     resilience of DKG protocol (threshold decryption)" << std::endl;
					std::cout << "  -v, --version  print the version number" << std::endl;
					std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
				{
#ifndef GNUNET
					std::cout << "dkg-generate " << version << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
					opt_verbose = 1; // verbose output
				continue;
			}
			else if (arg.find("-") == 0)
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
	}
	N = peers.size();
	T = (N - 1) / 2; // default: maximum synchronous t-resilience for DKG (RBC is not affected by this)
	S = (N - 1) / 2; // default: maximum s-resilience for tDSS (RBC is also not affected by this)

	if ((N < 3)  || (N > MAX_N))
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
	std::cout << "1. Please enter an OpenPGP-style user ID (name <email>): ";
	std::getline(std::cin, u);
	std::cout << "2. Choose a passphrase to protect your private key: ";
	std::getline(std::cin, passphrase);
	if (opt_verbose)
	{
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cout << peers[i] << std::endl;
	}
#ifdef GNUNET
	if (gnunet_opt_t_resilience != 0)
		T = gnunet_opt_t_resilience; // get value of T from GNUnet options
	if (gnunet_opt_s_resilience != MAX_N)
		S = gnunet_opt_s_resilience; // get value of S from GNUnet options
#else
	if (opt_t != 0)
		T = opt_t; // get vaule of T from options
	if (opt_s != 0)
		S = opt_s; // get vaule of S from options
#endif
	if (T == 0)
		T++; // 0-resilience is not preferable, because then only a single party can decrypt everything
	if (T > N)
		T = N; // apply an upper limit on T
	if (S > ((N - 1) / 2))
		S = (N - 1) / 2; // apply an upper limit on S
	if (opt_hostname != NULL)
	{
		int ret = 0;
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

#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated keys in seconds",
			&gnunet_opt_keyexptime
		),
		GNUNET_GETOPT_option_string('g',
			"group",
			"STRING",
			"common reference string that defines the underlying DDH-hard group",
			&gnunet_opt_crs
		),
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
		GNUNET_GETOPT_option_uint('s',
			"s-resilience",
			"INTEGER",
			"resilience of threshold DSS protocol (signature scheme)",
			&gnunet_opt_s_resilience
		),
		GNUNET_GETOPT_option_uint('t',
			"t-resilience",
			"INTEGER",
			"resilience of DKG protocol (threshold decryption)",
			&gnunet_opt_t_resilience
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of DKG/tDSS protocol",
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
	int ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run, argv[0]);
	GNUNET_free((void *) argv);
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNUnet development files are required for message exchange of DKG/tDSS protocol" << std::endl;
#endif

	std::cout << "INFO: running local test with " << peers.size() << " participants" << std::endl;
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
		if (opt_verbose)
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

