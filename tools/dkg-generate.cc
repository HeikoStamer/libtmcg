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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "dkg-gnunet-common.hh"

int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t				pid[MAX_N];
size_t				N, T;
std::string			crs, u, passphrase;
std::vector<std::string>	peers;
bool				instance_forked = false;
int 				opt_verbose = 0;

void run_instance
	(const size_t whoami, const time_t keytime, const size_t num_xtests)
{
	// create communication handles for all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < N; i++)
	{
		std::stringstream key;
		key << "dkg-generate::P_" << (i + whoami); // choose a simple key for now FIXME later -- we assume that GNUnet provides secure channels
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
		exit(-1);
	}
	// parse p, q, g, k
	for (size_t i = 0; i < 4; i++)
	{
		if ((mpz_set_str(crsmpz, TMCG_ParseHelper::gs(crs, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(crs, '|')))
		{
			std::cerr << "P_" << whoami << ": " << "common reference string (CRS) is corrupted!" << std::endl;
			exit(-1);
		}
		crss << crsmpz << std::endl;
	}
	mpz_clear(crsmpz);
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true); // with verifiable generation of $g$
	// check VTMF instance constructed
	if (!vtmf->CheckGroup())
	{
		std::cerr << "P_" << whoami << ": " << "Group G was not correctly generated!" << std::endl;
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
			
	// create and exchange keys in order to bootstrap the $h$-generation for DKG [JL00]
	// TODO: replace N-time NIZK by one interactive (distributed) zero-knowledge proof of knowledge
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
	if (opt_verbose)
		std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

	// check the generated key share
	std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
	if (!dkg->CheckKey())
	{
		std::cerr << "P_" << whoami << ": " << "DKG CheckKey() failed" << std::endl;
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
	if (tvs.size() < (T + 1))
	{
		std::cerr << "P_" << whoami << ": not enough timestamps received" << std::endl;
		exit(-1);
	}
	ckeytime = tvs[tvs.size()/2]; // use a median value as some kind of gentle agreement
	if (opt_verbose)
		std::cout << "P_" << whoami << ": canonicalized key creation time = " << ckeytime << std::endl;

	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_very_long;
	std::cout << "P_" << whoami << ": waiting " << synctime << " seconds for stalled parties" << std::endl;
	rbc->Sync(synctime);

	// create an OpenPGP DSA-based primary key and ElGamal-based subkey using computed values from DKG
	char buffer[2048];
	std::string out, crcout, armor;
	tmcg_octets_t all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
	tmcg_octets_t pub_hashing, sub_hashing;
	tmcg_octets_t uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
	tmcg_octets_t hash;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	size_t erroff;
	mpz_t dsa_y, dsa_x;
	mpz_init(dsa_y), mpz_init(dsa_x);
	mpz_ssrandomm(dsa_x, vtmf->q); // choose private key for DSA
	mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p); // compute public key for DSA	
	p = gcry_mpi_new(2048);
	q = gcry_mpi_new(2048);
	g = gcry_mpi_new(2048);
	y = gcry_mpi_new(2048);
	x = gcry_mpi_new(2048);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	mpz_get_str(buffer, 16, vtmf->p); // from CRS
	ret = gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for p" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
	mpz_get_str(buffer, 16, vtmf->q); // from CRS
	ret = gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for q" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
	mpz_get_str(buffer, 16, vtmf->g); // from CRS
	ret = gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for g" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
	mpz_get_str(buffer, 16, dsa_y); // computed for each participant/peer
	ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for dsa_y" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
	mpz_get_str(buffer, 16, dsa_x); // randomly choosen for each participant/peer (see above)
	ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for dsa_x" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	ret = gcry_sexp_build(&key, &erroff, "(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))", p, q, g, y, p, q, g, y, x);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_sexp_build() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		exit(-1);
	}
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
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ckeytime, p, q, g, y, pub); // use common key creation time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(ckeytime, p, q, g, y, x, passphrase, sec); // use common key creation time and individual passphrase
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, uid);
	dsaflags.push_back(0x01 | 0x02 | 0x20); // key may be used to certify other keys, to sign data, and for authentication
	sigtime = time(NULL); // current time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x13, hashalgo, sigtime, dsaflags, keyid, uidsig_hashing); // positive certification (0x13) of uid and pub
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, hashalgo, hash, uidsig_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
	hash.clear();
	mpz_get_str(buffer, 16, dkg->y); // computed by DKG (cf. LibTMCG source code)	
	ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for dkg->y" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	mpz_get_str(buffer, 16, dkg->x_i); // computed by DKG for each participant/peer (cf. LibTMCG source code)	
	ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": gcry_mpi_scan() failed for dkg->x_i" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ckeytime, p, g, y, sub); // use common key creation time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(ckeytime, p, g, y, x, passphrase, ssb); // use common key creation time and individual passphrase
	elgflags.push_back(0x04 | 0x10); // key may be used to encrypt communications and have been split by a secret-sharing mechanism
	sigtime = time(NULL); // current time
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x18, hashalgo, sigtime, elgflags, keyid, subsig_hashing); // Subkey Binding Signature (0x18) of sub
	for (size_t i = 6; i < sub.size(); i++)
		sub_hashing.push_back(sub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash, subsig_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
	if (ret)
	{
		std::cerr << "P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
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
	if (opt_verbose)
		std::cout << armor << std::endl;
	std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
	if (!pubofs.good())
	{
		std::cerr << "P_" << whoami << ": opening public key file failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	pubofs << armor;
	if (!pubofs.good())
	{
		std::cerr << "P_" << whoami << ": writing public key file failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
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
	if (opt_verbose)
		std::cout << armor << std::endl;
	std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
	if (!secofs.good())
	{
		std::cerr << "P_" << whoami << ": opening private key file failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	secofs << armor;
	if (!secofs.good())
	{
		std::cerr << "P_" << whoami << ": writing private key file failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		exit(-1);
	}
	secofs.close();
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(x);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	gcry_sexp_release(key);
	// export verification keys of DKG into a file
	std::stringstream dkgfilename;
	dkgfilename << peers[whoami] << ".dkg";
	std::ofstream dkgofs((dkgfilename.str()).c_str(), std::ofstream::out);
	if (!dkgofs.good())
	{
		std::cerr << "P_" << whoami << ": opening DKG file failed" << std::endl;
		exit(-1);
	}
	dkg->PublishVerificationKeys(dkgofs);
	if (!dkgofs.good())
	{
		std::cerr << "P_" << whoami << ": writing DKG file failed" << std::endl;
		exit(-1);
	}
	dkgofs.close();

	// release DKG
	delete dkg;

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
unsigned int gnunet_opt_t_resilience = 0;
unsigned int gnunet_opt_xtests = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	T = (N - 1) / 2; // default: maximum synchronous t-resilience for DKG (RBC is not affected by this)
#ifdef GNUNET
	if (gnunet_opt_crs != NULL)
		crs = gnunet_opt_crs; // get different CRS from GNUnet options
	if (gnunet_opt_t_resilience != 0)
		T = gnunet_opt_t_resilience; // get value of T from GNUnet options
#endif
	if (T == 0)
		T++; // 0-resilience is not preferable, because then only one party can decrypt everything
	if (T > N)
		T = N; // apply an upper limit on T
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-generate (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			time_t keytime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, keytime, gnunet_opt_xtests);
#else
			run_instance(whoami, keytime, 0);
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

#ifdef GNUNET
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_wait = 5;
int gnunet_opt_verbose = 0;
#endif

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

	bool notcon = false;
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
			std::string arg = argv[i + 1];
			// ignore options
			if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-t") == 0) || (arg.find("-w") == 0) || 
				(arg.find("-L") == 0) || (arg.find("-l") == 0) || (arg.find("-g") == 0) || (arg.find("-x") == 0))
			{
				i++;
				continue;
			}
			else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
			{
				if ((arg.find("--help") == 0) || (arg.find("--version") == 0))
					notcon = true; // not continue
				if ((arg.find("-h") == 0) || (arg.find("-v") == 0))
					notcon = true; // not continue
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
		N = peers.size();
	}
	if (!notcon)
	{
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
	}

#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_string('g',
			"group",
			NULL,
			"common reference string that defines the underlying DDH-hard group",
			&gnunet_opt_crs
		),
		GNUNET_GETOPT_option_string('p',
			"port",
			NULL,
			"GNUnet CADET port to listen/connect",
			&gnunet_opt_port
		),
		GNUNET_GETOPT_option_uint('t',
			"t-resilience",
			NULL,
			"resilience of DKG protocol",
			&gnunet_opt_t_resilience
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			NULL,
			"minutes to wait until start of DKG protocol",
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
    		return -1;
	int ret = GNUNET_PROGRAM_run(argc, argv, "dkg-generate [OPTIONS] PEERS", "distributed key generation (ElGamal with OpenPGP-output)",
                            options, &gnunet_run, argv[0]);
	GNUNET_free((void *) argv);
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNunet development files are required for message exchange of DKG protocol" << std::endl;
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
