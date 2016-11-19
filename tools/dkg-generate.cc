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

#ifdef FORKING

#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "pipestream.hh"

#undef NDEBUG
#define N 7
#define T 2

int pipefd[N][N][2], broadcast_pipefd[N][N][2];
pid_t pid[N];

void start_instance
	(std::istream &crs_in, const size_t whoami, const std::string u, const std::string pp)
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
			std::cout << "GennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", ...)" << std::endl;
			dkg = new GennaroJareckiKrawczykRabinDKG(N, T,
				vtmf->p, vtmf->q, vtmf->g, vtmf->h);
			assert(dkg->CheckGroup());

			// create asynchronous authenticated unicast channels
			aiounicast *aiou = new aiounicast(N, T, whoami, uP_in, uP_out, uP_key);

			// create asynchronous authenticated unicast channels
			aiounicast *aiou2 = new aiounicast(N, T, whoami, bP_in, bP_out, bP_key);
			
			// create an instance of a reliable broadcast protocol (RBC)
			std::string myID = "dkg-generate";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2);
			rbc->setID(myID);
			
			// generating $x$ and extracting $y = g^x \bmod p$
			std::stringstream err_log;
			std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
			assert(dkg->Generate(whoami, aiou, rbc, err_log));
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

			// check the generated key share
			std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
			assert(dkg->CheckKey(whoami));

			// create an OpenPGP DSA-based primary key and Elgamal-based subkey
			char buffer[2048];
			std::string out, crcout, armor;
			OCTETS all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
			OCTETS pub_hashing, sub_hashing;
			OCTETS uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
			time_t keytime, sigtime;
			gcry_mpi_t p, q, g, y, x, r, s, h;
			gcry_sexp_t key, signature, sigdata;
			gcry_error_t ret;
			size_t erroff;
			mpz_t dsa_y, dsa_x;
			mpz_init(dsa_y), mpz_init(dsa_x);
			mpz_srandomm(dsa_x, vtmf->q);
			mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
			keytime = time(NULL); // current time
			p = gcry_mpi_new(2048);
			q = gcry_mpi_new(2048);
			g = gcry_mpi_new(2048);
			y = gcry_mpi_new(2048);
			x = gcry_mpi_new(2048);
			r = gcry_mpi_new(2048);
			s = gcry_mpi_new(2048);
			h = gcry_mpi_new(2048);
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
			dsaflags.push_back(0x01);
			dsaflags.push_back(0x02);
			dsaflags.push_back(0x20);
			sigtime = time(NULL); // current time
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x13, sigtime, dsaflags, keyid, uidsig_hashing);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, h, uidsig_left);
			assert(!ret);
			ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
			assert(!ret);
			ret = gcry_pk_sign(&signature, sigdata, key);
			assert(!ret);
			ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
				mpz_get_str(buffer, 16, dkg->y);			
				ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
				mpz_get_str(buffer, 16, dkg->x_i);			
				ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(keytime, p, g, y, sub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(keytime, p, g, y, x, pp, ssb);
			elgflags.push_back(0x04);
			elgflags.push_back(0x10);
			sigtime = time(NULL); // current time
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x18, sigtime, elgflags, keyid, subsig_hashing);
			for (size_t i = 6; i < sub.size(); i++)
				sub_hashing.push_back(sub[i]);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, h, subsig_left);
			assert(!ret);
			ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
			assert(!ret);
			ret = gcry_pk_sign(&signature, sigdata, key);
			assert(!ret);
			ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
			// export generated public key in OpenPGP armor format
			armor = "", all.clear();
			all.insert(all.end(), pub.begin(), pub.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), sub.begin(), sub.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, all, armor);
			std::cout << armor << std::endl;
			// export generated private key in OpenPGP armor format
			armor = "", all.clear();
			all.insert(all.end(), sec.begin(), sec.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), ssb.begin(), ssb.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
			std::cout << armor << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_mpi_release(h);
			gcry_sexp_release(key);
			gcry_sexp_release(signature);
			gcry_sexp_release(sigdata);
			
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
	assert(init_libTMCG());

	BarnettSmartVTMF_dlog 	*vtmf;
	std::stringstream 	crs;
	std::string		uid, passphrase;

	std::cout << "1. Please enter an OpenPGP-style user ID: ";
	std::getline(std::cin, uid);
	std::cout << "2. Choose a passphrase to protect the private key: ";
	std::getline(std::cin, passphrase);

	// create and check VTMF instance
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
		start_instance(crs, i, uid, passphrase);
	
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
	std::cout << "test skipped" << std::endl;
	return 77;
}

#endif
