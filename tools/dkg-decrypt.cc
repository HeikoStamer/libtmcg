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

void start_instance
	(size_t whoami, const std::string my_keyid, const std::string passphrase, const std::string armored_message)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-decrypt (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */

			// read the exported DKG state from file
			std::string line, dkgfilename = my_keyid + ".dkg";
			std::stringstream dkgstate;
			std::ifstream dkgifs(dkgfilename.c_str(), std::ifstream::in);
			if (!dkgifs.is_open())
			{
				std::cerr << "ERROR: cannot open state file" << std::endl;
				exit(-1);
			}
			while (std::getline(dkgifs, line))
				dkgstate << line << std::endl;
			dkgifs.close();

			// create an instance of DKG
			GennaroJareckiKrawczykRabinDKG *dkg;
			std::cout << "GennaroJareckiKrawczykRabinDKG(...)" << std::endl;
			dkg = new GennaroJareckiKrawczykRabinDKG(dkgstate);
			if (!dkg->CheckGroup())
			{
				std::cerr << "ERROR: CheckGroup() failed" << std::endl;
				exit(-1);
			}

			// set correct index from saved DKG state
			whoami = dkg->i;

			// create pipe streams and handles between all players
			std::vector<ipipestream*> P_in;
			std::vector<opipestream*> P_out;
			std::vector<int> uP_in, uP_out, bP_in, bP_out;
			std::vector<std::string> uP_key, bP_key;
			for (size_t i = 0; i < dkg->n; i++)
			{
				std::stringstream key;
				key << "dkg-decrypt::P_" << (i + whoami);
				P_in.push_back(new ipipestream(pipefd[i][whoami][0]));
				P_out.push_back(new opipestream(pipefd[whoami][i][1]));
				uP_in.push_back(pipefd[i][whoami][0]);
				uP_out.push_back(pipefd[whoami][i][1]);
				uP_key.push_back(key.str());
				bP_in.push_back(broadcast_pipefd[i][whoami][0]);
				bP_out.push_back(broadcast_pipefd[whoami][i][1]);
				bP_key.push_back(key.str());
			}

			// create asynchronous authenticated unicast channels
			aiounicast *aiou = new aiounicast(dkg->n, dkg->t, whoami, uP_in, uP_out, uP_key);

			// create asynchronous authenticated unicast channels
			aiounicast *aiou2 = new aiounicast(dkg->n, dkg->t, whoami, bP_in, bP_out, bP_key);
			
			// create an instance of a reliable broadcast protocol (RBC)
			std::string myID = "dkg-decrypt";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(dkg->n, dkg->t, whoami, aiou2);
			rbc->setID(myID);

			// check the key share
			std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
			if (!dkg->CheckKey())
			{
				std::cerr << "ERROR: CheckKey() failed" << std::endl;
				exit(-1);
			}

			// read the private key from file
			dkgfilename = my_keyid + "_dkg-sec.asc";
			std::stringstream dkgseckey;
			std::ifstream secifs(dkgfilename.c_str(), std::ifstream::in);
			if (!secifs.is_open())
			{
				std::cerr << "ERROR: cannot open key file" << std::endl;
				exit(-1);
			}
			while (std::getline(secifs, line))
				dkgseckey << line << std::endl;
			secifs.close();
			std::string armored_seckey = dkgseckey.str();

	// parse the private key
	bool secdsa = false, sigdsa = false, ssbelg = false, sigelg = false;
	std::string u;
	BYTE atype = 0, ptag = 0xFF;
	BYTE dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	BYTE dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	BYTE *key, *iv;
	OCTETS pkts, pub, sub, msg, lit, mdc, seipd, pkesk, all;
	OCTETS seskey, salt, mpis, prefix, hash_input, hash, keyid, pub_hashing, subkeyid, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_mpi_t dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, dsa_r, dsa_s, elg_p, elg_g, elg_y, elg_x, elg_r, elg_s;
	gcry_sexp_t dsakey, elgkey;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	TMCG_OPENPGP_CONTEXT ctx;
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	dsa_x = gcry_mpi_new(2048);
	dsa_r = gcry_mpi_new(2048);
	dsa_s = gcry_mpi_new(2048);
	elg_p = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	elg_x = gcry_mpi_new(2048);
	elg_r = gcry_mpi_new(2048);
	elg_s = gcry_mpi_new(2048);
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armored_seckey, pkts);
	std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype == 5)
	{
		while (pkts.size() && ptag)
		{
			ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx);
			std::cout << "PacketDecode() = " << (int)ptag;
			if (!ptag)
			{
				std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
				exit(-1); // error detected
			}
			std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version;
			std::cout << std::endl;
			switch (ptag)
			{
				case 2: // Signature Packet
					issuer.clear();
					std::cout << " issuer = " << std::hex;
					for (size_t i = 0; i < sizeof(ctx.issuer); i++)
					{
						std::cout << (int)ctx.issuer[i] << " ";
						issuer.push_back(ctx.issuer[i]);
					}
					std::cout << std::dec << std::endl;
					if (secdsa && !ssbelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::endl;
						dsa_sigtype = ctx.type;
						dsa_pkalgo = ctx.pkalgo;
						dsa_hashalgo = ctx.hashalgo;
						for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
							dsa_keyflags[i] = ctx.keyflags[i];
						for (size_t i = 0; i < sizeof(dsa_psa); i++)
							dsa_psa[i] = ctx.psa[i];
						for (size_t i = 0; i < sizeof(dsa_pha); i++)
							dsa_pha[i] = ctx.pha[i];
						for (size_t i = 0; i < sizeof(dsa_pca); i++)
							dsa_pca[i] = ctx.pca[i];
						dsa_hspd.clear();
						for (size_t i = 0; i < ctx.hspdlen; i++)
							dsa_hspd.push_back(ctx.hspd[i]);
						dsa_r = ctx.r, dsa_s = ctx.s;
						if (dsa_pkalgo != 17)
						{
							std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
							exit(-1);
						}
						sigdsa = true;
					}
					else if (secdsa && ssbelg && (ctx.type == 0x18) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::endl;
						elg_sigtype = ctx.type;
						elg_pkalgo = ctx.pkalgo;
						elg_hashalgo = ctx.hashalgo;
						for (size_t i = 0; i < sizeof(elg_keyflags); i++)
							elg_keyflags[i] = ctx.keyflags[i];
						for (size_t i = 0; i < sizeof(elg_psa); i++)
							elg_psa[i] = ctx.psa[i];
						for (size_t i = 0; i < sizeof(elg_pha); i++)
							elg_pha[i] = ctx.pha[i];
						for (size_t i = 0; i < sizeof(elg_pca); i++)
							elg_pca[i] = ctx.pca[i];
						elg_hspd.clear();
						for (size_t i = 0; i < ctx.hspdlen; i++)
							elg_hspd.push_back(ctx.hspd[i]);
						elg_r = ctx.r, elg_s = ctx.s;
						if (elg_pkalgo != 17)
						{
							std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
							exit(-1);
						}
						sigelg = true;
					}
					break;
				case 5: // Secret-Key Packet
					if ((ctx.pkalgo == 17) && !secdsa)
					{
						secdsa = true;
						dsa_p = ctx.p, dsa_q = ctx.q, dsa_g = ctx.g, dsa_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime,
							dsa_p, dsa_q, dsa_g, dsa_y, pub);
						for (size_t i = 6; i < pub.size(); i++)
							pub_hashing.push_back(pub[i]);
						CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
						std::cout << " Key ID of DSA key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
						if (ctx.s2kconv == 0)
						{
							dsa_x = ctx.x; // not encrypted
						}
						else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
						{
							keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
							ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
							if (!keylen || !ivlen)
							{
								std::cerr << "ERROR: unknown symmetric algorithm" << std::endl;
								exit(-1);
							}
							salt.clear();
							for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
								salt.push_back(ctx.s2k_salt[i]);
							seskey.clear();
							if (ctx.s2k_type == 0x00)
							{
								salt.clear();
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, false, ctx.s2k_count, seskey);
							}
							else if (ctx.s2k_type == 0x01)
							{
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, false, ctx.s2k_count, seskey);
							}
							else if (ctx.s2k_type == 0x03)
							{
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, true, ctx.s2k_count, seskey);
							}
							else
							{
								std::cerr << "ERROR: unknown S2K specifier" << std::endl;
								exit(-1);
							}
							if (seskey.size() != keylen)
							{
								std::cerr << "ERROR: S2K failed" << std::endl;
								exit(-1);
							}
							if (!ctx.encdatalen || !ctx.encdata)
							{
								std::cerr << "ERROR: nothing to decrypt" << std::endl;
								exit(-1);
							}
							key = new BYTE[keylen], iv = new BYTE[ivlen];
							for (size_t i = 0; i < keylen; i++)
								key[i] = seskey[i];
							for (size_t i = 0; i < ivlen; i++)
								iv[i] = ctx.iv[i];
							ret = gcry_cipher_open(&hd, (int)ctx.symalgo, GCRY_CIPHER_MODE_CFB, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_setkey(hd, key, keylen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_setiv(hd, iv, ivlen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
								exit(-1);
							}
							gcry_cipher_close(hd);
							delete [] key, delete [] iv;
							// read MPI x and verify checksum/hash
							mpis.clear();
							chksum = 0;
							for (size_t i = 0; i < ctx.encdatalen; i++)
								mpis.push_back(ctx.encdata[i]);
							mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
							if (!mlen || (mlen > mpis.size()))
							{
								std::cerr << "ERROR: reading MPI x failed (bad passphrase)" << std::endl;
								exit(-1);
							}
							mpis.erase(mpis.begin(), mpis.begin()+mlen);
							if (ctx.s2kconv == 255)
							{
								if (mpis.size() < 2)
								{
									std::cerr << "ERROR: no checksum found" << std::endl;
									exit(-1);
								}
								chksum2 = (mpis[0] << 8) + mpis[1];
								if (chksum != chksum2)
								{
									std::cerr << "ERROR: checksum mismatch" << std::endl;
									exit(-1);
								}
							}
							else
							{
								if (mpis.size() != 20)
								{
									std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
									exit(-1);
								}
								hash_input.clear(), hash.clear();
								for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
									hash_input.push_back(ctx.encdata[i]);
								CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
								if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
								{
									std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
									exit(-1);
								}
							}
						}
						else
						{
							std::cerr << "ERROR: S2K format not supported" << std::endl;
							exit(-1);
						}
					}
					else if ((ctx.pkalgo == 17) && secdsa)
					{
						std::cerr << "ERROR: more than one primary key not supported" << std::endl;
						exit(-1);
					}
					else
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
					break;
				case 13: // User ID Packet
					std::cout << " uid = " << ctx.uid << std::endl;
					u = "";
					for (size_t i = 0; i < sizeof(ctx.uid); i++)
						if (ctx.uid[i])
							u += ctx.uid[i];
						else
							break;
					break;
				case 7: // Secret-Subkey Packet
					if ((ctx.pkalgo == 16) && !ssbelg)
					{
						ssbelg = true;
						elg_p = ctx.p, elg_g = ctx.g, elg_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime,
							elg_p, elg_g, elg_y, sub);
						for (size_t i = 6; i < sub.size(); i++)
							sub_hashing.push_back(sub[i]);
						CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
							std::cout << "Key ID of Elgamal subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cout << (int)subkeyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
						if (ctx.s2kconv == 0)
						{
							elg_x = ctx.x; // not encrypted
						}
						else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
						{
							keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
							ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
							if (!keylen || !ivlen)
							{
								std::cerr << "ERROR: unknown symmetric algorithm" << std::endl;
								exit(-1);
							}
							salt.clear();
							for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
								salt.push_back(ctx.s2k_salt[i]);
							seskey.clear();
							if (ctx.s2k_type == 0x00)
							{
								salt.clear();
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, false, ctx.s2k_count, seskey);
							}
							else if (ctx.s2k_type == 0x01)
							{
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, false, ctx.s2k_count, seskey);
							}
							else if (ctx.s2k_type == 0x03)
							{
								CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
									keylen, passphrase, salt, true, ctx.s2k_count, seskey);
							}
							else
							{
								std::cerr << "ERROR: unknown S2K specifier" << std::endl;
								exit(-1);
							}
							if (seskey.size() != keylen)
							{
								std::cerr << "ERROR: S2K failed" << std::endl;
								exit(-1);
							}
							if (!ctx.encdatalen || !ctx.encdata)
							{
								std::cerr << "ERROR: nothing to decrypt" << std::endl;
								exit(-1);
							}
							key = new BYTE[keylen], iv = new BYTE[ivlen];
							for (size_t i = 0; i < keylen; i++)
								key[i] = seskey[i];
							for (size_t i = 0; i < ivlen; i++)
								iv[i] = ctx.iv[i];
							ret = gcry_cipher_open(&hd, (int)ctx.symalgo, GCRY_CIPHER_MODE_CFB, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_setkey(hd, key, keylen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_setiv(hd, iv, ivlen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
								exit(-1);
							}
							ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
								exit(-1);
							}
							gcry_cipher_close(hd);
							delete [] key, delete [] iv;
							// read MPI x and verify checksum/hash
							mpis.clear();
							chksum = 0;
							for (size_t i = 0; i < ctx.encdatalen; i++)
								mpis.push_back(ctx.encdata[i]);
							mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, elg_x, chksum);
							if (!mlen || (mlen > mpis.size()))
							{
								std::cerr << "ERROR: reading MPI x failed (bad passphrase)" << std::endl;
								exit(-1);
							}
							mpis.erase(mpis.begin(), mpis.begin()+mlen);
							if (ctx.s2kconv == 255)
							{
								if (mpis.size() < 2)
								{
									std::cerr << "ERROR: no checksum found" << std::endl;
									exit(-1);
								}
								chksum2 = (mpis[0] << 8) + mpis[1];
								if (chksum != chksum2)
								{
									std::cerr << "ERROR: checksum mismatch" << std::endl;
									exit(-1);
								}
							}
							else
							{
								if (mpis.size() != 20)
								{
									std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
									exit(-1);
								}
								hash_input.clear(), hash.clear();
								for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
									hash_input.push_back(ctx.encdata[i]);
								CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
								if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
								{
									std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
									exit(-1);
								}
							}
						}
						else
						{
							std::cerr << "ERROR: S2K format not supported" << std::endl;
							exit(-1);
						}
					}
					else if ((ctx.pkalgo == 16) && ssbelg)
						std::cerr << "WARNING: Elgamal subkey already found" << std::endl; 
					else
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
					break;
			}
			// cleanup allocated buffers
			if (ctx.hspd != NULL)
				delete [] ctx.hspd;
			if (ctx.encdata != NULL)
				delete [] ctx.encdata;
			if (ctx.compdata != NULL)
				delete [] ctx.compdata;
			if (ctx.data != NULL)
				delete [] ctx.data;
		}
	}
	else
	{
		std::cerr << "ERROR: wrong type of ASCII Armor" << std::endl;
		exit(-1);
	}
	if (!secdsa)
	{
		std::cerr << "ERROR: no DSA private key found" << std::endl;
		exit(-1);
	}
	if (!ssbelg)
	{
		std::cerr << "ERROR: no Elgamal private subkey found" << std::endl;
		exit(-1);
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA key found" << std::endl;
		exit(-1);
	}
	if (!sigelg)
	{
		std::cerr << "ERROR: no self-signature for Elgamal subkey found" << std::endl;
		exit(-1);
	}

	// compare the key IDs
	std::stringstream seckeyid;
	seckeyid << std::hex;
	for (size_t i = 0; i < keyid.size(); i++)
		seckeyid << (int)keyid[i];
	if (my_keyid != seckeyid.str())
	{
		std::cerr << "ERROR: wrong key ID" << std::endl;
		exit(-1);
	}

	// build keys, check key usage and self-signatures
	OCTETS dsa_trailer, elg_trailer, dsa_left, elg_left;
	std::cout << "Primary User ID: " << u << std::endl;
	ret = gcry_sexp_build(&dsakey, &erroff, "(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))", dsa_p, dsa_q, dsa_g, dsa_y, dsa_x);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed" << std::endl;
		exit(-1);
	}
	std::cout << "DSA key flags: ";
	size_t flags = 0;
	for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
	{
		if (dsa_keyflags[i])	
			flags = (flags << 8) + dsa_keyflags[i];
		else
			break;
	}
	if ((flags & 0x01) == 0x01)
		std::cout << "C"; // The key may be used to certify other keys.
	if ((flags & 0x02) == 0x02)
		std::cout << "S"; // The key may be used to sign data.
	if ((flags & 0x04) == 0x04)
		std::cout << "E"; // The key may be used encrypt communications.
	if ((flags & 0x08) == 0x08)
		std::cout << "e"; // The key may be used encrypt storage.
	if ((flags & 0x10) == 0x10)
		std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
	if ((flags & 0x20) == 0x20)
		std::cout << "A"; // The key may be used for authentication.
	if ((flags & 0x80) == 0x80)
		std::cout << "M"; // The private component of this key may be in the possession of more than one person.
	std::cout << std::endl;
	dsa_trailer.push_back(4); // only V4 format supported
	dsa_trailer.push_back(dsa_sigtype);
	dsa_trailer.push_back(dsa_pkalgo);
	dsa_trailer.push_back(dsa_hashalgo);
	dsa_trailer.push_back(dsa_hspd.size() >> 8); // length of hashed subpacket data
	dsa_trailer.push_back(dsa_hspd.size());
	dsa_trailer.insert(dsa_trailer.end(), dsa_hspd.begin(), dsa_hspd.end());
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, dsa_trailer, dsa_hashalgo, hash, dsa_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, dsa_r, dsa_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of DSA key self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		exit(-1);
	}
	ret = gcry_sexp_build(&elgkey, &erroff, "(private-key (elg (p %M) (g %M) (y %M) (x %M)))", elg_p, elg_g, elg_y, elg_x);
	if (ret)
	{
		std::cerr << "ERROR: parsing Elgamal key material failed" << std::endl;
		exit(-1);
	}
	std::cout << "Elgamal key flags: ";
	flags = 0;
	for (size_t i = 0; i < sizeof(elg_keyflags); i++)
	{
		if (elg_keyflags[i])
			flags = (flags << 8) + elg_keyflags[i];
		else
			break;
	}
	if ((flags & 0x01) == 0x01)
		std::cout << "C"; // The key may be used to certify other keys.
	if ((flags & 0x02) == 0x02)
		std::cout << "S"; // The key may be used to sign data.
	if ((flags & 0x04) == 0x04)
		std::cout << "E"; // The key may be used encrypt communications.
	if ((flags & 0x08) == 0x08)
		std::cout << "e"; // The key may be used encrypt storage.
	if ((flags & 0x10) == 0x10)
		std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
	if ((flags & 0x20) == 0x20)
		std::cout << "A"; // The key may be used for authentication.
	if ((flags & 0x80) == 0x80)
		std::cout << "M"; // The private component of this key may be in the possession of more than one person.
	std::cout << std::endl;
	if ((flags & 0x04) != 0x04)
	{
		std::cerr << "ERROR: Elgamal subkey cannot used to encrypt communications" << std::endl;
		exit(-1);
	}
	elg_trailer.push_back(4); // only V4 format supported
	elg_trailer.push_back(elg_sigtype);
	elg_trailer.push_back(elg_pkalgo);
	elg_trailer.push_back(elg_hashalgo);
	elg_trailer.push_back(elg_hspd.size() >> 8); // length of hashed subpacket data
	elg_trailer.push_back(elg_hspd.size());
	elg_trailer.insert(elg_trailer.end(), elg_hspd.begin(), elg_hspd.end());
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, elg_trailer, elg_hashalgo, hash, elg_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, elg_r, elg_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of Elgamal subeky self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		exit(-1);
	}

	// parse encrypted message
	bool have_pkesk = false, have_sed = false, have_seipd = false, have_mdc = false;
	OCTETS pkesk_keyid;
	gcry_mpi_t gk, myk;
	gk = gcry_mpi_new(2048);
	myk = gcry_mpi_new(2048);
	ptag = 0xFF;
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armored_message, pkts);
	std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype == 1)
	{
		while (pkts.size() && ptag)
		{
			ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx);
			std::cout << "PacketDecode() = " << (int)ptag;
			if (!ptag)
			{
				std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
				exit(-1); // error detected
			}
			std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version;
			std::cout << std::endl;
			switch (ptag)
			{
				case 1: // Public-Key Encrypted Session Key
					if (ctx.pkalgo != 16)
					{
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
						break;
					}
					std::cout << " keyid = " << std::hex;
					for (size_t i = 0; i < sizeof(ctx.keyid); i++)
					{
						std::cout << (int)ctx.keyid[i] << " ";
						pkesk_keyid.push_back(ctx.keyid[i]);
					}
					std::cout << std::dec << std::endl;
					if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(pkesk_keyid, subkeyid))
					{
						std::cerr << "WARNING: pkesk-key ID does not match subkey ID" << std::endl;
						break;
					}
					have_pkesk = true;
					gk = ctx.gk, myk = ctx.myk;
					break;
				case 9: // Symmetrically Encrypted Data
					have_sed = true;
					break;
				case 18: // Symmetrically Encrypted Integrity Protected Data
					have_seipd = true;
					break;
				case 19: // Modification Detection Code
					have_mdc = true;
					break;
				default:
					std::cerr << "ERROR: unrecognized OpenPGP packet found" << std::endl;
					exit(-1);
			}
			// cleanup allocated buffers
			if (ctx.hspd != NULL)
				delete [] ctx.hspd;
			if (ctx.encdata != NULL)
				delete [] ctx.encdata;
			if (ctx.compdata != NULL)
				delete [] ctx.compdata;
			if (ctx.data != NULL)
				delete [] ctx.data;
		}
	}
	else
	{
		std::cerr << "ERROR: wrong type of ASCII Armor" << std::endl;
		exit(-1);
	}
	if (!have_pkesk)
	{
		std::cerr << "ERROR: no public-key encrypted session key found" << std::endl;
		exit(-1);
	}
	if (!have_sed && !have_seipd)
	{
		std::cerr << "ERROR: no symmetrically encrypted (and integrity protected) data found" << std::endl;
		exit(-1);
	}
	if (have_seipd && !have_mdc)
	{
		std::cerr << "ERROR: no modification detection code found" << std::endl;
		exit(-1);
	}
	// check whether DSA and Elgamal parameters match
	if (gcry_mpi_cmp(dsa_p, elg_p) || gcry_mpi_cmp(dsa_g, elg_g))
	{
		std::cerr << "ERROR: DSA and Elgamal group parameters does not match" << std::endl;
		exit(-1);
	}
	// check whether $0 < g^k < p$.
	if ((gcry_mpi_cmp_ui(gk, 0L) <= 0) || (gcry_mpi_cmp(gk, elg_p) >= 0))
	{
		std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
		exit(-1);
	}
	// check whether $(g^k)^q \equiv 1 \pmod{p}$.
	gcry_mpi_powm(dsa_r, gk, dsa_q, elg_p);
	if (gcry_mpi_cmp_ui(dsa_r, 1L))
	{
		std::cerr << "ERROR: (g^k)^q \equiv 1 mod p not satisfied" << std::endl;
		exit(-1);
	}	
	// compute the decryption share
	char buffer[2048];
	size_t buflen = sizeof(buffer);
	mpz_t nizk_p, nizk_q, nizk_g, nizk_gk, x_i, r_i, R;
	mpz_init(nizk_p), mpz_init(nizk_q), mpz_init(nizk_g), mpz_init(nizk_gk), mpz_init(x_i), mpz_init(r_i), mpz_init(R);
	std::memset(buffer, 0, buflen);
	gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buffer, buflen, &buflen, dsa_p);
	mpz_set_str(nizk_p, buffer, 16);
	std::memset(buffer, 0, buflen);
	gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buffer, buflen, &buflen, dsa_q);
	mpz_set_str(nizk_q, buffer, 16);
	std::memset(buffer, 0, buflen);
	gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buffer, buflen, &buflen, dsa_g);
	mpz_set_str(nizk_g, buffer, 16);
	std::memset(buffer, 0, buflen);
	gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buffer, buflen, &buflen, gk);
	mpz_set_str(nizk_gk, buffer, 16);
	std::memset(buffer, 0, buflen);
	gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char*)buffer, buflen, &buflen, elg_x);
	mpz_set_str(x_i, buffer, 16);
	mpz_spowm(r_i, nizk_gk, x_i, nizk_p);
	// compute NIZK argument for decryption share
		// proof of knowledge (equality of discrete logarithms) [CaS97]
		mpz_t a, b, omega, c, r;
		mpz_init(c), mpz_init(r), mpz_init(a), mpz_init(b), mpz_init(omega);
		// commitment
		mpz_srandomm(omega, nizk_q);
		mpz_spowm(a, nizk_gk, omega, nizk_p);
		mpz_spowm(b, nizk_g, omega, nizk_p);		
		// challenge
		// Here we use the well-known "Fiat-Shamir heuristic" to make
		// the PoK non-interactive, i.e. we turn it into a statistically
		// zero-knowledge (Schnorr signature scheme style) proof of
		// knowledge (SPK) in the random oracle model.
		mpz_shash(c, 6, a, b, r_i, dkg->y_i[dkg->i], nizk_gk, nizk_g);
		// response
		mpz_mul(r, c, x_i);
		mpz_neg(r, r);
		mpz_add(r, r, omega);
		mpz_mod(r, r, nizk_q);
	// broadcast the decryption share and the NIZK argument
	rbc->Broadcast(r_i);
	rbc->Broadcast(c);
	rbc->Broadcast(r);
	mpz_set(R, r_i); // put private key of this party in the accumulator
	std::vector<size_t> complaints;
	for (size_t i = 0; i < dkg->n; i++)
	{
		if (i != dkg->i)
		{
			// receive a decryption share and NIZK argument
			if (!rbc->DeliverFrom(r_i, i))
				complaints.push_back(i);
			if (!rbc->DeliverFrom(c, i))
				complaints.push_back(i);
			if (!rbc->DeliverFrom(r, i))
				complaints.push_back(i);
			// check the NIZK argument
			if ((mpz_cmpabs(r, nizk_q) >= 0) || (mpz_sizeinbase(c, 2L) <= 256)) // check the size of r and c
				complaints.push_back(i);
			// verify proof of knowledge (equality of discrete logarithms) [CaS97]
			mpz_powm(a, nizk_gk, r, nizk_p);
			mpz_powm(b, r_i, c, nizk_p);
			mpz_mul(a, a, b);
			mpz_mod(a, a, nizk_p);
			mpz_powm(b, nizk_g, r, nizk_p);
			mpz_powm(r, dkg->y_i[i], c, nizk_p);
			mpz_mul(b, b, r);
			mpz_mod(b, b, nizk_p);
			mpz_shash(r, 6, a, b, r_i, dkg->y_i[i], nizk_gk, nizk_g);
			if (mpz_cmp(r, c))
				complaints.push_back(i);
			if (std::find(complaints.begin(), complaints.end(), i) == complaints.end())
			{
				// accumulate decryption shares
				mpz_mul(R, R, r_i);
				mpz_mod(R, R, nizk_p);
			}
			else
				std::cout << "WARNING: complaint against P_" << i << std::endl;
		}

	}

// TODO: reconstruction of x_i for faulty parties

	// decrypt the session key
	mpz_get_str(buffer, 16, R);
	ret = gcry_mpi_scan(&gk, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
	assert(!ret);
	gcry_sexp_release(elgkey); // release the former private key
	gcry_mpi_set_ui(elg_x, 1); // the private key of this party has been already used in R
	ret = gcry_sexp_build(&elgkey, &erroff, "(private-key (elg (p %M) (g %M) (y %M) (x %M)))", elg_p, elg_g, elg_y, elg_x);
	if (ret)
	{
		std::cerr << "ERROR: processing Elgamal key material failed" << std::endl;
		exit(-1);
	}
	seskey.clear();
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptElgamal(gk, myk, elgkey, seskey);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricDecryptElgamal() failed with rc = " << gcry_err_code(ret) << std::endl;
		exit(-1);
	}

// TODO: decrypt OpenPGP message


	mpz_clear(c), mpz_clear(r), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
	mpz_clear(nizk_p), mpz_clear(nizk_q), mpz_clear(nizk_g), mpz_clear(nizk_gk), mpz_clear(x_i), mpz_clear(r_i), mpz_clear(R);

			// release RBC			
			delete rbc;

	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(dsa_x);
	gcry_mpi_release(dsa_r);
	gcry_mpi_release(dsa_s);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(elg_x);
	gcry_mpi_release(elg_r);
	gcry_mpi_release(elg_s);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	gcry_sexp_release(dsakey);
	gcry_sexp_release(elgkey);
			
			// release pipe streams (private channels)
			size_t numRead = 0, numWrite = 0;
			for (size_t i = 0; i < dkg->n; i++)
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

			// release DKG
			delete dkg;
			
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
	std::string passphrase, line, armored_message;
	std::vector<std::string> keyids;

	// read the passphrase and key IDs
	std::cout << "1. Please enter the passphrase to unlock your private key: ";
	std::getline(std::cin, passphrase);

	std::cout << "2. Now provide the key IDs (one per line) of the participants: ";
	while (std::getline(std::cin, line))
		keyids.push_back(line);
	std::cin.clear();

	// read the encrypted message
	std::cout << "3. Finally, enter the encrypted message (in ASCII Armor; ^D for EOF): " << std::endl;
	while (std::getline(std::cin, line))
		armored_message += line + "\r\n";
	std::cin.clear();

	// open pipes
	for (size_t i = 0; i < keyids.size(); i++)
	{
		for (size_t j = 0; j < keyids.size(); j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-decrypt (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-decrypt (pipe)");
		}
	}
	
	// start childs
	for (size_t i = 0; i < keyids.size(); i++)
		start_instance(i, keyids[i], passphrase, armored_message);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < keyids.size(); i++)
	{
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-decrypt (waitpid)");
		for (size_t j = 0; j < keyids.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
		}
	}
	
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
