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
#define N 7
#define T 2

int pipefd[N][N][2], broadcast_pipefd[N][N][2];
pid_t pid[N];

void start_instance
	(std::istream& crs_in, size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-decrypt (fork)");
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
				key << "t-dkg::P_" << (i + whoami);
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
			std::string myID = "t-dkg";
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

// TODO
			
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
	std::string passphrase, line, armored_seckey, message, armored_message;

	// read the private key
	std::cout << "1. Please enter the passphrase to unlock your private key: ";
	std::getline(std::cin, passphrase);

	std::cout << "2. Now provide your private key (in ASCII Armor; ^D for EOF): " << std::endl;
	while (std::getline(std::cin, line))
		armored_seckey += line + "\r\n";
	std::cin.clear();
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
				return -1; // error detected
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
							return -1;
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
							return -1;
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
								return -1;
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
								return -1;
							}
							if (seskey.size() != keylen)
							{
								std::cerr << "ERROR: S2K failed" << std::endl;
								return -1;
							}
							if (!ctx.encdatalen || !ctx.encdata)
							{
								std::cerr << "ERROR: nothing to decrypt" << std::endl;
								return -1;
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
								return -1;
							}
							ret = gcry_cipher_setkey(hd, key, keylen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
								return -1;
							}
							ret = gcry_cipher_setiv(hd, iv, ivlen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
								return -1;
							}
							ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
								return -1;
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
								return -1;
							}
							mpis.erase(mpis.begin(), mpis.begin()+mlen);
							if (ctx.s2kconv == 255)
							{
								if (mpis.size() < 2)
								{
									std::cerr << "ERROR: no checksum found" << std::endl;
									return -1;
								}
								chksum2 = (mpis[0] << 8) + mpis[1];
								if (chksum != chksum2)
								{
									std::cerr << "ERROR: checksum mismatch" << std::endl;
									return -1;
								}
							}
							else
							{
								if (mpis.size() != 20)
								{
									std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
									return -1;
								}
								hash_input.clear(), hash.clear();
								for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
									hash_input.push_back(ctx.encdata[i]);
								CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
								if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
								{
									std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
									return -1;
								}
							}
						}
						else
						{
							std::cerr << "ERROR: S2K format not supported" << std::endl;
							return -1;
						}
					}
					else if ((ctx.pkalgo == 17) && secdsa)
					{
						std::cerr << "ERROR: more than one primary key not supported" << std::endl;
						return -1;
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
								return -1;
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
								return -1;
							}
							if (seskey.size() != keylen)
							{
								std::cerr << "ERROR: S2K failed" << std::endl;
								return -1;
							}
							if (!ctx.encdatalen || !ctx.encdata)
							{
								std::cerr << "ERROR: nothing to decrypt" << std::endl;
								return -1;
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
								return -1;
							}
							ret = gcry_cipher_setkey(hd, key, keylen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
								return -1;
							}
							ret = gcry_cipher_setiv(hd, iv, ivlen);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
								return -1;
							}
							ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
							if (ret)
							{
								std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
								return -1;
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
								return -1;
							}
							mpis.erase(mpis.begin(), mpis.begin()+mlen);
							if (ctx.s2kconv == 255)
							{
								if (mpis.size() < 2)
								{
									std::cerr << "ERROR: no checksum found" << std::endl;
									return -1;
								}
								chksum2 = (mpis[0] << 8) + mpis[1];
								if (chksum != chksum2)
								{
									std::cerr << "ERROR: checksum mismatch" << std::endl;
									return -1;
								}
							}
							else
							{
								if (mpis.size() != 20)
								{
									std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
									return -1;
								}
								hash_input.clear(), hash.clear();
								for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
									hash_input.push_back(ctx.encdata[i]);
								CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
								if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
								{
									std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
									return -1;
								}
							}
						}
						else
						{
							std::cerr << "ERROR: S2K format not supported" << std::endl;
							return -1;
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
		return -1;
	}
	if (!secdsa)
	{
		std::cerr << "ERROR: no DSA private key found" << std::endl;
		return -1;
	}
	if (!ssbelg)
	{
		std::cerr << "ERROR: no Elgamal private subkey found" << std::endl;
		return -1;
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA key found" << std::endl;
		return -1;
	}
	if (!sigelg)
	{
		std::cerr << "ERROR: no self-signature for Elgamal subkey found" << std::endl;
		return -1;
	}

	// build keys, check key usage and self-signatures
	OCTETS dsa_trailer, elg_trailer, dsa_left, elg_left;
	std::cout << "Primary User ID: " << u << std::endl;
	ret = gcry_sexp_build(&dsakey, &erroff, "(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))", dsa_p, dsa_q, dsa_g, dsa_y, dsa_x);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed" << std::endl;
		return -1;
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
		return -1;
	}
	ret = gcry_sexp_build(&elgkey, &erroff, "(private-key (elg (p %M) (g %M) (y %M) (x %M)))", elg_p, elg_g, elg_y, elg_x);
	if (ret)
	{
		std::cerr << "ERROR: parsing Elgamal key material failed" << std::endl;
		return -1;
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
		return -1;
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
		return -1;
	}

	// read the encrypted message
	std::cout << "3. Finally, enter the encrypted message (in ASCII Armor; ^D for EOF): " << std::endl;
	while (std::getline(std::cin, line))
		armored_message += line + "\r\n";
	std::cin.clear();
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
				return -1; // error detected
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
					return -1;
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
		return -1;
	}
	if (!have_pkesk)
	{
		std::cerr << "ERROR: no public-key encrypted session key found" << std::endl;
		return -1;
	}
	if (!have_sed && !have_seipd)
	{
		std::cerr << "ERROR: no symmetrically encrypted (and integrity protected) data found" << std::endl;
		return -1;
	}
	if (have_seipd && !have_mdc)
	{
		std::cerr << "ERROR: no modification detection code found" << std::endl;
		return -1;
	}




// TODO: initialize and check DKG parameters


	BarnettSmartVTMF_dlog 	*vtmf;
	std::stringstream 	crs;

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
				perror("dkg-decrypt (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-decrypt (pipe)");
		}
	}
	
	// start childs
//	for (size_t i = 0; i < N; i++)
//		start_instance(crs, i);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < N; i++)
	{
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-decrypt (waitpid)");
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
		}
	}
	
	// release VTMF instance
	delete vtmf;

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
