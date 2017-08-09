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
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "dkg-builtin-common.hh"
#include "dkg-gnunet-common.hh"

int 					pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t 					pid[MAX_N];
std::vector<std::string>		peers;
bool					instance_forked = false;

std::string				passphrase, armored_seckey, ifilename, ofilename, passwords;
tmcg_octets_t				keyid;
mpz_t					dss_p, dss_q, dss_g, dss_h, dss_x_i, dss_xprime_i;
size_t					dss_n, dss_t, dss_i;
std::vector<size_t>			dss_qual;
std::vector< std::vector<mpz_ptr> >	dss_c_ik;
gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_g, elg_y;
int 					opt_verbose = 0;
char					*opt_ifilename = NULL;
char					*opt_ofilename = NULL;
char					*opt_passwords = NULL;

void read_private_key
	(const std::string filename, std::string &result)
{
	// read the private key from file
	std::string line;
	std::stringstream dkgseckey;
	std::ifstream secifs(filename.c_str(), std::ifstream::in);
	if (!secifs.is_open())
	{
		std::cerr << "ERROR: cannot open key file" << std::endl;
		exit(-1);
	}
	while (std::getline(secifs, line))
		dkgseckey << line << std::endl;
	if (!secifs.eof())
	{
		std::cerr << "ERROR: reading until EOF failed" << std::endl;
		exit(-1);
	}
	secifs.close();
	result = dkgseckey.str();
}

void write_signature
	(const std::string filename, const std::string armored_signature)
{

	// write out the armored signature
	std::ofstream ofs(ofilename.c_str(), std::ofstream::out);
	if (!ofs.good())
	{
		std::cerr << "ERROR: opening output file failed" << std::endl;
		exit(-1);
	}
	ofs << armored_signature << std::endl;
	if (!ofs.good())
	{
		std::cerr << "ERROR: writing to output file failed" << std::endl;
		exit(-1);
	}
	ofs.close();
}

void init_mpis
	()
{
	mpz_init(dss_p);
	mpz_init(dss_q);
	mpz_init(dss_g);
	mpz_init(dss_h);
	mpz_init(dss_x_i);
	mpz_init(dss_xprime_i);
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	dsa_x = gcry_mpi_new(2048);
	elg_p = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
}

bool parse_private_key
	(const std::string in)
{
	// parse the private key
	bool secdsa = false, sigdsa = false, ssbelg = false, sigelg = false;
	std::string u;
	tmcg_byte_t atype = 0, ptag = 0xFF;
	tmcg_byte_t dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	tmcg_byte_t dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	tmcg_byte_t *key, *iv;
	tmcg_octets_t pkts, pub, sub;
	tmcg_octets_t seskey, salt, mpis, hash_input, hash, subkeyid, pub_hashing, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	int algo;
	tmcg_openpgp_packet_ctx ctx;
	std::vector<gcry_mpi_t> qual, v_i;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	gcry_mpi_t dsa_r, dsa_s, elg_r, elg_s;
	dsa_r = gcry_mpi_new(2048);
	dsa_s = gcry_mpi_new(2048);
	elg_r = gcry_mpi_new(2048);
	elg_s = gcry_mpi_new(2048);
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype != 5)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor" << std::endl;
		exit(-1);
	}
	while (pkts.size() && ptag)
	{
		tmcg_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, v_i, c_ik);
		if (opt_verbose)
			std::cout << "PacketDecode(pkts.size = " << pkts.size() << ") = " << (int)ptag;
		if (!ptag)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
			exit(-1); // error detected
		}
		if (opt_verbose)
			std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		switch (ptag)
		{
			case 2: // Signature Packet
				issuer.clear();
				if (opt_verbose)
					std::cout << " issuer = " << std::hex;
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
				{
					if (opt_verbose)
						std::cout << (int)ctx.issuer[i] << " ";
					issuer.push_back(ctx.issuer[i]);
				}
				if (opt_verbose)
					std::cout << std::dec << std::endl;
				if (secdsa && !ssbelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) &&
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
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
					}
					if (sigdsa)
						std::cerr << "WARNING: more than one self-signatures; using last signature to check UID" << std::endl;
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
					if ((dsa_hashalgo < 8) || (dsa_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)dsa_hashalgo << 
							" used for signatures" << std::endl;
					sigdsa = true;
				}
				else if (secdsa && ssbelg && (ctx.type == 0x18) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
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
					}
					if (sigelg)
						std::cerr << "WARNING: more than one subkey binding signature; using last signature" << std::endl;
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
					if ((elg_hashalgo < 8) || (elg_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)elg_hashalgo << 
							" used for signatures" << std::endl;
					sigelg = true;
				}
				break;
			case 5: // Secret-Key Packet
				if ((ctx.pkalgo == 108) && !secdsa)
				{
					secdsa = true;
					dsa_p = ctx.p, dsa_q = ctx.q, dsa_g = ctx.g, dsa_y = ctx.y;
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, 17, // public-key is DSA 
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << " Key ID of tDSS key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dss_p))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_p" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.q, dss_q))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_q" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.g, dss_g))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_g" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.h, dss_h))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_h" << std::endl;
						exit(-1);
					}
					dss_n = get_gcry_mpi_ui(ctx.n);
					dss_t = get_gcry_mpi_ui(ctx.t);
					dss_i = get_gcry_mpi_ui(ctx.i);
					size_t qualsize = qual.size();
					for (size_t i = 0; i < qualsize; i++)
						dss_qual.push_back(get_gcry_mpi_ui(qual[i]));
					dss_c_ik.resize(c_ik.size());
					for (size_t i = 0; i < c_ik.size(); i++)
					{
						for (size_t k = 0; k < c_ik[i].size(); k++)
						{
							mpz_ptr tmp = new mpz_t();
							mpz_init(tmp);
							if (!mpz_set_gcry_mpi(c_ik[i][k], tmp))
							{
								std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp" << std::endl;
								exit(-1);
							}
							dss_c_ik[i].push_back(tmp);
						}
					}
					if (ctx.s2kconv == 0)
					{
						if (!mpz_set_gcry_mpi(ctx.x_i, dss_x_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_x_i" << std::endl;
							exit(-1);
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							exit(-1);
						}
					}
					else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
					{
						keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
						ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
						algo = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmSymGCRY(ctx.symalgo);
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
						key = new tmcg_byte_t[keylen], iv = new tmcg_byte_t[ivlen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
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
						// read MPIs x_i, xprime_i and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI x_i failed (bad passphrase)" << std::endl;
							// cleanup
							if (ctx.hspd != NULL)
								delete [] ctx.hspd;
							if (ctx.encdata != NULL)
								delete [] ctx.encdata;
							if (ctx.compdata != NULL)
								delete [] ctx.compdata;
							if (ctx.data != NULL)
								delete [] ctx.data;
							gcry_mpi_release(dsa_r);
							gcry_mpi_release(dsa_s);
							gcry_mpi_release(elg_r);
							gcry_mpi_release(elg_s);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_x_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_x_i" << std::endl;
							exit(-1);
						}
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							// cleanup
							if (ctx.hspd != NULL)
								delete [] ctx.hspd;
							if (ctx.encdata != NULL)
								delete [] ctx.encdata;
							if (ctx.compdata != NULL)
								delete [] ctx.compdata;
							if (ctx.data != NULL)
								delete [] ctx.data;
							gcry_mpi_release(dsa_r);
							gcry_mpi_release(dsa_s);
							gcry_mpi_release(elg_r);
							gcry_mpi_release(elg_s);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							exit(-1);
						}
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
				else if ((ctx.pkalgo == 108) && secdsa)
				{
					std::cerr << "ERROR: more than one primary key not supported" << std::endl;
					exit(-1);
				}
				else
					std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
				break;
			case 13: // User ID Packet
				if (opt_verbose)
					std::cout << " uid = " << ctx.uid << std::endl;
				u = "";
				for (size_t i = 0; i < sizeof(ctx.uid); i++)
					if (ctx.uid[i])
						u += ctx.uid[i];
					else
						break;
				break;
			case 7: // Secret-Subkey Packet
				if (((ctx.pkalgo == 16) || (ctx.pkalgo == 109)) && !ssbelg)
				{
					ssbelg = true;
					elg_p = ctx.p, elg_g = ctx.g, elg_y = ctx.y;
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime, 16, // public-key is ElGamal 
						elg_p, dsa_q, elg_g, elg_y, sub);
					for (size_t i = 6; i < sub.size(); i++)
						sub_hashing.push_back(sub[i]);
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
					if (opt_verbose)
					{
						std::cout << "Key ID of ElGamal subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cout << (int)subkeyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
				}
				else if (((ctx.pkalgo == 16) || (ctx.pkalgo == 109)) && ssbelg)
					std::cerr << "WARNING: ElGamal subkey already found" << std::endl; 
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
	if (!secdsa)
	{
		std::cerr << "ERROR: no tDSS private key found" << std::endl;
		exit(-1);
	}
	if (!ssbelg)
	{
		std::cerr << "ERROR: no ElGamal private subkey found" << std::endl;
		exit(-1);
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for tDSS key found" << std::endl;
		exit(-1);
	}
	if (!sigelg)
	{
		std::cerr << "ERROR: no self-signature for ElGamal subkey found" << std::endl;
		exit(-1);
	}

	// build keys, check key usage and self-signatures
	gcry_sexp_t dsakey;
	tmcg_octets_t dsa_trailer, elg_trailer, dsa_left, elg_left;
	if (opt_verbose)
		std::cout << "Primary User ID: " << u << std::endl;
	ret = gcry_sexp_build(&dsakey, &erroff, "(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))", dsa_p, dsa_q, dsa_g, dsa_y, dsa_x);
	if (ret)
	{
		std::cerr << "ERROR: parsing tDSS key material failed" << std::endl;
		exit(-1);
	}
	size_t flags = 0;
	for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
	{
		if (dsa_keyflags[i])	
			flags = (flags << 8) + dsa_keyflags[i];
		else
			break;
	}
	if (opt_verbose)
	{
		std::cout << "tDSS key flags: ";
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
	}
	if ((flags & 0x02) != 0x02)
	{
		std::cerr << "ERROR: tDSS primary key cannot used to sign data" << std::endl;
		exit(-1);
	}
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
		std::cerr << "ERROR: verification of tDSS key self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		exit(-1);
	}
	flags = 0;
	for (size_t i = 0; i < sizeof(elg_keyflags); i++)
	{
		if (elg_keyflags[i])
			flags = (flags << 8) + elg_keyflags[i];
		else
			break;
	}
	if (opt_verbose)
	{
		std::cout << "ElGamal key flags: ";
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
	}
	if ((flags & 0x04) != 0x04)
	{
		std::cerr << "ERROR: ElGamal subkey cannot used to encrypt communications" << std::endl;
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
		std::cerr << "ERROR: verification of ElGamal subkey self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		exit(-1);
	}
	gcry_sexp_release(dsakey);
	gcry_mpi_release(dsa_r);
	gcry_mpi_release(dsa_s);
	gcry_mpi_release(elg_r);
	gcry_mpi_release(elg_s);
	return true;
}

void release_mpis
	()
{
	mpz_clear(dss_p);
	mpz_clear(dss_q);
	mpz_clear(dss_g);
	mpz_clear(dss_h);
	mpz_clear(dss_x_i);
	mpz_clear(dss_xprime_i);
	for (size_t i = 0; i < dss_c_ik.size(); i++)
	{
		for (size_t k = 0; k < dss_c_ik[i].size(); k++)
		{
			mpz_clear(dss_c_ik[i][k]);
			delete [] dss_c_ik[i][k];
		}
	}
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(dsa_x);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
}

void run_instance
	(size_t whoami, const time_t sigtime, const time_t sigexptime, const size_t num_xtests)
{
	// read and parse the private key
	std::string thispeer = peers[whoami];
	read_private_key(thispeer + "_dkg-sec.asc", armored_seckey);
	init_mpis();
	if (!parse_private_key(armored_seckey))
	{
		keyid.clear();
		dss_qual.clear(), dss_c_ik.clear();
		// protected with password
		std::cout << "Please enter the passphrase to unlock your private key: ";
		std::getline(std::cin, passphrase);
		std::cin.clear();
		if (!parse_private_key(armored_seckey))
		{
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
		if (passwords.length())
		{
			key << TMCG_ParseHelper::gs(passwords, '/');
			if (TMCG_ParseHelper::gs(passwords, '/') == "ERROR")
			{
				std::cerr << "S_" << whoami << ": " << "cannot read password for protecting channel to S_" << i << std::endl;
				exit(-1);
			}
			else if (((i + 1) < peers.size()) && !TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "S_" << whoami << ": " << "cannot skip to next password for protecting channel to S_" << (i + 1) << std::endl;
				exit(-1);
			}
		}
		else
			key << "dkg-sign::S_" << (i + whoami); // use simple key -- we assume that GNUnet provides secure channels
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
	std::string myID = "dkg-sign|";
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
		std::cout << "S_" << whoami << ": xtest = " << xtest << " <-> ";
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

	// participants must agree on a common signature creation time (OpenPGP)
	time_t csigtime = 0;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, sigtime);
	rbc->Broadcast(mtv);
	tvs.push_back(sigtime);
	for (size_t i = 0; i < peers.size(); i++)
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
				std::cerr << "S_" << whoami << ": WARNING - no signature creation time received from " << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	if (tvs.size() < (dss_t + 1))
	{
		std::cerr << "S_" << whoami << ": not enough timestamps received" << std::endl;
		delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	csigtime = tvs[tvs.size()/2]; // use a median value as some kind of gentle agreement
	if (opt_verbose)
		std::cout << "S_" << whoami << ": canonicalized signature creation time = " << csigtime << std::endl;

	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_byte_t hashalgo = 0;
	if (mpz_sizeinbase(dss_q, 2L) == 256)
		hashalgo = 8; // SHA256 (alg 8)
	else if (mpz_sizeinbase(dss_q, 2L) == 384)
		hashalgo = 9; // SHA384 (alg 9)
	else if (mpz_sizeinbase(dss_q, 2L) == 512)
		hashalgo = 10; // SHA512 (alg 10)
	else
	{
		std::cerr << "S_" << whoami << ": selecting hash algorithm failed for |q| = " << mpz_sizeinbase(dss_q, 2L) << std::endl;
		delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}

	// compute the hash of the input file
	tmcg_octets_t trailer, hash, left;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDetachedSignature(0x00, hashalgo, csigtime, sigexptime, keyid, trailer);
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash(opt_ifilename, trailer, hashalgo, hash, left))
	{
		std::cerr << "S_" << whoami << ": BinaryDocumentHash() failed; cannot process input file \"" << opt_ifilename << "\"" << std::endl;
		delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}

	// create an instance of tDSS by stored parameters from private key
	std::stringstream dss_in;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dsa_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dsa_y << std::endl;
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
		std::cerr << "S_" << whoami << ": " << "tDSS parameters are not correctly generated!" << std::endl;
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}

	// sign the hash
	tmcg_byte_t buffer[1024];
	gcry_mpi_t h, r, s;
	mpz_t dsa_m, dsa_r, dsa_s;
	size_t buflen = 0;
	gcry_error_t ret;
	for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
		buffer[i] = hash[i];
	h = gcry_mpi_new(2048);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
	{
		std::cerr << "S_" << whoami << ": gcry_mpi_scan() failed for h" << std::endl;
		gcry_mpi_release(h);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_set_gcry_mpi(h, dsa_m))
	{
		std::cerr << "S_" << whoami << ": mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
		gcry_mpi_release(h);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	std::stringstream err_log_sign;
	if (opt_verbose)
		std::cout << "S_" << whoami << ": dss.Sign()" << std::endl;
	if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc, err_log_sign))
	{
		std::cerr << "S_" << whoami << ": " << "tDSS Sign() failed" << std::endl;
		std::cerr << "S_" << whoami << ": log follows " << std::endl << err_log_sign.str();
		gcry_mpi_release(h);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (opt_verbose)
		std::cout << "S_" << whoami << ": log follows " << std::endl << err_log_sign.str();
	if (!mpz_get_gcry_mpi(&r, dsa_r))
	{
		std::cerr << "S_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
		gcry_mpi_release(h);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	if (!mpz_get_gcry_mpi(&s, dsa_s))
	{
		std::cerr << "S_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
		gcry_mpi_release(h);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete dss, delete rbc, delete aiou, delete aiou2;
		release_mpis();
		exit(-1);
	}
	tmcg_octets_t sig;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(trailer, left, r, s, sig);
	gcry_mpi_release(h);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);

	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_very_long;
	if (opt_verbose)
		std::cout << "S_" << whoami << ": waiting " << synctime << " seconds for stalled parties" << std::endl;
	rbc->Sync(synctime);

	// release tDSS
	delete dss;

	// release RBC
	delete rbc;
	
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
		std::cout << "S_" << whoami << ": aiou.numRead = " << aiou->numRead <<
			" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
		std::cout << "S_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
			" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;

	// release
	release_mpis();

	// output the result
	std::string sigstr;
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(2, sig, sigstr);
	if (opt_ofilename == NULL)
		std::cout << sigstr << std::endl;
	else
		write_signature(opt_ofilename, sigstr);
}

#ifdef GNUNET
char *gnunet_opt_ifilename = NULL;
char *gnunet_opt_ofilename = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_sigexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-sign (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant S_i */
			time_t sigtime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, sigtime, gnunet_opt_sigexptime, gnunet_opt_xtests);
#else
			run_instance(whoami, sigtime, 0, 0);
#endif
			if (opt_verbose)
				std::cout << "S_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant S_i */
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
	static const char *usage = "dkg-sign [OPTIONS] PEERS";
	static const char *about = "threshold signature scheme for OpenPGP (only DSA/DSS)";
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
			"expiration time of generated signature in seconds",
			&gnunet_opt_sigexptime
		),
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"create detached signature from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write detached signature to FILENAME",
			&gnunet_opt_ofilename
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
		GNUNET_GETOPT_option_version(version),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of signature protocol",
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
	if (gnunet_opt_ifilename != NULL)
		opt_ifilename = gnunet_opt_ifilename;
	if (gnunet_opt_ofilename != NULL)
		opt_ofilename = gnunet_opt_ofilename;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
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
			if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-w") == 0) || (arg.find("-L") == 0) || 
				(arg.find("-l") == 0) || (arg.find("-i") == 0) || (arg.find("-o") == 0) || (arg.find("-e") == 0) ||
				(arg.find("-x") == 0) || (arg.find("-P") == 0))
			{
				size_t idx = ++i;
				if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) && (opt_ifilename == NULL))
				{
					ifilename = argv[i+1];
					opt_ifilename = (char*)ifilename.c_str();
				}
				if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) && (opt_ofilename == NULL))
				{
					ofilename = argv[i+1];
					opt_ofilename = (char*)ofilename.c_str();
				}
				if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) && (opt_passwords == NULL))
				{
					passwords = argv[i+1];
					opt_passwords = (char*)passwords.c_str();
				}
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
					std::cout << "  -i FILENAME    create detached signature from FILENAME" << std::endl;
					std::cout << "  -o FILENAME    write detached signature to FILENAME" << std::endl;
					std::cout << "  -P STRING      exchanged passwords to protect private and broadcast channels" << std::endl;
					std::cout << "  -v, --version  print the version number" << std::endl;
					std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
				{
#ifndef GNUNET
					std::cout << "dkg-sign " << version << std::endl;
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
	if (opt_ifilename == NULL)
	{
		std::cerr << "ERROR: option -i required to specify an input file" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cout << peers[i] << std::endl;
	}

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated signature in seconds",
			&gnunet_opt_sigexptime
		),
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"create detached signature from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write detached signature to FILENAME",
			&gnunet_opt_ofilename
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
			"minutes to wait until start of signature protocol",
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
	std::cerr << "WARNING: GNUnet development files are required for message exchange of signing protocol" << std::endl;
#endif

	std::cout << "INFO: running local test with " << peers.size() << " participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("dkg-sign (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("dkg-sign (pipe)");
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
			perror("dkg-sign (waitpid)");
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-sign (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-sign (close)");
		}
	}
	
	return 0;
}

