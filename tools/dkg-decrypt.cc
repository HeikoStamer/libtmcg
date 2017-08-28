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

std::string				passphrase, armored_message, armored_seckey, ifilename, ofilename, passwords, hostname, port;
gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_q, elg_g, elg_y, elg_x;
gcry_mpi_t 				gk, myk;
gcry_sexp_t				elgkey;
tmcg_octets_t				subkeyid, enc;
bool					have_seipd = false;
GennaroJareckiKrawczykRabinDKG		*dkg;
mpz_t					dkg_p, dkg_q, dkg_g, dkg_h, dkg_x_i, dkg_xprime_i, dkg_y;
size_t					dkg_n, dkg_t, dkg_i;
std::vector<size_t>			dkg_qual;
std::vector<mpz_ptr>			dkg_v_i;
std::vector< std::vector<mpz_ptr> >	dkg_c_ik;
int 					opt_verbose = 0;
char					*opt_ifilename = NULL;
char					*opt_ofilename = NULL;
char					*opt_passwords = NULL;
char					*opt_hostname = NULL;
unsigned long int			opt_p = 35000;

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

void read_message
	(const std::string ifilename, std::string &result)
{
	// read the encrypted message from file
	std::string line;
	std::stringstream msg;
	std::ifstream ifs(ifilename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open input file" << std::endl;
		exit(-1);
	}
	while (std::getline(ifs, line))
		msg << line << std::endl;
	if (!ifs.eof())
	{
		std::cerr << "ERROR: reading until EOF failed" << std::endl;
		exit(-1);
	}
	ifs.close();
	result = msg.str();
}

void write_message
	(const std::string filename, const tmcg_octets_t &msg)
{
	// write out the decrypted message
	std::ofstream ofs(filename.c_str(), std::ofstream::out);
	if (!ofs.good())
	{
		std::cerr << "ERROR: opening output file failed" << std::endl;
		exit(-1);
	}
	for (size_t i = 0; i < msg.size(); i++)
	{
		ofs << msg[i];
		if (!ofs.good())
		{
			std::cerr << "ERROR: writing to output file failed" << std::endl;
			exit(-1);
		}
	}
	ofs.close();
}

void print_message
	(const tmcg_octets_t &msg)
{
	// print out the decrypted message
	std::cout << "Decrypted message:" << std::endl;
	for (size_t i = 0; i < msg.size(); i++)
		std::cout << msg[i];
}

void init_mpis
	()
{
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	dsa_x = gcry_mpi_new(2048);
	elg_p = gcry_mpi_new(2048);
	elg_q = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	elg_x = gcry_mpi_new(2048);
	gk = gcry_mpi_new(2048);
	myk = gcry_mpi_new(2048);
	mpz_init(dkg_p);
	mpz_init(dkg_q);
	mpz_init(dkg_g);
	mpz_init(dkg_h);
	mpz_init(dkg_x_i);
	mpz_init(dkg_xprime_i);
	mpz_init(dkg_y);
}

void init_dkg
	()
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
		std::cerr << "ERROR: DKG parameters are not correctly generated!" << std::endl;
		delete dkg;
		exit(-1);
	}
	if (!dkg->CheckKey())
	{
		std::cerr << "ERROR: DKG CheckKey() failed!" << std::endl;
		delete dkg;
		exit(-1);
	}
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
	tmcg_octets_t seskey, salt, mpis, hash_input, hash, keyid, pub_hashing, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	int algo;
	tmcg_openpgp_packet_ctx ctx;
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
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector<std::string> capl;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
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
				if (secdsa && !ssbelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
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
						std::cerr << "WARNING: insecure hash algorithm " << (int)dsa_hashalgo << " used for signatures" << std::endl;
					sigdsa = true;
				}
				else if (secdsa && ssbelg && (ctx.type == 0x18) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
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
						std::cerr << "WARNING: insecure hash algorithm " << (int)elg_hashalgo << " used for signatures" << std::endl;
					sigelg = true;
				}
				break;
			case 5: // Secret-Key Packet
				if (((ctx.pkalgo == 17) || (ctx.pkalgo == 108)) && !secdsa)
				{
					secdsa = true;
					dsa_p = ctx.p, dsa_q = ctx.q, dsa_g = ctx.g, dsa_y = ctx.y;
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, 17, // public-key is in both cases a DSA key 
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << " Key ID of DSA/tDSS key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
					if (ctx.s2kconv == 0)
					{
						if (ctx.pkalgo == 17)
							dsa_x = ctx.x; // not encrypted
						else if (ctx.pkalgo == 108)
							gcry_mpi_set_ui(dsa_x, 0L); // no single secret key available
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
						// read MPI x reps. MPIs x_i, xprime_i and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						if (ctx.pkalgo == 17)
						{
							mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
							if (!mlen || (mlen > mpis.size()))
							{
								std::cerr << "ERROR: reading MPI x failed (bad passphrase)" << std::endl;
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
						}
						else if (ctx.pkalgo == 108)
						{
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
				else if (((ctx.pkalgo == 17) || (ctx.pkalgo == 108)) && secdsa)
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
				if ((ctx.pkalgo == 109) && !ssbelg)
				{
					ssbelg = true;
					elg_p = ctx.p, elg_q = ctx.q, elg_g = ctx.g, elg_y = ctx.y;
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
					if (!mpz_set_gcry_mpi(ctx.p, dkg_p))
					{
						std::cerr << "ERROR: converting key component dkg_p failed" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.q, dkg_q))
					{
						std::cerr << "ERROR: converting key component dkg_q failed" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.g, dkg_g))
					{
						std::cerr << "ERROR: converting key component dkg_g failed" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.h, dkg_h))
					{
						std::cerr << "ERROR: converting key component dkg_h failed" << std::endl;
						exit(-1);
					}
					if (!mpz_set_gcry_mpi(ctx.y, dkg_y))
					{
						std::cerr << "ERROR: converting key component dkg_y failed" << std::endl;
						exit(-1);
					}
					dkg_n = get_gcry_mpi_ui(ctx.n);
					dkg_t = get_gcry_mpi_ui(ctx.t);
					dkg_i = get_gcry_mpi_ui(ctx.i);
					for (size_t i = 0; i < qual.size(); i++)
						dkg_qual.push_back(get_gcry_mpi_ui(qual[i]));
					for (size_t i = 0; i < v_i.size(); i++)
					{
						mpz_ptr tmp = new mpz_t();
						mpz_init(tmp);
						if (!mpz_set_gcry_mpi(v_i[i], tmp))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp (v_i)" << std::endl;
							exit(-1);
						}
						dkg_v_i.push_back(tmp);
					}
					dkg_c_ik.resize(c_ik.size());
					for (size_t i = 0; i < c_ik.size(); i++)
					{
						for (size_t k = 0; k < c_ik[i].size(); k++)
						{
							mpz_ptr tmp = new mpz_t();
							mpz_init(tmp);
							if (!mpz_set_gcry_mpi(c_ik[i][k], tmp))
							{
								std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp (c_ik)" << std::endl;
								exit(-1);
							}
							dkg_c_ik[i].push_back(tmp);
						}
					}
					if (ctx.s2kconv == 0)
					{
						elg_x = ctx.x_i; // not encrypted
						if (!mpz_set_gcry_mpi(ctx.x_i, dkg_x_i))
						{
							std::cerr << "ERROR: converting key component dkg_x_i failed" << std::endl;
							exit(-1);
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
							exit(-1);
						}
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
						key = new tmcg_byte_t[keylen], iv = new tmcg_byte_t[ivlen];
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
						// read MPI x reps. MPIs x_i, xprime_i and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, elg_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI x_i failed (bad passphrase)" << std::endl;
							exit(-1);
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							exit(-1);
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(elg_x, dkg_x_i))
						{
							std::cerr << "ERROR: converting key component dkg_x_i failed" << std::endl;
							exit(-1);
						}
						if (!mpz_set_gcry_mpi(dsa_x, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
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
				else if ((ctx.pkalgo == 109) && ssbelg)
					std::cerr << "WARNING: DKG/ElGamal subkey already found" << std::endl; 
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
		std::cerr << "ERROR: no tDSS/DSA private key found" << std::endl;
		exit(-1);
	}
	if (!ssbelg)
	{
		std::cerr << "ERROR: no DKG/ElGamal private subkey found" << std::endl;
		exit(-1);
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA key found" << std::endl;
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
		std::cerr << "ERROR: parsing DSA key material failed" << std::endl;
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
		std::cout << "DSA key flags: ";
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
		std::cerr << "ERROR: parsing ElGamal key material failed" << std::endl;
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

void parse_message
	(const std::string in)
{
	// parse encrypted message
	bool have_pkesk = false, have_sed = false;
	tmcg_octets_t pkts;
	tmcg_byte_t atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype == 1)
	{	
		tmcg_byte_t ptag = 0xFF;
		while (pkts.size() && ptag)
		{
			tmcg_octets_t pkesk_keyid;
			tmcg_openpgp_packet_ctx ctx;
			tmcg_octets_t current_packet;
			std::vector<gcry_mpi_t> qual, v_i;
			std::vector<std::string> capl;
			std::vector< std::vector<gcry_mpi_t> > c_ik;
			ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
			if (opt_verbose)
				std::cout << "PacketDecode() = " << (int)ptag;
			if (!ptag)
			{
				std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
				exit(-1); // error detected
			}
			if (opt_verbose)
				std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
			switch (ptag)
			{
				case 1: // Public-Key Encrypted Session Key
					if (opt_verbose)
						std::cout << " pkalgo = " << (int)ctx.pkalgo << std::endl;
					if (ctx.pkalgo != 16)
					{
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
						break;
					}
					if (opt_verbose)
						std::cout << " keyid = " << std::hex;
					for (size_t i = 0; i < sizeof(ctx.keyid); i++)
					{
						if (opt_verbose)
							std::cout << (int)ctx.keyid[i] << " ";
						pkesk_keyid.push_back(ctx.keyid[i]);
					}
					if (opt_verbose)
						std::cout << std::dec << std::endl;
					if (CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero(pkesk_keyid))
						std::cerr << "WARNING: PKESK wildcard keyid found" << std::endl;
					else if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(pkesk_keyid, subkeyid))
					{
						std::cerr << "WARNING: PKESK keyid does not match subkey ID" << std::endl;
						break;
					}
					if (have_pkesk)
						std::cerr << "WARNING: matching PKESK packet already found; g^k and my^k overwritten" << std::endl;
					have_pkesk = true;
					gk = ctx.gk, myk = ctx.myk;
					break;
				case 9: // Symmetrically Encrypted Data
					if (have_sed)
					{
						std::cerr << "ERROR: duplicate SED packet found" << std::endl;
						exit(-1);
					}
					have_sed = true;
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc.push_back(ctx.encdata[i]);
					break;
				case 18: // Symmetrically Encrypted Integrity Protected Data
					if (have_seipd)
					{
						std::cerr << "ERROR: duplicate SEIPD packet found" << std::endl;
						exit(-1);
					}
					have_seipd = true;
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc.push_back(ctx.encdata[i]);
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
	if (have_sed && have_seipd)
	{
		std::cerr << "ERROR: multiple types of symmetrically encrypted data found" << std::endl;
		exit(-1);
	}
	// check whether $0 < g^k < p$.
	if ((gcry_mpi_cmp_ui(gk, 0L) <= 0) || (gcry_mpi_cmp(gk, elg_p) >= 0))
	{
		std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
		exit(-1);
	}
	// check whether $0 < my^k < p$.
	if ((gcry_mpi_cmp_ui(myk, 0L) <= 0) || (gcry_mpi_cmp(myk, elg_p) >= 0))
	{
		std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
		exit(-1);
	}
	// check whether $(g^k)^q \equiv 1 \pmod{p}$.
	gcry_mpi_t tmp;
	tmp = gcry_mpi_new(2048);
	gcry_mpi_powm(tmp, gk, elg_q, elg_p);
	if (gcry_mpi_cmp_ui(tmp, 1L))
	{
		std::cerr << "ERROR: (g^k)^q \equiv 1 mod p not satisfied" << std::endl;
		exit(-1);
	}
	gcry_mpi_release(tmp);
}

void compute_decryption_share
	(std::string &result)
{
	// [CGS97] Ronald Cramer, Rosario Gennaro, and Berry Schoenmakers:
	//  'A Secure and Optimally Efficient Multi-Authority Election Scheme'
	// Advances in Cryptology - EUROCRYPT '97, LNCS 1233, pp. 103--118, 1997.

	// compute the decryption share
	mpz_t nizk_gk, r_i, R;
	mpz_init(nizk_gk), mpz_init(r_i), mpz_init(R);
	mpz_spowm(R, dkg->g, dkg->x_i, dkg->p);
	if (mpz_cmp(R, dkg->v_i[dkg->i]))
	{
		std::cerr << "ERROR: check of DKG public verification key failed" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R);
		exit(-1);
	}
	if (!mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R);
		exit(-1);
	}
	mpz_spowm(r_i, nizk_gk, dkg->x_i, dkg->p);
	// compute NIZK argument for decryption share, e.g. see [CGS97]
	// proof of knowledge (equality of discrete logarithms)
	mpz_t a, b, omega, c, r, c2;
	mpz_init(c), mpz_init(r), mpz_init(c2), mpz_init(a), mpz_init(b), mpz_init(omega);
	// commitment
	mpz_srandomm(omega, dkg->q);
	mpz_spowm(a, nizk_gk, omega, dkg->p);
	mpz_spowm(b, dkg->g, omega, dkg->p);
	// challenge
	// Here we use the well-known "Fiat-Shamir heuristic" to make
	// the PoK non-interactive, i.e. we turn it into a statistically
	// zero-knowledge (Schnorr signature scheme style) proof of
	// knowledge (SPK) in the random oracle model.
	mpz_shash(c, 6, a, b, r_i, dkg->v_i[dkg->i], nizk_gk, dkg->g);
	// response
	mpz_mul(r, c, dkg->x_i);
	mpz_neg(r, r);
	mpz_add(r, r, omega);
	mpz_mod(r, r, dkg->q);
	// construct dds
	std::ostringstream dds;
	dds << "dds|" << dkg->i << "|" << r_i << "|" << c << "|" << r << "|";
	mpz_clear(c), mpz_clear(r), mpz_clear(c2), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
	mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R);
	result = dds.str();
}

void prove_decryption_share_interactive_publiccoin
	(mpz_srcptr r_i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc, JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	mpz_t nizk_gk;
	mpz_init(nizk_gk);
	if (!mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk);
		exit(-1);
	}
	// set ID for RBC
	std::stringstream myID;
	myID << "dkg-decrypt::*_decryption_share_interactive_publiccoin" << dkg->p << dkg->q << dkg->g << dkg->h << 
		edcf->h << r_i << "|" << rbc->j << "|" << dkg->i;
	rbc->setID(myID.str());
	// proof of knowledge (equality of discrete logarithms) [CGS97]
	mpz_t a, b, omega, c, r, c2;
	mpz_init(c), mpz_init(r), mpz_init(c2), mpz_init(a), mpz_init(b), mpz_init(omega);
	// 1. commitment
	mpz_srandomm(omega, dkg->q);
	mpz_spowm(a, dkg->g, omega, dkg->p);
	mpz_spowm(b, nizk_gk, omega, dkg->p);
	rbc->Broadcast(a);
	rbc->Broadcast(b);
	// 2. challenge
	if (edcf->Flip(rbc->j, c, aiou, rbc, err))
	{
		// 3. response
		mpz_mul(r, c, dkg->x_i);
		mpz_mod(r, r, dkg->q);
		mpz_add(r, r, omega);
		mpz_mod(r, r, dkg->q);
		rbc->Broadcast(r);
	}
	// release
	mpz_clear(c), mpz_clear(r), mpz_clear(c2), mpz_clear(a), mpz_clear(b), mpz_clear(omega);
	mpz_clear(nizk_gk);
	// unset ID for RBC
	rbc->unsetID();
}

bool verify_decryption_share
	(std::string in, size_t &idx_dkg, mpz_ptr r_i_out, mpz_ptr c_out, mpz_ptr r_out)
{
	// initialize
	mpz_t c2, a, b;
	mpz_init(c2), mpz_init(a), mpz_init(b);
	mpz_t nizk_gk;
	mpz_init(nizk_gk);
	if (!mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk);
		exit(-1);
	}

	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(in, "dds", '|'))
			throw false;
		// parse index
		std::string idxstr, mpzstr;
		if (!TMCG_ParseHelper::gs(in, '|', idxstr))
			throw false;
		if ((sscanf(idxstr.c_str(), "%zu", &idx_dkg) < 1) || !TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// r_i
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(r_i_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// c
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(c_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// r
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(r_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// check index for sanity
		if (idx_dkg >= (dkg->v_i).size())
			throw false;
		// check r_i for sanity
		if (!dkg->CheckElement(r_i_out))
			throw false;
		// check the NIZK argument for sanity
		if ((mpz_cmpabs(r_out, dkg->q) >= 0) || (mpz_sizeinbase(c_out, 2L) > 256)) // check the size of r and c (NOTE: output size of mpz_shash is fixed)
			throw false;
		// verify proof of knowledge (equality of discrete logarithms), e.g. see [CGS97]
		mpz_powm(a, nizk_gk, r_out, dkg->p);
		mpz_powm(b, r_i_out, c_out, dkg->p);
		mpz_mul(a, a, b);
		mpz_mod(a, a, dkg->p);
		mpz_powm(b, dkg->g, r_out, dkg->p);
		mpz_powm(c2, dkg->v_i[idx_dkg], c_out, dkg->p);
		mpz_mul(b, b, c2);
		mpz_mod(b, b, dkg->p);
		mpz_shash(c2, 6, a, b, r_i_out, dkg->v_i[idx_dkg], nizk_gk, dkg->g);
		if (mpz_cmp(c2, c_out))
			throw false;		

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(c2), mpz_clear(a), mpz_clear(b);
		mpz_clear(nizk_gk);
		// return
		return return_value;
	}
}

bool verify_decryption_share_interactive_publiccoin
	(const size_t idx_rbc, const size_t idx_dkg, mpz_srcptr r_i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc, JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	// initialize
	mpz_t a, b, c, r, foo, bar;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r), mpz_init(foo), mpz_init(bar);
	mpz_t nizk_gk;
	mpz_init(nizk_gk);
	if (!mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk);
		exit(-1);
	}
	// set ID for RBC
	std::stringstream myID;
	myID << "dkg-decrypt::*_decryption_share_interactive_publiccoin" << dkg->p << dkg->q << dkg->g << dkg->h <<
		edcf->h << r_i << "|" << idx_rbc << "|" << idx_dkg;
	rbc->setID(myID.str());

	try
	{
		// check index for sanity
		if (idx_dkg >= (dkg->v_i).size())
		{
			err << "verify PoK: bad idx_dkg for D_" << idx_rbc << std::endl;
			throw false;
		}
		// check r_i for sanity
		if (!dkg->CheckElement(r_i))
		{
			err << "verify PoK: r_i not in G for D_" << idx_rbc << std::endl;
			throw false;
		}
		// verify proof of knowledge (equality of discrete logarithms) [CGS97]
		// 1. receive and check the commitment, i.e., $a, b \in G$
		if (!rbc->DeliverFrom(a, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(a, idx_rbc) failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		if (!rbc->DeliverFrom(b, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(b, idx_rbc) failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		if (!dkg->CheckElement(a) || !dkg->CheckElement(b))
		{
			err << "verify PoK: check commitment failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		// 2. challenge: $c\in\mathbb{Z}_q$ is computed by a distributed coin-flip protocol [JL00]
		if (!edcf->Flip(rbc->j, c, aiou, rbc, err))
			throw false;
		// 3. receive, check and verify the response
		if (!rbc->DeliverFrom(r, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(r, idx_rbc) failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		if (mpz_cmpabs(r, dkg->q) >= 0)
		{
			err << "verify PoK: check response failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		// verify PoK equations [CGS97]
		mpz_powm(foo, dkg->g, r, dkg->p);
		mpz_powm(bar, dkg->v_i[idx_dkg], c, dkg->p);
		mpz_mul(bar, bar, a);
		mpz_mod(bar, bar, dkg->p);
		if (mpz_cmp(foo, bar))
		{
			err << "verify PoK: verify first equation failed for D_" << idx_rbc << std::endl;
			throw false;
		}
		mpz_powm(foo, nizk_gk, r, dkg->p);
		mpz_powm(bar, r_i, c, dkg->p);
		mpz_mul(bar, bar, b);
		mpz_mod(bar, bar, dkg->p);
		if (mpz_cmp(foo, bar))
		{
			err << "verify PoK: verify second equation failed for D_" << idx_rbc << std::endl;
			throw false;
		}
	
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(r), mpz_clear(foo), mpz_clear(bar);
		mpz_clear(nizk_gk);
		// return
		return return_value;
	}
}

bool combine_decryption_shares
	(std::vector<size_t> &parties, std::vector<mpz_ptr> &shares)
{
	// initialize
	mpz_t a, b, c, lambda, R;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(lambda), mpz_init_set_ui(R, 1L);

	try
	{
		std::vector<size_t> parties_sorted = parties;
		std::sort(parties_sorted.begin(), parties_sorted.end());
		std::vector<size_t>::iterator ut = std::unique(parties_sorted.begin(), parties_sorted.end());
		parties_sorted.resize(std::distance(parties_sorted.begin(), ut));
		if ((parties.size() <= dkg->t) || (shares.size() <= dkg->t) || (parties.size() != shares.size()) || (parties_sorted.size() <= dkg->t))
		{
			std::cerr << "ERROR: not enough decryption shares collected" << std::endl;
			throw false;
		}
		if (parties.size() > (dkg->t + 1))
			parties.resize(dkg->t + 1); // we need exactly $t + 1$ decryption shares
		if (opt_verbose)
		{
			std::cout << "combine_decryption_shares(): Lagrange interpolation with ";
			for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt)
				std::cout << "P_" << *jt << " ";
			std::cout << std::endl;
		}

		// compute $R = \prod_{i\in\Lambda} r_i^\lambda_{i,\Lambda} \bmod p$ where $\lambda_{i, \Lambda} = \prod_{l\in\Lambda\setminus\{i\}\frac{l}{l-i}}$
		size_t j = 0;
		for (std::vector<size_t>::iterator jt = parties.begin(); jt != parties.end(); ++jt, ++j)
		{
			mpz_set_ui(a, 1L); // compute optimized Lagrange coefficients
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(a, a, (*lt + 1)); // adjust index in computation
			}
			mpz_set_ui(b, 1L);
			for (std::vector<size_t>::iterator lt = parties.begin(); lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(c, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(c, c, (*jt + 1)); // adjust index in computation
					mpz_mul(b, b, c);
				}
			}
			if (!mpz_invert(b, b, dkg->q))
			{
				std::cerr << "ERROR: cannot invert during interpolation" << std::endl;
				throw false;
			}
			mpz_mul(lambda, a, b);
			mpz_mod(lambda, lambda, dkg->q); // computation of Lagrange coefficients finished
			// interpolate and accumulate correct decryption shares
			mpz_powm(a, shares[j], lambda, dkg->p);
			mpz_mul(R, R, a);
			mpz_mod(R, R, dkg->p);
		}

		// copy the result from R to gk
		gcry_mpi_release(gk);
		if (!mpz_get_gcry_mpi(&gk, R))
		{
			std::cerr << "ERROR: converting interpolated result failed" << std::endl;
			exit(-1);
		}

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(lambda), mpz_clear(R);
		// return
		return return_value;
	}
}

void decrypt_session_key
	(tmcg_octets_t &out)
{
	// decrypt the session key
	gcry_error_t ret;
	size_t erroff;
	if (elgkey != NULL)
		gcry_sexp_release(elgkey); // release already obtained private key
	gcry_mpi_set_ui(elg_x, 1); // cheat libgcrypt (decryption key shares have been already applied to gk)
	ret = gcry_sexp_build(&elgkey, &erroff, "(private-key (elg (p %M) (g %M) (y %M) (x %M)))", elg_p, elg_g, elg_y, elg_x);
	if (ret)
	{
		std::cerr << "ERROR: processing ElGamal key material failed" << std::endl;
		exit(-1);
	}
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptElgamal(gk, myk, elgkey, out);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricDecryptElgamal() failed with rc = " << gcry_err_code(ret) << std::endl;
		exit(-1);
	}
}

void decrypt_message
	(const tmcg_octets_t &in, tmcg_octets_t &key, tmcg_octets_t &out)
{
	// decrypt the given message
	tmcg_byte_t symalgo = 0;
	gcry_error_t ret;
	tmcg_octets_t prefix, litmdc;
	if (opt_verbose)
		std::cout << "symmetric decryption of message ..." << std::endl;
	if (key.size() > 0)
	{
		symalgo = key[0];
		if (opt_verbose)
			std::cout << "symalgo = " << (int)symalgo << std::endl;
	}
	else
	{
		std::cerr << "ERROR: no session key provided" << std::endl;
		exit(-1);
	}
	if (have_seipd)
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt(in, key, prefix, false, symalgo, litmdc);
	else
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt(in, key, prefix, true, symalgo, litmdc);
	if (ret)
	{
		std::cerr << "ERROR: SymmetricDecrypt() failed" << std::endl;
		exit(-1);
	}
	// parse content
	tmcg_openpgp_packet_ctx ctx;
	std::vector<gcry_mpi_t> qual, v_i;
	std::vector<std::string> capl;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	bool have_lit = false, have_mdc = false;
	tmcg_octets_t lit, mdc_hash;
	tmcg_byte_t ptag = 0xFF;
	if (litmdc.size() > (sizeof(ctx.mdc_hash) + 2))
		lit.insert(lit.end(), litmdc.begin(), litmdc.end() - (sizeof(ctx.mdc_hash) + 2));
	while (litmdc.size() && ptag)
	{
		tmcg_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(litmdc, ctx, current_packet, qual, capl, v_i, c_ik);
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag;
		if (!ptag)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
			exit(-1); // error detected
		}
		if (opt_verbose)
			std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		switch (ptag)
		{
			case 8: // Compressed Data
				std::cerr << "WARNING: compressed OpenPGP packet found; not supported" << std::endl;
				break;
			case 11: // Literal Data
				have_lit = true;
				for (size_t i = 0; i < ctx.datalen; i++)
					out.push_back(ctx.data[i]);
				break;
			case 19: // Modification Detection Code
				have_mdc = true;
				for (size_t i = 0; i < sizeof(ctx.mdc_hash); i++)
					mdc_hash.push_back(ctx.mdc_hash[i]);
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
	if (!have_lit)
	{
		std::cerr << "ERROR: no literal data found" << std::endl;
		exit(-1);
	}
	if (have_seipd && !have_mdc)
	{
		std::cerr << "ERROR: no modification detection code found" << std::endl;
		exit(-1);
	}
	tmcg_octets_t mdc_hashing, hash;
	if (have_mdc)
	{
		mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end()); // "it includes the prefix data described above" [RFC4880]
		mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end()); // "it includes all of the plaintext" [RFC4880]
		mdc_hashing.push_back(0xD3); // "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
		mdc_hashing.push_back(0x14);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(mdc_hash, hash))
		{
			std::cerr << "ERROR: MDC hash does not match" << std::endl;
			exit(-1);
		}
	}
}

void release_mpis
	()
{
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(dsa_x);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_q);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(elg_x);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	mpz_clear(dkg_p);
	mpz_clear(dkg_q);
	mpz_clear(dkg_g);
	mpz_clear(dkg_h);
	mpz_clear(dkg_x_i);
	mpz_clear(dkg_xprime_i);
	mpz_clear(dkg_y);
}

void release_keys
	()
{
	gcry_sexp_release(elgkey);
}

void done_dkg
	()
{
	// release DKG
	delete dkg;
}

void run_instance
	(size_t whoami, const size_t num_xtests)
{
	std::string thispeer = peers[whoami];
	read_private_key(thispeer + "_dkg-sec.asc", armored_seckey);
	init_mpis();
	if (!parse_private_key(armored_seckey))
	{
		subkeyid.clear(), enc.clear();
		dkg_qual.clear(), dkg_v_i.clear(), dkg_c_ik.clear();
		// protected with password
		std::cout << "Please enter the passphrase to unlock your private key: ";
		std::getline(std::cin, passphrase);
		std::cin.clear();
		if (!parse_private_key(armored_seckey))
		{
			std::cerr << "ERROR: cannot read encrypted content of private key";
			exit(-1);
		}
	}
	init_dkg();
	parse_message(armored_message);

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
				std::cerr << "D_" << whoami << ": " << "cannot read password for protecting channel to D_" << i << std::endl;
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) && !TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "D_" << whoami << ": " << "cannot skip to next password for protecting channel to D_" << (i + 1) << std::endl;
				exit(-1);
			}
		}
		else
			key << "dkg-decrypt::D_" << (i + whoami); // use simple key -- we assume that GNUnet provides secure channels
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
	std::string myID = "dkg-decrypt|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	myID += dkg->t; // include parameterized t-resiliance of DKG in the ID of broadcast protocol
	size_t T_RBC = (peers.size() - 1) / 3; // assume maximum asynchronous t-resilience for RBC
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami, aiou2);
	rbc->setID(myID);

	// perform a simple exchange test with debug output
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t xtest;
		mpz_init_set_ui(xtest, i);
		std::cout << "D_" << whoami << ": xtest = " << xtest << " <-> ";
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

	// initialize for interactive part
	mpz_t crs_p, crs_q, crs_g, crs_k;
	mpz_init(crs_p), mpz_init(crs_q), mpz_init(crs_g), mpz_init(crs_k);
	if (!mpz_set_gcry_mpi(dsa_p, crs_p))
	{
		std::cerr << "ERROR: converting group parameters failed" << std::endl;
		exit(-1);
	}
	if (!mpz_set_gcry_mpi(dsa_q, crs_q))
	{
		std::cerr << "ERROR: converting group parameters failed" << std::endl;
		exit(-1);
	}
	if (!mpz_set_gcry_mpi(dsa_g, crs_g))
	{
		std::cerr << "ERROR: converting group parameters failed" << std::endl;
		exit(-1);
	}
	mpz_sub_ui(crs_k, crs_p, 1L);
	if (!mpz_cmp_ui(crs_q, 0L))
	{
		std::cerr << "ERROR: q must not be zero" << std::endl;
		exit(-1);
	}
	mpz_div(crs_k, crs_k, crs_q);

	// create VTMF instance from original CRS (common reference string)
	std::stringstream crss;
	crss << crs_p << std::endl << crs_q << std::endl << crs_g << std::endl << crs_k << std::endl;
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true); // with verifiable generation of $g$
	if (!vtmf->CheckGroup())
	{
		std::cout << "D_" << whoami << ": " << "VTMF: Group G was not correctly generated!" << std::endl;
		exit(-1);
	}

	// create and exchange keys in order to bootstrap the $h$-generation for EDCF [JL00]
	// TODO: replace N-time NIZK by one interactive (distributed) zero-knowledge proof of knowledge
	if (opt_verbose)
		std::cout << "INFO: generate h by using VTMF key generation protocol" << std::endl;
	mpz_t nizk_c, nizk_r, h_j;
	mpz_init(nizk_c), mpz_init(nizk_r), mpz_init(h_j);
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_ComputeNIZK(nizk_c, nizk_r);
	rbc->Broadcast(vtmf->h_i);
	rbc->Broadcast(nizk_c);
	rbc->Broadcast(nizk_r);
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i != whoami)
		{
			if (!rbc->DeliverFrom(h_j, i))
			{
				std::cerr << "D_" << whoami << ": WARNING - no VTMF key received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_c, i))
			{
				std::cerr << "D_" << whoami << ": WARNING - no NIZK c received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_r, i))
			{
				std::cerr << "D_" << whoami << ": WARNING - no NIZK r received from " << i << std::endl;
			}
			std::stringstream lej;
			lej << h_j << std::endl << nizk_c << std::endl << nizk_r << std::endl;
			if (!vtmf->KeyGenerationProtocol_UpdateKey(lej))
			{
				std::cerr << "D_" << whoami << ": WARNING - VTMF public key of D_" << i <<
					" was not correctly generated!" << std::endl;
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();
	mpz_clear(nizk_c), mpz_clear(nizk_r), mpz_clear(h_j);

	// create an instance of the distributed coin-flip protocol (EDCF)
	size_t T_EDCF = (peers.size() - 1) / 2; // assume maximum synchronous t-resilience for EDCF
	if (opt_verbose)
		std::cout << "JareckiLysyanskayaEDCF(" << peers.size() << ", " << T_EDCF << ", ...)" << std::endl;
	JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(peers.size(), T_EDCF, vtmf->p, vtmf->q, vtmf->g, vtmf->h);

	// initialize
	mpz_t idx, r_i, c, r;
	mpz_init(idx), mpz_init(r_i), mpz_init(c), mpz_init(r);
	std::vector<size_t> interpol_parties;
	std::vector<mpz_ptr> interpol_shares;

	// compute own decryption share and store it
	std::string dds;
	size_t idx_tmp;
	compute_decryption_share(dds);
	if (verify_decryption_share(dds, idx_tmp, r_i, c, r))
	{
		assert((idx_tmp == dkg->i));
		// use this decryption share as first point for Lagrange interpolation
		mpz_ptr tmp1 = new mpz_t();
		mpz_init_set(tmp1, r_i);
		interpol_parties.push_back(dkg->i), interpol_shares.push_back(tmp1);
	}
	else
		std::cerr << "WARNING: verification of own decryption share failed for D_" << whoami << std::endl;

	// collect other decryption shares
	if (opt_verbose)
		std::cout << "INFO: start collecting other decryption shares" << std::endl;
	std::vector<size_t> complaints;
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i != whoami)
		{
			mpz_set_ui(idx, dkg->n), mpz_set_ui(r_i, 1L);
			// receive index
			if (!rbc->DeliverFrom(idx, i))
			{
				std::cerr << "WARNING: DeliverFrom(idx, i) failed for D_" << i << std::endl;
				complaints.push_back(i);
			}
			// receive a decryption share
			if (!rbc->DeliverFrom(r_i, i))
			{
				std::cerr << "WARNING: DeliverFrom(r_i, i) failed for D_" << i << std::endl;
				complaints.push_back(i);
			}
			// verify decryption share interactively
			std::stringstream err_log;
			size_t idx_dkg = mpz_get_ui(idx);
			if (!verify_decryption_share_interactive_publiccoin(i, idx_dkg, r_i, aiou, rbc, edcf, err_log))
			{
				std::cerr << "WARNING: bad decryption share of P_" << idx_dkg << " received from D_" << i << std::endl;
				if (opt_verbose)
					std::cerr << err_log.str() << std::endl;
				complaints.push_back(i);
			}
			if (std::find(complaints.begin(), complaints.end(), i) == complaints.end())
			{
				if (opt_verbose)
					std::cout << "D_" << whoami << ": good decryption share of P_" << idx_dkg << " received from D_" <<
						i << std::endl;
				// collect only verified decryption shares
				mpz_ptr tmp1 = new mpz_t();
				mpz_init_set(tmp1, r_i);
				interpol_parties.push_back(idx_dkg), interpol_shares.push_back(tmp1);
			}
		}
		else
		{
			if (verify_decryption_share(dds, idx_tmp, r_i, c, r))
				mpz_set_ui(idx, idx_tmp);
			else
				mpz_set_ui(idx, dkg->n); // indicates an error
			// broadcast own index and decryption share
			rbc->Broadcast(idx);
			rbc->Broadcast(r_i);
			// prove own decryption share interactively
			std::stringstream err_log;
			prove_decryption_share_interactive_publiccoin(r_i, aiou, rbc, edcf, err_log);
			if (opt_verbose)
				std::cout << "prove_decryption_share_interactive_publiccoin() finished; log follows" << std::endl << err_log.str() << std::endl;
		}
	}

	// Lagrange interpolation
	bool res = combine_decryption_shares(interpol_parties, interpol_shares);

	// release
	mpz_clear(idx), mpz_clear(r_i), mpz_clear(c), mpz_clear(r);
	mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g), mpz_clear(crs_k);
	for (size_t i = 0; i < interpol_shares.size(); i++)
	{
		mpz_clear(interpol_shares[i]);
		delete [] interpol_shares[i];
	}
	interpol_shares.clear(), interpol_parties.clear();

	// at the end: deliver some more rounds for waiting parties
	time_t synctime = aiounicast::aio_timeout_long;
	if (opt_verbose)
		std::cout << "D_" << whoami << ": waiting " << synctime << " seconds for stalled parties" << std::endl;
	rbc->Sync(synctime);

	// release EDCF
	delete edcf;

	// release VTMF
	delete vtmf;

	// release RBC
	delete rbc;
	
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
		std::cout << "D_" << whoami << ": aiou.numRead = " << aiou->numRead <<
			" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
		std::cout << "D_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
			" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;

	// do remaining decryption work
	tmcg_octets_t msg, seskey;
	if (res)
	{
		decrypt_session_key(seskey);
		decrypt_message(enc, seskey, msg);
		// output result
		if (opt_ofilename != NULL)
			write_message(opt_ofilename, msg);
		else
			print_message(msg);
	}

	// release
	release_mpis();
	release_keys();
	done_dkg();
}

#ifdef GNUNET
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_ifilename = NULL;
char *gnunet_opt_ofilename = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
int gnunet_opt_nonint = 0;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-decrypt (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant D_i */
#ifdef GNUNET
			run_instance(whoami, gnunet_opt_xtests);
#else
			run_instance(whoami, 0);
#endif
			if (opt_verbose)
				std::cout << "D_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant D_i */
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
	static const char *usage = "dkg-decrypt [OPTIONS] PEERS";
	static const char *about = "threshold decryption for OpenPGP (only ElGamal)";
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
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"read encrypted message from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
		GNUNET_GETOPT_option_flag('n',
			"non-interactive",
			"run in non-interactive mode",
			&gnunet_opt_nonint
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write decrypted message to FILENAME",
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
			"minutes to wait until start of decryption",
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
	if (gnunet_opt_hostname != NULL)
		opt_hostname = gnunet_opt_hostname;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
#endif

	bool nonint = false;
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
			if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-w") == 0) || (arg.find("-L") == 0) || (arg.find("-l") == 0) ||
				(arg.find("-i") == 0) || (arg.find("-o") == 0) || (arg.find("-x") == 0) || (arg.find("-P") == 0) || (arg.find("-H") == 0))
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
			else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-n") == 0) || (arg.find("-V") == 0))
			{
				if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
				{
#ifndef GNUNET
					std::cout << usage << std::endl;
					std::cout << about << std::endl;
					std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
					std::cout << "  -h, --help             print this help" << std::endl;
					std::cout << "  -H STRING              hostname (e.g. onion address) of this peer within PEERS" << std::endl;
					std::cout << "  -i FILENAME            read encrypted message from FILENAME" << std::endl;
					std::cout << "  -n, --non-interactive  run in non-interactive mode" << std::endl;
					std::cout << "  -o FILENAME            write decrypted message to FILENAME" << std::endl;
					std::cout << "  -p INTEGER             start port for built-in TCP/IP message exchange service" << std::endl;
					std::cout << "  -P STRING              exchanged passwords to protect private and broadcast channels" << std::endl;
					std::cout << "  -v, --version          print the version number" << std::endl;
					std::cout << "  -V, --verbose          turn on verbose output" << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
				{
#ifndef GNUNET
					std::cout << "dkg-decrypt " << version << std::endl;
#endif
					return 0; // not continue
				}
				if ((arg.find("-n") == 0) || (arg.find("--non-interactive") == 0))
					nonint = true; // non-interactive mode
				if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
					opt_verbose = 1; // verbose output
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
	if (!nonint && ((peers.size() < 3)  || (peers.size() > MAX_N)))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	else if (nonint && (peers.size() != 1))
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
	if (opt_ifilename != NULL)
		read_message(opt_ifilename, armored_message);
	else
	{
		std::cout << "Please enter the encrypted message (in ASCII Armor; ^D for EOF): " << std::endl;
		std::string line;
		while (std::getline(std::cin, line))
			armored_message += line + "\r\n";
		std::cin.clear();
	}
	if (opt_verbose)
	{
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cout << peers[i] << std::endl;
	}
	if (nonint)
	{
		size_t idx;
		tmcg_octets_t msg, seskey;
		std::string dds, thispeer = peers[0];
		mpz_t r_i, c, r;
		std::vector<size_t> interpol_parties;
		std::vector<mpz_ptr> interpol_shares;

		read_private_key(thispeer + "_dkg-sec.asc", armored_seckey);
		init_mpis();
		if (!parse_private_key(armored_seckey))
		{
			subkeyid.clear(), enc.clear();
			dkg_qual.clear(), dkg_v_i.clear(), dkg_c_ik.clear();
			// protected with password
			std::cout << "Please enter the passphrase to unlock your private key: ";
			std::getline(std::cin, passphrase);
			std::cin.clear();
			if (!parse_private_key(armored_seckey))
				exit(-1);
		}
		init_dkg();
		parse_message(armored_message);
		compute_decryption_share(dds);
		tmcg_octets_t dds_input;
		dds_input.push_back((tmcg_byte_t)(mpz_wrandom_ui() % 256)); // bluring the decryption share
		dds_input.push_back((tmcg_byte_t)(mpz_wrandom_ui() % 256)); // make NSA's spying a bit harder
		dds_input.push_back((tmcg_byte_t)(mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_byte_t)(mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_byte_t)(mpz_wrandom_ui() % 256));
		for (size_t i = 0; i < dds.length(); i++)
			dds_input.push_back(dds[i]);
		std::string dds_radix;
		CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode(dds_input, dds_radix, false);
		std::cout << "My decryption share (keep confidential): " << dds_radix << std::endl;
		mpz_init(r_i), mpz_init(c), mpz_init(r);
		if (!verify_decryption_share(dds, idx, r_i, c, r))
		{
			std::cerr << "ERROR: verification of my decryption share failed" << std::endl;
			exit(-1);
		}
		mpz_ptr tmp1 = new mpz_t();
		mpz_init_set(tmp1, r_i);
		interpol_parties.push_back(dkg->i), interpol_shares.push_back(tmp1);
		std::cout << "Enter decryption shares (one per line; ^D for EOF) from other parties/devices:" << std::endl;
		while (std::getline(std::cin, dds_radix))
		{
			tmcg_octets_t dds_output;
			dds = "", idx = 0;
			CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Decode(dds_radix, dds_output);
			for (size_t i = 5; i < dds_output.size(); i++)
				dds += dds_output[i];
			mpz_set_ui(r_i, 1L), mpz_set_ui(c, 1L), mpz_set_ui(r, 1L);
			if (verify_decryption_share(dds, idx, r_i, c, r))
			{
				if (!std::count(interpol_parties.begin(), interpol_parties.end(), idx))
				{
					mpz_ptr tmp1 = new mpz_t();
					mpz_init_set(tmp1, r_i);
					interpol_parties.push_back(idx), interpol_shares.push_back(tmp1);
				}
				else
					std::cout << "WARNING: decryption share of P_" << idx << " already stored" << std::endl;
			}
			else
				std::cout << "WARNING: verification of decryption share from P_" << idx << " failed" << std::endl;
		}
		bool res = combine_decryption_shares(interpol_parties, interpol_shares);
		mpz_clear(r_i), mpz_clear(c), mpz_clear(r);
		for (size_t i = 0; i < interpol_shares.size(); i++)
		{
			mpz_clear(interpol_shares[i]);
			delete [] interpol_shares[i];
		}
		interpol_shares.clear(), interpol_parties.clear();
		if (res)
		{
			decrypt_session_key(seskey);
			decrypt_message(enc, seskey, msg);
		}
		release_mpis();
		release_keys();
		done_dkg();
		if (res)
		{
			if (opt_ofilename != NULL)
				write_message(opt_ofilename, msg);
			else
				print_message(msg);
			return 0;
		}
		else
			return 1;
	}
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

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"read encrypted message from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_flag('n',
			"non-interactive",
			"run in non-interactive mode",
			&gnunet_opt_nonint
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write decrypted message to FILENAME",
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
			"minutes to wait until start of decryption",
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
	std::cerr << "WARNING: GNUnet development files are required for message exchange of decryption protocol" << std::endl;
#endif

	std::cout << "INFO: running local test with " << peers.size() << " participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("dkg-decrypt (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("dkg-decrypt (pipe)");
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
			perror("dkg-decrypt (waitpid)");
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-decrypt (close)");
		}
	}
	
	return 0;
}

