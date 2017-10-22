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
#include "dkg-common.hh"

extern std::vector<std::string>			peers;
extern int					opt_verbose;
extern std::string				passphrase, userid;
extern tmcg_octets_t				keyid, pub, sub, uidsig, subsig;
extern std::map<size_t, size_t>			idx2dkg, dkg2idx;
extern mpz_t					dss_p, dss_q, dss_g, dss_h, dss_x_i, dss_xprime_i;
extern size_t					dss_n, dss_t, dss_i;
extern std::vector<size_t>			dss_qual;
extern std::vector< std::vector<mpz_ptr> >	dss_c_ik;
extern mpz_t					dkg_p, dkg_q, dkg_g, dkg_h, dkg_x_i, dkg_xprime_i, dkg_y;
extern size_t					dkg_n, dkg_t, dkg_i;
extern std::vector<size_t>			dkg_qual;
extern std::vector<mpz_ptr>			dkg_v_i;
extern std::vector< std::vector<mpz_ptr> >	dkg_c_ik;
extern gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_q, elg_g, elg_y, elg_x;
extern gcry_mpi_t 				gk, myk;

bool read_private_key
	(const std::string filename, std::string &result)
{
	// read the private key from file
	std::string line;
	std::stringstream seckey;
	std::ifstream secifs(filename.c_str(), std::ifstream::in);
	if (!secifs.is_open())
	{
		std::cerr << "ERROR: cannot open private key file" << std::endl;
		return false;
	}
	while (std::getline(secifs, line))
		seckey << line << std::endl;
	if (!secifs.eof())
	{
		secifs.close();
		std::cerr << "ERROR: reading private key file until EOF failed" << std::endl;
		return false;
	}
	secifs.close();
	result = seckey.str();
	return true;
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
	mpz_init(dkg_p);
	mpz_init(dkg_q);
	mpz_init(dkg_g);
	mpz_init(dkg_h);
	mpz_init(dkg_x_i);
	mpz_init(dkg_xprime_i);
	mpz_init(dkg_y);
	elg_p = gcry_mpi_new(2048);
	elg_q = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	elg_x = gcry_mpi_new(2048);
	gk = gcry_mpi_new(2048);
	myk = gcry_mpi_new(2048);
}

bool parse_private_key
	(const std::string in, std::vector<std::string> &capl_out)
{
	// parse the private key according to OpenPGP
	bool secdsa = false, sigdsa = false, ssbelg = false, sigelg = false;
	tmcg_byte_t atype = 0, ptag = 0xFF;
	tmcg_byte_t dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	tmcg_byte_t dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	tmcg_byte_t *key, *iv;
	tmcg_octets_t pkts;
	tmcg_octets_t seskey, salt, mpis, hash_input, hash, subkeyid, pub_hashing, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	int algo;
	tmcg_openpgp_packet_ctx ctx;
	std::vector<gcry_mpi_t> qual, v_i;
	std::vector<std::string> capl;
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
		std::cerr << "ERROR: wrong type of ASCII Armor found" << std::endl;
		exit(-1);
	}
	while (pkts.size() && ptag)
	{
		tmcg_octets_t current_packet;
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
					for (size_t i = 0; i < current_packet.size(); i++)
						uidsig.push_back(current_packet[i]);
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
					for (size_t i = 0; i < current_packet.size(); i++)
						subsig.push_back(current_packet[i]);
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
					// create one-to-one mapping based on the stored canonicalized peer list
					idx2dkg.clear(), dkg2idx.clear();
					for (size_t i = 0; i < peers.size(); i++)
					{
						bool found = false;
						for (size_t j = 0; j < capl.size(); j++)
						{
							if (peers[i] == capl[j])
							{
								found = true;
								if (capl.size() == dss_qual.size())
								{
									idx2dkg[i] = dss_qual[j];
									dkg2idx[dss_qual[j]] = i;
								}
								else
								{
									std::cerr << "ERROR: QUAL size of tDSS key and CAPL does not match" << std::endl;
									exit(-1);
								}
								break;
							}
						}
						if (!found)
						{
							std::cerr << "ERROR: peer \"" << peers[i] << "\" not found inside set QUAL of tDSS key" << std::endl;
							exit(-1);
						}
					}
					// copy CAPL information
					capl_out.clear();
					for (size_t j = 0; j < capl.size(); j++)
						capl_out.push_back(capl[j]);
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
				userid = "";
				for (size_t i = 0; i < sizeof(ctx.uid); i++)
					if (ctx.uid[i])
						userid += ctx.uid[i];
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
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for tDSS key found" << std::endl;
		exit(-1);
	}
	if (ssbelg && !sigelg)
	{
		std::cerr << "ERROR: no self-signature for ElGamal subkey found" << std::endl;
		exit(-1);
	}

	// build keys, check key usage and self-signatures
	gcry_sexp_t dsakey;
	tmcg_octets_t dsa_trailer, elg_trailer, dsa_left, elg_left;
	if (opt_verbose)
		std::cout << "Primary User ID: " << userid << std::endl;
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
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, userid, dsa_trailer, dsa_hashalgo, hash, dsa_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, dsa_r, dsa_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of tDSS key self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		exit(-1);
	}
	if (ssbelg)
	{
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


	mpz_clear(dkg_p);
	mpz_clear(dkg_q);
	mpz_clear(dkg_g);
	mpz_clear(dkg_h);
	mpz_clear(dkg_x_i);
	mpz_clear(dkg_xprime_i);
	mpz_clear(dkg_y);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_q);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(elg_x);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
}

