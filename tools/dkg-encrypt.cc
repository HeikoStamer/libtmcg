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

#include <fstream>
#include <vector>
#include <algorithm>

int main
	(int argc, char **argv)
{
	if (argc < 2)
	{
		std::cerr << "ERROR: no KEYFILE given as argument; usage: " << argv[0] << " KEYFILE" << std::endl;
		return -1;
	}
	else if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}

	// read a public key from file
	std::string line, armored_pubkey, message, armored_message;
	std::ifstream pubifs(argv[1], std::ifstream::in);
	if (!pubifs.is_open())
	{
		std::cerr << "ERROR: cannot open KEYFILE" << std::endl;
		exit(-1);
	}
	while (std::getline(pubifs, line))
		armored_pubkey += line + "\n";
	if (!pubifs.eof())
	{
		std::cerr << "ERROR: reading until EOF failed" << std::endl;
		exit(-1);
	}
	pubifs.close();

	// parse packets of the provided public key
	bool pubdsa = false, sigdsa = false, subelg = false, sigelg = false;
	std::string u;
	tmcg_byte_t atype = 0;
	tmcg_byte_t dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	tmcg_byte_t dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	tmcg_octets_t pkts, pub, sub, msg, lit, mdc, seipd, pkesk, all;
	tmcg_octets_t seskey, prefix, enc, mdc_hashing, hash, keyid, pub_hashing, subkeyid, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_mpi_t dsa_p, dsa_q, dsa_g, dsa_y, dsa_r, dsa_s, elg_p, elg_g, elg_y, elg_r, elg_s, gk, myk;
	gcry_sexp_t dsakey, elgkey;
	gcry_error_t ret;
	size_t erroff;
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	dsa_r = gcry_mpi_new(2048);
	dsa_s = gcry_mpi_new(2048);
	elg_p = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	elg_r = gcry_mpi_new(2048);
	elg_s = gcry_mpi_new(2048);
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armored_pubkey, pkts);
	if (atype == 6)
	{
		tmcg_byte_t ptag = 0xFF;
		while (pkts.size() && ptag)
		{
			tmcg_openpgp_packet_ctx ctx;
			ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx);
			if (!ptag)
			{
				std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
				return -2; // parsing error detected
			}
			switch (ptag)
			{
				case 2: // Signature Packet
					issuer.clear();
					for (size_t i = 0; i < sizeof(ctx.issuer); i++)
						issuer.push_back(ctx.issuer[i]);
					if (pubdsa && !subelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
						CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
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
							return -1;
						}
						if ((dsa_hashalgo < 8) || (dsa_hashalgo >= 11))
							std::cerr << "WARNING: insecure hash algorithm " << (int)dsa_hashalgo << " used for signatures" << std::endl;
						sigdsa = true;
					}
					else if (pubdsa && subelg && (ctx.type == 0x18) && 
						CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
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
							return -1;
						}
						if ((elg_hashalgo < 8) || (elg_hashalgo >= 11))
							std::cerr << "WARNING: insecure hash algorithm " << (int)elg_hashalgo << " used for signatures" << std::endl;
						sigelg = true;
					}
					else if (pubdsa && !subelg && (ctx.type == 0x20) && // Key revocation signature 
						CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
						std::cerr << "WARNING: key revocation signature on primary key" << std::endl;
					}
					else if (pubdsa && subelg && (ctx.type == 0x28) && // Subkey revocation signature 
						CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
					{
						std::cerr << "WARNING: subkey revocation signature on subkey" << std::endl;
					}
					break;
				case 6: // Public-Key Packet
					if ((ctx.pkalgo == 17) && !pubdsa)
					{
						pubdsa = true;
						dsa_p = ctx.p, dsa_q = ctx.q, dsa_g = ctx.g, dsa_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime,
							dsa_p, dsa_q, dsa_g, dsa_y, pub);
						for (size_t i = 6; i < pub.size(); i++)
							pub_hashing.push_back(pub[i]);
						CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					}
					else if ((ctx.pkalgo == 17) && pubdsa)
					{
						std::cerr << "ERROR: more than one primary key not supported" << std::endl;
						return -1;
					}
					else
						std::cerr << "WARNING: public-key algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
					break;
				case 13: // User ID Packet
					u = "";
					for (size_t i = 0; i < sizeof(ctx.uid); i++)
						if (ctx.uid[i])
							u += ctx.uid[i];
						else
							break;
					break;
				case 14: // Public-Subkey Packet
					if ((ctx.pkalgo == 16) && !subelg)
					{
						subelg = true;
						elg_p = ctx.p, elg_g = ctx.g, elg_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime,
							elg_p, elg_g, elg_y, sub);
						for (size_t i = 6; i < sub.size(); i++)
							sub_hashing.push_back(sub[i]);
						CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
					}
					else if ((ctx.pkalgo == 16) && subelg)
						std::cerr << "WARNING: ElGamal subkey already found; the first one is used" << std::endl; 
					else
						std::cerr << "WARNING: public-key algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
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
		std::cerr << "ERROR: wrong ASCII armor found (type = " << (int)atype << ")" << std::endl;
		return -1;
	}
	if (!pubdsa)
	{
		std::cerr << "ERROR: no DSA key found" << std::endl;
		return -1;
	}
	if (!subelg)
	{
		std::cerr << "ERROR: no ElGamal subkey found" << std::endl;
		return -1;
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA key found" << std::endl;
		return -1;
	}
	if (!sigelg)
	{
		std::cerr << "ERROR: no self-signature for ElGamal subkey found" << std::endl;
		return -1;
	}
	
	// build keys, check key usage and self-signatures
	tmcg_octets_t dsa_trailer, elg_trailer, dsa_left, elg_left;
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed" << std::endl;
		return -1;
	}
	size_t flags = 0;
	for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
	{
		if (dsa_keyflags[i])	
			flags = (flags << 8) + dsa_keyflags[i];
		else
			break;
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
		return -1;
	}
	ret = gcry_sexp_build(&elgkey, &erroff, "(public-key (elg (p %M) (g %M) (y %M)))", elg_p, elg_g, elg_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing ElGamal key material failed" << std::endl;
		return -1;
	}
	flags = 0;
	for (size_t i = 0; i < sizeof(elg_keyflags); i++)
	{
		if (elg_keyflags[i])
			flags = (flags << 8) + elg_keyflags[i];
		else
			break;
	}
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
		std::cerr << "ERROR: verification of Elgamal subkey self-signature failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		return -1;
	}

	// read a text message from stdin
	while (std::getline(std::cin, line))
		message += line + "\r\n";
	std::cin.clear();

	// encrypt the provided message
	for (size_t i = 0; i < message.length(); i++)
		msg.push_back(message[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, true, enc); // seskey and prefix only
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		return ret;
	}
	enc.clear();
	mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end()); // "it includes the prefix data described above" [RFC4880]
	mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end()); // "it includes all of the plaintext" [RFC4880]
	mdc_hashing.push_back(0xD3); // "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
	mdc_hashing.push_back(0x14);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
	lit.insert(lit.end(), mdc.begin(), mdc.end()); // append Modification Detection Code packet
	seskey.clear(); // generate a fresh session key, but use the previous prefix
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, false, enc);
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);
	// Note that OpenPGP ElGamal encryption in $Z^*_p$ provides only OW-CPA security under the CDH assumption. In
	// order to achieve at least IND-CPA (aka semantic) security under DDH assumption the encoded message $m$ must
	// be an element of the DKG subgroup $G_q$ generated by $g$, unfortunately, the probability that this happens
	// is negligible, if the size of prime $q$ is much smaller than size of $p$.
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricEncryptElgamal() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, gk, myk, pkesk);

	// encode the packages in ASCII armor and print to stdout 
	all.clear();
	all.insert(all.end(), pkesk.begin(), pkesk.end());
	all.insert(all.end(), seipd.begin(), seipd.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(1, all, armored_message);
	std::cout << armored_message << std::endl;

	// release mpis and keys
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(dsa_r);
	gcry_mpi_release(dsa_s);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(elg_r);
	gcry_mpi_release(elg_s);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	gcry_sexp_release(dsakey);
	gcry_sexp_release(elgkey);
	
	return 0;
}
