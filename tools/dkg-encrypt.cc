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

#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());

	std::string line, armored_pubkey, message, armored_message;

	std::cout << "1. Please provide the recipients public key (in ASCII Armor): " << std::endl;
	while (std::getline(std::cin, line))
		armored_pubkey += line + "\r\n";
	std::cin.clear();

	bool pubdsa = false, sigdsa = false, subelg = false, sigelg = false;
	std::string u;
	BYTE atype = 0, ptag = 0xFF;
	BYTE dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	BYTE dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	time_t dsa_sigtime, elg_sigtime;
	OCTETS pkts, pub, sub, msg, lit, mdc, seipd, pkesk, all;
	OCTETS seskey, prefix, enc, mdc_hashing, hash, keyid, pub_hashing, subkeyid, sub_hashing, issuer;
	gcry_mpi_t dsa_p, dsa_q, dsa_g, dsa_y, dsa_r, dsa_s, elg_p, elg_g, elg_y, elg_r, elg_s, gk, myk;
	gcry_sexp_t dsakey, elgkey;
	gcry_error_t ret;
	size_t erroff;
	TMCG_OPENPGP_CONTEXT ctx;

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
	std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype == 6)
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
			std::cout << " version = " << (int)ctx.version;
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
					std::cout << std::hex << std::endl;
					if (pubdsa && !subelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) && CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompare(keyid, issuer))
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::dec << std::endl;
						dsa_sigtype = ctx.type;
						dsa_pkalgo = ctx.pkalgo;
						dsa_hashalgo = ctx.hashalgo;
						dsa_sigtime = ctx.sigcreationtime;
						
						for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
							dsa_keyflags[i] = ctx.keyflags[i];
						for (size_t i = 0; i < sizeof(dsa_psa); i++)
							dsa_psa[i] = ctx.psa[i];
						for (size_t i = 0; i < sizeof(dsa_pha); i++)
							dsa_pha[i] = ctx.pha[i];
						for (size_t i = 0; i < sizeof(dsa_pca); i++)
							dsa_pca[i] = ctx.pca[i];
						dsa_r = ctx.r, dsa_s = ctx.s;
						sigdsa = true;

					}
					else if (pubdsa && subelg && (ctx.type == 0x18) && CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompare(keyid, issuer))
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::dec << std::endl;

						sigelg = true;
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
						std::cout << " Key ID of DSA public key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::hex << std::endl;	
					}
					else if ((ctx.pkalgo == 17) && pubdsa)
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
							std::cout << "Key ID of Elgamal public subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cout << (int)subkeyid[i] << " ";
						std::cout << std::hex << std::endl;
					}
					else if ((ctx.pkalgo == 16) && subelg)
						std::cerr << "WARNING: Elgamal subkey already found" << std::endl; 
					else
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
					break;
			}
		}
	}
	else
	{
		std::cerr << "ERROR: wrong type of ASCII Armor" << std::endl;
		return -1;
	}

	if (!pubdsa)
	{
		std::cerr << "ERROR: no DSA public key found" << std::endl;
		return -1;
	}
	if (!subelg)
	{
		std::cerr << "ERROR: no Elgamal subkey found" << std::endl;
		return -1;
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA public key found" << std::endl;
		return -1;
	}
	if (!sigelg)
	{
		std::cerr << "ERROR: no self-signature for Elgamal subkey found" << std::endl;
		return -1;
	}
	
	
// TODO: build keys and signatures
	OCTETS dsa_flags, elg_flags, uidsig_hashing, uidsig_left;
	std::cout << "Primary User ID: " << u << std::endl;
	
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing key material failed" << std::endl;
		return -1;
	}
	std::cout << "Key flags: ";
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
	dsa_flags.push_back(dsa_keyflags[0]);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(dsa_sigtype, dsa_sigtime, dsa_flags, keyid, uidsig_hashing);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, dsa_hashalgo, hash, uidsig_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, dsa_r, dsa_s);
std::cerr << "ret=" << gcry_err_code(ret) << std::endl;

	
	ret = gcry_sexp_build(&elgkey, &erroff, "(public-key (elg (p %M) (g %M) (y %M)))", elg_p, elg_g, elg_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing key material failed" << std::endl;
		return -1;
	}


	

	std::cout << "2. Now type your private message (in ASCII): " << std::endl;
	while (std::getline(std::cin, line))
		message += line + "\r\n";
	std::cin.clear();

	for (size_t i = 0; i < message.length(); i++)
		msg.push_back(message[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, true, enc);
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed" << std::endl;
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
	lit.insert(lit.end(), mdc.begin(), mdc.end());
	seskey.clear(); // generate a fresh session key, but use the previous prefix
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, false, enc);
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed" << std::endl;
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricEncryptElgamal() failed" << std::endl;
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, gk, myk, pkesk);
	all.clear();
	all.insert(all.end(), pkesk.begin(), pkesk.end());
	all.insert(all.end(), seipd.begin(), seipd.end());
	all.insert(all.end(), mdc.begin(), mdc.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(1, all, armored_message);
	std::cout << armored_message << std::endl;

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
