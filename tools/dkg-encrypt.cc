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

	std::cout << "Please provide the recipients DKG public key (in ASCII Armor): " << std::endl;
	while (std::getline(std::cin, line))
		armored_pubkey += line + "\r\n";
	std::cin.clear();

	bool pubdsa = false, subelg = false;
	BYTE atype = 0, ptag = 0xFF;
	OCTETS pkts, pub, sub, msg, lit, mdc, seipd, pkesk, all;
	OCTETS seskey, prefix, enc, mdc_hashing, hash, keyid, pub_hashing, subkeyid, sub_hashing;
	gcry_mpi_t dsa_p, dsa_q, dsa_g, dsa_y, elg_p, elg_g, elg_y, gk, myk;
	gcry_sexp_t dsakey, elgkey;
	gcry_error_t ret;
	size_t erroff;
	TMCG_OPENPGP_CONTEXT ctx;

	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	elg_p = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
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
				case 6:
					if ((ctx.pkalgo == 17) && !pubdsa)
					{
						pubdsa = true;
						dsa_p = ctx.p, dsa_q = ctx.q, dsa_g = ctx.g, dsa_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime,
							dsa_p, dsa_q, dsa_g, dsa_y, pub);		
					}
					else if (pubdsa)
					{
						std::cerr << "ERROR: more than one primary key not supported" << std::endl;
						return -1;
					}
					else
						std::cerr << "WARNING: public-key algorithm not supported" << std::endl;
					break;
				case 13:
					std::cout << " uid = " << ctx.uid << std::endl;
					break;
				case 14:
					if ((ctx.pkalgo == 16) && !subelg)
					{
						subelg = true;
						elg_p = ctx.p, elg_g = ctx.g, elg_y = ctx.y;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime,
							elg_p, elg_g, elg_y, sub);
					}
					else if (subelg)
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
	
	
// TODO: check keys and signatures
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	std::cout << "Key ID of DSA public key: " << std::hex;
	for (size_t i = 0; i < keyid.size(); i++)
		std::cout << (int)keyid[i] << " ";
	std::cout << std::hex << std::endl;
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing key material failed" << std::endl;
		return -1;
	}


	for (size_t i = 6; i < sub.size(); i++)
		sub_hashing.push_back(sub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
	std::cout << "Key ID of Elgamal public subkey: " << std::hex;
	for (size_t i = 0; i < subkeyid.size(); i++)
		std::cout << (int)subkeyid[i] << " ";
	std::cout << std::hex << std::endl;
	ret = gcry_sexp_build(&elgkey, &erroff, "(public-key (elg (p %M) (g %M) (y %M)))", elg_p, elg_g, elg_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing key material failed" << std::endl;
		return -1;
	}


	

	std::cout << "Now type your private message (in ASCII): " << std::endl;
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
	CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
	lit.insert(lit.end(), mdc.begin(), mdc.end());
	seskey.clear(); // generate a fresh session key
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
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	gcry_sexp_release(dsakey);
	gcry_sexp_release(elgkey);
	
	return 0;
}
