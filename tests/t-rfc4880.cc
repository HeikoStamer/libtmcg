/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018, 2019, 2020,
               2021  Heiko Stamer <HeikoStamer@gmx.net>

   LibTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   LibTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

#include <exception>
#include <iostream>
#include <fstream>
#include <cassert>
#include <ctime>
#include <cstdio>
#include <unistd.h>

#include "test_helper.h"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	try
	{
		gcry_error_t ret;
		tmcg_openpgp_octets_t in, out;
		tmcg_openpgp_secure_octets_t ins, outs;

		assert(init_libTMCG(true)); // enable libgcrypt's secure memory

		// testing OctetsCompare(), OctetsCompareConstantTime(), OctetsCompareZero()
		std::cout << "OctetsCompareZero() ";
		do
		{
			in.clear(), out.clear(), ins.clear(), outs.clear();
			for (size_t j = 0; j < 6; j++)
				in.push_back(tmcg_mpz_wrandom_ui() % 2);
			for (size_t j = 0; j < 6; j++)
				out.push_back(tmcg_mpz_wrandom_ui() % 2);
			for (size_t j = 0; j < in.size(); j++)
				ins.push_back(in[j]);
			for (size_t j = 0; j < out.size(); j++)
				outs.push_back(out[j]);
			assert((CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompare(in, out) == CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompareConstantTime(outs, ins)));
			std::cout << "~" << std::flush;
		}
		while (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero(in));
		std::cout << std::endl;

		// testing CRC24Compute()
		size_t inlen = 2048;
		size_t crclen = gcry_md_get_algo_dlen(GCRY_MD_CRC24_RFC2440);
		std::cout << "CRC24Compute() ";
		assert((crclen > 0));
		for (size_t i = 0; i < 420; i++)
		{
			char crcin[inlen], crcout[crclen];
			size_t len = 1 + (tmcg_mpz_wrandom_ui() % (inlen-1));
			in.clear(), out.clear();
			for (size_t j = 0; j < len; j++)
				in.push_back(tmcg_mpz_wrandom_ui() % 256);
			for (size_t j = 0; j < len; j++)
				crcin[j] = in[j];
			CallasDonnerhackeFinneyShawThayerRFC4880::
				CRC24Compute(in, out);
			gcry_md_hash_buffer(GCRY_MD_CRC24_RFC2440, crcout, crcin, len);
			in.clear();
			for (size_t j = 0; j < crclen; j++)
				in.push_back(crcout[j]);
			assert((CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompare(in, out)));
			if ((i % 10) == 0)
				std::cout << "~" << std::flush;
		}
		std::cout << std::endl;

		// testing Radix64Encode() and Radix64Decode()
		in.clear(), out.clear();
		for (size_t j = 0; j < 256; j++)
		{
			std::string radix;
			in.push_back(j);
			if (tmcg_mpz_wrandom_ui() % 2)
			{
				std::cout << "Radix64Encode(in, radix, false) = " << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					Radix64Encode(in, radix, false);
			}
			else
			{
				std::cout << "Radix64Encode(in, radix) = " << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					Radix64Encode(in, radix);
			}
			std::cout << radix << std::endl;
			out.clear();
			std::cout << "Radix64Decode(radix, out)" << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::
					Radix64Decode(radix, out);
			assert(in.size() == out.size());
			for (size_t i = 0; i < in.size(); i++)
			{
				assert(in[i] == out[i]);
			}		
		}
	
		// testing ArmorEncode() and ArmorDecode()
		std::vector<tmcg_openpgp_armor_t> vat;
		tmcg_openpgp_armor_t at;
		vat.push_back(TMCG_OPENPGP_ARMOR_MESSAGE);
		vat.push_back(TMCG_OPENPGP_ARMOR_SIGNATURE);
		vat.push_back(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK);
		vat.push_back(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK);
		for (std::vector<tmcg_openpgp_armor_t>::iterator j = vat.begin();
		     j != vat.end(); ++j)
		{
			std::string u = "Max Mustermann <max@gaos.org>";
			for (size_t k = 0; k < 256; k++)
			{
				std::string armor;
				in.clear(), out.clear();
				std::cout << "PackedUidEncode(\"" << u << "\", in)" << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketUidEncode(u, in);
				std::cout << "ArmorEncode(" << *j << ", in, armor)" << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					ArmorEncode(*j, in, armor);
				std::cout << armor << std::endl;
				std::cout << "ArmorDecode(armor, out) = ";
				at = CallasDonnerhackeFinneyShawThayerRFC4880::
					ArmorDecode(armor, out);
				std::cout << (int)at << std::endl;
				assert(at == *j);
				assert(in.size() == out.size());
				for (size_t i = 0; i < in.size(); i++)
				{
					assert(in[i] == out[i]);
				}
				size_t cpos = armor.find("\r\n=");
				u += armor[cpos+3]; // append a single character
			}
		}
		for (std::vector<tmcg_openpgp_armor_t>::iterator j = vat.begin();
		     j != vat.end(); ++j)
		{
			std::string u = "Alexander von Humboldt";
			std::string comment = "Sibirien ist die Fortsetzung der Hasenheide";
			for (size_t k = 0; k < 256; k++)
			{
				std::string armor;
				in.clear(), out.clear();
				std::cout << "PackedUidEncode(\"" << u << "\", in)" << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketUidEncode(u, in);
				std::cout << "ArmorEncode(" << *j << ", in, armor)" << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					ArmorEncode(*j, comment, in, armor, true);
				std::cout << armor << std::endl;
				std::cout << "ArmorDecode(armor, out) = ";
				at = CallasDonnerhackeFinneyShawThayerRFC4880::
					ArmorDecode(armor, out);
				std::cout << (int)at << std::endl;
				assert(at == *j);
				assert(in.size() == out.size());
				for (size_t i = 0; i < in.size(); i++)
				{
					assert(in[i] == out[i]);
				}
				size_t cpos = armor.find("\r\n=");
				u += armor[cpos+3]; // append a single character
				comment += ".\r\nComment: "; // append a new comment line
				comment += armor[cpos+3]; // with a single character
			}
		}

		// testing S2K functions
		tmcg_openpgp_byte_t octcnt = 1;
		size_t hashcnt = ((uint32_t)16 + (octcnt & 15)) << ((octcnt >> 4) + 6);
		size_t keylen = gcry_cipher_get_algo_keylen(TMCG_GCRY_ENC_ALGO);
		tmcg_openpgp_secure_string_t keystr = "Test";
		for (size_t i = 0; i < 42; i++)
		{
			char key[keylen];
			gcry_error_t err;
			std::cout << "gcry_kdf_derive(..., GCRY_KDF_SIMPLE_S2K, " <<
				"TMCG_GCRY_MD_ALGO, ..., " << hashcnt << ", ...)" << std::endl;
			err = gcry_kdf_derive(keystr.c_str(), keystr.length(),
				GCRY_KDF_SIMPLE_S2K, TMCG_GCRY_MD_ALGO, NULL, 0,
				hashcnt, sizeof(key), key);
			assert(!err);
			outs.clear();
			for (size_t i = 0; i < sizeof(key); i++)
				outs.push_back(key[i]); // copy the result
			std::cout << "S2KCompute(..., false, ...)" << std::endl;
			tmcg_openpgp_octets_t salt2;
			tmcg_openpgp_secure_octets_t outs2;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, keylen, keystr, salt2,
				false, octcnt, outs2);
			assert(CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompareConstantTime(outs, outs2));
			keylen++; // increase length of the derived key during tests
		}
		keylen = gcry_cipher_get_algo_keylen(TMCG_GCRY_ENC_ALGO); // reset
		for (size_t i = 0; i < 42; i++)
		{
			char salt[8];
			char key[keylen];
			gcry_error_t err;
			gcry_create_nonce(salt, sizeof(salt));
			std::cout << "gcry_kdf_derive(..., GCRY_KDF_ITERSALTED_S2K, " <<
				"TMCG_GCRY_MD_ALGO, ..., " << hashcnt << ", ...)" << std::endl;
			err = gcry_kdf_derive(keystr.c_str(), keystr.length(),
				GCRY_KDF_ITERSALTED_S2K, TMCG_GCRY_MD_ALGO, salt, sizeof(salt),
				hashcnt, sizeof(key), key);
			assert(!err);
			tmcg_openpgp_octets_t salt2;
			tmcg_openpgp_secure_octets_t outs2;
			outs.clear();
			for (size_t i = 0; i < sizeof(key); i++)
				outs.push_back(key[i]); // copy the result
			for (size_t i = 0; i < sizeof(salt); i++)
				salt2.push_back(salt[i]); // copy the salt
			std::cout << "S2KCompute(..., true, ...)" << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, keylen, keystr, salt2,
				true, octcnt, outs2);
			assert(CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompareConstantTime(outs, outs2));
			keylen++; // increase length of the derived key during tests
		}

		// create different asymmetric keys by using libgcrypt
		size_t erroff = 0;
		gcry_sexp_t elgkey, elgparms;
		std::cout << "gcry_sexp_build(...)" << std::endl;
		ret = gcry_sexp_build(&elgparms, &erroff,
			"(genkey (elg (nbits 4:2048)))");
		assert(!ret);
		std::cout << "gcry_pk_genkey(..., [elg])" << std::endl;
		ret = gcry_pk_genkey(&elgkey, elgparms);
		assert(!ret);
		gcry_sexp_t dsakey, dsaparms;
		std::cout << "gcry_sexp_build(...)" << std::endl;
		ret = gcry_sexp_build(&dsaparms, &erroff,
			"(genkey (dsa (nbits 4:3072)))");
		assert(!ret);
		std::cout << "gcry_pk_genkey(..., [dsa])" << std::endl;
		ret = gcry_pk_genkey(&dsakey, dsaparms);
		assert(!ret);
		gcry_sexp_t ecdsakey, ecdsaparms;
		std::cout << "gcry_sexp_build(...)" << std::endl;
		ret = gcry_sexp_build(&ecdsaparms, &erroff,
			"(genkey (ecdsa (curve secp384r1)))");
		assert(!ret);
		std::cout << "gcry_pk_genkey(..., [ecdsa])" << std::endl;
		ret = gcry_pk_genkey(&ecdsakey, ecdsaparms);
		assert(!ret);
		gcry_sexp_t dsakey2, dsaparms2;
		std::cout << "gcry_sexp_build(...)" << std::endl;
		ret = gcry_sexp_build(&dsaparms2, &erroff,
			"(genkey (dsa (nbits 4:2048)))");
		assert(!ret);
		std::cout << "gcry_pk_genkey(..., [dsa])" << std::endl;
		ret = gcry_pk_genkey(&dsakey2, dsaparms);
		assert(!ret);
		gcry_sexp_t rsakey, rsaparms;
		std::cout << "gcry_sexp_build(...)" << std::endl;
		ret = gcry_sexp_build(&rsaparms, &erroff,
			"(genkey (rsa (nbits 4:3072)))");
		assert(!ret);
		std::cout << "gcry_pk_genkey(..., [rsa])" << std::endl;
		ret = gcry_pk_genkey(&rsakey, rsaparms);
		assert(!ret);
		time_t creation = time(NULL); // set OpenPGP creation time

		// create a literal data packet
		tmcg_openpgp_octets_t lit;
		std::string m = "This is a simple test message. Okay, let's start."
			" Finally one, two, three, and more bytes to proceed ...";
		in.clear();
		for (size_t i = 0; i < m.length(); i++)
			in.push_back(m[i]);
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(in, lit);

		// testing SymmetricEncryptAES256() and SymmetricDecryptAES256()
		// testing AsymmetricEncryptElgamal() and AsymmetricDecryptElgamal()
		tmcg_openpgp_octets_t prefix, enc, subkeyid;
		tmcg_openpgp_secure_octets_t seskey;
		std::cout << "SymmetricEncryptAES256(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricEncryptAES256(lit, seskey, prefix, true, enc);
		assert(!ret);
		out.clear();
		gcry_mpi_t gk, myk;
		gk = gcry_mpi_new(2048);
		myk = gcry_mpi_new(2048);
		std::cout << "AsymmetricEncryptElgamal(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
		assert(!ret);
		for (size_t i = 0; i < 8; i++)
			subkeyid.push_back(0x00); // set OpenPGP wildcard key ID 
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, gk, myk, out);
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode(enc, out);
		std::string armored_message;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, out, armored_message);
		std::cout << armored_message << std::endl;
		out.clear(), prefix.clear(), seskey.clear();
		std::cout << "AsymmetricDecryptElgamal(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricDecryptElgamal(gk, myk, elgkey, seskey);
		assert(!ret);
		gcry_mpi_release(gk);
		gcry_mpi_release(myk);
		std::cout << "SymmetricDecryptAES256(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricDecryptAES256(enc, seskey, prefix, true, out);
		assert(!ret);
		assert(lit.size() == out.size());
		for (size_t i = 0; i < lit.size(); i++)
		{
			assert(lit[i] == out[i]); // check the result
		}

		// testing SymmetricEncryptAEAD(), SymmetricDecryptAEAD() with |ad| = 4
		tmcg_openpgp_octets_t ad, iv, aeadin;
		ad.push_back(0xC3); // packet tag in new format
		ad.push_back(0x05); // packet version number
		ad.push_back(TMCG_OPENPGP_SKALGO_AES256); // cipher algorithm octet
		ad.push_back(TMCG_OPENPGP_AEADALGO_OCB); // AEAD algorithm octet
		for (size_t j = 0; j < 32; j++)
		{
			aeadin.push_back(0xAD);
			enc.clear(), out.clear(), iv.clear();
			std::cout << "SymmetricEncryptAEAD(...)" << std::endl;
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::
				SymmetricEncryptAEAD(aeadin, seskey, TMCG_OPENPGP_SKALGO_AES256,
					TMCG_OPENPGP_AEADALGO_OCB, 0, ad, 3, iv, enc);
			assert(!ret);
			std::cout << "SymmetricDecryptAEAD(...)" << std::endl;
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::
				SymmetricDecryptAEAD(enc, seskey, TMCG_OPENPGP_SKALGO_AES256,
					TMCG_OPENPGP_AEADALGO_OCB, 0, iv, ad, 3, out);
			assert(!ret);
			assert(aeadin.size() == out.size());
			for (size_t i = 0; i < aeadin.size(); i++)
			{
				assert(aeadin[i] == out[i]); // check the result
			}
		}

		// testing SymmetricEncryptAEAD(), SymmetricDecryptAEAD() with |ad| = 13
		for (tmcg_openpgp_byte_t c = 0; c < 3; c++)
		{
			ad.clear(), aeadin.clear();
			ad.push_back(0xD4); // packet tag in new format
			ad.push_back(0x01); // packet version number
			ad.push_back(TMCG_OPENPGP_SKALGO_AES256); // cipher algorithm octet
			ad.push_back(TMCG_OPENPGP_AEADALGO_OCB); // AEAD algorithm octet
			ad.push_back(c); // chunk size octet
			for (size_t i = 0; i < 8; i++)
				ad.push_back(0x00); // initial eight-octet big-endian chunk index
			for (size_t j = 0; j < 128; j++)
			{
				aeadin.push_back(0xAE);
				enc.clear(), out.clear(), iv.clear();
				std::cout << "SymmetricEncryptAEAD(...)" << std::endl;
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					SymmetricEncryptAEAD(aeadin, seskey,
						TMCG_OPENPGP_SKALGO_AES256,	TMCG_OPENPGP_AEADALGO_OCB,
						c, ad, 3, iv, enc);
				assert(!ret);
				std::cout << "SymmetricDecryptAEAD(...)" << std::endl;
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					SymmetricDecryptAEAD(enc, seskey,
						TMCG_OPENPGP_SKALGO_AES256, TMCG_OPENPGP_AEADALGO_OCB,
						c, iv, ad, 3, out);
				assert(!ret);
				assert(aeadin.size() == out.size());
				for (size_t i = 0; i < aeadin.size(); i++)
				{
					assert(aeadin[i] == out[i]); // check the result
				}
			}
		}

		// testing BinaryDocumentHash(), DashEscapeFile()
		std::string filename = "t-rfc4880.tmp";
		time_t filecreation = time(NULL);
		std::ofstream ofs(filename.c_str(), std::ofstream::out);
		assert(ofs.good());
		ofs << "This is a simple test file createt at " << ctime(&filecreation);
		assert(ofs.good());
		ofs << "--- The second line begins with some dashes." << std::endl;
		assert(ofs.good());
		ofs << "From Edward Snowden" << std::endl;
		assert(ofs.good());
		ofs << "The third line should also be dash-escaped." << std::endl;
		assert(ofs.good());
		ofs.close();
		tmcg_openpgp_octets_t hash, trailer, left;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareDetachedSignature(TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT,
			TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 360, "", subkeyid, trailer);
		std::cout << "BinaryDocumentHash(\"" << filename << "\", ...)" << std::endl;
		bool hash_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			BinaryDocumentHash(filename, trailer, TMCG_OPENPGP_HASHALGO_SHA256,
			hash, left);
		assert(hash_ok);
		std::cout << "DashEscapeFile(\"" << filename << "\", ...)" << std::endl;
		std::string dash_escaped;
		bool dash_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			DashEscapeFile(filename, dash_escaped);
		assert(dash_ok);
		std::cout << dash_escaped << std::endl;
		assert((dash_escaped.find("- ---") != dash_escaped.npos));
		assert((dash_escaped.find("- From") != dash_escaped.npos));

		// testing AsymmetricSignDSA() and AsymmetricVerifyDSA()
		tmcg_openpgp_octets_t sig;
		std::string armored_signature;
		gcry_mpi_t r, s;
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		std::cout << "AsymmetricSignDSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, dsakey, r, s);
		assert(!ret);
		std::cout << "r = " << r << std::endl;
		std::cout << "s = " << s << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(trailer, left, r, s, sig);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, sig, armored_signature);
		std::cout << armored_signature << std::endl;
		std::cout << "AsymmetricVerifyDSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyDSA(hash, dsakey, r, s);
		assert(!ret);
		tmcg_openpgp_octets_t hash2;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			HashCompute(TMCG_OPENPGP_HASHALGO_SHA512, lit, hash2); // SHA512
		std::cout << "AsymmetricSignDSA(...) with truncated hash" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash2, dsakey, r, s);
		assert(!ret);
		std::cout << "AsymmetricVerifyDSA(...) with truncated hash" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyDSA(hash2, dsakey, r, s);
		assert(!ret);
		gcry_mpi_release(r);
		gcry_mpi_release(s);

		// testing AsymmetricSignECDSA() and AsymmetricVerifyECDSA()
		hash.clear(), trailer.clear(), left.clear(), sig.clear();
		r = gcry_mpi_new(1024);
		s = gcry_mpi_new(1024);
		std::cout << "AsymmetricSignECDSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignECDSA(hash, ecdsakey, r, s);
		assert(!ret);
		std::cout << "r = " << r << std::endl;
		std::cout << "s = " << s << std::endl;
		std::cout << "AsymmetricVerifyECDSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyECDSA(hash, ecdsakey, r, s);
		assert(!ret);
		gcry_mpi_release(r);
		gcry_mpi_release(s);

		// testing AsymmetricSignRSA() and AsymmetricVerifyRSA()
		hash.clear(), trailer.clear(), left.clear(), sig.clear();
		for (size_t i = 0; i < 2; i++)
			left.push_back(i); // dummy values
		CallasDonnerhackeFinneyShawThayerRFC4880::
			HashCompute(TMCG_OPENPGP_HASHALGO_SHA256, lit, hash); // SHA256
		s = gcry_mpi_new(3072);
		std::cout << "AsymmetricSignRSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignRSA(hash, rsakey, TMCG_OPENPGP_HASHALGO_SHA256, s);
		assert(!ret);
		std::cout << "AsymmetricVerifyRSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyRSA(hash, rsakey, TMCG_OPENPGP_HASHALGO_SHA256, s);
		assert(!ret);
		gcry_mpi_release(s);

		// testing AsymmetricEncryptRSA() and AsymmetricDecryptRSA()
		gcry_mpi_t me;
		me = gcry_mpi_new(2048);
		armored_message = "";
		std::cout << "AsymmetricEncryptRSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptRSA(seskey, rsakey, me);
		assert(!ret);
		subkeyid.clear(), out.clear(), enc.clear();
		for (size_t i = 0; i < 8; i++)
			subkeyid.push_back(0x00); // set OpenPGP wildcard key ID 
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, me, out);
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode(enc, out);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, out, armored_message);
		std::cout << armored_message << std::endl;
		std::cout << "AsymmetricDecryptRSA(...)" << std::endl;
		tmcg_openpgp_secure_octets_t seskey2;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricDecryptRSA(me, rsakey, seskey2);
		assert(!ret);
		assert(CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompareConstantTime(seskey, seskey2));
		gcry_mpi_release(me);

		// testing PublicKeyBlockParse(), FingerprintCompute(), KeyidCompute()
		tmcg_openpgp_octets_t all, pub, uid, uidsig, sub, subsig, pubflags, empty;
		tmcg_openpgp_octets_t subflags, keyid, pub_hashing, uidsig_hashing, issuer;
		tmcg_openpgp_octets_t uidsig_left, sub_hashing, subsig_hashing, subsig_left;
		tmcg_openpgp_octets_t sec, subsec;
		std::string armored_pubkeyblock, username = "Test";
		tmcg_openpgp_secure_string_t passphrase = "FCK!NSA";
		gcry_mpi_t p, q, g, y, x;
		std::cout << "gcry_sexp_extract_param(...)" << std::endl;
		ret = gcry_sexp_extract_param(dsakey, NULL, "pqgy", &p, &q, &g, &y, NULL);
		assert(!ret);
		std::cout << "gcry_sexp_extract_param(...)" << std::endl;
		ret = gcry_sexp_extract_param(dsakey, NULL, "x", &x, NULL);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPubEncode(creation, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSecEncode(creation, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, x,
			passphrase, sec);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(pub, 3, pub_hashing);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(pub_hashing, keyid);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintCompute(pub_hashing, issuer);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketUidEncode(username, uid);
		pubflags.push_back(0x01 | 0x02);  // certify other keys and sign data
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
				TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, pubflags, keyid,
				uidsig_hashing); 
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing, username, empty, uidsig_hashing,
				TMCG_OPENPGP_HASHALGO_SHA256, hash, uidsig_left);
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		std::cout << "AsymmetricSignDSA()" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, dsakey, r, s);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
		gcry_mpi_release(p);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		std::cout << "gcry_sexp_extract_param(...)" << std::endl;
		ret = gcry_sexp_extract_param(elgkey, NULL, "pgyx", &p, &g, &y, &x, NULL);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSubEncode(creation, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				sub);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSsbEncode(creation, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				x, passphrase, subsec);
		subflags.push_back(0x04 | 0x08); // encrypt communications and storage
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
				TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, subflags,
				issuer, subsig_hashing);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(sub, 3, sub_hashing);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, sub_hashing, subsig_hashing,
				TMCG_OPENPGP_HASHALGO_SHA256, hash, subsig_left);
		std::cout << "AsymmetricSignDSA()" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, dsakey, r, s);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
		all.insert(all.end(), pub.begin(), pub.end());
		all.insert(all.end(), uid.begin(), uid.end());
		all.insert(all.end(), uidsig.begin(), uidsig.end());
		all.insert(all.end(), sub.begin(), sub.end());
		all.insert(all.end(), subsig.begin(), subsig.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all,
				armored_pubkeyblock);
		std::cout << armored_pubkeyblock << std::endl;
		TMCG_OpenPGP_Pubkey *primary = NULL;
		TMCG_OpenPGP_Keyring *ring = new TMCG_OpenPGP_Keyring();
		std::cout << "PublicKeyBlockParse()" << std::endl;
		bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(armored_pubkeyblock, 3, primary);
		assert(parse_ok);
		tmcg_openpgp_octets_t expub, expub2, expub3, expub4, expub5;
		std::cout << "Export()" << std::endl;
		primary->Export(expub);
		assert((CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(all, expub)));
		std::cout << "Export(TMCG_OPENPGP_EXPORT_KEYSONLY)" << std::endl;
		primary->Export(expub2, TMCG_OPENPGP_EXPORT_KEYSONLY);
		assert(expub2.size() < expub.size());
		std::cout << "Export(TMCG_OPENPGP_EXPORT_MINIMAL)" << std::endl;
		primary->Export(expub3, TMCG_OPENPGP_EXPORT_MINIMAL);
		assert(expub3.size() == 0);
		std::cout << "Export(TMCG_OPENPGP_EXPORT_REVCERT)" << std::endl;
		primary->Export(expub4, TMCG_OPENPGP_EXPORT_REVCERT);
		assert(expub4.size() <= expub.size());
		std::cout << "CheckSelfSignatures()" << std::endl;
		parse_ok = primary->CheckSelfSignatures(ring, 3);
		assert(parse_ok);
		std::cout << "CheckSubkeys()" << std::endl;
		parse_ok = primary->CheckSubkeys(ring, 3);
		assert(parse_ok);
		std::cout << "Export(TMCG_OPENPGP_EXPORT_MINIMAL)" << std::endl;
		primary->Export(expub5, TMCG_OPENPGP_EXPORT_MINIMAL);
		assert((CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(all, expub5)));
		std::string fpr, kid;
		std::cout << "FingerprintConvertPlain()" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPlain(primary->fingerprint, fpr);
		std::cout << fpr << std::endl;
		std::cout << "KeyidConvert()" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidConvert(primary->id, kid);
		std::cout << kid << std::endl;
		std::cout << "!primary->Weak()" << std::endl;
		bool check_ok = primary->Weak(3);
		assert(!check_ok);
		delete primary;
		delete ring;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);

		// testing SignatureParse()
		sleep(1);
		TMCG_OpenPGP_Signature *signature = NULL;
		std::cout << "SignatureParse()" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			SignatureParse(armored_signature, 3, signature);
		assert(parse_ok);
		TMCG_OpenPGP_Signature signature2 = *signature;
		assert(signature->Good());
		assert(signature2.Good());
		std::cout << "PrintInfo()" << std::endl;
		signature->PrintInfo();
		signature2.PrintInfo();
		std::cout << "CheckValidity()" << std::endl;
		parse_ok = signature->CheckValidity(creation, 3);
		assert(parse_ok);
		parse_ok = signature2.CheckValidity(creation, 3);
		assert(parse_ok);
		std::cout << "!CheckValidity()" << std::endl;
		parse_ok = signature->CheckValidity(time(NULL), 3);
		assert(!parse_ok);
		parse_ok = signature2.CheckValidity(time(NULL), 3);
		assert(!parse_ok);
		std::cout << "Verify(..., \"" << filename << "\", ...)" << std::endl;
		parse_ok = signature->Verify(dsakey, filename, 3);
		assert(parse_ok);
		parse_ok = signature2.Verify(dsakey, filename, 3);
		assert(parse_ok);
		delete signature;
		remove(filename.c_str());

		// testing PublicKeyringParse()
		std::string armored_pubkeyringblock;
		all.insert(all.end(), pub.begin(), pub.end()); // append the same pubkey
		all.insert(all.end(), uid.begin(), uid.end());
		all.insert(all.end(), uidsig.begin(), uidsig.end());
		all.insert(all.end(), sub.begin(), sub.end());
		all.insert(all.end(), subsig.begin(), subsig.end());
		tmcg_openpgp_octets_t pub2, uid2, uidsig2, sub2, subsig2;
		tmcg_openpgp_octets_t keyid2, pub_hashing2, uidsig_hashing2, uidsig_left2;
		tmcg_openpgp_octets_t sub_hashing2, subsig_hashing2, subsig_left2;
		std::cout << "gcry_sexp_extract_param(...)" << std::endl;
		ret = gcry_sexp_extract_param(dsakey2, NULL, "pqgy", &p, &q, &g, &y, NULL);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPubEncode(creation, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y,
				pub2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(pub2, 3, pub_hashing2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(pub_hashing2, keyid2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketUidEncode(username, uid2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
				TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, pubflags, keyid2,
				uidsig_hashing2);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing2, username, empty, uidsig_hashing2,
				TMCG_OPENPGP_HASHALGO_SHA256, hash, uidsig_left2);
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		std::cout << "AsymmetricSignDSA()" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, dsakey2, r, s);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(uidsig_hashing2, uidsig_left2, r, s, uidsig2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSubEncode(creation, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				sub2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
				TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, subflags, keyid2,
				subsig_hashing2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(sub2, 3, sub_hashing2);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing2, sub_hashing2, subsig_hashing2,
				TMCG_OPENPGP_HASHALGO_SHA256, hash, subsig_left2);
		std::cout << "AsymmetricSignDSA()" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, dsakey2, r, s);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(subsig_hashing2, subsig_left2, r, s, subsig2);
		all.insert(all.end(), pub2.begin(), pub2.end()); // append another pubkey
		all.insert(all.end(), uid2.begin(), uid2.end());
		all.insert(all.end(), uidsig2.begin(), uidsig2.end());
		all.insert(all.end(), sub2.begin(), sub2.end());
		all.insert(all.end(), subsig2.begin(), subsig2.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all,
				armored_pubkeyringblock);
		std::cout << armored_pubkeyringblock << std::endl;
		ring = NULL;
		std::cout << "PublicKeyringParse()" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyringParse(armored_pubkeyringblock, 3, ring);
		assert(parse_ok);
		assert((ring->Size() == 2));
		assert((ring->List("") == 2));
		assert((ring->Check(0) == 2));
		ring->Reduce();
		assert((ring->Size() == 2));
		std::string kid2, kid3, fpr2, fpr3;
		tmcg_openpgp_octets_t fingerprint;		
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidConvert(keyid2, kid2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintCompute(pub_hashing2, fingerprint);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPlain(fingerprint, fpr2);
		kid3 = kid2, fpr3 = fpr2; // convert to lower-case
		for (size_t i = 0; i < kid3.length(); i++)
		{
			switch (kid3[i])
			{
				case 'A':
					kid3[i] = 'a';
					break;
				case 'B':
					kid3[i] = 'b';
					break;
				case 'C':
					kid3[i] = 'c';
					break;
				case 'D':
					kid3[i] = 'd';
					break;
				case 'E':
					kid3[i] = 'e';
					break;
				case 'F':
					kid3[i] = 'f';
					break;
			}
		}
		for (size_t i = 0; i < fpr3.length(); i++)
		{
			switch (fpr3[i])
			{
				case 'A':
					fpr3[i] = 'a';
					break;
				case 'B':
					fpr3[i] = 'b';
					break;
				case 'C':
					fpr3[i] = 'c';
					break;
				case 'D':
					fpr3[i] = 'd';
					break;
				case 'E':
					fpr3[i] = 'e';
					break;
				case 'F':
					fpr3[i] = 'f';
					break;
			}
		}
		std::cout << "!Find(" << kid2 << ")" << std::endl;
		assert((ring->Find(kid2) == NULL));
		std::cout << "!Find(" << kid3 << ")" << std::endl;
		assert((ring->Find(kid3) == NULL));
		std::cout << "Find(" << fpr2 << ")" << std::endl;
		assert((ring->Find(fpr2) != NULL));
		std::cout << "Find(" << fpr3 << ")" << std::endl;
		assert((ring->Find(fpr3) != NULL));
		std::cout << "FindByKeyid(" << kid2 << ")" << std::endl;
		assert((ring->FindByKeyid(kid2) != NULL));
		std::cout << "FindByKeyid(" << kid3 << ")" << std::endl;
		assert((ring->FindByKeyid(kid3) != NULL));
		std::cout << "FindByKeyid(" << fpr2 << ")" << std::endl;		
		assert((ring->FindByKeyid(fpr2) != NULL));
		delete ring;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(r);
		gcry_mpi_release(s);

		// testing PrivateKeyBlockParse()
		std::string armored_prvkey_dsa;
		all.clear();
		all.insert(all.end(), sec.begin(), sec.end());
		all.insert(all.end(), uid.begin(), uid.end());
		all.insert(all.end(), uidsig.begin(), uidsig.end());
		all.insert(all.end(), subsec.begin(), subsec.end());
		all.insert(all.end(), subsig.begin(), subsig.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, all,
				armored_prvkey_dsa);
		std::cout << armored_prvkey_dsa << std::endl;
		TMCG_OpenPGP_Prvkey *dsa = NULL;
		std::cout << "!PrivateKeyBlockParse(..., dsa)" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_prvkey_dsa, 3, "wrong password", dsa);
		assert(!parse_ok);
		std::cout << "PrivateKeyBlockParse(..., dsa)" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_prvkey_dsa, 3, passphrase, dsa);
		assert(parse_ok);
		tmcg_openpgp_octets_t exsec;
		std::cout << "Export()" << std::endl;
		dsa->Export(exsec);
		assert((CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(all, exsec)));

		// testing MessageParse()
		all.clear(), seskey.clear(), prefix.clear(), enc.clear(), hash.clear();
		tmcg_openpgp_octets_t litmdc, mdc_hashing, mdc, seipd;
		std::cout << "SymmetricEncryptAES256(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricEncryptAES256(lit, seskey, prefix, true, enc); // prepare
		assert(!ret);
		enc.clear();
		mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end());
		mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end());
		mdc_hashing.push_back(0xD3);
		mdc_hashing.push_back(0x14);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash);
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
		litmdc.insert(litmdc.end(), lit.begin(), lit.end());
		litmdc.insert(litmdc.end(), mdc.begin(), mdc.end()); // append MDC
		seskey.clear(); // generate a fresh session key and keep the previous prefix
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricEncryptAES256(litmdc, seskey, prefix, false, enc); // encrypt
		std::cout << "SymmetricEncryptAES256(...)" << std::endl;
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);
		tmcg_openpgp_octets_t pkesk;
		me = gcry_mpi_new(2048);
		std::cout << "AsymmetricEncryptRSA(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptRSA(seskey, rsakey, me);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, me, pkesk);
		gcry_mpi_release(me);
		all.insert(all.end(), pkesk.begin(), pkesk.end());
		pkesk.clear(); // construct another PKESK
		gk = gcry_mpi_new(2048);
		myk = gcry_mpi_new(2048);
		std::cout << "AsymmetricEncryptElgamal(...)" << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
		assert(!ret);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, gk, myk, pkesk);
		gcry_mpi_release(gk);
		gcry_mpi_release(myk);
		all.insert(all.end(), pkesk.begin(), pkesk.end());
		armored_message = "";
		all.insert(all.end(), seipd.begin(), seipd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, all, armored_message);
		std::cout << armored_message << std::endl;
		TMCG_OpenPGP_Message *msg = NULL;
		std::cout << "MessageParse()" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			MessageParse(armored_message, 3, msg);
		assert(parse_ok);
		msg->PrintInfo();
		seskey.clear();
		for (size_t i = 0; i < (msg->PKESKs).size(); i++)
		{
			const TMCG_OpenPGP_PKESK *esk = (msg->PKESKs)[i];
			if (esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				bool decrypt_ok = false;
				for (size_t j = 0; j < (dsa->private_subkeys).size(); j++)
				{
					if ((dsa->private_subkeys)[j]->Decrypt(esk, 3, seskey))
					{
						decrypt_ok = true;
						break;
					}
				}
				if (decrypt_ok)
					break;
			}
		}
		tmcg_openpgp_octets_t dec;	
		std::cout << "Decrypt()" << std::endl;
		parse_ok = msg->Decrypt(seskey, 3, dec);
		assert(parse_ok);
		std::cout << "MessageParse(dec)" << std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			MessageParse(dec, 3, msg);
		assert(parse_ok);
		msg->PrintInfo();
		assert(CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(lit, msg->literal_message));
		assert(CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(in, msg->literal_data));
		delete msg;
		delete dsa;

		// release keys generated by using libgcrypt
		gcry_sexp_release(elgparms);
		gcry_sexp_release(elgkey);
		gcry_sexp_release(dsaparms);
		gcry_sexp_release(dsakey);
		gcry_sexp_release(ecdsaparms);
		gcry_sexp_release(ecdsakey);
		gcry_sexp_release(dsaparms2);
		gcry_sexp_release(dsakey2);
		gcry_sexp_release(rsaparms);
		gcry_sexp_release(rsakey);

		// test externally generated Ed25519 public key
		std::string mallory_armored =
"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\n"
"mDMEW3P+yxYJKwYBBAHaRw8BAQdAFWO/NfdgP1sX27GUdaporGJkMhCNfr/ZlyMm\r\n"
"6i8vwD20B01hbGxvcnmIkAQTFggAOBYhBOOe9Pt+rWYkOw5dGnchfMwJwVMrBQJb\r\n"
"c/7LAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEHchfMwJwVMrrYYBAKEK\r\n"
"Y0uKnES/YPmXB6Jj5qmK82MX+mJx8hccHPdsJb/nAQDusYVS/4Xx+uWK9/zntrDq\r\n"
"Jf1hYsjSxe/03+cT2ze/A7g4BFtz/ssSCisGAQQBl1UBBQEBB0BaH+8/c76A3gPe\r\n"
"a631zMYQou+bF7l9x25iPrWrivoCNgMBCAeIeAQYFggAIBYhBOOe9Pt+rWYkOw5d\r\n"
"GnchfMwJwVMrBQJbc/7LAhsMAAoJEHchfMwJwVMrsVoA/09EgCBkINfruB0MomXK\r\n"
"KiG6cUjGtAO0aURabyiKWiS1AP97KMY0ixHTQIV0sCR3LGIIu3ojnNtapLuqzqJt\r\n"
"uO6+DQ==\r\n"
"=VqXx\r\n"
"-----END PGP PUBLIC KEY BLOCK-----\r\n";
		TMCG_OpenPGP_Pubkey *mallory = NULL;
		ring = new TMCG_OpenPGP_Keyring();
		std::cout << "PublicKeyBlockParse(mallory_armored, 3, mallory)" <<
			std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(mallory_armored, 3, mallory);
		assert(parse_ok);
		if (gcry_check_version("1.7.0"))
		{
			std::cout << "CheckSelfSignatures()" << std::endl;
			parse_ok = mallory->CheckSelfSignatures(ring, 3);
			assert(parse_ok);
			std::cout << "CheckSubkeys()" << std::endl;
			parse_ok = mallory->CheckSubkeys(ring, 3);
			assert(parse_ok);
			std::cout << "!mallory->Weak()" << std::endl;
			check_ok = mallory->Weak(3);
			assert(!check_ok);
		}
		delete mallory;
		delete ring;

		// test a non-encrypted V5 key provided by Werner Koch
		std::string emma_armored =
"-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n"
"lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\r\n"
"fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA\r\n"
"Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC\r\n"
"X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI\r\n"
"CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9\r\n"
"M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA\r\n"
"MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD\r\n"
"AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF\r\n"
"GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb\r\n"
"DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7\r\n"
"TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\r\n"
"=IiS2\r\n"
"-----END PGP PRIVATE KEY BLOCK-----\r\n";
		TMCG_OpenPGP_Prvkey *emma = NULL;
		ring = new TMCG_OpenPGP_Keyring();
		std::cout << "PrivateKeyBlockParse(emma_armored, 3, \"\", emma)" <<
			std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(emma_armored, 3, "", emma);
		assert(parse_ok);
		if (gcry_check_version("1.7.0"))
		{
			TMCG_OpenPGP_Pubkey *emmapub = emma->pub; // get the public key 
			emma->RelinkPublicSubkeys(); // relink the contained subkeys
			std::cout << "CheckSelfSignatures()" << std::endl;
			parse_ok = emmapub->CheckSelfSignatures(ring, 3);
			assert(parse_ok);
			std::cout << "CheckSubkeys()" << std::endl;
			parse_ok = emmapub->CheckSubkeys(ring, 3);
			assert(parse_ok);
			std::cout << "!emmapub->Weak()" << std::endl;
			check_ok = emmapub->Weak(3);
			assert(!check_ok);
			emma->RelinkPrivateSubkeys(); // undo the relinking
			time_t sigtime = time(NULL); // current time, fixed algo SHA2-512
			tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
			tmcg_openpgp_octets_t trailer, hash, left, sig;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareDetachedSignature(
					TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT, emmapub->pkalgo,
					hashalgo, sigtime, 0, "", emmapub->fingerprint, trailer);
			std::cout << "BinaryDocumentHash()" << std::endl;
			check_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				BinaryDocumentHash(dec, trailer, hashalgo, hash, left);
			assert(check_ok);
			std::cout << "SignData()" << std::endl;
			check_ok = emma->SignData(hash, hashalgo, trailer, left, 3, sig);
			assert(check_ok);
			TMCG_OpenPGP_Signature *emma_signature = NULL;
			std::cout << "SignatureParse()" << std::endl;
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				SignatureParse(sig, 3, emma_signature);
			assert(parse_ok);
			assert(emma_signature->Good());
			std::cout << "PrintInfo()" << std::endl;
			emma_signature->PrintInfo();
			std::cout << "CheckValidity()" << std::endl;
			parse_ok = emma_signature->CheckValidity(emmapub->creationtime, 3);
			assert(parse_ok);
			std::cout << "VerifyData()" << std::endl;
			parse_ok = emma_signature->VerifyData(emmapub->key, dec, 3);
			assert(parse_ok);
			delete emma_signature;
		}
		delete emma;
		delete ring;

		// test externally generated public key with attested certifications
		std::string davey_armored =
"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
"Comment: D1A6 6E1A 23B1 82C9 980F  788C FBFC C82A 015E 7330\r\n"
"Comment: Bob Babbage <bob@openpgp.example>\r\n\r\n"
"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\r\n"
"5KjhX2PVNEJd3XZRzaXZE2aAMQ==\r\n"
"=O7Nv\r\n"
"-----END PGP PUBLIC KEY BLOCK-----\r\n";
		TMCG_OpenPGP_Pubkey *davey = NULL;
		ring = new TMCG_OpenPGP_Keyring();
		std::cout << "PublicKeyBlockParse(davey_armored, 3, davey)" <<
			std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(davey_armored, 3, davey);
		assert(parse_ok);
		if (gcry_check_version("1.7.0"))
		{
			std::cout << "CheckSelfSignatures()" << std::endl;
			parse_ok = davey->CheckSelfSignatures(ring, 3);
			assert(parse_ok);
			std::cout << "!davey->Weak()" << std::endl;
			check_ok = davey->Weak(3);
			assert(!check_ok);
			for (size_t i = 0; i < davey->userids.size(); i++)
			{
				std::string uid = davey->userids[i]->userid_sanitized;
				std::cout << "userid = \"" << uid << "\" is ";
				if (davey->userids[i]->valid)
					std::cout << "valid" << std::endl;
				else
					std::cout << "invalid" << std::endl;
				std::cout << "AccumulateAttestations()" << std::endl;
				assert(davey->userids[i]->AccumulateAttestations(davey, 3) == 1);
				std::cout << "CheckAttestations()" << std::endl;
				assert(davey->userids[i]->CheckAttestations(davey, 3));
			}
		}
		delete davey;
		delete ring;

		// test EdDSA public key and a signature with leading zeros 
		std::string alice_armored =
"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
"Comment: Alice's OpenPGP certificate\r\n"
"Comment: https://tools.ietf.org/html/draft-bre-openpgp-samples\r\n\r\n"
"mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\r\n"
"b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE\r\n"
"ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy\r\n"
"MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO\r\n"
"dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4\r\n"
"OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s\r\n"
"E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb\r\n"
"DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn\r\n"
"0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=\r\n"
"=iIGO\r\n"
"-----END PGP PUBLIC KEY BLOCK-----\r\n";
		std::string alice_sig =
"-----BEGIN PGP SIGNATURE-----\r\n\r\n"
"wnQEABYKACcFAl23GYsJEPIxVQxPR+OOFiEE64W7X6M6deFelE5j8jFVDE9H444A\r\n"
"ANOWAPsHrQTUDtDyP3gr2KsdhX/iapwrO3HSLUD7X41YUasdygD4r6QGQxJXKfbR\r\n"
"lpZFZ4otf72qcIzc82oZxaApG9L6Dg==\r\n"
"=WUuG\r\n"
"-----END PGP SIGNATURE-----\r\n";
		TMCG_OpenPGP_Pubkey *alice = NULL;
		ring = new TMCG_OpenPGP_Keyring();
		std::cout << "PublicKeyBlockParse(alice_armored, 3, alice)" <<
			std::endl;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(alice_armored, 3, alice);
		assert(parse_ok);
		if (gcry_check_version("1.7.0"))
		{
			std::cout << "CheckSelfSignatures()" << std::endl;
			parse_ok = alice->CheckSelfSignatures(ring, 3);
			assert(parse_ok);
			std::cout << "!alice->Weak()" << std::endl;
			check_ok = alice->Weak(3);
			assert(!check_ok);
			for (size_t i = 0; i < alice->userids.size(); i++)
			{
				std::string uid = alice->userids[i]->userid_sanitized;
				std::cout << "userid = \"" << uid << "\" is ";
				if (alice->userids[i]->valid)
					std::cout << "valid" << std::endl;
				else
					std::cout << "invalid" << std::endl;
			}
			TMCG_OpenPGP_Signature *alice_signature = NULL;
			std::cout << "SignatureParse()" << std::endl;
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				SignatureParse(alice_sig, 3, alice_signature);
			assert(parse_ok);
			assert(alice_signature->Good());
			std::cout << "PrintInfo()" << std::endl;
			alice_signature->PrintInfo();
			std::cout << "CheckValidity()" << std::endl;
			parse_ok = alice_signature->CheckValidity(alice->creationtime, 3);
			assert(parse_ok);
			std::string alice_filename = "t-rfc4880.tmp";
			std::ofstream ofs(alice_filename.c_str(), std::ofstream::out);
			assert(ofs.good());
			ofs << "huhu" << std::endl;
			assert(ofs.good());
			ofs.close();
			std::cout << "Verify(..., \"" << alice_filename << "\", ...)" <<
				std::endl;
			parse_ok = alice_signature->Verify(alice->key, alice_filename, 3);
			assert(parse_ok);
			delete alice_signature;
			remove(alice_filename.c_str());
		}
		delete alice;
		delete ring;
	
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() <<
			std::endl;
		return -1;
	}
}

