/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
		assert(signature->Good());
		std::cout << "PrintInfo()" << std::endl;
		signature->PrintInfo();
		std::cout << "CheckValidity()" << std::endl;
		parse_ok = signature->CheckValidity(creation, 3);
		assert(parse_ok);
		std::cout << "!CheckValidity()" << std::endl;
		parse_ok = signature->CheckValidity(time(NULL), 3);
		assert(!parse_ok);
		std::cout << "Verify(..., \"" << filename << "\", ...)" << std::endl;
		parse_ok = signature->Verify(dsakey, filename, 3);
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
		}
		delete emma;
		delete ring;

		// test externally generated public key with attested certifications
		std::string davey_armored =
"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\n"
"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\r\n"
"=PUl0\r\n"
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
				assert(davey->userids[i]->AccumulateAttestations(davey, 3) == 2);
				std::cout << "CheckAttestations()" << std::endl;
				assert(davey->userids[i]->CheckAttestations(davey, 3));
			}
		}
		delete davey;
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

