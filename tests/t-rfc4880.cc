/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

#include <iostream>
#include <fstream>
#include <cassert>
#include <ctime>
#include <cstdio>
#include <unistd.h>

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

#include "test_helper.h"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	gcry_error_t ret;
	tmcg_openpgp_octets_t in, out;

	// testing OctetsCompare(), OctetsCompareConstantTime(), OctetsCompareZero()
	std::cout << "OctetsCompareZero() ";
	do
	{
		in.clear(), out.clear();
		for (size_t j = 0; j < 6; j++)
			in.push_back(mpz_wrandom_ui() % 2);
		for (size_t j = 0; j < 6; j++)
			out.push_back(mpz_wrandom_ui() % 2);
		assert((CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(in, out) == CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompareConstantTime(out, in)));
		std::cout << "~";
	}
	while (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero(in));
	std::cout << std::endl;

	// testing Radix64Encode() and Radix64Decode()
	in.clear(), out.clear();
	for (size_t j = 0; j < 256; j++)
	{
		std::string radix;
		in.push_back(j);
		if (mpz_wrandom_ui() % 2)
		{
			std::cout << "Radix64Encode(in, radix, false) = " << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode(in, radix,
				false);
		}
		else
		{
			std::cout << "Radix64Encode(in, radix) = " << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode(in, radix);
		}
		std::cout << radix << std::endl;
		out.clear();
		std::cout << "Radix64Decode(radix, out)" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Decode(radix, out);
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
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, in);
			std::cout << "ArmorEncode(" << *j << ", in, armor)" << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(*j, in,
				armor);
			std::cout << armor << std::endl;
			std::cout << "ArmorDecode(armor, out) = ";
			at = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armor,
				out);
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
	size_t hashcnt = (16 + (octcnt & 15)) << ((octcnt >> 4) + 6);
	size_t keylen = gcry_cipher_get_algo_keylen(TMCG_GCRY_ENC_ALGO);
	std::string keystr = "Test";
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
	tmcg_openpgp_octets_t salt2, out2;
	out.clear();
	for (size_t i = 0; i < sizeof(key); i++)
		out.push_back(key[i]); // copy the result
	for (size_t i = 0; i < sizeof(salt); i++)
		salt2.push_back(salt[i]); // copy the salt
	std::cout << "S2KCompute(...)" << std::endl;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, keylen, keystr, salt2, true,
		octcnt, out2);
	assert(CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(out, out2));

	// create different asymmetric keys by using libgcrypt
	size_t erroff = 0;
	gcry_sexp_t elgkey, elgparms;
	std::cout << "gcry_sexp_build(...)" << std::endl;
	ret = gcry_sexp_build(&elgparms, &erroff, "(genkey (elg (nbits 4:2048)))");
	assert(!ret);
	std::cout << "gcry_pk_genkey(..., [elg])" << std::endl;
	ret = gcry_pk_genkey(&elgkey, elgparms);
	assert(!ret);
	gcry_sexp_t dsakey, dsaparms;
	std::cout << "gcry_sexp_build(...)" << std::endl;
	ret = gcry_sexp_build(&dsaparms, &erroff, "(genkey (dsa (nbits 4:3072)))");
	assert(!ret);
	std::cout << "gcry_pk_genkey(..., [dsa])" << std::endl;
	ret = gcry_pk_genkey(&dsakey, dsaparms);
	assert(!ret);
	gcry_sexp_t dsakey2, dsaparms2;
	std::cout << "gcry_sexp_build(...)" << std::endl;
	ret = gcry_sexp_build(&dsaparms2, &erroff, "(genkey (dsa (nbits 4:2048)))");
	assert(!ret);
	std::cout << "gcry_pk_genkey(..., [dsa])" << std::endl;
	ret = gcry_pk_genkey(&dsakey2, dsaparms);
	assert(!ret);
	gcry_sexp_t rsakey, rsaparms;
	std::cout << "gcry_sexp_build(...)" << std::endl;
	ret = gcry_sexp_build(&rsaparms, &erroff, "(genkey (rsa (nbits 4:3072)))");
	assert(!ret);
	std::cout << "gcry_pk_genkey(..., [rsa])" << std::endl;
	ret = gcry_pk_genkey(&rsakey, rsaparms);
	assert(!ret);
	time_t creation = time(NULL); // set OpenPGP creation time

	// testing SymmetricEncryptAES256() and SymmetricDecryptAES256()
	// testing AsymmetricEncryptElgamal() and AsymmetricDecryptElgamal()
	tmcg_openpgp_octets_t lit, seskey, prefix, enc, subkeyid;
	std::string m = "This is a test message.", armored_message;
	in.clear();
	for (size_t i = 0; i < m.length(); i++)
		in.push_back(m[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(in, lit);
	std::cout << "SymmetricEncryptAES256(...)" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit,
		seskey, prefix, true, enc);
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
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecryptAES256(enc,
		seskey, prefix, true, out);
	assert(!ret);
	assert(lit.size() == out.size());
	for (size_t i = 0; i < lit.size(); i++)
	{
		assert(lit[i] == out[i]); // check the result
	}

	// testing BinaryDocumentHash()
	std::string filename = "t-rfc4880.tmp";
	time_t filecreation = time(NULL);
	std::ofstream ofs(filename.c_str(), std::ofstream::out);
	assert(ofs.good());
	ofs << "This is a simple test file createt at " <<
		ctime(&filecreation) << std::endl;
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

	// testing AsymmetricSignDSA() and AsymmetricVerifyDSA()
	tmcg_openpgp_octets_t sig;
	std::string armored_signature;
	gcry_mpi_t r, s;
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	std::cout << "AsymmetricSignDSA(...)" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash,
		dsakey, r, s);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(trailer, left,
		r, s, sig);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, sig, armored_signature);
	std::cout << armored_signature << std::endl;
	std::cout << "AsymmetricVerifyDSA(...)" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash,
		dsakey, r, s);
	assert(!ret);
	tmcg_openpgp_octets_t hash2;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		HashCompute(TMCG_OPENPGP_HASHALGO_SHA512, lit, hash2); // SHA512
	std::cout << "AsymmetricSignDSA(...) with truncated hash" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash2,
		dsakey, r, s);
	assert(!ret);
	std::cout << "AsymmetricVerifyDSA(...) with truncated hash" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash2,
		dsakey, r, s);
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
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignRSA(hash,
		rsakey, TMCG_OPENPGP_HASHALGO_SHA256, s);
	assert(!ret);
	std::cout << "AsymmetricVerifyRSA(...)" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyRSA(hash,
		rsakey, TMCG_OPENPGP_HASHALGO_SHA256, s);
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
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, me,
		out);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode(enc, out);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, out, armored_message);
	std::cout << armored_message << std::endl;
	std::cout << "AsymmetricDecryptRSA(...)" << std::endl;
	tmcg_openpgp_octets_t seskey2;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptRSA(me,
		rsakey, seskey2);
	assert(!ret);
	assert(CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(seskey,
		seskey2));
	gcry_mpi_release(me);

	// testing PublicKeyBlockParse(), FingerprintCompute(), KeyidCompute()
	tmcg_openpgp_octets_t all, pub, uid, uidsig, sub, subsig, pubflags, empty;
	tmcg_openpgp_octets_t subflags, keyid, pub_hashing, uidsig_hashing;
	tmcg_openpgp_octets_t uidsig_left, sub_hashing, subsig_hashing, subsig_left;
	std::string armored_pubkeyblock;
	gcry_mpi_t p, q, g, y;
	std::cout << "gcry_sexp_extract_param(...)" << std::endl;
	ret = gcry_sexp_extract_param(dsakey, NULL, "pqgy", &p, &q, &g, &y, NULL);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(creation,
		TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub);
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(keystr, uid);
	pubflags.push_back(0x01 | 0x02);  // certify other keys and sign data
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
			TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, pubflags, keyid,
			uidsig_hashing); 
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing,
		keystr, empty, uidsig_hashing, TMCG_OPENPGP_HASHALGO_SHA256, hash,
		uidsig_left);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	std::cout << "AsymmetricSignDSA()" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash,
		dsakey, r, s);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing,
		uidsig_left, r, s, uidsig);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creation,
		TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y, sub);
	subflags.push_back(0x04 | 0x08); // encrypt communications and storage
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
			TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, subflags, keyid,
			subsig_hashing);
	for (size_t i = 6; i < sub.size(); i++)
		sub_hashing.push_back(sub[i]);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyHash(pub_hashing, sub_hashing,
		subsig_hashing, TMCG_OPENPGP_HASHALGO_SHA256, hash, subsig_left);
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
	std::cout << "CheckSelfSignatures()" << std::endl;
	parse_ok = primary->CheckSelfSignatures(ring, 3);
	assert(parse_ok);
	std::cout << "CheckSubkeys()" << std::endl;
	parse_ok = primary->CheckSubkeys(ring, 3);
	assert(parse_ok);
	std::string fpr, kid;
	std::cout << "FingerprintCompute()" << std::endl;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(primary->pub_hashing, fpr);
	std::cout << fpr << std::endl;
	std::cout << "KeyidCompute()" << std::endl;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(primary->pub_hashing, kid);
	std::cout << kid << std::endl;
	std::cout << "!primary->weak()" << std::endl;
	bool check_ok = primary->weak(3);
	assert(!check_ok);
	delete primary;
	delete ring;
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(r);
	gcry_mpi_release(s);

	// testing SignatureParse()
	sleep(1);
	TMCG_OpenPGP_Signature *signature = NULL;
	std::cout << "SignatureParse()" << std::endl;
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		SignatureParse(armored_signature, 3, signature);
	assert(parse_ok);
	assert(signature->good());
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
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(creation,
		TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub2);
	for (size_t i = 6; i < pub2.size(); i++)
		pub_hashing2.push_back(pub2[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(pub_hashing2, keyid2);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(keystr, uid2);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
			TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, pubflags, keyid2,
			uidsig_hashing2);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing2,
		keystr, empty, uidsig_hashing2, TMCG_OPENPGP_HASHALGO_SHA256, hash,
		uidsig_left2);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	std::cout << "AsymmetricSignDSA()" << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash,
		dsakey2, r, s);
	assert(!ret);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing2,
		uidsig_left2, r, s, uidsig2);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creation,
		TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y, sub2);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
			TMCG_OPENPGP_HASHALGO_SHA256, time(NULL), 1000, subflags, keyid2,
			subsig_hashing2);
	for (size_t i = 6; i < sub2.size(); i++)
		sub_hashing2.push_back(sub2[i]);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyHash(pub_hashing2, sub_hashing2,
		subsig_hashing2, TMCG_OPENPGP_HASHALGO_SHA256, hash, subsig_left2);
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
	assert((ring->size() == 2));
	delete ring;
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(r);
	gcry_mpi_release(s);

	// testing PrivateKeyBlockParse()
// TODO

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
// TODO: reconstruct seskey by decrypting pkesk 
	tmcg_openpgp_octets_t dec;	
	std::cout << "Decrypt()" << std::endl;
	parse_ok = msg->Decrypt(seskey, 3, dec);
	assert(parse_ok);
	std::cout << "MessageParse(dec)" << std::endl;
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		MessageParse(dec, 3, msg);
	assert(parse_ok);
	std::cout << "CheckMDC()" << std::endl;
	parse_ok = msg->CheckMDC(3);
	assert(parse_ok);
	assert(CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(lit,
		msg->literal_message));
	assert(CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(in,
		msg->literal_data));
	delete msg;

	// release keys generated by using libgcrypt
	gcry_sexp_release(elgparms);
	gcry_sexp_release(elgkey);
	gcry_sexp_release(dsaparms);
	gcry_sexp_release(dsakey);
	gcry_sexp_release(dsaparms2);
	gcry_sexp_release(dsakey2);
	gcry_sexp_release(rsaparms);
	gcry_sexp_release(rsakey);
	
	return 0;
}
