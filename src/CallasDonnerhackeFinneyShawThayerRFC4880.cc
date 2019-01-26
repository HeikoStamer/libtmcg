/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.cc, OpenPGP Message Format

     J. Callas, L. Donnerhacke, H. Finney, D. Shaw, R. Thayer:
	 'OpenPGP Message Format',
     Network Working Group, Request for Comments: 4880,
     November 2007.

     A. Jivsov:
     'Elliptic Curve Cryptography (ECC) in OpenPGP',
     Internet Engineering Task Force (IETF), Request for Comments: 6637,
     June 2012.

     W. Koch et al.:
     'OpenPGP Message Format draft-ietf-openpgp-rfc4880bis-06',
     Network Working Group, Internet-Draft,
     November 2018.

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
   along with LibTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "CallasDonnerhackeFinneyShawThayerRFC4880.hh"

// additional headers
#include <cassert>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include "mpz_srandom.hh"
#include "mpz_helper.hh"

TMCG_OpenPGP_Signature::TMCG_OpenPGP_Signature
	(const bool revocable_in,
	 const bool exportable_in,
	 const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const tmcg_openpgp_hashalgo_t hashalgo_in,
	 const tmcg_openpgp_signature_t type_in,
	 const tmcg_openpgp_byte_t version_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const time_t keyexptime_in,
	 const tmcg_openpgp_revcode_t revcode_in,
	 const gcry_mpi_t md,
	 const tmcg_openpgp_octets_t &packet_in,
	 const tmcg_openpgp_octets_t &hspd_in,
	 const tmcg_openpgp_octets_t &issuer_in,
	 const tmcg_openpgp_octets_t &issuerfpr_in,
	 const tmcg_openpgp_octets_t &keyflags_in,
	 const tmcg_openpgp_octets_t &keyfeatures_in,
	 const tmcg_openpgp_octets_t &keyprefs_psa_in,
	 const tmcg_openpgp_octets_t &keyprefs_pha_in,
	 const tmcg_openpgp_octets_t &keyprefs_pca_in,
	 const tmcg_openpgp_octets_t &keyprefs_paa_in,
	 const tmcg_openpgp_octets_t &embeddedsig_in):
		ret(GPG_ERR_BAD_SIGNATURE),
		erroff(0),
		valid(false),
		revoked(false),
		revocable(revocable_in),
		exportable(exportable_in),
		pkalgo(pkalgo_in),
		hashalgo(hashalgo_in),
		type(type_in),
		version(version_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		keyexpirationtime(keyexptime_in),
		revcode(revcode_in)
{
	rsa_md = gcry_mpi_new(2048);
	dsa_r = gcry_mpi_new(8);
	dsa_s = gcry_mpi_new(8);
	gcry_mpi_set(rsa_md, md);
	ret = gcry_sexp_build(&signature, &erroff,
		"(sig-val (rsa (s %M)))", md);
	packet.insert(packet.end(),
		packet_in.begin(), packet_in.end());
	hspd.insert(hspd.end(),
		hspd_in.begin(), hspd_in.end());
	issuer.insert(issuer.end(),
		issuer_in.begin(), issuer_in.end());
	issuerfpr.insert(issuerfpr.end(),
		issuerfpr_in.begin(), issuerfpr_in.end());
	keyflags.insert(keyflags.end(),
		keyflags_in.begin(), keyflags_in.end());
	keyfeatures.insert(keyfeatures.end(), 
		keyfeatures_in.begin(), keyfeatures_in.end());
	keyprefs_psa.insert(keyprefs_psa.end(),
		keyprefs_psa_in.begin(), keyprefs_psa_in.end());
	keyprefs_pha.insert(keyprefs_pha.end(),
		keyprefs_pha_in.begin(), keyprefs_pha_in.end());
	keyprefs_pca.insert(keyprefs_pca.end(),
		keyprefs_pca_in.begin(), keyprefs_pca_in.end());
	keyprefs_paa.insert(keyprefs_paa.end(),
		keyprefs_paa_in.begin(), keyprefs_paa_in.end());
	embeddedsig.insert(embeddedsig.end(),
		embeddedsig_in.begin(), embeddedsig_in.end());
}

TMCG_OpenPGP_Signature::TMCG_OpenPGP_Signature
	(const bool revocable_in,
	 const bool exportable_in,
	 const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const tmcg_openpgp_hashalgo_t hashalgo_in,
	 const tmcg_openpgp_signature_t type_in,
	 const tmcg_openpgp_byte_t version_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const time_t keyexptime_in,
	 const tmcg_openpgp_revcode_t revcode_in,
	 const gcry_mpi_t r,
	 const gcry_mpi_t s,
	 const tmcg_openpgp_octets_t &packet_in,
	 const tmcg_openpgp_octets_t &hspd_in,
	 const tmcg_openpgp_octets_t &issuer_in,
	 const tmcg_openpgp_octets_t &issuerfpr_in,
	 const tmcg_openpgp_octets_t &keyflags_in,
	 const tmcg_openpgp_octets_t &keyfeatures_in,
	 const tmcg_openpgp_octets_t &keyprefs_psa_in,
	 const tmcg_openpgp_octets_t &keyprefs_pha_in,
	 const tmcg_openpgp_octets_t &keyprefs_pca_in,
	 const tmcg_openpgp_octets_t &keyprefs_paa_in,
	 const tmcg_openpgp_octets_t &embeddedsig_in):
		ret(GPG_ERR_BAD_SIGNATURE),
		erroff(0),
		valid(false),
		revoked(false),
		revocable(revocable_in),
		exportable(exportable_in),
		pkalgo(pkalgo_in),
		hashalgo(hashalgo_in),
		type(type_in),
		version(version_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		keyexpirationtime(keyexptime_in),
		revcode(revcode_in)
{
	rsa_md = gcry_mpi_new(8);
	dsa_r = gcry_mpi_new(256);
	dsa_s = gcry_mpi_new(256);
	gcry_mpi_set(dsa_r, r);
	gcry_mpi_set(dsa_s, s);
	if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		ret = gcry_sexp_build(&signature, &erroff,
			"(sig-val (dsa (r %M) (s %M)))", r, s);
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		ret = gcry_sexp_build(&signature, &erroff,
			"(sig-val (ecdsa (r %M) (s %M)))", r, s);
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		ret = gcry_sexp_build(&signature, &erroff,
			"(sig-val (eddsa (r %M) (s %M)))", r, s);
	else
		signature = NULL;
	packet.insert(packet.end(),
		packet_in.begin(), packet_in.end());
	hspd.insert(hspd.end(),
		hspd_in.begin(), hspd_in.end());
	issuer.insert(issuer.end(),
		issuer_in.begin(), issuer_in.end());
	issuerfpr.insert(issuerfpr.end(),
		issuerfpr_in.begin(), issuerfpr_in.end());
	keyflags.insert(keyflags.end(),
		keyflags_in.begin(), keyflags_in.end());
	keyfeatures.insert(keyfeatures.end(),
		keyfeatures_in.begin(), keyfeatures_in.end());
	keyprefs_psa.insert(keyprefs_psa.end(),
		keyprefs_psa_in.begin(), keyprefs_psa_in.end());
	keyprefs_pha.insert(keyprefs_pha.end(),
		keyprefs_pha_in.begin(), keyprefs_pha_in.end());
	keyprefs_pca.insert(keyprefs_pca.end(),
		keyprefs_pca_in.begin(), keyprefs_pca_in.end());
	keyprefs_paa.insert(keyprefs_paa.end(),
		keyprefs_paa_in.begin(), keyprefs_paa_in.end());
	embeddedsig.insert(embeddedsig.end(),
		embeddedsig_in.begin(), embeddedsig_in.end());
}

bool TMCG_OpenPGP_Signature::Good
	() const
{
	return (ret == 0);
}

void TMCG_OpenPGP_Signature::PrintInfo
	() const
{
	std::cerr << "INFO: sig type = 0x" << std::hex << (int)type <<
		std::dec << " pkalgo = " << (int)pkalgo <<
		" hashalgo = " << (int)hashalgo <<
		" revocable = " << (revocable ? "true" : "false") <<
		" exportable = " << (exportable ? "true" : "false") <<
		" version = " << (int)version <<
		" creationtime = " << creationtime <<
		" expirationtime = " << expirationtime <<
		" keyexpirationtime = " << keyexpirationtime <<
		" revcode = " << (int)revcode <<
		" packet.size() = " << packet.size() <<
		" hspd.size() = " << hspd.size() <<
		" issuer = " << std::hex;
		for (size_t i = 0; i < issuer.size(); i++)
			std::cerr << (int)issuer[i] << " ";
		std::cerr << " issuerfpr = ";
		for (size_t i = 0; i < issuerfpr.size(); i++)
			std::cerr << (int)issuerfpr[i] << " ";
		std::cerr << " keyflags = ";
		for (size_t i = 0; i < keyflags.size(); i++)
			std::cerr << (int)keyflags[i] << " ";
		std::cerr << std::dec << 
		" revkeys.size() = " << revkeys.size() << std::endl;
}

bool TMCG_OpenPGP_Signature::CheckValidity
	(const time_t keycreationtime,
	 const int verbose) const
{
	time_t current = time(NULL);
	time_t fmax = 60 * 60 * 25; // deviation time: 25 hours
	time_t vmax = creationtime + expirationtime;
	if (expirationtime && (current > vmax))
	{
		if (verbose)
			std::cerr << "WARNING: signature has been expired" << std::endl;
		return false;
	}
	if (creationtime < keycreationtime)
	{
		if (verbose)
			std::cerr << "WARNING: signature is " <<
				"older than corresponding key" << std::endl;
		return false;
	}
	if (creationtime > (current + fmax))
	{
		if (verbose)
			std::cerr << "WARNING: creation time of " <<
				"signature is in far future" << std::endl;
		return false;
	}
	if ((hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
	    (hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
	    (hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
	{
		if (verbose)
			std::cerr << "WARNING: insecure hash algorithm " << 
				(int)hashalgo << " used for signature" << std::endl;
		// return false;
	}
	return true;
}

bool TMCG_OpenPGP_Signature::CheckIntegrity
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &hash,
	 const int verbose) const
{
	gcry_error_t vret;
	if ((pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		vret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyRSA(hash, key, hashalgo, rsa_md);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		vret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyDSA(hash, key, dsa_r, dsa_s);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		vret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyECDSA(hash, key, dsa_r, dsa_s);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		vret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricVerifyEdDSA(hash, key, dsa_r, dsa_s);
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature algorithm " <<
				"not supported" << std::endl;
		return false;
	}
	if (vret)
	{
		if (verbose)
			std::cerr << "ERROR: verification of signature " <<
				"failed (rc = " << gcry_err_code(vret) <<
				", str = " << gcry_strerror(vret) << ")" << std::endl;
		return false;
	}
	return true;
}

// All signatures are formed by producing a hash over the signature
// data, and then using the resulting hash in the signature algorithm.
// [...]
// Once the data body is hashed, then a trailer is hashed. A V3
// signature hashes five octets of the packet body, starting from the
// signature type field. This data is the signature type, followed by
// the four-octet signature time. A V4 signature hashes the packet body
// starting from its first field, the version number, through the end
// of the hashed subpacket data. Thus, the fields hashed are the
// signature version, the signature type, the public-key algorithm, the
// hash algorithm, the hashed subpacket length, and the hashed
// subpacket body.
// [...]
// After all this has been hashed in a single hash context, the
// resulting hash field is used in the signature algorithm and placed
// at the end of the Signature packet.

bool TMCG_OpenPGP_Signature::VerifyData
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &data,
	 const int verbose) const
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		bool hret;
		switch (type)
		{
			case TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					BinaryDocumentHashV3(data, trailer, hashalgo, hash, left);
				break;
			case TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					TextDocumentHashV3(data, trailer, hashalgo, hash, left);
				break;
			default:
				if (verbose)
					std::cerr << "ERROR: signature type not supported " <<
						std::endl;
				return false;
				break;
		}
		if (!hret)
		{
			if (verbose)
				std::cerr << "ERROR: cannot process input data" << std::endl;
			return false;
		}
	}
	else if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		bool hret;
		switch (type)
		{
			case TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					BinaryDocumentHash(data, trailer, hashalgo, hash, left);
				break;
			case TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					TextDocumentHash(data, trailer, hashalgo, hash, left);
				break;
			default:
				if (verbose)
					std::cerr << "ERROR: signature type not supported " <<
						std::endl;
				return false;
				break;
		}
		if (!hret)
		{
			if (verbose)
				std::cerr << "ERROR: cannot process input data" << std::endl;
			return false;
		}
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
		return true;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const std::string &filename,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		bool hret;
		switch (type)
		{
			case TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					BinaryDocumentHashV3(filename, trailer, hashalgo, hash, left);
				break;
			case TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					TextDocumentHashV3(filename, trailer, hashalgo, hash, left);
				break;
			default:
				if (verbose)
					std::cerr << "ERROR: signature type not supported " <<
						std::endl;
				return false;
				break;
		}
		if (!hret)
		{
			if (verbose)
				std::cerr << "ERROR: cannot process input " <<
					"file \"" << filename << "\"" <<
				std::endl;
			return false;
		}
	}
	else if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		bool hret;
		switch (type)
		{
			case TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					BinaryDocumentHash(filename, trailer, hashalgo, hash, left);
				break;
			case TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT:
				hret = CallasDonnerhackeFinneyShawThayerRFC4880::
					TextDocumentHash(filename, trailer, hashalgo, hash, left);
				break;
			default:
				if (verbose)
					std::cerr << "ERROR: signature type not supported " <<
						std::endl;
				return false;
				break;
		}
		if (!hret)
		{
			if (verbose)
				std::cerr << "ERROR: cannot process input " <<
					"file \"" << filename << "\"" <<
				std::endl;
			return false;
		}
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version " <<
				"not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			StandaloneHashV3(trailer, hashalgo, hash, left);
	}
	else if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			StandaloneHash(trailer, hashalgo, hash, left);
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version " <<
				"not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &hashing,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHashV3(hashing, trailer, hashalgo, hash, left);
	}
	else if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(hashing, trailer, hashalgo, hash, left);
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version " <<
				"not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &pub_hashing,
	 const tmcg_openpgp_octets_t &sub_hashing,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHashV3(pub_hashing, sub_hashing, trailer, hashalgo, hash, left);
	}
	else if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, sub_hashing, trailer, hashalgo, hash, left);
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version " <<
				"not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &pub_hashing,
	 const std::string &userid,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 3)
	{
		tmcg_openpgp_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketTimeEncode(creationtime, sigtime_octets);
		trailer.push_back(type);
		trailer.insert(trailer.end(),
			sigtime_octets.begin(), sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHashV3(pub_hashing, userid, trailer,
			hashalgo, hash, left);
	}
	else if (version == 4)
	{
		tmcg_openpgp_octets_t empty;
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing, userid, empty, trailer,
			hashalgo, hash, left);	
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version " <<
				"not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::Verify
	(const gcry_sexp_t key,
	 const tmcg_openpgp_octets_t &pub_hashing,
	 const tmcg_openpgp_octets_t &userattribute,
	 const int dummy,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad signature material" <<	std::endl;
		return false;
	}
	tmcg_openpgp_octets_t trailer, left, hash;
	if (version == 4)
	{
		trailer.push_back(4);
		trailer.push_back(type);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back((hspd.size() >> 8) & 0xFF);
		trailer.push_back(hspd.size() & 0xFF);
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing, "", userattribute, trailer,
			hashalgo, hash, left);
		if (dummy)
			trailer.clear();
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: signature version" <<
				" not supported" << std::endl;
		return false;
	}
	if (verbose > 2)
		std::cerr << "INFO: left = " << std::hex << (int)left[0] <<
			" " << (int)left[1] << std::dec << std::endl;
	if (CheckIntegrity(key, hash, verbose))
	{
		valid = true;
		return true;
	}
	valid = false;
	return false;
}

bool TMCG_OpenPGP_Signature::operator <
	(const TMCG_OpenPGP_Signature &that) const
{
	return (creationtime < that.creationtime);
}

TMCG_OpenPGP_Signature::~TMCG_OpenPGP_Signature
	()
{
	gcry_mpi_release(rsa_md);
	gcry_mpi_release(dsa_r);
	gcry_mpi_release(dsa_s);
	if (!ret && (signature != NULL))
		gcry_sexp_release(signature);
	packet.clear();
	hspd.clear();
	issuer.clear();
	issuerfpr.clear();
	keyflags.clear();
	keyfeatures.clear();
	keyprefs_psa.clear();
	keyprefs_pha.clear();
	keyprefs_pca.clear();
	keyprefs_paa.clear();
	revkeys.clear();
}

bool TMCG_OpenPGP_Signature_Compare
	(TMCG_OpenPGP_Signature *sigf, TMCG_OpenPGP_Signature *sigs)
{
	return (*sigf < *sigs);
}

// ===========================================================================

TMCG_OpenPGP_UserID::TMCG_OpenPGP_UserID
	(const std::string &userid_in,
	 const tmcg_openpgp_octets_t &packet_in):
		valid(false),
		revoked(false),
		userid(userid_in)
{
	userid_sanitized.resize(userid.size());
	std::transform(userid.begin(), userid.end(),
		userid_sanitized.begin(), ClearForbiddenCharacter);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

bool TMCG_OpenPGP_UserID::Check
	(const TMCG_OpenPGP_Pubkey *primary,
	 const int verbose)
{
	// Note that one valid certification revocation signature makes
	// the whole user ID invalid. I guess this is widely-used practice.
	for (size_t j = 0; j < revsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			revsigs[j]->PrintInfo();
		if (!revsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (revsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		if (revsigs[j]->Verify(primary->key, primary->pub_hashing,
		                       userid, verbose))
		{
			// set the revoked flag for all self-signatures
			for (size_t i = 0; i < selfsigs.size(); i++)
			{
				if (selfsigs[i]->revocable)
					selfsigs[i]->revoked = true;
			}
			revoked = true;
		}
		else if (verbose)
			std::cerr << "WARNING: revocation signature" <<
				"verification failed" << std::endl;
	}
	bool one_valid_selfsig = false;
	std::sort(selfsigs.begin(), selfsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < selfsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			selfsigs[j]->PrintInfo();
		if (!selfsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (selfsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the self-signature cryptographically
		if (selfsigs[j]->Verify(primary->key, primary->pub_hashing,
		                        userid, verbose))
		{
			one_valid_selfsig = true;
		}
		else if (verbose)
			std::cerr << "WARNING: self-signature verification" <<
				" failed" << std::endl;
	}
	// update validity state of this user ID and return the result
	if (one_valid_selfsig)
	{
		valid = true;
		return true;
	}
	else
	{
		valid = false;
		return false;
	}
}

TMCG_OpenPGP_UserID::~TMCG_OpenPGP_UserID
	()
{
	packet.clear();
	for (size_t i = 0; i < selfsigs.size(); i++)
		delete selfsigs[i];
	selfsigs.clear();
	for (size_t i = 0; i < revsigs.size(); i++)
		delete revsigs[i];
	revsigs.clear();
	for (size_t i = 0; i < certsigs.size(); i++)
		delete certsigs[i];
	certsigs.clear();
}

// ===========================================================================

TMCG_OpenPGP_UserAttribute::TMCG_OpenPGP_UserAttribute
	(const tmcg_openpgp_octets_t &userattribute_in,
	 const tmcg_openpgp_octets_t &packet_in):
		valid(false),
		revoked(false)
{
	userattribute.insert(userattribute.end(),
		userattribute_in.begin(), userattribute_in.end());
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

bool TMCG_OpenPGP_UserAttribute::Check
	(const TMCG_OpenPGP_Pubkey *primary,
	 const int verbose)
{
	// Note that one valid certification revocation signature makes
	// the whole user attribute invalid. I guess this is widely-used practice.
	for (size_t j = 0; j < revsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			revsigs[j]->PrintInfo();
		if (!revsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (revsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		if (revsigs[j]->Verify(primary->key, primary->pub_hashing,
		                       userattribute, 0, verbose))
		{
			// set the revoked flag for all self-signatures
			for (size_t i = 0; i < selfsigs.size(); i++)
			{
				if (selfsigs[i]->revocable)
					selfsigs[i]->revoked = true;
			}
			revoked = true;
		}
		else if (verbose)
			std::cerr << "WARNING: revocation signature" <<
				" verification failed" << std::endl;
	}
	bool one_valid_selfsig = false;
	std::sort(selfsigs.begin(), selfsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < selfsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			selfsigs[j]->PrintInfo();
		if (!selfsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (selfsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the self-signature cryptographically
		if (selfsigs[j]->Verify(primary->key, primary->pub_hashing,
		                        userattribute, 0, verbose))
		{
			one_valid_selfsig = true;
		}
		else if (verbose)
			std::cerr << "WARNING: self-signature verification" <<
				" failed" << std::endl;
	}
	// update validity state of this user attribute and return the result
	if (one_valid_selfsig)
	{
		valid = true;
		return true;
	}
	else
	{
		valid = false;
		return false;
	}
}

TMCG_OpenPGP_UserAttribute::~TMCG_OpenPGP_UserAttribute
	()
{
	userattribute.clear();
	packet.clear();
	for (size_t i = 0; i < selfsigs.size(); i++)
		delete selfsigs[i];
	selfsigs.clear();
	for (size_t i = 0; i < revsigs.size(); i++)
		delete revsigs[i];
	revsigs.clear();
	for (size_t i = 0; i < certsigs.size(); i++)
		delete certsigs[i];
	certsigs.clear();
}

// ===========================================================================

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	():
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(TMCG_OPENPGP_PKALGO_RSA),
		creationtime(0),
		expirationtime(0),
		key(NULL),
		ec_curve(""),
		kdf_hashalgo(TMCG_OPENPGP_HASHALGO_UNKNOWN),
		kdf_skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT)
{
	// this is a dummy constructor used for simple relinking
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	elg_p = gcry_mpi_new(8);
	elg_g = gcry_mpi_new(8);
	elg_y = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(8);
	gcry_mpi_set_ui(rsa_n, 437);
	gcry_mpi_set_ui(rsa_e, 41);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (rsa (n %M) (e %M)))", rsa_n, rsa_e);
}

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t n,
	 const gcry_mpi_t e,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve(""),
		kdf_hashalgo(TMCG_OPENPGP_HASHALGO_UNKNOWN),
		kdf_skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT)
{
	rsa_n = gcry_mpi_new(2048);
	rsa_e = gcry_mpi_new(256);
	elg_p = gcry_mpi_new(8);
	elg_g = gcry_mpi_new(8);
	elg_y = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(8);
	// public-key algorithm is RSA
	gcry_mpi_set(rsa_n, n);
	gcry_mpi_set(rsa_e, e);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (rsa (n %M) (e %M)))", n, e);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, sub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(sub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(sub_hashing, fingerprint);
}

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve(""),
		kdf_hashalgo(TMCG_OPENPGP_HASHALGO_UNKNOWN),
		kdf_skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT)
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	elg_p = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(8);
	// public-key algorithm is ElGamal
	gcry_mpi_set(elg_p, p);
	gcry_mpi_set(elg_g, g);
	gcry_mpi_set(elg_y, y);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (elg (p %M) (g %M) (y %M)))", p, g, y);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, sub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(sub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(sub_hashing, fingerprint);
}

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve(""),
		kdf_hashalgo(TMCG_OPENPGP_HASHALGO_UNKNOWN),
		kdf_skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT)
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	elg_p = gcry_mpi_new(8);
	elg_g = gcry_mpi_new(8);
	elg_y = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(512);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	ec_pk = gcry_mpi_new(8);
	// public-key algorithm is DSA
	gcry_mpi_set(dsa_p, p);
	gcry_mpi_set(dsa_q, q);
	gcry_mpi_set(dsa_g, g);
	gcry_mpi_set(dsa_y, y);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", p, q, g, y);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, sub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(sub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(sub_hashing, fingerprint);
}

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		kdf_hashalgo(TMCG_OPENPGP_HASHALGO_UNKNOWN),
		kdf_skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT)
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	elg_p = gcry_mpi_new(8);
	elg_g = gcry_mpi_new(8);
	elg_y = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(1024);
	// public-key algorithm is ECDSA/EdDSA
	gcry_mpi_set(ec_pk, ecpk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{ 
		ret = gcry_sexp_build(&key, &erroff,
			"(public-key (ecdsa (curve %s) (q %m)))", curve, ecpk);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		ret = gcry_sexp_build(&key, &erroff,
			"(public-key (ecc (curve %s) (flags eddsa) (q %m)))", curve, ecpk);
	}
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, sub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(sub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(sub_hashing, fingerprint);
}

TMCG_OpenPGP_Subkey::TMCG_OpenPGP_Subkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const tmcg_openpgp_hashalgo_t kdf_hashalgo_in,
	 const tmcg_openpgp_skalgo_t kdf_skalgo_in,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		kdf_hashalgo(kdf_hashalgo_in),
		kdf_skalgo(kdf_skalgo_in)
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	elg_p = gcry_mpi_new(8);
	elg_g = gcry_mpi_new(8);
	elg_y = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(1024);
	// public-key algorithm is ECDH
	gcry_mpi_set(ec_pk, ecpk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (ecdh (curve %s) (q %m)))", curve, ecpk);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, sub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(sub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(sub_hashing, fingerprint);
}

bool TMCG_OpenPGP_Subkey::Good
	() const
{
	return (ret == 0);
}

bool TMCG_OpenPGP_Subkey::Weak
	(const int verbose) const
{
	gcry_error_t wret;
	if ((pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int nbits = 0, ebits = 0;
		nbits = gcry_mpi_get_nbits(rsa_n);
		ebits = gcry_mpi_get_nbits(rsa_e);
		if (verbose > 1)
			std::cerr << "INFO: RSA with |n| = " <<
				nbits << " bits, |e| = " <<
				ebits << " bits" << std::endl;
		if ((nbits < 2048) || (ebits < 6))
			return true; // weak key
		wret = gcry_prime_check(rsa_e, 0);
		if (wret)
			return true; // e is not a prime
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
	{
		unsigned int pbits = 0, gbits = 0, ybits = 0;
		pbits = gcry_mpi_get_nbits(elg_p);
		gbits = gcry_mpi_get_nbits(elg_g);
		ybits = gcry_mpi_get_nbits(elg_y);
		if (verbose > 1)
			std::cerr << "INFO: ElGamal with |p| = " <<
				pbits << " bits, |g| = " <<
				gbits << " bits, |y| = " <<
				ybits << " bits" << std::endl;
		if ((pbits < 2048) || (gbits < 2) || (ybits < 2))
			return true; // weak key
		wret = gcry_prime_check(elg_p, 0);
		if (wret)
			return true; // p is not a prime
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		unsigned int pbits = 0, qbits = 0, gbits = 0, ybits = 0;
		pbits = gcry_mpi_get_nbits(dsa_p);
		qbits = gcry_mpi_get_nbits(dsa_q);
		gbits = gcry_mpi_get_nbits(dsa_g);
		ybits = gcry_mpi_get_nbits(dsa_y);
		if (verbose > 1)
			std::cerr << "INFO: DSA with |p| = " <<
				pbits << " bits, |q| = " <<
				qbits << " bits, |g| = " <<
				gbits << " bits, |y| = " <<
				ybits << " bits" <<	std::endl;
		if ((pbits < 2048) || (qbits < 256) || (gbits < 2) || (ybits < 2))
			return true; // weak key
		wret = gcry_prime_check(dsa_p, 0);
		if (wret)
			return true; // p is not a prime
		wret = gcry_prime_check(dsa_q, 0);
		if (wret)
			return true; // q is not a prime
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
		if (curvename != NULL)
		{
			if (verbose > 1)
			{
				std::cerr << "INFO: ECDH with curve \"" << curvename <<
					"\" and " << curvebits << " bits" << std::endl;
				std::cerr << "INFO: ECDH with KDF hashalgo = " <<
					(int)kdf_hashalgo << " and KEK skalgo = " <<
					(int)kdf_skalgo << std::endl;
			}
			if (curvebits < 256)
				return true; // weak key
			if ((kdf_hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
			    (kdf_hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
				(kdf_hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
			{
				return true; // weak KDF hash algorithm
			}
			if ((kdf_skalgo != TMCG_OPENPGP_SKALGO_AES128) &&
			    (kdf_skalgo != TMCG_OPENPGP_SKALGO_AES192) &&
				(kdf_skalgo != TMCG_OPENPGP_SKALGO_AES256))
			{
				return true; // weak KEK algorithm
			}
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: ECDH with unknown curve" << std::endl;
			return true; // unknown curve
		}
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
		if (curvename != NULL)
		{
			if (verbose > 1)
				std::cerr << "INFO: ECDSA with curve \"" << curvename <<
					"\" and " << curvebits << " bits" << std::endl;
			if (curvebits < 256)
				return true; // weak key
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: ECDSA with unknown curve" << std::endl;
			return true; // unknown curve
		}
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
		if (curvename != NULL)
		{
			if (verbose > 1)
				std::cerr << "INFO: EdDSA with curve \"" << curvename <<
					"\" and " << curvebits << " bits" << std::endl;
			if (curvebits < 256)
				return true; // weak key
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: EdDSA with unknown curve" << std::endl;
			return true; // unknown curve
		}
	}
	else
		return true; // unknown public-key algorithm
	return false;
}

size_t TMCG_OpenPGP_Subkey::AccumulateFlags
	() const
{
	size_t allflags = 0;
	for (size_t i = 0; i < flags.size(); i++)
	{
		if (flags[i] && (i < 3)) // FIXME: only 3 octets of flags recognized
			allflags += ((size_t)flags[i] << (8 * i));
	}
	return allflags;
}

size_t TMCG_OpenPGP_Subkey::AccumulateFeatures
	() const
{
	size_t allfeatures = 0;
	for (size_t i = 0; i < features.size(); i++)
	{
		if (features[i] && (i < 3)) // FIXME: only 3 octets of flags recognized
			allfeatures += ((size_t)features[i] << (8 * i));
	}
	return allfeatures;
}

tmcg_openpgp_revcode_t TMCG_OpenPGP_Subkey::AccumulateRevocationCodes
	() const
{
	tmcg_openpgp_revcode_t revcode = TMCG_OPENPGP_REVCODE_NO_REASON_SPECIFIED;
	for (size_t j = 0; j < keyrevsigs.size(); j++)
	{
		if ((revcode == TMCG_OPENPGP_REVCODE_NO_REASON_SPECIFIED) ||
			(revcode == TMCG_OPENPGP_REVCODE_KEY_COMPROMISED))
		{
			revcode = keyrevsigs[j]->revcode;
		}
	}
	return revcode;
}

void TMCG_OpenPGP_Subkey::UpdateProperties
	(const TMCG_OpenPGP_Signature *sig,
	 const int verbose)
{
	expirationtime = sig->keyexpirationtime;
	if (verbose > 1)
		std::cerr << "INFO: subkey update expirationtime to " <<
			expirationtime << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update flags to " << std::hex;
	flags.clear();			
	for (size_t i = 0; i < sig->keyflags.size(); i++)
	{
		flags.push_back(sig->keyflags[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyflags[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::dec << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update features to " << std::hex;
	features.clear();
	for (size_t i = 0; i < sig->keyfeatures.size(); i++)
	{
		features.push_back(sig->keyfeatures[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyfeatures[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::dec << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update psa to ";
	psa.clear();
	for (size_t i = 0; i < sig->keyprefs_psa.size(); i++)
	{
		psa.push_back(sig->keyprefs_psa[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_psa[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update pha to ";
	pha.clear();
	for (size_t i = 0; i < sig->keyprefs_pha.size(); i++)
	{
		pha.push_back(sig->keyprefs_pha[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_pha[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update pca to ";
	pca.clear();
	for (size_t i = 0; i < sig->keyprefs_pca.size(); i++)
	{
		pca.push_back(sig->keyprefs_pca[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_pca[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update paa to ";
	paa.clear();
	for (size_t i = 0; i < sig->keyprefs_paa.size(); i++)
	{
		paa.push_back(sig->keyprefs_paa[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_paa[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: subkey update revkeys with added ";
	for (size_t i = 0; i < sig->revkeys.size(); i++)
	{
		tmcg_openpgp_revkey_t rk = sig->revkeys[i];
		revkeys.push_back(rk);
		if (verbose > 1)
		{
			size_t fprlen = 0;
			if ((rk.key_fingerprint[20] == 0x00) &&
				(rk.key_fingerprint[21] == 0x00) &&
				(rk.key_fingerprint[22] == 0x00) &&
				(rk.key_fingerprint[23] == 0x00) &&
				(rk.key_fingerprint[24] == 0x00) &&
				(rk.key_fingerprint[25] == 0x00) &&
				(rk.key_fingerprint[26] == 0x00) &&
				(rk.key_fingerprint[27] == 0x00) &&
				(rk.key_fingerprint[28] == 0x00) &&
				(rk.key_fingerprint[29] == 0x00) &&
				(rk.key_fingerprint[30] == 0x00) &&
				(rk.key_fingerprint[31] == 0x00))
			{
				fprlen = 20; // V4 key
			}
			else
				fprlen = 32; // V5 key			
			tmcg_openpgp_octets_t fpr(rk.key_fingerprint,
				 rk.key_fingerprint+fprlen);
			std::string fpr_str;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintConvertPretty(fpr, fpr_str);
			std::cerr << "[" << fpr_str << "]";
		}
	}
	if (verbose > 1)
		std::cerr << std::endl;
}

bool TMCG_OpenPGP_Subkey::CheckValidity
	(const int verbose) const
{
	time_t current = time(NULL);
	time_t fmax = 60 * 60 * 25; // deviation time: 25 hours
	time_t kmax = creationtime + expirationtime;
	if (expirationtime && (current > kmax))
	{
		if (verbose)
			std::cerr << "WARNING: subkey has been expired" <<
				std::endl;
		return false;
	}
	if (creationtime > (current + fmax))
	{
		if (verbose)
			std::cerr << "WARNING: subkey has been created " <<
				"in far future" << std::endl;
		return false;
	}
	return true;
}

bool TMCG_OpenPGP_Subkey::CheckValidityPeriod
	(const time_t at, const int verbose) const
{
	time_t kmax = creationtime + expirationtime;
	if (expirationtime && (at > kmax))
	{
		if (verbose)
			std::cerr << "WARNING: not in validity period of subkey" <<
				std::endl;
		return false;
	}
	if (creationtime > at)
	{
		if (verbose)
			std::cerr << "WARNING: not in validity period of subkey" <<
				std::endl;
		return false;
	}
	return true;
}

bool TMCG_OpenPGP_Subkey::CheckExternalRevocation
	(TMCG_OpenPGP_Signature* sig, const TMCG_OpenPGP_Keyring* ring,
	 const int verbose)
{
	bool valid_revsig = false;
	for (size_t k = 0; k < revkeys.size(); k++)
	{
		size_t fprlen = 0;
		if ((revkeys[k].key_fingerprint[20] == 0x00) &&
			(revkeys[k].key_fingerprint[21] == 0x00) &&
			(revkeys[k].key_fingerprint[22] == 0x00) &&
			(revkeys[k].key_fingerprint[23] == 0x00) &&
			(revkeys[k].key_fingerprint[24] == 0x00) &&
			(revkeys[k].key_fingerprint[25] == 0x00) &&
			(revkeys[k].key_fingerprint[26] == 0x00) &&
			(revkeys[k].key_fingerprint[27] == 0x00) &&
			(revkeys[k].key_fingerprint[28] == 0x00) &&
			(revkeys[k].key_fingerprint[29] == 0x00) &&
			(revkeys[k].key_fingerprint[30] == 0x00) &&
			(revkeys[k].key_fingerprint[31] == 0x00))
		{
			fprlen = 20; // V4 key
		}
		else
			fprlen = 32; // V5 key
		tmcg_openpgp_octets_t fpr(revkeys[k].key_fingerprint,
			revkeys[k].key_fingerprint+fprlen);
		std::string fprstr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPlain(fpr, fprstr);
		if (verbose > 2)
			std::cerr << "INFO: looking for external revocation" <<
				" key with fingerprint " << fprstr << std::endl;
		TMCG_OpenPGP_Pubkey *revkey = ring->Find(fprstr);
		if (revkey != NULL)
		{
			if (!revkey->valid && !revkey->revoked)
			{
				// disable external revocations to avoid recursion
				revkey->CheckSelfSignatures(ring, verbose, false);
			}
			if (!revkey->valid)
			{
				if (verbose)
					std::cerr << "WARNING: revocation key is not valid" <<
						std::endl;
				continue;
			}
			if (sig->Verify(revkey->key, sub_hashing, verbose))
				valid_revsig = true;
		}
	}
	return valid_revsig;
}

bool TMCG_OpenPGP_Subkey::Check
	(const TMCG_OpenPGP_Pubkey *primary,
	 const TMCG_OpenPGP_Keyring *ring,
	 const int verbose)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad key material" << std::endl;
		return false;
	}
	// print statistics of subkey
	if (verbose > 1)
	{
		std::cerr << "INFO: key ID of subkey: " << std::hex;
		for (size_t i = 0; i < id.size(); i++)
			std::cerr << (int)id[i] << " ";
		std::cerr << std::dec << std::endl;
		std::cerr << "INFO: fingerprint of subkey: " << std::hex;
		for (size_t i = 0; i < fingerprint.size(); i++)
			std::cerr << (int)fingerprint[i] << " ";
		std::cerr << std::dec << std::endl;
		std::cerr << "INFO: number of selfsigs = " << 
			selfsigs.size() << std::endl;
		std::cerr << "INFO: number of bindsigs = " << 
			bindsigs.size() << std::endl;
		std::cerr << "INFO: number of pbindsigs = " << 
			pbindsigs.size() << std::endl;
		std::cerr << "INFO: number of keyrevsigs = " <<
			keyrevsigs.size() << std::endl;
		std::cerr << "INFO: number of certrevsigs = " <<
			certrevsigs.size() << std::endl;
		std::cerr << "INFO: number of revkeys = " <<
			revkeys.size() << std::endl;
	}
	// check whether there are valid revocation signatures for 0x1f sigs
	for (size_t j = 0; j < certrevsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			certrevsigs[j]->PrintInfo();
		if (!certrevsigs[j]->CheckValidity(primary->creationtime,
		    verbose))
			continue; // ignore an expired signature
		if (!certrevsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (certrevsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		bool valid_revsig = false;
		if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(primary->id, certrevsigs[j]->issuer))
		{
			if (certrevsigs[j]->Verify(primary->key, sub_hashing, verbose))
				valid_revsig = true;
			else if (verbose)
				std::cerr << "ERROR: signature verification" <<
					" failed" << std::endl;
		}
		else if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(id, certrevsigs[j]->issuer))
		{
			if (certrevsigs[j]->Verify(key, sub_hashing, verbose))
				valid_revsig = true;
			else if (verbose)
				std::cerr << "ERROR: signature verification" <<
					" failed" << std::endl;
		}
		else
		{
			valid_revsig = CheckExternalRevocation(certrevsigs[j], ring,
				verbose);
			if (!valid_revsig && verbose)
				std::cerr << "WARNING: cannot verify revocation " <<
					"signature of an external key due to missing " <<
					"public key" << std::endl;
		}
		if (valid_revsig)
		{
			if (verbose)
				std::cerr << "WARNING: valid certification " <<
					"revocation signature found for " <<
					"subkey" << std::endl;			
			// TODO: check certrevsig.creationtime > selfsig.creation time
			// TODO: mark ONLY corresponding 0x1f sig from selfsigs as revoked
			// TODO: evaluate signature target subpacket, if available
			// WORKAROUND: set the revoked flag for all self-signatures
			for (size_t i = 0; i < selfsigs.size(); i++)
			{
				if (selfsigs[i]->revocable)
					selfsigs[i]->revoked = true;
			}
		}
		else if (verbose)
			std::cerr << "WARNING: invalid certification revocation " <<
				"signature found for subkey" << std::endl;
	}
	// check whether some self-signatures (0x1f) on subkey are valid
	std::sort(selfsigs.begin(), selfsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < selfsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			selfsigs[j]->PrintInfo();
		if (!selfsigs[j]->CheckValidity(primary->creationtime,
		    verbose))
			continue; // ignore an expired signature
		if (!selfsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (selfsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the self-signature cryptographically
		if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(primary->id, selfsigs[j]->issuer))
		{
			if (selfsigs[j]->Verify(primary->key, sub_hashing,
			    verbose))
			{
				UpdateProperties(selfsigs[j], verbose);
			}
			else
			{
				if (verbose)
					std::cerr << "WARNING: self-signature verification" <<
						" failed" << std::endl;
			}
		}
		else if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(id, selfsigs[j]->issuer))
		{
			if (selfsigs[j]->Verify(key, sub_hashing, verbose))
			{
				UpdateProperties(selfsigs[j], verbose);
			}
			else
			{
				if (verbose)
					std::cerr << "WARNING: self-signature verification" <<
						" failed" << std::endl;
			}
		}
		else if (verbose)
			std::cerr << "WARNING: unknown issuer of self-signature" <<
				std::endl;
	}
	// check validity of subkey
	if (!CheckValidity(verbose))
	{
		valid = false;
		return false;
	}
	// check whether there is at least one valid subkey binding signature
	bool one_valid_bind = false;
	std::sort(bindsigs.begin(), bindsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < bindsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			bindsigs[j]->PrintInfo();
		if (!bindsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (!bindsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (bindsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the binding signature cryptographically
		if (bindsigs[j]->type == TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING)
		{
			if (bindsigs[j]->Verify(primary->key,
			    primary->pub_hashing, sub_hashing, verbose))
			{
				one_valid_bind = true;
				UpdateProperties(bindsigs[j], verbose);
			}
			else
			{
				if (verbose)
					std::cerr << "WARNING: binding signature verification " <<
						"failed" << std::endl;
			}
		}
		else if (verbose)
			std::cerr << "WARNING: unknown binding signature " <<
				"of type 0x" << std::hex <<
				(int)bindsigs[j]->type << std::dec << std::endl;
	}
	// check validity again because property updates has been applied
	if (!CheckValidity(verbose))
	{
		valid = false;
		return false;
	}
	// check whether valid key revocation signature exists for this subkey
	std::sort(keyrevsigs.begin(), keyrevsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < keyrevsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			keyrevsigs[j]->PrintInfo();
		if (!keyrevsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (!keyrevsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (keyrevsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		bool valid_revsig = false;
		if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(primary->id, keyrevsigs[j]->issuer))
		{
			if (keyrevsigs[j]->Verify(primary->key, primary->pub_hashing,
			    sub_hashing, verbose))
				valid_revsig = true;
			else if (verbose)
				std::cerr << "ERROR: signature verification failed" <<
					std::endl;
		}
		else
		{
			valid_revsig = CheckExternalRevocation(keyrevsigs[j], ring,
				verbose);
			if (!valid_revsig && verbose)
				std::cerr << "WARNING: cannot verify revocation " <<
					"signature of an external key due to missing " <<
					"public key" << std::endl;
		}
		if (valid_revsig)
		{
			if (verbose)
				std::cerr << "WARNING: valid revocation signature found " <<
					"for subkey" << std::endl;
			valid = false;
			revoked = true;
			return false;
		}
		else if (verbose)
			std::cerr << "WARNING: invalid revocation signature" <<
				" found for subkey" << std::endl;
	}
	// last but not least, check whether there is a valid subkey binding
	// signature and a valid primary key binding signature, if subkey is
	// a signing key
	bool one_valid_pbind = false;
	std::sort(pbindsigs.begin(), pbindsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < pbindsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			pbindsigs[j]->PrintInfo();
		if (!pbindsigs[j]->CheckValidity(primary->creationtime, verbose))
			continue; // ignore an expired signature
		if (!pbindsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (pbindsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the binding signature cryptographically
		if (pbindsigs[j]->type == TMCG_OPENPGP_SIGNATURE_PRIMARY_KEY_BINDING)
		{
			if (pbindsigs[j]->Verify(key, primary->pub_hashing, sub_hashing,
			    verbose))
			{
				one_valid_pbind = true;
			}
			else
			{
				if (verbose)
					std::cerr << "WARNING: pbinding signature verification " <<
						"failed" << std::endl;
			}
		}
		else if (verbose)
			std::cerr << "WARNING: unknown pbinding signature " <<
				"of type 0x" << std::hex <<
				(int)pbindsigs[j]->type << std::dec << std::endl;
	}
	bool signing_subkey = false;
	size_t allflags = AccumulateFlags();
	if ((allflags & 0x01) == 0x01)
		signing_subkey = true;
	if ((allflags & 0x02) == 0x02)
		signing_subkey = true;
	// update validity state of this key and return the result
	if (one_valid_bind)
	{
		if (signing_subkey)
		{
			if (one_valid_pbind)
			{
				valid = true;
				return true;
			}
			else
			{
				valid = false;
				return false;
			}
		}
		else
		{
			valid = true;
			return true;
		}
	}
	else
	{
		valid = false;
		return false;
	}
}

TMCG_OpenPGP_Subkey::~TMCG_OpenPGP_Subkey
	()
{
	gcry_mpi_release(rsa_n);
	gcry_mpi_release(rsa_e);
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(ec_pk);
	if (ret == 0)
		gcry_sexp_release(key);
	packet.clear();
	sub_hashing.clear();
	id.clear();
	flags.clear();
	features.clear();
	psa.clear();
	pha.clear();
	pca.clear();
	paa.clear();
	for (size_t i = 0; i < selfsigs.size(); i++)
		delete selfsigs[i];
	selfsigs.clear();
	for (size_t i = 0; i < bindsigs.size(); i++)
		delete bindsigs[i];
	bindsigs.clear();
	for (size_t i = 0; i < pbindsigs.size(); i++)
		delete pbindsigs[i];
	pbindsigs.clear();
	for (size_t i = 0; i < keyrevsigs.size(); i++)
		delete keyrevsigs[i];
	keyrevsigs.clear();
	for (size_t i = 0; i < certrevsigs.size(); i++)
		delete certrevsigs[i];
	certrevsigs.clear();
	revkeys.clear();
}

// ===========================================================================

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t n,
	 const gcry_mpi_t e,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t u,
	 const gcry_mpi_t d,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		telg_n(0),
		telg_t(0),
		telg_i(0),
		ec_curve("")
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creationtime_in,
		pkalgo_in, n, e, e, e, sub);
	pub = new TMCG_OpenPGP_Subkey(pkalgo_in, creationtime_in, expirationtime_in,
		n, e, sub);
	rsa_p = gcry_mpi_snew(2048);
	rsa_q = gcry_mpi_snew(2048);
	rsa_u = gcry_mpi_snew(2048);
	rsa_d = gcry_mpi_snew(2048);
	elg_x = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(8);
	telg_q = gcry_mpi_new(8);
	telg_h = gcry_mpi_new(8);
	telg_x_i = gcry_mpi_snew(8);
	telg_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is RSA
	gcry_mpi_set(rsa_p, p);
	gcry_mpi_set(rsa_q, q);
	gcry_mpi_set(rsa_u, u);
	gcry_mpi_set(rsa_d, d);
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (rsa (n %M) (e %M) (d %M) (p %M) (q %M) (u %M)))",
		n, e, d, p, q, u);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const gcry_mpi_t x,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		telg_n(0),
		telg_t(0),
		telg_i(0),
		ec_curve("")
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creationtime_in,
		pkalgo_in, p, p, g, y, sub);
	pub = new TMCG_OpenPGP_Subkey(pkalgo_in, creationtime_in, expirationtime_in,
		p, g, y, sub);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	elg_x = gcry_mpi_snew(256);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(8);
	telg_q = gcry_mpi_new(8);
	telg_h = gcry_mpi_new(8);
	telg_x_i = gcry_mpi_snew(8);
	telg_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is ElGamal
	gcry_mpi_set(elg_x, x);
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (elg (p %M) (g %M) (y %M) (x %M)))", p, g, y, x);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const gcry_mpi_t x,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		telg_n(0),
		telg_t(0),
		telg_i(0),
		ec_curve("")
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creationtime_in,
		pkalgo_in, p, q, g, y, sub);
	pub = new TMCG_OpenPGP_Subkey(pkalgo_in, creationtime_in, expirationtime_in,
		p, q, g, y, sub);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	elg_x = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(256);
	ec_sk = gcry_mpi_snew(8);
	telg_q = gcry_mpi_new(8);
	telg_h = gcry_mpi_new(8);
	telg_x_i = gcry_mpi_snew(8);
	telg_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is DSA
	gcry_mpi_set(dsa_x, x);
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))",
		p, q, g, y, x);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t h,
	 const gcry_mpi_t y,
	 const gcry_mpi_t x_i,
	 const gcry_mpi_t xprime_i,
	 const gcry_mpi_t n_in,
	 const gcry_mpi_t t_in,
	 const gcry_mpi_t i_in,
	 const std::vector<gcry_mpi_t> &qual,
	 const std::vector<gcry_mpi_t> &v_i,
	 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		ec_curve("")
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(creationtime_in,
		TMCG_OPENPGP_PKALGO_ELGAMAL, p, p, g, y, sub);
	pub = new TMCG_OpenPGP_Subkey(TMCG_OPENPGP_PKALGO_ELGAMAL, creationtime_in,
		expirationtime_in, p, g, y, sub);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	elg_x = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(8);
	telg_q = gcry_mpi_new(2048);
	telg_h = gcry_mpi_new(2048);
	telg_x_i = gcry_mpi_snew(256);
	telg_xprime_i = gcry_mpi_snew(256);
	// public-key algorithm is tElG (threshold ElGamal)
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (elg (p %M) (g %M) (y %M) (x %M)))",
		p, g, y, h); // NOTE: this is only a dummy private key
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	gcry_mpi_set(telg_q, q);
	gcry_mpi_set(telg_h, h);
	gcry_mpi_set(telg_x_i, x_i);
	gcry_mpi_set(telg_xprime_i, xprime_i);
	telg_n = tmcg_get_gcry_mpi_ui(n_in);
	telg_t = tmcg_get_gcry_mpi_ui(t_in);
	telg_i = tmcg_get_gcry_mpi_ui(i_in);
	for (size_t i = 0; i < qual.size(); i++)
		telg_qual.push_back(tmcg_get_gcry_mpi_ui(qual[i]));
	for (size_t i = 0; i < v_i.size(); i++)
	{
			gcry_mpi_t tmp;
			tmp = gcry_mpi_new(2048);
			gcry_mpi_set(tmp, v_i[i]);
			telg_v_i.push_back(tmp);
	}
	telg_c_ik.resize(c_ik.size());
	for (size_t i = 0; i < c_ik.size(); i++)
	{
		for (size_t k = 0; k < c_ik[i].size(); k++)
		{
			gcry_mpi_t tmp;
			tmp = gcry_mpi_new(2048);
			gcry_mpi_set(tmp, c_ik[i][k]);
			telg_c_ik[i].push_back(tmp);
		}
	}
}

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const gcry_mpi_t ecsk,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		telg_n(0),
		telg_t(0),
		telg_i(0)
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSubEncode(creationtime_in, pkalgo_in, oidlen, oid, ecpk,
		TMCG_OPENPGP_HASHALGO_UNKNOWN, TMCG_OPENPGP_SKALGO_PLAINTEXT, sub);
	pub = new TMCG_OpenPGP_Subkey(pkalgo_in, creationtime_in, expirationtime_in,
		oidlen, oid, ecpk, sub);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	elg_x = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(256);
	telg_q = gcry_mpi_new(8);
	telg_h = gcry_mpi_new(8);
	telg_x_i = gcry_mpi_snew(8);
	telg_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is ECDSA/EdDSA
	gcry_mpi_set(ec_sk, ecsk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecdsa (curve %s) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecc (curve %s) (flags eddsa) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	}
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PrivateSubkey::TMCG_OpenPGP_PrivateSubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const gcry_mpi_t ecsk,
	 const tmcg_openpgp_hashalgo_t kdf_hashalgo_in,
	 const tmcg_openpgp_skalgo_t kdf_skalgo_in,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		telg_n(0),
		telg_t(0),
		telg_i(0)
{
	tmcg_openpgp_octets_t sub;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSubEncode(creationtime_in, pkalgo_in, oidlen, oid, ecpk,
		kdf_hashalgo_in, kdf_skalgo_in, sub);
	pub = new TMCG_OpenPGP_Subkey(pkalgo_in, creationtime_in, expirationtime_in,
		oidlen, oid, ecpk, kdf_hashalgo_in, kdf_skalgo_in, sub);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	elg_x = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(256);
	telg_q = gcry_mpi_new(8);
	telg_h = gcry_mpi_new(8);
	telg_x_i = gcry_mpi_snew(8);
	telg_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is ECDH
	gcry_mpi_set(ec_sk, ecsk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	if (ec_curve == "Curve25519")
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecc (curve %s) (flags djb-tweak) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	else
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecdh (curve %s) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

bool TMCG_OpenPGP_PrivateSubkey::Good
	() const
{
	return ((ret == 0) && pub->Good());
}

bool TMCG_OpenPGP_PrivateSubkey::Weak
	(const int verbose) const
{
	if ((pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int pbits = 0, qbits = 0;
		pbits = gcry_mpi_get_nbits(rsa_p);
		qbits = gcry_mpi_get_nbits(rsa_q);
		if (verbose > 1)
			std::cerr << "INFO: RSA with |p| = " << pbits <<
				" bits, |q| = " << qbits << " bits" << std::endl;
		if ((pbits < 1024) || (qbits < 1024))
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
	{
		unsigned int xbits = 0;
		xbits = gcry_mpi_get_nbits(elg_x);
		if (verbose > 1)
			std::cerr << "INFO: ElGamal with |x| = " <<
				xbits << " bits" << std::endl;
		if (xbits < 245)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		unsigned int xbits = 0;
		xbits = gcry_mpi_get_nbits(dsa_x);
		if (verbose > 1)
			std::cerr << "INFO: DSA with |x| = " <<
				xbits << " bits" << std::endl; 
		if (xbits < 245)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
	{
		unsigned int qbits = 0, xibits = 0, xprimeibits = 0;
		qbits = gcry_mpi_get_nbits(telg_q);
		xibits = gcry_mpi_get_nbits(telg_x_i);
		xprimeibits = gcry_mpi_get_nbits(telg_xprime_i);
		if (verbose > 1)
			std::cerr << "INFO: tElG with |q| = " <<
				qbits << " bits, |x_i| = " <<
				xibits << " bits, |xprime_i| = " <<
				xprimeibits << " bits" << std::endl; 
		if ((qbits < 256) || (xibits < 245) || (xprimeibits < 245))
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if ((pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
		(pkalgo == TMCG_OPENPGP_PKALGO_EDDSA) ||
		(pkalgo == TMCG_OPENPGP_PKALGO_ECDH))
	{
		unsigned int skbits = 0;
		skbits = gcry_mpi_get_nbits(ec_sk);
		if (verbose > 1)
			std::cerr << "INFO: ECC with |x| = " <<
				skbits << " bits" << std::endl;
		if (skbits < 250)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else
		return true; // unknown public-key algorithm
	return false;
}

bool TMCG_OpenPGP_PrivateSubkey::Decrypt
	(const TMCG_OpenPGP_PKESK* &esk, const int verbose,
	 tmcg_openpgp_secure_octets_t &out) const
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad key material" << std::endl;
		return false;
	}
	if (pub->AccumulateFlags() &&
		((pub->AccumulateFlags() & 0x04) != 0x04) &&
		((pub->AccumulateFlags() & 0x08) != 0x08))
	{
		if (verbose)
			std::cerr << "ERROR: subkey is not capable of encryption" <<
				std::endl;
		return false;
	}
	if (esk->pkalgo != pub->pkalgo)
	{
		if (verbose)
			std::cerr << "ERROR: PKESK pkalgo does not match public-key" <<
				" algorithm of subkey" << std::endl;
		return false;

	}
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::
		OctetsCompare(esk->keyid, pub->id) &&
		!CallasDonnerhackeFinneyShawThayerRFC4880::
		OctetsCompareZero(esk->keyid))
	{
		if (verbose)
			std::cerr << "ERROR: PKESK keyid does not match subkey ID or" <<
				" wildcard pattern" << std::endl;
		return false;
	}
	if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		(esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
	{
		// check whether $0 < m^e < n$.
		if ((gcry_mpi_cmp_ui(esk->me, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->me, pub->rsa_n) >= 0))
		{
			if (verbose)
				std::cerr << "ERROR: 0 < m^e < n not satisfied" << 
					std::endl;
			return false;
		}
		gcry_error_t dret;
		dret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricDecryptRSA(esk->me, private_key, out);
		if (dret)
		{
			if (verbose)
				std::cerr << "ERROR: AsymmetricDecryptRSA() failed" <<
					" with rc = " << gcry_err_code(dret) << std::endl;
			return false;
		}
		return true;
	}
	else if (esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
	{
		// check whether $0 < g^k < p$.
		if ((gcry_mpi_cmp_ui(esk->gk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->gk, pub->elg_p) >= 0))
		{
			if (verbose)
				std::cerr << "ERROR: 0 < g^k < p not satisfied" << 
					std::endl;
			return false;
		}
		// check whether $0 < my^k < p$.
		if ((gcry_mpi_cmp_ui(esk->myk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->myk, pub->elg_p) >= 0))
		{
			if (verbose)
				std::cerr << "ERROR: 0 < my^k < p not satisfied" <<
					std::endl;
			return false;
		}
		gcry_error_t dret;
		dret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricDecryptElgamal(esk->gk, esk->myk, private_key, out);
		if (dret)
		{
			if (verbose)
				std::cerr << "ERROR: AsymmetricDecryptElgamal() failed" <<
					" with rc = " << gcry_err_code(dret) << std::endl;
			return false;
		}
		return true;
	}
	else if (esk->pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
	{
		gcry_error_t dret;
		if (ec_curve != "Curve25519")
		{
			// check whether esk->ecepk is point on curve of this key
			gcry_mpi_point_t tmp;
			gcry_ctx_t ec;
			dret = gcry_mpi_ec_new(&ec, NULL, ec_curve.c_str());
			if (dret)
			{
				if (verbose)
					std::cerr << "ERROR: gcry_mpi_ec_new() failed" <<
						" with rc = " << gcry_err_code(dret) << std::endl;
				return false;
			}
			dret = gcry_mpi_ec_set_mpi("q", esk->ecepk, ec);
			if (dret)
			{
				if (verbose)
					std::cerr << "ERROR: gcry_mpi_ec_set_mpi() failed" <<
						" with rc = " << gcry_err_code(dret) << std::endl;
				gcry_ctx_release(ec);
				return false;
			}
			tmp = gcry_mpi_ec_get_point("q", ec, 0);
			if (tmp == NULL)
			{
				if (verbose)
					std::cerr << "ERROR: gcry_mpi_ec_curve_point() failed" <<
						std::endl;
				gcry_ctx_release(ec);
				return false;
			}
			int ok = gcry_mpi_ec_curve_point(tmp, ec);
			gcry_mpi_point_release(tmp);
			gcry_ctx_release(ec);
			if (!ok)
			{
				if (verbose)
					std::cerr << "ERROR: gcry_mpi_ec_curve_point() failed" <<
						std::endl;
				return false;
			}
		}
		// decrypt session key
		tmcg_openpgp_octets_t rcpfpr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintCompute(pub->sub_hashing, rcpfpr);
		dret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricDecryptECDH(esk->ecepk, private_key, esk->rkwlen,
				esk->rkw, pub->kdf_hashalgo, pub->kdf_skalgo, ec_curve,
				rcpfpr, out);
		if (dret)
		{
			if (verbose)
				std::cerr << "ERROR: AsymmetricDecryptECDH() failed" <<
					" with rc = " << gcry_err_code(dret) << std::endl;
			return false;
		}
		return true;
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: public-key algorithm " << (int)esk->pkalgo <<
				" not supported for decryption" << std::endl;
		return false;
	}
}

TMCG_OpenPGP_PrivateSubkey::~TMCG_OpenPGP_PrivateSubkey
	()
{
	delete pub;
	if (ret == 0)
		gcry_sexp_release(private_key);
	gcry_mpi_release(rsa_p);
	gcry_mpi_release(rsa_q);
	gcry_mpi_release(rsa_u);
	gcry_mpi_release(rsa_d);
	gcry_mpi_release(elg_x);
	gcry_mpi_release(dsa_x);
	gcry_mpi_release(ec_sk);
	gcry_mpi_release(telg_q);
	gcry_mpi_release(telg_h);
	gcry_mpi_release(telg_x_i);
	gcry_mpi_release(telg_xprime_i);
	telg_qual.clear();
	for (size_t i = 0; i < telg_v_i.size(); i++)
		gcry_mpi_release(telg_v_i[i]);
	telg_v_i.clear();
	for (size_t i = 0; i < telg_c_ik.size(); i++)
	{
		for (size_t k = 0; k < telg_c_ik[i].size(); k++)
			gcry_mpi_release(telg_c_ik[i][k]);
		telg_c_ik[i].clear();
	}
	telg_c_ik.clear();
	packet.clear();
}

// ===========================================================================

TMCG_OpenPGP_Pubkey::TMCG_OpenPGP_Pubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t n,
	 const gcry_mpi_t e,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve("")
{
	rsa_n = gcry_mpi_new(2048);
	rsa_e = gcry_mpi_new(256);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(8);
	// public-key algorithm is RSA
	gcry_mpi_set(rsa_n, n);
	gcry_mpi_set(rsa_e, e);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (rsa (n %M) (e %M)))", n, e);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, pub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(pub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(pub_hashing, fingerprint);
}

TMCG_OpenPGP_Pubkey::TMCG_OpenPGP_Pubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve("")
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(512);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	ec_pk = gcry_mpi_new(8);
	// public-key algorithm is DSA
	gcry_mpi_set(dsa_p, p);
	gcry_mpi_set(dsa_q, q);
	gcry_mpi_set(dsa_g, g);
	gcry_mpi_set(dsa_y, y);
	ret = gcry_sexp_build(&key, &erroff,
		"(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", p, q, g, y);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, pub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(pub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(pub_hashing, fingerprint);
}

TMCG_OpenPGP_Pubkey::TMCG_OpenPGP_Pubkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_PUBKEY),
		erroff(0),
		valid(false),
		revoked(false),
		pkalgo(pkalgo_in),
		creationtime(creationtime_in),
		expirationtime(expirationtime_in),
		key(NULL),
		ec_curve("")
{
	rsa_n = gcry_mpi_new(8);
	rsa_e = gcry_mpi_new(8);
	dsa_p = gcry_mpi_new(8);
	dsa_q = gcry_mpi_new(8);
	dsa_g = gcry_mpi_new(8);
	dsa_y = gcry_mpi_new(8);
	ec_pk = gcry_mpi_new(1024);
	// public-key algorithm is ECDSA/EdDSA
	gcry_mpi_set(ec_pk, ecpk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		ret = gcry_sexp_build(&key, &erroff,
			"(public-key (ecdsa (curve %s) (q %m)))", curve, ecpk);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		ret = gcry_sexp_build(&key, &erroff,
			"(public-key (ecc (curve %s) (flags eddsa) (q %m)))", curve, ecpk);
	}
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(packet, 0, pub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(pub_hashing, id);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(pub_hashing, fingerprint);
}

bool TMCG_OpenPGP_Pubkey::Good
	() const
{
	return (ret == 0);
}

bool TMCG_OpenPGP_Pubkey::Weak
	(const int verbose) const
{
	gcry_error_t wret;
	if ((pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int nbits = 0, ebits = 0;
		nbits = gcry_mpi_get_nbits(rsa_n);
		ebits = gcry_mpi_get_nbits(rsa_e);
		if (verbose > 1)
			std::cerr << "INFO: RSA with |n| = " <<
				nbits << " bits, |e| = " <<
				ebits << " bits" << std::endl;
		if ((nbits < 2048) || (ebits < 6))
			return true; // weak key
		wret = gcry_prime_check(rsa_e, 0);
		if (wret)
			return true; // e is not a prime
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		unsigned int pbits = 0, qbits = 0, gbits = 0, ybits = 0;
		pbits = gcry_mpi_get_nbits(dsa_p);
		qbits = gcry_mpi_get_nbits(dsa_q);
		gbits = gcry_mpi_get_nbits(dsa_g);
		ybits = gcry_mpi_get_nbits(dsa_y);
		if (verbose > 1)
			std::cerr << "INFO: DSA with |p| = " <<
				pbits << " bits, |q| = " <<
				qbits << " bits, |g| = " <<
				gbits << " bits, |y| = " <<
				ybits << " bits" <<	std::endl;
		if ((pbits < 2048) || (qbits < 256) || (gbits < 2) || (ybits < 2))
			return true; // weak key
		wret = gcry_prime_check(dsa_p, 0);
		if (wret)
			return true; // p is not a prime
		wret = gcry_prime_check(dsa_q, 0);
		if (wret)
			return true; // q is not a prime
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
		if (curvename != NULL)
		{
			if (verbose > 1)
				std::cerr << "INFO: ECDSA with curve \"" << curvename <<
					"\" and " << curvebits << " bits" << std::endl;
			if (curvebits < 256)
				return true; // weak key
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: ECDSA with unknown curve" << std::endl;
			return true; // unknown curve
		}
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
		if (curvename != NULL)
		{
			if (verbose > 1)
				std::cerr << "INFO: EdDSA with curve \"" << curvename <<
					"\" and " << curvebits << " bits" << std::endl;
			if (curvebits < 256)
				return true; // weak key
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: EdDSA with unknown curve" << std::endl;
			return true; // unknown curve
		}
	}
	else
		return true; // unknown public-key algorithm
	return false;
}

size_t TMCG_OpenPGP_Pubkey::AccumulateFlags
	() const
{
	size_t allflags = 0;
	for (size_t i = 0; i < flags.size(); i++)
	{
		if (flags[i] && (i < 3))  // FIXME: only 3 octets of flags recognized
			allflags += ((size_t)flags[i] << (8 * i));
	}
	return allflags;
}

size_t TMCG_OpenPGP_Pubkey::AccumulateFeatures
	() const
{
	size_t allfeatures = 0;
	for (size_t i = 0; i < features.size(); i++)
	{
		if (features[i] && (i < 3)) // FIXME: only 3 octets of flags recognized
			allfeatures += ((size_t)features[i] << (8 * i));
	}
	return allfeatures;
}

tmcg_openpgp_revcode_t TMCG_OpenPGP_Pubkey::AccumulateRevocationCodes
	() const
{
	tmcg_openpgp_revcode_t revcode = TMCG_OPENPGP_REVCODE_NO_REASON_SPECIFIED;
	for (size_t j = 0; j < keyrevsigs.size(); j++)
	{
		if ((revcode == TMCG_OPENPGP_REVCODE_NO_REASON_SPECIFIED) ||
			(revcode == TMCG_OPENPGP_REVCODE_KEY_COMPROMISED))
		{
			revcode = keyrevsigs[j]->revcode;
		}
	}
	return revcode;
}

void TMCG_OpenPGP_Pubkey::UpdateProperties
	(const TMCG_OpenPGP_Signature *sig,
	 const int verbose)
{
	expirationtime = sig->keyexpirationtime;
	if (verbose > 1)
		std::cerr << "INFO: primary key update expirationtime to " <<
			expirationtime << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update flags to " << std::hex;
	flags.clear();			
	for (size_t i = 0; i < sig->keyflags.size(); i++)
	{
		flags.push_back(sig->keyflags[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyflags[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::dec << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update features to " <<
			std::hex;
	features.clear();
	for (size_t i = 0; i < sig->keyfeatures.size(); i++)
	{
		features.push_back(sig->keyfeatures[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyfeatures[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::dec << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update psa to ";
	psa.clear();
	for (size_t i = 0; i < sig->keyprefs_psa.size(); i++)
	{
		psa.push_back(sig->keyprefs_psa[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_psa[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update pha to ";
	pha.clear();
	for (size_t i = 0; i < sig->keyprefs_pha.size(); i++)
	{
		pha.push_back(sig->keyprefs_pha[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_pha[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update pca to ";
	pca.clear();
	for (size_t i = 0; i < sig->keyprefs_pca.size(); i++)
	{
		pca.push_back(sig->keyprefs_pca[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_pca[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update paa to ";
	paa.clear();
	for (size_t i = 0; i < sig->keyprefs_paa.size(); i++)
	{
		paa.push_back(sig->keyprefs_paa[i]);
		if (verbose > 1)
			std::cerr << (int)sig->keyprefs_paa[i] << " ";
	}
	if (verbose > 1)
		std::cerr << std::endl;
	if (verbose > 1)
		std::cerr << "INFO: primary key update revkeys with added ";
	for (size_t i = 0; i < sig->revkeys.size(); i++)
	{
		tmcg_openpgp_revkey_t rk = sig->revkeys[i];
		revkeys.push_back(rk);
		if (verbose > 1)
		{
			size_t fprlen = 0;
			if ((rk.key_fingerprint[20] == 0x00) &&
				(rk.key_fingerprint[21] == 0x00) &&
				(rk.key_fingerprint[22] == 0x00) &&
				(rk.key_fingerprint[23] == 0x00) &&
				(rk.key_fingerprint[24] == 0x00) &&
				(rk.key_fingerprint[25] == 0x00) &&
				(rk.key_fingerprint[26] == 0x00) &&
				(rk.key_fingerprint[27] == 0x00) &&
				(rk.key_fingerprint[28] == 0x00) &&
				(rk.key_fingerprint[29] == 0x00) &&
				(rk.key_fingerprint[30] == 0x00) &&
				(rk.key_fingerprint[31] == 0x00))
			{
				fprlen = 20; // V4 key
			}
			else
				fprlen = 32; // V5 key
			tmcg_openpgp_octets_t fpr(rk.key_fingerprint,
				 rk.key_fingerprint+fprlen);
			std::string fpr_str;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintConvertPretty(fpr, fpr_str);
			std::cerr << "[" << fpr_str << "]";
		}
	}
	if (verbose > 1)
		std::cerr << std::endl;
}

bool TMCG_OpenPGP_Pubkey::CheckValidity
	(const int verbose) const
{
	time_t current = time(NULL);
	time_t fmax = 60 * 60 * 25; // deviation time: 25 hours
	time_t kmax = creationtime + expirationtime;
	if (expirationtime && (current > kmax))
	{
		if (verbose)
			std::cerr << "WARNING: primary key has been " <<
				"expired" << std::endl;
		return false;
	}
	if (creationtime > (current + fmax))
	{
		if (verbose)
			std::cerr << "WARNING: primary key has been " <<
				"created in far future" << std::endl;
		return false;
	}
	return true;
}

bool TMCG_OpenPGP_Pubkey::CheckValidityPeriod
	(const time_t at, const int verbose) const
{
	time_t kmax = creationtime + expirationtime;
	if (expirationtime && (at > kmax))
	{
		if (verbose)
			std::cerr << "WARNING: not in validity period of primary key" <<
				std::endl;
		return false;
	}
	if (creationtime > at)
	{
		if (verbose)
			std::cerr << "WARNING: not in validity period of primary key" <<
				std::endl;
		return false;
	}
	return true;
}

bool TMCG_OpenPGP_Pubkey::CheckExternalRevocation
	(TMCG_OpenPGP_Signature* sig, const TMCG_OpenPGP_Keyring* ring,
	 const int verbose)
{
	bool valid_revsig = false;
	for (size_t k = 0; k < revkeys.size(); k++)
	{
		size_t fprlen = 0;
		if ((revkeys[k].key_fingerprint[20] == 0x00) &&
			(revkeys[k].key_fingerprint[21] == 0x00) &&
			(revkeys[k].key_fingerprint[22] == 0x00) &&
			(revkeys[k].key_fingerprint[23] == 0x00) &&
			(revkeys[k].key_fingerprint[24] == 0x00) &&
			(revkeys[k].key_fingerprint[25] == 0x00) &&
			(revkeys[k].key_fingerprint[26] == 0x00) &&
			(revkeys[k].key_fingerprint[27] == 0x00) &&
			(revkeys[k].key_fingerprint[28] == 0x00) &&
			(revkeys[k].key_fingerprint[29] == 0x00) &&
			(revkeys[k].key_fingerprint[30] == 0x00) &&
			(revkeys[k].key_fingerprint[31] == 0x00))
		{
			fprlen = 20; // V4 key
		}
		else
			fprlen = 32; // V5 key
		tmcg_openpgp_octets_t fpr(revkeys[k].key_fingerprint,
			revkeys[k].key_fingerprint+fprlen);
		std::string fprstr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPlain(fpr, fprstr);
		if (verbose > 2)
			std::cerr << "INFO: looking for external revocation" <<
				" key with fingerprint " << fprstr << std::endl;
		TMCG_OpenPGP_Pubkey *revkey = ring->Find(fprstr);
		if (revkey != NULL)
		{
			if (!revkey->valid && !revkey->revoked)
			{
				// disable external revocations to avoid recursion
				revkey->CheckSelfSignatures(ring, verbose, false);
			}
			if (!revkey->valid)
			{
				if (verbose)
					std::cerr << "WARNING: revocation key is not valid" <<
						std::endl;
				continue;
			}
			if (sig->Verify(revkey->key, pub_hashing, verbose))
				valid_revsig = true;
		}
	}
	return valid_revsig;
}

bool TMCG_OpenPGP_Pubkey::CheckSelfSignatures
	(const TMCG_OpenPGP_Keyring *ring, const int verbose,
	 const bool external)
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad key material" << std::endl;
		return false;
	}
	// print statistics of primary key
	if (verbose > 1)
	{
		std::cerr << "INFO: key ID of primary key: " << std::hex;
		for (size_t i = 0; i < id.size(); i++)
			std::cerr << (int)id[i] << " ";
		std::cerr << std::dec << std::endl;
		std::cerr << "INFO: fingerprint of primary key: " << std::hex;
		for (size_t i = 0; i < fingerprint.size(); i++)
			std::cerr << (int)fingerprint[i] << " ";
		std::cerr << std::dec << std::endl;
		std::cerr << "INFO: number of selfsigs = " << 
			selfsigs.size() << std::endl;
		std::cerr << "INFO: number of keyrevsigs = " <<
			keyrevsigs.size() << std::endl;
		std::cerr << "INFO: number of certrevsigs = " <<
			certrevsigs.size() << std::endl;
		std::cerr << "INFO: number of userids = " <<
			userids.size() << std::endl;
		std::cerr << "INFO: number of userattributes = " <<
			userattributes.size() << std::endl;
		std::cerr << "INFO: number of subkeys = " <<
			subkeys.size() << std::endl;
		std::cerr << "INFO: number of revkeys = " <<
			revkeys.size() << std::endl;
	}
	// check whether there are valid revocation signatures for 0x1f sigs
	for (size_t j = 0; j < certrevsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			certrevsigs[j]->PrintInfo();
		if (!certrevsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (certrevsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		bool valid_revsig = false;
		if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(id, certrevsigs[j]->issuer))
		{
			if (certrevsigs[j]->Verify(key, pub_hashing, verbose))
				valid_revsig = true;
			else if (verbose)
				std::cerr << "ERROR: signature verification failed" <<
					std::endl;
		}
		else if (external)
		{
				valid_revsig = CheckExternalRevocation(certrevsigs[j], ring,
					verbose);
				if (!valid_revsig && verbose)
					std::cerr << "WARNING: cannot verify revocation " <<
						"signature of an external key due to missing " <<
						"public key" << std::endl;
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: check of external revocation disabled" <<
					std::endl;
			valid_revsig = false;
		}
		if (valid_revsig)
		{
			if (verbose)
				std::cerr << "WARNING: valid certification revocation " <<
					"signature found for primary key" << std::endl;
			// TODO: check certrevsig.creationtime > selfsig.creation time
			// TODO: mark ONLY corresponding 0x1f sig from selfsigs as revoked
			// TODO: evaluate signature target subpacket, if available
			// WORKAROUND: set the revoked flag for all self-signatures
			for (size_t i = 0; i < selfsigs.size(); i++)
			{
				if (selfsigs[i]->revocable)
					selfsigs[i]->revoked = true;
			}
		}
		else if (verbose)
			std::cerr << "WARNING: invalid certification revocation " <<
				"signature found for subkey" << std::endl;
	}
	// check whether some self-signatures (0x1f) on primary key are valid
	std::sort(selfsigs.begin(), selfsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < selfsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			selfsigs[j]->PrintInfo();
		if (!selfsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (selfsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the self-signature cryptographically
		if (selfsigs[j]->Verify(key, pub_hashing, verbose))
		{
			// update properties of primary key
			UpdateProperties(selfsigs[j], verbose);
		}
		else if (verbose)
			std::cerr << "WARNING: invalid self-signature found" << std::endl;
	}
	// check validity of primary key
	if (!CheckValidity(verbose))
	{
		valid = false;
		return false;
	}
	// check user IDs of primary key
	bool one_valid_uid = false;
	for (size_t i = 0; i < userids.size(); i++)
	{
		if (verbose > 1)
		{
			std::cerr << "INFO: userid = \"" <<
				userids[i]->userid_sanitized << "\"" << std::endl;
			std::cerr << "INFO: number of selfsigs = " <<
				userids[i]->selfsigs.size() << std::endl;
			std::cerr << "INFO: number of revsigs = " <<
				userids[i]->revsigs.size() << std::endl;
			std::cerr << "INFO: number of certsigs = " <<
				userids[i]->certsigs.size() << std::endl;
		}
		if (userids[i]->Check(this, verbose))
		{
			one_valid_uid = true;
			if (verbose > 1)
				std::cerr << "INFO: user ID is valid" << std::endl;
			for (size_t j = 0; j < userids[i]->selfsigs.size(); j++)
			{
				// update properties of primary key
				if (userids[i]->selfsigs[j]->valid)
				{
					UpdateProperties(userids[i]->selfsigs[j], verbose);
				}
				else if (verbose > 1)
					std::cerr << "WARNING: one self-signature on this " <<
						"user ID is NOT valid" << std::endl;
			}
		}
		else if (verbose > 1)
			std::cerr << "INFO: user ID is NOT valid" << std::endl;
		// check validity of primary key again due to possible property updates
		if (!CheckValidity(verbose))
		{
			valid = false;
			return false;
		}
	}
	// check user attributes of primary key
	for (size_t i = 0; i < userattributes.size(); i++)
	{
		if (verbose > 1)
		{
			std::cerr << "INFO: userattribute #" << (i+1) << " with opaque" <<
				" content of " << (userattributes[i]->userattribute).size() <<
				" bytes" << std::endl;
			std::cerr << "INFO: number of selfsigs = " <<
				userattributes[i]->selfsigs.size() << std::endl;
			std::cerr << "INFO: number of revsigs = " <<
				userattributes[i]->revsigs.size() << std::endl;
			std::cerr << "INFO: number of certsigs = " <<
				userattributes[i]->certsigs.size() << std::endl;
		}
		if (userattributes[i]->Check(this, verbose))
		{
			if (verbose > 1)
				std::cerr << "INFO: user attribute is valid" << std::endl;
			for (size_t j = 0; j < userattributes[i]->selfsigs.size(); j++)
			{
				// update properties of primary key
				if (userattributes[i]->selfsigs[j]->valid)
				{
					UpdateProperties(userattributes[i]->selfsigs[j], verbose);
				}
				else if (verbose > 1)
					std::cerr << "WARNING: one self-signature on this " <<
						"user attribute is NOT valid" << std::endl;
			}
		}
		else if (verbose > 1)
			std::cerr << "INFO: user attribute is NOT valid" << std::endl;
		// check validity of primary key again due to possible property updates
		if (!CheckValidity(verbose))
		{
			valid = false;
			return false;
		}
	}
	// print accumulated key flags of the primary key
	size_t allflags = AccumulateFlags();
	if (verbose > 1)
	{
		std::cerr << "INFO: key flags on primary key are ";
 		// The key may be used to certify other keys.
		if ((allflags & 0x01) == 0x01)
			std::cerr << "C";
		// The key may be used to sign data.
		if ((allflags & 0x02) == 0x02)
			std::cerr << "S";
		// The key may be used encrypt communications.
		if ((allflags & 0x04) == 0x04)
			std::cerr << "E";
		// The key may be used encrypt storage.
		if ((allflags & 0x08) == 0x08)
			std::cerr << "e";
		// The private component of this key may have
		// been split by a secret-sharing mechanism.
		if ((allflags & 0x10) == 0x10)
			std::cerr << "D";
		// The key may be used for authentication.
		if ((allflags & 0x20) == 0x20)
			std::cerr << "A";
		// The private component of this key may be
		// in the possession of more than one person.
		if ((allflags & 0x80) == 0x80)
			std::cerr << "G";
		// This key may be used for timestamping. [draft RFC 4880bis]
		if ((allflags & 0x0800) == 0x0800)
			std::cerr << "T";
		std::cerr << std::endl;
	}
	// check key revocation signatures of primary key
	std::sort(keyrevsigs.begin(), keyrevsigs.end(),
		TMCG_OpenPGP_Signature_Compare);
	for (size_t j = 0; j < keyrevsigs.size(); j++)
	{
		// print and check basic properties of the signature
		if (verbose > 2)
			keyrevsigs[j]->PrintInfo();
		if (!keyrevsigs[j]->CheckValidity(creationtime, verbose))
			continue; // ignore an expired signature
		if (keyrevsigs[j]->revoked)
			continue; // ignore a revoked signature
		// check the revocation signature cryptographically
		bool valid_revsig = false;
		if (CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(id, keyrevsigs[j]->issuer))
		{
			if (keyrevsigs[j]->Verify(key, pub_hashing, verbose))
				valid_revsig = true;
			else if (verbose)
				std::cerr << "ERROR: signature verification failed" <<
					std::endl;
		}
		else if (external)
		{
				valid_revsig = CheckExternalRevocation(keyrevsigs[j], ring,
					verbose);
				if (!valid_revsig && verbose)
					std::cerr << "WARNING: cannot verify revocation " <<
						"signature of an external key due to missing " <<
						"public key" << std::endl;
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: check of external revocation disabled" <<
					std::endl;
			valid_revsig = false;
		}
		if (valid_revsig)
		{
			if (verbose)
				std::cerr << "WARNING: valid revocation signature found " <<
					"for primary key" << std::endl;
			valid = false;
			revoked = true;
			return false;
		}
		else if (verbose)
			std::cerr << "WARNING: invalid revocation " <<
				"signature found for subkey" << std::endl;
	}
	// update validity state of this key and return the result
	if (one_valid_uid)
	{
		valid = true;
		return true;
	}
	else
	{
		valid = false;
		return false;
	}
}

bool TMCG_OpenPGP_Pubkey::CheckSubkeys
	(const TMCG_OpenPGP_Keyring *ring, const int verbose)
{
	bool one_valid_sub = false;
	for (size_t i = 0; i < subkeys.size(); i++)
	{
		if (subkeys[i]->Check(this, ring, verbose))
		{
			one_valid_sub = true;
			if (verbose > 1)
				std::cerr << "INFO: subkey is valid" << std::endl;
			// print accumulated key flags of the subkey
			size_t allflags = subkeys[i]->AccumulateFlags();
			if (verbose > 1)
			{
				std::cerr << "INFO: key flags on subkey are ";
				// The key may be used to certify other keys.
				if ((allflags & 0x01) == 0x01)
					std::cerr << "C";
				// The key may be used to sign data.
				if ((allflags & 0x02) == 0x02)
					std::cerr << "S";
				// The key may be used encrypt communications.
				if ((allflags & 0x04) == 0x04)
					std::cerr << "E";
				// The key may be used encrypt storage.
				if ((allflags & 0x08) == 0x08)
					std::cerr << "e";
				// The private component of this key may have
				// been split by a secret-sharing mechanism.
				if ((allflags & 0x10) == 0x10)
					std::cerr << "D";
				// The key may be used for authentication.
				if ((allflags & 0x20) == 0x20)
					std::cerr << "A";
				// The private component of this key may be
				// in the possession of more than one person.
				if ((allflags & 0x80) == 0x80)
					std::cerr << "G";
				// This key may be used for timestamping. [draft RFC 4880bis]
				if ((allflags & 0x0800) == 0x0800)
					std::cerr << "T";
				std::cerr << std::endl;
			}
		}
		else if (verbose > 1)
			std::cerr << "INFO: subkey is NOT valid" << std::endl;
	}
	return one_valid_sub;
}

void TMCG_OpenPGP_Pubkey::Reduce
	()
{
	std::vector<TMCG_OpenPGP_UserID*> valid_userids;
	for (size_t i = 0; i < userids.size(); i++)
		if (userids[i]->valid)
			valid_userids.push_back(userids[i]);
		else
			delete userids[i];
	userids.clear();
	userids.insert(userids.end(),
		valid_userids.begin(), valid_userids.end());
	std::vector<TMCG_OpenPGP_UserAttribute*> valid_userattributes;
	for (size_t i = 0; i < userattributes.size(); i++)
		if (userattributes[i]->valid)
			valid_userattributes.push_back(userattributes[i]);
		else
			delete userattributes[i];
	userattributes.clear();
	userattributes.insert(userattributes.end(),
		valid_userattributes.begin(), valid_userattributes.end());
	std::vector<TMCG_OpenPGP_Subkey*> valid_subkeys;
	for (size_t i = 0; i < subkeys.size(); i++)
		if (subkeys[i]->valid)
			valid_subkeys.push_back(subkeys[i]);
		else
			delete subkeys[i];
	subkeys.clear();
	subkeys.insert(subkeys.end(),
		valid_subkeys.begin(), valid_subkeys.end());
}

void TMCG_OpenPGP_Pubkey::Export
	(tmcg_openpgp_octets_t &out) const
{
	out.insert(out.end(),
		packet.begin(),
		packet.end());
	for (size_t i = 0; i < keyrevsigs.size(); i++)
	{
		out.insert(out.end(),
			(keyrevsigs[i]->packet).begin(),
			(keyrevsigs[i]->packet).end());
	}
	for (size_t i = 0; i < selfsigs.size(); i++)
	{
		out.insert(out.end(),
			(selfsigs[i]->packet).begin(),
			(selfsigs[i]->packet).end());
	}
	for (size_t i = 0; i < certrevsigs.size(); i++)
	{
		out.insert(out.end(),
			(certrevsigs[i]->packet).begin(),
			(certrevsigs[i]->packet).end());
	}
	for (size_t j = 0; j < userids.size(); j++)
	{
		out.insert(out.end(),
			(userids[j]->packet).begin(),
			(userids[j]->packet).end());
		for (size_t i = 0; i < (userids[j]->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(userids[j]->selfsigs[i]->packet).begin(),
				(userids[j]->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (userids[j]->revsigs).size(); i++)
		{
			out.insert(out.end(),
				(userids[j]->revsigs[i]->packet).begin(),
				(userids[j]->revsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (userids[j]->certsigs).size(); i++)
		{
			if (userids[j]->certsigs[i]->exportable == false)
				continue;
			out.insert(out.end(),
				(userids[j]->certsigs[i]->packet).begin(),
				(userids[j]->certsigs[i]->packet).end());
		}
	}
	for (size_t j = 0; j < userattributes.size(); j++)
	{
		out.insert(out.end(),
			(userattributes[j]->packet).begin(),
			(userattributes[j]->packet).end());
		for (size_t i = 0; i < (userattributes[j]->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(userattributes[j]->selfsigs[i]->packet).begin(),
				(userattributes[j]->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (userattributes[j]->revsigs).size(); i++)
		{
			out.insert(out.end(),
				(userattributes[j]->revsigs[i]->packet).begin(),
				(userattributes[j]->revsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (userattributes[j]->certsigs).size(); i++)
		{
			if (userattributes[j]->certsigs[i]->exportable == false)
				continue;
			out.insert(out.end(),
				(userattributes[j]->certsigs[i]->packet).begin(),
				(userattributes[j]->certsigs[i]->packet).end());
		}
	}
	for (size_t j = 0; j < subkeys.size(); j++)
	{
		out.insert(out.end(),
			(subkeys[j]->packet).begin(),
			(subkeys[j]->packet).end());
		for (size_t i = 0; i < (subkeys[j]->keyrevsigs).size(); i++)
		{
			out.insert(out.end(),
				(subkeys[j]->keyrevsigs[i]->packet).begin(),
				(subkeys[j]->keyrevsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (subkeys[j]->bindsigs).size(); i++)
		{
			out.insert(out.end(),
				(subkeys[j]->bindsigs[i]->packet).begin(),
				(subkeys[j]->bindsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (subkeys[j]->pbindsigs).size(); i++)
		{
			out.insert(out.end(),
				(subkeys[j]->pbindsigs[i]->packet).begin(),
				(subkeys[j]->pbindsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (subkeys[j]->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(subkeys[j]->selfsigs[i]->packet).begin(),
				(subkeys[j]->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (subkeys[j]->certrevsigs).size(); i++)
		{
			out.insert(out.end(),
				(subkeys[j]->certrevsigs[i]->packet).begin(),
				(subkeys[j]->certrevsigs[i]->packet).end());
		}
	}
}

TMCG_OpenPGP_Pubkey::~TMCG_OpenPGP_Pubkey
	()
{
	gcry_mpi_release(rsa_n);
	gcry_mpi_release(rsa_e);
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(ec_pk);
	if (ret == 0)
		gcry_sexp_release(key);
	packet.clear();
	pub_hashing.clear();
	id.clear();
	flags.clear();
	features.clear();
	psa.clear();
	pha.clear();
	pca.clear();
	paa.clear();
	for (size_t i = 0; i < selfsigs.size(); i++)
		delete selfsigs[i];
	selfsigs.clear();
	for (size_t i = 0; i < keyrevsigs.size(); i++)
		delete keyrevsigs[i];
	keyrevsigs.clear();
	for (size_t i = 0; i < certrevsigs.size(); i++)
		delete certrevsigs[i];
	certrevsigs.clear();
	for (size_t i = 0; i < userids.size(); i++)
		delete userids[i];
	userids.clear();
	for (size_t i = 0; i < userattributes.size(); i++)
		delete userattributes[i];
	userattributes.clear();
	for (size_t i = 0; i < subkeys.size(); i++)
		delete subkeys[i];
	subkeys.clear();
	revkeys.clear();
}

// ===========================================================================

TMCG_OpenPGP_Prvkey::TMCG_OpenPGP_Prvkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t n,
	 const gcry_mpi_t e,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t u,
	 const gcry_mpi_t d,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		tdss_n(0),
		tdss_t(0),
		tdss_i(0)
{
	tmcg_openpgp_octets_t pkt;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(creationtime_in,
		pkalgo_in, n, e, e, e, pkt);
	pub = new TMCG_OpenPGP_Pubkey(pkalgo_in, creationtime_in, expirationtime_in,
		n, e, pkt);
	rsa_p = gcry_mpi_snew(2048);
	rsa_q = gcry_mpi_snew(2048);
	rsa_u = gcry_mpi_snew(2048);
	rsa_d = gcry_mpi_snew(2048);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(8);
	tdss_h = gcry_mpi_new(8);
	tdss_x_i = gcry_mpi_snew(8);
	tdss_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is RSA
	gcry_mpi_set(rsa_p, p);
	gcry_mpi_set(rsa_q, q);
	gcry_mpi_set(rsa_u, u);
	gcry_mpi_set(rsa_d, d);
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (rsa (n %M) (e %M) (d %M) (p %M) (q %M) (u %M)))",
		n, e, d, p, q, u);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_Prvkey::TMCG_OpenPGP_Prvkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const gcry_mpi_t x,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		tdss_n(0),
		tdss_t(0),
		tdss_i(0)
{
	tmcg_openpgp_octets_t pkt;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(creationtime_in,
		pkalgo_in, p, q, g, y, pkt);
	pub = new TMCG_OpenPGP_Pubkey(pkalgo_in, creationtime_in, expirationtime_in,
		p, q, g, y, pkt);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(256);
	ec_sk = gcry_mpi_snew(8);
	tdss_h = gcry_mpi_new(8);
	tdss_x_i = gcry_mpi_snew(8);
	tdss_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is DSA
	gcry_mpi_set(dsa_x, x);
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))",
		p, q, g, y, x);
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_Prvkey::TMCG_OpenPGP_Prvkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const gcry_mpi_t p,
	 const gcry_mpi_t q,
	 const gcry_mpi_t g,
	 const gcry_mpi_t h,
	 const gcry_mpi_t y,
	 const gcry_mpi_t x_i,
	 const gcry_mpi_t xprime_i,
	 const gcry_mpi_t n_in,
	 const gcry_mpi_t t_in,
	 const gcry_mpi_t i_in,
	 const std::vector<std::string> &capl,
	 const std::vector<gcry_mpi_t> &qual,
	 const std::vector<gcry_mpi_t> &x_rvss_qual,
	 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL)
{
	tmcg_openpgp_octets_t pkt;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(creationtime_in,
		TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pkt);
	pub = new TMCG_OpenPGP_Pubkey(TMCG_OPENPGP_PKALGO_DSA, creationtime_in,
		expirationtime_in, p, q, g, y, pkt);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(8);
	tdss_h = gcry_mpi_new(2048);
	tdss_x_i = gcry_mpi_snew(256);
	tdss_xprime_i = gcry_mpi_snew(256);
	// public-key algorithm is tDSS/DSA
	ret = gcry_sexp_build(&private_key, &erroff,
		"(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))",
		p, q, g, y, h); // NOTE: this is only a dummy private key
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
	gcry_mpi_set(tdss_h, h);
	gcry_mpi_set(tdss_x_i, x_i);
	gcry_mpi_set(tdss_xprime_i, xprime_i);
	tdss_n = tmcg_get_gcry_mpi_ui(n_in);
	tdss_t = tmcg_get_gcry_mpi_ui(t_in);
	tdss_i = tmcg_get_gcry_mpi_ui(i_in);
	for (size_t i = 0; i < capl.size(); i++)
		tdss_capl.push_back(capl[i]);
	for (size_t i = 0; i < qual.size(); i++)
		tdss_qual.push_back(tmcg_get_gcry_mpi_ui(qual[i]));
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		tdss_x_rvss_qual.push_back(tmcg_get_gcry_mpi_ui(x_rvss_qual[i]));
	tdss_c_ik.resize(c_ik.size());
	for (size_t i = 0; i < c_ik.size(); i++)
	{
		for (size_t k = 0; k < c_ik[i].size(); k++)
		{
			gcry_mpi_t tmp;
			tmp = gcry_mpi_new(2048);
			gcry_mpi_set(tmp, c_ik[i][k]);
			tdss_c_ik[i].push_back(tmp);
		}
	}
	if (tdss_capl.size() != tdss_n)
	{
		std::cerr << "ERROR: tDSS/DSA parameter mismatch" << std::endl;
		if (ret == 0)
			gcry_sexp_release(private_key);	
		ret = GPG_ERR_BAD_KEY;
	}
}

TMCG_OpenPGP_Prvkey::TMCG_OpenPGP_Prvkey
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const time_t creationtime_in,
	 const time_t expirationtime_in,
	 const size_t oidlen,
	 const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk,
	 const gcry_mpi_t ecsk,
	 const tmcg_openpgp_octets_t &packet_in):
		ret(GPG_ERR_BAD_SECKEY),
		erroff(0),
		pkalgo(pkalgo_in),
		private_key(NULL),
		tdss_n(0),
		tdss_t(0),
		tdss_i(0)
{
	tmcg_openpgp_octets_t pkt;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketPubEncode(creationtime_in, pkalgo_in, oidlen, oid, ecpk,
		TMCG_OPENPGP_HASHALGO_UNKNOWN, TMCG_OPENPGP_SKALGO_PLAINTEXT, pkt);
	pub = new TMCG_OpenPGP_Pubkey(pkalgo_in, creationtime_in, expirationtime_in,
		oidlen, oid, ecpk, pkt);
	rsa_p = gcry_mpi_snew(8);
	rsa_q = gcry_mpi_snew(8);
	rsa_u = gcry_mpi_snew(8);
	rsa_d = gcry_mpi_snew(8);
	dsa_x = gcry_mpi_snew(8);
	ec_sk = gcry_mpi_snew(256);
	tdss_h = gcry_mpi_new(8);
	tdss_x_i = gcry_mpi_snew(8);
	tdss_xprime_i = gcry_mpi_snew(8);
	// public-key algorithm is ECDSA/EdDSA
	gcry_mpi_set(ec_sk, ecsk);
	const char *curve = NULL;
	std::string ec_unknown = "unknown";
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (oidlen == tmcg_openpgp_oidtable[idx].oid[0])
		{
			bool cmp = true;
			for (size_t i = 0; i < oidlen; i++)
			{
				if (oid[i] != tmcg_openpgp_oidtable[idx].oid[1+i])
				cmp = false;
			}
			if (cmp)
				curve = tmcg_openpgp_oidtable[idx].name;
		}
	}
	if (curve != NULL)
		ec_curve = curve;
	else
		curve = ec_unknown.c_str();
	if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecdsa (curve %s) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		ret = gcry_sexp_build(&private_key, &erroff,
			"(private-key (ecc (curve %s) (flags eddsa) (q %m) (d %m)))",
			curve, ecpk, ecsk);
	}
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

bool TMCG_OpenPGP_Prvkey::Good
	() const
{
	return ((ret == 0) && pub->Good());
}

bool TMCG_OpenPGP_Prvkey::Weak
	(const int verbose) const
{
	if ((pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
	    (pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int pbits = 0, qbits = 0;
		pbits = gcry_mpi_get_nbits(rsa_p);
		qbits = gcry_mpi_get_nbits(rsa_q);
		if (verbose > 1)
			std::cerr << "INFO: RSA with |p| = " << pbits <<
				" bits, |q| = " << qbits << " bits" << std::endl;
		if ((pbits < 1024) || (qbits < 1024))
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		unsigned int xbits = 0;
		xbits = gcry_mpi_get_nbits(dsa_x);
		if (verbose > 1)
			std::cerr << "INFO: DSA with |x| = " <<
				xbits << " bits" << std::endl; 
		if (xbits < 245)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
	{
		unsigned int xibits = 0, xprimeibits = 0;
		xibits = gcry_mpi_get_nbits(tdss_x_i);
		xprimeibits = gcry_mpi_get_nbits(tdss_xprime_i);
		if (verbose > 1)
			std::cerr << "INFO: tDSS/DSA with |x_i| = " <<
				xibits << " bits, |xprime_i| = " <<
				xprimeibits << " bits" << std::endl; 
		if ((xibits < 245) || (xprimeibits < 245))
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		unsigned int skbits = 0;
		skbits = gcry_mpi_get_nbits(ec_sk);
		if (verbose > 1)
			std::cerr << "INFO: ECDSA with |x| = " <<
				skbits << " bits" << std::endl;
		if (skbits < 250)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else if (pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		unsigned int skbits = 0;
		skbits = gcry_mpi_get_nbits(ec_sk);
		if (verbose > 1)
			std::cerr << "INFO: EdDSA with |x| = " <<
				skbits << " bits" << std::endl;
		if (skbits < 250)
			return true; // weak key
		return pub->Weak(verbose);
	}
	else
		return true; // unknown public-key algorithm
	return false;
}

bool TMCG_OpenPGP_Prvkey::Decrypt
	(const TMCG_OpenPGP_PKESK* &esk, const int verbose,
	 tmcg_openpgp_secure_octets_t &out) const
{
	if (!Good())
	{
		if (verbose)
			std::cerr << "ERROR: bad key material" << std::endl;
		return false;
	}
	if (CallasDonnerhackeFinneyShawThayerRFC4880::
		OctetsCompare(esk->keyid, pub->id) ||
		CallasDonnerhackeFinneyShawThayerRFC4880::
		OctetsCompareZero(esk->keyid))
	{
		if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			(esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
		{
			// check whether $0 < m^e < n$.
			if ((gcry_mpi_cmp_ui(esk->me, 0L) <= 0) ||
				(gcry_mpi_cmp(esk->me, pub->rsa_n) >= 0))
			{
				if (verbose)
					std::cerr << "ERROR: 0 < m^e < n not satisfied" << 
						std::endl;
				return false;
			}
			gcry_error_t dret;
			dret = CallasDonnerhackeFinneyShawThayerRFC4880::
				AsymmetricDecryptRSA(esk->me, private_key, out);
			if (dret)
			{
				if (verbose)
					std::cerr << "ERROR: AsymmetricDecryptRSA() failed" <<
						" with rc = " << gcry_err_code(ret) << std::endl;
				return false;
			}
			return true;
		}
		else
		{
			if (verbose)
				std::cerr << "ERROR: public-key algorithm not supported" <<
					" for decryption" << std::endl;
			return false;
		}
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: PKESK keyid does not match key ID or" <<
				" wildcard pattern" << std::endl;
		return false;
	}
}

void TMCG_OpenPGP_Prvkey::RelinkPublicSubkeys
	()
{
	assert((pub->subkeys).size() == 0);
	// relink the public subkeys within private key structures
	for (size_t i = 0; i < private_subkeys.size(); i++)
	{
		(pub->subkeys).push_back(private_subkeys[i]->pub);
		private_subkeys[i]->pub = new TMCG_OpenPGP_Subkey(); // create dummy
	}
}

void TMCG_OpenPGP_Prvkey::RelinkPrivateSubkeys
	()
{
	for (size_t i = 0; i < private_subkeys.size(); i++)
		delete private_subkeys[i]->pub; // release dummy
	// relink the private subkeys within private key structures
	for (size_t i = 0; i < private_subkeys.size(); i++)
	{
		private_subkeys[i]->pub = pub->subkeys[i];
	}
	(pub->subkeys).clear();
}

bool TMCG_OpenPGP_Prvkey::tDSS_CreateMapping
	(const std::vector<std::string> &peers, const int verbose)
{
	// create one-to-one mapping based on the stored canonicalized peer list
	tdss_idx2dkg.clear();
	tdss_dkg2idx.clear();
	for (size_t i = 0; i < peers.size(); i++)
	{
		bool found = false;
		for (size_t j = 0; j < tdss_capl.size(); j++)
		{
			if (peers[i] == tdss_capl[j])
			{
				found = true;
				tdss_idx2dkg[i] = j;
				tdss_dkg2idx[j] = i;
				if (verbose > 1)
					std::cerr << "INFO: mapping " << i << " -> " <<
						"P_" << j << std::endl; 
				break;
			}
		}
		if (!found)
		{
			tdss_idx2dkg.clear();
			tdss_dkg2idx.clear();
			if (verbose)
				std::cerr << "ERROR: peer \"" << peers[i] << "\" not" <<
					" found inside CAPL from tDSS/DSA key" << std::endl;
			return false;
		}
	}
	return true;
}

void TMCG_OpenPGP_Prvkey::Export
	(tmcg_openpgp_octets_t &out) const
{
	out.insert(out.end(),
		packet.begin(),
		packet.end());
	for (size_t i = 0; i < pub->keyrevsigs.size(); i++)
	{
		out.insert(out.end(),
			(pub->keyrevsigs[i]->packet).begin(),
			(pub->keyrevsigs[i]->packet).end());
	}
	for (size_t i = 0; i < pub->selfsigs.size(); i++)
	{
		out.insert(out.end(),
			(pub->selfsigs[i]->packet).begin(),
			(pub->selfsigs[i]->packet).end());
	}
	for (size_t i = 0; i < pub->certrevsigs.size(); i++)
	{
		out.insert(out.end(),
			(pub->certrevsigs[i]->packet).begin(),
			(pub->certrevsigs[i]->packet).end());
	}
	for (size_t j = 0; j < pub->userids.size(); j++)
	{
		out.insert(out.end(),
			(pub->userids[j]->packet).begin(),
			(pub->userids[j]->packet).end());
		for (size_t i = 0; i < (pub->userids[j]->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userids[j]->selfsigs[i]->packet).begin(),
				(pub->userids[j]->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (pub->userids[j]->revsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userids[j]->revsigs[i]->packet).begin(),
				(pub->userids[j]->revsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (pub->userids[j]->certsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userids[j]->certsigs[i]->packet).begin(),
				(pub->userids[j]->certsigs[i]->packet).end());
		}
	}
	for (size_t j = 0; j < pub->userattributes.size(); j++)
	{
		out.insert(out.end(),
			(pub->userattributes[j]->packet).begin(),
			(pub->userattributes[j]->packet).end());
		for (size_t i = 0; i < (pub->userattributes[j]->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userattributes[j]->selfsigs[i]->packet).begin(),
				(pub->userattributes[j]->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (pub->userattributes[j]->revsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userattributes[j]->revsigs[i]->packet).begin(),
				(pub->userattributes[j]->revsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (pub->userattributes[j]->certsigs).size(); i++)
		{
			out.insert(out.end(),
				(pub->userattributes[j]->certsigs[i]->packet).begin(),
				(pub->userattributes[j]->certsigs[i]->packet).end());
		}
	}
	for (size_t j = 0; j < private_subkeys.size(); j++)
	{
		out.insert(out.end(),
			(private_subkeys[j]->packet).begin(),
			(private_subkeys[j]->packet).end());
		for (size_t i = 0; i < (private_subkeys[j]->pub->keyrevsigs).size(); i++)
		{
			out.insert(out.end(),
				(private_subkeys[j]->pub->keyrevsigs[i]->packet).begin(),
				(private_subkeys[j]->pub->keyrevsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (private_subkeys[j]->pub->bindsigs).size(); i++)
		{
			out.insert(out.end(),
				(private_subkeys[j]->pub->bindsigs[i]->packet).begin(),
				(private_subkeys[j]->pub->bindsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (private_subkeys[j]->pub->pbindsigs).size(); i++)
		{
			out.insert(out.end(),
				(private_subkeys[j]->pub->pbindsigs[i]->packet).begin(),
				(private_subkeys[j]->pub->pbindsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (private_subkeys[j]->pub->selfsigs).size(); i++)
		{
			out.insert(out.end(),
				(private_subkeys[j]->pub->selfsigs[i]->packet).begin(),
				(private_subkeys[j]->pub->selfsigs[i]->packet).end());
		}
		for (size_t i = 0; i < (private_subkeys[j]->pub->certrevsigs).size(); i++)
		{
			out.insert(out.end(),
				(private_subkeys[j]->pub->certrevsigs[i]->packet).begin(),
				(private_subkeys[j]->pub->certrevsigs[i]->packet).end());
		}
	}
}

TMCG_OpenPGP_Prvkey::~TMCG_OpenPGP_Prvkey
	()
{
	delete pub;
	if (ret == 0)
		gcry_sexp_release(private_key);
	for (size_t i = 0; i < private_subkeys.size(); i++)
		delete private_subkeys[i];
	private_subkeys.clear();
	gcry_mpi_release(rsa_p);
	gcry_mpi_release(rsa_q);
	gcry_mpi_release(rsa_u);
	gcry_mpi_release(rsa_d);
	gcry_mpi_release(dsa_x);
	gcry_mpi_release(ec_sk);
	gcry_mpi_release(tdss_h);
	gcry_mpi_release(tdss_x_i);
	gcry_mpi_release(tdss_xprime_i);
	tdss_capl.clear();
	tdss_qual.clear();
	tdss_x_rvss_qual.clear();
	for (size_t i = 0; i < tdss_c_ik.size(); i++)
	{
		for (size_t k = 0; k < tdss_c_ik[i].size(); k++)
			gcry_mpi_release(tdss_c_ik[i][k]);
		tdss_c_ik[i].clear();
	}
	tdss_c_ik.clear();
	tdss_idx2dkg.clear();
	tdss_dkg2idx.clear();
	packet.clear();
}

// ===========================================================================

TMCG_OpenPGP_Keyring::TMCG_OpenPGP_Keyring
	()
{
}

bool TMCG_OpenPGP_Keyring::Add
	(TMCG_OpenPGP_Pubkey *key)
{
	std::string fpr_str;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(key->pub_hashing, fpr_str);
	if (keys.count(fpr_str))
		return false; // key is already there
	keys[fpr_str] = key;
	// register several key IDs of primary key and subkeys
	std::string kid_str;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(key->pub_hashing, kid_str);
	if (!keys_by_keyid.count(kid_str))
	{
		keys_by_keyid[kid_str] = key;
		keys_by_keyid["0x"+kid_str] = key;
	}
	else
		return false; // dup key ID
	if (!keys_by_keyid.count(fpr_str))
	{
		keys_by_keyid[fpr_str] = key;
		keys_by_keyid["0x"+fpr_str] = key;
	}
	else
		return false; // dup key ID (full fingerprint)
	for (size_t i = 0; i < (key->subkeys).size(); i++)
	{
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintCompute(key->subkeys[i]->sub_hashing, fpr_str);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(key->subkeys[i]->sub_hashing, kid_str);
		if (!keys_by_keyid.count(kid_str))
		{
			keys_by_keyid[kid_str] = key;
			keys_by_keyid["0x"+kid_str] = key;
		}
		else
			return false; // dup key ID
		if (!keys_by_keyid.count(fpr_str))
		{
			keys_by_keyid[fpr_str] = key;
			keys_by_keyid["0x"+fpr_str] = key;
		}
		else
			return false; // dup key ID (full fingerprint)
	}	
	return true;
}

TMCG_OpenPGP_Pubkey* TMCG_OpenPGP_Keyring::Find
	(const std::string &fingerprint) const
{
	if (keys.count(fingerprint))
	{
		std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
			it = keys.find(fingerprint);
		return it->second;
	}
	else
		return NULL; // key not found
}

TMCG_OpenPGP_Pubkey* TMCG_OpenPGP_Keyring::FindByKeyid
	(const std::string &keyid) const
{
	if (keys_by_keyid.count(keyid))
	{
		std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
			it = keys_by_keyid.find(keyid);
		return it->second;
	}
	else
		return NULL; // key not found
}

size_t TMCG_OpenPGP_Keyring::Size
	() const
{
	return keys.size();
}

size_t TMCG_OpenPGP_Keyring::List
	(const std::string &userid) const
{
	size_t selected = 0;
	for (std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
	     it = keys.begin(); it != keys.end(); ++it)
	{
		const TMCG_OpenPGP_Pubkey *p = it->second;
		bool select = false;
		if (userid.length() == 0)
			select = true;
		else
		{
			for (size_t i = 0; i < p->userids.size(); i++)
			{
				if (((p->userids[i])->userid_sanitized).find(userid) !=
					((p->userids[i])->userid_sanitized).npos)
				{
					select = true;
				}
			}
		}
		if (select)
		{
			TMCG_OpenPGP_Pubkey *pub = it->second;
			pub->CheckSelfSignatures(this, 0); // check validity
			unsigned int curvebits = 0;
			std::string pub_kid;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				KeyidCompute(pub->pub_hashing, pub_kid);
			selected++;
			std::cout << "pub:";
			if (pub->valid)
				std::cout << "f:";
			else if (pub->revoked)
				std::cout << "r:";
			else
				std::cout << "i:";
			switch (pub->pkalgo)
			{
				case TMCG_OPENPGP_PKALGO_RSA:
				case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
				case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
					std::cout << gcry_mpi_get_nbits(pub->rsa_n) << ":";
					break;
				case TMCG_OPENPGP_PKALGO_DSA:
					std::cout << gcry_mpi_get_nbits(pub->dsa_p) << ":";
					break;
				case TMCG_OPENPGP_PKALGO_ECDH:
				case TMCG_OPENPGP_PKALGO_ECDSA:
				case TMCG_OPENPGP_PKALGO_EDDSA:
					if (gcry_pk_get_curve(pub->key, 0, &curvebits) != NULL)
						std::cout << curvebits << ":";
					else
						std::cout << "?:";
					break;
				default:
					std::cout << "?:";
					break;
			}
			std::cout << (int)pub->pkalgo << ":";
			std::cout << pub_kid << ":";
			std::cout << (long int)pub->creationtime << ":";
			if (pub->expirationtime)
			{
				time_t exp_date = pub->creationtime + pub->expirationtime;
				std::cout << (long int)exp_date;
			}
			std::cout << ":::::";
			size_t allflags = pub->AccumulateFlags();
			if ((allflags & 0x01) == 0x01)
				std::cout << "c";
			if ((allflags & 0x02) == 0x02)
				std::cout << "s";
			if (((allflags & 0x04) == 0x04) || ((allflags & 0x08) == 0x08))
				std::cout << "e";
			if ((allflags & 0x20) == 0x20)
				std::cout << "a";
			if (allflags == 0)
			{
				if ((pub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_ECDH))
						std::cout << "e";
				if ((pub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
					(pub->pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
						std::cout << "s";
			}
			std::cout << ":";
			// TODO: implement other fields
			std::cout << std::endl;
			for (size_t i = 0; i < pub->revkeys.size(); i++)
			{
				tmcg_openpgp_revkey_t rvk = pub->revkeys[i]; 
				std::cout << "rvk:::";
				std::cout << (int)rvk.key_pkalgo << "::::::";
				size_t fprlen = 0;
				if ((rvk.key_fingerprint[20] == 0x00) &&
					(rvk.key_fingerprint[21] == 0x00) &&
					(rvk.key_fingerprint[22] == 0x00) &&
					(rvk.key_fingerprint[23] == 0x00) &&
					(rvk.key_fingerprint[24] == 0x00) &&
					(rvk.key_fingerprint[25] == 0x00) &&
					(rvk.key_fingerprint[26] == 0x00) &&
					(rvk.key_fingerprint[27] == 0x00) &&
					(rvk.key_fingerprint[28] == 0x00) &&
					(rvk.key_fingerprint[29] == 0x00) &&
					(rvk.key_fingerprint[30] == 0x00) &&
					(rvk.key_fingerprint[31] == 0x00))
				{
					fprlen = 20; // V4 key
				}
				else
					fprlen = 32; // V5 key
				for (size_t j = 0; j < fprlen; j++)
					fprintf(stdout, "%02X", rvk.key_fingerprint[j]);
				fprintf(stdout, ":%02x", rvk.key_class);
				if ((rvk.key_class & 0x40) == 0x40)
					std::cout << "l";
				else
					std::cout << "x";
				std::cout << ":" << std::endl;
			}
			std::string pub_fpr;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintCompute(pub->pub_hashing, pub_fpr);
			std::cout << "fpr:::::::::" << pub_fpr << ":" << std::endl;
			for (size_t i = 0; i < pub->userids.size(); i++)
			{
				TMCG_OpenPGP_UserID *uid = pub->userids[i];
				uid->Check(pub, 0); // check validity
				std::cout << "uid:";
				if (uid->valid)
					std::cout << "f:";
				else if (uid->revoked)
					std::cout << "r:";
				else
					std::cout << "i:";
				std::cout << ":::";
				if (uid->selfsigs.size())
					std::cout << (long int)uid->selfsigs[0]->creationtime << ":";
				else
					std::cout << ":";
				std::cout << ":";
				std::string uid_fpr;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					FingerprintCompute(uid->userid, uid_fpr);
				std::cout << uid_fpr << ":";
				std::cout << ":";
				for (size_t j = 0; j < uid->userid.length(); j++)
				{
					char c = uid->userid[j];
					char chex[3];
					memset(chex, 0, sizeof(chex));
					snprintf(chex, sizeof(chex), "%02x", c);
					if ((c < 0x20) || (c == 0x7F) || (c == ':'))
						std::cout << "\\x" << chex;
					else
						std::cout << c;
				}
				std::cout << ":";
				// TODO: implement other fields
				std::cout << std::endl;
			}
			for (size_t i = 0; i < pub->userattributes.size(); i++)
			{
				TMCG_OpenPGP_UserAttribute *uat = pub->userattributes[i];
				uat->Check(pub, 0); // check validity
				std::cout << "uat:";
				if (uat->valid)
					std::cout << "f:";
				else if (uat->revoked)
					std::cout << "r:";
				else
					std::cout << "i:";
				std::cout << ":::";
				if (uat->selfsigs.size())
					std::cout << (long int)uat->selfsigs[0]->creationtime << ":";
				else
					std::cout << ":";
				// TODO: implement other fields
				std::cout << std::endl;
			}
			for (size_t i = 0; i < pub->subkeys.size(); i++)
			{
				TMCG_OpenPGP_Subkey *sub = pub->subkeys[i];
				pub->subkeys[i]->Check(pub, this, 0);
				std::string sub_kid;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					KeyidCompute(sub->sub_hashing, sub_kid);
				std::cout << "sub:";
				if (pub->subkeys[i]->valid)
					std::cout << "f:";
				else if (pub->subkeys[i]->revoked)
					std::cout << "r:";
				else
					std::cout << "i:";
				switch (sub->pkalgo)
				{
					case TMCG_OPENPGP_PKALGO_RSA:
					case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
					case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
						std::cout << gcry_mpi_get_nbits(sub->rsa_n) << ":";
						break;
					case TMCG_OPENPGP_PKALGO_ELGAMAL:
						std::cout << gcry_mpi_get_nbits(sub->elg_p) << ":";
						break;
					case TMCG_OPENPGP_PKALGO_DSA:
						std::cout << gcry_mpi_get_nbits(sub->dsa_p) << ":";
						break;
					case TMCG_OPENPGP_PKALGO_ECDH:
					case TMCG_OPENPGP_PKALGO_ECDSA:
					case TMCG_OPENPGP_PKALGO_EDDSA:
						if (gcry_pk_get_curve(sub->key, 0, &curvebits) != NULL)
							std::cout << curvebits << ":";
						else
							std::cout << "?:";
						break;
					default:
						std::cout << "?:";
						break;
				}
				std::cout << (int)sub->pkalgo << ":";
				std::cout << sub_kid << ":";
				std::cout << (long int)sub->creationtime << ":";
				if (sub->expirationtime)
				{
					time_t exp_date = sub->creationtime + sub->expirationtime;
					std::cout << (long int)exp_date;
				}
				std::cout << ":::::";
				size_t allflags = sub->AccumulateFlags();
				if ((allflags & 0x01) == 0x01)
					std::cout << "c";
				if ((allflags & 0x02) == 0x02)
					std::cout << "s";
				if (((allflags & 0x04) == 0x04) || ((allflags & 0x08) == 0x08))
					std::cout << "e";
				if ((allflags & 0x20) == 0x20)
					std::cout << "a";
				if (allflags == 0)
				{
					if ((sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_ECDH))
							std::cout << "e";
					if ((sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
						(sub->pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
							std::cout << "s";
				}
				std::cout << ":";
				// TODO: implement other fields
				std::cout << std::endl;
				std::string sub_fpr;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					FingerprintCompute(sub->sub_hashing, sub_fpr);
				std::cout << "fpr:::::::::" << sub_fpr << ":" << std::endl;
			}
		}
	}
	return selected;
}

size_t TMCG_OpenPGP_Keyring::Check
	(const int verbose) const
{
	size_t valid_keys = 0;
	for (std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
	     it = keys.begin(); it != keys.end(); ++it)
	{
		TMCG_OpenPGP_Pubkey *pub = it->second;
		if (pub->CheckSelfSignatures(this, verbose))
			valid_keys++;
		pub->CheckSubkeys(this, verbose);
	}
	return valid_keys;
}

void TMCG_OpenPGP_Keyring::Reduce
	()
{
	std::vector<std::string> rmv;
	for (std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
	     it = keys.begin(); it != keys.end(); ++it)
	{
		// reduce primary key (e.g. remove invalid user IDs)
		TMCG_OpenPGP_Pubkey *pub = it->second;
		pub->Reduce();
		if (!pub->valid)
			rmv.push_back(it->first);
	}
	for (size_t i = 0; i < rmv.size(); i++)
	{
		// remove invalid primary keys
		std::string fpr_str = rmv[i];
		std::string kid_str;
		const TMCG_OpenPGP_Pubkey *key = keys[fpr_str];
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(key->pub_hashing, kid_str);
		keys_by_keyid.erase(fpr_str);
		keys_by_keyid.erase("0x"+fpr_str);
		keys_by_keyid.erase(kid_str);
		keys_by_keyid.erase("0x"+kid_str);
		for (size_t j = 0; j < (key->subkeys).size(); j++)
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintCompute(key->subkeys[j]->sub_hashing, fpr_str);
			CallasDonnerhackeFinneyShawThayerRFC4880::
				KeyidCompute(key->subkeys[j]->sub_hashing, kid_str);
			keys_by_keyid.erase(fpr_str);
			keys_by_keyid.erase("0x"+fpr_str);
			keys_by_keyid.erase(kid_str);
			keys_by_keyid.erase("0x"+kid_str);
		}	
		delete key;
		keys.erase(fpr_str);
	}
}


TMCG_OpenPGP_Keyring::~TMCG_OpenPGP_Keyring
	()
{
	for (std::map<std::string, TMCG_OpenPGP_Pubkey*>::const_iterator
	     it = keys.begin(); it != keys.end(); ++it)
		delete it->second;
	keys.clear();
	keys_by_keyid.clear();
}

// ===========================================================================

TMCG_OpenPGP_PKESK::TMCG_OpenPGP_PKESK
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const tmcg_openpgp_octets_t &keyid_in,
	 const gcry_mpi_t me_in,
	 const tmcg_openpgp_octets_t &packet_in):
		pkalgo(pkalgo_in), rkwlen(0)
{
	keyid.insert(keyid.end(), keyid_in.begin(), keyid_in.end());
	me = gcry_mpi_new(2048);
	gk = gcry_mpi_new(8);
	myk = gcry_mpi_new(8);
	ecepk = gcry_mpi_new(8);
	// public-key algorithm is RSA
	gcry_mpi_set(me, me_in);
	memset(rkw, 0 , sizeof(rkw));
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PKESK::TMCG_OpenPGP_PKESK
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const tmcg_openpgp_octets_t &keyid_in,
	 const gcry_mpi_t gk_in,
	 const gcry_mpi_t myk_in,
	 const tmcg_openpgp_octets_t &packet_in):
		pkalgo(pkalgo_in), rkwlen(0)
{
	keyid.insert(keyid.end(), keyid_in.begin(), keyid_in.end());
	me = gcry_mpi_new(8);
	gk = gcry_mpi_new(2048);
	myk = gcry_mpi_new(2048);
	ecepk = gcry_mpi_new(8);
	// public-key algorithm is ElGamal
	gcry_mpi_set(gk, gk_in);
	gcry_mpi_set(myk, myk_in);
	memset(rkw, 0 , sizeof(rkw));
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PKESK::TMCG_OpenPGP_PKESK
	(const tmcg_openpgp_pkalgo_t pkalgo_in,
	 const tmcg_openpgp_octets_t &keyid_in,
	 const gcry_mpi_t ecepk_in,
	 const size_t rkwlen_in,
	 const tmcg_openpgp_byte_t* rkw_in,
	 const tmcg_openpgp_octets_t &packet_in):
		pkalgo(pkalgo_in), rkwlen(rkwlen_in)
{
	keyid.insert(keyid.end(), keyid_in.begin(), keyid_in.end());
	me = gcry_mpi_new(8);
	gk = gcry_mpi_new(8);
	myk = gcry_mpi_new(8);
	ecepk = gcry_mpi_new(1024);
	// public-key algorithm is ECDH
	gcry_mpi_set(ecepk, ecepk_in);
	memset(rkw, 0, sizeof(rkw));
	for (size_t i = 0; ((i < rkwlen) && (i < sizeof(rkw))); i++)
		rkw[i] = rkw_in[i];
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_PKESK::~TMCG_OpenPGP_PKESK
	()
{
	keyid.clear();
	gcry_mpi_release(me);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	gcry_mpi_release(ecepk);
	memset(rkw, 0, sizeof(rkw));
	packet.clear();
}

// ===========================================================================

TMCG_OpenPGP_SKESK::TMCG_OpenPGP_SKESK
	(const tmcg_openpgp_byte_t version_in,
	 const tmcg_openpgp_skalgo_t skalgo_in,
	 const tmcg_openpgp_aeadalgo_t aeadalgo_in,
	 const tmcg_openpgp_stringtokey_t s2k_type_in,
	 const tmcg_openpgp_hashalgo_t s2k_hashalgo_in,
	 const tmcg_openpgp_octets_t &s2k_salt_in,
	 const tmcg_openpgp_byte_t s2k_count_in,
	 const tmcg_openpgp_octets_t &iv_in,
	 const tmcg_openpgp_octets_t &encrypted_key_in,
	 const tmcg_openpgp_octets_t &packet_in):
		version(version_in),
		skalgo(skalgo_in),
		aeadalgo(aeadalgo_in),
		s2k_type(s2k_type_in),
		s2k_hashalgo(s2k_hashalgo_in),
		s2k_count(s2k_count_in)
{
	s2k_salt.insert(s2k_salt.end(), s2k_salt_in.begin(), s2k_salt_in.end());
	iv.insert(iv.end(), iv_in.begin(), iv_in.end());
	encrypted_key.insert(encrypted_key.end(),
		encrypted_key_in.begin(), encrypted_key_in.end());
	packet.insert(packet.end(), packet_in.begin(), packet_in.end());
}

TMCG_OpenPGP_SKESK::~TMCG_OpenPGP_SKESK
	()
{
	s2k_salt.clear();
	iv.clear();
	encrypted_key.clear();
	packet.clear();
}

// ===========================================================================

TMCG_OpenPGP_Message::TMCG_OpenPGP_Message
	():
		have_sed(false),
		have_seipd(false),
		have_aead(false),
		compalgo(TMCG_OPENPGP_COMPALGO_UNCOMPRESSED),
		format(0x00),
		filename(""),
		timestamp(0),
		skalgo(TMCG_OPENPGP_SKALGO_PLAINTEXT),
		aeadalgo(TMCG_OPENPGP_AEADALGO_UNKNOWN),
		chunksize(0)
{
}

bool TMCG_OpenPGP_Message::CheckMDC
	(const tmcg_openpgp_octets_t &prefix,
	 const tmcg_openpgp_octets_t &mdc,
	 const tmcg_openpgp_octets_t &mdc_message,
	 const int verbose) const
{
	if (!have_seipd)
	{
		if (verbose)
			std::cerr << "ERROR: no SEIPD packet found" << std::endl;
		return false;
	}
	if (prefix.size() == 0)
	{
		if (verbose)
			std::cerr << "ERROR: no prefix found" << std::endl;
		return false;
	}
	if (mdc.size() == 0)
	{
		if (verbose)
			std::cerr << "ERROR: no MDC found" << std::endl;
		return false;
	}
	if (mdc_message.size() == 0)
	{
		if (verbose)
			std::cerr << "ERROR: no data found" << std::endl;
		return false;
	}
	tmcg_openpgp_octets_t mdc_hashing, hash;
	// "it includes the prefix data described above" [RFC4880]
	mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end());
	// "it includes all of the plaintext" [RFC4880]
	mdc_hashing.insert(mdc_hashing.end(),
		mdc_message.begin(), mdc_message.end());
	// "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
	mdc_hashing.push_back(0xD3);
	mdc_hashing.push_back(0x14);
	// "passed through the SHA-1 hash function" [RFC4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::
		HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash);
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(mdc, hash))
	{
		if (verbose)
			std::cerr << "ERROR: MDC does not match (security issue)" <<
				std::endl;
		return false;
	}
	return true;
}

bool TMCG_OpenPGP_Message::Decrypt
	(const tmcg_openpgp_secure_octets_t &key, const int verbose,
	 tmcg_openpgp_octets_t &out) const
{
	if (verbose > 1)
		std::cerr << "INFO: symmetric decryption of message ..." << std::endl;
	if (encrypted_message.size() == 0)
	{
		if (verbose)
			std::cerr << "ERROR: nothing to decrypt" << std::endl;
		return false;
	}
	tmcg_openpgp_skalgo_t msg_skalgo = skalgo;
	if ((key.size() > 0) && (!have_aead))
		msg_skalgo = (tmcg_openpgp_skalgo_t)key[0];
	if (verbose > 1)
		std::cerr << "INFO: msg_skalgo = " << (int)msg_skalgo << std::endl;
	size_t sklen = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmKeyLength(msg_skalgo);
	tmcg_openpgp_secure_octets_t sk;
	if (key.size() == (sklen + 3))
	{
		for (size_t i = 0; i < key.size(); i++)
			sk.push_back(key[i]);
	}
	else if (key.size() == (sklen + 1))
	{
		for (size_t i = 0; i < sklen; i++)
			sk.push_back(key[1+i]);
	}
	else if (key.size() == sklen)
	{
		for (size_t i = 0; i < sklen; i++)
			sk.push_back(key[i]);
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: wrong length (" << key.size() <<
				" bytes) of session key found" << std::endl;
		return false;
	}
	if (have_aead)
	{
		tmcg_openpgp_octets_t ad; // additional data
		ad.push_back(0xD4); // packet tag in new format
		ad.push_back(0x01); // packet version number FIXME: read packet version from stored data
		ad.push_back(msg_skalgo); // cipher algorithm octet
		ad.push_back(aeadalgo); // AEAD algorithm octet
		ad.push_back(chunksize); // chunk size octet
		for (size_t i = 0; i < 8; i++)
			ad.push_back(0x00); // initial eight-octet big-endian chunk index
		gcry_error_t ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricDecryptAEAD(encrypted_message, sk, msg_skalgo, aeadalgo,
				chunksize, iv, ad, verbose, out);
		if (ret)
		{
			if (verbose)
			{
				std::cerr << "ERROR: SymmetricDecryptAEAD() failed" <<
					" with rc = " << gcry_err_code(ret) << 
					" str = " << gcry_strerror(ret) << std::endl;
			}
			return false;
		}
	}
	else
	{
		tmcg_openpgp_octets_t prefix;
		gcry_error_t ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricDecrypt(encrypted_message, sk, prefix, false, msg_skalgo,
				out);
		if (ret)
		{
			if (verbose)
				std::cerr << "ERROR: SymmetricDecrypt() failed" <<
					" with rc = " << gcry_err_code(ret) << std::endl;
			return false;
		}
		// copy the decryption result for computing the MDC
		if (have_seipd)
		{
			if (out.size() < 22)
			{
				if (verbose)
				{
					std::cerr << "ERROR: decrypted result too short" <<
						std::endl;
				}
				return false;
			}
			else if ((out[out.size() - 22] != 0xD3) ||
				(out[out.size() - 21] != 0x14))
			{
				if (verbose)
				{
					std::cerr << "ERROR: no appended MDC packet found" <<
						std::endl;
				}
				return false;
			}
			else		
			{
				tmcg_openpgp_octets_t mdc, mdc_message;
				mdc.insert(mdc.end(), out.end() - 20, out.end());
				if (verbose > 1)
				{
					std::cerr << "INFO: copy the message for MDC ..." <<
						std::endl;
				}
				mdc_message.insert(mdc_message.end(), out.begin(), out.end());
				mdc_message.resize(out.size() - 22); // remove MDC packet
				if (!CheckMDC(prefix, mdc, mdc_message, verbose))
					return false;
			}
		}
		else
		{
			if (verbose)
				std::cerr << "WARNING: encrypted message was not integrity" <<
					" protected" << std::endl;
		}
	}
	return true;
}

TMCG_OpenPGP_Message::~TMCG_OpenPGP_Message
	()
{
	iv.clear();
	for (size_t i = 0; i < PKESKs.size(); i++)
		delete PKESKs[i];
	PKESKs.clear();
	for (size_t i = 0; i < SKESKs.size(); i++)
		delete SKESKs[i];
	SKESKs.clear();
	encrypted_message.clear();
	signed_message.clear();
	compressed_message.clear();
	compressed_data.clear();
	literal_message.clear();
	literal_data.clear();
	mdc.clear();
	for (size_t i = 0; i < signatures.size(); i++)
		delete signatures[i];
}

// ===========================================================================

unsigned long int CallasDonnerhackeFinneyShawThayerRFC4880::tmcg_openpgp_mem_alloc = 0;

void CallasDonnerhackeFinneyShawThayerRFC4880::MemoryGuardReset
	()
{
	tmcg_openpgp_mem_alloc = 0;
}

unsigned long int CallasDonnerhackeFinneyShawThayerRFC4880::MemoryGuardInfo
	()
{
	return tmcg_openpgp_mem_alloc;
}

// ===========================================================================

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength
	(const tmcg_openpgp_skalgo_t algo)
{
	switch (algo)
	{
		case TMCG_OPENPGP_SKALGO_PLAINTEXT:
			return 0; // Plaintext or unencrypted data
		case TMCG_OPENPGP_SKALGO_IDEA: 
			return 16; // IDEA
		case TMCG_OPENPGP_SKALGO_3DES: 
			return 24; // TripleDES (168 bit key derived from 192)
		case TMCG_OPENPGP_SKALGO_CAST5:
			return 16; // CAST5 (128 bit key, as per [RFC2144])
		case TMCG_OPENPGP_SKALGO_BLOWFISH:
			return 16; // Blowfish (128 bit key, 16 rounds)
		case TMCG_OPENPGP_SKALGO_AES128:
			return 16; // AES with 128-bit key
		case TMCG_OPENPGP_SKALGO_AES192:
			return 24; // AES with 192-bit key
		case TMCG_OPENPGP_SKALGO_AES256:
			return 32; // AES with 256-bit key
		case TMCG_OPENPGP_SKALGO_TWOFISH:
			return 32; // Twofish with 256-bit key
		case TMCG_OPENPGP_SKALGO_CAMELLIA128:
			return 16; // Camellia with 128-bit key (cf. [RFC3713, RFC5581]) 
		case TMCG_OPENPGP_SKALGO_CAMELLIA192:
			return 24; // Camellia with 192-bit key (cf. [RFC3713, RFC5581])
		case TMCG_OPENPGP_SKALGO_CAMELLIA256:
			return 32; // Camellia with 256-bit key (cf. [RFC3713, RFC5581])
		default:
			return 0;
	}
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength
	(const tmcg_openpgp_skalgo_t algo)
{
	// Most ciphers have a block size of 8 octets. The AES and
	// Twofish have a block size of 16 octets.
	// [...]
	// If secret data is encrypted (string-to-key usage octet
	// not zero), an Initial Vector (IV) of the same length as the
	// cipher’s block size.
	switch (algo)
	{
		case TMCG_OPENPGP_SKALGO_PLAINTEXT:
			return 0; // Plaintext or unencrypted data
		case TMCG_OPENPGP_SKALGO_IDEA:
		case TMCG_OPENPGP_SKALGO_3DES:
		case TMCG_OPENPGP_SKALGO_CAST5:
		case TMCG_OPENPGP_SKALGO_BLOWFISH:
			return 8; // IDEA, TripleDES, CAST5, Blowfish
		case TMCG_OPENPGP_SKALGO_AES128:
		case TMCG_OPENPGP_SKALGO_AES192:
		case TMCG_OPENPGP_SKALGO_AES256:
		case TMCG_OPENPGP_SKALGO_TWOFISH:
			return 16; // AES128, AES192, AES256, Twofish
		case TMCG_OPENPGP_SKALGO_CAMELLIA128:
		case TMCG_OPENPGP_SKALGO_CAMELLIA192:
		case TMCG_OPENPGP_SKALGO_CAMELLIA256:
			return 16; // Camellia (cf. [RFC3713, RFC5581])
		default:
			return 0;
	}
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength
	(const tmcg_openpgp_aeadalgo_t algo)
{
	// The EAX algorithm can only use block ciphers with 16-octet blocks.
	// The starting initialization vector and authentication tag are both 16
	// octets long.
	// [...]
	// OCB usage requires specification of the following parameters:
	//  o  a blockcipher that operate on 128-bit (16-octet) blocks
	//  o  an authentication tag length of 16 octets
	//  o  a nonce of 15 octets long (which is the longest nonce allowed
	//     specified by [RFC7253])
	//  o  an initialization vector of at least 15 octets long
	//
	//  In the case that the initialization vector is longer than 15 octets
	//  (such as in Section {5.5.3} Secret-Key Packet Formats), only the 15
	//  leftmost octets are used in calculations; the remaining octets MUST
	//  be considered as zero.
	switch (algo)
	{
		case TMCG_OPENPGP_AEADALGO_EAX:
			return 16;
		case TMCG_OPENPGP_AEADALGO_OCB:
			return 15;
		default:
			return 0;
	}
}

int CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmSymGCRY
	(const tmcg_openpgp_skalgo_t algo)
{
	switch (algo)
	{
		// Plaintext or unencrypted data
		case TMCG_OPENPGP_SKALGO_PLAINTEXT:
			return GCRY_CIPHER_NONE;
		// IDEA
		case TMCG_OPENPGP_SKALGO_IDEA:
			return GCRY_CIPHER_IDEA;
		// TripleDES (DES-EDE, 168 bit key derived from 192)
		case TMCG_OPENPGP_SKALGO_3DES:
			return GCRY_CIPHER_3DES;
		// CAST5 (128 bit key, as per [RFC2144])
		case TMCG_OPENPGP_SKALGO_CAST5:
			return GCRY_CIPHER_CAST5;
		// Blowfish (128 bit key, 16 rounds)
		case TMCG_OPENPGP_SKALGO_BLOWFISH:
			return GCRY_CIPHER_BLOWFISH;
		// AES with 128-bit key
		case TMCG_OPENPGP_SKALGO_AES128:
			return GCRY_CIPHER_AES;
		// AES with 192-bit key
		case TMCG_OPENPGP_SKALGO_AES192:
			return GCRY_CIPHER_AES192;
		// AES with 256-bit key
		case TMCG_OPENPGP_SKALGO_AES256:
			return GCRY_CIPHER_AES256;
		// Twofish with 256-bit key
		case TMCG_OPENPGP_SKALGO_TWOFISH:
			return GCRY_CIPHER_TWOFISH;
		// Camellia with 128-bit key (cf. [RFC3713])
		case TMCG_OPENPGP_SKALGO_CAMELLIA128:
			return GCRY_CIPHER_CAMELLIA128;
		// Camellia with 192-bit key (cf. [RFC3713])
		case TMCG_OPENPGP_SKALGO_CAMELLIA192:
			return GCRY_CIPHER_CAMELLIA192;
		// Camellia with 256-bit key (cf. [RFC3713])
		case TMCG_OPENPGP_SKALGO_CAMELLIA256:
			return GCRY_CIPHER_CAMELLIA256;
		default:
			return 0;
	}
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashLength
	(const tmcg_openpgp_hashalgo_t algo)
{
	switch (algo)
	{
		case TMCG_OPENPGP_HASHALGO_MD5:
			return 16; // MD5
		case TMCG_OPENPGP_HASHALGO_SHA1:
		case TMCG_OPENPGP_HASHALGO_RMD160:
			return 20; // SHA-1, RIPE-MD/160
		case TMCG_OPENPGP_HASHALGO_SHA256:
			return 32; // SHA256
		case TMCG_OPENPGP_HASHALGO_SHA384:
			return 48; // SHA384
		case TMCG_OPENPGP_HASHALGO_SHA512:
			return 64; // SHA512
		case TMCG_OPENPGP_HASHALGO_SHA224:
			return 28; // SHA224
		default:
			return 0;
	}
}

int CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashGCRY
	(const tmcg_openpgp_hashalgo_t algo)
{
	switch (algo)
	{
		case TMCG_OPENPGP_HASHALGO_MD5:
			return GCRY_MD_MD5;
		case TMCG_OPENPGP_HASHALGO_SHA1:
			return GCRY_MD_SHA1;
		case TMCG_OPENPGP_HASHALGO_RMD160:
			return GCRY_MD_RMD160;
		case TMCG_OPENPGP_HASHALGO_SHA256:
			return GCRY_MD_SHA256;
		case TMCG_OPENPGP_HASHALGO_SHA384:
			return GCRY_MD_SHA384;
		case TMCG_OPENPGP_HASHALGO_SHA512:
			return GCRY_MD_SHA512;
		case TMCG_OPENPGP_HASHALGO_SHA224:
			return GCRY_MD_SHA224;
		default:
			return 0;
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashGCRYName
	(const tmcg_openpgp_hashalgo_t algo, std::string &out)
{
	switch (algo)
	{
		case TMCG_OPENPGP_HASHALGO_MD5:
			out = "md5";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA1:
			out = "sha1";
			break;
		case TMCG_OPENPGP_HASHALGO_RMD160:
			out = "rmd160";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA256:
			out = "sha256";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA384:
			out = "sha384";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA512:
			out = "sha512";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA224:
			out = "sha224";
			break;
		default:
			out = "unknown";
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashTextName
	(const tmcg_openpgp_hashalgo_t algo, std::string &out)
{
	switch (algo)
	{
		case TMCG_OPENPGP_HASHALGO_MD5:
			out = "MD5";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA1:
			out = "SHA1";
			break;
		case TMCG_OPENPGP_HASHALGO_RMD160:
			out = "RIPEMD160";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA256:
			out = "SHA256";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA384:
			out = "SHA384";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA512:
			out = "SHA512";
			break;
		case TMCG_OPENPGP_HASHALGO_SHA224:
			out = "SHA224";
			break;
		default:
			out = "unknown";
	}
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare
	(const tmcg_openpgp_octets_t &in, const tmcg_openpgp_octets_t &in2)
{
	if (in.size() != in2.size())
		return false;
	for (size_t i = 0; i < in.size(); i++)
		if (in[i] != in2[i])
			return false;
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareConstantTime
	(const tmcg_openpgp_secure_octets_t &in, const tmcg_openpgp_secure_octets_t &in2)
{
	size_t len = (in.size() < in2.size()) ? in.size() : in2.size(); 
	tmcg_openpgp_byte_t res = 0;

	for (size_t i = 0; i < len; i++)
		res |= in[i] ^ in2[i];
	return (res == 0) ? true : false;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero
	(const tmcg_openpgp_octets_t &in)
{
	for (size_t i = 0; i < in.size(); i++)
		if (in[i] != 0x00)
			return false;
	return true;
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode
	(const tmcg_openpgp_octets_t &in, std::string &out, const bool linebreaks)
{
	size_t len = in.size();
	size_t i = 0, c = 1;

	// Each 6-bit group is used as an index into an array of 
	// 64 printable characters from the table below. The character
	// referenced by the index is placed in the output string.
	for (; len >= 3; len -= 3, i += 3)
	{
		tmcg_openpgp_byte_t l[4];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2) + ((in[i+2] & 0xC0) >> 6);
		l[3] = in[i+2] & 0x3F;
		for (size_t j = 0; j < 4; j++, c++)
		{
			assert(l[j] < 64);
			out += tmcg_openpgp_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (((c % TMCG_OPENPGP_RADIX64_MC) == 0) &&
			    ((len >= 4) || (j < 3)) && linebreaks)
				out += "\r\n"; // add a line delimiter
		}
	}
	// Special processing is performed if fewer than 24 bits are
	// available at the end of the data being encoded. There are three
	// possibilities:
	// 1. The last data group has 24 bits (3 octets).
	//    No special processing is needed.
	// 2. The last data group has 16 bits (2 octets).
	//    The first two 6-bit groups are processed as above. The third
	//    (incomplete) data group has two zero-value bits added to it,
	//    and is processed as above. A pad character (=) is added to
	//    the output.
	// 3. The last data group has 8 bits (1 octet).
	//    The first 6-bit group is processed as above. The second
	//    (incomplete) data group has four zero-value bits added to it,
	//    and is processed as above. Two pad characters (=) are added
	//    to the output. 
	if (len == 2)
	{
		tmcg_openpgp_byte_t l[3];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2);
		for (size_t j = 0; j < 3; j++, c++)
		{
			out += tmcg_openpgp_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (linebreaks && ((c % TMCG_OPENPGP_RADIX64_MC) == 0))
				out += "\r\n"; // add a line delimiter
		}
		out += "=";
	}
	else if (len == 1)
	{
		tmcg_openpgp_byte_t l[2];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4);
		for (size_t j = 0; j < 2; j++, c++)
		{
			out += tmcg_openpgp_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (linebreaks && ((c % TMCG_OPENPGP_RADIX64_MC) == 0))
				out += "\r\n"; // add a line delimiter
		}
		out += "==";
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Decode
	(std::string in, tmcg_openpgp_octets_t &out)
{
	// remove all whitespaces, delimiters and other non-radix64 characters
	in.erase(std::remove_if(in.begin(), in.end(), NotRadix64), in.end());

	size_t len = in.size();
	for (size_t j = 0; j < (4 - (len % 4)); j++)
		in += "="; // append pad until a multiple of four reached
	for (size_t i = 0; i < len; i += 4)
	{
        	tmcg_openpgp_byte_t l[4];
		for (size_t j = 0; j < 4; j++)
			l[j] = tmcg_openpgp_fRadix64[(size_t)in[i+j]];
		tmcg_openpgp_byte_t t[3];
		t[0] = ((l[0] & 0x3F) << 2) + ((l[1] & 0x30) >> 4);
		t[1] = ((l[1] & 0x0F) << 4) + ((l[2] & 0x3C) >> 2);
		t[2] = ((l[2] & 0x03) << 6) + (l[3] & 0x3F);
		for (size_t j = 0; j < 3; j++)
		{
			if (l[j+1] != 255)
				out.push_back(t[j]);
		}
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CRC24Compute
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// The CRC is computed by using the generator 0x864CFB and an
	// initialization of 0xB704CE. The accumulation is done on the
	// data before it is converted to radix-64, rather than on the
	// converted data. A sample implementation of this algorithm is
	// in the next section. 
	uint32_t crc = TMCG_OPENPGP_CRC24_INIT;
	for (size_t len = 0; len < in.size(); len++)
	{
		crc ^= in[len] << 16;
		for (size_t i = 0; i < 8; i++)
		{
			crc <<= 1;
			if (crc & 0x1000000)
				crc ^= TMCG_OPENPGP_CRC24_POLY;
		}
	}
	crc &= 0xFFFFFF;
	out.push_back((crc >> 16) & 0xFF);
	out.push_back((crc >> 8) & 0xFF);
	out.push_back(crc & 0xFF);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CRC24Encode
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	tmcg_openpgp_octets_t crc;

	// The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted
	// to four characters of radix-64 encoding by the same MIME base64
	// transformation, preceded by an equal sign (=).
	out += "=";
	CRC24Compute(in, crc);
	Radix64Encode(crc, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode
	(const tmcg_openpgp_armor_t type, const tmcg_openpgp_octets_t &in,
	 std::string &out)
{
	// Concatenating the following data creates ASCII Armor:
	//  - An Armor Header Line, appropriate for the type of data
	//  - Armor Headers
	//  - A blank (zero-length, or containing only whitespace) line
	//  - The ASCII-Armored data
	//  - An Armor Checksum
	//  - The Armor Tail, which depends on the Armor Header Line

	// An Armor Header Line consists of the appropriate header line text
	// surrounded by five (5) dashes ('-', 0x2D) on either side of the
	// header line text. The header line text is chosen based upon the
	// type of data that is being encoded in Armor, and how it is being
	// encoded. Header line texts include the following strings:
	// [...]
	// BEGIN PGP PUBLIC KEY BLOCK
	//    Used for armoring public keys.
	// BEGIN PGP PRIVATE KEY BLOCK
	//    Used for armoring private keys.
	// [...]
	// Note that all these Armor Header Lines are to consist of a complete
	// line. That is to say, there is always a line ending preceding the
	// starting five dashes, and following the ending five dashes. The
	// header lines, therefore, MUST start at the beginning of a line, and
	// MUST NOT have text other than whitespace following them on the same
	// line. These line endings are considered a part of the Armor Header
	// Line for the purposes of determining the content they delimit.
	switch (type)
	{
		case TMCG_OPENPGP_ARMOR_MESSAGE:
			out += "-----BEGIN PGP MESSAGE-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_SIGNATURE:
			out += "-----BEGIN PGP SIGNATURE-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK:
			out += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK:
			out += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
			break;
		default:
			break;
	}

	// The Armor Headers are pairs of strings that can give the user or 
	// the receiving OpenPGP implementation some information about how to
	// decode or use the message. The Armor Headers are a part of the
	// armor, not a part of the message, and hence are not protected by
	// any signatures applied to the message.
	// The format of an Armor Header is that of a key-value pair. A colon
	// (':' 0x38) and a single space (0x20) separate the key and value.
	// [...]
	// Currently defined Armor Header Keys are as follows:
	//  - "Version", which states the OpenPGP implementation and version
	//    used to encode the message.
	out += "Version: LibTMCG " VERSION "\r\n";

	// Next, a blank (zero-length, or containing only whitespace) line
	out += "\r\n";

	// Next, the ASCII-Armored data
	Radix64Encode(in, out);
	out += "\r\n";

	// Next, an Armor Checksum
	CRC24Encode(in, out);
	out += "\r\n";

	// The Armor Tail Line is composed in the same manner as the Armor
	// Header Line, except the string "BEGIN" is replaced by the string
	// "END".
	switch (type)
	{
		case TMCG_OPENPGP_ARMOR_MESSAGE:
			out += "-----END PGP MESSAGE-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_SIGNATURE:
			out += "-----END PGP SIGNATURE-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK:
			out += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
			break;
		case TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK:
			out += "-----END PGP PUBLIC KEY BLOCK-----\r\n";
			break;
		default:
			break;
	}
}

tmcg_openpgp_armor_t CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode
	(std::string in, tmcg_openpgp_octets_t &out)
{
	tmcg_openpgp_armor_t type = TMCG_OPENPGP_ARMOR_UNKNOWN;
	size_t spos = 0, epos = 0, rpos = 0, rlen = 4, cpos = 0, clen = 3;

	spos = in.find("-----BEGIN PGP MESSAGE-----");
	epos = in.find("-----END PGP MESSAGE-----");
	if ((spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = TMCG_OPENPGP_ARMOR_MESSAGE;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP SIGNATURE-----");
		epos = in.find("-----END PGP SIGNATURE-----");
	}		
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = TMCG_OPENPGP_ARMOR_SIGNATURE;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP PRIVATE KEY BLOCK-----");
		epos = in.find("-----END PGP PRIVATE KEY BLOCK-----");
	}		
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP PUBLIC KEY BLOCK-----");
		epos = in.find("-----END PGP PUBLIC KEY BLOCK-----");
	}
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK;
	in.erase(std::remove(in.begin(), in.end(), ' '), in.end());
	in.erase(std::remove(in.begin(), in.end(), '\t'), in.end());
	switch (type)
	{
		case TMCG_OPENPGP_ARMOR_MESSAGE:
			spos = in.find("-----BEGINPGPMESSAGE-----");
			epos = in.find("-----ENDPGPMESSAGE-----");
			break;
		case TMCG_OPENPGP_ARMOR_SIGNATURE:
			spos = in.find("-----BEGINPGPSIGNATURE-----");
			epos = in.find("-----ENDPGPSIGNATURE-----");
			break;
		case TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK:
			spos = in.find("-----BEGINPGPPRIVATEKEYBLOCK-----");
			epos = in.find("-----ENDPGPPRIVATEKEYBLOCK-----");
			break;
		case TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK:
			spos = in.find("-----BEGINPGPPUBLICKEYBLOCK-----");
			epos = in.find("-----ENDPGPPUBLICKEYBLOCK-----");
			break;
		default:
			return TMCG_OPENPGP_ARMOR_UNKNOWN; // header and trailer not found
	}
	rpos = in.find("\r\n\r\n", spos);
	if (rpos == in.npos)
	{
		rpos = in.find("\n\n", spos);
		rlen = 2;
	}
	cpos = in.find("\r\n=", spos); // TODO: use regex for reliable detection
	if (cpos == in.npos)
	{
		cpos = in.find("\n=");
		clen = 2;
	}
	if ((rpos == in.npos) || (cpos == in.npos))
		return TMCG_OPENPGP_ARMOR_UNKNOWN; // wrong radix64 encoding
	if (((spos + 24) < rpos) && ((rpos + rlen) < cpos) &&
	    ((cpos + clen + 4) < epos))
	{
		if (in.find("-----", spos + 33) != epos)
			return TMCG_OPENPGP_ARMOR_UNKNOWN; // nested armor block
		tmcg_openpgp_octets_t decoded_data;
		std::string chksum = "";
		std::string data = in.substr(rpos + rlen, cpos - rpos - rlen);
		Radix64Decode(data, decoded_data);
		CRC24Encode(decoded_data, chksum);
		if (chksum != in.substr(cpos + (clen - 1), 5))
		{
			std::cerr << "ERROR: wrong checksum in ArmorDecode()" << std::endl;
			return TMCG_OPENPGP_ARMOR_UNKNOWN; // checksum error
		}
		out.insert(out.end(), decoded_data.begin(), decoded_data.end());
		return type;
	}
	else
	{
		std::cerr << "ERROR: ArmorDecode() spos = " << spos <<
			" rpos = " << rpos << " cpos = " << cpos <<
			" epos = " << epos << " rlen = " << rlen << std::endl; 
		return TMCG_OPENPGP_ARMOR_UNKNOWN;
	}
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::DashEscapeFile
	(const std::string &filename, std::string &out)
{
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
		return false;
	// Dash-escaped cleartext is the ordinary cleartext where every line
	// starting with a dash ’-’ (0x2D) is prefixed by the sequence dash ’-’
	// (0x2D) and space ’ ’ (0x20). This prevents the parser from
	// recognizing armor headers of the cleartext itself. An implementation
	// MAY dash-escape any line, SHOULD dash-escape lines commencing "From"
	// followed by a space, and MUST dash-escape any line commencing in a
	// dash. The message digest is computed using the cleartext itself, not
	// the dash-escaped form.
	// As with binary signatures on text documents, a cleartext signature is
	// calculated on the text using canonical <CR><LF> line endings. The
	// line ending (i.e., the <CR><LF>) before the ’-----BEGIN PGP
	// SIGNATURE-----’ line that terminates the signed text is not
	// considered part of the signed text.
	// [...]
	// Also, any trailing whitespace -- spaces (0x20) and tabs (0x09) -- at
	// the end of any line is removed when the cleartext signature is
	// generated.
	char line[19995]; // we use the constant from GnuPG for maximum line chars
	while (ifs.getline(line, sizeof(line)))
	{
		std::string line_str(line);
		if ((line_str.find("-") == 0) || (line_str.find("From ") == 0))
			line_str = "- " + line_str;
		size_t line_len = line_str.length();
		while ((line_len > 0) && ((line_str[line_len-1] == ' ') ||
			(line_str[line_len-1] == '\t') || (line_str[line_len-1] == '\r')))
		{
			line_len--;
		}
		line_str = line_str.substr(0, line_len);
		if (!ifs.eof())
			out += line_str + "\r\n";
		else
			out += line_str;
	}
	if (!ifs.eof())
	{
		ifs.close();
		return false;
	}
	ifs.close();
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	tmcg_openpgp_byte_t *buffer = new tmcg_openpgp_byte_t[in.size() + 3];
	tmcg_openpgp_byte_t *hash = new tmcg_openpgp_byte_t[20]; // SHA-1 size

	// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	// followed by the two-octet packet length, followed by the entire
	// Public-Key packet starting with the version field.
	buffer[0] = 0x99;
	buffer[1] = (in.size() >> 8) & 0xFF;
	buffer[2] = in.size() & 0xFF;
	for (size_t i = 0; i < in.size(); i++)
		buffer[3+i] = in[i];
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, in.size() + 3);
	for (size_t i = 0; i < 20; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintConvertPlain
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	char *hex_digest = new char[(2 * in.size()) + 1];
	memset(hex_digest, 0, (2 * in.size()) + 1);
	for (size_t i = 0; i < in.size(); i++)
		snprintf(hex_digest + (2 * i), 3, "%02X", in[i]);
	out = hex_digest;
	delete [] hex_digest;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintConvertPretty
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	char *hex_digest = new char[(3 * in.size()) + 1];
	memset(hex_digest, 0, (3 * in.size()) + 1);
	for (size_t i = 0; i < (in.size() / 2); i++)
		snprintf(hex_digest + (5 * i), 6, "%02X%02X ", in[2*i], in[(2*i)+1]);
	out = hex_digest;
	delete [] hex_digest;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	tmcg_openpgp_octets_t fpr;
	FingerprintCompute(in, fpr);
	FingerprintConvertPlain(fpr, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute
	(const std::string &in, std::string &out)
{
	tmcg_openpgp_octets_t input, fpr;
	for (size_t i = 0; i < in.length(); i++)
		input.push_back(in[i]);
	FingerprintCompute(input, fpr);
	FingerprintConvertPlain(fpr, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintComputePretty
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	tmcg_openpgp_octets_t fpr;
	FingerprintCompute(in, fpr);
	FingerprintConvertPretty(fpr, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	tmcg_openpgp_octets_t fpr;

	// A Key ID is an eight-octet scalar that identifies a key.
	// Implementations SHOULD NOT assume that Key IDs are unique.
	// [...]
	// The Key ID is the low-order 64 bits of the fingerprint.
	FingerprintCompute(in, fpr);
	for (size_t i = 12; i < 20; i++)
		out.push_back(fpr[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyidConvert
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	char *hex_digest = new char[(2 * in.size()) + 1];
	memset(hex_digest, 0, (2 * in.size()) + 1);
	for (size_t i = 0; i < in.size(); i++)
		snprintf(hex_digest + (2 * i), 3, "%02X", in[i]);
	out = hex_digest;
	delete [] hex_digest;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	tmcg_openpgp_octets_t kid;
	KeyidCompute(in, kid);
	KeyidConvert(kid, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_openpgp_hashalgo_t algo, const tmcg_openpgp_octets_t &in,
	 tmcg_openpgp_octets_t &out)
{
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);

	if (!dlen || !in.size())
	{
		out.clear(); // indicates an error
		return;
	}
	tmcg_openpgp_byte_t *buffer = new tmcg_openpgp_byte_t[in.size()];
	tmcg_openpgp_byte_t *hash = new tmcg_openpgp_byte_t[dlen];
	for (size_t i = 0; i < in.size(); i++)
		buffer[i] = in[i];
	gcry_md_hash_buffer(a, hash, buffer, in.size()); 
	for (size_t i = 0; i < dlen; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_openpgp_hashalgo_t algo,
	 const tmcg_openpgp_secure_octets_t &in,
	 tmcg_openpgp_secure_octets_t &out)
{
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, GCRY_MD_FLAG_SECURE);
	if (ret)
		return ret;
	for (size_t i = 0; i < in.size(); i++)
		gcry_md_putc(hd, in[i]);
	gcry_md_final(hd);
	tmcg_openpgp_byte_t *buf = gcry_md_read(hd, a);
	if (buf == NULL)
	{	
		gcry_md_close(hd);
		return GPG_ERR_DIGEST_ALGO;
	}
	for (size_t i = 0; i < dlen; i++)
		out.push_back(buf[i]);
	gcry_md_close(hd);
	return 0;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_openpgp_hashalgo_t algo, const size_t cnt,
	 const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	size_t c = in.size();
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, 0);
	if (ret || (hd == NULL) || !dlen || !in.size())
	{
		out.clear(); // indicates an error
		return;
	}
	for (size_t i = 0; i < in.size(); i++)
		gcry_md_putc(hd, in[i]);
	while (c < cnt)
	{
		for (size_t i = 0; (i < in.size()) && (c < cnt); i++, c++)
			gcry_md_putc(hd, in[i]);
	}
	gcry_md_final(hd);
	tmcg_openpgp_byte_t *hash = gcry_md_read(hd, a);
	if (hash != NULL)
	{
		for (size_t i = 0; i < dlen; i++)
			out.push_back(hash[i]);
	}
	else
		out.clear(); // indicates an error
	gcry_md_close(hd);
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_openpgp_hashalgo_t algo, const size_t cnt,
	 const tmcg_openpgp_secure_octets_t &in,
	 tmcg_openpgp_secure_octets_t &out)
{
	size_t c = in.size();
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, GCRY_MD_FLAG_SECURE);
	if (ret)
		return ret;
	for (size_t i = 0; i < in.size(); i++)
		gcry_md_putc(hd, in[i]);
	while (c < cnt)
	{
		for (size_t i = 0; (i < in.size()) && (c < cnt); i++, c++)
			gcry_md_putc(hd, in[i]);
	}
	gcry_md_final(hd);
	tmcg_openpgp_byte_t *buf = gcry_md_read(hd, a);
	if (buf == NULL)
	{	
		gcry_md_close(hd);
		return GPG_ERR_DIGEST_ALGO;
	}
	for (size_t i = 0; i < dlen; i++)
		out.push_back(buf[i]);
	gcry_md_close(hd);
	return 0;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::HashComputeFile
	(const tmcg_openpgp_hashalgo_t algo, const std::string &filename,
	 const bool text, const tmcg_openpgp_octets_t &trailer,
	 tmcg_openpgp_octets_t &out)
{
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, 0);
	if (ret || (hd == NULL) || !dlen)
		return false;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		gcry_md_close(hd);
		return false;
	}
	if (text)
	{
		char line[19995]; // constant from GnuPG for maximum chars of a line
		while (ifs.getline(line, sizeof(line)))
		{
			std::string line_str(line);
			size_t line_len = line_str.length();
			while ((line_len > 0) && ((line_str[line_len-1] == ' ') ||
				(line_str[line_len-1] == '\t') ||
				(line_str[line_len-1] == '\r')))
			{
				line_len--;
			}
			line_str = line_str.substr(0, line_len);
			for (size_t i = 0; i < line_str.length(); i++)
				gcry_md_putc(hd, line_str[i]);
			if (!ifs.eof())
			{
				gcry_md_putc(hd, '\r'); // convert line ending to <CR><LF>
				gcry_md_putc(hd, '\n');
			}
		}
	}
	else
	{
		char c;
		while (ifs.get(c))
			gcry_md_putc(hd, c);
	}
	if (!ifs.eof())
	{
		ifs.close();
		gcry_md_close(hd);
		return false;
	}
	ifs.close();
	for (size_t i = 0; i < trailer.size(); i++)
		gcry_md_putc(hd, trailer[i]);
	tmcg_openpgp_byte_t *hash = gcry_md_read(hd, a);
	if (hash != NULL)
	{
		for (size_t i = 0; i < dlen; i++)
			out.push_back(hash[i]);
	}
	else
	{
		gcry_md_close(hd);
		return false;
	}
	gcry_md_close(hd);
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute
	(const tmcg_openpgp_hashalgo_t algo, const size_t sklen,
	 const tmcg_openpgp_secure_string_t &in, const tmcg_openpgp_octets_t &salt,
	 const bool iterated, const tmcg_openpgp_byte_t octcnt, 
	 tmcg_openpgp_secure_octets_t &out)
{
	// The count is coded into a one-octet number using the following
	// formula:
	//   #define EXPBIAS 6
	//     count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
	// The above formula is in C, where "Int32" is a type for a 32-bit
	// integer, and the variable "c" is the coded count, Octet 10.
	size_t hashcnt = (16 + (octcnt & 15)) << ((octcnt >> 4) + 6);
	size_t hashlen = AlgorithmHashLength(algo);

	// Simple S2K hashes the passphrase to produce the session key. The
	// manner in which this is done depends on the size of the session key
	// (which will depend on the cipher used) and the size of the hash
	// algorithm's output. If the hash size is greater than the session key
	// size, the high-order (leftmost) octets of the hash are used as the
	// key.
	// If the hash size is less than the key size, multiple instances of
	// the hash context are created -- enough to produce the required key
	// data.
	// These instances are preloaded with 0, 1, 2, ... octets of zeros
	// (that is to say, the first instance has no preloading, the second
	// gets preloaded with 1 octet of zero, the third is preloaded with
	// two octets of zeros, and so forth).
	// As the data is hashed, it is given independently to each hash
	// context. Since the contexts have been initialized differently, they
	// will each produce different hash output. Once the passphrase is
	// hashed, the output data from the multiple hashes is concatenated,
	// first hash leftmost, to produce the key data, with any excess octets
	// on the right discarded.
	// [...]
	// Salted S2K is exactly like Simple S2K, except that the input to the
	// hash function(s) consists of the 8 octets of salt from the S2K
	// specifier, followed by the passphrase.
	if (salt.size() != 8)
		return;
	// [...]
	// Iterated-Salted S2K hashes the passphrase and salt data multiple
	// times. The total number of octets to be hashed is specified in the
	// encoded count in the S2K specifier. Note that the resulting count
	// value is an octet count of how many octets will be hashed, not an
	// iteration count.
	// Initially, one or more hash contexts are set up as with the other
	// S2K algorithms, depending on how many octets of key data are needed.
	// Then the salt, followed by the passphrase data, is repeatedly hashed
	// until the number of octets specified by the octet count has been
	// hashed. The one exception is that if the octet count is less than
	// the size of the salt plus passphrase, the full salt plus passphrase
	// will be hashed even though that is greater than the octet count.
	// After the hashing is done, the data is unloaded from the hash
	// context(s) as with the other S2K algorithms.
	if (hashlen >= sklen)
	{
		tmcg_openpgp_secure_octets_t hash_in, hash_out;
		hash_in.insert(hash_in.end(), salt.begin(), salt.end());
		for (size_t i = 0; i < in.length(); i++)
			hash_in.push_back(in[i]);
		if (iterated)
			HashCompute(algo, hashcnt, hash_in, hash_out);
		else
			HashCompute(algo, hash_in, hash_out);
		for (size_t i = 0; (i < hash_out.size()) && (i < sklen); i++)
			out.push_back(hash_out[i]);
	}
	else if (hashlen > 0)
	{
		size_t instances = (sklen / hashlen) + 1;
		size_t skcnt = 0;
		for (size_t j = 0; j < instances; j++)
		{
			tmcg_openpgp_secure_octets_t hash_in, hash_out;
			for (size_t i = 0; i < j; i++)
				hash_in.push_back(0x00); // preload with zeros
			hash_in.insert(hash_in.end(), salt.begin(), salt.end());
			for (size_t i = 0; i < in.length(); i++)
				hash_in.push_back(in[i]);
			if (iterated)
				HashCompute(algo, hashcnt, hash_in, hash_out);
			else
				HashCompute(algo, hash_in, hash_out);
			for (size_t i = 0; (i < hash_out.size()) && 
			     (skcnt < sklen); i++, skcnt++)
				out.push_back(hash_out[i]);
		}
	}
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::KDFCompute
	(const tmcg_openpgp_hashalgo_t hashalgo,
	 const tmcg_openpgp_skalgo_t skalgo,
	 const tmcg_openpgp_secure_octets_t &ZB,
	 const std::string &curve,
	 const tmcg_openpgp_octets_t &rcpfpr,
	 tmcg_openpgp_secure_octets_t &MB)
{
	// compute Key Derivation Function (KDF) for ECDH [RFC 6637]
	tmcg_openpgp_secure_octets_t kdf_buffer;
	kdf_buffer.push_back(0x00);
	kdf_buffer.push_back(0x00);
	kdf_buffer.push_back(0x00);
	kdf_buffer.push_back(0x01);
	for (size_t i = 0; i < ZB.size(); i++)
		kdf_buffer.push_back(ZB[i]); // x-coordinate of the shared secret point
	for (size_t idx = 0; (tmcg_openpgp_oidtable[idx].name != NULL); idx++)
	{
		if (curve == tmcg_openpgp_oidtable[idx].name)
		{
			for (size_t i = 0; i <= tmcg_openpgp_oidtable[idx].oid[0]; i++)
				kdf_buffer.push_back(tmcg_openpgp_oidtable[idx].oid[i]); // OID
			break;
		}
	}
	kdf_buffer.push_back(TMCG_OPENPGP_PKALGO_ECDH);
	kdf_buffer.push_back(0x03); // length of KDF parameters
	kdf_buffer.push_back(0x01);
	kdf_buffer.push_back(hashalgo);
	kdf_buffer.push_back(skalgo);
	kdf_buffer.push_back(0x41); // UTF-8 encoding of "Anonymous Sender    "
	kdf_buffer.push_back(0x6E);
	kdf_buffer.push_back(0x6F);
	kdf_buffer.push_back(0x6E);
	kdf_buffer.push_back(0x79);
	kdf_buffer.push_back(0x6D);
	kdf_buffer.push_back(0x6F);
	kdf_buffer.push_back(0x75);
	kdf_buffer.push_back(0x73);
	kdf_buffer.push_back(0x20);
	kdf_buffer.push_back(0x53);
	kdf_buffer.push_back(0x65);
	kdf_buffer.push_back(0x6E);
	kdf_buffer.push_back(0x64);
	kdf_buffer.push_back(0x65);
	kdf_buffer.push_back(0x72);
	kdf_buffer.push_back(0x20);
	kdf_buffer.push_back(0x20);
	kdf_buffer.push_back(0x20);
	kdf_buffer.push_back(0x20);
	for (size_t i = 0; i < rcpfpr.size(); i++)
		kdf_buffer.push_back(rcpfpr[i]); // fingerprint of recipient's key
	return HashCompute(hashalgo, kdf_buffer, MB);
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTagEncode
	(const tmcg_openpgp_byte_t tag, tmcg_openpgp_octets_t &out)
{
	// always use V4 (new) packet format
	out.push_back(tag | 0x80 | 0x40);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketLengthEncode
	(const size_t len, tmcg_openpgp_octets_t &out)
{
	if (len < 192)
	{
		// one-octet length format
		out.push_back(len);
	}
	else if (len < 8384)
	{
		size_t tlen = (len - 192) + (192 << 8);
		// two-octet length format
		out.push_back((tlen >> 8) & 0xFF);
		out.push_back(tlen & 0xFF);
	}
	else
	{
		// four-octet length format with 0xFF prefix
		out.push_back(0xFF);
		out.push_back((len >> 24) & 0xFF);
		out.push_back((len >> 16) & 0xFF);
		out.push_back((len >> 8) & 0xFF);
		out.push_back(len & 0xFF);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FixedLengthEncode
	(const size_t len, tmcg_openpgp_octets_t &out)
{
	// four-octet length format with 0xFF prefix
	out.push_back(0xFF);
	out.push_back((len >> 24) & 0xFF);
	out.push_back((len >> 16) & 0xFF);
	out.push_back((len >> 8) & 0xFF);
	out.push_back(len & 0xFF);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketLengthDecode
	(const tmcg_openpgp_octets_t &in, const bool newformat,
	 tmcg_openpgp_byte_t lentype, uint32_t &len, bool &partlen)
{
	// New format packets have four possible ways of encoding length:
	// 1. A one-octet Body Length header encodes packet lengths of up to
	//    191 octets.
	// 2. A two-octet Body Length header encodes packet lengths of 192 to
	//    8383 octets.
	// 3. A five-octet Body Length header encodes packet lengths of up to
	//    4,294,967,295 (0xFFFFFFFF) octets in length. (This actually
	//    encodes a four-octet scalar number.)
	// 4. When the length of the packet body is not known in advance by
	//    the issuer, Partial Body Length headers encode a packet of
	//    indeterminate length, effectively making it a stream.
	partlen = false;
	if (in.size() < 1)
		return 0; // error: too few octets of length encoding
	if (newformat && (in[0] < 192))
	{
		// A one-octet Body Length header encodes a length of 0 to
		// 191 octets. This type of length header is recognized
		// because the one octet value is less than 192.
		len = in[0];	
		return 1;
	}
	else if (newformat && (in[0] < 224))
	{
		if (in.size() < 2)
			return 0; // error: too few octets of length encoding
		// A two-octet Body Length header encodes a length of 192 to
		// 8383 octets. It is recognized because its first octet is
		// in the range 192 to 223.
		len = ((in[0] - 192) << 8) + in[1] + 192;
		return 2;
	}
	else if (newformat && (in[0] == 255))
	{
		if (in.size() < 5)
			return 0; // error: too few octets of length encoding
		// A five-octet Body Length header consists of a single octet
		// holding the value 255, followed by a four-octet scalar.
		len = (in[1] << 24) + (in[2] << 16) + (in[3] << 8) + in[4];
		return 5;
	}
	else if (newformat)
	{
		// A Partial Body Length header is one octet long and encodes
		// the length of only part of the data packet. This length is
		// a power of 2, from 1 to 1,073,741,824 (2 to the 30th
		// power). It is recognized by its one octet value that is
		// greater than or equal to 224, and less than 255.
		len = (1 << (in[0] & 0x1F));
		partlen = true;
		return 1;
	}
	else if (!newformat && (lentype == 0x00))
	{
		// The packet has a one-octet length.
		len = in[0];
		return 1;
	}
	else if (!newformat && (lentype == 0x01))
	{
		// The packet has a two-octet length.
		if (in.size() < 2)
			return 0; // error: too few octets of length encoding
		len = (in[0] << 8) + in[1];
		return 2;
	}
	else if (!newformat && (lentype == 0x02))
	{
		// The packet has a four-octet length.
		if (in.size() < 4)
			return 0; // error: too few octets of length encoding
		// A five-octet Body Length header consists of a single octet
		len = (in[0] << 24) + (in[1] << 16) + (in[2] << 8) + in[3];
		return 4;
	}
	else if (!newformat && (lentype == 0x03))
	{
		// The packet is of indeterminate length. The header is 1 octet
		// long, and the implementation must determine how long the packet
		// is. If the packet is in a file, this means that the packet
		// extends until the end of the file.
		len = in.size();
		return 42;
	}
	else
		return 0; // error: unknown length type 
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(const time_t in, tmcg_openpgp_octets_t &out)
{
	// A time field is an unsigned four-octet number containing the number
	// of seconds elapsed since midnight, 1 January 1970 UTC.
	out.push_back((in >> 24) & 0xFF);
	out.push_back((in >> 16) & 0xFF);
	out.push_back((in >> 8) & 0xFF);
	out.push_back(in & 0xFF);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(tmcg_openpgp_octets_t &out)
{
	time_t current = time(NULL);
	PacketTimeEncode(current, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(const gcry_mpi_t in, tmcg_openpgp_octets_t &out, size_t &sum)
{
	gcry_error_t ret;
	size_t bitlen = gcry_mpi_get_nbits(in);
	size_t buflen = ((bitlen + 7) / 8) + 2;
	tmcg_openpgp_byte_t *buffer = new tmcg_openpgp_byte_t[buflen];

	// Multiprecision integers (also called MPIs) are unsigned integers
	// used to hold large integers such as the ones used in cryptographic
	// calculations.
	// An MPI consists of two pieces: a two-octet scalar that is the length
	// of the MPI in bits followed by a string of octets that contain the
	// actual integer.
	// These octets form a big-endian number; a big-endian number can be
	// made into an MPI by prefixing it with the appropriate length.
	ret = gcry_mpi_print(GCRYMPI_FMT_PGP, buffer, buflen, &buflen, in);
	for (size_t i = 0; ((!ret) && (i < buflen)); i++)
	{
		out.push_back(buffer[i]);
		sum += buffer[i];
		sum %= 65536;
	}
	delete [] buffer;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(const gcry_mpi_t in, tmcg_openpgp_secure_octets_t &out, size_t &sum)
{
	gcry_error_t ret;
	size_t bitlen = gcry_mpi_get_nbits(in);
	size_t buflen = ((bitlen + 7) / 8) + 2;
	unsigned char *buffer = (unsigned char*)gcry_malloc_secure(buflen);
	if (buffer == NULL)
		return; // cannot allocate secure memory

	// Multiprecision integers (also called MPIs) are unsigned integers
	// used to hold large integers such as the ones used in cryptographic
	// calculations.
	// An MPI consists of two pieces: a two-octet scalar that is the length
	// of the MPI in bits followed by a string of octets that contain the
	// actual integer.
	// These octets form a big-endian number; a big-endian number can be
	// made into an MPI by prefixing it with the appropriate length.
	ret = gcry_mpi_print(GCRYMPI_FMT_PGP, buffer, buflen, &buflen, in);
	for (size_t i = 0; ((!ret) && (i < buflen)); i++)
	{
		out.push_back(buffer[i]);
		sum += buffer[i];
		sum %= 65536;
	}
	gcry_free(buffer);
}


void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(const gcry_mpi_t in, tmcg_openpgp_octets_t &out)
{
	size_t sum = 0;
	PacketMPIEncode(in, out, sum);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(const gcry_mpi_t in, tmcg_openpgp_secure_octets_t &out)
{
	size_t sum = 0;
	PacketMPIEncode(in, out, sum);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const tmcg_openpgp_octets_t &in, gcry_mpi_t &out, size_t &sum)
{
	gcry_error_t ret;

	if (in.size() < 2)
		return 0; // error: no length given
	size_t buflen = ((in[0] << 8) + in[1] + 7) / 8;
	sum += in[0];
	sum %= 65536;
	sum += in[1];
	sum %= 65536;
	if (in.size() < (2 + buflen))
		return 0; // error: mpi too short
	tmcg_openpgp_byte_t *buffer = new tmcg_openpgp_byte_t[buflen];
	for (size_t i = 0; i < buflen; i++)
	{
		buffer[i] = in[2+i];
		sum += buffer[i];
		sum %= 65536;
	}
	gcry_mpi_release(out); // release an already allocated mpi
	ret = gcry_mpi_scan(&out, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	delete [] buffer;
	if (ret)
		return 0; // error: could not read/parse mpi
	else
		return (2 + buflen);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const tmcg_openpgp_secure_octets_t &in, gcry_mpi_t &out, size_t &sum)
{
	gcry_error_t ret;

	if (in.size() < 2)
		return 0; // error: no length given
	size_t buflen = ((in[0] << 8) + in[1] + 7) / 8;
	sum += in[0];
	sum %= 65536;
	sum += in[1];
	sum %= 65536;
	if (in.size() < (2 + buflen))
		return 0; // error: mpi too short
	unsigned char *buffer = (unsigned char*)gcry_malloc_secure(buflen);
	if (buffer == NULL)
		return 0; // error: cannot allocate secure memory
	for (size_t i = 0; i < buflen; i++)
	{
		buffer[i] = in[2+i];
		sum += buffer[i];
		sum %= 65536;
	}
	gcry_mpi_release(out); // release an already allocated mpi
	ret = gcry_mpi_scan(&out, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	gcry_free(buffer);
	if (ret)
		return 0; // error: could not read/parse mpi
	else
		return (2 + buflen);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const tmcg_openpgp_octets_t &in, gcry_mpi_t &out)
{
	size_t sum = 0;
	return PacketMPIDecode(in, out, sum);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const tmcg_openpgp_secure_octets_t &in, gcry_mpi_t &out)
{
	size_t sum = 0;
	return PacketMPIDecode(in, out, sum);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketStringEncode
	(const std::string &in, tmcg_openpgp_octets_t &out)
{
	FixedLengthEncode(in.length(), out);
	for (size_t i = 0; i < in.length(); i++)
		out.push_back(in[i]);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketStringDecode
	(const tmcg_openpgp_octets_t &in, std::string &out)
{
	size_t headlen = 0;
	uint32_t len = 0;
	bool partlen = false;

	headlen = PacketLengthDecode(in, true, 0x00, len, partlen);
	if (!headlen || partlen || (headlen == 42))
		return 0; // error: wrong length
	if (!len)
		return 0; // error: string of zero length
	if (in.size() < (len + headlen))
		return 0; // error: input too short 
	for (size_t i = 0; i < len; i++)
		out += in[headlen+i];
	return (len + headlen);
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode
	(const tmcg_openpgp_octets_t &keyid, const gcry_mpi_t gk,
	 const gcry_mpi_t myk, tmcg_openpgp_octets_t &out)
{
	size_t gklen = (gcry_mpi_get_nbits(gk) + 7) / 8;
	size_t myklen = (gcry_mpi_get_nbits(myk) + 7) / 8;

	// A Public-Key Encrypted Session Key packet holds the session key used
	// to encrypt a message. Zero or more Public-Key Encrypted Session Key
	// packets and/or Symmetric-Key Encrypted Session Key packets may
	// precede a Symmetrically Encrypted Data Packet, which holds an
	// encrypted message. The message is encrypted with the session key,
	// and the session key is itself encrypted and stored in the Encrypted
	// Session Key packet(s). The Symmetrically Encrypted Data Packet is
	// preceded by one Public-Key Encrypted Session Key packet for each
	// OpenPGP key to which the message is encrypted. The recipient of the
	// message finds a session key that is encrypted to their public key,
	// decrypts the session key, and then uses the session key to decrypt
	// the message.
	// The body of this packet consists of:
	//  - A one-octet number giving the version number of the packet type.
	//    The currently defined value for packet version is 3.
	//  - An eight-octet number that gives the Key ID of the public key to
	//    which the session key is encrypted. If the session key is
	//    encrypted to a subkey, then the Key ID of this subkey is used
	//    here instead of the Key ID of the primary key.
	//  - A one-octet number giving the public-key algorithm used.
	//  - A string of octets that is the encrypted session key. This
	//    string takes up the remainder of the packet, and its contents are
	//    dependent on the public-key algorithm used.
	// [...]
	// Algorithm Specific Fields for Elgamal encryption:
	//  - MPI of Elgamal (Diffie-Hellman) value g**k mod p.
	//  - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
	// The value "m" in the above formulas is derived from the session key
	// as follows. First, the session key is prefixed with a one-octet
	// algorithm identifier that specifies the symmetric encryption
	// algorithm used to encrypt the following Symmetrically Encrypted Data
	// Packet. Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the algorithm
	// identifier, modulo 65536. This value is then encoded as described in
	// PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
	// form the "m" value used in the formulas above. See Section 13.1 of
	// this document for notes on OpenPGP’s use of PKCS#1.
	// Note that when an implementation forms several PKESKs with one
	// session key, forming a message that can be decrypted by several keys,
	// the implementation MUST make a new PKCS#1 encoding for each key.
	// An implementation MAY accept or use a Key ID of zero as a "wild card"
	// or "speculative" Key ID. In this case, the receiving implementation
	// would try all available private keys, checking for a valid decrypted
	// session key. This format helps reduce traffic analysis of messages.
	PacketTagEncode(1, out);
	PacketLengthEncode(1+keyid.size()+1+2+gklen+2+myklen, out);
	out.push_back(3); // V3 format
	out.insert(out.end(), keyid.begin(), keyid.end()); // Key ID
	out.push_back(TMCG_OPENPGP_PKALGO_ELGAMAL); // public-key algorithm
	PacketMPIEncode(gk, out); // MPI g**k mod p
	PacketMPIEncode(myk, out); // MPI m * y**k mod p
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode
	(const tmcg_openpgp_octets_t &keyid, const gcry_mpi_t me,
	 tmcg_openpgp_octets_t &out)
{
	size_t melen = (gcry_mpi_get_nbits(me) + 7) / 8;

	// A Public-Key Encrypted Session Key packet holds the session key used
	// to encrypt a message. Zero or more Public-Key Encrypted Session Key
	// packets and/or Symmetric-Key Encrypted Session Key packets may
	// precede a Symmetrically Encrypted Data Packet, which holds an
	// encrypted message. The message is encrypted with the session key,
	// and the session key is itself encrypted and stored in the Encrypted
	// Session Key packet(s). The Symmetrically Encrypted Data Packet is
	// preceded by one Public-Key Encrypted Session Key packet for each
	// OpenPGP key to which the message is encrypted. The recipient of the
	// message finds a session key that is encrypted to their public key,
	// decrypts the session key, and then uses the session key to decrypt
	// the message.
	// The body of this packet consists of:
	//  - A one-octet number giving the version number of the packet type.
	//    The currently defined value for packet version is 3.
	//  - An eight-octet number that gives the Key ID of the public key to
	//    which the session key is encrypted. If the session key is
	//    encrypted to a subkey, then the Key ID of this subkey is used
	//    here instead of the Key ID of the primary key.
	//  - A one-octet number giving the public-key algorithm used.
	//  - A string of octets that is the encrypted session key. This
	//    string takes up the remainder of the packet, and its contents are
	//    dependent on the public-key algorithm used.
	// Algorithm Specific Fields for RSA encryption
	//  - multiprecision integer (MPI) of RSA encrypted value m**e mod n.
	// [...]
	// The value "m" in the above formulas is derived from the session key
	// as follows. First, the session key is prefixed with a one-octet
	// algorithm identifier that specifies the symmetric encryption
	// algorithm used to encrypt the following Symmetrically Encrypted Data
	// Packet. Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the algorithm
	// identifier, modulo 65536. This value is then encoded as described in
	// PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
	// form the "m" value used in the formulas above. See Section 13.1 of
	// this document for notes on OpenPGP’s use of PKCS#1.
	// Note that when an implementation forms several PKESKs with one
	// session key, forming a message that can be decrypted by several keys,
	// the implementation MUST make a new PKCS#1 encoding for each key.
	// An implementation MAY accept or use a Key ID of zero as a "wild card"
	// or "speculative" Key ID. In this case, the receiving implementation
	// would try all available private keys, checking for a valid decrypted
	// session key. This format helps reduce traffic analysis of messages.
	PacketTagEncode(1, out);
	PacketLengthEncode(1+keyid.size()+1+2+melen, out);
	out.push_back(3); // V3 format
	out.insert(out.end(), keyid.begin(), keyid.end()); // Key ID
	out.push_back(TMCG_OPENPGP_PKALGO_RSA); // public-key algorithm
	PacketMPIEncode(me, out); // MPI m**e mod n
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode
	(const tmcg_openpgp_octets_t &keyid, const gcry_mpi_t ecepk,
	 const size_t rkwlen, const tmcg_openpgp_byte_t rkw[256],
	 tmcg_openpgp_octets_t &out)
{
	size_t ecepklen = (gcry_mpi_get_nbits(ecepk) + 7) / 8;
	
	// Message Encoding with Public Keys [RFC 6637]
	PacketTagEncode(1, out);
	PacketLengthEncode(1+keyid.size()+1+2+ecepklen+1+rkwlen, out);
	out.push_back(3); // V3 format
	out.insert(out.end(), keyid.begin(), keyid.end()); // Key ID
	out.push_back(TMCG_OPENPGP_PKALGO_ECDH); // public-key algorithm
	PacketMPIEncode(ecepk, out); // MPI of an EC point representing EPK
	out.push_back(rkwlen);
	for (size_t i = 0; i < rkwlen; i++)
		out.push_back(rkw[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode
	(const tmcg_openpgp_octets_t &hashing,
	 const tmcg_openpgp_octets_t &left,
	 const gcry_mpi_t r, const gcry_mpi_t s, tmcg_openpgp_octets_t &out)
{
	size_t rlen = (gcry_mpi_get_nbits(r) + 7) / 8;
	size_t slen = (gcry_mpi_get_nbits(s) + 7) / 8;

	// A Signature packet describes a binding between some public key and
	// some data. The most common signatures are a signature of a file or a
	// block of text, and a signature that is a certification of a User ID.
	// Two versions of Signature packets are defined. Version 3 provides
	// basic signature information, while version 4 provides an expandable
	// format with subpackets that can specify more information about the
	// signature.
	PacketTagEncode(2, out);
	PacketLengthEncode(hashing.size()+2+0+left.size()+2+rlen+2+slen, out);
	// hashed area including subpackets
	out.insert(out.end(), hashing.begin(), hashing.end());
	// unhashed subpacket area
	out.push_back((0 >> 8) & 0xFF); // length of unhashed subpacket data
	out.push_back(0 & 0xFF);
	// signature data
	out.insert(out.end(), left.begin(), left.end()); // 16 bits of hash
	PacketMPIEncode(r, out); // signature - MPI r
	PacketMPIEncode(s, out); // signature - MPI s
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode
	(const tmcg_openpgp_octets_t &hashing,
	 const tmcg_openpgp_octets_t &left,
	 const gcry_mpi_t s, tmcg_openpgp_octets_t &out)
{
	size_t slen = (gcry_mpi_get_nbits(s) + 7) / 8;

	// A Signature packet describes a binding between some public key and
	// some data. The most common signatures are a signature of a file or a
	// block of text, and a signature that is a certification of a User ID.
	// Two versions of Signature packets are defined. Version 3 provides
	// basic signature information, while version 4 provides an expandable
	// format with subpackets that can specify more information about the
	// signature.
	PacketTagEncode(2, out);
	PacketLengthEncode(hashing.size()+2+0+left.size()+2+slen, out);
	// hashed area including subpackets
	out.insert(out.end(), hashing.begin(), hashing.end());
	// unhashed subpacket area
	out.push_back((0 >> 8) & 0xFF); // length of unhashed subpacket data
	out.push_back(0 & 0xFF);
	// signature data
	out.insert(out.end(), left.begin(), left.end()); // 16 bits of hash
	PacketMPIEncode(s, out); // signature - MPI s
}

void CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketEncode
	(const tmcg_openpgp_byte_t type, const bool critical,
	 const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// A subpacket data set consists of zero or more Signature subpackets.
	// In Signature packets, the subpacket data set is preceded by a two-
	// octet scalar count of the length in octets of all the subpackets.
	// A pointer incremented by this number will skip over the subpacket
	// data set.
	// Each subpacket consists of a subpacket header and a body. The
	// header consists of:
	//  - the subpacket length (1, 2, or 5 octets),
	//  - the subpacket type (1 octet),
	// and is followed by the subpacket-specific data.
	// The length includes the type octet but not this length. Its format
	// is similar to the "new" format packet header lengths, but cannot
	// have Partial Body Lengths.
	FixedLengthEncode(in.size() + 1, out);
	if (critical)
		out.push_back(type | 0x80);
	else
		out.push_back(type);
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareSelfSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const time_t sigtime, const time_t keyexptime, 
	 const tmcg_openpgp_octets_t &flags,
	 const tmcg_openpgp_octets_t &issuer, tmcg_openpgp_octets_t &out)
{
	PacketSigPrepareSelfSignature(type, TMCG_OPENPGP_PKALGO_DSA, hashalgo,
		sigtime, keyexptime, flags, issuer, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareSelfSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const time_t sigtime, const time_t keyexptime, 
	 const tmcg_openpgp_octets_t &flags,
	 const tmcg_openpgp_octets_t &issuer, tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 8;
	size_t subpktlen = (subpkts * 6) + 4 + 2 + 3 + 1 + 1 + flags.size() + 1;
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (keyexptime != 0)
		subpktlen += (6 + 4);
#if GCRYPT_VERSION_NUMBER < 0x010700
	// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
	subpktlen += (6 + 1);
#if GCRYPT_VERSION_NUMBER < 0x010900
	// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
#else
	subpktlen += 1;
#endif
#endif
	out.push_back(4); // V4 format
	out.push_back(type); // type (e.g. 0x10-0x13 for UID certification)
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// [optional] key expiration time (length = 4)
		if (keyexptime != 0)
		{
			tmcg_openpgp_octets_t subpkt_keyexptime;
			PacketTimeEncode(keyexptime, subpkt_keyexptime);
			SubpacketEncode(9, false, subpkt_keyexptime, out);
		}
		// 2. preferred symmetric algorithms (length = 2)
		tmcg_openpgp_octets_t psa;
		psa.push_back(TMCG_OPENPGP_SKALGO_AES256);
		psa.push_back(TMCG_OPENPGP_SKALGO_TWOFISH);
		SubpacketEncode(11, false, psa, out);
		// 3. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, false, keyid, out);
		}
		else
			SubpacketEncode(16, false, issuer, out);
		// 4. preferred hash algorithms  (length = 3)
		tmcg_openpgp_octets_t pha;
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA512);
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA384);
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA256);
		SubpacketEncode(21, false, pha, out);
		// 5. preferred compression algorithms  (length = 1)
		tmcg_openpgp_octets_t pca;
		pca.push_back(0); // uncompressed
		SubpacketEncode(22, false, pca, out);
		// 6. key server preferences (length = 1)
		tmcg_openpgp_octets_t ksp;
		ksp.push_back(0x80); // no-modify
		SubpacketEncode(23, false, ksp, out);
		// 7. key flags (variable length)
		SubpacketEncode(27, false, flags, out);
		// 8. features (length = 1)
		tmcg_openpgp_octets_t features;
		features.push_back(0x01); // Modification Detection (tags 18, 19)
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		// AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key
		// Encrypted Session Key Packets (packet 3)
		features[0] |= 0x02;
#endif
		SubpacketEncode(30, false, features, out);
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		// [optional] preferred AEAD algorithms  (variable length)
		tmcg_openpgp_octets_t paa;
#if GCRYPT_VERSION_NUMBER < 0x010900
		// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
#else
		paa.push_back(TMCG_OPENPGP_AEADALGO_EAX);
#endif
		paa.push_back(TMCG_OPENPGP_AEADALGO_OCB);
		SubpacketEncode(34, false, paa, out);
#endif
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDesignatedRevoker
	(const tmcg_openpgp_hashalgo_t hashalgo, const time_t sigtime, 
	 const tmcg_openpgp_octets_t &flags, const tmcg_openpgp_octets_t &issuer,
	 const tmcg_openpgp_pkalgo_t pkalgo2, const tmcg_openpgp_octets_t &revoker,
	 tmcg_openpgp_octets_t &out)
{
	PacketSigPrepareDesignatedRevoker(TMCG_OPENPGP_PKALGO_DSA, hashalgo,
		sigtime, flags, issuer, pkalgo2, revoker, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDesignatedRevoker
	(const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo, const time_t sigtime,
	 const tmcg_openpgp_octets_t &flags, const tmcg_openpgp_octets_t &issuer,
	 const tmcg_openpgp_pkalgo_t pkalgo2, const tmcg_openpgp_octets_t &revoker,
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 8;
	size_t subpktlen = (subpkts * 6) + 4 + 2 + 3 + 1 + 1 + flags.size() + 1;
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (revoker.size())
		subpktlen += (6 + 22); // size of Revocation Key subpacket
#if GCRYPT_VERSION_NUMBER < 0x010700
	// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
	subpktlen += (6 + 1);
#if GCRYPT_VERSION_NUMBER < 0x010900
	// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
#else
	subpktlen += 1;
#endif
#endif
	out.push_back(4); // V4 format
	out.push_back(TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY); // type
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// 2. preferred symmetric algorithms (length = 2)
		tmcg_openpgp_octets_t psa;
		psa.push_back(TMCG_OPENPGP_SKALGO_AES256); // AES256
		psa.push_back(TMCG_OPENPGP_SKALGO_TWOFISH); // Twofish
		SubpacketEncode(11, false, psa, out);
		// [optional] revocation key (length = 22)
		if (revoker.size())
		{
			tmcg_openpgp_octets_t rk;
			rk.push_back(0x80); // class octet (non-sensitive relationship)
			rk.push_back(pkalgo2); // public-key algorithm
			assert((revoker.size() == 20));
			for (size_t i = 0; i < 20; i++)
				rk.push_back(revoker[i]); // SHA-1 fingerprint
			SubpacketEncode(12, true, rk, out); // critical bit set
		}
		// 3. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, false, keyid, out);
		}
		else
			SubpacketEncode(16, false, issuer, out);
		// 4. preferred hash algorithms  (length = 3)
		tmcg_openpgp_octets_t pha;
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA512); // SHA512
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA384); // SHA384
		pha.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // SHA256
		SubpacketEncode(21, false, pha, out);
		// 5. preferred compression algorithms  (length = 1)
		tmcg_openpgp_octets_t pca;
		pca.push_back(0); // uncompressed
		SubpacketEncode(22, false, pca, out);
		// 6. key server preferences (length = 1)
		tmcg_openpgp_octets_t ksp;
		ksp.push_back(0x80); // no-modify
		SubpacketEncode(23, false, ksp, out);
		// 7. key flags (variable length)
		SubpacketEncode(27, false, flags, out);
		// 8. features (length = 1)
		tmcg_openpgp_octets_t features;
		features.push_back(0x01); // Modification Detection (tags 18, 19)
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		// AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key
		// Encrypted Session Key Packets (packet 3)
		features[0] |= 0x02;
#endif
		SubpacketEncode(30, false, features, out);
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		// [optional] preferred AEAD algorithms  (variable length)
		tmcg_openpgp_octets_t paa;
#if GCRYPT_VERSION_NUMBER < 0x010900
		// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
#else
		paa.push_back(TMCG_OPENPGP_AEADALGO_EAX);
#endif
		paa.push_back(TMCG_OPENPGP_AEADALGO_OCB);
		SubpacketEncode(34, false, paa, out);
#endif
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDetachedSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const time_t sigtime, const time_t sigexptime,
	 const std::string &policy, const tmcg_openpgp_octets_t &issuer,
	 tmcg_openpgp_octets_t &out)
{
	PacketSigPrepareDetachedSignature(type, TMCG_OPENPGP_PKALGO_DSA, hashalgo,
		sigtime, sigexptime, policy, issuer, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDetachedSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const time_t sigtime, const time_t sigexptime,
	 const std::string &policy, const tmcg_openpgp_octets_t &issuer,
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 2;
	size_t subpktlen = (subpkts * 6) + 4;
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (sigexptime != 0)
		subpktlen += (6 + 4);
	if (policy.length())
		subpktlen += (6 + policy.length());
	out.push_back(4); // V4 format
	out.push_back(type); // type (e.g. 0x00 for signature on a binary document)
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// [optional] signature expiration time (length = 4)
		if (sigexptime != 0)
		{
			tmcg_openpgp_octets_t subpkt_sigexptime;
			PacketTimeEncode(sigexptime, subpkt_sigexptime);
			SubpacketEncode(3, false, subpkt_sigexptime, out);
		}
		// 2. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, false, keyid, out);
		}
		else
			SubpacketEncode(16, false, issuer, out);
		// [optional] policy URI (variable length)
		if (policy.length())
		{
			tmcg_openpgp_octets_t subpkt_policy;
			for (size_t i = 0; i < policy.length(); i++)
				subpkt_policy.push_back(policy[i]);
			SubpacketEncode(26, false, subpkt_policy, out);
		}
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareRevocationSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const time_t sigtime, const tmcg_openpgp_revcode_t revcode,
	 const std::string &reason, const tmcg_openpgp_octets_t &issuer, 
	 tmcg_openpgp_octets_t &out)
{
	PacketSigPrepareRevocationSignature(type, TMCG_OPENPGP_PKALGO_DSA, hashalgo,
		sigtime, revcode, reason, issuer, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareRevocationSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 const time_t sigtime, const tmcg_openpgp_revcode_t revcode,
	 const std::string &reason, const tmcg_openpgp_octets_t &issuer, 
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 3;
	size_t subpktlen = (subpkts * 6) + 4 + 1 + reason.length();
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	out.push_back(4); // V4 format
	out.push_back(type); // type (e.g. 0x20/0x28 for key/subkey revocation)
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// 2. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, false, keyid, out);
		}
		else
			SubpacketEncode(16, false, issuer, out);
		// 3. reason for revocation (length = 1 + variable length)
		tmcg_openpgp_octets_t subpkt_reason;
		subpkt_reason.push_back(revcode); // machine-readable code
		for (size_t i = 0; i < reason.length(); i++)
			subpkt_reason.push_back(reason[i]);
		SubpacketEncode(29, false, subpkt_reason, out);
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareCertificationSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 const time_t sigtime, const time_t sigexptime, 
	 const std::string &policy, const tmcg_openpgp_octets_t &issuer, 
	 tmcg_openpgp_octets_t &out)
{
	PacketSigPrepareCertificationSignature(type, TMCG_OPENPGP_PKALGO_DSA,
		hashalgo, sigtime, sigexptime, policy, issuer, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareCertificationSignature
	(const tmcg_openpgp_signature_t type,
	 const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 const time_t sigtime, const time_t sigexptime, 
	 const std::string &policy, const tmcg_openpgp_octets_t &issuer, 
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 2;
	size_t subpktlen = (subpkts * 6) + 4;
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (sigexptime != 0)
		subpktlen += (6 + 4);
	if (policy.length())
		subpktlen += (6 + policy.length());
	out.push_back(4); // V4 format
	out.push_back(type); // type (e.g. 0x10 for user ID certification)
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// [optional] signature expiration time (length = 4)
		if (sigexptime != 0)
		{
			tmcg_openpgp_octets_t subpkt_sigexptime;
			PacketTimeEncode(sigexptime, subpkt_sigexptime);
			SubpacketEncode(3, false, subpkt_sigexptime, out);
		}
		// 2. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, false, keyid, out);
		}
		else
			SubpacketEncode(16, false, issuer, out);
		// [optional] policy URI (variable length)
		if (policy.length())
		{
			tmcg_openpgp_octets_t subpkt_policy;
			for (size_t i = 0; i < policy.length(); i++)
				subpkt_policy.push_back(policy[i]);
			SubpacketEncode(26, false, subpkt_policy, out);
		}
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareTimestampSignature
	(const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo, const time_t sigtime,
	 const std::string &policy,
	 const tmcg_openpgp_octets_t &issuer,
	 const tmcg_openpgp_pkalgo_t target_pkalgo,
	 const tmcg_openpgp_hashalgo_t target_hashalgo,
	 const tmcg_openpgp_octets_t &target_hash,
	 const tmcg_openpgp_notations_t &notations,
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 4;
	size_t subpktlen = (subpkts * 6) + 4 + 1 + 2 + target_hash.size();
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (policy.length())
		subpktlen += (6 + policy.length());
	for (size_t i = 0; i < notations.size(); i++)
		subpktlen += (6 + 8 + notations[i].first.size() +
			notations[i].second.size());	
	out.push_back(4); // V4 format
	out.push_back(TMCG_OPENPGP_SIGNATURE_TIMESTAMP); // type
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, true, subpkt_sigtime, out);
		// 2. revocable (length = 1)
		tmcg_openpgp_octets_t revocable;
		revocable.push_back(0x00); // not revocable
		SubpacketEncode(7, true, revocable, out); 
		// 3. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, true, keyid, out);
		}
		else
			SubpacketEncode(16, true, issuer, out);
		// [optional] notation data (variable length)
		for (size_t i = 0; i < notations.size(); i++)
		{
			tmcg_openpgp_octets_t subpkt_notation;
			subpkt_notation.push_back(0x80); // human-readable
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back((notations[i].first.size() >> 8) & 0xFF);
			subpkt_notation.push_back(notations[i].first.size() & 0xFF);
			subpkt_notation.push_back((notations[i].second.size() >> 8) & 0xFF);
			subpkt_notation.push_back(notations[i].second.size() & 0xFF);
			for (size_t j = 0; j < notations[i].first.size(); j++)
				subpkt_notation.push_back(notations[i].first[j]);
			for (size_t j = 0; j < notations[i].second.size(); j++)
				subpkt_notation.push_back(notations[i].second[j]);
			SubpacketEncode(20, false, subpkt_notation, out);
		}
		// [optional] policy URI (variable length)
		if (policy.length())
		{
			tmcg_openpgp_octets_t subpkt_policy;
			for (size_t i = 0; i < policy.length(); i++)
				subpkt_policy.push_back(policy[i]);
			SubpacketEncode(26, false, subpkt_policy, out);
		}
		// 4. signature target (variable length)
		tmcg_openpgp_octets_t target;
		target.push_back(target_pkalgo); // public-key algorithm
		target.push_back(target_hashalgo); // hash algorithm
		target.insert(target.end(),
			target_hash.begin(), target_hash.end()); // hash
		SubpacketEncode(31, true, target, out);
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareTimestampSignature
	(const tmcg_openpgp_pkalgo_t pkalgo,
	 const tmcg_openpgp_hashalgo_t hashalgo, const time_t sigtime,
	 const std::string &policy,
	 const tmcg_openpgp_octets_t &issuer,
	 const tmcg_openpgp_octets_t &target_signature,
	 const tmcg_openpgp_notations_t &notations,
	 tmcg_openpgp_octets_t &out)
{
	size_t subpkts = 4;
	size_t subpktlen = (subpkts * 6) + 4 + 1 + target_signature.size();
	if (issuer.size() == 20)
	{
		subpktlen += (6 + 21); // size of Issuer Fingerprint subpacket
		subpktlen += 8; // size of Issuer subpacket
	}
	else
		subpktlen += issuer.size();
	if (policy.length())
		subpktlen += (6 + policy.length());
	for (size_t i = 0; i < notations.size(); i++)
		subpktlen += (6 + 8 + notations[i].first.size() +
			notations[i].second.size());	
	out.push_back(4); // V4 format
	out.push_back(TMCG_OPENPGP_SIGNATURE_TIMESTAMP); // type
	out.push_back(pkalgo); // public-key algorithm
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back((subpktlen >> 8) & 0xFF); // length hashed subpacket data
	out.push_back(subpktlen & 0xFF);
		// 1. signature creation time (length = 4)
		tmcg_openpgp_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, true, subpkt_sigtime, out);
		// 2. revocable (length = 1)
		tmcg_openpgp_octets_t revocable;
		revocable.push_back(0x00); // not revocable
		SubpacketEncode(7, true, revocable, out); 
		// 3. issuer (variable length)
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t keyid;
			// extract low-order 64 bits of the fingerprint
			for (size_t i = 12; i < 20; i++)
				keyid.push_back(issuer[i]);
			SubpacketEncode(16, true, keyid, out);
		}
		else
			SubpacketEncode(16, true, issuer, out);
		// [optional] notation data (variable length)
		for (size_t i = 0; i < notations.size(); i++)
		{
			tmcg_openpgp_octets_t subpkt_notation;
			subpkt_notation.push_back(0x80); // human-readable
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back(0x00);
			subpkt_notation.push_back((notations[i].first.size() >> 8) & 0xFF);
			subpkt_notation.push_back(notations[i].first.size() & 0xFF);
			subpkt_notation.push_back((notations[i].second.size() >> 8) & 0xFF);
			subpkt_notation.push_back(notations[i].second.size() & 0xFF);
			for (size_t j = 0; j < notations[i].first.size(); j++)
				subpkt_notation.push_back(notations[i].first[j]);
			for (size_t j = 0; j < notations[i].second.size(); j++)
				subpkt_notation.push_back(notations[i].second[j]);
			SubpacketEncode(20, false, subpkt_notation, out);
		}
		// [optional] policy URI (variable length)
		if (policy.length())
		{
			tmcg_openpgp_octets_t subpkt_policy;
			for (size_t i = 0; i < policy.length(); i++)
				subpkt_policy.push_back(policy[i]);
			SubpacketEncode(26, false, subpkt_policy, out);
		}
		// 4. embedded signature (variable length)
		SubpacketEncode(32, true, target_signature, out);
		// [optional] issuer fingerprint
		if (issuer.size() == 20)
		{
			tmcg_openpgp_octets_t issuerfpr;
			issuerfpr.push_back(4); // key version number (V4)
			issuerfpr.insert(issuerfpr.end(),
				issuer.begin(), issuer.end());			
			SubpacketEncode(33, false, issuerfpr, out);
		}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const gcry_mpi_t p, const gcry_mpi_t q, const gcry_mpi_t g,
	 const gcry_mpi_t y, tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			len += 2+plen+2+qlen;
			break;
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			len += 2+plen+2+glen+2+ylen;
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
		default:
			return;  // not supported
	}

	// A Public-Key packet starts a series of packets that forms an
	// OpenPGP key (sometimes called an OpenPGP certificate).
	// [...]
	// A version 4 packet contains:
	//  - A one-octet version number (4).
	//  - A four-octet number denoting the time that the key was created.
	//  - A one-octet number denoting the public-key algorithm of this key.
	//  - A series of multiprecision integers comprising the key material.
	//    This algorithm-specific portion is:
	//      Algorithm-Specific Fields for RSA public keys:
	//       - multiprecision integer (MPI) of RSA public modulus n;
	//       - MPI of RSA public encryption exponent e.
	//      Algorithm-Specific Fields for DSA public keys:
	//       - MPI of DSA prime p;
	//       - MPI of DSA group order q (q is a prime divisor of p-1);
	//       - MPI of DSA group generator g;
	//       - MPI of DSA public-key value y (= g**x mod p where x 
	//         is secret).
	//      Algorithm-Specific Fields for Elgamal public keys:
	//       - MPI of Elgamal prime p;
	//       - MPI of Elgamal group generator g;
	//       - MPI of Elgamal public key value y (= g**x mod p where x
	//         is secret).
	PacketTagEncode(6, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			PacketMPIEncode(p, out); // MPI n
			PacketMPIEncode(q, out); // MPI e
			break;
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		default:
			return; // not supported
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const size_t oidlen, const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk, const tmcg_openpgp_hashalgo_t kdf_hashalgo,
	 const tmcg_openpgp_skalgo_t kdf_skalgo, tmcg_openpgp_octets_t &out)
{
	size_t ecpklen = (gcry_mpi_get_nbits(ecpk) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
			len += 1+oidlen+2+ecpklen;
			break;
		case TMCG_OPENPGP_PKALGO_ECDH:
			len += 1+oidlen+2+ecpklen+4;
			break;
		default:
			return; // not supported
	}

	// The following algorithm-specific packets are added to Section 5.5.2
	// of [RFC4880], "Public-Key Packet Formats", to support ECDH and ECDSA.
	//
	// This algorithm-specific portion is:
	//
	// Algorithm-Specific Fields for ECDSA keys:
	//  o  a variable-length field containing a curve OID, formatted
	//     as follows:
	//      -  a one-octet size of the following field; values 0 and
	//         0xFF are reserved for future extensions
	//      -  octets representing a curve OID, defined in Section 11
	//  o  MPI of an EC point representing a public key
	//
	// Algorithm-Specific Fields for ECDH keys:
	//  o  a variable-length field containing a curve OID, formatted
	//     as follows:
	//      -  a one-octet size of the following field; values 0 and
	//         0xFF are reserved for future extensions
	//      -  the octets representing a curve OID, defined in Section 11
	//      -  MPI of an EC point representing a public key
	//  o  a variable-length field containing KDF parameters,
	//     formatted as follows:
	//      -  a one-octet size of the following fields; values 0 and
	//         0xff are reserved for future extensions
	//      -  a one-octet value 01, reserved for future extensions
	//      -  a one-octet hash function ID used with a KDF
	//      -  a one-octet algorithm ID for the symmetric algorithm
	//         used to wrap the symmetric key used for the message
	//         encryption; see Section 8 for details
	// Observe that an ECDH public key is composed of the same sequence of
	// fields that define an ECDSA key, plus the KDF parameters field.
	PacketTagEncode(6, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
			out.push_back(oidlen);
			for (size_t i = 0; i < oidlen; i++)
				out.push_back(oid[i]);
			PacketMPIEncode(ecpk, out);
			break;
		case TMCG_OPENPGP_PKALGO_ECDH:
			out.push_back(oidlen);
			for (size_t i = 0; i < oidlen; i++)
				out.push_back(oid[i]);
			PacketMPIEncode(ecpk, out);
			out.push_back(0x03);
			out.push_back(0x01);
			out.push_back(kdf_hashalgo);
			out.push_back(kdf_skalgo);
			break;
		default:
			return; // not supported
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const gcry_mpi_t p, const gcry_mpi_t q, const gcry_mpi_t g,
	 const gcry_mpi_t y, const gcry_mpi_t x,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			len += 2+plen+2+glen+2+ylen;
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
		default:
			return; // not supported
	}
	if (passphrase.length() == 0)
		len += 1+2+xlen+2; // S2K usage is zero
	else
		len += 29+2+xlen+20; // S2K usage is 254

	// The Secret-Key and Secret-Subkey packets contain all the data of the
	// Public-Key and Public-Subkey packets, with additional algorithm-
	// specific secret-key data appended, usually in encrypted form.
	// The packet contains:
	//  - A Public-Key or Public-Subkey packet, as described above.
	//  - One octet indicating string-to-key usage conventions. Zero
	//    indicates that the secret-key data is not encrypted. 255 or 254
	//    indicates that a string-to-key specifier is being given. Any
	//    other value is a symmetric-key encryption algorithm identifier.
	//  - [Optional] If string-to-key usage octet was 255 or 254, a one-
	//    octet symmetric encryption algorithm.
	//  - [Optional] If string-to-key usage octet was 255 or 254, a
	//    string-to-key specifier. The length of the string-to-key
	//    specifier is implied by its type, as described above.
	//  - [Optional] If secret data is encrypted (string-to-key usage octet
	//    not zero), an Initial Vector (IV) of the same length as the
	//    cipher’s block size.
	//  - Plain or encrypted multiprecision integers comprising the secret
	//    key data. These algorithm-specific fields are as described
	//    below.
	//  - If the string-to-key usage octet is zero or 255, then a two-octet
	//    checksum of the plaintext of the algorithm-specific portion (sum
	//    of all octets, mod 65536). If the string-to-key usage octet was
	//    254, then a 20-octet SHA-1 hash of the plaintext of the
	//    algorithm-specific portion. This checksum or hash is encrypted
	//    together with the algorithm-specific fields (if string-to-key
	//    usage octet is not zero). Note that for all other values, a
	//    two-octet checksum is required.
	PacketTagEncode(5, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		default:
			return; // not supported
	}

	// Secret MPI values can be encrypted using a passphrase. If a string-
	// to-key specifier is given, that describes the algorithm for
	// converting the passphrase to a key, else a simple MD5 hash of the
	// passphrase is used. Implementations MUST use a string-to-key
	// specifier; the simple hash is for backward compatibility and is
	// deprecated, though implementations MAY continue to use existing
	// private keys in the old format. The cipher for encrypting the MPIs
	// is specified in the Secret-Key packet.
	// Encryption/decryption of the secret data is done in CFB mode using
	// the key created from the passphrase and the Initial Vector from the
	// packet.
	// [...]
	// With V4 keys, a simpler method is used. All secret MPI values are
	// encrypted in CFB mode, including the MPI bitcount prefix.
	// The two-octet checksum that follows the algorithm-specific portion
	// is the algebraic sum, mod 65536, of the plaintext of all the
	// algorithm-specific octets (including MPI prefix and data). With V3
	// keys, the checksum is stored in the clear. With V4 keys, the
	// checksum is encrypted like the algorithm-specific data. This value
	// is used to check that the passphrase was correct. However, this
	// checksum is deprecated; an implementation SHOULD NOT use it, but
	// should rather use the SHA-1 hash denoted with a usage octet of 254.
	// The reason for this is that there are some attacks that involve
	// undetectably modifying the secret key.
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x, out, chksum); // MPI x
		out.push_back((chksum >> 8) & 0xFF); // two-octet checksum
		out.push_back(chksum & 0xFF);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier and SHA-1 hash
		out.push_back(TMCG_OPENPGP_SKALGO_AES256); // encryption algo
		out.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated + Salted
		out.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // hash algo
		tmcg_openpgp_byte_t rand[8], iv[16], count;
		tmcg_openpgp_octets_t salt;
		tmcg_openpgp_secure_octets_t plain, seskey, hash;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
		count = 0xAC; // set resonable S2K count: 0xAB
		for (size_t i = 0; i < sizeof(rand); i++)
		{
			salt.push_back(rand[i]);
			out.push_back(rand[i]); // salt
		}
		out.push_back(count); // count, a one-octet, coded value
		for (size_t i = 0; i < sizeof(iv); i++)
			out.push_back(iv[i]); // IV
		PacketMPIEncode(x, plain); // MPI x
		gcry_error_t ret;
		ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, plain, hash);
		if (ret)
			return;
		plain.insert(plain.end(), hash.begin(), hash.end()); // hash
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(plain.size());
		if (buf == NULL)
			return; // cannot allocate secure memory
		gcry_cipher_hd_t hd;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, 32,
			passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < 32; i++)
			buf[i] = seskey[i];
		ret = gcry_cipher_setkey(hd, buf, 32);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			buf[i] = plain[i];
		ret = gcry_cipher_encrypt(hd, buf, plain.size(), NULL, 0);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buf[i]);
		gcry_free(buf);
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental108
	(const time_t keytime, const gcry_mpi_t p, const gcry_mpi_t q,
	 const gcry_mpi_t g, const gcry_mpi_t h, const gcry_mpi_t y,
	 const gcry_mpi_t n, const gcry_mpi_t t, const gcry_mpi_t i,
	 const gcry_mpi_t qualsize, const std::vector<gcry_mpi_t> &qual,
	 const std::vector<std::string> &capl,
	 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 const gcry_mpi_t x_i, const gcry_mpi_t xprime_i,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t hlen = (gcry_mpi_get_nbits(h) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t nlen = (gcry_mpi_get_nbits(n) + 7) / 8;
	size_t tlen = (gcry_mpi_get_nbits(t) + 7) / 8;
	size_t ilen = (gcry_mpi_get_nbits(i) + 7) / 8;
	size_t qualsizelen = (gcry_mpi_get_nbits(qualsize) + 7) / 8;
	size_t x_ilen = (gcry_mpi_get_nbits(x_i) + 7) / 8;
	size_t xprime_ilen = (gcry_mpi_get_nbits(xprime_i) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	assert((qual.size() == tmcg_get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((qual.size() == capl.size()));
	for (size_t j = 0; j < capl.size(); j++)
		len += 5+capl[j].length();
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+
	       2+qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(5, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(TMCG_OPENPGP_PKALGO_EXPERIMENTAL8); // public-key algo 
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(q, out); // MPI q
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(h, out); // MPI h
	PacketMPIEncode(y, out); // MPI y
	PacketMPIEncode(n, out); // MPI n
	PacketMPIEncode(t, out); // MPI t
	PacketMPIEncode(i, out); // MPI i
	PacketMPIEncode(qualsize, out); // MPI qualsize
	for (size_t j = 0; j < qual.size(); j++)
		PacketMPIEncode(qual[j], out); // MPI qual[j]
	for (size_t j = 0; j < qual.size(); j++)
		PacketStringEncode(capl[j], out); // STRING capl[j]
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back((chksum >> 8) & 0xFF); // two-octet checksum
		out.push_back(chksum & 0xFF);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier and SHA-1 hash
		out.push_back(TMCG_OPENPGP_SKALGO_AES256); // encryption algo
		out.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated + Salted
		out.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // hash algo
		tmcg_openpgp_byte_t rand[8], iv[16], count;
		tmcg_openpgp_octets_t salt;
		tmcg_openpgp_secure_octets_t plain, seskey, hash;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
		count = 0xAC; // set resonable S2K count: 0xAB
		for (size_t i = 0; i < sizeof(rand); i++)
		{
			salt.push_back(rand[i]);
			out.push_back(rand[i]); // salt
		}
		out.push_back(count); // count, a one-octet, coded value
		for (size_t i = 0; i < sizeof(iv); i++)
			out.push_back(iv[i]); // IV
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		gcry_error_t ret;
		ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, plain, hash);
		if (ret)
			return;
		plain.insert(plain.end(), hash.begin(), hash.end()); // hash
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(plain.size());
		if (buf == NULL)
			return; // cannot allocate secure memory
		gcry_cipher_hd_t hd;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, 32,
			passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < 32; i++)
			buf[i] = seskey[i];
		ret = gcry_cipher_setkey(hd, buf, 32);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			buf[i] = plain[i];
		ret = gcry_cipher_encrypt(hd, buf, plain.size(), NULL, 0);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buf[i]);
		gcry_free(buf);
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental107
	(const time_t keytime, const gcry_mpi_t p,
	 const gcry_mpi_t q, const gcry_mpi_t g,
	 const gcry_mpi_t h, const gcry_mpi_t y,
	 const gcry_mpi_t n, const gcry_mpi_t t,
	 const gcry_mpi_t i, const gcry_mpi_t qualsize,
	 const std::vector<gcry_mpi_t> &qual,
	 const gcry_mpi_t x_rvss_qualsize,
	 const std::vector<gcry_mpi_t> &x_rvss_qual,
	 const std::vector<std::string> &capl,
	 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 const gcry_mpi_t x_i, const gcry_mpi_t xprime_i,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t hlen = (gcry_mpi_get_nbits(h) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t nlen = (gcry_mpi_get_nbits(n) + 7) / 8;
	size_t tlen = (gcry_mpi_get_nbits(t) + 7) / 8;
	size_t ilen = (gcry_mpi_get_nbits(i) + 7) / 8;
	size_t qualsizelen = (gcry_mpi_get_nbits(qualsize) + 7) / 8;
	size_t x_rvss_qualsizelen = 
		(gcry_mpi_get_nbits(x_rvss_qualsize) + 7) / 8;
	size_t x_ilen = (gcry_mpi_get_nbits(x_i) + 7) / 8;
	size_t xprime_ilen = (gcry_mpi_get_nbits(xprime_i) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	assert((qual.size() == tmcg_get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((x_rvss_qual.size() == tmcg_get_gcry_mpi_ui(x_rvss_qualsize)));
	for (size_t j = 0; j < x_rvss_qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(x_rvss_qual[j]) + 7) / 8);
	assert((capl.size() == tmcg_get_gcry_mpi_ui(n)));
	assert((qual.size() <= capl.size()));
	assert((x_rvss_qual.size() <= capl.size()));
	for (size_t j = 0; j < capl.size(); j++)
		len += 5+capl[j].length();
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+
	       2+qualsizelen+2+x_rvss_qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(5, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(TMCG_OPENPGP_PKALGO_EXPERIMENTAL7); // public-key algo
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(q, out); // MPI q
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(h, out); // MPI h
	PacketMPIEncode(y, out); // MPI y
	PacketMPIEncode(n, out); // MPI n
	PacketMPIEncode(t, out); // MPI t
	PacketMPIEncode(i, out); // MPI i
	PacketMPIEncode(qualsize, out); // MPI qualsize
	for (size_t j = 0; j < qual.size(); j++)
		PacketMPIEncode(qual[j], out); // MPI qual[j]
	PacketMPIEncode(x_rvss_qualsize, out); // MPI x_rvss_qualsize
	for (size_t j = 0; j < x_rvss_qual.size(); j++)
		PacketMPIEncode(x_rvss_qual[j], out); // MPI x_rvss_qual[j]
	for (size_t j = 0; j < capl.size(); j++)
		PacketStringEncode(capl[j], out); // STRING capl[j]
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back((chksum >> 8) & 0xFF); // two-octet checksum
		out.push_back(chksum & 0xFF);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier and SHA-1 hash
		out.push_back(TMCG_OPENPGP_SKALGO_AES256); // encryption algo
		out.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated + Salted
		out.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // hash algo
		tmcg_openpgp_byte_t rand[8], iv[16], count;
		tmcg_openpgp_octets_t salt;
		tmcg_openpgp_secure_octets_t plain, seskey, hash;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
		count = 0xAC; // set resonable S2K count: 0xAB
		for (size_t i = 0; i < sizeof(rand); i++)
		{
			salt.push_back(rand[i]);
			out.push_back(rand[i]); // salt
		}
		out.push_back(count); // count, a one-octet, coded value
		for (size_t i = 0; i < sizeof(iv); i++)
			out.push_back(iv[i]); // IV
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		gcry_error_t ret;
		ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, plain, hash);
		if (ret)
			return;
		plain.insert(plain.end(), hash.begin(), hash.end()); // hash
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(plain.size());
		if (buf == NULL)
			return; // cannot allocate secure memory
		gcry_cipher_hd_t hd;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, 32,
			passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < 32; i++)
			buf[i] = seskey[i];
		ret = gcry_cipher_setkey(hd, buf, 32);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			buf[i] = plain[i];
		ret = gcry_cipher_encrypt(hd, buf, plain.size(), NULL, 0);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buf[i]);
		gcry_free(buf);
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const gcry_mpi_t p, const gcry_mpi_t q, const gcry_mpi_t g,
	 const gcry_mpi_t y, tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			len += 2+plen+2+qlen;
			break;
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			len += 2+plen+2+glen+2+ylen;
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
		default:
			return; // not supported
	}

	// A Public-Subkey packet (tag 14) has exactly the same format as a
	// Public-Key packet, but denotes a subkey. One or more subkeys may be
	// associated with a top-level key. By convention, the top-level key
	// provides signature services, and the subkeys provide encryption
	// services.
	// [...]
	//
	PacketTagEncode(14, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			PacketMPIEncode(p, out); // MPI n
			PacketMPIEncode(q, out); // MPI e
			break;
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		default:
			return; // not supported
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const size_t oidlen, const tmcg_openpgp_byte_t* oid,
	 const gcry_mpi_t ecpk, const tmcg_openpgp_hashalgo_t kdf_hashalgo,
	 const tmcg_openpgp_skalgo_t kdf_skalgo, tmcg_openpgp_octets_t &out)
{
	size_t ecpklen = (gcry_mpi_get_nbits(ecpk) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
			len += 1+oidlen+2+ecpklen;
			break;
		case TMCG_OPENPGP_PKALGO_ECDH:
			len += 1+oidlen+2+ecpklen+4;
			break;
		default:
			return; // not supported
	}

	// The following algorithm-specific packets are added to Section 5.5.2
	// of [RFC4880], "Public-Key Packet Formats", to support ECDH and ECDSA.
	//
	// This algorithm-specific portion is:
	//
	// Algorithm-Specific Fields for ECDSA keys:
	//  o  a variable-length field containing a curve OID, formatted
	//     as follows:
	//      -  a one-octet size of the following field; values 0 and
	//         0xFF are reserved for future extensions
	//      -  octets representing a curve OID, defined in Section 11
	//  o  MPI of an EC point representing a public key
	//
	// Algorithm-Specific Fields for ECDH keys:
	//  o  a variable-length field containing a curve OID, formatted
	//     as follows:
	//      -  a one-octet size of the following field; values 0 and
	//         0xFF are reserved for future extensions
	//      -  the octets representing a curve OID, defined in Section 11
	//      -  MPI of an EC point representing a public key
	//  o  a variable-length field containing KDF parameters,
	//     formatted as follows:
	//      -  a one-octet size of the following fields; values 0 and
	//         0xff are reserved for future extensions
	//      -  a one-octet value 01, reserved for future extensions
	//      -  a one-octet hash function ID used with a KDF
	//      -  a one-octet algorithm ID for the symmetric algorithm
	//         used to wrap the symmetric key used for the message
	//         encryption; see Section 8 for details
	// Observe that an ECDH public key is composed of the same sequence of
	// fields that define an ECDSA key, plus the KDF parameters field.
	PacketTagEncode(14, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
			out.push_back(oidlen);
			for (size_t i = 0; i < oidlen; i++)
				out.push_back(oid[i]);
			PacketMPIEncode(ecpk, out);
			break;
		case TMCG_OPENPGP_PKALGO_ECDH:
			out.push_back(oidlen);
			for (size_t i = 0; i < oidlen; i++)
				out.push_back(oid[i]);
			PacketMPIEncode(ecpk, out);
			out.push_back(0x03);
			out.push_back(0x01);
			out.push_back(kdf_hashalgo);
			out.push_back(kdf_skalgo);
			break;
		default:
			return; // not supported
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode
	(const time_t keytime, const tmcg_openpgp_pkalgo_t algo,
	 const gcry_mpi_t p, const gcry_mpi_t q, const gcry_mpi_t g,
	 const gcry_mpi_t y, const gcry_mpi_t x,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			len += 2+plen+2+glen+2+ylen;
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
		default:
			return; // not supported
	}
	if (passphrase.length() == 0)
		len += 1+2+xlen+2; // S2K usage is zero
	else
		len += 29+2+xlen+20; // S2K usage is 254

	// A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
	// Key packet and has exactly the same format.
	PacketTagEncode(7, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(algo);
	switch (algo)
	{
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		default:
			return; // not supported
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x, out, chksum); // MPI x
		out.push_back((chksum >> 8) & 0xFF); // two-octet checksum
		out.push_back(chksum & 0xFF);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier and SHA-1 hash
		out.push_back(TMCG_OPENPGP_SKALGO_AES256); // encryption algo
		out.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated + Salted
		out.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // hash algo
		tmcg_openpgp_byte_t rand[8], iv[16], count;
		tmcg_openpgp_octets_t salt;
		tmcg_openpgp_secure_octets_t plain, seskey, hash;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
		count = 0xAC; // set resonable S2K count: 0xAB
		for (size_t i = 0; i < sizeof(rand); i++)
		{
			salt.push_back(rand[i]);
			out.push_back(rand[i]); // salt
		}
		out.push_back(count); // count, a one-octet, coded value
		for (size_t i = 0; i < sizeof(iv); i++)
			out.push_back(iv[i]); // IV
		PacketMPIEncode(x, plain); // MPI x
		gcry_error_t ret;
		ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, plain, hash);
		if (ret)
			return;
		plain.insert(plain.end(), hash.begin(), hash.end()); // hash
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(plain.size());
		if (buf == NULL)
			return; // cannot allocate secure memory
		gcry_cipher_hd_t hd;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, 32,
			passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < 32; i++)
			buf[i] = seskey[i];
		ret = gcry_cipher_setkey(hd, buf, 32);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			buf[i] = plain[i];
		ret = gcry_cipher_encrypt(hd, buf, plain.size(), NULL, 0);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buf[i]);
		gcry_free(buf);
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncodeExperimental109
	(const time_t keytime, const gcry_mpi_t p, const gcry_mpi_t q,
	 const gcry_mpi_t g, const gcry_mpi_t h, const gcry_mpi_t y,
	 const gcry_mpi_t n, const gcry_mpi_t t, const gcry_mpi_t i,
	 const gcry_mpi_t qualsize, const std::vector<gcry_mpi_t> &qual,
	 const std::vector<gcry_mpi_t> &v_i,
	 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 const gcry_mpi_t x_i, const gcry_mpi_t xprime_i,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 tmcg_openpgp_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t hlen = (gcry_mpi_get_nbits(h) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t nlen = (gcry_mpi_get_nbits(n) + 7) / 8;
	size_t tlen = (gcry_mpi_get_nbits(t) + 7) / 8;
	size_t ilen = (gcry_mpi_get_nbits(i) + 7) / 8;
	size_t qualsizelen = (gcry_mpi_get_nbits(qualsize) + 7) / 8;
	size_t x_ilen = (gcry_mpi_get_nbits(x_i) + 7) / 8;
	size_t xprime_ilen = (gcry_mpi_get_nbits(xprime_i) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	assert((qual.size() == tmcg_get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((v_i.size() == tmcg_get_gcry_mpi_ui(n)));
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
		len += 2+((gcry_mpi_get_nbits(v_i[j]) + 7) / 8);
	assert((c_ik.size() == tmcg_get_gcry_mpi_ui(n)));
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+
	       2+qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(7, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(TMCG_OPENPGP_PKALGO_EXPERIMENTAL9); // public-key algo
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(q, out); // MPI q
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(h, out); // MPI h
	PacketMPIEncode(y, out); // MPI y
	PacketMPIEncode(n, out); // MPI n
	PacketMPIEncode(t, out); // MPI t
	PacketMPIEncode(i, out); // MPI i
	PacketMPIEncode(qualsize, out); // MPI qualsize
	for (size_t j = 0; j < qual.size(); j++)
		PacketMPIEncode(qual[j], out); // MPI qual[j]
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
		PacketMPIEncode(v_i[j], out); // MPI v_i[j]
	for (size_t j = 0; j < tmcg_get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= tmcg_get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back((chksum >> 8) & 0xFF); // two-octet checksum
		out.push_back(chksum & 0xFF);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier and SHA-1 hash
		out.push_back(TMCG_OPENPGP_SKALGO_AES256); // encryption algo
		out.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated + Salted
		out.push_back(TMCG_OPENPGP_HASHALGO_SHA256); // hash algo
		tmcg_openpgp_byte_t rand[8], iv[16], count;
		tmcg_openpgp_octets_t salt;
		tmcg_openpgp_secure_octets_t plain, seskey, hash;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
		count = 0xAC; // set resonable S2K count: 0xAB
		for (size_t i = 0; i < sizeof(rand); i++)
		{
			salt.push_back(rand[i]);
			out.push_back(rand[i]); // salt
		}
		out.push_back(count); // count, a one-octet, coded value
		for (size_t i = 0; i < sizeof(iv); i++)
			out.push_back(iv[i]); // IV
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		gcry_error_t ret;
		ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, plain, hash);
		if (ret)
			return;
		plain.insert(plain.end(), hash.begin(), hash.end()); // hash
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(plain.size());
		if (buf == NULL)
			return; // cannot allocate secure memory
		gcry_cipher_hd_t hd;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		S2KCompute(TMCG_OPENPGP_HASHALGO_SHA256, 32,
			passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < 32; i++)
			buf[i] = seskey[i];
		ret = gcry_cipher_setkey(hd, buf, 32);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			buf[i] = plain[i];
		ret = gcry_cipher_encrypt(hd, buf, plain.size(), NULL, 0);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buf[i]);
		gcry_free(buf);
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// The Symmetrically Encrypted Data packet contains data encrypted with
	// a symmetric-key algorithm. When it has been decrypted, it contains
	// other packets (usually a literal data packet or compressed data
	// packet, but in theory other Symmetrically Encrypted Data packets or
	// sequences of packets that form whole OpenPGP messages).
	// The body of this packet consists of:
	//  - Encrypted data, the output of the selected symmetric-key cipher
	//    operating in OpenPGP’s variant of Cipher Feedback (CFB) mode.
	PacketTagEncode(9, out);
	PacketLengthEncode(in.size(), out);
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// A Literal Data packet contains the body of a message; data that is
	// not to be further interpreted.
	// The body of this packet consists of:
	//  - A one-octet field that describes how the data is formatted.
	// If it is a ’b’ (0x62), then the Literal packet contains binary data.
	// If it is a ’t’ (0x74), then it contains text data, and thus may need
	// line ends converted to local form, or other text-mode changes. The
	// tag ’u’ (0x75) means the same as ’t’, but also indicates that
	// implementation believes that the literal data contains UTF-8 text.
	// [...]
	//  - File name as a string (one-octet length, followed by a file
	//    name). This may be a zero-length string. Commonly, if the
	//    source of the encrypted data is a file, this will be the name of
	//    the encrypted file. An implementation MAY consider the file name
	//    in the Literal packet to be a more authoritative name than the
	//    actual file name.
	// If the special name "_CONSOLE" is used, the message is considered to
	// be "for your eyes only". This advises that the message data is
	// unusually sensitive, and the receiving program should process it more
	// carefully, perhaps avoiding storing the received data to disk, for
	// example.
	// - A four-octet number that indicates a date associated with the
	//   literal data. Commonly, the date might be the modification date
	//   of a file, or the time the packet was created, or a zero that
	//   indicates no specific time.
	// - The remainder of the packet is literal data.
	//   Text data is stored with <CR><LF> text endings (i.e., network-
	//   normal line endings). These should be converted to native line
	//   endings by the receiving software.
	PacketTagEncode(11, out);
	PacketLengthEncode(1+1+4+in.size(), out);
	out.push_back(0x62); // format: binary data
	out.push_back(0); // no file name
	PacketTimeEncode(out); // current time
	out.insert(out.end(), in.begin(), in.end()); // data
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode
	(const std::string &uid, tmcg_openpgp_octets_t &out)
{
	// A User ID packet consists of UTF-8 text that is intended to 
	// represent the name and email address of the key holder. By
	// convention, it includes an RFC 2822 [RFC2822] mail name-addr,
	// but there are no restrictions on its content. The packet length
	// in the header specifies the length of the User ID.
	PacketTagEncode(13, out);
	PacketLengthEncode(uid.length(), out);
	for (size_t i = 0; i < uid.length(); i++)
		out.push_back(uid[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// The Symmetrically Encrypted Integrity Protected Data packet is a
	// variant of the Symmetrically Encrypted Data packet. It is a new
	// feature created for OpenPGP that addresses the problem of detecting
	// a modification to encrypted data. It is used in combination with a
	// Modification Detection Code packet.
	// There is a corresponding feature in the features Signature subpacket
	// that denotes that an implementation can properly use this packet
	// type. An implementation MUST support decrypting these packets and
	// SHOULD prefer generating them to the older Symmetrically Encrypted
	// Data packet when possible. Since this data packet protects against
	// modification attacks, this standard encourages its proliferation.
	// While blanket adoption of this data packet would create
	// interoperability problems, rapid adoption is nevertheless important.
	// An implementation SHOULD specifically denote support for this packet,
	// but it MAY infer it from other mechanisms.
	// [...]
	// This packet contains data encrypted with a symmetric-key algorithm
	// and protected against modification by the SHA-1 hash algorithm. When
	// it has been decrypted, it will typically contain other packets
	// (often a Literal Data packet or Compressed Data packet). The last
	// decrypted packet in this packet’s payload MUST be a Modification
	// Detection Code packet.
	// The body of this packet consists of:
	//  - A one-octet version number. The only currently defined value
	//    is 1.
	//  - Encrypted data, the output of the selected symmetric-key cipher
	//    operating in Cipher Feedback mode with shift amount equal to the
	//    block size of the cipher (CFB-n where n is the block size).
	// The symmetric cipher used MUST be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In either case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// The data is encrypted in CFB mode, with a CFB shift size equal to
	// the cipher's block size. The Initial Vector (IV) is specified as all
	// zeros. Instead of using an IV, OpenPGP prefixes an octet string to
	// the data before it is encrypted. The length of the octet string
	// equals the block size of the cipher in octets, plus two. The first
	// octets in the group, of length equal to the block size of the cipher,
	// are random; the last two octets are each copies of their 2nd
	// preceding octet. For example, with a cipher whose block size is 128
	// bits or 16 octets, the prefix data will contain 16 random octets,
	// then two more octets, which are copies of the 15th and 16th octets,
	// respectively. Unlike the Symmetrically Encrypted Data Packet, no
	// special CFB resynchronization is done after encrypting this prefix
	// data. See "OpenPGP CFB Mode" below for more details.
	// [...]
	// The plaintext of the data to be encrypted is passed through the
	// SHA-1 hash function, and the result of the hash is appended to the
	// plaintext in a Modification Detection Code packet. The input to the
	// hash function includes the prefix data described above; it includes
	// all of the plaintext, and then also includes two octets of values
	// 0xD3, 0x14. These represent the encoding of a Modification Detection
	// Code packet tag and length field of 20 octets.
	// The resulting hash value is stored in a Modification Detection Code
	// (MDC) packet, which MUST use the two octet encoding just given to
	// represent its tag and length field. The body of the MDC packet is
	// the 20-octet output of the SHA-1 hash.
	// The Modification Detection Code packet is appended to the plaintext
	// and encrypted along with the plaintext using the same CFB context.
	// During decryption, the plaintext data should be hashed with SHA-1,
	// including the prefix data as well as the packet tag and length field
	// of the Modification Detection Code packet. The body of the MDC
	// packet, upon decryption, is compared with the result of the SHA-1
	// hash.
	PacketTagEncode(18, out);
	PacketLengthEncode(1+in.size(), out);
	out.push_back(1); // version
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_octets_t &out)
{
	// The Modification Detection Code packet contains a SHA-1 hash of
	// plaintext data, which is used to detect message modification. It is
	// only used with a Symmetrically Encrypted Integrity Protected Data
	// packet. The Modification Detection Code packet MUST be the last
	// packet in the plaintext data that is encrypted in the Symmetrically
	// Encrypted Integrity Protected Data packet, and MUST appear in no
	// other place.
	// A Modification Detection Code packet MUST have a length of 20
	// octets.
	// The body of this packet consists of:
	//  - A 20-octet SHA-1 hash of the preceding plaintext data of the
	//    Symmetrically Encrypted Integrity Protected Data packet,
	//    including prefix data, the tag octet, and length octet of the
	//    Modification Detection Code packet.
	// Note that the Modification Detection Code packet MUST always use a
	// new format encoding of the packet tag, and a one-octet encoding of
	// the packet length. The reason for this is that the hashing rules for
	// modification detection include a one-octet tag and one-octet length
	// in the data hash. While this is a bit restrictive, it reduces
	// complexity.
	PacketTagEncode(19, out);
	out.push_back(20); // one-octet length of SHA-1 hash value
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketAeadEncode
	(const tmcg_openpgp_skalgo_t skalgo,
	 const tmcg_openpgp_aeadalgo_t aeadalgo,
	 const tmcg_openpgp_byte_t chunksize,
	 const tmcg_openpgp_octets_t &iv,
	 const tmcg_openpgp_octets_t &in,
	 tmcg_openpgp_octets_t &out)
{
	// This packet contains data encrypted with an authenticated encryption
	// and additional data (AEAD) construction.  When it has been decrypted,
	// it will typically contain other packets (often a Literal Data packet
	// or Compressed Data packet).
	//
	// The body of this packet consists of:
	//
	//  o  A one-octet version number.  The only currently defined value is 1.
	//
	//  o  A one-octet cipher algorithm.
	//
	//  o  A one-octet AEAD algorithm.
	//
	//  o  A one-octet chunk size.
	//
	//  o  A starting initialization vector of size specified by the AEAD
	//     algorithm.
	//
	//  o  Encrypted data, the output of the selected symmetric-key cipher
	//     operating in the given AEAD mode.
	//
	//  o  A final, summary authentication tag for the AEAD mode.
	PacketTagEncode(20, out);
	PacketLengthEncode(4+iv.size()+in.size(), out);
	out.push_back(1); // one-octet version number
	out.push_back(skalgo); // one-octet cipher algorithm
	out.push_back(aeadalgo); // one-octet AEAD algorithm
	out.push_back(chunksize); // one-octet chunk size
	out.insert(out.end(), iv.begin(), iv.end()); // starting IV
	out.insert(out.end(), in.begin(), in.end());
}

// ===========================================================================

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketDecode
	(tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_packet_ctx_t &out)
{
	if (in.size() < 2)
		return 0; // error: incorrect subpacket header
	// Each subpacket consists of a subpacket header and a body.
	// The header consists of:
	//  - the subpacket length (1, 2, or 5 octets),
	//  - the subpacket type (1 octet),
	// and is followed by the subpacket-specific data.
	// The length includes the type octet but not this length. Its format
	// is similar to the "new" format packet header lengths, but cannot
	// have Partial Body Lengths.
	uint32_t len = 0, headlen = 1;
	if (in[0] < 192)
	{
		// if the 1st octet <  192, then
		// lengthOfLength = 1
		// subpacketLen = 1st_octet
		headlen += 1;
		len = in[0];
	}
	else if (in[0] < 255)
	{
		if (in.size() < 3)
			return 0; // error: too few octets of length encoding
		// if the 1st octet >= 192 and < 255, then
		// lengthOfLength = 2
		// subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
		headlen += 2;
		len = ((in[0] - 192) << 8) + in[1] + 192;
	}
	else if (in[0] == 255)
	{
		if (in.size() < 6)
			return 0; // error: too few octets of length encoding
		// if the 1st octet = 255, then
		// lengthOfLength = 5
		// subpacket length = [four-octet scalar starting at 2nd_octet]
		headlen += 5;
		len = (in[1] << 24) + (in[2] << 16) + (in[3] << 8) + in[4];
	}
	else
		return 0; // error: Partial Body Lengths are not allowed
	// Bit 7 of the subpacket type is the "critical" bit. If set, it
	// denotes that the subpacket is one that is critical for the evaluator
	// of the signature to recognize. If a subpacket is encountered that is
	// marked critical but is unknown to the evaluating software, the
	// evaluator SHOULD consider the signature to be in error.
	// An evaluator may "recognize" a subpacket, but not implement it. The
	// purpose of the critical bit is to allow the signer to tell an
	// evaluator that it would prefer a new, unknown feature to generate an
	// error than be ignored.
	out.critical = false;
	tmcg_openpgp_byte_t type = in[headlen-1];
	if ((type & 0x80) == 0x80)
	{
		out.critical = true;
		type -= 0x80;
	}
	if (len > 0)
		len -= 1; // first octet (subpacket type) is already processed
	else
		return 0; // error: subpacket without type octet
	if (in.size() < (headlen + len))
		return 0; // error: subpacket too short
	tmcg_openpgp_octets_t pkt;
	pkt.insert(pkt.end(), in.begin()+headlen, in.begin()+headlen+len);
	switch (type)
	{
		case 2: // Signature Creation Time 
			if (pkt.size() != 4)
				return 0; // error: incorrect subpacket body 
			out.sigcreationtime = (pkt[0] << 24) +
				(pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
			break;
		case 3: // Signature Expiration Time
			if (pkt.size() != 4)
				return 0; // error: incorrect subpacket body 
			out.sigexpirationtime = (pkt[0] << 24) +
				(pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
			break;
		case 4: // Exportable Certification
			if (pkt.size() != 1)
				return 0; // error: incorrect subpacket body
			if (pkt[0] == 0x00)
				out.exportablecertification = false;
			else if (pkt[0] == 0x01)
				out.exportablecertification = true;
			else
				return 0; // error: bad value
			break;
		case 5: // Trust Signature
			if (pkt.size() != 2)
				return 0; // error: incorrect subpacket body
			out.trustlevel = pkt[0];
			out.trustamount = pkt[1];
			break;
		case 6: // Regular Expression
			if (pkt.size() >= sizeof(out.trustregex))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.trustregex[i] = pkt[i];
			break;
		case 7: // Revocable
			if (pkt.size() != 1)
				return 0; // error: incorrect subpacket body
			if (pkt[0] == 0x00)
				out.revocable = false;
			else if (pkt[0] == 0x01)
				out.revocable = true;
			else
				return 0; // error: bad value
			break;
		case 9: // Key Expiration Time
			if (pkt.size() != 4)
				return 0; // error: incorrect subpacket body 
			out.keyexpirationtime = (pkt[0] << 24) +
				(pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
			break;
		case 11: // Preferred Symmetric Algorithms
			if (pkt.size() > sizeof(out.psa))
				return 0; // error: too long subpacket body
			out.psalen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.psa[i] = pkt[i];
			break;
		case 12: // Revocation Key (cf. changes from [draft RFC 4880bis])
			if ((pkt.size() != 22) && (pkt.size() != 34))
				return 0; // error: incorrect subpacket body
			// Class octet must have bit 0x80 set.
			if ((pkt[0] & 0x80) != 0x80)
				return 0; // error: bad class
			out.revocationkey_class = pkt[0];
			out.revocationkey_pkalgo = (tmcg_openpgp_pkalgo_t)pkt[1];
			for (size_t i = 0; i < (pkt.size() - 2); i++)
				out.revocationkey_fingerprint[i] = pkt[2+i];
			break;
		case 16: // Issuer
			if (pkt.size() != 8)
				return 0; // error: incorrect subpacket body
			for (size_t i = 0; i < 8; i++)
				out.issuer[i] = pkt[i];
			break;
		case 20: // Notation Data
			out.notation_human_readable = false;
			if (pkt.size() < 8)
				return 0; // error: incorrect subpacket body
			// Flags: First octet: 0x80=human-readable
			if ((pkt[0] & 0x80) == 0x80)
				out.notation_human_readable = true;
			out.notation_name_length = (pkt[4] << 8) + pkt[5];
			out.notation_value_length = (pkt[6] << 8) + pkt[7];
			if (pkt.size() != (out.notation_name_length +
			                   out.notation_value_length + 8))
				return 0; // error: incorrect length
			if (out.notation_name_length > 
			    sizeof(out.notation_name))
				return 0; // error: too long notation name
			if (out.notation_value_length > 
			    sizeof(out.notation_value))
				return 0; // error: too long notation value
			for (size_t i = 0; i < out.notation_name_length; i++)
				out.notation_name[i] = pkt[8+i];
			for (size_t i = 0; i < out.notation_value_length; i++)
				out.notation_value[i] =
					pkt[8+i+out.notation_name_length];
			break;
		case 21: // Preferred Hash Algorithms
			if (pkt.size() > sizeof(out.pha))
				return 0; // error: too long subpacket body
			out.phalen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.pha[i] = pkt[i];
			break;
		case 22: // Preferred Compression Algorithms
			if (pkt.size() > sizeof(out.pca))
				return 0; // error: too long subpacket body
			out.pcalen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.pca[i] = pkt[i];
			break;
		case 23: // Key Server Preferences
			if (pkt.size() >= sizeof(out.keyserverpreferences))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.keyserverpreferences[i] = pkt[i];
			break;
		case 24: // Preferred Key Server
			if (pkt.size() >= sizeof(out.preferedkeyserver))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.preferedkeyserver[i] = pkt[i];
			break;
		case 25: // Primary User ID
			if (pkt.size() != 1)
				return 0; // error: incorrect subpacket body
			if (pkt[0] == 0x00)
				out.primaryuserid = false;
			else if (pkt[0] == 0x01)
				out.primaryuserid = true;
			else
				return 0; // error: bad value
			break;
		case 26: // Policy URI
			if (pkt.size() >= sizeof(out.policyuri))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.policyuri[i] = pkt[i];
			break;
		case 27: // Key Flags
			if (pkt.size() > sizeof(out.keyflags))
				return 0; // error: too long subpacket body
			out.keyflagslen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.keyflags[i] = pkt[i];
			break;
		case 28: // Signer's User ID
			if (pkt.size() > sizeof(out.signersuserid))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.signersuserid[i] = pkt[i];
			break;
		case 29: // Reason for Revocation
			if (pkt.size() > (sizeof(out.revocationreason) + 1))
				return 0; // error: too long subpacket body
			if (pkt.size() < 1)
				return 0; // error: too short subpacket body
			out.revocationcode = (tmcg_openpgp_revcode_t)pkt[0];
			for (size_t i = 0; i < (pkt.size() - 1); i++)
				out.revocationreason[i] = pkt[1+i];
			break;
		case 30: // Features
			if (pkt.size() > sizeof(out.features))
				return 0; // error: too long subpacket body
			out.featureslen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.features[i] = pkt[i];
			break;
		case 31: // Signature Target
			if (pkt.size() < 2)
				return 0; // error: too short subpacket body
			out.signaturetarget_pkalgo = (tmcg_openpgp_pkalgo_t)pkt[0];
			out.signaturetarget_hashalgo = (tmcg_openpgp_hashalgo_t)pkt[1];
			if (pkt.size() > (sizeof(out.signaturetarget_hash) + 2))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < (pkt.size() - 2); i++)
				out.signaturetarget_hash[i] = pkt[2+i];
			break;
		case 32: // Embedded Signature
			if (out.embeddedsignaturelen != 0)
			{
				if (verbose)
					std::cerr << "WARNING: more than one embedded signature" <<
						" found" << std::endl;
				delete [] out.embeddedsignature;
			}
			out.embeddedsignaturelen = pkt.size();
			if (verbose > 2)
				std::cerr << "INFO: embeddedsignaturelen = " <<
					out.embeddedsignaturelen << std::endl;
			tmcg_openpgp_mem_alloc += out.embeddedsignaturelen;
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= out.embeddedsignaturelen;
				out.embeddedsignaturelen = 0;
				return 0; // error: memory limit exceeded
			}
			out.embeddedsignature =
				new tmcg_openpgp_byte_t[out.embeddedsignaturelen];	
			for (size_t i = 0; i < pkt.size(); i++)
				out.embeddedsignature[i] = pkt[i];
			break;
		case 33: // Issuer Fingerprint [draft RFC 4880bis]
			if (pkt.size() < 2)
				return 0; // error: too short subpacket body
			out.issuerkeyversion = pkt[0];
			switch (out.issuerkeyversion)
			{
				case 0x04:
					if (pkt.size() != 21)
						return 0; // error: incorrect subpacket body
					for (size_t i = 0; i < 20; i++)
						out.issuerfingerprint[i] = pkt[1+i];
					break;
				case 0x05:
					if (pkt.size() != 33)
						return 0; // error: incorrect subpacket body
					for (size_t i = 0; i < 32; i++)
						out.issuerfingerprint[i] = pkt[1+i];
					break;
				default:
					type = 0xFE; // subpacket not recognized
					break;
			}
			break;
		case 34: // Preferred AEAD Algorithms [draft RFC 4880bis]
			if (pkt.size() > sizeof(out.paa))
				return 0; // error: too long subpacket body
			out.paalen = pkt.size();
			for (size_t i = 0; i < pkt.size(); i++)
				out.paa[i] = pkt[i];
			break;
		case 100: // Private or experimental -- not implemented; ignore
		case 101:
		case 102:
		case 103:
		case 104:
		case 105:
		case 106:
		case 107:
		case 108:
		case 109:
		case 110:
			type = 0xFE; // subpacket not recognized
			break;
		default: // unknown subpacket type; ignore, if not critical
			type = 0xFE; // subpacket not recognized
			break; 
	}
	in.erase(in.begin(), in.begin()+headlen+len); // remove subpacket
	return type;
}

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketParse
	(tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_packet_ctx_t &out, tmcg_openpgp_notations_t &notations)
{
	tmcg_openpgp_byte_t tag = 0x02; // signature subpackets only
	while (in.size())
	{
		out.notation_name_length = 0;
		out.notation_value_length = 0;
		tmcg_openpgp_byte_t sptype = SubpacketDecode(in, verbose, out);
		if (sptype == 0)
		{
			if (verbose)
			{
				std::cerr << "ERROR: incorrect ";
				if (out.critical)
					std::cerr << "critical ";
				std::cerr << "signature subpacket found" << std::endl;
			}
			return 0x00; // error: incorrect subpacket
		}
		else if (sptype == 0xFE)
		{
			 // critical subpacket?
			if (out.critical)
				tag = 0xFA;
			else
				tag = 0xFB;
			if (verbose > 2)
			{
				std::cerr << "WARNING: unrecognized ";
				if (out.critical)
					std::cerr << "critical ";
				std::cerr << "signature subpacket found" << std::endl;
			}
		}
		else
		{
			if (verbose > 2)
			{
				std::cerr << "INFO: signature subpacket type = " <<
					(int)sptype << " found" << std::endl;
			}
			if (out.notation_name_length != 0)
			{
				tmcg_openpgp_notation_t notation;
				for (size_t i = 0; i < out.notation_name_length; i++)
					notation.first.push_back(out.notation_name[i]);
				for (size_t i = 0; i < out.notation_value_length; i++)
					notation.second.push_back(out.notation_value[i]);
				notations.push_back(notation);
				if (verbose > 2)
					std::cerr << "INFO: notation data found" <<
						std::endl;
			}
		}
	}
	return tag;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextEvaluate
	(const tmcg_openpgp_packet_ctx_t &in, tmcg_openpgp_packet_ctx_t &out)
{
	// copy Issuer, if not already set
	bool copy = true;
	for (size_t i = 0; i < sizeof(out.issuer); i++)
	{
		if (out.issuer[i])
			copy = false;
	}
	for (size_t i = 0; (copy && (i < sizeof(out.issuer))); i++)
		out.issuer[i] = in.issuer[i];
	// copy Embedded Signature, if not already set
	if (out.embeddedsignaturelen == 0)
	{
		out.embeddedsignaturelen = in.embeddedsignaturelen;
		out.embeddedsignature =
			new tmcg_openpgp_byte_t[out.embeddedsignaturelen];	
		for (size_t i = 0; i < in.embeddedsignaturelen; i++)
			out.embeddedsignature[i] = in.embeddedsignature[i];
	}
	// copy Issuer Fingerprint, if not already set
	copy = true;
	for (size_t i = 0; i < sizeof(out.issuerfingerprint); i++)
	{
		if (out.issuerfingerprint[i])
			copy = false;
	}
	if (copy)
	{
		out.issuerkeyversion = in.issuerkeyversion;
		for (size_t i = 0; i < sizeof(out.issuerfingerprint); i++)
			out.issuerfingerprint[i] = in.issuerfingerprint[i];
	}
}

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketBodyExtract
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_octets_t &out)
{
	bool newformat;
	// The first octet of the packet header is called the "Packet
	// Tag". It determines the format of the header and denotes the
	// packet contents. The remainder of the packet header is the
	// length of the packet.
	// Note that the most significant bit is the leftmost bit, called
	// bit 7. A mask for this bit is 0x80 in hexadecimal.
	//      +---------------+
	// PTag |7 6 5 4 3 2 1 0|
	//      +---------------+
	// Bit 7 -- Always one
	// Bit 6 -- New packet format if set
	tmcg_openpgp_octets_t work;
	work.insert(work.end(), in.begin(), in.end());
	if (work.size() < 1)
		return 0; // error: no first octet of packet header
	tmcg_openpgp_byte_t tag = work[0];
	tmcg_openpgp_byte_t lentype = 0x00;
	work.erase(work.begin(), work.begin()+1); // remove first octet
	if ((tag & 0x80) != 0x80)
		return 0; // error: Bit 7 of first octet not set
	if ((tag & 0x40) == 0x40)
	{
		newformat = true;
		tag -= (0x80 + 0x40); // Bits 5-0 -- packet tag
	}
	else
	{
		newformat = false;
		lentype = tag & 0x03; // Bits 1-0 -- length-type
		tag = (tag >> 2) & 0x1F; // Bits 5-2 -- packet tag
	}
	// Each Partial Body Length header is followed by a portion of the
	// packet body data. The Partial Body Length header specifies this
	// portion's length. Another length header (one octet, two-octet,
	// five-octet, or partial) follows that portion. The last length
	// header in the packet MUST NOT be a Partial Body Length header.
	// Partial Body Length headers may only be used for the non-final
	// parts of the packet.
	uint32_t len = 0;
	bool partlen = true, firstlen = true;
	while (partlen)
	{
		size_t headlen = PacketLengthDecode(work, newformat,
			lentype, len, partlen);
		if (!headlen)
			return 0; // error: invalid length header
		if (headlen == 42)
			headlen = 0; // special case: indeterminate length
		if (work.size() < (headlen + len))
			return 0; // error: packet too short
		// An implementation MAY use Partial Body Lengths for data
		// packets, be they literal, compressed, or encrypted. The
		// first partial length MUST be at least 512 octets long.
		// Partial Body Lengths MUST NOT be used for any other packet
		// types.
		if (partlen && firstlen && (len < 512))
			return 0; // error: first partial less than 512 octets
		if (partlen && (tag != 8) && (tag != 9) && (tag != 11) && 
		    (tag != 18))
		{
			if (verbose > 1)
				std::cerr << "WARNING: tag not allowed by spec" << std::endl;
			return 0; // error: no literal, compressed, ... allowed
		}
		out.insert(out.end(),
			work.begin()+headlen, work.begin()+headlen+len);
		work.erase(work.begin(), work.begin()+headlen+len); // remove chunck
		firstlen = false;
	}
	return tag;
}

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_packet_ctx_t &out,
	 tmcg_openpgp_octets_t &current_packet,
	 std::vector<gcry_mpi_t> &qual,
	 std::vector<gcry_mpi_t> &x_rvss_qual,
	 std::vector<std::string> &capl,
	 std::vector<gcry_mpi_t> &v_i,
	 std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 tmcg_openpgp_notations_t &notations)
{
	memset(&out, 0, sizeof(out)); // clear output context
	// Exportable Certification: If this packet is not present, the
	// certification is exportable; it is equivalent to a flag 
	// containing a 1.
	out.exportablecertification = true;
	// Revocable: If this packet is not present, the signature is
	// revocable.
	out.revocable = true;
	// The first octet of the packet header is called the "Packet
	// Tag". It determines the format of the header and denotes the
	// packet contents. The remainder of the packet header is the
	// length of the packet.
	// Note that the most significant bit is the leftmost bit, called
	// bit 7. A mask for this bit is 0x80 in hexadecimal.
	//      +---------------+
	// PTag |7 6 5 4 3 2 1 0|
	//      +---------------+
	// Bit 7 -- Always one
	// Bit 6 -- New packet format if set
	if (in.size() < 1)
		return 0; // error: no first octet of packet header
	tmcg_openpgp_byte_t tag = in[0];
	tmcg_openpgp_byte_t lentype = 0x00;
	current_packet.push_back(tag); // store packet header
	in.erase(in.begin(), in.begin()+1); // remove first octet
	if ((tag & 0x80) != 0x80)
		return 0; // error: Bit 7 of first octet not set
	if ((tag & 0x40) == 0x40)
	{
		out.newformat = true;
		tag -= (0x80 + 0x40); // Bits 5-0 -- packet tag
	}
	else
	{
		out.newformat = false;
		lentype = tag & 0x03; // Bits 1-0 -- length-type
		tag = (tag >> 2) & 0x1F; // Bits 5-2 -- packet tag
	}
	out.tag = tag;
	// Each Partial Body Length header is followed by a portion of the
	// packet body data. The Partial Body Length header specifies this
	// portion's length. Another length header (one octet, two-octet,
	// five-octet, or partial) follows that portion. The last length
	// header in the packet MUST NOT be a Partial Body Length header.
	// Partial Body Length headers may only be used for the non-final
	// parts of the packet.
	tmcg_openpgp_octets_t pkt; // only the packet body
	uint32_t len = 0;
	bool partlen = true, firstlen = true;
	while (partlen)
	{
		size_t headlen = PacketLengthDecode(in, out.newformat, lentype, len,
			partlen);
		if (!headlen)
			return 0; // error: invalid length header
		if (headlen == 42)
		{
			headlen = 0; // special case: indeterminate length
			out.indetlen = true;
		}
		if (in.size() < (headlen + len))
			return 0; // error: packet too short
		// An implementation MAY use Partial Body Lengths for data
		// packets, be they literal, compressed, or encrypted. The
		// first partial length MUST be at least 512 octets long.
		// Partial Body Lengths MUST NOT be used for any other packet
		// types.
		if (partlen && firstlen && (len < 512))
			return 0; // error: first partial less than 512 octets
		if (partlen && (tag != 8) && (tag != 9) && (tag != 11) && (tag != 18))
		{
			return 0; // error: no literal, compressed, ... allowed
		}
		current_packet.insert(current_packet.end(), // copy packet data
			in.begin(), in.begin()+headlen+len);
		pkt.insert(pkt.end(),
			in.begin()+headlen, in.begin()+headlen+len);
		in.erase(in.begin(), in.begin()+headlen+len); // remove chunck
		firstlen = false;
	}
	tmcg_openpgp_octets_t hspd, uspd, mpis;
	size_t mlen = 0;
	uint32_t hspdlen = 0, uspdlen = 0;
	switch (tag)
	{
		case 1: // Public-Key Encrypted Session Key Packet
			if (pkt.size() < 16)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 3)
				return 0; // error: version not supported
			for (size_t i = 0; i < 8; i++)
				out.keyid[i] = pkt[1+i];
			out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[9];
			mpis.insert(mpis.end(), pkt.begin()+10, pkt.end());
			if ((out.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
			{
				// Algorithm-Specific Fields for RSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.me);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				// Algorithm-Specific Fields for Elgamal
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.gk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.myk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
			{
				// Algorithm-Specific Fields for ECDH keys [RFC 6637]
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.ecepk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				// a one-octet size, followed by a symmetric key encoded
				// using the method described in Section 8 [RFC 6637]
				if (mpis.size() <= 2)
					return 0; // error: result of key wrapping too short
				out.rkwlen = mpis[0];
				if ((out.rkwlen == 0) || (out.rkwlen == 255))
					return 0; // error: bad result of key wrapping
				if (mpis.size() < (out.rkwlen + 1))
					return 0; // error: result of key wrapping too short
				for (size_t i = 0; i < out.rkwlen; i++)
					out.rkw[i] = mpis[1+i];
				mpis.erase(mpis.begin(), mpis.begin()+out.rkwlen+1);
			}
			else
				return 0xFE; // warning: unsupported algo
			break;
		case 2: // Signature Packet
			if (pkt.size() < 1)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version == 3)
			{
				if (pkt.size() < 22)
					return 0; // error: packet too short
				if (pkt[1] != 5)
					return 0; // error: incorrect length
				out.type = (tmcg_openpgp_signature_t)pkt[2];
				out.sigcreationtime = (pkt[3] << 24) + (pkt[4] << 16) +
					(pkt[5] << 8) + pkt[6];
				for (size_t i = 0; i < 8; i++)
					out.issuer[i] = pkt[7+i];
				out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[15];
				out.hashalgo = (tmcg_openpgp_hashalgo_t)pkt[16];
				// left 16 bits of signed hash value
				for (size_t i = 0; i < 2; i++)
					out.left[i] = pkt[17+i];
				mpis.insert(mpis.end(), pkt.begin()+19, pkt.end());
			}
			else if (out.version == 4)
			{
				if (pkt.size() < 12)
					return 0; // error: packet too short
				out.type = (tmcg_openpgp_signature_t)pkt[1];
				out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[2];
				out.hashalgo = (tmcg_openpgp_hashalgo_t)pkt[3];
				hspdlen = (pkt[4] << 8) + pkt[5];
				if (pkt.size() < (6 + hspdlen))
					return 0; // error: packet too short
				hspd.insert(hspd.end(),
					pkt.begin()+6, pkt.begin()+6+hspdlen);
				out.hspdlen = hspdlen;
				tmcg_openpgp_mem_alloc += out.hspdlen;
				if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
				{
					tmcg_openpgp_mem_alloc -= out.hspdlen;
					return 0; // error: memory limit exceeded
				}
				out.hspd = new tmcg_openpgp_byte_t[out.hspdlen];
				for (size_t i = 0; i < out.hspdlen; i++)
					out.hspd[i] = pkt[6+i];
				tag = SubpacketParse(hspd, verbose, out, notations);
				if (tag == 0x00)
					return 0; // error: incorrect subpacket
				if (pkt.size() < (8 + hspdlen))
					return 0; // error: packet too short
				uspdlen = (pkt[6+hspdlen] << 8) + pkt[7+hspdlen];
				if (pkt.size() < (8 + hspdlen + uspdlen))
					return 0; // error: packet too short
				uspd.insert(uspd.end(),
					pkt.begin()+8+hspdlen, pkt.begin()+8+hspdlen+uspdlen);
				// If a subpacket is not hashed, then the
				// information in it cannot be considered
				// definitive because it is not part of the
				// signature proper.
				tmcg_openpgp_packet_ctx_t untrusted;
				tmcg_openpgp_notations_t unotations;
				memset(&untrusted, 0, sizeof(untrusted));
				tag = SubpacketParse(uspd, verbose, untrusted, unotations);
				if (tag == 0x00)
					return 0; // error: incorrect subpacket
				PacketContextEvaluate(untrusted, out);
				PacketContextRelease(untrusted);
				if (pkt.size() < (10 + hspdlen + uspdlen))
					return 0; // error: packet too short
				 // left 16 bits of signed hash value
				for (size_t i = 0; i < 2; i++)
					out.left[i] = pkt[8+hspdlen+uspdlen+i];
				mpis.insert(mpis.end(),
					pkt.begin()+10+hspdlen+uspdlen, pkt.end());
			}
			else
				return 0xFC; // warning: version not supported
			if ((out.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
			{
				// Algorithm-Specific Fields for RSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.md);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				// Algorithm-Specific Fields for DSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.r);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.s);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
				(out.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
			{
				// Algorithm-Specific Fields for ECDSA/EdDSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.r);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.s);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else
				return 0xFC; // warning: unsupported algo
			break;
		case 3: // Symmetric-Key Encrypted Session Key Packet
			if (pkt.size() < 1)
				return 0; // error: packet too short
			out.version = pkt[0];
			if (out.version == 4)
			{
				if (pkt.size() < 4)
					return 0; // error: packet too short
				out.skalgo = (tmcg_openpgp_skalgo_t)pkt[1];
				out.s2k_type = (tmcg_openpgp_stringtokey_t)pkt[2];
				out.s2k_hashalgo = (tmcg_openpgp_hashalgo_t)pkt[3];
				if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SIMPLE)
				{
					// Simple S2K -- forbidden by RFC 4880 (only for completeness)
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 4);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 4);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 4;
					if (out.encdatalen == 0)
						break; // no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[4+i];
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SALTED)
				{
					// Salted S2K
					if (pkt.size() < 12)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = pkt[4+i];
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 12);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 12);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 12;
					if (out.encdatalen == 0)
						break; // no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[12+i];
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_ITERATED)
				{
					// Iterated and Salted S2K
					if (pkt.size() < 12)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = pkt[4+i];
					if (pkt.size() < 13)
						return 0; // error: no count
					out.s2k_count = pkt[12];
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 13);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 13);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 13;
					if (out.encdatalen == 0)
						break; // no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[13+i];
				}
				else
					return 0; // unknown S2K specifier
			}
			else if (out.version == 5)
			{
				// AEAD SKESK [draft RFC 4880bis]
				if (pkt.size() < 5)
					return 0; // error: packet too short
				out.skalgo = (tmcg_openpgp_skalgo_t)pkt[1];
				out.aeadalgo = (tmcg_openpgp_aeadalgo_t)pkt[2];
				out.s2k_type = (tmcg_openpgp_stringtokey_t)pkt[3];
				out.s2k_hashalgo = (tmcg_openpgp_hashalgo_t)pkt[4];
				if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SIMPLE)
				{
					// Simple S2K -- forbidden by RFC 4880 (only for completeness)
					size_t ivlen = AlgorithmIVLength(out.aeadalgo);
					if (pkt.size() < (5 + ivlen))
						return 0; // error: no IV
					if (ivlen > sizeof(out.iv))
						return 0; // error: IV too long
					for (size_t i = 0; i < ivlen; i++)
						out.iv[i] = pkt[5+i];
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 5 - ivlen);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 5 - ivlen);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 5 - ivlen;
					if (out.encdatalen == 0)
						return 0; // error: no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[5+ivlen+i];
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SALTED)
				{
					// Salted S2K
					if (pkt.size() < 13)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = pkt[5+i];
					size_t ivlen = AlgorithmIVLength(out.aeadalgo);
					if (pkt.size() < (13 + ivlen))
						return 0; // error: no IV
					if (ivlen > sizeof(out.iv))
						return 0; // error: IV too long
					for (size_t i = 0; i < ivlen; i++)
						out.iv[i] = pkt[13+i];
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 13 - ivlen);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 13 - ivlen);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 13 - ivlen;
					if (out.encdatalen == 0)
						return 0; // error: no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[13+ivlen+i];
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_ITERATED)
				{
					// Iterated and Salted S2K
					if (pkt.size() < 13)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = pkt[5+i];
					if (pkt.size() < 14)
						return 0; // error: no count
					out.s2k_count = pkt[13];
					size_t ivlen = AlgorithmIVLength(out.aeadalgo);
					if (pkt.size() < (14 + ivlen))
						return 0; // error: no IV
					if (ivlen > sizeof(out.iv))
						return 0; // error: IV too long
					for (size_t i = 0; i < ivlen; i++)
						out.iv[i] = pkt[14+i];
					if (out.encdatalen != 0)
						return 0; // error: already seen within context
					tmcg_openpgp_mem_alloc += (pkt.size() - 14 - ivlen);
					if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
					{
						tmcg_openpgp_mem_alloc -= (pkt.size() - 14 - ivlen);
						return 0; // error: memory limit exceeded
					}
					out.encdatalen = pkt.size() - 14 - ivlen;
					if (out.encdatalen == 0)
						return 0; // error: no encrypted session key
					out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
					for (size_t i = 0; i < out.encdatalen; i++)
						out.encdata[i] = pkt[14+ivlen+i];
				}
				else
					return 0; // unknown S2K specifier	
			}
			else
				return 0; // error: version not supported
			break;
		case 4: // One-Pass Signature Packet
			if (pkt.size() != 13)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 3)
				return 0; // error: version not supported
			out.type = (tmcg_openpgp_signature_t)pkt[1];
			out.hashalgo = (tmcg_openpgp_hashalgo_t)pkt[2];
			out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[3];
			for (size_t i = 0; i < 8; i++)
				out.signingkeyid[i] = pkt[4+i];
			out.nestedsignature = pkt[12];
			break;
		case 5: // Secret-Key Packet
		case 7: // Secret-Subkey Packet
			if (pkt.size() < 10)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.keycreationtime = (pkt[1] << 24) +
				(pkt[2] << 16) + (pkt[3] << 8) + pkt[4];
			out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
			if ((out.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
			{
				// Algorithm-Specific Fields for RSA keys
				mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.e);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				// Algorithm-Specific Fields for Elgamal keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				// Algorithm-Specific Fields for DSA keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
			{
				// Algorithm-Specific Fields for ECDH keys [RFC 6637]
				out.curveoidlen = (tmcg_openpgp_pkalgo_t)pkt[6];
				if ((out.curveoidlen == 0) || (out.curveoidlen == 255))
					return 0; // error: values reserved for future extensions
				if (pkt.size() < (7 + out.curveoidlen))
					return 0; // error: OID too short
				for (size_t i = 0; i < out.curveoidlen; i++)
					out.curveoid[i] = pkt[7+i];
				mpis.clear();
				mpis.insert(mpis.end(),
					pkt.begin()+7+out.curveoidlen, pkt.end());
				mlen = PacketMPIDecode(mpis, out.ecpk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() < 4)
					return 0; // error: bad KDF params size
				if (mpis[0] != 0x03)
					return 0; // error: bad KDF size
				if (mpis[1] != 0x01)
					return 0; // error: bad KDF extensions
				out.kdf_hashalgo = (tmcg_openpgp_hashalgo_t)mpis[2];
				out.kdf_skalgo = (tmcg_openpgp_skalgo_t)mpis[3];
				mpis.erase(mpis.begin(), mpis.begin()+4);
			}
			else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
				(out.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
			{
				// Algorithm-Specific Fields for ECDSA keys [RFC 6637]
				// Algorithm-Specific Fields for EdDSA keys [draft RFC 4880bis]
				out.curveoidlen = (tmcg_openpgp_pkalgo_t)pkt[6];
				if ((out.curveoidlen == 0) || (out.curveoidlen == 255))
					return 0; // error: values reserved for future extensions
				if (pkt.size() < (7 + out.curveoidlen))
					return 0; // error: OID too short
				for (size_t i = 0; i < out.curveoidlen; i++)
					out.curveoid[i] = pkt[7+i];
				mpis.clear();
				mpis.insert(mpis.end(),
					pkt.begin()+7+out.curveoidlen, pkt.end());
				mlen = PacketMPIDecode(mpis, out.ecpk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
			{
				// Algorithm-Specific Fields for new tDSS/DSA keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.h);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.t);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.i);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.qualsize);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				size_t qs = tmcg_get_gcry_mpi_ui(out.qualsize);
				if (qs > 255)
					return 0; // error: too many parties
				qual.resize(qs);
				for (size_t j = 0; j < qs; j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				mlen = PacketMPIDecode(mpis, out.x_rvss_qualsize);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				size_t xqs =
					tmcg_get_gcry_mpi_ui(out.x_rvss_qualsize);
				if (xqs > 255)
					return 0; // error: too many parties
				x_rvss_qual.resize(xqs);
				for (size_t j = 0; j < xqs; j++)
				{
					mlen = PacketMPIDecode(mpis, x_rvss_qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				size_t n = tmcg_get_gcry_mpi_ui(out.n);
				size_t t = tmcg_get_gcry_mpi_ui(out.t);
				if ((n > 255) || (t > 128) ||
				    (tmcg_get_gcry_mpi_ui(out.i) >= n))
				{
					return 0; // error: too many parties, 
					          //        bad threshold/index
				}
				capl.clear();
				for (size_t j = 0; j < n; j++)
				{
					std::string peerid;
					mlen = PacketStringDecode(mpis, peerid);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					capl.push_back(peerid);
				}
				c_ik.resize(n);
				for (size_t j = 0; j < n; j++)
				{
					c_ik[j].resize(t + 1);
					for (size_t k = 0; k <= t; k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
					}
				}
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL8)
			{
				// Algorithm-Specific Fields for old tDSS/DSA keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.h);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.t);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.i);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.qualsize);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				size_t qs = tmcg_get_gcry_mpi_ui(out.qualsize);
				if (qs > 255)
					return 0; // error: too many parties
				qual.resize(qs);
				for (size_t j = 0; j < qs; j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				capl.clear();
				for (size_t j = 0; j < qs; j++)
				{
					std::string peerid;
					mlen = PacketStringDecode(mpis, peerid);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					capl.push_back(peerid);
				}
				size_t n = tmcg_get_gcry_mpi_ui(out.n);
				size_t t = tmcg_get_gcry_mpi_ui(out.t);
				if ((n > 255) || (t > 128))
					return 0; // error: too many parties
				c_ik.resize(n);
				for (size_t j = 0; j < n; j++)
				{
					c_ik[j].resize(t + 1);
					for (size_t k = 0; k <= t; k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
					}
				}
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
			{
				// Algorithm-Specific Fields for tElG keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.h);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.t);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.i);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.qualsize);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				size_t qs = tmcg_get_gcry_mpi_ui(out.qualsize);
				if (qs > 255)
					return 0; // error: too many parties
				qual.resize(qs);
				for (size_t j = 0; j < qs; j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				size_t n = tmcg_get_gcry_mpi_ui(out.n);
				size_t t = tmcg_get_gcry_mpi_ui(out.t);
				if ((n > 255) || (t > 128))
					return 0; // error: too many parties
				v_i.resize(n);
				for (size_t j = 0; j < n; j++)
				{
					mlen = PacketMPIDecode(mpis, v_i[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				c_ik.resize(n);
				for (size_t j = 0; j < n; j++)
				{
					c_ik[j].resize(t + 1);
					for (size_t k = 0; k <= t; k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
					}
				}
			}
			else
				return 0; // error: unsupported public-key algo
			// secret fields
			if (mpis.size() < 1)
				return 0; // error: no S2K convention
			out.s2kconv = mpis[0];
			mpis.erase(mpis.begin(), mpis.begin()+1);
			if (out.s2kconv == 0)
			{
				tmcg_openpgp_secure_octets_t smpis;
				for (size_t i = 0; i < mpis.size(); i++)
					smpis.push_back(mpis[i]); // copy
				// not encrypted + checksum
				size_t chksum = 0;
				if ((out.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
				    (out.pkalgo == TMCG_OPENPGP_PKALGO_DSA))
				{
					// Algorithm-Specific Fields for Elgamal
					// Algorithm-Specific Fields for DSA
					mlen = PacketMPIDecode(smpis, out.x, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
				         (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
				         (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
				{
					// Algorithm-Specific Fields for RSA
					mlen = PacketMPIDecode(smpis, out.d, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(smpis, out.p, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(smpis, out.q, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(smpis, out.u, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_ECDH) ||
					(out.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
					(out.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
				{
					// Algorithm-Specific Fields for ECDH keys [RFC 6637]
					// Algorithm-Specific Fields for ECDSA keys [RFC 6637]
					// Algorithm-Specific Fields for EdDSA [draft RFC 4880bis]
					mlen = PacketMPIDecode(smpis, out.ecsk, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) ||
				         (out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL8) ||
				         (out.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
				{
					// Algorithm-Specific Fields tDSS/DKG
					mlen = PacketMPIDecode(smpis, out.x_i, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(smpis, out.xprime_i, chksum);
					if (!mlen || (mlen > smpis.size()))
						return 0; // error: bad mpi
					smpis.erase(smpis.begin(), smpis.begin()+mlen);
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else
					return 0; // error: algo not supported
				if (mpis.size() < 2)
					return 0; // error: no checksum
				size_t chksum2 = (mpis[0] << 8) + mpis[1];
				if (chksum != chksum2)
					return 0; // error: checksum mismatch
				mpis.erase(mpis.begin(), mpis.begin()+2);
			}
			else if ((out.s2kconv == 254) || (out.s2kconv == 255))
			{
				// encrypted + SHA-1 hash or checksum
				if (mpis.size() < 1)
					return 0; // error: no sym. algorithm
				out.skalgo = (tmcg_openpgp_skalgo_t)mpis[0];
				mpis.erase(mpis.begin(), mpis.begin()+1);
				if (mpis.size() < 2)
					return 0; // error: bad S2K specifier
				out.s2k_type = (tmcg_openpgp_stringtokey_t)mpis[0];
				out.s2k_hashalgo = (tmcg_openpgp_hashalgo_t)mpis[1];
				mpis.erase(mpis.begin(), mpis.begin()+2);
				if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SIMPLE)
				{
					// Simple S2K
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SALTED)
				{
					// Salted S2K
					if (mpis.size() < 8)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = mpis[i];
					mpis.erase(mpis.begin(), mpis.begin()+8);
				}
				else if (out.s2k_type == TMCG_OPENPGP_STRINGTOKEY_ITERATED)
				{
					// Iterated and Salted S2K
					if (mpis.size() < 8)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = mpis[i];
					mpis.erase(mpis.begin(), mpis.begin()+8);
					if (mpis.size() < 1)
						return 0; // error: no count
					out.s2k_count = mpis[0];
					mpis.erase(mpis.begin(), mpis.begin()+1);
				}
				else
					return 0; // unknown S2K specifier
				size_t ivlen = AlgorithmIVLength(out.skalgo);
				if (mpis.size() < ivlen)
					return 0; // error: no IV
				if (ivlen > sizeof(out.iv))
					return 0; // error: IV too long
				for (size_t i = 0; i < ivlen; i++)
					out.iv[i] = mpis[i];
				mpis.erase(mpis.begin(), mpis.begin()+ivlen);
				if (mpis.size() < 4)
					return 0; // error: bad encrypted data
				if (out.encdatalen != 0)
					return 0; // already seen within context
				tmcg_openpgp_mem_alloc += mpis.size();
				if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
				{
					tmcg_openpgp_mem_alloc -= mpis.size();
					return 0; // error: memory limit exceeded
				}
				out.encdatalen = mpis.size();
				out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
				for (size_t i = 0; i < out.encdatalen; i++)
					out.encdata[i] = mpis[i];
			}
			else
				return 0; // S2K convention not supported
			break;
		case 6: // Public-Key Packet
		case 14: // Public-Subkey Packet
			if (pkt.size() < 10)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.keycreationtime = (pkt[1] << 24) +
				(pkt[2] << 16) + (pkt[3] << 8) + pkt[4];
			out.pkalgo = (tmcg_openpgp_pkalgo_t)pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
			if ((out.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
			    (out.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
			{
				// Algorithm-Specific Fields for RSA keys
				mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.e);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				// Algorithm-Specific Fields for Elgamal keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				// Algorithm-Specific Fields for DSA keys
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
			{
				// Algorithm-Specific Fields for ECDH keys [RFC 6637]
				out.curveoidlen = (tmcg_openpgp_pkalgo_t)pkt[6];
				if ((out.curveoidlen == 0) || (out.curveoidlen == 255))
					return 0; // error: values reserved for future extensions
				if (pkt.size() < (7 + out.curveoidlen))
					return 0; // error: OID too short
				for (size_t i = 0; i < out.curveoidlen; i++)
					out.curveoid[i] = pkt[7+i];
				mpis.clear();
				mpis.insert(mpis.end(),
					pkt.begin()+7+out.curveoidlen, pkt.end());
				mlen = PacketMPIDecode(mpis, out.ecpk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() != 4)
					return 0; // error: bad KDF params size
				if (mpis[0] != 0x03)
					return 0; // error: bad KDF size
				if (mpis[1] != 0x01)
					return 0; // error: bad KDF extensions
				out.kdf_hashalgo = (tmcg_openpgp_hashalgo_t)mpis[2];
				out.kdf_skalgo = (tmcg_openpgp_skalgo_t)mpis[3];
			}
			else if ((out.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
				(out.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
			{
				// Algorithm-Specific Fields for ECDSA keys [RFC 6637]
				// Algorithm-Specific Fields for EdDSA keys [draft RFC 4880bis]
				out.curveoidlen = (tmcg_openpgp_pkalgo_t)pkt[6];
				if ((out.curveoidlen == 0) || (out.curveoidlen == 255))
					return 0; // error: values reserved for future extensions
				if (pkt.size() < (7 + out.curveoidlen))
					return 0; // error: OID too short
				for (size_t i = 0; i < out.curveoidlen; i++)
					out.curveoid[i] = pkt[7+i];
				mpis.clear();
				mpis.insert(mpis.end(),
					pkt.begin()+7+out.curveoidlen, pkt.end());
				mlen = PacketMPIDecode(mpis, out.ecpk);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else
				return 0xFD; // warning: unsupported algo
			break;
		case 8: // Compressed Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.compalgo = (tmcg_openpgp_compalgo_t)pkt[0];
			if (out.compdatalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += (pkt.size() - 1);
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= (pkt.size() - 1);
				return 0; // error: memory limit exceeded
			}
			out.compdatalen = pkt.size() - 1;
			out.compdata = new tmcg_openpgp_byte_t[out.compdatalen];
			for (size_t i = 0; i < out.compdatalen; i++)
				out.compdata[i] = pkt[1+i];
			break;
		case 9: // Symmetrically Encrypted Data Packet
			if (pkt.size() == 0)
				return 0; // error: empty packet body
			if (out.encdatalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += pkt.size();
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= pkt.size();
				return 0; // error: memory limit exceeded
			}
			out.encdatalen = pkt.size();
			out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
			for (size_t i = 0; i < out.encdatalen; i++)
				out.encdata[i] = pkt[i];
			break;
		case 10: // Marker Packet
			if (pkt.size() != 3)
				return 0; // error: incorrect packet body
			if ((pkt[0] != 0x50) || (pkt[1] != 0x47) || 
			    (pkt[3] != 0x50))
				return 0; // error: bad marker 
			break;
		case 11: // Literal Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.dataformat = pkt[0];
			out.datafilenamelen = pkt[1];
			if (pkt.size() < (out.datafilenamelen + 2))
				return 0; // error: packet too short
			for (size_t i = 0; i < out.datafilenamelen; i++)
				out.datafilename[i] = pkt[2+i];
			if (pkt.size() < (out.datafilenamelen + 7))
				return 0; // error: packet too short
			out.datatime = (pkt[3+out.datafilenamelen] << 24) +
				(pkt[4+out.datafilenamelen] << 16) +
				(pkt[5+out.datafilenamelen] << 8) +
				pkt[6+out.datafilenamelen];
			if (out.datalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += (pkt.size() - (out.datafilenamelen + 6));
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= (pkt.size()-(out.datafilenamelen+6));
				return 0; // error: memory limit exceeded
			}
			out.datalen = pkt.size() - (out.datafilenamelen + 6);
			out.data = new tmcg_openpgp_byte_t[out.datalen];
			for (size_t i = 0; i < out.datalen; i++)
				out.data[i] = pkt[6+out.datafilenamelen+i];
			break;
		case 12: // Trust Packet -- not supported, ignore silently
			break;
		case 13: // User ID Packet
			if (out.uiddatalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += pkt.size();
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= pkt.size();
				return 0; // error: memory limit exceeded
			}
			out.uiddatalen = pkt.size();
			if (pkt.size() > 0)
			{
				out.uiddata = new tmcg_openpgp_byte_t[out.uiddatalen];
				for (size_t i = 0; i < out.uiddatalen; i++)
					out.uiddata[i] = pkt[i];
			}
			break;
		case 17: // User Attribute Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			if (out.uatdatalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += pkt.size();
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= pkt.size();
				return 0; // error: memory limit exceeded
			}
			out.uatdatalen = pkt.size();
			out.uatdata = new tmcg_openpgp_byte_t[out.uatdatalen];
			for (size_t i = 0; i < out.uatdatalen; i++)
				out.uatdata[i] = pkt[i];
			break;
		case 18: // Sym. Encrypted and Integrity Protected Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 1)
				return 0; // error: version not supported
			if (out.encdatalen != 0)
				return 0; // error: already seen within context
			tmcg_openpgp_mem_alloc += (pkt.size() - 1);
			if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
			{
				tmcg_openpgp_mem_alloc -= (pkt.size() - 1);
				return 0; // error: memory limit exceeded
			}
			out.encdatalen = pkt.size() - 1;
			out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
			for (size_t i = 0; i < out.encdatalen; i++)
				out.encdata[i] = pkt[1+i];
			break;
		case 19: // Modification Detection Code Packet
			if (!out.newformat)
				return 0; // error: wrong format of packet tag
			if (pkt.size() != 20)
				return 0; // error: incorrect packet body
			for (size_t i = 0; i < pkt.size(); i++)
				out.mdc_hash[i] = pkt[i];
			break;
		case 20: // AEAD Encrypted Data Packet [draft RFC 4880bis]
			if (pkt.size() < 4)
				return 0; // error: packet too short
			out.version = pkt[0];
			out.skalgo = (tmcg_openpgp_skalgo_t)pkt[1];
			out.aeadalgo = (tmcg_openpgp_aeadalgo_t)pkt[2];
			out.chunksize = pkt[3];
			if (out.version == 1)
			{
				size_t ivlen = AlgorithmIVLength(out.aeadalgo);
				if (pkt.size() < (4 + ivlen))
					return 0; // error: no IV
				if (ivlen > sizeof(out.iv))
					return 0; // error: IV too long
				for (size_t i = 0; i < ivlen; i++)
					out.iv[i] = pkt[4+i];
				if (out.encdatalen != 0)
					return 0; // error: already seen within context
				tmcg_openpgp_mem_alloc += (pkt.size() - 4 - ivlen);
				if (tmcg_openpgp_mem_alloc > TMCG_OPENPGP_MAX_ALLOC)
				{
					tmcg_openpgp_mem_alloc -= (pkt.size() - 4 - ivlen);
					return 0; // error: memory limit exceeded
				}
				out.encdatalen = pkt.size() - 4 - ivlen;
				if (out.encdatalen == 0)
					return 0; // error: no encrypted session key
				out.encdata = new tmcg_openpgp_byte_t[out.encdatalen];
				for (size_t i = 0; i < out.encdatalen; i++)
					out.encdata[i] = pkt[4+ivlen+i];
			}
			else
				return 0; // error: version not supported
			break;
		default:
			return 0xFE; // warning: unknown packet tag
	}
	return tag;
}

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_packet_ctx_t &out,
	 tmcg_openpgp_octets_t &current_packet,
	 std::vector<gcry_mpi_t> &qual,
	 std::vector<std::string> &capl,
	 std::vector<gcry_mpi_t> &v_i,
	 std::vector< std::vector<gcry_mpi_t> > &c_ik,
	 tmcg_openpgp_notations_t &notations)
{
	std::vector<gcry_mpi_t> x_rvss_qual; // dummy container
	tmcg_openpgp_byte_t ret;

	ret = PacketDecode(in, verbose, out, current_packet, qual,
		x_rvss_qual, capl, v_i, c_ik, notations);
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		gcry_mpi_release(x_rvss_qual[i]); // release allocated mpi
	x_rvss_qual.clear();
	return ret;
}

tmcg_openpgp_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(tmcg_openpgp_octets_t &in, const int verbose,
	 tmcg_openpgp_packet_ctx_t &out,
	 tmcg_openpgp_octets_t &current_packet,
	 tmcg_openpgp_notations_t &notations)
{
	std::vector<gcry_mpi_t> qual; // dummy container
	std::vector<std::string> capl; // dummy container
	std::vector<gcry_mpi_t> v_i; // dummy container
	std::vector< std::vector<gcry_mpi_t> > c_ik; // dummy container
	tmcg_openpgp_byte_t ret;

	ret = PacketDecode(in, verbose, out, current_packet,
		qual, capl, v_i, c_ik, notations);
	for (size_t i = 0; i < qual.size(); i++)
		gcry_mpi_release(qual[i]); // release allocated mpi
	qual.clear();
	capl.clear();
	for (size_t i = 0; i < v_i.size(); i++)
		gcry_mpi_release(v_i[i]); // release allocated mpi
	for (size_t i = 0; i < c_ik.size(); i++)
	{
		for (size_t k = 0; k < c_ik[i].size(); k++)
			gcry_mpi_release(c_ik[i][k]); // release allocated mpi
		c_ik[i].clear();
	}
	c_ik.clear();
	return ret;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease
	(tmcg_openpgp_packet_ctx_t &ctx)
{
	gcry_mpi_release(ctx.me);
	gcry_mpi_release(ctx.gk);
	gcry_mpi_release(ctx.myk);
	gcry_mpi_release(ctx.md);
	gcry_mpi_release(ctx.r);
	gcry_mpi_release(ctx.s);
	gcry_mpi_release(ctx.ecpk);
	gcry_mpi_release(ctx.ecsk);
	gcry_mpi_release(ctx.ecepk);
	gcry_mpi_release(ctx.n);
	gcry_mpi_release(ctx.e);
	gcry_mpi_release(ctx.d);
	gcry_mpi_release(ctx.p);
	gcry_mpi_release(ctx.q);
	gcry_mpi_release(ctx.u);
	gcry_mpi_release(ctx.g);
	gcry_mpi_release(ctx.h);
	gcry_mpi_release(ctx.y);
	gcry_mpi_release(ctx.x);
	gcry_mpi_release(ctx.t);
	gcry_mpi_release(ctx.i);
	gcry_mpi_release(ctx.qualsize);
	gcry_mpi_release(ctx.x_rvss_qualsize);
	gcry_mpi_release(ctx.x_i);
	gcry_mpi_release(ctx.xprime_i);
	if (ctx.hspd != NULL)
	{
		delete [] ctx.hspd;
		if (tmcg_openpgp_mem_alloc >= ctx.hspdlen)
			tmcg_openpgp_mem_alloc -= ctx.hspdlen;
	}
	if (ctx.encdata != NULL)
	{
		delete [] ctx.encdata;
		if (tmcg_openpgp_mem_alloc >= ctx.encdatalen)
			tmcg_openpgp_mem_alloc -= ctx.encdatalen;
	}
	if (ctx.compdata != NULL)
	{
		delete [] ctx.compdata;
		if (tmcg_openpgp_mem_alloc >= ctx.compdatalen)
			tmcg_openpgp_mem_alloc -= ctx.compdatalen;
	}
	if (ctx.data != NULL)
	{
		delete [] ctx.data;
		if (tmcg_openpgp_mem_alloc >= ctx.datalen)
			tmcg_openpgp_mem_alloc -= ctx.datalen;
	}
	if (ctx.uiddata != NULL)
	{
		delete [] ctx.uiddata;
		if (tmcg_openpgp_mem_alloc >= ctx.uiddatalen)
			tmcg_openpgp_mem_alloc -= ctx.uiddatalen;
	}
	if (ctx.uatdata != NULL)
	{
		delete [] ctx.uatdata;
		if (tmcg_openpgp_mem_alloc >= ctx.uatdatalen)
			tmcg_openpgp_mem_alloc -= ctx.uatdatalen;
	}
	if (ctx.embeddedsignature != NULL)
	{
		delete [] ctx.embeddedsignature;
		if (tmcg_openpgp_mem_alloc >= ctx.embeddedsignaturelen)
			tmcg_openpgp_mem_alloc -= ctx.embeddedsignaturelen;
	}
}

// ===========================================================================

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHashV3
	(const std::string &filename, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// For binary document signatures (type 0x00), the document data is
	// hashed directly.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	if (!HashComputeFile(hashalgo, filename, false, hash_input, hash))
		return false;
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHashV3
	(const tmcg_openpgp_octets_t &data, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// For binary document signatures (type 0x00), the document data is
	// hashed directly.
	hash_input.insert(hash_input.end(), data.begin(), data.end());
	// [...]
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash
	(const std::string &filename, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// For binary document signatures (type 0x00), the document data is
	// hashed directly.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	if (!HashComputeFile(hashalgo, filename, false, hash_input, hash))
		return false;
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash
	(const tmcg_openpgp_octets_t &data, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// For binary document signatures (type 0x00), the document data is
	// hashed directly.
	hash_input.insert(hash_input.end(), data.begin(), data.end());
	// [...]
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::TextDocumentHashV3
	(const std::string &filename, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] For text document signatures (type 0x01), the document is
	// canonicalized by converting line endings to <CR><LF>, and the
	// resulting data is hashed.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	if (!HashComputeFile(hashalgo, filename, true, hash_input, hash))
		return false;
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::TextDocumentHashV3
	(const tmcg_openpgp_octets_t &data, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] For text document signatures (type 0x01), the document is
	// canonicalized by converting line endings to <CR><LF>, and the
	// resulting data is hashed.
	tmcg_openpgp_byte_t last = '!';
	for (size_t i = 0; i < data.size(); i++)
	{
		if ((data[i] == '\n') && (last != '\r'))
			hash_input.push_back('\r');
		hash_input.push_back(data[i]);
		last = data[i];
	}
	// [...]
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::TextDocumentHash
	(const std::string &filename, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] For text document signatures (type 0x01), the document is
	// canonicalized by converting line endings to <CR><LF>, and the
	// resulting data is hashed.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	if (!HashComputeFile(hashalgo, filename, true, hash_input, hash))
		return false;
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::TextDocumentHash
	(const tmcg_openpgp_octets_t &data, const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] For text document signatures (type 0x01), the document is
	// canonicalized by converting line endings to <CR><LF>, and the
	// resulting data is hashed.
	tmcg_openpgp_byte_t last = '!';
	for (size_t i = 0; i < data.size(); i++)
	{
		if ((data[i] == '\n') && (last != '\r'))
			hash_input.push_back('\r');
		hash_input.push_back(data[i]);
		last = data[i];
	}
	// [...]
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::StandaloneHashV3
	(const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] This signature is a signature of only its own subpacket contents.
	// It is calculated identically to a signature over a zero-length binary
	// document.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time.
	HashCompute(hashalgo, trailer, hash);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::StandaloneHash
	(const tmcg_openpgp_octets_t &trailer, 
	 const tmcg_openpgp_hashalgo_t hashalgo, tmcg_openpgp_octets_t &hash,
	 tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// All signatures are formed by producing a hash over the signature
	// data, and then using the resulting hash in the signature algorithm.
	// [...] This signature is a signature of only its own subpacket contents.
	// It is calculated identically to a signature over a zero-length binary
	// document.
	// [...]
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	HashCompute(hashalgo, hash_input, hash);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHashV3
	(const tmcg_openpgp_octets_t &key, const std::string &uid, 
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.)
	hash_input.push_back(0x99);
	hash_input.push_back((key.size() >> 8) & 0xFF);
	hash_input.push_back(key.size() & 0xFF);
	hash_input.insert(hash_input.end(), key.begin(), key.end());
	// A certification signature (type 0x10 through 0x13) hashes the User
	// ID being bound to the key into the hash context after the above
	// data. A V3 certification hashes the contents of the User ID or
	// attribute packet packet, without any header.
	for (size_t i = 0; i < uid.length(); i++)
		hash_input.push_back(uid[i]);
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time. [...]
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash
	(const tmcg_openpgp_octets_t &key, const std::string &uid, 
	 const tmcg_openpgp_octets_t &uat, const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;
	size_t uidlen = uid.length();

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.)
	hash_input.push_back(0x99);
	hash_input.push_back((key.size() >> 8) & 0xFF);
	hash_input.push_back(key.size() & 0xFF);
	hash_input.insert(hash_input.end(), key.begin(), key.end());
	// A certification signature (type 0x10 through 0x13) hashes the User
	// ID being bound to the key into the hash context after the above
	// data. [...] A V4 certification hashes the constant 0xB4 for User
	// ID certifications or the constant 0xD1 for User Attribute
	// certifications, followed by a four-octet number giving the length
	// of the User ID or User Attribute data, and then the User ID or 
	// User Attribute data.
	if (uat.size() == 0)
	{
		hash_input.push_back(0xB4);
		hash_input.push_back((uidlen >> 24) & 0xFF);
		hash_input.push_back((uidlen >> 16) & 0xFF);
		hash_input.push_back((uidlen >> 8) & 0xFF);
		hash_input.push_back(uidlen & 0xFF);
		for (size_t i = 0; i < uidlen; i++)
			hash_input.push_back(uid[i]);
	}
	else
	{
		hash_input.push_back(0xD1);
		hash_input.push_back((uat.size() >> 24) & 0xFF);
		hash_input.push_back((uat.size() >> 16) & 0xFF);
		hash_input.push_back((uat.size() >> 8) & 0xFF);
		hash_input.push_back(uat.size() & 0xFF);
		for (size_t i = 0; i < uat.size(); i++)
			hash_input.push_back(uat[i]);
	}
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyHashV3
	(const tmcg_openpgp_octets_t &key,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet). Key revocation signatures (types 0x20 and 0x28)
	// hash only the key being revoked.
	// RFC ERRATA: Primary key revocation signatures (type 0x20) hash only
	// the key being revoked. Subkey revocation signature (type 0x28) hash
	// first the primary key and then the subkey being revoked.
	hash_input.push_back(0x99);
	hash_input.push_back((key.size() >> 8) & 0xFF);
	hash_input.push_back(key.size() & 0xFF);
	hash_input.insert(hash_input.end(), key.begin(), key.end());
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time. [...]
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyHash
	(const tmcg_openpgp_octets_t &key,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet). Key revocation signatures (types 0x20 and 0x28)
	// hash only the key being revoked.
	// RFC ERRATA: Primary key revocation signatures (type 0x20) hash only
	// the key being revoked. Subkey revocation signature (type 0x28) hash
	// first the primary key and then the subkey being revoked.
	hash_input.push_back(0x99);
	hash_input.push_back((key.size() >> 8) & 0xFF);
	hash_input.push_back(key.size() & 0xFF);
	hash_input.insert(hash_input.end(), key.begin(), key.end());
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyHashV3
	(const tmcg_openpgp_octets_t &primary,
	 const tmcg_openpgp_octets_t &subkey,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet).
	// RFC ERRATA: Primary key revocation signatures (type 0x20) hash only
	// the key being revoked. Subkey revocation signature (type 0x28) hash
	// first the primary key and then the subkey being revoked.
	hash_input.push_back(0x99);
	hash_input.push_back((primary.size() >> 8) & 0xFF);
	hash_input.push_back(primary.size() & 0xFF);
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
	hash_input.push_back(0x99);
	hash_input.push_back((subkey.size() >> 8) & 0xFF);
	hash_input.push_back(subkey.size() & 0xFF);
	hash_input.insert(hash_input.end(), subkey.begin(), subkey.end());
	// Once the data body is hashed, then a trailer is hashed. A V3
	// signature hashes five octets of the packet body, starting from the
	// signature type field. This data is the signature type, followed by
	// the four-octet signature time. [...]
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyHash
	(const tmcg_openpgp_octets_t &primary,
	 const tmcg_openpgp_octets_t &subkey,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_hashalgo_t hashalgo, 
	 tmcg_openpgp_octets_t &hash, tmcg_openpgp_octets_t &left)
{
	tmcg_openpgp_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet).
	// RFC ERRATA: Primary key revocation signatures (type 0x20) hash only
	// the key being revoked. Subkey revocation signature (type 0x28) hash
	// first the primary key and then the subkey being revoked.
	hash_input.push_back(0x99);
	hash_input.push_back((primary.size() >> 8) & 0xFF);
	hash_input.push_back(primary.size() & 0xFF);
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
	hash_input.push_back(0x99);
	hash_input.push_back((subkey.size() >> 8) & 0xFF);
	hash_input.push_back(subkey.size() & 0xFF);
	hash_input.insert(hash_input.end(), subkey.begin(), subkey.end());
	// Once the data body is hashed, then a trailer is hashed. [...]
	// A V4 signature hashes the packet body starting from its first
	// field, the version number, through the end of the hashed subpacket
	// data. Thus, the fields hashed are the signature version, the
	// signature type, the public-key algorithm, the hash algorithm,
	// the hashed subpacket length, and the hashed subpacket body.
	hash_input.insert(hash_input.end(), trailer.begin(), trailer.end());
	// V4 signatures also hash in a final trailer of six octets: the
	// version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
	// big-endian number that is the length of the hashed data from the
	// Signature packet (note that this number does not include these final
	// six octets).
	hash_input.push_back(0x04);
	FixedLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; ((i < 2) && (i < hash.size())); i++)
		left.push_back(hash[i]);
}

// ===========================================================================

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_secure_octets_t &seskey,
	 tmcg_openpgp_octets_t &prefix, const bool resync,
	 tmcg_openpgp_octets_t &out)
{
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t chksum = 0;
	// get block size of AES256
	size_t bs = AlgorithmIVLength(TMCG_OPENPGP_SKALGO_AES256);
	// get key size of AES256
	size_t ks = AlgorithmKeyLength(TMCG_OPENPGP_SKALGO_AES256);
	tmcg_openpgp_byte_t pre[bs+2];
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(ks);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	if ((bs == 0) || (ks == 0))
	{
		gcry_free(buf);
		return GPG_ERR_CIPHER_ALGO; // error: bad algorithm
	}
	if (seskey.size() == (ks + 3))
	{
		// reuse the provided session key and calculate checksum
		if (seskey[0] != TMCG_OPENPGP_SKALGO_AES256)
		{
			gcry_free(buf);
			return GPG_ERR_CIPHER_ALGO; // error: algorithm is not AES256
		}
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
		{
			gcry_free(buf);
			return GPG_ERR_CHECKSUM; // error: checksum does not match
		}
	}
	else if (seskey.size() == ks)
	{
		// use the provided session key and append checksum
		seskey.insert(seskey.begin(), TMCG_OPENPGP_SKALGO_AES256);
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		seskey.push_back((chksum >> 8) & 0xFF); // checksum
		seskey.push_back(chksum & 0xFF);
	}
	else
	{
		// generate a random session key and the OpenPGP checksum
		gcry_randomize(buf, ks, GCRY_STRONG_RANDOM);
		seskey.clear();
		seskey.push_back(TMCG_OPENPGP_SKALGO_AES256);
		for (size_t i = 0; i < ks; i++)
		{
			seskey.push_back(buf[i]);
			chksum += buf[i];
		}
		chksum %= 65536;
		seskey.push_back((chksum >> 8) & 0xFF); // checksum
		seskey.push_back(chksum & 0xFF);
	}
	// The data is encrypted in CFB mode, with a CFB shift size equal to
	// the cipher’s block size. The Initial Vector (IV) is specified as
	// all zeros. Instead of using an IV, OpenPGP prefixes a string of
	// length equal to the block size of the cipher plus two to the data
	// before it is encrypted. The first block-size octets (for example,
	// 8 octets for a 64-bit block length) are random, and the following
	// two octets are copies of the last two octets of the IV. For example,
	// in an 8-octet block, octet 9 is a repeat of octet 7, and octet 10
	// is a repeat of octet 8. In a cipher of length 16, octet 17 is a
	// repeat of octet 15 and octet 18 is a repeat of octet 16. As a
	// pedantic clarification, in both these examples, we consider the
	// first octet to be numbered 1.
	// After encrypting the first block-size-plus-two octets, the CFB state
	// is resynchronized. The last block-size octets of ciphertext are
	// passed through the cipher and the block boundary is reset.
	ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB,
		GCRY_CIPHER_ENABLE_SYNC | GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, ks);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	if (prefix.size() != sizeof(pre))
	{
		// generate a random prefix and the checksum
		gcry_randomize(pre, bs, GCRY_STRONG_RANDOM);
		pre[bs] = pre[bs-2];
		pre[bs+1] = pre[bs-1];
		for (size_t i = 0; i < sizeof(pre); i++)
			prefix.push_back(pre[i]);
	}
	else
	{
		// reuse the prefix from input argument
		for (size_t i = 0; i < sizeof(pre); i++)
			pre[i] = prefix[i];
	}
	ret = gcry_cipher_encrypt(hd, pre, sizeof(pre), NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	if (resync)
	{  	
		ret = gcry_cipher_sync(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
	}
	for (size_t i = 0; i < sizeof(pre); i++)
		out.push_back(pre[i]); // encrypted prefix
	for (size_t i = 0; i < in.size(); i++)
	{
		ret = gcry_cipher_encrypt(hd, buf, 1, &in[i], 1);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		out.push_back(buf[0]); // encrypted input
	}
	gcry_free(buf);
	gcry_cipher_close(hd);

	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAEAD
	(const tmcg_openpgp_octets_t &in,
	 tmcg_openpgp_secure_octets_t &seskey,
	 const tmcg_openpgp_skalgo_t skalgo,
	 const tmcg_openpgp_aeadalgo_t aeadalgo,
	 const tmcg_openpgp_byte_t chunksize,
	 const tmcg_openpgp_octets_t &ad,
	 const int verbose,
	 tmcg_openpgp_octets_t &iv,
	 tmcg_openpgp_octets_t &out)
{
	// An AEAD encrypted data packet consists of one or more chunks of data.
	// The plaintext of each chunk is of a size specified using the chunk
	// size octet using the method specified below.
	//
	// The encrypted data consists of the encryption of each chunk of
	// plaintext, followed immediately by the relevant authentication tag.
	// If the last chunk of plaintext is smaller than the chunk size, the
	// ciphertext for that data may be shorter; it is nevertheless followed
	// by a full authentication tag.
	//
	// For each chunk, the AEAD construction is given the Packet Tag in new
	// format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag),
	// version number, cipher algorithm octet, AEAD algorithm octet, chunk
	// size octet, and an eight-octet, big-endian chunk index as additional
	// data. The index of the first chunk is zero. For example, the
	// additional data of the first chunk using EAX and AES-128 with a chunk
	// size of 64 kiByte consists of the octets 0xD4, 0x01, 0x07, 0x01,
	// 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, and 0x00.
	//
	// After the final chunk, the AEAD algorithm is used to produce a final
	// authentication tag encrypting the empty string. This AEAD instance
	// is given the additional data specified above, plus an eight-octet,
	// big-endian value specifying the total number of plaintext octets
	// encrypted. This allows detection of a truncated ciphertext.
	//
	// The chunk size octet specifies the size of chunks using the following
	// formula (in C), where c is the chunk size octet:
	//
	//    chunk_size = ((uint64_t)1 << (c + 6))
	//
	// An implementation MUST support chunk size octets with values from 0
	// to 56. Chunk size octets with other values are reserved for future
	// extensions. Implementations SHOULD NOT create data with a chunk size
	// octet value larger than 21 (128 MiB chunks) to facilitate buffering
	// of not yet authenticated plaintext.
	//
	// A new random initialization vector MUST be used for each message.
	// Failure to do so for each message will lead to a catastrophic failure
	// depending on the used AEAD mode.
	size_t bs = AlgorithmIVLength(skalgo); // get block size of algorithm
	size_t ks = AlgorithmKeyLength(skalgo); // get key size of algorithm
	size_t is = AlgorithmIVLength(aeadalgo); // get IV length of AEAD algorithm
	if ((bs == 0) || (ks == 0) || (is == 0))
		return GPG_ERR_CIPHER_ALGO; // error: bad algorithm
	if (bs != 16)
		return GPG_ERR_NOT_SUPPORTED; // error: other sizes are not supported
	if (chunksize > 21)
		return GPG_ERR_NOT_SUPPORTED; // error: other sizes are not supported 

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(ks);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory
	size_t chksum = 0;
	if (seskey.size() == (ks + 3))
	{
		// use the provided session key and calculate the checksum
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
		{
			gcry_free(buf);
			return GPG_ERR_CHECKSUM; // error: checksum does not match
		}
	}
	else if (seskey.size() == ks)
	{
		// use the provided session key without calculating the checksum
		for (size_t i = 0; i < ks; i++)
			buf[i] = seskey[i]; // copy the session key
	}
	else if (seskey.size() == 0)
	{
		// generate a random session key
		gcry_randomize(buf, ks, GCRY_STRONG_RANDOM);
		for (size_t i = 0; i < ks; i++)
			seskey.push_back(buf[i]);
	}
	else
	{
		gcry_free(buf);
		return GPG_ERR_INV_SESSION_KEY; // error: bad session key provided
	}

	enum gcry_cipher_modes ciphermode;
	switch (aeadalgo)
	{
		case TMCG_OPENPGP_AEADALGO_EAX:
#if GCRYPT_VERSION_NUMBER < 0x010900
			// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
			ciphermode = (enum gcry_cipher_modes)14;
#else
			ciphermode = GCRY_CIPHER_MODE_EAX;
#endif
			break;
		case TMCG_OPENPGP_AEADALGO_OCB:
#if GCRYPT_VERSION_NUMBER < 0x010700
			// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
			ciphermode = (enum gcry_cipher_modes)11;
#else
			ciphermode = GCRY_CIPHER_MODE_OCB;
#endif
			break;
		default:
			return GPG_ERR_INV_CIPHER_MODE; // error: bad AEAD algorithm
	}
	if (verbose > 1)
	{
		std::cerr << "INFO: SymmetricEncryptAEAD called with skalgo = " <<
			(int)skalgo << " cipher mode = " << (int)ciphermode << std::endl;
	}
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	ret = gcry_cipher_open(&hd, AlgorithmSymGCRY(skalgo), ciphermode,
		GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, ks);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	size_t taglen = 0;
#if GCRYPT_VERSION_NUMBER < 0x010700
	// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
	taglen = 16;
#else
	ret = gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
#endif
	if (taglen != 16)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return GPG_ERR_INV_CIPHER_MODE; // error: length is out of specification
	}
	if (verbose > 1)
	{
		std::cerr << "INFO: SymmetricEncryptAEAD |in| = " << in.size() <<
			" and |ad| = " << ad.size() << std::endl;
	}
	// initially set nonce (starting IV) for AEAD algorithm
	unsigned char ivbuf[16];
	memset(ivbuf, 0, sizeof(ivbuf));
	gcry_randomize(ivbuf, is, GCRY_STRONG_RANDOM);
	if (verbose > 2)
		std::cerr << "INFO: SymmetricEncryptAEAD nonce = " << std::hex;
	for (size_t i = 0; ((i < is) && (i < sizeof(ivbuf))); i++)
	{
		iv.push_back(ivbuf[i]);
		if (verbose > 2)
			std::cerr << (int)ivbuf[i] << " ";
	}
	if (verbose > 2)
		std::cerr << std::dec << std::endl;
	if (ad.size() == 4) // identifies an AEAD-encrypted SKESK packet (version 5)
	{
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		unsigned char adbuf[4];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD ad = " << std::hex;
		for (size_t i = 0; i < ad.size(); i++)
		{
			adbuf[i] = ad[i]; // set additional data
			if (verbose > 2)
				std::cerr << (int)ad[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_authenticate(hd, adbuf, ad.size());
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		if (in.size() < 1)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		size_t len = in.size();
		unsigned char inbuf[len], outbuf[len], tag[taglen];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD in = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			inbuf[i] = in[i];
			if (verbose > 2)
				std::cerr << (int)inbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_encrypt(hd, outbuf, len, inbuf, len);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_encrypt() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD out = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			out.push_back(outbuf[i]);
			if (verbose > 2)
				std::cerr << (int)outbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_gettag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_gettag() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		for (size_t i = 0; i < taglen; i++)
			out.push_back(tag[i]);
	}
	else
	{
		uint64_t chunkdim = ((uint64_t)1 << (chunksize + 6));
		uint64_t chunks = (((uint64_t)in.size() - 1) / chunkdim);
		if (verbose > 1)
		{
			std::cerr << "INFO: SymmetricEncryptAEAD chunkdim = " << chunkdim <<
				" and chunks = " << chunks << std::endl;
		}
		unsigned char adbuf[21];
		memset(adbuf, 0, sizeof(adbuf));
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD ad = " << std::hex;
		for (size_t i = 0; i < ad.size(); i++)
		{
			adbuf[i] = ad[i]; // initially set additional data
			if (verbose > 2)
				std::cerr << (int)ad[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		uint64_t chunkidx = 0, nbytes = 0;
		for (uint64_t c = 0; c < chunks; c++, chunkidx++)
		{
			if (verbose > 2)
			{
				std::cerr << "INFO: SymmetricEncryptAEAD on chunk #" <<
					chunkidx << " with nbytes = " << nbytes << std::endl;
			}
			switch (aeadalgo)
			{
				// The nonce for EAX mode is computed by treating the starting
				// initialization vector as a 16-octet, big-endian value and
				// exclusive-oring the low eight octets of it with the chunk
				// index.
				case TMCG_OPENPGP_AEADALGO_EAX:
					ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
					ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
 					ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
					ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
					ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
					ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
					ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
					ivbuf[15] ^= (chunkidx & 0xFF);
					break;
				// The nonce for OCB mode is computed by the exclusive-oring
				// of the initialization vector as a 15-octet, big endian value,
				// against the chunk index.
				case TMCG_OPENPGP_AEADALGO_OCB:
					ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
					ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
 					ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
					ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
					ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
					ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
					ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
					ivbuf[14] ^= (chunkidx & 0xFF);
					break;
				default:
					break; // should never happen
			}
			ret = gcry_cipher_setiv(hd, ivbuf, is);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
			adbuf[5] = ((chunkidx >> 56) & 0xFF);
			adbuf[6] = ((chunkidx >> 48) & 0xFF);
 			adbuf[7] = ((chunkidx >> 40) & 0xFF);
			adbuf[8] = ((chunkidx >> 32) & 0xFF);
			adbuf[9] = ((chunkidx >> 24) & 0xFF);
			adbuf[10] = ((chunkidx >> 16) & 0xFF);
			adbuf[11] = ((chunkidx >> 8) & 0xFF);
			adbuf[12] = (chunkidx & 0xFF);
			ret = gcry_cipher_authenticate(hd, adbuf, 13);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
			ret = gcry_cipher_final(hd);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
#endif
			if (in.size() < (nbytes + chunkdim))
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return GPG_ERR_TOO_SHORT; // error: input too short
			}
			unsigned char inbuf[chunkdim], outbuf[chunkdim], tag[taglen];
			for (uint64_t i = 0; i < chunkdim; i++)
				inbuf[i] = in[nbytes+i];
			ret = gcry_cipher_encrypt(hd, outbuf, chunkdim, inbuf, chunkdim);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				if (verbose > 2)
				{
					std::cerr << "ERROR: gcry_cipher_encrypt() failed" <<
						" (rc = " << gcry_err_code(ret) <<
						", str = " << gcry_strerror(ret) << ")" << std::endl;
				}
				return ret;
			}
			if (verbose > 2)
				std::cerr << "INFO: SymmetricEncryptAEAD out = " << std::hex;
			for (size_t i = 0; i < chunkdim; i++)
			{
				out.push_back(outbuf[i]);
				if (verbose > 2)
					std::cerr << (int)outbuf[i] << " ";
			}
			if (verbose > 2)
				std::cerr << std::dec << std::endl;
			ret = gcry_cipher_gettag(hd, tag, taglen);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				if (verbose > 2)
				{
					std::cerr << "ERROR: gcry_cipher_gettag() failed" <<
						" (rc = " << gcry_err_code(ret) <<
						", str = " << gcry_strerror(ret) << ")" << std::endl;
				}
				return ret;
			}
			if (verbose > 2)
				std::cerr << "INFO: SymmetricEncryptAEAD tag = " << std::hex;
			for (size_t i = 0; i < taglen; i++)
			{
				out.push_back(tag[i]);
				if (verbose > 2)
					std::cerr << (int)tag[i] << " ";
			}
			if (verbose > 2)
				std::cerr << std::dec << std::endl;
			nbytes += chunkdim;
		}
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricEncryptAEAD on final chunk #" <<
				chunkidx << " with nbytes = " << nbytes << std::endl;
		}
		switch (aeadalgo)
		{
			case TMCG_OPENPGP_AEADALGO_EAX:
				ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[15] ^= (chunkidx & 0xFF);
				break;
			case TMCG_OPENPGP_AEADALGO_OCB:
				ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[14] ^= (chunkidx & 0xFF);
				break;
			default:
				break; // should never happen
		}
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		adbuf[5] = ((chunkidx >> 56) & 0xFF);
		adbuf[6] = ((chunkidx >> 48) & 0xFF);
		adbuf[7] = ((chunkidx >> 40) & 0xFF);
		adbuf[8] = ((chunkidx >> 32) & 0xFF);
		adbuf[9] = ((chunkidx >> 24) & 0xFF);
		adbuf[10] = ((chunkidx >> 16) & 0xFF);
		adbuf[11] = ((chunkidx >> 8) & 0xFF);
		adbuf[12] = (chunkidx & 0xFF);
		ret = gcry_cipher_authenticate(hd, adbuf, 13);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		if (in.size() <= nbytes)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		size_t len = in.size() - nbytes;
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricEncryptAEAD len = " << len <<
				std::endl;
		}
		unsigned char inbuf[len], outbuf[len], tag[taglen];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD in = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			inbuf[i] = in[nbytes+i];
			if (verbose > 2)
				std::cerr << (int)inbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_encrypt(hd, outbuf, len, inbuf, len);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_encrypt() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD out = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			out.push_back(outbuf[i]);
			if (verbose > 2)
				std::cerr << (int)outbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_gettag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_gettag() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			out.push_back(tag[i]);
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		nbytes += len;

		// now create the final authentication tag
		uint64_t totalbytes = (chunks * chunkdim) + len;
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricEncryptAEAD totalbytes = " <<
				totalbytes << std::endl;
		}
		chunkidx++;
		switch (aeadalgo)
		{
			case TMCG_OPENPGP_AEADALGO_EAX:
				ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[15] ^= (chunkidx & 0xFF);
				break;
			case TMCG_OPENPGP_AEADALGO_OCB:
				ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[14] ^= (chunkidx & 0xFF);
				break;
			default:
				break; // should never happen
		}
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		adbuf[5] = ((chunkidx >> 56) & 0xFF);
		adbuf[6] = ((chunkidx >> 48) & 0xFF);
		adbuf[7] = ((chunkidx >> 40) & 0xFF);
		adbuf[8] = ((chunkidx >> 32) & 0xFF);
		adbuf[9] = ((chunkidx >> 24) & 0xFF);
		adbuf[10] = ((chunkidx >> 16) & 0xFF);
		adbuf[11] = ((chunkidx >> 8) & 0xFF);
		adbuf[12] = (chunkidx & 0xFF);
		adbuf[13] = ((totalbytes >> 56) & 0xFF);
		adbuf[14] = ((totalbytes >> 48) & 0xFF);
		adbuf[15] = ((totalbytes >> 40) & 0xFF);
		adbuf[16] = ((totalbytes >> 32) & 0xFF);
		adbuf[17] = ((totalbytes >> 24) & 0xFF);
		adbuf[18] = ((totalbytes >> 16) & 0xFF);
		adbuf[19] = ((totalbytes >> 8) & 0xFF);
		adbuf[20] = (totalbytes & 0xFF);
		ret = gcry_cipher_authenticate(hd, adbuf, sizeof(adbuf));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd); // tell decrypt that it's the final call
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		ret = gcry_cipher_encrypt(hd, outbuf, 0, NULL, 0); // empty string
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_encrypt() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		ret = gcry_cipher_gettag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricEncryptAEAD final tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			out.push_back(tag[i]);
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
	}
	gcry_free(buf);
	gcry_cipher_close(hd);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_secure_octets_t &seskey,
	 tmcg_openpgp_octets_t &prefix, const bool resync,
	 const tmcg_openpgp_skalgo_t algo, tmcg_openpgp_octets_t &out)
{
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t chksum = 0;
	size_t bs = AlgorithmIVLength(algo); // get block size of algorithm
	size_t ks = AlgorithmKeyLength(algo); // get key size of algorithm
	if ((bs == 0) || (ks == 0))
		return GPG_ERR_CIPHER_ALGO; // error: bad algorithm
	if (seskey.size() == 0)
		return GPG_ERR_INV_SESSION_KEY; // error: no session key provided
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(ks);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.

	if (seskey.size() == (ks + 3))
	{
		// use the provided session key and calculate the checksum
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
		{
			gcry_free(buf);
			return GPG_ERR_CHECKSUM; // error: checksum does not match
		}
	}
	else if (seskey.size() == ks)
	{
		// use the provided session key and append the checksum
		seskey.insert(seskey.begin(), algo); // specified algorithm
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		seskey.push_back((chksum >> 8) & 0xFF); // append checksum
		seskey.push_back(chksum & 0xFF);
	}
	else
	{
		gcry_free(buf);
		return GPG_ERR_INV_SESSION_KEY; // error: bad session key provided
	}
	if (in.size() < (bs + 2))
	{
		gcry_free(buf);
		return GPG_ERR_TOO_SHORT; // error: input too short (no encrypt. prefix)
	}
	// The data is encrypted in CFB mode, with a CFB shift size equal to
	// the cipher’s block size. The Initial Vector (IV) is specified as
	// all zeros. Instead of using an IV, OpenPGP prefixes a string of
	// length equal to the block size of the cipher plus two to the data
	// before it is encrypted. The first block-size octets (for example,
	// 8 octets for a 64-bit block length) are random, and the following
	// two octets are copies of the last two octets of the IV. For example,
	// in an 8-octet block, octet 9 is a repeat of octet 7, and octet 10
	// is a repeat of octet 8. In a cipher of length 16, octet 17 is a
	// repeat of octet 15 and octet 18 is a repeat of octet 16. As a
	// pedantic clarification, in both these examples, we consider the
	// first octet to be numbered 1.
	// After encrypting the first block-size-plus-two octets, the CFB state
	// is resynchronized. The last block-size octets of ciphertext are
	// passed through the cipher and the block boundary is reset.
	ret = gcry_cipher_open(&hd, AlgorithmSymGCRY(algo), GCRY_CIPHER_MODE_CFB,
		GCRY_CIPHER_ENABLE_SYNC | GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, ks);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < (bs + 2); i++)
	{
		ret = gcry_cipher_decrypt(hd, buf, 1, &in[i], 1);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		prefix.push_back(buf[0]); // decrypted prefix
	}
	if ((prefix[bs] != prefix[bs-2]) || (prefix[bs+1] != prefix[bs-1]))
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return GPG_ERR_INV_SESSION_KEY; // error: prefix corrupt
	}
	if (resync)
	{  	
		ret = gcry_cipher_sync(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
	}
	for (size_t i = 0; i < (in.size() - (bs + 2)); i++)
	{
		ret = gcry_cipher_decrypt(hd, buf, 1, &in[bs+2+i], 1);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		out.push_back(buf[0]); // decrypted input
	}
	gcry_free(buf);
	gcry_cipher_close(hd);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecryptAES256
	(const tmcg_openpgp_octets_t &in, tmcg_openpgp_secure_octets_t &seskey,
	 tmcg_openpgp_octets_t &prefix, const bool resync,
	 tmcg_openpgp_octets_t &out)
{
	return CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt(in, 
		seskey, prefix, resync, TMCG_OPENPGP_SKALGO_AES256, out);
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecryptAEAD
	(const tmcg_openpgp_octets_t &in,
	 const tmcg_openpgp_secure_octets_t &seskey,
	 const tmcg_openpgp_skalgo_t skalgo,
	 const tmcg_openpgp_aeadalgo_t aeadalgo,
	 const tmcg_openpgp_byte_t chunksize,
	 const tmcg_openpgp_octets_t &iv,
	 const tmcg_openpgp_octets_t &ad,
	 const int verbose,
	 tmcg_openpgp_octets_t &out)
{
	// An AEAD encrypted data packet consists of one or more chunks of data.
	// The plaintext of each chunk is of a size specified using the chunk
	// size octet using the method specified below.
	//
	// The encrypted data consists of the encryption of each chunk of
	// plaintext, followed immediately by the relevant authentication tag.
	// If the last chunk of plaintext is smaller than the chunk size, the
	// ciphertext for that data may be shorter; it is nevertheless followed
	// by a full authentication tag.
	//
	// For each chunk, the AEAD construction is given the Packet Tag in new
	// format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag),
	// version number, cipher algorithm octet, AEAD algorithm octet, chunk
	// size octet, and an eight-octet, big-endian chunk index as additional
	// data. The index of the first chunk is zero. For example, the
	// additional data of the first chunk using EAX and AES-128 with a chunk
	// size of 64 kiByte consists of the octets 0xD4, 0x01, 0x07, 0x01,
	// 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, and 0x00.
	//
	// After the final chunk, the AEAD algorithm is used to produce a final
	// authentication tag encrypting the empty string. This AEAD instance
	// is given the additional data specified above, plus an eight-octet,
	// big-endian value specifying the total number of plaintext octets
	// encrypted. This allows detection of a truncated ciphertext.
	//
	// The chunk size octet specifies the size of chunks using the following
	// formula (in C), where c is the chunk size octet:
	//
	//    chunk_size = ((uint64_t)1 << (c + 6))
	//
	// An implementation MUST support chunk size octets with values from 0
	// to 56. Chunk size octets with other values are reserved for future
	// extensions. Implementations SHOULD NOT create data with a chunk size
	// octet value larger than 21 (128 MiB chunks) to facilitate buffering
	// of not yet authenticated plaintext.
	size_t bs = AlgorithmIVLength(skalgo); // get block size of algorithm
	size_t ks = AlgorithmKeyLength(skalgo); // get key size of algorithm
	size_t is = AlgorithmIVLength(aeadalgo); // get IV length of AEAD algorithm
	if ((bs == 0) || (ks == 0))
		return GPG_ERR_CIPHER_ALGO; // error: bad algorithm
	if (seskey.size() == 0)
		return GPG_ERR_INV_SESSION_KEY; // error: no session key provided
	if (bs != 16)
		return GPG_ERR_CIPHER_ALGO; // error: other block sizes are not permitted
	if ((is == 0) || (is > iv.size()))
		return GPG_ERR_INV_PACKET; // error: bad algorithm or IV too short
	if (chunksize > 56)
		return GPG_ERR_INV_PACKET; // error: chunk size out of specification
	if (chunksize > 21)
		return GPG_ERR_NOT_SUPPORTED; // error: other sizes are not supported 

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(ks);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory
	size_t chksum = 0;
	if (seskey.size() == (ks + 3))
	{
		// use the provided session key and calculate the checksum
		for (size_t i = 0; i < ks; i++)
		{
			buf[i] = seskey[1+i]; // copy the session key
			chksum += buf[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
		{
			gcry_free(buf);
			return GPG_ERR_CHECKSUM; // error: checksum does not match
		}
	}
	else if (seskey.size() == ks)
	{
		// use the provided session key without calculating the checksum
		for (size_t i = 0; i < ks; i++)
			buf[i] = seskey[i]; // copy the session key
	}
	else
	{
		gcry_free(buf);
		return GPG_ERR_INV_SESSION_KEY; // error: bad session key provided
	}

	enum gcry_cipher_modes ciphermode;
	switch (aeadalgo)
	{
		case TMCG_OPENPGP_AEADALGO_EAX:
#if GCRYPT_VERSION_NUMBER < 0x010900
			// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
			ciphermode = (enum gcry_cipher_modes)14;
#else
			ciphermode = GCRY_CIPHER_MODE_EAX;
#endif
			break;
		case TMCG_OPENPGP_AEADALGO_OCB:
#if GCRYPT_VERSION_NUMBER < 0x010700
			// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
			ciphermode = (enum gcry_cipher_modes)11;
#else
			ciphermode = GCRY_CIPHER_MODE_OCB;
#endif
			break;
		default:
			return GPG_ERR_INV_CIPHER_MODE; // error: bad AEAD algorithm
	}
	if (verbose > 1)
	{
		std::cerr << "INFO: SymmetricDecryptAEAD called with skalgo = " <<
			(int)skalgo << " cipher mode = " << (int)ciphermode << std::endl;
	}
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	ret = gcry_cipher_open(&hd, AlgorithmSymGCRY(skalgo), ciphermode,
		GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, ks);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	size_t taglen = 0;
#if GCRYPT_VERSION_NUMBER < 0x010700
	// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
	taglen = 16;
#else
	ret = gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
#endif
	if (taglen != 16)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return GPG_ERR_INV_CIPHER_MODE; // error: length is out of specification
	}
	if (verbose > 1)
	{
		std::cerr << "INFO: SymmetricDecryptAEAD |in| = " << in.size() <<
			" and |ad| = " << ad.size() << std::endl;
	}
	// initially set nonce (starting IV) for AEAD algorithm
	unsigned char ivbuf[16];
	memset(ivbuf, 0, sizeof(ivbuf));
	if (verbose > 2)
		std::cerr << "INFO: SymmetricDecryptAEAD nonce = " << std::hex;
	for (size_t i = 0; ((i < is) && (i < sizeof(ivbuf))); i++)
	{
		ivbuf[i] = iv[i];
		if (verbose > 2)
			std::cerr << (int)ivbuf[i] << " ";
	}
	if (verbose > 2)
		std::cerr << std::dec << std::endl;
	if (ad.size() == 4) // identifies an AEAD-encrypted SKESK packet (version 5)
	{
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		unsigned char adbuf[4];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD ad = " << std::hex;
		for (size_t i = 0; i < ad.size(); i++)
		{
			adbuf[i] = ad[i]; // set additional data
			if (verbose > 2)
				std::cerr << (int)ad[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_authenticate(hd, adbuf, ad.size());
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		if (in.size() < (1 + taglen))
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		size_t len = in.size() - taglen;
		unsigned char inbuf[len], outbuf[len], tag[taglen];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD in = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			inbuf[i] = in[i];
			if (verbose > 2)
				std::cerr << (int)inbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			tag[i] = in[len+i];
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_decrypt(hd, outbuf, len, inbuf, len);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		ret = gcry_cipher_checktag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		for (size_t i = 0; i < len; i++)
			out.push_back(outbuf[i]);
	}
	else
	{
		if (in.size() < (1 + taglen + taglen))
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		uint64_t chunkdim = ((uint64_t)1 << (chunksize + 6));
		uint64_t chunks = ((uint64_t)in.size()-1-taglen) / (chunkdim + taglen);
		if (verbose > 1)
		{
			std::cerr << "INFO: SymmetricDecryptAEAD chunkdim = " << chunkdim <<
				" and chunks = " << chunks << std::endl;
		}
		unsigned char adbuf[21];
		memset(adbuf, 0, sizeof(adbuf));
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD ad = " << std::hex;
		for (size_t i = 0; i < ad.size(); i++)
		{
			adbuf[i] = ad[i]; // initially set additional data
			if (verbose > 2)
				std::cerr << (int)ad[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		uint64_t chunkidx = 0, nbytes = 0;
		for (uint64_t c = 0; c < chunks; c++, chunkidx++)
		{
			if (verbose > 2)
			{
				std::cerr << "INFO: SymmetricDecryptAEAD on chunk #" <<
					chunkidx << " with nbytes = " << nbytes << std::endl;
			}
			switch (aeadalgo)
			{
				// The nonce for EAX mode is computed by treating the starting
				// initialization vector as a 16-octet, big-endian value and
				// exclusive-oring the low eight octets of it with the chunk
				// index.
				case TMCG_OPENPGP_AEADALGO_EAX:
					ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
					ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
 					ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
					ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
					ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
					ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
					ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
					ivbuf[15] ^= (chunkidx & 0xFF);
					break;
				// The nonce for OCB mode is computed by the exclusive-oring
				// of the initialization vector as a 15-octet, big endian value,
				// against the chunk index.
				case TMCG_OPENPGP_AEADALGO_OCB:
					ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
					ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
 					ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
					ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
					ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
					ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
					ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
					ivbuf[14] ^= (chunkidx & 0xFF);
					break;
				default:
					break; // should never happen
			}
			ret = gcry_cipher_setiv(hd, ivbuf, is);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
			adbuf[5] = ((chunkidx >> 56) & 0xFF);
			adbuf[6] = ((chunkidx >> 48) & 0xFF);
 			adbuf[7] = ((chunkidx >> 40) & 0xFF);
			adbuf[8] = ((chunkidx >> 32) & 0xFF);
			adbuf[9] = ((chunkidx >> 24) & 0xFF);
			adbuf[10] = ((chunkidx >> 16) & 0xFF);
			adbuf[11] = ((chunkidx >> 8) & 0xFF);
			adbuf[12] = (chunkidx & 0xFF);
			ret = gcry_cipher_authenticate(hd, adbuf, 13);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
			ret = gcry_cipher_final(hd);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
#endif
			if (in.size() < (nbytes + chunkdim + taglen))
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return GPG_ERR_TOO_SHORT; // error: input too short
			}
			unsigned char inbuf[chunkdim], outbuf[chunkdim], tag[taglen];
			for (uint64_t i = 0; i < chunkdim; i++)
				inbuf[i] = in[nbytes+i];
			for (size_t i = 0; i < taglen; i++)
				tag[i] = in[nbytes+chunkdim+i];
			ret = gcry_cipher_decrypt(hd, outbuf, chunkdim, inbuf, chunkdim);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
			ret = gcry_cipher_checktag(hd, tag, taglen);
			if (ret)
			{
				gcry_free(buf);
				gcry_cipher_close(hd);
				return ret;
			}
			for (size_t i = 0; i < chunkdim; i++)
				out.push_back(outbuf[i]);
			nbytes += (chunkdim + taglen);
		}
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricDecryptAEAD on final chunk #" <<
				chunkidx << " with nbytes = " << nbytes << std::endl;
		}
		switch (aeadalgo)
		{
			case TMCG_OPENPGP_AEADALGO_EAX:
				ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[15] ^= (chunkidx & 0xFF);
				break;
			case TMCG_OPENPGP_AEADALGO_OCB:
				ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[14] ^= (chunkidx & 0xFF);
				break;
			default:
				break; // should never happen
		}
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		adbuf[5] = ((chunkidx >> 56) & 0xFF);
		adbuf[6] = ((chunkidx >> 48) & 0xFF);
		adbuf[7] = ((chunkidx >> 40) & 0xFF);
		adbuf[8] = ((chunkidx >> 32) & 0xFF);
		adbuf[9] = ((chunkidx >> 24) & 0xFF);
		adbuf[10] = ((chunkidx >> 16) & 0xFF);
		adbuf[11] = ((chunkidx >> 8) & 0xFF);
		adbuf[12] = (chunkidx & 0xFF);
		ret = gcry_cipher_authenticate(hd, adbuf, 13);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		if (in.size() < (nbytes + taglen + taglen))
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		size_t len = in.size() - (nbytes + taglen + taglen);
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricDecryptAEAD len = " << len <<
				std::endl;
		}
		unsigned char inbuf[len], outbuf[len], tag[taglen];
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD in = " << std::hex;
		for (size_t i = 0; i < len; i++)
		{
			inbuf[i] = in[nbytes+i];
			if (verbose > 2)
				std::cerr << (int)inbuf[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			tag[i] = in[nbytes+len+i];
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_decrypt(hd, outbuf, len, inbuf, len);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_decrypt() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		ret = gcry_cipher_checktag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		for (size_t i = 0; i < len; i++)
			out.push_back(outbuf[i]);
		nbytes += (len + taglen);

		// now check the final authentication tag
		uint64_t totalbytes = (chunks * chunkdim) + len;
		if (verbose > 2)
		{
			std::cerr << "INFO: SymmetricDecryptAEAD totalbytes = " <<
				totalbytes << std::endl;
		}
		chunkidx++;
		switch (aeadalgo)
		{
			case TMCG_OPENPGP_AEADALGO_EAX:
				ivbuf[8] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[14] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[15] ^= (chunkidx & 0xFF);
				break;
			case TMCG_OPENPGP_AEADALGO_OCB:
				ivbuf[7] ^= ((chunkidx >> 56) & 0xFF);
				ivbuf[8] ^= ((chunkidx >> 48) & 0xFF);
				ivbuf[9] ^= ((chunkidx >> 40) & 0xFF);
				ivbuf[10] ^= ((chunkidx >> 32) & 0xFF);
				ivbuf[11] ^= ((chunkidx >> 24) & 0xFF);
				ivbuf[12] ^= ((chunkidx >> 16) & 0xFF);
				ivbuf[13] ^= ((chunkidx >> 8) & 0xFF);
				ivbuf[14] ^= (chunkidx & 0xFF);
				break;
			default:
				break; // should never happen
		}
		ret = gcry_cipher_setiv(hd, ivbuf, is);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
		adbuf[5] = ((chunkidx >> 56) & 0xFF);
		adbuf[6] = ((chunkidx >> 48) & 0xFF);
		adbuf[7] = ((chunkidx >> 40) & 0xFF);
		adbuf[8] = ((chunkidx >> 32) & 0xFF);
		adbuf[9] = ((chunkidx >> 24) & 0xFF);
		adbuf[10] = ((chunkidx >> 16) & 0xFF);
		adbuf[11] = ((chunkidx >> 8) & 0xFF);
		adbuf[12] = (chunkidx & 0xFF);
		adbuf[13] = ((totalbytes >> 56) & 0xFF);
		adbuf[14] = ((totalbytes >> 48) & 0xFF);
		adbuf[15] = ((totalbytes >> 40) & 0xFF);
		adbuf[16] = ((totalbytes >> 32) & 0xFF);
		adbuf[17] = ((totalbytes >> 24) & 0xFF);
		adbuf[18] = ((totalbytes >> 16) & 0xFF);
		adbuf[19] = ((totalbytes >> 8) & 0xFF);
		adbuf[20] = (totalbytes & 0xFF);
		ret = gcry_cipher_authenticate(hd, adbuf, sizeof(adbuf));
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#if GCRYPT_VERSION_NUMBER < 0x010700
		// FIXME: remove, if libgcrypt >= 1.7.0 required by configure.ac
#else
		ret = gcry_cipher_final(hd); // tell decrypt that it's the final call
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
#endif
		if (in.size() < (nbytes + taglen))
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return GPG_ERR_TOO_SHORT; // error: input too short
		}
		if (verbose > 2)
			std::cerr << "INFO: SymmetricDecryptAEAD final tag = " << std::hex;
		for (size_t i = 0; i < taglen; i++)
		{
			tag[i] = in[nbytes+i];
			if (verbose > 2)
				std::cerr << (int)tag[i] << " ";
		}
		if (verbose > 2)
			std::cerr << std::dec << std::endl;
		ret = gcry_cipher_decrypt(hd, outbuf, 0, NULL, 0); // empty string
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			if (verbose > 2)
			{
				std::cerr << "ERROR: gcry_cipher_decrypt() failed" <<
					" (rc = " << gcry_err_code(ret) <<
					", str = " << gcry_strerror(ret) << ")" << std::endl;
			}
			return ret;
		}
		ret = gcry_cipher_checktag(hd, tag, taglen);
		if (ret)
		{
			gcry_free(buf);
			gcry_cipher_close(hd);
			return ret;
		}
	}
	gcry_free(buf);
	gcry_cipher_close(hd);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal
	(const tmcg_openpgp_secure_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &gk, gcry_mpi_t &myk)
{
	gcry_sexp_t encryption, data;
	gcry_error_t ret;
	size_t bufsize = 2048, buflen = 0, erroff;
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(bufsize);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	memset(buf, 0, bufsize);
	for (size_t i = 0; ((i < in.size()) && (i < bufsize)); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&data, &erroff, "(data (flags pkcs1) (value %b))",
		(int)buflen, buf);
	gcry_free(buf);
	if (ret)
		return ret;
	ret = gcry_pk_encrypt(&encryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	gcry_mpi_release(gk); // release already allocated mpi's
	gcry_mpi_release(myk);
	ret = gcry_sexp_extract_param(encryption, NULL, "ab", &gk, &myk, NULL);
	gcry_sexp_release(encryption);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptElgamal
	(const gcry_mpi_t gk, const gcry_mpi_t myk, const gcry_sexp_t key, 
	 tmcg_openpgp_secure_octets_t &out)
{
	const char *buf;
	gcry_sexp_t decryption, data;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	ret = gcry_sexp_build(&data, &erroff,
		"(enc-val (flags pkcs1) (elg (a %M) (b %M)))", gk, myk);
	if (ret)
		return ret;
	ret = gcry_pk_decrypt(&decryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	buf = gcry_sexp_nth_data(decryption, 1, &buflen);
	if (buf == NULL)
	{
		gcry_sexp_release(decryption);
		return GPG_ERR_VALUE_NOT_FOUND;
	}
	for (size_t i = 0; i < buflen; i++)
		out.push_back(buf[i]);
	gcry_sexp_release(decryption);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptRSA
	(const tmcg_openpgp_secure_octets_t &in, const gcry_sexp_t key,
	 gcry_mpi_t &me)
{
	gcry_sexp_t encryption, data;
	gcry_error_t ret;
	size_t bufsize = 2048, buflen = 0, erroff;
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(bufsize);
	if (buf == NULL)
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	memset(buf, 0, bufsize);
	for (size_t i = 0; ((i < in.size()) && (i < bufsize)); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&data, &erroff, "(data (flags pkcs1) (value %b))",
		(int)buflen, buf);
	gcry_free(buf);
	if (ret)
		return ret;
	ret = gcry_pk_encrypt(&encryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	gcry_mpi_release(me); // release already allocated mpi's
	ret = gcry_sexp_extract_param(encryption, NULL, "a", &me, NULL);
	gcry_sexp_release(encryption);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptRSA
	(const gcry_mpi_t me, const gcry_sexp_t key, 
	 tmcg_openpgp_secure_octets_t &out)
{
	const char *buf;
	gcry_sexp_t decryption, data;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	ret = gcry_sexp_build(&data, &erroff,
		"(enc-val (flags pkcs1) (rsa (a %M)))", me);
	if (ret)
		return ret;
	ret = gcry_pk_decrypt(&decryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	buf = gcry_sexp_nth_data(decryption, 1, &buflen);
	if (buf == NULL)
	{
		gcry_sexp_release(decryption);
		return GPG_ERR_VALUE_NOT_FOUND;
	}
	for (size_t i = 0; i < buflen; i++)
		out.push_back(buf[i]);
	gcry_sexp_release(decryption);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptECDH
	(const tmcg_openpgp_secure_octets_t &in, const gcry_sexp_t key,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 const tmcg_openpgp_skalgo_t skalgo, const std::string &curve,
	 const tmcg_openpgp_octets_t &rcpfpr, gcry_mpi_t &ecepk,
	 size_t &rkwlen, tmcg_openpgp_byte_t rkw[256])
{
	// generate an ephemeral key pair {v, V=vG} [RFC 6637]
	unsigned int curvebits = 0;
	const char *curvename = gcry_pk_get_curve(key, 0, &curvebits);
	if (curvename == NULL)
		return GPG_ERR_BAD_DATA;
	gcry_mpi_t v;
	v = gcry_mpi_snew(1024);
	gcry_mpi_randomize(v, curvebits - 1, GCRY_STRONG_RANDOM);
	// compute V = vG and the shared point S = vR [RFC 6637]
	gcry_sexp_t encryption, data;
	gcry_mpi_t S;
	gcry_error_t ret;
	ret = gcry_sexp_build(&data, NULL, "%m", v);
	gcry_mpi_release(v);
	if (ret)
		return ret;
	ret = gcry_pk_encrypt(&encryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	ret = gcry_sexp_extract_param(encryption, NULL, "s", &S, NULL);
	if (ret)
	{
		gcry_sexp_release(encryption);
		return ret;
	}
	gcry_mpi_release(ecepk); // release already allocated mpi
	ret = gcry_sexp_extract_param(encryption, NULL, "e", &ecepk, NULL);
	gcry_sexp_release(encryption);
	if (ret)
	{
		gcry_mpi_release(S);
		return ret;
	}

	size_t bufsize = 1024, buflen = 0;
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(bufsize);
	if (buf == NULL)
	{
		gcry_mpi_release(S);
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory
	}
	ret = gcry_mpi_print(GCRYMPI_FMT_USG, buf, bufsize, &buflen, S);
	gcry_mpi_release(S);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	// compute Z = KDF(S, Z_len, Param) [RFC 6637]
	tmcg_openpgp_secure_octets_t ZB, Z;
	if (buf[0] == 0x04)
	{
		for (size_t i = 0; i < ((buflen - 1) / 2); i++)
			ZB.push_back(buf[1+i]);
	}
	else if (buf[0] == 0x40)
	{
		for (size_t i = 0; i < (buflen - 1); i++)
			ZB.push_back(buf[1+i]);
	}
	else
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	ret = KDFCompute(hashalgo, skalgo, ZB, curve, rcpfpr, Z);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	memset(buf, 0, bufsize);
	for (size_t i = 0; ((i < Z.size()) && (i < bufsize)); i++)
		buf[i] = Z[i];
	// compute of C = AESKeyWrap(Z, m) as per [RFC 3394]
	if (Z.size() < AlgorithmHashLength(hashalgo))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	if (Z.size() < gcry_cipher_get_algo_keylen(skalgo))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	if ((hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
		(hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
		(hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_PUBKEY;
	}
	if ((skalgo != TMCG_OPENPGP_SKALGO_AES128) &&
		(skalgo != TMCG_OPENPGP_SKALGO_AES192) &&
		(skalgo != TMCG_OPENPGP_SKALGO_AES256))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_PUBKEY;
	}
	gcry_cipher_hd_t hd;
	ret = gcry_cipher_open(&hd, skalgo, GCRY_CIPHER_MODE_AESWRAP,
		GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, gcry_cipher_get_algo_keylen(skalgo));
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	memset(buf, 0, bufsize);
	for (size_t i = 0; ((i < in.size()) && (i < bufsize)); i++)
		buf[i] = in[i];
	tmcg_openpgp_skalgo_t symm_alg_ID = (tmcg_openpgp_skalgo_t)buf[0];
	size_t pkcs5_padding_off = AlgorithmKeyLength(symm_alg_ID) + 3;
	size_t pkcs5_padding_len = 40 - pkcs5_padding_off;
	for (size_t i = pkcs5_padding_off; i < 40; i++)
	{
		if ((pkcs5_padding_len == 21) && (i >= 24))
			buf[i] = 0x08;
		else if ((pkcs5_padding_len == 13) && (i >= 32))
			buf[i] = 0x08;
		else
			buf[i] = 0x05;		
	}
	rkwlen = in.size() + pkcs5_padding_len;
	ret = gcry_cipher_encrypt(hd, rkw, rkwlen+8, buf, rkwlen);
	gcry_cipher_close(hd);
	gcry_free(buf);
	if (ret)
		return ret;
	rkwlen += 8;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricDecryptECDH
	(const gcry_mpi_t ecepk, const gcry_sexp_t key, const size_t rkwlen,
	 const tmcg_openpgp_byte_t rkw[256], const tmcg_openpgp_hashalgo_t hashalgo,
	 const tmcg_openpgp_skalgo_t skalgo, const std::string &curve,
	 const tmcg_openpgp_octets_t &rcpfpr, tmcg_openpgp_secure_octets_t &out)
{
	gcry_sexp_t decryption, data;
	gcry_mpi_t S;
	gcry_error_t ret;
	size_t bufsize = 1024, buflen = 0, erroff;

	// compute shared secret S = rV, where V is the ephemeral key [RFC 6637]
	ret = gcry_sexp_build(&data, &erroff,
		"(enc-val (ecdh (e %m)))", ecepk);
	if (ret)
		return ret;
	ret = gcry_pk_decrypt(&decryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	ret = gcry_sexp_extract_param(decryption, NULL, "'value'", &S, NULL);
	gcry_sexp_release(decryption);
	if (ret)
		return ret;
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(bufsize);
	if (buf == NULL)
	{
		gcry_mpi_release(S);
		return GPG_ERR_RESOURCE_LIMIT; // cannot allocate secure memory
	}
	ret = gcry_mpi_print(GCRYMPI_FMT_USG, buf, bufsize, &buflen, S);
	gcry_mpi_release(S);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	// compute Z = KDF(S, Z_len, Param) [RFC 6637]
	tmcg_openpgp_secure_octets_t ZB, Z;
	if (buf[0] == 0x04)
	{
		for (size_t i = 0; i < ((buflen - 1) / 2); i++)
			ZB.push_back(buf[1+i]);
	}
	else if (buf[0] == 0x40)
	{
		for (size_t i = 0; i < (buflen - 1); i++)
			ZB.push_back(buf[1+i]);
	}
	else
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	ret = KDFCompute(hashalgo, skalgo, ZB, curve, rcpfpr, Z);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	memset(buf, 0, bufsize);
	for (size_t i = 0; ((i < Z.size()) && (i < bufsize)); i++)
		buf[i] = Z[i];
	// compute m by inverse operation of C = AESKeyWrap(Z, m)
	if (Z.size() < AlgorithmHashLength(hashalgo))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	if (Z.size() < gcry_cipher_get_algo_keylen(skalgo))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	if ((hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
		(hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
		(hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_PUBKEY;
	}
	if ((skalgo != TMCG_OPENPGP_SKALGO_AES128) &&
		(skalgo != TMCG_OPENPGP_SKALGO_AES192) &&
		(skalgo != TMCG_OPENPGP_SKALGO_AES256))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_PUBKEY;
	}
	gcry_cipher_hd_t hd;
	ret = gcry_cipher_open(&hd, skalgo, GCRY_CIPHER_MODE_AESWRAP,
		GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, buf, gcry_cipher_get_algo_keylen(skalgo));
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	if ((rkwlen % 8) || (rkwlen < 32))
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return GPG_ERR_BAD_DATA;
	}
	ret = gcry_cipher_decrypt(hd, buf, bufsize, rkw, rkwlen);
	gcry_cipher_close(hd);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	// check and extract the padded session key
	tmcg_openpgp_skalgo_t symm_alg_ID = (tmcg_openpgp_skalgo_t)buf[0];
	size_t symm_alg_keylen = AlgorithmKeyLength(symm_alg_ID);
	if ((symm_alg_keylen == 0) || ((rkwlen - 8) < symm_alg_keylen))
	{
		gcry_free(buf);
		return GPG_ERR_BAD_DATA;
	}
	for (size_t i = 0; ((i <= symm_alg_keylen) && (i < bufsize)); i++)
		out.push_back(buf[i]);
	gcry_free(buf);
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &r, gcry_mpi_t &s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_mpi_t q;
	unsigned int qbits = 0;
	gcry_error_t ret;
	size_t buflen = 0, erroff, trunclen = 0;

	// DSA signatures MUST use hashes that are equal in size to the number
	// of bits of q, the group generated by the DSA key's generator value.
	// If the output size of the chosen hash is larger than the number of
	// bits of q, the hash result is truncated to fit by taking the number
	// of leftmost bits equal to the number of bits of q. This (possibly
	// truncated) hash function result is treated as a number and used
	// directly in the DSA signature algorithm.
	ret = gcry_sexp_extract_param(key, NULL, "q", &q, NULL);
	if (ret)
		return ret;
	qbits = gcry_mpi_get_nbits(q);
	gcry_mpi_release(q);
	if (((in.size() * 8) < qbits) || (qbits < 160))
		return GPG_ERR_BAD_PUBKEY;
	trunclen = in.size();
	while ((trunclen * 8) > qbits)
		--trunclen;
	if ((trunclen * 8) != qbits)
		return GPG_ERR_BAD_PUBKEY;
	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf)) && 
	                    (i < trunclen)); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags raw) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_pk_sign(&signature, sigdata, key);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	gcry_mpi_release(r); // release already allocated mpi's
	gcry_mpi_release(s);
	ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
	gcry_sexp_release(signature);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignECDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &r, gcry_mpi_t &s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags raw) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_pk_sign(&signature, sigdata, key);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	gcry_mpi_release(r); // release already allocated mpi's
	gcry_mpi_release(s);
	ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
	gcry_sexp_release(signature);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignEdDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &r, gcry_mpi_t &s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags eddsa) (hash-algo sha512) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_pk_sign(&signature, sigdata, key);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	gcry_mpi_release(r); // release already allocated mpi's
	gcry_mpi_release(s);
	ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
	gcry_sexp_release(signature);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 const gcry_mpi_t r, const gcry_mpi_t s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_mpi_t q;
	unsigned int qbits = 0;
	gcry_error_t ret;
	size_t buflen = 0, erroff, trunclen = 0;

	// DSA signatures MUST use hashes that are equal in size to the number
	// of bits of q, the group generated by the DSA key's generator value.
	// If the output size of the chosen hash is larger than the number of
	// bits of q, the hash result is truncated to fit by taking the number
	// of leftmost bits equal to the number of bits of q.  This (possibly
	// truncated) hash function result is treated as a number and used
	// directly in the DSA signature algorithm.
	ret = gcry_sexp_extract_param(key, NULL, "q", &q, NULL);
	if (ret)
		return ret;
	qbits = gcry_mpi_get_nbits(q);
	gcry_mpi_release(q);
	if (((in.size() * 8) < qbits) || (qbits < 160))
		return GPG_ERR_BAD_PUBKEY;
	trunclen = in.size();
	while ((trunclen * 8) > qbits)
		--trunclen;
	if ((trunclen * 8) != qbits)
		return GPG_ERR_BAD_PUBKEY;
	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf)) &&
	                    (i < trunclen)); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags raw) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&signature, &erroff,
		"(sig-val (dsa (r %M) (s %M)))", r, s);
	if (ret)
	{
		gcry_sexp_release(sigdata);
		return ret;
	}
	ret = gcry_pk_verify(signature, sigdata, key);
	gcry_sexp_release(signature);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyECDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 const gcry_mpi_t r, const gcry_mpi_t s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;
	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags raw) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&signature, &erroff,
		"(sig-val (ecdsa (r %M) (s %M)))", r, s);
	if (ret)
	{
		gcry_sexp_release(sigdata);
		return ret;
	}
	ret = gcry_pk_verify(signature, sigdata, key);
	gcry_sexp_release(signature);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyEdDSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key, 
	 const gcry_mpi_t r, const gcry_mpi_t s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;
	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	ret = gcry_sexp_build(&sigdata, &erroff,
		"(data (flags eddsa) (hash-algo sha512) (value %b))", (int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&signature, &erroff,
		"(sig-val (eddsa (r %M) (s %M)))", r, s);
	if (ret)
	{
		gcry_sexp_release(sigdata);
		return ret;
	}
	ret = gcry_pk_verify(signature, sigdata, key);
	gcry_sexp_release(signature);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignRSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key,
	 const tmcg_openpgp_hashalgo_t hashalgo, gcry_mpi_t &s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;
	std::stringstream sexp;
	std::string hashname;

	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	AlgorithmHashGCRYName(hashalgo, hashname);
	sexp << "(data (flags pkcs1) (hash " << hashname << " %b))";
	ret = gcry_sexp_build(&sigdata, &erroff, (sexp.str()).c_str(),
		(int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_pk_sign(&signature, sigdata, key);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	gcry_mpi_release(s); // release already allocated mpi
	ret = gcry_sexp_extract_param(signature, NULL, "s", &s, NULL);
	gcry_sexp_release(signature);
	if (ret)
		return ret;
	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyRSA
	(const tmcg_openpgp_octets_t &in, const gcry_sexp_t key,
	 const tmcg_openpgp_hashalgo_t hashalgo, const gcry_mpi_t s)
{
	char buf[2048];
	gcry_sexp_t sigdata, signature;
	gcry_error_t ret;
	size_t buflen = 0, erroff;
	std::stringstream sexp;
	std::string hashname;

	// With RSA signatures, the hash value is encoded using PKCS#1 encoding
	// type EMSA-PKCS1-v1_5 as described in Section 9.2 of RFC 3447. This
	// requires inserting the hash value as an octet string into an ASN.1
	// structure. The object identifier for the type of hash being used is
	// included in the structure.
	memset(buf, 0, sizeof(buf));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buf))); i++, buflen++)
		buf[i] = in[i];
	AlgorithmHashGCRYName(hashalgo, hashname);
	sexp << "(data (flags pkcs1) (hash " << hashname << " %b))";
	ret = gcry_sexp_build(&sigdata, &erroff, (sexp.str()).c_str(),
		(int)buflen, buf);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&signature, &erroff,
		"(sig-val (rsa (s %M)))", s);
	if (ret)
	{
		gcry_sexp_release(sigdata);
		return ret;
	}
	ret = gcry_pk_verify(signature, sigdata, key);
	gcry_sexp_release(signature);
	gcry_sexp_release(sigdata);
	if (ret)
		return ret;
	return 0;
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::Release
	(std::vector<gcry_mpi_t> &qual, std::vector<gcry_mpi_t> &v_i, 
	 std::vector<gcry_mpi_t> &x_rvss_qual,
	 std::vector< std::vector<gcry_mpi_t> > &c_ik)
{
	for (size_t i = 0; i < qual.size(); i++)
		gcry_mpi_release(qual[i]);
	qual.clear();
	for (size_t i = 0; i < v_i.size(); i++)
		gcry_mpi_release(v_i[i]);
	v_i.clear();
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		gcry_mpi_release(x_rvss_qual[i]);
	x_rvss_qual.clear();
	for (size_t i = 0; i < c_ik.size(); i++)
	{
		for (size_t k = 0; k < c_ik[i].size(); k++)
			gcry_mpi_release(c_ik[i][k]);
		c_ik[i].clear();
	}
	c_ik.clear();
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse_Tag2
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const bool primary, const bool subkey, const bool badkey,
	 const bool uid_flag, const bool uat_flag,
	 const tmcg_openpgp_octets_t &current_packet,
	 tmcg_openpgp_octets_t &embedded_pkt,
	 TMCG_OpenPGP_Pubkey* &pub, TMCG_OpenPGP_Subkey* &sub,
	 TMCG_OpenPGP_UserID* &uid, TMCG_OpenPGP_UserAttribute* &uat)
{
	// 0x10: Generic certification of a User ID and Public-Key packet.
	// The issuer of this certification does not make any particular
	// assertion as to how well the certifier has checked that the owner
	// of the key is in fact the person described by the User ID.
	// 0x11: Persona certification of a User ID and Public-Key packet.
	// The issuer of this certification has not done any verification of
	// the claim that the owner of this key is the User ID specified.
	// 0x12: Casual certification of a User ID and Public-Key packet.
	// The issuer of this certification has done some casual verification
	// of the claim of identity.
	// 0x13: Positive certification of a User ID and Public-Key packet.
	// The issuer of this certification has done substantial verification
	// of the claim of identity.
	// Most OpenPGP implementations make their "key signatures" as 0x10
	// certifications. Some implementations can issue 0x11-0x13
	// certifications, but few differentiate between the types.
	// 0x18: Subkey Binding Signature
	// This signature is a statement by the top-level signing key that
	// indicates that it owns the subkey. This signature is calculated
	// directly on the primary key and subkey, and not on any User ID or
	// other packets. [...]
	// 0x19: Primary Key Binding Signature
	// This signature is a statement by a signing subkey, indicating that
	// it is owned by the primary key and subkey. This signature is
	// calculated the same way as a 0x18 signature: directly on the primary
	// key and subkey, and not on any User ID or other packets.
	// 0x1F: Signature directly on a key
	// This signature is calculated directly on a key. It binds the
	// information in the Signature subpackets to the key, and is
	// appropriate to be used for subpackets that provide information
	// about the key, such as the Revocation Key subpacket. It is also
	// appropriate for statements that non-self certifiers want to make
	// about the key itself, rather than the binding between a key and a
	// name.
	// 0x20: Key revocation signature
	// The signature is calculated directly on the key being revoked. A
	// revoked key is not to be used. Only revocation signatures by the
	// key being revoked, or by an authorized revocation key, should be
	// considered valid revocation signatures.
	// 0x28: Subkey revocation signature
	// The signature is calculated directly on the subkey being revoked.
	// A revoked subkey is not to be used. Only revocation signatures by
	// the top-level signature key that is bound to this subkey, or by
	// an authorized revocation key, should be considered valid revocation
	// signatures.
	// 0x30: Certification revocation signature
	// This signature revokes an earlier User ID certification signature
	// (signature class 0x10 through 0x13) or direct-key signature (0x1F).
	// It should be issued by the same key that issued the revoked
	// signature or an authorized revocation key. The signature is
	// computed over the same data as the certificate that it revokes,
	// and should have a later creation date than that certificate.
	TMCG_OpenPGP_Signature *sig = NULL;
	tmcg_openpgp_octets_t issuer, issuerfpr, hspd, keyflags;
	tmcg_openpgp_octets_t features, psa, pha, pca, paa, embeddedsig;
	for (size_t i = 0; i < sizeof(ctx.issuer); i++)
		issuer.push_back(ctx.issuer[i]);
	switch (ctx.issuerkeyversion)
	{
		case 0x04: // V4 keys use SHA-1
			for (size_t i = 0; i < 20; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
		case 0x05: // V5 keys use SHA256
			for (size_t i = 0; i < 32; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
	}
	for (size_t i = 0; i < ctx.hspdlen; i++)
		hspd.push_back(ctx.hspd[i]);
	for (size_t i = 0; i < ctx.keyflagslen; i++)
		keyflags.push_back(ctx.keyflags[i]);
	for (size_t i = 0; i < ctx.featureslen; i++)
		features.push_back(ctx.features[i]);
	for (size_t i = 0; i < ctx.psalen; i++)
		psa.push_back(ctx.psa[i]);
	for (size_t i = 0; i < ctx.phalen; i++)
		pha.push_back(ctx.pha[i]);
	for (size_t i = 0; i < ctx.pcalen; i++)
		pca.push_back(ctx.pca[i]);
	for (size_t i = 0; i < ctx.paalen; i++)
		paa.push_back(ctx.paa[i]);
	for (size_t i = 0; i < ctx.embeddedsignaturelen; i++)
		embeddedsig.push_back(ctx.embeddedsignature[i]);
	if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int mdbits = 0;
		mdbits = gcry_mpi_get_nbits(ctx.md);
		if (verbose > 2)
			std::cerr << "INFO: mdbits = " << mdbits << std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo, ctx.type,
			ctx.version, ctx.sigcreationtime, ctx.sigexpirationtime,
			ctx.keyexpirationtime, ctx.revocationcode, ctx.md,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		unsigned int rbits = 0, sbits = 0;
		rbits = gcry_mpi_get_nbits(ctx.r);
		sbits = gcry_mpi_get_nbits(ctx.s);
		if (verbose > 2)
			std::cerr << "INFO: rbits = " << rbits <<
				" sbits = " << sbits <<	std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo, ctx.type,
			ctx.version, ctx.sigcreationtime, ctx.sigexpirationtime,
			ctx.keyexpirationtime, ctx.revocationcode, ctx.r, ctx.s,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		unsigned int rbits = 0, sbits = 0;
		rbits = gcry_mpi_get_nbits(ctx.r);
		sbits = gcry_mpi_get_nbits(ctx.s);
		if (verbose > 2)
			std::cerr << "INFO: ECDSA rbits = " << rbits <<
				" sbits = " << sbits <<	std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo, ctx.type,
			ctx.version, ctx.sigcreationtime, ctx.sigexpirationtime,
			ctx.keyexpirationtime, ctx.revocationcode, ctx.r, ctx.s,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		unsigned int rbits = 0, sbits = 0;
		rbits = gcry_mpi_get_nbits(ctx.r);
		sbits = gcry_mpi_get_nbits(ctx.s);
		if (verbose > 2)
			std::cerr << "INFO: EdDSA rbits = " << rbits <<
				" sbits = " << sbits <<	std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo, ctx.type,
			ctx.version, ctx.sigcreationtime, ctx.sigexpirationtime,
			ctx.keyexpirationtime, ctx.revocationcode, ctx.r, ctx.s,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else
	{
		if (verbose)
			std::cerr << "WARNING: public-key signature algorithm " <<
				(int)ctx.pkalgo << " not supported" << std::endl;
		return true; // continue loop through packets
	}
	if (!sig->Good())
	{
		if (verbose)
			std::cerr << "ERROR: parsing signature" <<
				" material failed" << std::endl;

		delete sig;
		return false;
	}
	// evaluate the context of the signature
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		delete sig;
		return false;
	}
	if (badkey)
	{
		if (verbose)
			std::cerr << "WARNING: signature for unrecognized" <<
				" subkey ignored" << std::endl;
		delete sig;
		return true; // continue loop through packets
	}
	if (subkey)
	{
		if (OctetsCompare(pub->id, issuer))
		{
			if (ctx.type == TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING)
			{
				// Authorizes the specified key to issue revocation signatures
				// for this key. Class octet must have bit 0x80 set. If the bit
				// 0x40 is set, then this means that the revocation information
				// is sensitive. Other bits are for future expansion to other
				// kinds of authorizations. This is found on a self-signature.
				if ((ctx.revocationkey_class & 0x80) == 0x80)
				{
					tmcg_openpgp_revkey_t revkey;
					revkey.key_class = ctx.revocationkey_class;
					revkey.key_pkalgo =	ctx.revocationkey_pkalgo;
					memcpy(revkey.key_fingerprint,
						ctx.revocationkey_fingerprint,
						sizeof(revkey.key_fingerprint));
					sig->revkeys.push_back(revkey);
				}
				// A signature that binds a signing subkey MUST have an
				// Embedded Signature subpacket in this binding signature that
				// contains a 0x19 signature made by the signing subkey on the
				// primary key and subkey.
				if (ctx.embeddedsignaturelen != 0)
				{
					PacketTagEncode(2, embedded_pkt);
					PacketLengthEncode(ctx.embeddedsignaturelen, embedded_pkt);
					for (size_t i = 0; i < ctx.embeddedsignaturelen; i++)
						embedded_pkt.push_back(ctx.embeddedsignature[i]);
				}
				// Subkey binding signature
				sub->bindsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY)
			{
				// Authorizes the specified key to issue revocation signatures
				// for this key. Class octet must have bit 0x80 set. If the bit
				// 0x40 is set, then this means that the revocation information
				// is sensitive. Other bits are for future expansion to other
				// kinds of authorizations. This is found on a self-signature.
				if ((ctx.revocationkey_class & 0x80) == 0x80)
				{
					tmcg_openpgp_revkey_t revkey;
					revkey.key_class = ctx.revocationkey_class;
					revkey.key_pkalgo = ctx.revocationkey_pkalgo;
					memcpy(revkey.key_fingerprint, 
						ctx.revocationkey_fingerprint,
						sizeof(revkey.key_fingerprint));
					sig->revkeys.push_back(revkey);
				}
				// Direct key signature on subkey
				sub->selfsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_SUBKEY_REVOCATION)
			{
				// Key revocation signature on subkey
				sub->keyrevsigs.push_back(sig);
				if (verbose)
					std::cerr << "WARNING: key revocation signature on" <<
						" subkey found" << std::endl;
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
			{
				// Certification revocation signature on subkey
				sub->certrevsigs.push_back(sig);
				if (verbose)
					std::cerr << "WARNING: certification revocation" <<
						" signature on subkey found" << std::endl;
			}
			else
			{
				delete sig;
				if (verbose)
					std::cerr << "WARNING: signature of type 0x" << std::hex <<
						(int)ctx.type << std::dec << " on subkey ignored" <<
						std::endl;
			}
		}
		else if (OctetsCompare(sub->id, issuer))
		{
			if (ctx.type == TMCG_OPENPGP_SIGNATURE_PRIMARY_KEY_BINDING)
			{
				// Primary key binding signature on subkey
				sub->pbindsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY)
			{
				// Authorizes the specified key to issue revocation signatures
				// for this key. Class octet must have bit 0x80 set. If the bit
				// 0x40 is set, then this means that the revocation information
				// is sensitive. Other bits are for future expansion to other
				// kinds of authorizations. This is found on a self-signature.
				if ((ctx.revocationkey_class & 0x80) == 0x80)
				{
					tmcg_openpgp_revkey_t revkey;
					revkey.key_class = ctx.revocationkey_class;
					revkey.key_pkalgo = ctx.revocationkey_pkalgo;
					memcpy(revkey.key_fingerprint, 
						ctx.revocationkey_fingerprint,
						sizeof(revkey.key_fingerprint));
					sig->revkeys.push_back(revkey);
				}
				// Direct key signature on subkey
				sub->selfsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
			{
				// Certification revocation signature on subkey
				sub->certrevsigs.push_back(sig);
				if (verbose)
					std::cerr << "WARNING: certification revocation" <<
						" signature on subkey found" << std::endl;
			}
			else
			{
				delete sig;
				if (verbose)
					std::cerr << "WARNING: signature of type 0x" << std::hex <<
						(int)ctx.type << std::dec << " on subkey ignored" <<
						std::endl;
			}
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_SUBKEY_REVOCATION)
		{
			// accumulate key revocation signatures
			// issued by external revocation keys
			sub->keyrevsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: sub-level key revocation signature" <<
					" on subkey found " << std::endl;
		}
		else
		{
			delete sig;
			if (verbose)
				std::cerr << "WARNING: signature of type 0x" << std::hex <<
					(int)ctx.type << std::dec << " on subkey from unknown" <<
					" issuer ignored" << std::endl;
		}
		return true; // continue loop through packets
	}
	// non-self issuer found?
	if (!OctetsCompare(pub->id, issuer))
	{
		if (uid_flag)
		{
			if ((ctx.type == TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION))
			{
				// Certification signature on user ID
				uid->certsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
			{
				// Certification revocation signature (user ID)
				uid->certsigs.push_back(sig);
			}
			else 
			{
				delete sig;
				if (verbose)
					std::cerr << "WARNING: signature of type 0x" << std::hex <<
						(int)ctx.type << std::dec << " ignored (non-self)" <<
						std::endl;
			}
		}
		else if (uat_flag)
		{
			if ((ctx.type == TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION) ||
				(ctx.type == TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION))
			{
				// Certification signature on user attribute
				uat->certsigs.push_back(sig);
			}
			else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
			{
				// Certification revocation signature (user attribute)
				uat->certsigs.push_back(sig);
			}
			else 
			{
				delete sig;
				if (verbose)
					std::cerr << "WARNING: signature of type 0x" << std::hex <<
						(int)ctx.type << std::dec << " ignored (non-self)" <<
						std::endl;
			}
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_KEY_REVOCATION)
		{
			// accumulate key revocation signatures
			// issued by external revocation keys
			pub->keyrevsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: external key revocation signature" <<
					" on primary key found" << std::endl;
		}
		else
		{
			delete sig;
			if (verbose)
				std::cerr << "WARNING: non-uid/uat signature of type 0x" <<
					std::hex << (int)ctx.type << std::dec <<
					" on primary key ignored" << std::endl;
		}
		return true; // continue loop through packets
	}
	if (!uid_flag && !uat_flag)
	{
		if (ctx.type == TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY)
		{
			// Authorizes the specified key to issue revocation signatures
			// for this key. Class octet must have bit 0x80 set. If the bit
			// 0x40 is set, then this means that the revocation information
			// is sensitive. Other bits are for future expansion to other
			// kinds of authorizations. This is found on a self-signature.
			if ((ctx.revocationkey_class & 0x80) == 0x80)
			{
				tmcg_openpgp_revkey_t revkey;
				revkey.key_class = ctx.revocationkey_class;
				revkey.key_pkalgo =	ctx.revocationkey_pkalgo;
				memcpy(revkey.key_fingerprint, 
					ctx.revocationkey_fingerprint,
					sizeof(revkey.key_fingerprint));
				sig->revkeys.push_back(revkey);
			}
			// Direct key signature on primary key
			pub->selfsigs.push_back(sig);
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_KEY_REVOCATION)
		{
			// Key revocation signature on primary key
			pub->keyrevsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: key revocation signature on primary" <<
					" key found" << std::endl;
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
		{
			// Certification revocation signature on primary key
			pub->certrevsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: certification revocation signature" <<
					" on primary key" << std::endl;
		}
		else
		{
			delete sig;
			if (verbose)
				std::cerr << "WARNING: non-self signature of type 0x" <<
					std::hex << (int)ctx.type << std::dec <<
					" on primary key ignored" << std::endl;
		}
		return true; // continue loop through packets
	}
	else if (!uid_flag && uat_flag)
	{
		if ((ctx.type == TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION))
		{
			// Authorizes the specified key to issue revocation signatures
			// for this key. Class octet must have bit 0x80 set. If the bit
			// 0x40 is set, then this means that the revocation information
			// is sensitive. Other bits are for future expansion to other
			// kinds of authorizations. This is found on a self-signature.
			if ((ctx.revocationkey_class & 0x80) == 0x80)
			{
				tmcg_openpgp_revkey_t revkey;
				revkey.key_class = ctx.revocationkey_class;
				revkey.key_pkalgo =	ctx.revocationkey_pkalgo;
				memcpy(revkey.key_fingerprint, 
					ctx.revocationkey_fingerprint,
					sizeof(revkey.key_fingerprint));
				sig->revkeys.push_back(revkey);
			}
			// Certification self-signature on user attribute
			uat->selfsigs.push_back(sig);
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
		{
			// Certification revocation signature on user attribute
			uat->revsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: certification revocation signature" <<
					" on user attribute" << std::endl;
		}
		else
		{
			delete sig;
			if (verbose)
				std::cerr << "WARNING: signature of type 0x" << std::hex <<
					(int)ctx.type << std::dec << " ignored (uat_flag)" <<
					std::endl;
		}
		return true; // continue loop through packets
	}
	else if (uid_flag && !uat_flag)
	{
		if ((ctx.type == TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION) ||
			(ctx.type == TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION))
		{
			// Authorizes the specified key to issue revocation signatures
			// for this key. Class octet must have bit 0x80 set. If the bit
			// 0x40 is set, then this means that the revocation information
			// is sensitive. Other bits are for future expansion to other
			// kinds of authorizations. This is found on a self-signature.
			if ((ctx.revocationkey_class & 0x80) == 0x80)
			{
				tmcg_openpgp_revkey_t revkey;
				revkey.key_class = ctx.revocationkey_class;
				revkey.key_pkalgo =	ctx.revocationkey_pkalgo;
				memcpy(revkey.key_fingerprint, 
					ctx.revocationkey_fingerprint,
					sizeof(revkey.key_fingerprint));
				sig->revkeys.push_back(revkey);
			}
			// Certification self-signature on user ID
			uid->selfsigs.push_back(sig);
		}
		else if (ctx.type == TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION)
		{
			// Certification revocation signature on user ID
			uid->revsigs.push_back(sig);
			if (verbose)
				std::cerr << "WARNING: certification revocation signature" <<
					" on user ID" << std::endl;
		}
		else
		{
			delete sig;
			if (verbose)
				std::cerr << "WARNING: signature of type 0x" << std::hex <<
					(int)ctx.type << std::dec << " ignored (uid_flag)" <<
					std::endl;
		}
		return true; // continue loop through packets
	}
	// should never reach, however, it's here to make static analyzers happy
	delete sig;
	return true; // continue loop through packets
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse_Tag6
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 bool &primary, TMCG_OpenPGP_Pubkey* &pub)
{
	if (ctx.version != 4)
	{
		if (verbose)
			std::cerr << "WARNING: public-key packet version " <<
				(int)ctx.version << " not supported" << std::endl;
	}
	else if (!primary)
	{
		primary = true;
		// evaluate the context
		if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			// public-key algorithm is RSA: create new pubkey
			pub = new TMCG_OpenPGP_Pubkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.n, ctx.e, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			// public-key algorithm is DSA: create new pubkey
			pub = new TMCG_OpenPGP_Pubkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.p, ctx.q, ctx.g, ctx.y, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		{
			// public-key algorithm is ECDSA: create new pubkey
			pub = new TMCG_OpenPGP_Pubkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.curveoidlen, ctx.curveoid, ctx.ecpk, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		{
			// public-key algorithm is EdDSA: create new pubkey
			pub = new TMCG_OpenPGP_Pubkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.curveoidlen, ctx.curveoid, ctx.ecpk, current_packet);
		}
		else
		{
			primary = false;
			if (verbose)
				std::cerr << "ERROR: public-key algorithm " <<
					(int)ctx.pkalgo << " not supported" << std::endl;
			return false;
		}
		if (!pub->Good())
		{
			if (verbose)
				std::cerr << "ERROR: reading primary key" <<
					" material failed" << std::endl;
			return false;
		}
		if (verbose > 1)
		{
			std::cerr << "INFO: key ID of primary key: " << std::hex;
			for (size_t i = 0; i < pub->id.size(); i++)
				std::cerr << (int)pub->id[i] << " ";
			std::cerr << std::dec << std::endl;
		}
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: more than one primary key not allowed" <<
				std::endl;
		return false;
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse_Tag13
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const bool primary, const tmcg_openpgp_octets_t &current_packet,
	 bool &uid_flag, bool &uat_flag, TMCG_OpenPGP_Pubkey* &pub,
	 TMCG_OpenPGP_UserID* &uid, TMCG_OpenPGP_UserAttribute* &uat)
{
	std::string userid = "";
	for (size_t i = 0; i < ctx.uiddatalen; i++)
	{
		if (ctx.uiddata[i] != 0)
			userid += ctx.uiddata[i];
		else
			break;
	}
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		return false;
	}
	if (uid_flag)
		pub->userids.push_back(uid);
	if (uat_flag)
		pub->userattributes.push_back(uat);
	uid = NULL, uat = NULL, uid_flag = true, uat_flag = false;
	// create a new user ID object
	uid = new TMCG_OpenPGP_UserID(userid, current_packet);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse_Tag14
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const bool primary, const tmcg_openpgp_octets_t &current_packet,
	 bool &subkey, bool &badkey, TMCG_OpenPGP_Pubkey* &pub,
	 TMCG_OpenPGP_Subkey* &sub)
{
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		return false;
	}
	if (!badkey && subkey)
		pub->subkeys.push_back(sub);
	sub = NULL, subkey = true, badkey = false;
	if (ctx.version != 4)
	{
		if (verbose)
			std::cerr << "WARNING: public-subkey packet version " <<
				(int)ctx.version << " not supported" << std::endl;
		badkey = true;
	}
	else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDH) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
	{
		// evaluate the context
		if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			// public-key algorithm is RSA: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.n, ctx.e,
				current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{
			// public-key algorithm is ElGamal: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.p, ctx.g,
				ctx.y, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			// public-key algorithm is DSA: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.p, ctx.q, ctx.g, 
				ctx.y, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
		{
			// public-key algorithm is ECDH: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid, 
				ctx.ecpk, ctx.kdf_hashalgo, ctx.kdf_skalgo, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		{
			// public-key algorithm is ECDSA: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid, 
				ctx.ecpk, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		{
			// public-key algorithm is EdDSA: create new subkey
			sub = new TMCG_OpenPGP_Subkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid, 
				ctx.ecpk, current_packet);
		}
		if (!sub->Good())
		{
			if (verbose)
				std::cerr << "ERROR: parsing subkey" <<
					" material failed" << std::endl;
			delete sub;
			sub = NULL;
			return false;
		}
		if (verbose > 1)
		{
			std::cerr << "INFO: key ID of subkey: " << std::hex;
			for (size_t i = 0; i < sub->id.size(); i++)
				std::cerr << (int)sub->id[i] << " ";
			std::cerr << std::dec << std::endl;
		}
		if (verbose && OctetsCompare(sub->id, pub->id))
			std::cerr << "WARNING: probably same key material" <<
				" used for primary key and subkey" << std::endl;
	}
	else
	{
		if (verbose)
			std::cerr << "WARNING: public-key algorithm " <<
				(int)ctx.pkalgo << " for subkey not supported" << std::endl;
		badkey = true;
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse_Tag17
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const bool primary, const tmcg_openpgp_octets_t &current_packet,
	 bool &uid_flag, bool &uat_flag, TMCG_OpenPGP_Pubkey* &pub,
	 TMCG_OpenPGP_UserID* &uid, TMCG_OpenPGP_UserAttribute* &uat)
{
	tmcg_openpgp_octets_t userattribute;
	for (size_t i = 0; i < ctx.uatdatalen; i++)
		userattribute.push_back(ctx.uatdata[i]);
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		return false;
	}
	if (uid_flag)
		pub->userids.push_back(uid);
	if (uat_flag)
		pub->userattributes.push_back(uat);
	uid = NULL, uat = NULL, uid_flag = false, uat_flag = true;
	// create a new user attribute object
	uat = new TMCG_OpenPGP_UserAttribute(userattribute, current_packet);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PrivateKeyBlockParse_Decrypt
	(tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_secure_string_t &passphrase)
{
	if (verbose > 1)
	{
		std::cerr << "INFO: encdatalen = " << ctx.encdatalen << std::endl;
		std::cerr << "INFO: skalgo = " << (int)ctx.skalgo << std::endl;
		std::cerr << "INFO: aeadalgo = " << (int)ctx.aeadalgo << std::endl;
		std::cerr << "INFO: s2kconv = " << (int)ctx.s2kconv << std::endl;
		std::cerr << "INFO: s2k_type = " << (int)ctx.s2k_type <<
			" s2k_hashalgo = " << (int)ctx.s2k_hashalgo <<
			" s2k_count = " << (int)ctx.s2k_count << std::endl;
	}
	if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
	{
		// decrypt the secret parameters
		size_t keylen = AlgorithmKeyLength(ctx.skalgo);
		size_t ivlen = AlgorithmIVLength(ctx.skalgo);
		int	algo = AlgorithmSymGCRY(ctx.skalgo);
		if (!keylen || !ivlen)
		{
			if (verbose)
				std::cerr << "ERROR: algorithm not supported" << std::endl;
			return false;
		}
		tmcg_openpgp_octets_t salt;
		for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
			salt.push_back(ctx.s2k_salt[i]);
		tmcg_openpgp_secure_octets_t skey;
		if (ctx.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SIMPLE)
		{
			salt.clear();
			S2KCompute(ctx.s2k_hashalgo, keylen, passphrase, salt, false,
				ctx.s2k_count, skey);
		}
		else if (ctx.s2k_type == TMCG_OPENPGP_STRINGTOKEY_SALTED)
		{
			S2KCompute(ctx.s2k_hashalgo, keylen, passphrase, salt, false,
				ctx.s2k_count, skey);
		}
		else if (ctx.s2k_type == TMCG_OPENPGP_STRINGTOKEY_ITERATED)
		{
			S2KCompute(ctx.s2k_hashalgo, keylen, passphrase, salt, true,
				ctx.s2k_count, skey);
		}
		else
		{
			if (verbose)
				std::cerr << "ERROR: unknown S2K specifier" << std::endl;
			return false;
		}
		if ((skey.size() != keylen) || (keylen > ctx.encdatalen))
		{
			if (verbose)
				std::cerr << "ERROR: S2K failed" << std::endl;
			return false;
		}
		if (!ctx.encdatalen || !ctx.encdata)
		{
			if (verbose)
				std::cerr << "ERROR: no data to decrypt" << std::endl;
			return false;
		}
		tmcg_openpgp_byte_t *iv = new tmcg_openpgp_byte_t[ivlen];
		for (size_t i = 0; i < ivlen; i++)
			iv[i] = ctx.iv[i];
		unsigned char *buf = (unsigned char*)gcry_malloc_secure(ctx.encdatalen);
		if (buf == NULL)
		{
			delete [] iv;
			return false; // cannot allocate secure memory
		}
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB,
			GCRY_CIPHER_SECURE);
		if (ret)
		{
			if (verbose)
				std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
			delete [] iv;
			gcry_free(buf);
			gcry_cipher_close(hd);
			return false;
		}
		for (size_t i = 0; i < keylen; i++)
			buf[i] = skey[i];
		ret = gcry_cipher_setkey(hd, buf, keylen);
		if (ret)
		{
			if (verbose)
				std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
			delete [] iv;
			gcry_free(buf);
			gcry_cipher_close(hd);
			return false;
		}
		ret = gcry_cipher_setiv(hd, iv, ivlen);
		if (ret)
		{
			if (verbose)
				std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
			delete [] iv;
			gcry_free(buf);
			gcry_cipher_close(hd);
			return false;
		}
		delete [] iv;
		for (size_t i = 0; i < ctx.encdatalen; i++)
			buf[i] = ctx.encdata[i];
		ret = gcry_cipher_decrypt(hd, buf, ctx.encdatalen, NULL, 0);
		if (ret)
		{
			if (verbose)
				std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
			gcry_free(buf);
			gcry_cipher_close(hd);
			return false;
		}
		gcry_cipher_close(hd);
		tmcg_openpgp_secure_octets_t mpis;
		for (size_t i = 0; i < ctx.encdatalen; i++)
			mpis.push_back(buf[i]);
		size_t chksum = 0, mlen;
		if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			mlen = PacketMPIDecode(mpis, ctx.d, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI d failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
			mlen = PacketMPIDecode(mpis, ctx.p, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI p failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
			mlen = PacketMPIDecode(mpis, ctx.q, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI q failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
			mlen = PacketMPIDecode(mpis, ctx.u, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI u failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{
			mlen = PacketMPIDecode(mpis, ctx.x, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI x failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			mlen = PacketMPIDecode(mpis, ctx.x, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI x failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
		}
		else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDH) ||
				(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
				(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
		{
			mlen = PacketMPIDecode(mpis, ctx.ecsk, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI ecsk failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
		}
		else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) ||
		         (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL8) ||
		         (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
		{
			mlen = PacketMPIDecode(mpis, ctx.x_i, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI x_i failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
			mlen = PacketMPIDecode(mpis, ctx.xprime_i, chksum);
			if (!mlen || (mlen > mpis.size()))
			{
				std::cerr << "ERROR: reading MPI xprime_i failed" <<
					" (bad passphrase)" << std::endl;
				gcry_free(buf);
				return false;
			}
			mpis.erase(mpis.begin(), mpis.begin()+mlen);
		}
		else
		{
			if (verbose)
				std::cerr << "ERROR: algorithm not supported" << std::endl;
			gcry_free(buf);
			return false;
		}
		if (ctx.s2kconv == 255)
		{
			if (mpis.size() < 2)
			{
				if (verbose)
					std::cerr << "ERROR: no checksum found" << std::endl;
				gcry_free(buf);
				return false;
			}
			size_t chksum2 = (mpis[0] << 8) + mpis[1];
			if (chksum != chksum2)
			{
				if (verbose)
					std::cerr << "ERROR: checksum mismatch" << std::endl;
				gcry_free(buf);
				return false;
			}
		}
		else
		{
			if ((mpis.size() != 20) || (ctx.encdatalen < 20))
			{
				if (verbose)
					std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
				gcry_free(buf);
				return false;
			}
			tmcg_openpgp_secure_octets_t hash_input, hash;
			for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
				hash_input.push_back(buf[i]);
			ret = HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, hash_input, hash);
			if (ret)
			{
				if (verbose)
					std::cerr << "ERROR: HashCompute() failed" << std::endl;
				gcry_free(buf);
				return false;
			}
			if (!OctetsCompareConstantTime(hash, mpis))
			{
				if (verbose)
					std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
				gcry_free(buf);
				return false;
			}
		}
		gcry_free(buf);
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PrivateKeyBlockParse_Tag5
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 bool &primary, TMCG_OpenPGP_Prvkey* &prv)
{
	if (ctx.version != 4)
	{
		if (verbose)
			std::cerr << "WARNING: secret-key packet version " <<
				(int)ctx.version << " not supported" << std::endl;
	}
	else if (!primary)
	{
		primary = true;
		// evaluate the context
		if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			// public-key algorithm is RSA: create new prvkey
			prv = new TMCG_OpenPGP_Prvkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.n, ctx.e, ctx.p, ctx.q, ctx.u, ctx.d, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			// public-key algorithm is DSA: create new prvkey
			prv = new TMCG_OpenPGP_Prvkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.p, ctx.q, ctx.g, ctx.y, ctx.x, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		{
			// public-key algorithm is ECDSA: create new prvkey
			prv = new TMCG_OpenPGP_Prvkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.curveoidlen, ctx.curveoid, ctx.ecpk, ctx.ecsk,
				current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		{
			// public-key algorithm is EdDSA: create new prvkey
			prv = new TMCG_OpenPGP_Prvkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.curveoidlen, ctx.curveoid, ctx.ecpk, ctx.ecsk,
				current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
		{
			std::vector<std::string> capl;
			std::vector<gcry_mpi_t> qual, v_i, x_rvss_qual;
			std::vector< std::vector<gcry_mpi_t> > c_ik;
			tmcg_openpgp_octets_t pcur, pkts;
			tmcg_openpgp_packet_ctx_t pctx;
			tmcg_openpgp_notations_t notations;
			tmcg_openpgp_byte_t ptag = 0xFF;
			pkts.insert(pkts.end(),
				current_packet.begin(), current_packet.end());
			ptag = PacketDecode(pkts, verbose, pctx, pcur,
				qual, x_rvss_qual, capl, v_i, c_ik, notations);
			if (ptag != 5)
			{
				if (verbose)
					std::cerr << "ERROR: decoding tDSS/DSA key failed" <<
						std::endl;
				PacketContextRelease(pctx);
				Release(qual, v_i, x_rvss_qual, c_ik);
				return false;
			}
			// public-key algorithm is tDSS/DSA: create new prvkey
			prv = new TMCG_OpenPGP_Prvkey(ctx.pkalgo, ctx.keycreationtime, 0,
				ctx.p, ctx.q, ctx.g, ctx.h, ctx.y, ctx.x_i, ctx.xprime_i,
				ctx.n, ctx.t, ctx.i, capl, qual, x_rvss_qual, c_ik,
				current_packet);
			PacketContextRelease(pctx);
			Release(qual, v_i, x_rvss_qual, c_ik);
		}
		else
		{
			primary = false;
			if (verbose)
				std::cerr << "ERROR: public-key algorithm " <<
					(int)ctx.pkalgo << " not supported" << std::endl;
			return false;
		}
		if (!prv->Good())
		{
			if (verbose)
				std::cerr << "ERROR: reading primary key " <<
					"material failed" << std::endl;
			return false;
		}
		if (verbose > 1)
		{
			std::cerr << "INFO: key ID of private primary key: " << std::hex;
			for (size_t i = 0; i < prv->pub->id.size(); i++)
				std::cerr << (int)prv->pub->id[i] << " ";
			std::cerr << std::dec << std::endl;
		}
	}
	else
	{
		if (verbose)
			std::cerr << "ERROR: more than one primary key not allowed" <<
				std::endl;
		return false;
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PrivateKeyBlockParse_Tag7
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const bool primary, const tmcg_openpgp_octets_t &current_packet,
	 bool &subkey, bool &badkey,
	 TMCG_OpenPGP_Prvkey* &prv, TMCG_OpenPGP_PrivateSubkey* &sub)
{
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		return false;
	}
	if (!badkey && subkey)
		prv->private_subkeys.push_back(sub);
	sub = NULL, subkey = true, badkey = false;
	if (ctx.version != 4)
	{
		if (verbose)
			std::cerr << "WARNING: secret-subkey packet " <<
				"version " << (int)ctx.version <<
				" not supported" << std::endl;
		badkey = true;
	}
	else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDH) ||
			(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
	{
		// evaluate the context
		if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
		    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			// public-key algorithm is RSA: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.n, ctx.e, ctx.p, ctx.q,
				ctx.u, ctx.d, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{
			// public-key algorithm is ElGamal: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.p, ctx.g, ctx.y, ctx.x,
				current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			// public-key algorithm is DSA: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.p, ctx.q, ctx.g, ctx.y, ctx.x,
				current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
		{
			std::vector<std::string> capl;
			std::vector<gcry_mpi_t> qual, v_i, x_rvss_qual;
			std::vector< std::vector<gcry_mpi_t> > c_ik;
			tmcg_openpgp_octets_t pcur, pkts;
			tmcg_openpgp_packet_ctx_t pctx;
			tmcg_openpgp_notations_t notations;
			tmcg_openpgp_byte_t ptag = 0xFF;
			pkts.insert(pkts.end(),
				current_packet.begin(), current_packet.end());
			ptag = PacketDecode(pkts, verbose, pctx, pcur,
				qual, x_rvss_qual, capl, v_i, c_ik, notations);
			if (ptag != 7)
			{
				if (verbose)
					std::cerr << "ERROR: decoding tElG key failed" << std::endl;
				PacketContextRelease(pctx);
				Release(qual, v_i, x_rvss_qual, c_ik);
				return false;
			}
			// public-key algorithm is tElG: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.p, ctx.q, ctx.g, ctx.h, ctx.y,
				ctx.x_i, ctx.xprime_i, ctx.n, ctx.t, ctx.i, qual, v_i, c_ik,
				current_packet);
			PacketContextRelease(pctx);
			Release(qual, v_i, x_rvss_qual, c_ik);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		{
			// public-key algorithm is ECDSA: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid,
				ctx.ecpk, ctx.ecsk, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		{
			// public-key algorithm is EdDSA: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid,
				ctx.ecpk, ctx.ecsk, current_packet);
		}
		else if (ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
		{
			// public-key algorithm is ECDSA: create new private subkey
			sub = new TMCG_OpenPGP_PrivateSubkey(ctx.pkalgo,
				ctx.keycreationtime, 0, ctx.curveoidlen, ctx.curveoid,
				ctx.ecpk, ctx.ecsk, ctx.kdf_hashalgo, ctx.kdf_skalgo,
				current_packet);
		}
		if (!sub->Good())
		{
			if (verbose)
				std::cerr << "ERROR: parsing subkey " <<
					"material failed" << std::endl;
			delete sub;
			sub = NULL;
			return false;
		}
		if (verbose > 1)
		{
			std::cerr << "INFO: key ID of private subkey: " << std::hex;
			for (size_t i = 0; i < sub->pub->id.size(); i++)
				std::cerr << (int)sub->pub->id[i] << " ";
			std::cerr << std::dec << std::endl;
		}
		if (verbose && OctetsCompare(sub->pub->id, prv->pub->id))
			std::cerr << "WARNING: probably same key material " <<
				"used for primary key and subkey" << std::endl;
	}
	else
	{
		if (verbose)
			std::cerr << "WARNING: public-key algorithm " <<
				(int)ctx.pkalgo << " for subkey not " <<
				"supported" << std::endl;
		badkey = true;
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag1
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	TMCG_OpenPGP_PKESK *esk = NULL;
	if (verbose > 1)
		std::cerr << "INFO: ESK pkalgo = " << (int)ctx.pkalgo << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	tmcg_openpgp_octets_t keyid;
	if (verbose > 1)
		std::cerr << "INFO: ESK keyid = " << std::hex;
	for (size_t i = 0; i < sizeof(ctx.keyid); i++)
	{
		if (verbose > 1)
			std::cerr << (int)ctx.keyid[i] << " ";
		keyid.push_back(ctx.keyid[i]);
	}
	if (verbose > 1)
		std::cerr << std::dec << std::endl;
	switch (ctx.pkalgo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
			esk = new TMCG_OpenPGP_PKESK(ctx.pkalgo, keyid, ctx.me,
				current_packet);
			(msg->PKESKs).push_back(esk);
			break;
		case TMCG_OPENPGP_PKALGO_ELGAMAL:
			esk = new TMCG_OpenPGP_PKESK(ctx.pkalgo, keyid, ctx.gk, ctx.myk,
				current_packet);
			(msg->PKESKs).push_back(esk);
			break;
		case TMCG_OPENPGP_PKALGO_ECDH:
			esk = new TMCG_OpenPGP_PKESK(ctx.pkalgo, keyid, ctx.ecepk,
				ctx.rkwlen, ctx.rkw, current_packet);
			(msg->PKESKs).push_back(esk);
			break;
		default:
			break; // ignore not supported public-key algorithms
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag2
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	tmcg_openpgp_octets_t issuer, issuerfpr, hspd, keyflags;
	tmcg_openpgp_octets_t features, psa, pha, pca, paa, embeddedsig;
	for (size_t i = 0; i < sizeof(ctx.issuer); i++)
		issuer.push_back(ctx.issuer[i]);
	switch (ctx.issuerkeyversion)
	{
		case 0x04: // V4 keys use SHA-1
			for (size_t i = 0; i < 20; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
		case 0x05: // V5 keys use SHA256
			for (size_t i = 0; i < 32; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
	}
	for (size_t i = 0; i < ctx.hspdlen; i++)
		hspd.push_back(ctx.hspd[i]);
	for (size_t i = 0; i < ctx.keyflagslen; i++)
		keyflags.push_back(ctx.keyflags[i]);
	for (size_t i = 0; i < ctx.featureslen; i++)
		features.push_back(ctx.features[i]);
	for (size_t i = 0; i < ctx.psalen; i++)
		psa.push_back(ctx.psa[i]);
	for (size_t i = 0; i < ctx.phalen; i++)
		pha.push_back(ctx.pha[i]);
	for (size_t i = 0; i < ctx.pcalen; i++)
		pca.push_back(ctx.pca[i]);
	for (size_t i = 0; i < ctx.paalen; i++)
		paa.push_back(ctx.paa[i]);
	for (size_t i = 0; i < ctx.embeddedsignaturelen; i++)
		embeddedsig.push_back(ctx.embeddedsignature[i]);
	TMCG_OpenPGP_Signature *sig = NULL;
	if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		unsigned int mdbits = 0;
		mdbits = gcry_mpi_get_nbits(ctx.md);
		if (verbose > 2)
			std::cerr << "INFO: mdbits = " << mdbits << std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo,
			ctx.type, ctx.version, ctx.sigcreationtime,
			ctx.sigexpirationtime, 0, ctx.revocationcode, ctx.md,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
		(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
		(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
	{
		unsigned int rbits = 0, sbits = 0;
		rbits = gcry_mpi_get_nbits(ctx.r);
		sbits = gcry_mpi_get_nbits(ctx.s);
		if (verbose > 2)
			std::cerr << "INFO: rbits = " << rbits <<
				" sbits = " << sbits << std::endl;
		// create a new signature object
		sig = new TMCG_OpenPGP_Signature(ctx.revocable,
			ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo,
			ctx.type, ctx.version, ctx.sigcreationtime,
			ctx.sigexpirationtime, 0, ctx.revocationcode, ctx.r, ctx.s,
			current_packet, hspd, issuer, issuerfpr, keyflags, features,
			psa, pha, pca, paa, embeddedsig);
	}
	else
	{
		if (verbose)
		{
			std::cerr << "WARNING: public-key signature algorithm " <<
				(int)ctx.pkalgo << " not supported" << std::endl;
		}
		return true;
	}
	if (!sig->Good())
	{
		if (verbose)
			std::cerr << "ERROR: parsing signature material failed" << std::endl;
		delete sig;
		return false;
	}
	else
		(msg->signatures).push_back(sig);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag3
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: ESK skalgo = " << (int)ctx.skalgo <<
			" aeadalgo = " << (int)ctx.aeadalgo <<
			" s2k_type = " << (int)ctx.s2k_type << 
			" s2k_hashalgo = " << (int)ctx.s2k_hashalgo <<
			" s2k_count = " << (int)ctx.s2k_count <<  
			" encdatalen = " << ctx.encdatalen << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	tmcg_openpgp_octets_t salt, iv, enckey;
	for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
		salt.push_back(ctx.s2k_salt[i]);
	size_t ivlen = AlgorithmIVLength(ctx.aeadalgo);
	for (size_t i = 0; i < ivlen; i++)
		iv.push_back(ctx.iv[i]);
	for (size_t i = 0; i < ctx.encdatalen; i++)
		enckey.push_back(ctx.encdata[i]);
	TMCG_OpenPGP_SKESK *esk = new TMCG_OpenPGP_SKESK(ctx.version, ctx.skalgo,
		ctx.aeadalgo, ctx.s2k_type, ctx.s2k_hashalgo, salt, ctx.s2k_count, iv,
		enckey, current_packet);
	(msg->SKESKs).push_back(esk);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag8
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: COMP length = " << ctx.compdatalen <<
			" compalgo = " << (int)ctx.compalgo << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	if ((msg->compressed_message).size() != 0)
	{
		if (verbose)
			std::cerr << "ERROR: duplicate COMP packet found" << std::endl;
		return false;
	}
	else
	{
		(msg->compressed_message).insert((msg->compressed_message).end(),
			current_packet.begin(), current_packet.end());
		msg->compalgo = ctx.compalgo;
		for (size_t i = 0; i < ctx.compdatalen; i++)
			(msg->compressed_data).push_back(ctx.compdata[i]);
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag9
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: SE length = " << ctx.encdatalen << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	if (msg->have_sed || msg->have_seipd || msg->have_aead)
	{
		if (verbose)
		{
			std::cerr << "ERROR: duplicate SE/SEIP/AEAD packet found" <<
				std::endl;
		}
		return false;
	}
	else
	{
		msg->have_sed = true;
		for (size_t i = 0; i < ctx.encdatalen; i++)
			(msg->encrypted_message).push_back(ctx.encdata[i]);
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag11
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: LIT length = " << ctx.datalen << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	if ((msg->literal_message).size() != 0)
	{
		if (verbose)
			std::cerr << "ERROR: duplicate LIT packet found" << std::endl;
		return false;
	}
	else
	{
		(msg->literal_message).insert((msg->literal_message).end(),
			current_packet.begin(), current_packet.end());
		msg->format = ctx.dataformat;
		for (size_t i = 0; i < ctx.datafilenamelen; i++)
			msg->filename += ctx.datafilename[i];
		msg->timestamp = ctx.datatime;
		for (size_t i = 0; i < ctx.datalen; i++)
			(msg->literal_data).push_back(ctx.data[i]);
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag18
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: SEIP length = " << ctx.encdatalen << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	if (msg->have_sed || msg->have_seipd || msg->have_aead)
	{
		if (verbose)
		{
			std::cerr << "ERROR: duplicate SE/SEIP/AEAD packet found" <<
				std::endl;
		}
		return false;
	}
	else
	{
		msg->have_seipd = true;
		for (size_t i = 0; i < ctx.encdatalen; i++)
			(msg->encrypted_message).push_back(ctx.encdata[i]);
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag19
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
		std::cerr << "INFO: MDC length = " << sizeof(ctx.mdc_hash) << std::endl;
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	(msg->mdc).clear();
	for (size_t i = 0; i < sizeof(ctx.mdc_hash); i++)
		(msg->mdc).push_back(ctx.mdc_hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse_Tag20
	(const tmcg_openpgp_packet_ctx_t &ctx, const int verbose,
	 const tmcg_openpgp_octets_t &current_packet,
	 TMCG_OpenPGP_Message* &msg)
{
	if (verbose > 1)
	{
		std::cerr << "INFO: AEAD length = " << ctx.encdatalen << std::endl;
		std::cerr << "INFO: AEAD skalgo = " << (int)ctx.skalgo << std::endl;
		std::cerr << "INFO: AEAD aeadalgo = " << (int)ctx.aeadalgo << std::endl;
		std::cerr << "INFO: AEAD chunksize = " << (int)ctx.chunksize <<
			std::endl;
	}
	if (verbose > 2)
	{
		std::cerr << "INFO: packet length = " << current_packet.size() <<
			std::endl;
	}
	if (msg->have_sed || msg->have_seipd || msg->have_aead)
	{
		if (verbose)
		{
			std::cerr << "ERROR: duplicate SE/SEIP/AEAD packet found" <<
				std::endl;
		}
		return false;
	}
	else
	{
		msg->have_aead = true;
		msg->skalgo = ctx.skalgo;
		msg->aeadalgo = ctx.aeadalgo;
		msg->chunksize = ctx.chunksize;
		size_t ivlen = AlgorithmIVLength(msg->aeadalgo);
		for (size_t i = 0; i < ivlen; i++)
			msg->iv.push_back(ctx.iv[i]);
		for (size_t i = 0; i < ctx.encdatalen; i++)
			(msg->encrypted_message).push_back(ctx.encdata[i]);
	}
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyringParse_Add
	(const int verbose, bool &primary, bool &subkey, bool &badkey,
	 bool &uid_flag, bool &uat_flag,
	 TMCG_OpenPGP_Pubkey* &pub, TMCG_OpenPGP_Subkey* &sub,
	 TMCG_OpenPGP_UserID* &uid, TMCG_OpenPGP_UserAttribute* &uat,
	 TMCG_OpenPGP_Keyring* &ring)
{
	if (primary)
	{
		if (uid_flag)
			pub->userids.push_back(uid);
		if (uat_flag)
			pub->userattributes.push_back(uat);
		if (!badkey && subkey)
			pub->subkeys.push_back(sub);
		// add key to ring
		if (!ring->Add(pub))
		{
			if (verbose)
				std::cerr << "WARNING: keyring already contains" <<
					" this key; duplicate key ignored" << std::endl;
			delete pub;
		}
		pub = NULL, sub = NULL, uid = NULL, uat = NULL;
		primary = false, subkey = false, badkey = false;
		uid_flag = false, uat_flag = false;
	}
	else if (verbose > 2)
		std::cerr << "INFO: cannot add nothing to keyring" << std::endl;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 TMCG_OpenPGP_Pubkey* &pub)
{
	pub = NULL;
	// copy the message for processing
	tmcg_openpgp_octets_t pkts;
	pkts.insert(pkts.end(), in.begin(), in.end());
	// parse the public key block packet by packet
	bool primary = false, subkey = false, badkey = false;
	bool uid_flag = false, uat_flag = false, ret = true;
	TMCG_OpenPGP_Subkey *sub = NULL;
	TMCG_OpenPGP_UserID *uid = NULL;
	TMCG_OpenPGP_UserAttribute *uat = NULL;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t pnum = 0;
	tmcg_openpgp_octets_t embedded_pkt;
	while (pkts.size() || embedded_pkt.size())
	{
		tmcg_openpgp_packet_ctx_t ctx;
		tmcg_openpgp_octets_t current_packet;
		tmcg_openpgp_notations_t notations;
		if (embedded_pkt.size())
		{
			ptag = PacketDecode(embedded_pkt, verbose, ctx, current_packet,
				notations);
			if (verbose > 2)
				std::cerr << "INFO: [EMBEDDED] PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
			embedded_pkt.clear();
		}
		else
		{
			ptag = PacketDecode(pkts, verbose, ctx, current_packet, notations);
			++pnum;
			if (verbose > 2)
				std::cerr << "INFO: PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
		}
		if (ptag == 0x00)
		{
			if (verbose)
				std::cerr << "WARNING: decoding OpenPGP packets failed " <<
					"at packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFA)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized critical OpenPGP" <<
					" subpacket found at packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore signature with critical subpacket
		}
		else if (ptag == 0xFB)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP" <<
					" subpacket found at packet #" << pnum << std::endl;
			ptag = 0x02; // try to process signature anyway
		}
		else if (ptag == 0xFC)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP" <<
					" signature packet found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFD)
		{
			if (primary)
			{
				if (verbose)
					std::cerr << "WARNING: unrecognized OpenPGP " <<
						"key packet found at #" << pnum << std::endl;
				if (!badkey && subkey)
				{
					pub->subkeys.push_back(sub);
					sub = NULL;
				}
				badkey = true;
				PacketContextRelease(ctx);
				continue; // ignore packet
			}
			else
			{
				if (verbose)
					std::cerr << "ERROR: public-key algorithm " <<
						(int)ctx.pkalgo << " not supported" << std::endl;
				PacketContextRelease(ctx);
				return false;
			}
		}
		else if (ptag == 0xFE)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP " <<
					"packet found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature Packet
				ret = PublicKeyBlockParse_Tag2(ctx, verbose, primary,
					subkey, badkey, uid_flag, uat_flag,
					current_packet, embedded_pkt, pub, sub, uid, uat);
				break;
			case 6: // Public-Key Packet
				ret = PublicKeyBlockParse_Tag6(ctx, verbose,
					current_packet, primary, pub);
				break;
			case 13: // User ID Packet
				ret = PublicKeyBlockParse_Tag13(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, pub, uid, uat);
				break;
			case 14: // Public-Subkey Packet
				ret = PublicKeyBlockParse_Tag14(ctx, verbose, primary,
					current_packet, subkey, badkey, pub, sub);
				break;
			case 17: // User Attribute Packet
				ret = PublicKeyBlockParse_Tag17(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, pub, uid, uat);
				break;
			default:
				if (verbose > 1)
					std::cerr << "INFO: OpenPGP packet with tag " <<
						(int)ptag << " ignored" << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		PacketContextRelease(ctx);
		if (!ret)
		{
			if (pub)
				delete pub;
			if (sub)
				delete sub;
			if (uid)
				delete uid;
			if (uat)
				delete uat;
			return false;
		}
	}
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		if (pub)
			delete pub;
		if (sub)
			delete sub;
		if (uid)
			delete uid;
		if (uat)
			delete uat;
		return false;
	}
	if (uid_flag)
		pub->userids.push_back(uid);
	if (uat_flag)
		pub->userattributes.push_back(uat);
	if (!badkey && subkey)
		pub->subkeys.push_back(sub);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyBlockParse
	(const std::string &in, const int verbose,
	 TMCG_OpenPGP_Pubkey* &pub)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t type = ArmorDecode(in, pkts);
	if (type != TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK)
	{
		if (verbose)
			std::cerr << "ERROR: wrong type of ASCII Armor found" <<
				" (type = " << (int)type << ")" << std::endl;
		return false;
	}
	return PublicKeyBlockParse(pkts, verbose, pub);
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::SignatureParse
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 TMCG_OpenPGP_Signature* &sig)
{
	sig = NULL;
	// copy the message for processing
	tmcg_openpgp_octets_t pkts;
	pkts.insert(pkts.end(), in.begin(), in.end());
	// parse a single signature packet
	tmcg_openpgp_packet_ctx_t ctx;
	tmcg_openpgp_octets_t current_packet;
	tmcg_openpgp_notations_t notations;
	tmcg_openpgp_byte_t ptag = PacketDecode(pkts, verbose, ctx, current_packet,
		notations);
	if (verbose > 2)
		std::cerr << "INFO: PacketDecode() = " << (int)ptag << 
			" version = " << (int)ctx.version << std::endl;
	if (ptag == 0x00)
	{
		if (verbose)
			std::cerr << "ERROR: decoding OpenPGP packet failed" << std::endl;
		PacketContextRelease(ctx);
		return false;
	}
	else if (ptag == 0xFA)
	{
		if (verbose)
			std::cerr << "ERROR: unrecognized critical OpenPGP" <<
				" signature subpacket found" << std::endl;
		PacketContextRelease(ctx);
		return false;
	}
	else if (ptag == 0xFB)
	{
		if (verbose)
			std::cerr << "WARNING: unrecognized OpenPGP" <<
				" signature subpacket found" << std::endl;
		ptag = 0x02; // process signature anyway
	}
	else if (ptag == 0xFC)
	{
		if (verbose)
			std::cerr << "ERROR: unrecognized OpenPGP" <<
				" signature packet found " << std::endl;
		PacketContextRelease(ctx);
		return false;
	}
	else if (ptag == 0xFD)
	{
		if (verbose)
			std::cerr << "ERROR: unrecognized OpenPGP" <<
				" key packet found" << std::endl;
		PacketContextRelease(ctx);
		return false;
	}
	else if (ptag == 0xFE)
	{
		if (verbose)
			std::cerr << "ERROR: unrecognized OpenPGP" << 
				" packet found" << std::endl;
		PacketContextRelease(ctx);
		return false;
	}
	tmcg_openpgp_octets_t issuer, issuerfpr, hspd, keyflags;
	tmcg_openpgp_octets_t features, psa, pha, pca, paa, embeddedsig;
	for (size_t i = 0; i < sizeof(ctx.issuer); i++)
		issuer.push_back(ctx.issuer[i]);
	switch (ctx.issuerkeyversion)
	{
		case 0x04: // V4 keys use SHA-1
			for (size_t i = 0; i < 20; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
		case 0x05: // V5 keys use SHA256
			for (size_t i = 0; i < 32; i++)
				issuerfpr.push_back(ctx.issuerfingerprint[i]);
			break;
	}
	for (size_t i = 0; i < ctx.hspdlen; i++)
		hspd.push_back(ctx.hspd[i]);
	for (size_t i = 0; i < ctx.keyflagslen; i++)
		keyflags.push_back(ctx.keyflags[i]);
	for (size_t i = 0; i < ctx.featureslen; i++)
		features.push_back(ctx.features[i]);
	for (size_t i = 0; i < ctx.psalen; i++)
		psa.push_back(ctx.psa[i]);
	for (size_t i = 0; i < ctx.phalen; i++)
		pha.push_back(ctx.pha[i]);
	for (size_t i = 0; i < ctx.pcalen; i++)
		pca.push_back(ctx.pca[i]);
	for (size_t i = 0; i < ctx.paalen; i++)
		paa.push_back(ctx.paa[i]);
	for (size_t i = 0; i < ctx.embeddedsignaturelen; i++)
		embeddedsig.push_back(ctx.embeddedsignature[i]);
	switch (ptag)
	{
		case 2: // Signature Packet
			if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
			    (ctx.pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
			{
				unsigned int mdbits = 0;
				mdbits = gcry_mpi_get_nbits(ctx.md);
				if (verbose > 2)
					std::cerr << "INFO: mdbits = " << mdbits << std::endl;
				// create a new signature object
				sig = new TMCG_OpenPGP_Signature(ctx.revocable,
					ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo,
					ctx.type, ctx.version, ctx.sigcreationtime,
					ctx.sigexpirationtime, 0, ctx.revocationcode, ctx.md,
					current_packet, hspd, issuer, issuerfpr, keyflags, features,
					psa, pha, pca, paa, embeddedsig);
			}
			else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
				(ctx.pkalgo == TMCG_OPENPGP_PKALGO_ECDSA) ||
				(ctx.pkalgo == TMCG_OPENPGP_PKALGO_EDDSA))
			{
				unsigned int rbits = 0, sbits = 0;
				rbits = gcry_mpi_get_nbits(ctx.r);
				sbits = gcry_mpi_get_nbits(ctx.s);
				if (verbose > 2)
					std::cerr << "INFO: rbits = " << rbits <<
						" sbits = " << sbits << std::endl;
				// create a new signature object
				sig = new TMCG_OpenPGP_Signature(ctx.revocable,
					ctx.exportablecertification, ctx.pkalgo, ctx.hashalgo,
					ctx.type, ctx.version, ctx.sigcreationtime,
					ctx.sigexpirationtime, 0, ctx.revocationcode, ctx.r, ctx.s,
					current_packet, hspd, issuer, issuerfpr, keyflags, features,
					psa, pha, pca, paa, embeddedsig);
			}
			else
			{
				if (verbose)
					std::cerr << "ERROR: public-key signature algorithm " <<
						(int)ctx.pkalgo << " not supported" << std::endl;
				PacketContextRelease(ctx);
				return false;
			}
			if (!sig->Good())
			{
				if (verbose)
					std::cerr << "ERROR: parsing signature material failed" <<
						std::endl;
				PacketContextRelease(ctx);
				delete sig;
				return false;
			}
			break;
		default:
			if (verbose)
				std::cerr << "ERROR: wrong OpenPGP packet with tag " << 
					(int)ptag << std::endl;
			PacketContextRelease(ctx);
			return false;
			break;
	}
	// cleanup allocated buffers and mpi's
	PacketContextRelease(ctx);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::SignatureParse
	(const std::string &in, const int verbose,
	 TMCG_OpenPGP_Signature* &sig)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t type = ArmorDecode(in, pkts);
	if (type != TMCG_OPENPGP_ARMOR_SIGNATURE)
	{
		if (verbose)
			std::cerr << "ERROR: wrong type of ASCII Armor found" <<
				" (type = " << (int)type << ")" << std::endl;
		return false;
	}
	return SignatureParse(pkts, verbose, sig);
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyringParse
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 TMCG_OpenPGP_Keyring* &ring)
{
	// create a new keyring object, if none is supplied by caller
	if (ring == NULL)
		ring = new TMCG_OpenPGP_Keyring();
	// copy the message for processing
	tmcg_openpgp_octets_t pkts;
	pkts.insert(pkts.end(), in.begin(), in.end());
	// parse the public key ring packet by packet
	bool primary = false, subkey = false, badkey = false;
	bool uid_flag = false, uat_flag = false, ret = true;
	bool ignore = false;
	TMCG_OpenPGP_Pubkey *pub = NULL;
	TMCG_OpenPGP_Subkey *sub = NULL;
	TMCG_OpenPGP_UserID *uid = NULL;
	TMCG_OpenPGP_UserAttribute *uat = NULL;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t knum = 0, pnum = 0;
	tmcg_openpgp_octets_t embedded_pkt;
	while (pkts.size() || embedded_pkt.size())
	{
		tmcg_openpgp_packet_ctx_t ctx;
		tmcg_openpgp_octets_t current_packet;
		tmcg_openpgp_notations_t notations;
		if (embedded_pkt.size())
		{
			ptag = PacketDecode(embedded_pkt, verbose, ctx, current_packet,
				notations);
			if (verbose > 2)
				std::cerr << "INFO: [EMBEDDED] PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
			embedded_pkt.clear();
		}
		else
		{
			ptag = PacketDecode(pkts, verbose, ctx, current_packet, notations);
			++pnum;
			if ((ptag == 5) || (ptag == 6) || (ctx.tag == 5) || (ctx.tag == 6))
				++knum;
			if (verbose > 2)
				std::cerr << "INFO: PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
		}
		// handle return code from PacketDecode()
		if (ptag == 0x00)
		{
			if (verbose)
				std::cerr << "WARNING: decoding OpenPGP packets failed " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFA)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized critical subpacket " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore signature with critical subpacket
		}
		else if (ptag == 0xFB)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized subpacket found " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
			ptag = 0x02; // process signature anyway
		}
		else if (ptag == 0xFC)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized signature packet found " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFD)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized key packet found " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
			if ((ctx.tag == 14) || (ctx.tag == 7))
			{
				if (primary && !badkey && subkey)
				{
					pub->subkeys.push_back(sub);
					sub = NULL;
				}
				badkey = true;
			}
			else if ((ctx.tag == 6) || (ctx.tag == 5))
			{
				PublicKeyringParse_Add(verbose, primary, subkey, badkey,
					uid_flag, uat_flag, pub, sub, uid, uat, ring);
				ignore = true; // ignore all following packets of this key block
			}
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFE)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP packet found " <<
					"at key #" << knum << " and packet #" << pnum << std::endl;
		}
		// ignore all packets of an unrecognized key block
		if (ignore && (ptag != 6))
		{
			PacketContextRelease(ctx);
			continue; // ignore packet		
		}
		if (ignore && (ptag == 6))
			ignore = false; // process next key block
		// process packet
		switch (ptag)
		{
			case 2: // Signature Packet
				ret = PublicKeyBlockParse_Tag2(ctx, verbose, primary,
					subkey, badkey, uid_flag, uat_flag,
					current_packet, embedded_pkt, pub, sub, uid, uat);
				break;
			case 6: // Public-Key Packet
				PublicKeyringParse_Add(verbose, primary, subkey, badkey,
					uid_flag, uat_flag, pub, sub, uid, uat, ring);
				ret = PublicKeyBlockParse_Tag6(ctx, verbose,
					current_packet, primary, pub);
				break;
			case 13: // User ID Packet
				ret = PublicKeyBlockParse_Tag13(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, pub, uid, uat);
				break;
			case 14: // Public-Subkey Packet
				ret = PublicKeyBlockParse_Tag14(ctx, verbose, primary,
					current_packet, subkey, badkey, pub, sub);
				break;
			case 17: // User Attribute Packet
				ret = PublicKeyBlockParse_Tag17(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, pub, uid, uat);
				break;
			default:
				if (verbose > 1)
					std::cerr << "INFO: OpenPGP packet with tag " <<
						(int)ptag << " ignored" << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		PacketContextRelease(ctx);
		if (!ret)
		{
			if (pub)
				delete pub;
			if (sub)
				delete sub;
			if (uid)
				delete uid;
			if (uat)
				delete uat;
			delete ring;
			return false;
		}
	}
	if (primary)
	{
		PublicKeyringParse_Add(verbose, primary, subkey, badkey, uid_flag,
			uat_flag, pub, sub, uid, uat, ring);
	}
	else
	{
		if (pub)
			delete pub;
		if (sub)
			delete sub;
		if (uid)
			delete uid;
		if (uat)
			delete uat;
	}
	if (verbose > 1)
		std::cerr << "INFO: ring.Size() = " << ring->Size() << std::endl;	
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PublicKeyringParse
	(const std::string &in, const int verbose,
	 TMCG_OpenPGP_Keyring* &ring)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t type = ArmorDecode(in, pkts);
	if (type != TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK)
	{
		if (verbose)
			std::cerr << "ERROR: wrong type of ASCII Armor found" <<
				" (type = " << (int)type << ")" << std::endl;
		return false;
	}
	return PublicKeyringParse(pkts, verbose, ring);
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PrivateKeyBlockParse
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 TMCG_OpenPGP_Prvkey* &prv)
{
	prv = NULL;
	// copy the message for processing
	tmcg_openpgp_octets_t pkts;
	pkts.insert(pkts.end(), in.begin(), in.end());
	// parse the private key block packet by packet
	bool primary = false, subkey = false, badkey = false;
	bool uid_flag = false, uat_flag = false, ret = true;
	TMCG_OpenPGP_PrivateSubkey *sub = NULL;
	TMCG_OpenPGP_UserID *uid = NULL;
	TMCG_OpenPGP_UserAttribute *uat = NULL;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t pnum = 0;
	tmcg_openpgp_octets_t embedded_pkt;
	while (pkts.size() || embedded_pkt.size())
	{
		tmcg_openpgp_packet_ctx_t ctx;
		tmcg_openpgp_octets_t current_packet;
		tmcg_openpgp_notations_t notations;
		if (embedded_pkt.size())
		{
			ptag = PacketDecode(embedded_pkt, verbose, ctx, current_packet,
				notations);
			if (verbose > 2)
				std::cerr << "INFO: [EMBEDDED] PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
			embedded_pkt.clear();
		}
		else
		{
			ptag = PacketDecode(pkts, verbose, ctx, current_packet, notations);
			++pnum;
			if (verbose > 2)
				std::cerr << "INFO: PacketDecode() = " <<
					(int)ptag << " version = " << (int)ctx.version << std::endl;
		}
		if (ptag == 0x00)
		{
			if (verbose)
				std::cerr << "ERROR: decoding OpenPGP packets failed " <<
					"at packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			if (prv)
				delete prv;
			if (sub)
				delete sub;
			if (uid)
				delete uid;
			if (uat)
				delete uat;
			return false;
		}
		else if (ptag == 0xFA)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized critical OpenPGP " <<
					"subpacket found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore signature with critical subpacket
		}
		else if (ptag == 0xFB)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP subpacket " <<
					"found at #" << pnum << std::endl;
			ptag = 0x02; // process signature
		}
		else if (ptag == 0xFC)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP signature " <<
					"packet found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFD)
		{
			if (primary)
			{
				if (verbose)
					std::cerr << "WARNING: unrecognized OpenPGP key packet" <<
						" found at #" << pnum << std::endl;
				if (!badkey && subkey)
				{
					prv->private_subkeys.push_back(sub);
					sub = NULL;
				}
				badkey = true;
				PacketContextRelease(ctx);
				continue; // ignore packet
			}
			else
			{
				if (verbose)
					std::cerr << "ERROR: public-key algorithm " <<
						(int)ctx.pkalgo << " not supported" << std::endl;
				PacketContextRelease(ctx);
				return false;
			}
		}
		else if (ptag == 0xFE)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP packet" <<
					" found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature Packet
				ret = PublicKeyBlockParse_Tag2(ctx, verbose, primary,
					subkey, badkey, uid_flag, uat_flag,	current_packet,
					embedded_pkt, prv->pub, sub->pub, uid, uat);
				break;
			case 5: // Secret-Key Packet
				if (!PrivateKeyBlockParse_Decrypt(ctx, verbose, passphrase))
				{
					ret = false; // wrong passphrase
				}
				else
				{
					ret = PrivateKeyBlockParse_Tag5(ctx, verbose,
						current_packet, primary, prv);
				}
				break;
			case 7: // Secret-Subkey Packet
				if (!PrivateKeyBlockParse_Decrypt(ctx, verbose, passphrase))
				{
					ret = false; // wrong passphrase
				}
				else
				{
					ret = PrivateKeyBlockParse_Tag7(ctx, verbose, primary,
						current_packet, subkey, badkey, prv, sub);
				}
				break;
			case 13: // User ID Packet
				ret = PublicKeyBlockParse_Tag13(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, prv->pub, uid, uat);
				break;
			case 17: // User Attribute Packet
				ret = PublicKeyBlockParse_Tag17(ctx, verbose, primary,
					current_packet, uid_flag, uat_flag, prv->pub, uid, uat);
				break;
			default:
				if (verbose > 1)
					std::cerr << "INFO: OpenPGP packet with tag " <<
						(int)ptag << " ignored" << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		PacketContextRelease(ctx);
		if (!ret)
		{
			if (prv)
				delete prv;
			if (sub)
				delete sub;
			if (uid)
				delete uid;
			if (uat)
				delete uat;
			return false;
		}
	}
	if (!primary)
	{
		if (verbose)
			std::cerr << "ERROR: no usable primary key found" << std::endl;
		if (prv)
			delete prv;
		if (sub)
			delete sub;
		if (uid)
			delete uid;
		if (uat)
			delete uat;
		return false;
	}
	if (uid_flag)
		prv->pub->userids.push_back(uid);
	if (uat_flag)
		prv->pub->userattributes.push_back(uat);
	if (!badkey && subkey)
		prv->private_subkeys.push_back(sub);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::PrivateKeyBlockParse
	(const std::string &in, const int verbose,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 TMCG_OpenPGP_Prvkey* &prv)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t type = ArmorDecode(in, pkts);
	if (type != TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK)
	{
		if (verbose)
			std::cerr << "ERROR: wrong type of ASCII Armor found" <<
				" (type = " << (int)type << ")" << std::endl;
		return false;
	}
	return PrivateKeyBlockParse(pkts, verbose, passphrase, prv);
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse
	(const tmcg_openpgp_octets_t &in, const int verbose,
	 TMCG_OpenPGP_Message* &msg)
{
	// create a new message object, if none is supplied by caller
	if (msg == NULL)
		msg = new TMCG_OpenPGP_Message();
	// copy the message for processing
	tmcg_openpgp_octets_t pkts;
	pkts.insert(pkts.end(), in.begin(), in.end());
	// parse the message packet by packet
	bool stop = false, kseq = false;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t pnum = 0;
	while (pkts.size() && !stop)
	{
		bool ret = true;
		tmcg_openpgp_packet_ctx_t ctx;
		tmcg_openpgp_octets_t current_packet;
		tmcg_openpgp_notations_t notations;
		ptag = PacketDecode(pkts, verbose, ctx, current_packet, notations);
		++pnum;
		if (verbose > 2)
			std::cerr << "INFO: PacketDecode() = " <<
				(int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			if (verbose)
				std::cerr << "ERROR: decoding OpenPGP packets failed " <<
					"at packet #" << pnum << std::endl;
			PacketContextRelease(ctx);
			return false;
		}
		else if (ptag == 0xFA)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized critical OpenPGP " <<
					"subpacket found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore signature with critical subpacket
		}
		else if (ptag == 0xFB)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP subpacket " <<
					"found at #" << pnum << std::endl;
			ptag = 0x02; // process signature
		}
		else if (ptag == 0xFC)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP signature " <<
					"packet found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFD)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP key packet " <<
					"found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		else if (ptag == 0xFE)
		{
			if (verbose)
				std::cerr << "WARNING: unrecognized OpenPGP packet " <<
					"found at #" << pnum << std::endl;
			PacketContextRelease(ctx);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 1: // Public-Key Encrypted Session Key
				ret = MessageParse_Tag1(ctx, verbose, current_packet, msg);
				kseq = true;
				break;
			case 2: // Signature
				ret = MessageParse_Tag2(ctx, verbose, current_packet, msg);
				if (kseq)
					ret = false; // ESK sequence detected
				break;
			case 3: // Symmetric-Key Encrypted Session Key
				ret = MessageParse_Tag3(ctx, verbose, current_packet, msg);
				kseq = true;
				break;
			case 4: // One-Pass Signature
				if (verbose)
					std::cerr << "WARNING: one-pass signature OpenPGP packet" <<
						" found; not supported and ignored" << std::endl;
				break;
			case 8: // Compressed Data
				if (ctx.indetlen && msg->have_seipd &&
					((msg->mdc).size() == 0) && (ctx.compdatalen > 22))
				{
					// handle MDC, if COMP packet has indeterminate length
					if (verbose)
						std::cerr << "WARNING: assume MDC at the end of COMP" <<
							" packet (indeterminate length)" << std::endl;
					ctx.compdatalen -= 22;
					for (size_t i = 0; i < 22; i++)
					{
						pkts.push_back(ctx.compdata[ctx.compdatalen+i]);
						current_packet.pop_back();
					}
				}
				ret = MessageParse_Tag8(ctx, verbose, current_packet, msg);
				if (kseq)
					ret = false; // ESK sequence detected
				break;
			case 9: // Symmetrically Encrypted Data
				ret = MessageParse_Tag9(ctx, verbose, current_packet, msg);
				stop = true; // ensures well-formedness of an OpenPGP message
				break;
			case 11: // Literal Data
				if (ctx.indetlen && msg->have_seipd &&
					((msg->mdc).size() == 0) && (ctx.datalen > 22))
				{
					// handle MDC, if LIT packet has indeterminate length
					if (verbose)
						std::cerr << "WARNING: assume MDC at the end of LIT" <<
							" packet (indeterminate length)" << std::endl;
					ctx.datalen -= 22;
					for (size_t i = 0; i < 22; i++)
					{
						pkts.push_back(ctx.data[ctx.datalen+i]);
						current_packet.pop_back();
					}
				}
				ret = MessageParse_Tag11(ctx, verbose, current_packet, msg);
				if (kseq)
					ret = false; // ESK sequence detected
				break;
			case 18: // Symmetrically Encrypted Integrity Protected Data
				ret = MessageParse_Tag18(ctx, verbose, current_packet, msg);
				stop = true; // ensures well-formedness of an OpenPGP message
				break;
			case 19: // Modification Detection Code
				ret = MessageParse_Tag19(ctx, verbose, current_packet, msg);
				stop = true; // ensures well-formedness of an OpenPGP message
				if (kseq)
					ret = false; // ESK sequence detected
				break;
			case 20: // AEAD Encrypted Data [draft RFC 4880bis]
				ret = MessageParse_Tag20(ctx, verbose, current_packet, msg);
				stop = true; // ensures well-formedness of an OpenPGP message
				break;
			default:
				if (verbose > 1)
					std::cerr << "INFO: OpenPGP packet with tag " <<
						(int)ptag << " ignored" << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		PacketContextRelease(ctx);
		if (!ret)
			return false;
	}
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse
	(const std::string &in, const int verbose,
	 TMCG_OpenPGP_Message* &msg)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t type = ArmorDecode(in, pkts);
	if (type != TMCG_OPENPGP_ARMOR_MESSAGE)
	{
		if (verbose)
			std::cerr << "ERROR: wrong type of ASCII Armor " <<
				"found (type = " << (int)type << ")" << std::endl;
		return false;
	}
	return MessageParse(pkts, verbose, msg);
}

