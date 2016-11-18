/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.hh, OpenPGP Message Format

     J. Callas, L. Donnerhacke, H. Finney, D. Shaw, R. Thayer:
	'OpenPGP Message Format',
     Network Working Group, Request for Comments: 4880, November 2007. 

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

#ifndef INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH
	#define INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH

	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	// C and STL header
	#include <vector>
	#include <string>
	#include <iostream>
	#include <algorithm>
	#include <ctime>
	#include <inttypes.h>

	// GNU crypto library
	#include <gcrypt.h>

	typedef unsigned char BYTE;
	typedef std::vector<BYTE> OCTETS;


	static const BYTE fRadix64[] = {
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255,  62, 255,  62, 255,  63,
		 52,  53,  54,  55,  56,  57,  58,  59,
		 60,  61, 255, 255,   0, 255, 255, 255,
		255,   0,   1,   2,   3,   4,   5,   6,
		  7,   8,   9,  10,  11,  12,  13,  14,
		 15,  16,  17,  18,  19,  20,  21,  22,
		 23,  24,  25, 255, 255, 255, 255,  63,
		255,  26,  27,  28,  29,  30,  31,  32,
		 33,  34,  35,  36,  37,  38,  39,  40,
		 41,  42,  43,  44,  45,  46,  47,  48,
		 49,  50,  51, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	};

	static const BYTE tRadix64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	typedef struct
	{
		bool newformat;
		BYTE version;
		BYTE keyid[8];
		BYTE pkalgo;
		gcry_mpi_t me;
		gcry_mpi_t gk;
		gcry_mpi_t myk;
		BYTE type;
		BYTE hashalgo;
		bool critical;
		time_t sigcreationtime;
		BYTE issuer[8]; // key ID
		time_t keyexpirationtime;
		BYTE psa[255]; // array of 1-octet flags
		BYTE pha[255]; // array of 1-octet flags
		BYTE pca[255]; // array of 1-octet flags
		time_t sigexpirationtime;
		bool exportablecertification;
		bool revocable;
		BYTE trustlevel;
		BYTE trustamount;
		BYTE trustregex[1024]; // string
		BYTE revocationkey_class;
		BYTE revocationkey_pkalgo; // id of public-key algorithm
		BYTE revocationkey_fingerprint[20]; // SHA-1 based fingerprint
		BYTE keyserverpreferences[255]; // array of 1-octet flags
		BYTE preferedkeyserver[1024]; // string
		bool primaryuserid;
		BYTE policyuri[1024]; // string
		BYTE keyflags[255]; // array of 1-octet flags
		BYTE signersuserid[1024]; // string
		BYTE revocationcode;
		BYTE revocationreason[1024]; // string
		BYTE features[255]; // array of 1-octet flags
		BYTE signaturetarget_pkalgo; // id of public-key algorithm
		BYTE signaturetarget_hashalgo; // id of hash algorithm
		BYTE signaturetarget_hash[1024]; // n-octets hash
		BYTE embeddedsignature[4096]; // signature packet body
		BYTE left[2];
		gcry_mpi_t md;
		gcry_mpi_t r;
		gcry_mpi_t s;
		BYTE signingkeyid[8];
		BYTE nestedsignature;
		time_t keycreationtime;
		gcry_mpi_t n;
		gcry_mpi_t e;
		gcry_mpi_t d;
		gcry_mpi_t p;
		gcry_mpi_t q;
		gcry_mpi_t u;
		gcry_mpi_t g;
		gcry_mpi_t y;
		gcry_mpi_t x;
		BYTE compalgo;
		BYTE *compresseddata; // pointer to an allocated buffer with data
		size_t compresseddatalen;
		BYTE *encrypteddata; // pointer to an allocated buffer with data
		size_t encrypteddatalen;
		BYTE dataformat;
		size_t datafilenamelen;
		BYTE datafilename[255]; // filename of specified length
		time_t datatime;
		BYTE *data; // pointer to an allocated buffer with data
		size_t datalen;
		BYTE uid[1024]; // string
		BYTE mdc_hash[20];
	} TMCG_OPENPGP_CONTEXT;

class CallasDonnerhackeFinneyShawThayerRFC4880
{
	private:
		struct notRadix64 {
			bool operator() (char c)
			{
				for (size_t i = 0; i < sizeof(tRadix64); i++)
				{
					if (c == tRadix64[i])
						return false;
				}
				return true;
			}
		};

	public:
		static void Radix64Encode
			(const OCTETS &in, std::string &out);
		static void Radix64Decode
			(std::string in, OCTETS &out);
		static void CRC24Compute
			(const OCTETS &in, OCTETS &out);
		static void CRC24Encode
			(const OCTETS &in, std::string &out);
		static void ArmorEncode
			(const BYTE type, const OCTETS &in, std::string &out);
		static BYTE ArmorDecode
			(const std::string in, OCTETS &out);
		static void FingerprintCompute
			(const OCTETS &in, OCTETS &out); 
		static void KeyidCompute
			(const OCTETS &in, OCTETS &out);
		static void HashCompute
			(const BYTE algo, const OCTETS &in, OCTETS &out);
		static void HashCompute
			(const BYTE algo, const size_t cnt, const OCTETS &in,
			 OCTETS &out);
		static void S2KCompute
			(const BYTE algo, const size_t sklen,
			 const std::string in, const OCTETS &salt, 
			 const bool iterated, const BYTE octcnt, OCTETS &out);

		static void PacketTagEncode
			(const BYTE tag, OCTETS &out); 
		static void PacketLengthEncode
			(size_t len, OCTETS &out);
		static void PacketTimeEncode
			(const time_t in, OCTETS &out);
		static void PacketTimeEncode
			(OCTETS &out);
		static void PacketMPIEncode
			(gcry_mpi_t in, OCTETS &out, size_t &sum);
		static void PacketMPIEncode
			(gcry_mpi_t in, OCTETS &out);
		static size_t PacketMPIDecode
			(const OCTETS &in, gcry_mpi_t &out, size_t &sum);
		static size_t PacketMPIDecode
			(const OCTETS &in, gcry_mpi_t &out);

		static void PacketPkeskEncode
			(const OCTETS &keyid, gcry_mpi_t gk, gcry_mpi_t myk,
			 OCTETS &out);
		static void PacketSigEncode
			(const OCTETS &hashing, const OCTETS &left,
			 gcry_mpi_t r, gcry_mpi_t s, OCTETS &out);
		static void SubpacketEncode
			(const BYTE type, bool critical, const OCTETS &in,
			 OCTETS &out);
		static void PacketSigPrepare
			(const BYTE sigtype, const time_t sigtime,
			 const OCTETS &flags, const OCTETS &keyid, 
			 OCTETS &out);
		static void PacketPubEncode
			(const time_t keytime, gcry_mpi_t p, gcry_mpi_t q,
			 gcry_mpi_t g, gcry_mpi_t y, OCTETS &out);
		static void PacketSecEncode
			(const time_t keytime, gcry_mpi_t p, gcry_mpi_t q, 
			 gcry_mpi_t g, gcry_mpi_t y, gcry_mpi_t x,
			 OCTETS &out);
		static void PacketSubEncode
			(const time_t keytime, gcry_mpi_t p, gcry_mpi_t g, 
			 gcry_mpi_t y, OCTETS &out);
		static void PacketSsbEncode
			(const time_t keytime, gcry_mpi_t p, gcry_mpi_t g, 
			 gcry_mpi_t y, gcry_mpi_t x, OCTETS &out);
		static void PacketSedEncode
			(const OCTETS &in, OCTETS &out);
		static void PacketLitEncode
			(const OCTETS &in, OCTETS &out);
		static void PacketUidEncode
			(const std::string uid, OCTETS &out);
		static void PacketSeipdEncode
			(const OCTETS &in, OCTETS &out);
		static void PacketMdcEncode
			(const OCTETS &in, OCTETS &out);

		static BYTE SubpacketDecode
			(OCTETS &in, TMCG_OPENPGP_CONTEXT &out);
		static BYTE PacketDecode
			(OCTETS &in, TMCG_OPENPGP_CONTEXT &out);

		static gcry_error_t CertificationHash
			(const OCTETS &primary, std::string uid,
			 const OCTETS &trailer, gcry_mpi_t &h, OCTETS &left);
		static gcry_error_t SubkeyBindingHash
			(const OCTETS &primary, const OCTETS &subkey,
			 const OCTETS &trailer, gcry_mpi_t &h, OCTETS &left);
		static gcry_error_t SymmetricEncryptAES256
			(const OCTETS &in, OCTETS &seskey, OCTETS &prefix,
			bool resync, OCTETS &out);
		static gcry_error_t AsymmetricEncryptElgamal
			(const OCTETS &in, const gcry_sexp_t key, 
			 gcry_mpi_t &gk, gcry_mpi_t &myk);
};

#endif

