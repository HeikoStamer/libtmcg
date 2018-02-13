/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.hh, OpenPGP Message Format

     J. Callas, L. Donnerhacke, H. Finney, D. Shaw, R. Thayer:
	'OpenPGP Message Format',
     Network Working Group, Request for Comments: 4880, November 2007. 

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
   along with LibTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH
	#define INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH
	
	// C and STL header
	#include <vector>
	#include <string>
	#include <fstream>
	#include <sstream>
	#include <iostream>
	#include <algorithm>
	#include <ctime>
	#include <inttypes.h>

	// GNU crypto library
	#include <gcrypt.h>

	#include "mpz_srandom.h"
	#include "mpz_helper.hh"

	typedef unsigned char tmcg_openpgp_byte_t;
	typedef std::vector<tmcg_openpgp_byte_t> tmcg_openpgp_octets_t;

	enum tmcg_openpgp_armor_t
	{
		TMCG_OPENPGP_ARMOR_UNKNOWN		= 0,
		TMCG_OPENPGP_ARMOR_MESSAGE		= 1,
		TMCG_OPENPGP_ARMOR_SIGNATURE		= 2,
		TMCG_OPENPGP_ARMOR_MESSAGE_PART_X	= 3,
		TMCG_OPENPGP_ARMOR_MESSAGE_PART_X_Y	= 4,
		TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK	= 5,
		TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK	= 6
	};

	// FIXME(C++11): move following definitions into class
	static const tmcg_openpgp_byte_t tmcg_openpgp_fRadix64[] = {
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255,  62, 255, 255, 255,  63,
			 52,  53,  54,  55,  56,  57,  58,  59,
			 60,  61, 255, 255, 255, 255, 255, 255,
			255,   0,   1,   2,   3,   4,   5,   6,
			  7,   8,   9,  10,  11,  12,  13,  14,
			 15,  16,  17,  18,  19,  20,  21,  22,
			 23,  24,  25, 255, 255, 255, 255, 255,
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
			255, 255, 255, 255, 255, 255, 255, 255
	};
	static const tmcg_openpgp_byte_t tmcg_openpgp_tRadix64[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz0123456789+/";

	typedef struct
	{
		bool newformat;
		tmcg_openpgp_byte_t version;
		tmcg_openpgp_byte_t keyid[8];
		tmcg_openpgp_byte_t pkalgo;
		gcry_mpi_t me;
		gcry_mpi_t gk;
		gcry_mpi_t myk;
		tmcg_openpgp_byte_t type;
		tmcg_openpgp_byte_t hashalgo;
		tmcg_openpgp_byte_t *hspd; // allocated buffer with data
		size_t hspdlen;
		bool critical;
		uint32_t sigcreationtime;
		tmcg_openpgp_byte_t issuer[8]; // key ID
		uint32_t keyexpirationtime;
		tmcg_openpgp_byte_t psa[2048]; // array of 1-octet flags
		tmcg_openpgp_byte_t pha[2048]; // array of 1-octet flags
		tmcg_openpgp_byte_t pca[2048]; // array of 1-octet flags
		uint32_t sigexpirationtime;
		bool exportablecertification;
		bool revocable;
		tmcg_openpgp_byte_t trustlevel;
		tmcg_openpgp_byte_t trustamount;
		tmcg_openpgp_byte_t trustregex[2048]; // string
		tmcg_openpgp_byte_t revocationkey_class;
		tmcg_openpgp_byte_t revocationkey_pkalgo; // id of public-key algorithm
		tmcg_openpgp_byte_t revocationkey_fingerprint[20]; // SHA-1 fingerprint
		tmcg_openpgp_byte_t keyserverpreferences[2048]; // array of 1-octet flags
		tmcg_openpgp_byte_t preferedkeyserver[2048]; // string
		bool primaryuserid;
		tmcg_openpgp_byte_t policyuri[2048]; // string
		tmcg_openpgp_byte_t keyflags[32]; // n-octets of flags
		tmcg_openpgp_byte_t signersuserid[2048]; // string
		tmcg_openpgp_byte_t revocationcode;
		tmcg_openpgp_byte_t revocationreason[2048]; // string
		tmcg_openpgp_byte_t features[32]; // n-octets of flags
		tmcg_openpgp_byte_t signaturetarget_pkalgo; // id of public-key algorithm
		tmcg_openpgp_byte_t signaturetarget_hashalgo; // id of hash algorithm
		tmcg_openpgp_byte_t signaturetarget_hash[2048]; // n-octets hash
		tmcg_openpgp_byte_t embeddedsignature[4096]; // signature packet body
		tmcg_openpgp_byte_t left[2];
		gcry_mpi_t md;
		gcry_mpi_t r;
		gcry_mpi_t s;
		tmcg_openpgp_byte_t signingkeyid[8];
		tmcg_openpgp_byte_t nestedsignature;
		uint32_t keycreationtime;
		gcry_mpi_t n;
		gcry_mpi_t e;
		gcry_mpi_t d;
		gcry_mpi_t p;
		gcry_mpi_t q;
		gcry_mpi_t u;
		gcry_mpi_t g;
		gcry_mpi_t h;
		gcry_mpi_t y;
		gcry_mpi_t x;
		gcry_mpi_t t;
		gcry_mpi_t i;
		gcry_mpi_t qualsize;
		gcry_mpi_t x_rvss_qualsize;
		gcry_mpi_t x_i;
		gcry_mpi_t xprime_i;
		tmcg_openpgp_byte_t symalgo;
		tmcg_openpgp_byte_t s2kconv;
		tmcg_openpgp_byte_t s2k_type;
		tmcg_openpgp_byte_t s2k_hashalgo;
		tmcg_openpgp_byte_t s2k_salt[8];
		tmcg_openpgp_byte_t s2k_count;
		tmcg_openpgp_byte_t iv[32];
		tmcg_openpgp_byte_t *encdata; // allocated buffer with data
		size_t encdatalen;
		tmcg_openpgp_byte_t compalgo;
		tmcg_openpgp_byte_t *compdata; // allocated buffer with data
		size_t compdatalen;
		tmcg_openpgp_byte_t dataformat;
		size_t datafilenamelen;
		tmcg_openpgp_byte_t datafilename[2048]; // filename of specified length
		uint32_t datatime;
		tmcg_openpgp_byte_t *data; // allocated buffer with data
		size_t datalen;
		tmcg_openpgp_byte_t uid[2048]; // string
		tmcg_openpgp_byte_t mdc_hash[20];
	} tmcg_openpgp_packet_ctx_t;

class TMCG_OpenPGP_Signature
{
	private:
		gcry_error_t ret;
		size_t erroff;

	public:
		tmcg_openpgp_byte_t pkalgo;
		tmcg_openpgp_byte_t hashalgo;
		tmcg_openpgp_byte_t type;
		tmcg_openpgp_byte_t version;
		time_t creationtime;
		time_t expirationtime;
		time_t keyexpirationtime;
		tmcg_openpgp_byte_t keyflags[32];
		gcry_sexp_t signature;
		gcry_mpi_t rsa_md;
		gcry_mpi_t dsa_r;
		gcry_mpi_t dsa_s;
		tmcg_openpgp_octets_t packet;
		tmcg_openpgp_octets_t hspd;

		TMCG_OpenPGP_Signature
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const tmcg_openpgp_byte_t hashalgo_in,
			 const tmcg_openpgp_byte_t type_in,
			 const tmcg_openpgp_byte_t version_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const time_t keyexpirationtime_in,
			 const tmcg_openpgp_byte_t* keyflags_in,
			 const gcry_mpi_t md,
			 const tmcg_openpgp_octets_t &packet_in,
			 const tmcg_openpgp_octets_t &hspd_in);
		TMCG_OpenPGP_Signature
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const tmcg_openpgp_byte_t hashalgo_in,
			 const tmcg_openpgp_byte_t type_in,
			 const tmcg_openpgp_byte_t version_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const time_t keyexpirationtime_in,
			 const tmcg_openpgp_byte_t* keyflags_in,
			 const gcry_mpi_t r,
			 const gcry_mpi_t s,
			 const tmcg_openpgp_octets_t &packet_in,
			 const tmcg_openpgp_octets_t &hspd_in);
		bool good
			() const;
		~TMCG_OpenPGP_Signature
			();
};

class TMCG_OpenPGP_UserID
{
	public:
		std::string userid;
		tmcg_openpgp_octets_t packet;
		std::vector<TMCG_OpenPGP_Signature*> selfsigs;
		std::vector<TMCG_OpenPGP_Signature*> revsigs;
		std::vector<TMCG_OpenPGP_Signature*> certsigs;

		TMCG_OpenPGP_UserID
			(const std::string &userid_in,
			 const tmcg_openpgp_octets_t &packet_in);
		~TMCG_OpenPGP_UserID
			();
};

class TMCG_OpenPGP_Subkey
{
	private:
		gcry_error_t ret;
		size_t erroff;

	public:
		tmcg_openpgp_byte_t pkalgo;
		time_t creationtime;
		time_t expirationtime;
		gcry_sexp_t key;
		tmcg_openpgp_octets_t packet;
		tmcg_openpgp_octets_t id;
		std::vector<TMCG_OpenPGP_Signature*> selfsigs;
		std::vector<TMCG_OpenPGP_Signature*> bindsigs;
		std::vector<TMCG_OpenPGP_Signature*> revsigs;

		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const gcry_mpi_t n,
			 const gcry_mpi_t e,
			 const tmcg_openpgp_octets_t &packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const gcry_mpi_t p,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 const tmcg_openpgp_octets_t &packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 const tmcg_openpgp_octets_t &packet_in);
		bool good
			() const;
		~TMCG_OpenPGP_Subkey
			();
};

class TMCG_OpenPGP_Pubkey
{
	private:
		gcry_error_t ret;
		size_t erroff;

	public:
		tmcg_openpgp_byte_t pkalgo;
		time_t creationtime;
		time_t expirationtime;
		gcry_sexp_t key;
		tmcg_openpgp_octets_t packet;
		tmcg_openpgp_octets_t pub_hashing;
		tmcg_openpgp_octets_t id;
		tmcg_openpgp_byte_t flags[32];
		std::vector<TMCG_OpenPGP_Signature*> selfsigs;
		std::vector<TMCG_OpenPGP_Signature*> revsigs;
		std::vector<TMCG_OpenPGP_UserID*> userids;
		std::vector<TMCG_OpenPGP_Subkey*> subkeys;

		TMCG_OpenPGP_Pubkey
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const gcry_mpi_t n,
			 const gcry_mpi_t e,
			 const tmcg_openpgp_octets_t &packet_in);
		TMCG_OpenPGP_Pubkey
			(const tmcg_openpgp_byte_t pkalgo_in,
			 const time_t creationtime_in,
			 const time_t expirationtime_in,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 const tmcg_openpgp_octets_t &packet_in);
		bool good
			() const;
		bool CheckSelfSignatures
			(const int verbose);
		~TMCG_OpenPGP_Pubkey
			();
};

class CallasDonnerhackeFinneyShawThayerRFC4880
{
	private:
		struct notRadix64 {
			bool operator() (const char c)
			{
				for (size_t i = 0; i < sizeof(tmcg_openpgp_tRadix64); i++)
				{
					if (c == tmcg_openpgp_tRadix64[i])
						return false;
				}
				return true;
			}
		};

	public:
		static size_t AlgorithmKeyLength
			(const tmcg_openpgp_byte_t algo);
		static size_t AlgorithmIVLength
			(const tmcg_openpgp_byte_t algo);
		static int AlgorithmSymGCRY
			(const tmcg_openpgp_byte_t algo);
		static size_t AlgorithmHashLength
			(const tmcg_openpgp_byte_t algo);
		static int AlgorithmHashGCRY
			(const tmcg_openpgp_byte_t algo);
		static void AlgorithmHashGCRYName
			(const tmcg_openpgp_byte_t algo,
			 std::string &out);
		static bool OctetsCompare
			(const tmcg_openpgp_octets_t &in,
			 const tmcg_openpgp_octets_t &in2);
		static bool OctetsCompareConstantTime
			(const tmcg_openpgp_octets_t &in,
			 const tmcg_openpgp_octets_t &in2);
		static bool OctetsCompareZero
			(const tmcg_openpgp_octets_t &in);

		static void Radix64Encode
			(const tmcg_openpgp_octets_t &in,
			 std::string &out,
			 bool linebreaks = true);
		static void Radix64Decode
			(std::string in,
			 tmcg_openpgp_octets_t &out);
		static void CRC24Compute
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void CRC24Encode
			(const tmcg_openpgp_octets_t &in,
			 std::string &out);
		static void ArmorEncode
			(const tmcg_openpgp_armor_t type,
			 const tmcg_openpgp_octets_t &in,
			 std::string &out);
		static tmcg_openpgp_armor_t ArmorDecode
			(const std::string &in,
			 tmcg_openpgp_octets_t &out);
		static void FingerprintCompute
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out); 
		static void KeyidCompute
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void HashCompute
			(const tmcg_openpgp_byte_t algo,
			 const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void HashCompute
			(const tmcg_openpgp_byte_t algo,
			 const size_t cnt,
			 const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static bool HashComputeFile
			(const tmcg_openpgp_byte_t algo,
			 const std::string &filename,
			 const tmcg_openpgp_octets_t &trailer,
			 tmcg_openpgp_octets_t &out);
		static void S2KCompute
			(const tmcg_openpgp_byte_t algo,
			 const size_t sklen,
			 const std::string &in,
			 const tmcg_openpgp_octets_t &salt, 
			 const bool iterated,
			 const tmcg_openpgp_byte_t octcnt,
			 tmcg_openpgp_octets_t &out);

		static void PacketTagEncode
			(const tmcg_openpgp_byte_t tag,
			 tmcg_openpgp_octets_t &out); 
		static void PacketLengthEncode
			(const size_t len,
			 tmcg_openpgp_octets_t &out);
		static size_t PacketLengthDecode
			(const tmcg_openpgp_octets_t &in,
			 const bool newformat,
			 tmcg_openpgp_byte_t lentype,
			 uint32_t &len,
			 bool &partlen);
		static void PacketTimeEncode
			(const time_t in,
			 tmcg_openpgp_octets_t &out);
		static void PacketTimeEncode
			(tmcg_openpgp_octets_t &out);
		static void PacketMPIEncode
			(const gcry_mpi_t in,
			 tmcg_openpgp_octets_t &out,
			 size_t &sum);
		static void PacketMPIEncode
			(const gcry_mpi_t in,
			 tmcg_openpgp_octets_t &out);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_octets_t &in,
			 gcry_mpi_t &out, size_t &sum);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_octets_t &in,
			 gcry_mpi_t &out);
		static void PacketStringEncode
			(const std::string &in,
			 tmcg_openpgp_octets_t &out);
		static size_t PacketStringDecode
			(const tmcg_openpgp_octets_t &in,
			 std::string &out);

		static void PacketPkeskEncode
			(const tmcg_openpgp_octets_t &keyid,
			 const gcry_mpi_t gk,
			 const gcry_mpi_t myk,
			 tmcg_openpgp_octets_t &out);
		static void PacketSigEncode
			(const tmcg_openpgp_octets_t &hashing,
			 const tmcg_openpgp_octets_t &left,
			 const gcry_mpi_t r,
			 const gcry_mpi_t s,
			 tmcg_openpgp_octets_t &out);
		static void SubpacketEncode
			(const tmcg_openpgp_byte_t type,
			 bool critical,
			 const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void PacketSigPrepareSelfSignature
			(const tmcg_openpgp_byte_t sigtype,
			 const tmcg_openpgp_byte_t hashalgo, 
			 const time_t sigtime,
			 const time_t keyexptime,
			 const tmcg_openpgp_octets_t &flags,
			 const tmcg_openpgp_octets_t &issuer, 
			 tmcg_openpgp_octets_t &out);
		static void PacketSigPrepareDetachedSignature
			(const tmcg_openpgp_byte_t sigtype,
			 const tmcg_openpgp_byte_t hashalgo, 
			 const time_t sigtime,
			 const time_t sigexptime,
			 const tmcg_openpgp_octets_t &issuer, 
			 tmcg_openpgp_octets_t &out);
		static void PacketSigPrepareRevocationSignature
			(const tmcg_openpgp_byte_t sigtype,
			 const tmcg_openpgp_byte_t hashalgo, 
			 const time_t sigtime,
			 const tmcg_openpgp_byte_t revcode,
			 const std::string &reason,
			 const tmcg_openpgp_octets_t &issuer, 
			 tmcg_openpgp_octets_t &out);
		static void PacketSigPrepareCertificationSignature
			(const tmcg_openpgp_byte_t sigtype,
			 const tmcg_openpgp_byte_t hashalgo, 
			 const time_t sigtime,
			 const time_t sigexptime,
			 const std::string &policy,
			 const tmcg_openpgp_octets_t &issuer,
			 tmcg_openpgp_octets_t &out);
		static void PacketPubEncode
			(const time_t keytime,
			 const tmcg_openpgp_byte_t algo,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 tmcg_openpgp_octets_t &out);
		static void PacketSecEncode
			(const time_t keytime,
			 const tmcg_openpgp_byte_t algo,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 const gcry_mpi_t x,
			 const std::string &passphrase,
			 tmcg_openpgp_octets_t &out);
		static void PacketSecEncodeExperimental108
			(const time_t keytime,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t h,
			 const gcry_mpi_t y,
			 const gcry_mpi_t n,
			 const gcry_mpi_t t,
			 const gcry_mpi_t i,
			 const gcry_mpi_t qualsize,
			 const std::vector<gcry_mpi_t> &qual,
			 const std::vector<std::string> &capl,
			 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
			 const gcry_mpi_t x_i,
			 const gcry_mpi_t xprime_i,
			 const std::string &passphrase,
			 tmcg_openpgp_octets_t &out);
		static void PacketSecEncodeExperimental107
			(const time_t keytime,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t h,
			 const gcry_mpi_t y,
			 const gcry_mpi_t n,
			 const gcry_mpi_t t,
			 const gcry_mpi_t i,
			 const gcry_mpi_t qualsize,
			 const std::vector<gcry_mpi_t> &qual,
			 const gcry_mpi_t x_rvss_qualsize,
			 const std::vector<gcry_mpi_t> &x_rvss_qual,
			 const std::vector<std::string> &capl,
			 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
			 const gcry_mpi_t x_i,
			 const gcry_mpi_t xprime_i,
			 const std::string &passphrase,
			 tmcg_openpgp_octets_t &out);
		static void PacketSubEncode
			(const time_t keytime,
			 const tmcg_openpgp_byte_t algo,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y,
			 tmcg_openpgp_octets_t &out);
		static void PacketSsbEncode
			(const time_t keytime,
			 const tmcg_openpgp_byte_t algo,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t y, 
			 const gcry_mpi_t x,
			 const std::string &passphrase,
			 tmcg_openpgp_octets_t &out);
		static void PacketSsbEncodeExperimental109
			(const time_t keytime,
			 const gcry_mpi_t p,
			 const gcry_mpi_t q,
			 const gcry_mpi_t g,
			 const gcry_mpi_t h,
			 const gcry_mpi_t y,
			 const gcry_mpi_t n,
			 const gcry_mpi_t t,
			 const gcry_mpi_t i,
			 const gcry_mpi_t qualsize,
			 const std::vector<gcry_mpi_t> &qual,
			 const std::vector<gcry_mpi_t> &v_i,
			 const std::vector< std::vector<gcry_mpi_t> > &c_ik,
			 const gcry_mpi_t x_i,
			 const gcry_mpi_t xprime_i,
			 const std::string &passphrase,
			 tmcg_openpgp_octets_t &out);
		static void PacketSedEncode
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void PacketLitEncode
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void PacketUidEncode
			(const std::string &uid,
			 tmcg_openpgp_octets_t &out);
		static void PacketSeipdEncode
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);
		static void PacketMdcEncode
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &out);

		static tmcg_openpgp_byte_t SubpacketDecode
			(tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_packet_ctx_t &out);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_packet_ctx_t &out,
			 tmcg_openpgp_octets_t &current_packet,
			 std::vector<gcry_mpi_t> &qual,
			 std::vector<gcry_mpi_t> &x_rvss_qual,
			 std::vector<std::string> &capl,
			 std::vector<gcry_mpi_t> &v_i,
			 std::vector< std::vector<gcry_mpi_t> > &c_ik);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_packet_ctx_t &out,
			 tmcg_openpgp_octets_t &current_packet,
			 std::vector<gcry_mpi_t> &qual,
			 std::vector<std::string> &capl,
			 std::vector<gcry_mpi_t> &v_i,
			 std::vector< std::vector<gcry_mpi_t> > &c_ik);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_packet_ctx_t &out,
			 tmcg_openpgp_octets_t &current_packet);
		static void ReleasePacketContext
			(tmcg_openpgp_packet_ctx_t &ctx);

		static bool BinaryDocumentHashV3
			(const std::string &filename,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static bool BinaryDocumentHash
			(const std::string &filename,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void CertificationHashV3
			(const tmcg_openpgp_octets_t &key,
			 const std::string &uid,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void CertificationHash
			(const tmcg_openpgp_octets_t &key,
			 const std::string &uid,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void SubkeyBindingHashV3
			(const tmcg_openpgp_octets_t &primary,
			 const tmcg_openpgp_octets_t &subkey,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void SubkeyBindingHash
			(const tmcg_openpgp_octets_t &primary,
			 const tmcg_openpgp_octets_t &subkey,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void KeyRevocationHashV3
			(const tmcg_openpgp_octets_t &key,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void KeyRevocationHash
			(const tmcg_openpgp_octets_t &key,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void KeyRevocationHashV3
			(const tmcg_openpgp_octets_t &primary,
			 const tmcg_openpgp_octets_t &subkey,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);
		static void KeyRevocationHash
			(const tmcg_openpgp_octets_t &primary,
			 const tmcg_openpgp_octets_t &subkey,
			 const tmcg_openpgp_octets_t &trailer,
			 const tmcg_openpgp_byte_t hashalgo,
			 tmcg_openpgp_octets_t &hash,
			 tmcg_openpgp_octets_t &left);

		static gcry_error_t SymmetricEncryptAES256
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &seskey,
			 tmcg_openpgp_octets_t &prefix,
			 const bool resync,
			 tmcg_openpgp_octets_t &out);
		static gcry_error_t SymmetricDecrypt
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &seskey,
			 tmcg_openpgp_octets_t &prefix,
			 const bool resync,
			 const tmcg_openpgp_byte_t algo,
			 tmcg_openpgp_octets_t &out);
		static gcry_error_t SymmetricDecryptAES256
			(const tmcg_openpgp_octets_t &in,
			 tmcg_openpgp_octets_t &seskey,
			 tmcg_openpgp_octets_t &prefix,
			 const bool resync,
			 tmcg_openpgp_octets_t &out);
		static gcry_error_t AsymmetricEncryptElgamal
			(const tmcg_openpgp_octets_t &in,
			 const gcry_sexp_t key, 
			 gcry_mpi_t &gk,
			 gcry_mpi_t &myk);
		static gcry_error_t AsymmetricDecryptElgamal
			(const gcry_mpi_t gk,
			 const gcry_mpi_t myk,
			 const gcry_sexp_t key,
			 tmcg_openpgp_octets_t &out);
		static gcry_error_t AsymmetricSignDSA
			(const tmcg_openpgp_octets_t &in,
			 const gcry_sexp_t key,
			 gcry_mpi_t &r,
			 gcry_mpi_t &s);
		static gcry_error_t AsymmetricVerifyDSA
			(const tmcg_openpgp_octets_t &in,
			 const gcry_sexp_t key, 
	 		 const gcry_mpi_t r,
			 const gcry_mpi_t s);
		static gcry_error_t AsymmetricSignRSA
			(const tmcg_openpgp_octets_t &in,
			 const gcry_sexp_t key,
			 const tmcg_openpgp_byte_t hashalgo, 
			 gcry_mpi_t &s);
		static gcry_error_t AsymmetricVerifyRSA
			(const tmcg_openpgp_octets_t &in,
			 const gcry_sexp_t key,
			 const tmcg_openpgp_byte_t hashalgo, 
	 		 const gcry_mpi_t s);

		static bool ParsePublicKeyBlock
			(const std::string &in, const int verbose,
			 TMCG_OpenPGP_Pubkey* &pub);
};

#endif

