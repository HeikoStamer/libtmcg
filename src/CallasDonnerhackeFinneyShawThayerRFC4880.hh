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
		static void SHA256Compute
			(const OCTETS &in, OCTETS &out);

		static void PacketTagEncode
			(size_t tag, OCTETS &out); 
		static void PacketLengthEncode
			(size_t len, OCTETS &out);
		static void PacketTimeEncode
			(OCTETS &out);
		static void PacketMPIEncode
			(gcry_mpi_t in, OCTETS &out, size_t &sum);
		static void PacketMPIEncode
			(gcry_mpi_t in, OCTETS &out);

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
			(const BYTE sigtype, const OCTETS &flags,
			 const OCTETS &keyid, OCTETS &out);
		static void PacketPubEncode
			(gcry_mpi_t p, gcry_mpi_t q, gcry_mpi_t g, 
			 gcry_mpi_t y, OCTETS &out);
		static void PacketSecEncode
			(gcry_mpi_t p, gcry_mpi_t q, gcry_mpi_t g, 
			 gcry_mpi_t y, gcry_mpi_t x, OCTETS &out);
		static void PacketSubEncode
			(gcry_mpi_t p, gcry_mpi_t g, gcry_mpi_t y,
			 OCTETS &out);
		static void PacketSsbEncode
			(gcry_mpi_t p, gcry_mpi_t g, gcry_mpi_t y,
			 gcry_mpi_t x, OCTETS &out);
		static void PacketSedEncode
			(const OCTETS &in, OCTETS &out);
		static void PacketLitEncode
			(const OCTETS &in, OCTETS &out);
		static void PacketUidEncode
			(const std::string uid, OCTETS &out);

		static gcry_error_t CertificationHash
			(const OCTETS &primary, std::string uid,
			 const OCTETS &trailer, gcry_mpi_t &h, OCTETS &left);
		static gcry_error_t SubkeyBindingHash
			(const OCTETS &primary, const OCTETS &subkey,
			 const OCTETS &trailer, gcry_mpi_t &h, OCTETS &left);
		static gcry_error_t SymmetricEncrypt
			(const OCTETS &in, OCTETS &seskey, OCTETS &out);
		static gcry_error_t AsymmetricEncrypt
			(const OCTETS &in, const gcry_sexp_t key, 
			 gcry_mpi_t &gk, gcry_mpi_t &myk);
};

#endif

