/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.cc, OpenPGP Message Format

     J. Callas, L. Donnerhacke, H. Finney, D. Shaw, R. Thayer:
	'OpenPGP Message Format',
     Network Working Group, Request for Comments: 4880, November 2007. 

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
#include "CallasDonnerhackeFinneyShawThayerRFC4880.hh"

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength
	(const tmcg_byte_t algo)
{
	switch (algo)
	{
		case 0: // Plaintext or unencrypted data
			return 0;
		case 1: // IDEA
			return 16;
		case 2: // TripleDES (DES-EDE, 168 bit key derived from 192)
			return 24;
		case 3: // CAST5 (128 bit key, as per [RFC2144])
			return 16;
		case 4: // Blowfish (128 bit key, 16 rounds)
			return 16;
		case 7: // AES with 128-bit key
			return 16;
		case 8: // AES with 192-bit key
			return 24;
		case 9: // AES with 256-bit key
			return 32;
		case 10: // Twofish with 256-bit key
			return 32;
		default:
			return 0;
	}
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength
	(const tmcg_byte_t algo)
{
	// Most ciphers have a block size of 8 octets. The AES and
	// Twofish have a block size of 16 octets.
	// [...]
	// If secret data is encrypted (string-to-key usage octet
	// not zero), an Initial Vector (IV) of the same length as the
	// cipher’s block size.
	switch (algo)
	{
		case 0: // Plaintext or unencrypted data
			return 0;
		case 1: // IDEA
		case 2: // TripleDES
		case 3: // CAST5
		case 4: // Blowfish
			return 8;
		case 7: // AES with 128-bit key
		case 8: // AES with 192-bit key
		case 9: // AES with 256-bit key
		case 10: // Twofish with 256-bit key
			return 16;
		default:
			return 0;
	}
}

int CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmSymGCRY
	(const tmcg_byte_t algo)
{
	switch (algo)
	{
		case 0: // Plaintext or unencrypted data
			return GCRY_CIPHER_NONE;
		case 1: // IDEA
			return GCRY_CIPHER_IDEA;
		case 2: // TripleDES (DES-EDE, 168 bit key derived from 192)
			return GCRY_CIPHER_3DES;
		case 3: // CAST5 (128 bit key, as per [RFC2144])
			return GCRY_CIPHER_CAST5;
		case 4: // Blowfish (128 bit key, 16 rounds)
			return GCRY_CIPHER_BLOWFISH;
		case 7: // AES with 128-bit key
			return GCRY_CIPHER_AES;
		case 8: // AES with 192-bit key
			return GCRY_CIPHER_AES192;
		case 9: // AES with 256-bit key
			return GCRY_CIPHER_AES256;
		case 10: // Twofish with 256-bit key
			return GCRY_CIPHER_TWOFISH;
		default:
			return 0;
	}
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashLength
	(const tmcg_byte_t algo)
{
	switch (algo)
	{
		case 1: // MD5
			return 16;
		case 2: // SHA-1
		case 3: // RIPE-MD/160
			return 20;
		case 8: // SHA256
			return 32;
		case 9: // SHA384
			return 48;
		case 10: // SHA512
			return 64;
		case 11: // SHA224
			return 28;
		default:
			return 0;
	}
}

int CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmHashGCRY
	(const tmcg_byte_t algo)
{
	switch (algo)
	{
		case 1: // MD5
			return GCRY_MD_MD5;
		case 2: // SHA-1
			return GCRY_MD_SHA1;
		case 3: // RIPE-MD/160
			return GCRY_MD_RMD160;
		case 8: // SHA256
			return GCRY_MD_SHA256;
		case 9: // SHA384
			return GCRY_MD_SHA384;
		case 10: // SHA512
			return GCRY_MD_SHA512;
		case 11: // SHA224
			return GCRY_MD_SHA224;
		default:
			return 0;
	}
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare
	(const tmcg_octets_t &in, const tmcg_octets_t &in2)
{
	if (in.size() != in2.size())
		return false;
	for (size_t i = 0; i < in.size(); i++)
		if (in[i] != in2[i])
			return false;
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero
	(const tmcg_octets_t &in)
{
	for (size_t i = 0; i < in.size(); i++)
		if (in[i] != 0x00)
			return false;
	return true;
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode
	(const tmcg_octets_t &in, std::string &out, bool linebreaks)
{
	size_t len = in.size();
	size_t i = 0, c = 1;

	// Each 6-bit group is used as an index into an array of 
	// 64 printable characters from the table below. The character
	// referenced by the index is placed in the output string.
	for (; len >= 3; len -= 3, i += 3)
	{
		tmcg_byte_t l[4];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2) + ((in[i+2] & 0xC0) >> 6);
		l[3] = in[i+2] & 0x3F;
		for (size_t j = 0; j < 4; j++, c++)
		{
			assert(l[j] < 64);
			out += tmcg_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (((c % TMCG_OPENPGP_RADIX64_MC) == 0) && ((len >= 4) || (j < 3)) && linebreaks)
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
		tmcg_byte_t l[3];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2);
		for (size_t j = 0; j < 3; j++, c++)
		{
			out += tmcg_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (linebreaks && ((c % TMCG_OPENPGP_RADIX64_MC) == 0))
				out += "\r\n"; // add a line delimiter
		}
		out += "=";
	}
	else if (len == 1)
	{
		tmcg_byte_t l[2];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4);
		for (size_t j = 0; j < 2; j++, c++)
		{
			out += tmcg_tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (linebreaks && ((c % TMCG_OPENPGP_RADIX64_MC) == 0))
				out += "\r\n"; // add a line delimiter
		}
		out += "==";
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Decode
	(std::string in, tmcg_octets_t &out)
{
	// remove all whitespaces, delimiters and other non-radix64 characters
	in.erase(std::remove_if(in.begin(), in.end(), notRadix64()), in.end());

	size_t len = in.size();
	for (size_t j = 0; j < (4 - (len % 4)); j++)
		in += "="; // append pad until a multiple of four reached
	for (size_t i = 0; i < len; i += 4)
	{
        	tmcg_byte_t l[4];
		for (size_t j = 0; j < 4; j++)
			l[j] = tmcg_fRadix64[(size_t)in[i+j]];
		tmcg_byte_t t[3];
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
	(const tmcg_octets_t &in, tmcg_octets_t &out)
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
	out.push_back(crc >> 16);
	out.push_back(crc >> 8);
	out.push_back(crc);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CRC24Encode
	(const tmcg_octets_t &in, std::string &out)
{
	tmcg_octets_t crc;

	// The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted
	// to four characters of radix-64 encoding by the same MIME base64
	// transformation, preceded by an equal sign (=).
	out += "=";
	CRC24Compute(in, crc);
	Radix64Encode(crc, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode
	(const tmcg_byte_t type, const tmcg_octets_t &in, std::string &out)
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
		case 1:
			out += "-----BEGIN PGP MESSAGE-----\r\n";
			break;
		case 2:
			out += "-----BEGIN PGP SIGNATURE-----\r\n";
			break;
		case 5:
			out += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
			break;
		case 6:
			out += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
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
		case 1:
			out += "-----END PGP MESSAGE-----\r\n";
			break;
		case 2:
			out += "-----END PGP SIGNATURE-----\r\n";
			break;
		case 5:
			out += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
			break;
		case 6:
			out += "-----END PGP PUBLIC KEY BLOCK-----\r\n";
			break;
	}
}

tmcg_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode
	(const std::string &in, tmcg_octets_t &out)
{
	tmcg_byte_t type = 0;
	size_t spos = 0, rpos = 0, rlen = 4, cpos = 0, clen = 3, epos = 0;

	rpos = in.find("\r\n\r\n");
	if (rpos == in.npos)
	{
		rpos = in.find("\n\n");
		rlen = 2;
	}
	cpos = in.find("\r\n="); // FIXME: does not work in all cases (use regex for detecting checksum start)
	if (cpos == in.npos)
	{
		cpos = in.find("\n=");
		clen = 2;
	}
	if ((rpos == in.npos) || (cpos == in.npos))
		return 0; // no radix-64 start or checksum found in armor body
	spos = in.find("-----BEGIN PGP MESSAGE-----");
	epos = in.find("-----END PGP MESSAGE-----");
	if ((spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = 1;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP SIGNATURE-----");
		epos = in.find("-----END PGP SIGNATURE-----");
	}		
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = 2;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP PRIVATE KEY BLOCK-----");
		epos = in.find("-----END PGP PRIVATE KEY BLOCK-----");
	}		
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = 5;
	if (!type)
	{
		spos = in.find("-----BEGIN PGP PUBLIC KEY BLOCK-----");
		epos = in.find("-----END PGP PUBLIC KEY BLOCK-----");
	}
	if (!type && (spos != in.npos) && (epos != in.npos) && (epos > spos))
		type = 6;
	if (!type)
		return 0; // no armor header or trailer line found
	if (((spos + 26) < rpos) && ((rpos + rlen) < cpos) && ((cpos + clen + 4) < epos))
	{
		if (in.find("-----", spos + 34) != epos)
			return 0; // nested armor block detected
		tmcg_octets_t decoded_data;
		std::string chksum = "";
		std::string data = in.substr(rpos + rlen, cpos - rpos - rlen);
		Radix64Decode(data, decoded_data);
		CRC24Encode(decoded_data, chksum);
		if (chksum != in.substr(cpos + (clen - 1), 5))
			return 0; // checksum error detected
		out.insert(out.end(), decoded_data.begin(), decoded_data.end());
		return type;
	}
	else
	{
		std::cerr << "ERROR: ArmorDecode() spos = " << spos << " rpos = " << rpos << " cpos = " << cpos << " epos = " << epos << std::endl; 
		return 0;
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute
	(const tmcg_octets_t &in, tmcg_octets_t &out)
{
	tmcg_byte_t *buffer = new tmcg_byte_t[in.size() + 3]; // additional 3 bytes needed
	tmcg_byte_t *hash = new tmcg_byte_t[20]; // fixed output size of SHA-1

	// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	// followed by the two-octet packet length, followed by the entire
	// Public-Key packet starting with the version field.
	buffer[0] = 0x99;
	buffer[1] = in.size() >> 8;
	buffer[2] = in.size();
	for (size_t i = 0; i < in.size(); i++)
		buffer[3+i] = in[i];
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, in.size() + 3); 
	for (size_t i = 0; i < 20; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute
	(const tmcg_octets_t &in, tmcg_octets_t &out)
{
	tmcg_octets_t fpr;

	// A Key ID is an eight-octet scalar that identifies a key.
	// Implementations SHOULD NOT assume that Key IDs are unique.
	// [...]
	// The Key ID is the low-order 64 bits of the fingerprint.
	FingerprintCompute(in, fpr);
	for (size_t i = 12; i < 20; i++)
		out.push_back(fpr[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_byte_t algo, const tmcg_octets_t &in, tmcg_octets_t &out)
{
	int a = AlgorithmHashGCRY(algo);
	size_t dlen = gcry_md_get_algo_dlen(a);
	tmcg_byte_t *buffer = new tmcg_byte_t[in.size()];
	tmcg_byte_t *hash = new tmcg_byte_t[dlen];

	for (size_t i = 0; i < in.size(); i++)
		buffer[i] = in[i];
	gcry_md_hash_buffer(a, hash, buffer, in.size()); 
	for (size_t i = 0; i < dlen; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const tmcg_byte_t algo, const size_t cnt, const tmcg_octets_t &in,
	 tmcg_octets_t &out)
{
	size_t c = in.size();
	int a = AlgorithmHashGCRY(algo);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, 0);
	if (ret || (hd == NULL))
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
	tmcg_byte_t *hash = gcry_md_read(hd, a);
	if (hash != NULL)
	{
		size_t dlen = gcry_md_get_algo_dlen(a);
		for (size_t i = 0; i < dlen; i++)
			out.push_back(hash[i]);
	}
	gcry_md_close(hd);
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::HashComputeFile
	(const tmcg_byte_t algo, const std::string &filename,
	 const tmcg_octets_t &trailer, tmcg_octets_t &out)
{
	char c;
	int a = AlgorithmHashGCRY(algo);
	gcry_error_t ret;
	gcry_md_hd_t hd;

	ret = gcry_md_open(&hd, a, 0);
	if (ret || (hd == NULL))
		return false;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		gcry_md_close(hd);
		return false;
	}
	while (ifs.get(c))
		gcry_md_putc(hd, c);
	if (!ifs.eof())
	{
		ifs.close();
		gcry_md_close(hd);
		return false;
	}
	ifs.close();
	for (size_t i = 0; i < trailer.size(); i++)
		gcry_md_putc(hd, trailer[i]);
	tmcg_byte_t *hash = gcry_md_read(hd, a);
	if (hash != NULL)
	{
		size_t dlen = gcry_md_get_algo_dlen(a);
		for (size_t i = 0; i < dlen; i++)
			out.push_back(hash[i]);
	}
	gcry_md_close(hd);
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute
	(const tmcg_byte_t algo, const size_t sklen, const std::string &in, 
	 const tmcg_octets_t &salt, const bool iterated, const tmcg_byte_t octcnt, 
	 tmcg_octets_t &out)
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
		tmcg_octets_t hash_in, hash_out;
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
			tmcg_octets_t hash_in, hash_out;
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

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTagEncode
	(const tmcg_byte_t tag, tmcg_octets_t &out)
{
	// use V4 packet format
	out.push_back(tag | 0x80 | 0x40);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketLengthEncode
	(const size_t len, tmcg_octets_t &out)
{
	// use scalar length format
	out.push_back(0xFF);
	out.push_back(len >> 24);
	out.push_back(len >> 16);
	out.push_back(len >> 8);
	out.push_back(len);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketLengthDecode
	(const tmcg_octets_t &in, bool newformat, tmcg_byte_t lentype,
	uint32_t &len, bool &partlen)
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
		return 0; // error: indeterminate length is not supported
	}
	else
		return 0; // error: unknown length type 
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(const time_t in, tmcg_octets_t &out)
{
	// A time field is an unsigned four-octet number containing the number
	// of seconds elapsed since midnight, 1 January 1970 UTC.
	out.push_back(in >> 24);
	out.push_back(in >> 16);
	out.push_back(in >> 8);
	out.push_back(in);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(tmcg_octets_t &out)
{
	time_t current = time(NULL);
	PacketTimeEncode(current, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(const gcry_mpi_t in, tmcg_octets_t &out, size_t &sum)
{
	gcry_error_t ret;
	size_t bitlen = gcry_mpi_get_nbits(in);
	size_t buflen = ((bitlen + 7) / 8) + 2;
	tmcg_byte_t *buffer = new tmcg_byte_t[buflen];

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
	(const gcry_mpi_t in, tmcg_octets_t &out)
{
	size_t sum = 0;
	PacketMPIEncode(in, out, sum);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const tmcg_octets_t &in, gcry_mpi_t &out, size_t &sum)
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
	tmcg_byte_t *buffer = new tmcg_byte_t[buflen];
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
	(const tmcg_octets_t &in, gcry_mpi_t &out)
{
	size_t sum = 0;
	return PacketMPIDecode(in, out, sum);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketStringEncode
	(const std::string &in, tmcg_octets_t &out)
{
	PacketLengthEncode(in.length(), out);
	for (size_t i = 0; i < in.length(); i++)
		out.push_back(in[i]);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketStringDecode
	(const tmcg_octets_t &in, std::string &out)
{
	size_t headlen = 0;
	uint32_t len = 0;
	bool partlen = false;

	headlen = PacketLengthDecode(in, true, 0x00, len, partlen);
	if (!headlen || partlen)
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
	(const tmcg_octets_t &keyid, const gcry_mpi_t gk, const gcry_mpi_t myk, 
	 tmcg_octets_t &out)
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
	out.push_back(16); // public-key algorithm: Elgamal
	PacketMPIEncode(gk, out); // MPI g**k mod p
	PacketMPIEncode(myk, out); // MPI m * y**k mod p
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode
	(const tmcg_octets_t &hashing, const tmcg_octets_t &left, const gcry_mpi_t r, 
	 const gcry_mpi_t s, tmcg_octets_t &out)
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
	out.push_back(0 >> 8); // length of unhashed subpacket data
	out.push_back(0);
	// signature data
	out.insert(out.end(), left.begin(), left.end()); // 16 bits of hash
	PacketMPIEncode(r, out); // signature - MPI r
	PacketMPIEncode(s, out); // signature - MPI s
}

void CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketEncode
	(const tmcg_byte_t type, bool critical, const tmcg_octets_t &in,
	 tmcg_octets_t &out)
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
	PacketLengthEncode(in.size() + 1, out);
	if (critical)
		out.push_back(type | 0x80);
	else
		out.push_back(type);
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareSelfSignature
	(const tmcg_byte_t sigtype, const tmcg_byte_t hashalgo,
	 const time_t sigtime, const time_t keyexptime, 
	 const tmcg_octets_t &flags, const tmcg_octets_t &issuer, 
	 tmcg_octets_t &out)
{
	size_t subpkts = 7;
	size_t subpktlen = (subpkts * 6) + 4 + 1 + issuer.size() + 1 + 1 + flags.size() + 1;
	if (keyexptime != 0)
		subpktlen += (6 + 4);
	out.push_back(4); // V4 format
	out.push_back(sigtype); // type (e.g. 0x13 UID cert., 0x18 subkey bind.)
	out.push_back(17); // public-key algorithm: DSA
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back(subpktlen >> 8); // length of hashed subpacket data
	out.push_back(subpktlen);
		// signature creation time
		tmcg_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// key expiration time
		if (keyexptime != 0)
		{
			tmcg_octets_t subpkt_keyexptime;
			PacketTimeEncode(keyexptime, subpkt_keyexptime);
			SubpacketEncode(9, false, subpkt_keyexptime, out);
		}
		// preferred symmetric algorithms
		tmcg_octets_t psa;
		psa.push_back(9); // AES256
		SubpacketEncode(11, false, psa, out);
		// issuer
		SubpacketEncode(16, false, issuer, out);
		// preferred hash algorithms
		tmcg_octets_t pha;
		pha.push_back(8); // SHA256
		SubpacketEncode(21, false, pha, out);
		// preferred compression algorithms
		tmcg_octets_t pca;
		pca.push_back(0); // uncompressed
		SubpacketEncode(22, false, pca, out);
		// key flags
		SubpacketEncode(27, false, flags, out);
		// features
		tmcg_octets_t features;
		features.push_back(0x01); // Modification Detection (packets 18 and 19)
		SubpacketEncode(30, false, features, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareDetachedSignature
	(const tmcg_byte_t sigtype, const tmcg_byte_t hashalgo, 
	 const time_t sigtime, const time_t sigexptime, 
	 const tmcg_octets_t &issuer, 
	 tmcg_octets_t &out)
{
	size_t subpkts = 2;
	size_t subpktlen = (subpkts * 6) + 4 + issuer.size();
	if (sigexptime != 0)
		subpktlen += (6 + 4);
	out.push_back(4); // V4 format
	out.push_back(sigtype); // type (e.g. 0x00 Binary Document)
	out.push_back(17); // public-key algorithm: DSA
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back(subpktlen >> 8); // length of hashed subpacket data
	out.push_back(subpktlen);
		// signature creation time
		tmcg_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// signature expiration time
		if (sigexptime != 0)
		{
			tmcg_octets_t subpkt_sigexptime;
			PacketTimeEncode(sigexptime, subpkt_sigexptime);
			SubpacketEncode(3, false, subpkt_sigexptime, out);
		}
		// issuer
		SubpacketEncode(16, false, issuer, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepareRevocationSignature
	(const tmcg_byte_t sigtype, const tmcg_byte_t hashalgo, 
	 const time_t sigtime, const tmcg_byte_t revcode,
	 const std::string &reason, const tmcg_octets_t &issuer, 
	 tmcg_octets_t &out)
{
	size_t subpkts = 3;
	size_t subpktlen = (subpkts * 6) + 4 + issuer.size() + 1 + reason.length();
	out.push_back(4); // V4 format
	out.push_back(sigtype); // type (e.g. 0x20 key revocation, 0x28 subkey revocation)
	out.push_back(17); // public-key algorithm: DSA
	out.push_back(hashalgo); // hash algorithm
	// hashed subpacket area
	out.push_back(subpktlen >> 8); // length of hashed subpacket data
	out.push_back(subpktlen);
		// signature creation time
		tmcg_octets_t subpkt_sigtime;
		PacketTimeEncode(sigtime, subpkt_sigtime);
		SubpacketEncode(2, false, subpkt_sigtime, out);
		// issuer
		SubpacketEncode(16, false, issuer, out);
		// reason for revocation
		tmcg_octets_t subpkt_reason;
		subpkt_reason.push_back(revcode); // machine-readable code
		for (size_t i = 0; i < reason.length(); i++)
			subpkt_reason.push_back(reason[i]);
		SubpacketEncode(29, false, subpkt_reason, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode
	(const time_t keytime, const tmcg_byte_t algo, const gcry_mpi_t p,
	 const gcry_mpi_t q, const gcry_mpi_t g, const gcry_mpi_t y,
	 tmcg_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case 16: // public-key algorithm: Elgamal
			len += 2+plen+2+glen+2+ylen;
			break;
		case 17: // public-key algorithm: DSA
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
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
		case 16: // public-key algorithm: Elgamal
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case 17: // public-key algorithm: DSA
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode
	(const time_t keytime, const tmcg_byte_t algo, const gcry_mpi_t p,
	 const gcry_mpi_t q, const gcry_mpi_t g, const gcry_mpi_t y,
	 const gcry_mpi_t x, const std::string &passphrase,
	 tmcg_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case 16: // public-key algorithm: Elgamal
			len += 2+plen+2+glen+2+ylen;
			break;
		case 17: // public-key algorithm: DSA
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
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
		case 16: // public-key algorithm: Elgamal
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case 17: // public-key algorithm: DSA
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
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
		out.push_back(chksum >> 8); // two-octet checksum
		out.push_back(chksum);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier given + SHA-1 hash
		out.push_back(9); // AES256
		out.push_back(0x03); // Iterated and Salted S2K
		out.push_back(8); // SHA256
		tmcg_byte_t rand[8], iv[16], key[32], count;
		tmcg_octets_t salt, plain, hash, seskey;
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
		S2KCompute(8, sizeof(key), passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < sizeof(key); i++)
			key[i] = seskey[i];
		PacketMPIEncode(x, plain); // MPI x
		HashCompute(2, plain, hash); // compute 20-octet SHA-1 hash
		plain.insert(plain.end(), hash.begin(), hash.end()); // append hash
		tmcg_byte_t *buffer = new tmcg_byte_t[plain.size()];
		for (size_t i = 0; i < plain.size(); i++)
			buffer[i] = plain[i];
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setkey(hd, key, sizeof(key));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_encrypt(hd, buffer, plain.size(), NULL, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buffer[i]);
		delete [] buffer;
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
	 const std::string &passphrase,
	 tmcg_octets_t &out)
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
	assert((qual.size() == get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((qual.size() == capl.size()));
	for (size_t j = 0; j < capl.size(); j++)
		len += 5+capl[j].length();
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+2+qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(5, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(108); // public-key algo: ID 108 (private/experimental) 
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
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back(chksum >> 8); // two-octet checksum
		out.push_back(chksum);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier given + SHA-1 hash
		out.push_back(9); // AES256
		out.push_back(0x03); // Iterated and Salted S2K
		out.push_back(8); // SHA256
		tmcg_byte_t rand[8], iv[16], key[32], count;
		tmcg_octets_t salt, plain, hash, seskey;
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
		S2KCompute(8, sizeof(key), passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < sizeof(key); i++)
			key[i] = seskey[i];
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		HashCompute(2, plain, hash); // compute 20-octet SHA-1 hash
		plain.insert(plain.end(), hash.begin(), hash.end()); // append hash
		tmcg_byte_t *buffer = new tmcg_byte_t[plain.size()];
		for (size_t i = 0; i < plain.size(); i++)
			buffer[i] = plain[i];
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setkey(hd, key, sizeof(key));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_encrypt(hd, buffer, plain.size(), NULL, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buffer[i]);
		delete [] buffer;
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
	 const std::string &passphrase,
	 tmcg_octets_t &out)
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
	size_t x_rvss_qualsizelen = (gcry_mpi_get_nbits(x_rvss_qualsize) + 7) / 8;
	size_t x_ilen = (gcry_mpi_get_nbits(x_i) + 7) / 8;
	size_t xprime_ilen = (gcry_mpi_get_nbits(xprime_i) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	assert((qual.size() == get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((x_rvss_qual.size() == get_gcry_mpi_ui(x_rvss_qualsize)));
	for (size_t j = 0; j < x_rvss_qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(x_rvss_qual[j]) + 7) / 8);
	assert((capl.size() == get_gcry_mpi_ui(n)));
	assert((qual.size() <= capl.size()));
	assert((x_rvss_qual.size() <= capl.size()));
	for (size_t j = 0; j < capl.size(); j++)
		len += 5+capl[j].length();
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+2+qualsizelen+2+x_rvss_qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(5, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(107); // public-key algo: ID 107 (private/experimental) 
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
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back(chksum >> 8); // two-octet checksum
		out.push_back(chksum);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier given + SHA-1 hash
		out.push_back(9); // AES256
		out.push_back(0x03); // Iterated and Salted S2K
		out.push_back(8); // SHA256
		tmcg_byte_t rand[8], iv[16], key[32], count;
		tmcg_octets_t salt, plain, hash, seskey;
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
		S2KCompute(8, sizeof(key), passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < sizeof(key); i++)
			key[i] = seskey[i];
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		HashCompute(2, plain, hash); // compute 20-octet SHA-1 hash
		plain.insert(plain.end(), hash.begin(), hash.end()); // append hash
		tmcg_byte_t *buffer = new tmcg_byte_t[plain.size()];
		for (size_t i = 0; i < plain.size(); i++)
			buffer[i] = plain[i];
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setkey(hd, key, sizeof(key));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_encrypt(hd, buffer, plain.size(), NULL, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buffer[i]);
		delete [] buffer;
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode
	(const time_t keytime, const tmcg_byte_t algo, const gcry_mpi_t p,
	 const gcry_mpi_t q, const gcry_mpi_t g, const gcry_mpi_t y,
	 tmcg_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case 16: // public-key algorithm: Elgamal
			len += 2+plen+2+glen+2+ylen;
			break;
		case 17: // public-key algorithm: DSA
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
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
		case 16: // public-key algorithm: Elgamal
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case 17: // public-key algorithm: DSA
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode
	(const time_t keytime, const tmcg_byte_t algo, const gcry_mpi_t p,
	 const gcry_mpi_t q, const gcry_mpi_t g, const gcry_mpi_t y,
	 const gcry_mpi_t x, const std::string &passphrase,
	 tmcg_octets_t &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;
	size_t len = 1+4+1; // number of octets for version, keytime, and algo
	switch (algo)
	{
		case 16: // public-key algorithm: Elgamal
			len += 2+plen+2+glen+2+ylen;
			break;
		case 17: // public-key algorithm: DSA
			len += 2+plen+2+qlen+2+glen+2+ylen;
			break;
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
		case 16: // public-key algorithm: Elgamal
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
		case 17: // public-key algorithm: DSA
			PacketMPIEncode(p, out); // MPI p
			PacketMPIEncode(q, out); // MPI q
			PacketMPIEncode(g, out); // MPI g
			PacketMPIEncode(y, out); // MPI y
			break;
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x, out, chksum); // MPI x
		out.push_back(chksum >> 8); // two-octet checksum
		out.push_back(chksum);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier given + SHA-1 hash
		out.push_back(9); // AES256
		out.push_back(0x03); // Iterated and Salted S2K
		out.push_back(8); // SHA256
		tmcg_byte_t rand[8], iv[16], key[32], count;
		tmcg_octets_t salt, plain, hash, seskey;
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
		S2KCompute(8, sizeof(key), passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < sizeof(key); i++)
			key[i] = seskey[i];
		PacketMPIEncode(x, plain); // MPI x
		HashCompute(2, plain, hash); // compute 20-octet SHA-1 hash
		plain.insert(plain.end(), hash.begin(), hash.end()); // append hash
		tmcg_byte_t *buffer = new tmcg_byte_t[plain.size()];
		for (size_t i = 0; i < plain.size(); i++)
			buffer[i] = plain[i];
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setkey(hd, key, sizeof(key));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_encrypt(hd, buffer, plain.size(), NULL, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buffer[i]);
		delete [] buffer;
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
	 const std::string &passphrase,
	 tmcg_octets_t &out)
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
	assert((qual.size() == get_gcry_mpi_ui(qualsize)));
	for (size_t j = 0; j < qual.size(); j++)
		len += 2+((gcry_mpi_get_nbits(qual[j]) + 7) / 8);
	assert((v_i.size() == get_gcry_mpi_ui(n)));
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
		len += 2+((gcry_mpi_get_nbits(v_i[j]) + 7) / 8);
	assert((c_ik.size() == get_gcry_mpi_ui(n)));
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			len += 2+((gcry_mpi_get_nbits(c_ik[j][k]) + 7) / 8);
	}
	len += 2+plen+2+qlen+2+glen+2+hlen+2+ylen+2+nlen+2+tlen+2+ilen+2+qualsizelen;
	if (passphrase.length() == 0)
		len += 1+2+x_ilen+2+xprime_ilen+2; // S2K usage is zero
	else
		len += 29+2+x_ilen+2+xprime_ilen+20; // S2K usage is 254
	PacketTagEncode(7, out);
	PacketLengthEncode(len, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(keytime, out);
	out.push_back(109); // public-key algo: ID 109 (private/experimental) 
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
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
		PacketMPIEncode(v_i[j], out); // MPI v_i[j]
	for (size_t j = 0; j < get_gcry_mpi_ui(n); j++)
	{
		for (size_t k = 0; k <= get_gcry_mpi_ui(t); k++)
			PacketMPIEncode(c_ik[j][k], out); // MPI c_ik[j][k]
	}
	if (passphrase.length() == 0)
	{
		size_t chksum = 0;
		out.push_back(0); // S2K convention: no encryption
		PacketMPIEncode(x_i, out, chksum); // MPI x_i
		PacketMPIEncode(xprime_i, out, chksum); // MPI xprime_i
		out.push_back(chksum >> 8); // two-octet checksum
		out.push_back(chksum);
	}
	else
	{
		out.push_back(254); // S2K convention: specifier given + SHA-1 hash
		out.push_back(9); // AES256
		out.push_back(0x03); // Iterated and Salted S2K
		out.push_back(8); // SHA256
		tmcg_byte_t rand[8], iv[16], key[32], count;
		tmcg_octets_t salt, plain, hash, seskey;
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
		S2KCompute(8, sizeof(key), passphrase, salt, true, count, seskey);
		for (size_t i = 0; i < sizeof(key); i++)
			key[i] = seskey[i];
		PacketMPIEncode(x_i, plain); // MPI x_i
		PacketMPIEncode(xprime_i, plain); // MPI xprime_i
		HashCompute(2, plain, hash); // compute 20-octet SHA-1 hash
		plain.insert(plain.end(), hash.begin(), hash.end()); // append hash
		tmcg_byte_t *buffer = new tmcg_byte_t[plain.size()];
		for (size_t i = 0; i < plain.size(); i++)
			buffer[i] = plain[i];
		gcry_cipher_hd_t hd;
		gcry_error_t ret;
		ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setkey(hd, key, sizeof(key));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_setiv(hd, iv, sizeof(iv));
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		ret = gcry_cipher_encrypt(hd, buffer, plain.size(), NULL, 0);
		if (ret)
		{
			delete [] buffer;
			gcry_cipher_close(hd);
			return;
		}
		for (size_t i = 0; i < plain.size(); i++)
			out.push_back(buffer[i]);
		delete [] buffer;
		gcry_cipher_close(hd);
	}
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode
	(const tmcg_octets_t &in, tmcg_octets_t &out)
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
	(const tmcg_octets_t &in, tmcg_octets_t &out)
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
	(const std::string &uid, tmcg_octets_t &out)
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
	(const tmcg_octets_t &in, tmcg_octets_t &out)
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
	PacketLengthEncode(in.size() + 1, out);
	out.push_back(1); // version
	out.insert(out.end(), in.begin(), in.end());
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode
	(const tmcg_octets_t &in, tmcg_octets_t &out)
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

// ===========================================================================

tmcg_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketDecode
	(tmcg_octets_t &in, tmcg_openpgp_packet_ctx &out)
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
		// A one-octet Body Length header encodes a length of 0 to
		// 191 octets. This type of length header is recognized
		// because the one octet value is less than 192.
		headlen += 1;
		len = in[0];
	}
	else if (in[0] < 224)
	{
		if (in.size() < 3)
			return 0; // error: too few octets of length encoding
		// A two-octet Body Length header encodes a length of 192 to
		// 8383 octets. It is recognized because its first octet is
		// in the range 192 to 223.
		headlen += 2;
		len = ((in[0] - 192) << 8) + in[1] + 192;
	}
	else if (in[0] == 255)
	{
		if (in.size() < 6)
			return 0; // error: too few octets of length encoding
		// A five-octet Body Length header consists of a single octet
		// holding the value 255, followed by a four-octet scalar.
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
	tmcg_byte_t type = in[headlen-1];
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
	tmcg_octets_t pkt;
	pkt.insert(pkt.end(), in.begin()+headlen, in.begin()+headlen+len);
	switch (type)
	{
		case 2: // Signature Creation Time 
			if (pkt.size() != 4)
				return 0; // error: incorrect subpacket body 
			out.sigcreationtime = (pkt[0] << 24) + (pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
			break;
		case 3: // Signature Expiration Time
			if (pkt.size() != 4)
				return 0; // error: incorrect subpacket body 
			out.sigexpirationtime = (pkt[0] << 24) + (pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
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
			out.keyexpirationtime = (pkt[0] << 24) + (pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
			break;
		case 11: // Preferred Symmetric Algorithms
			if (pkt.size() > sizeof(out.psa))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.psa[i] = pkt[i]; 
			break;
		case 12: // Revocation Key
			if (pkt.size() != 22)
				return 0; // error: incorrect subpacket body
			out.revocationkey_class = pkt[0];
			out.revocationkey_pkalgo = pkt[1];
			for (size_t i = 0; i < 20; i++)
				out.revocationkey_fingerprint[i] = pkt[2+i]; 
			break;
		case 16: // Issuer
			if (pkt.size() != 8)
				return 0; // error: incorrect subpacket body
			for (size_t i = 0; i < 8; i++)
				out.issuer[i] = pkt[i];
			break;
		case 20: // Notation Data -- not implemented; ignore subpacket
			{
			bool notation_human_readable = false;
			if (pkt.size() < 8)
				return 0; // error: incorrect subpacket body
			if (pkt[0] == 0x80) // First octet: 0x80=human-readable
				notation_human_readable = true;
			else
				return 0; // error: undefined notation flag
			size_t notation_name_length = (pkt[4] << 8) + pkt[5];
			size_t notation_value_length = (pkt[6] << 8) + pkt[7];
			if (pkt.size() != (notation_name_length + notation_value_length + 8))
				return 0; // error: incorrect length
			// TODO: store notation data in a given container
			}
			break;
		case 21: // Preferred Hash Algorithms
			if (pkt.size() > sizeof(out.pha))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.pha[i] = pkt[i]; 
			break;
		case 22: // Preferred Compression Algorithms
			if (pkt.size() > sizeof(out.pca))
				return 0; // error: too long subpacket body
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
			out.revocationcode = pkt[0];
			for (size_t i = 0; i < (pkt.size() - 1); i++)
				out.revocationreason[i] = pkt[1+i];
			break;
		case 30: // Features
			if (pkt.size() > sizeof(out.features))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.features[i] = pkt[i]; 
			break;
		case 31: // Signature Target
			if (pkt.size() < 2)
				return 0; // error: too short subpacket body
			out.signaturetarget_pkalgo = pkt[0];
			out.signaturetarget_hashalgo = pkt[1];
			if (pkt.size() > (sizeof(out.signaturetarget_hash) + 2))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < (pkt.size() - 2); i++)
				out.signaturetarget_hash[i] = pkt[2+i];
			break;
		case 32: // Embedded Signature
			if (pkt.size() > sizeof(out.embeddedsignature))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.embeddedsignature[i] = pkt[i]; 
			break;
		case 100: // Private or experimental -- not yet impl.; ignore
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
			break;
		default: // unknown subpacket type; ignore
			break; 
	}
	in.erase(in.begin(), in.begin()+headlen+len); // remove subpacket
	return type;
}

tmcg_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(tmcg_octets_t &in, tmcg_openpgp_packet_ctx &out,
	 tmcg_octets_t &current_packet,
	 std::vector<gcry_mpi_t> &qual,
	 std::vector<std::string> &capl,
	 std::vector<gcry_mpi_t> &v_i,
	 std::vector< std::vector<gcry_mpi_t> > &c_ik)
{
	std::vector<gcry_mpi_t> x_rvss_qual; // dummy container
	tmcg_byte_t ret = PacketDecode(in, out, current_packet, qual, x_rvss_qual, capl, v_i, c_ik);
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		gcry_mpi_release(x_rvss_qual[i]); // release allocated mpi's
	x_rvss_qual.clear();
	return ret;
}

tmcg_byte_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(tmcg_octets_t &in, tmcg_openpgp_packet_ctx &out,
	 tmcg_octets_t &current_packet,
	 std::vector<gcry_mpi_t> &qual,
	 std::vector<gcry_mpi_t> &x_rvss_qual,
	 std::vector<std::string> &capl,
	 std::vector<gcry_mpi_t> &v_i,
	 std::vector< std::vector<gcry_mpi_t> > &c_ik)
{
	memset(&out, 0, sizeof(out)); // clear output context
	// Exportable Certification: If this packet is not present, the
	// certification is exportable; it is equivalent to a flag 
	// containing a 1.
	out.exportablecertification = true; 
	// Revocable: If this packet is not present, the signature is
	// revocable.
	out.revocable = true;
	if (in.size() < 2)
		return 0; // error: incorrect packet header
	tmcg_byte_t tag = in[0];
	tmcg_byte_t lentype = 0x00;
	current_packet.push_back(tag); // store packet header
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
	in.erase(in.begin(), in.begin()+1); // remove first octet
	// Each Partial Body Length header is followed by a portion of the
	// packet body data. The Partial Body Length header specifies this
	// portion's length. Another length header (one octet, two-octet,
	// five-octet, or partial) follows that portion. The last length
	// header in the packet MUST NOT be a Partial Body Length header.
	// Partial Body Length headers may only be used for the non-final
	// parts of the packet.
	tmcg_octets_t pkt;
	uint32_t len = 0;
	bool partlen = true, firstlen = true;
	while (partlen)
	{
		size_t headlen = PacketLengthDecode(in, out.newformat, lentype, len, partlen);
		if (!headlen)
			return 0; // error: invalid length header
		if (in.size() < (headlen + len))
			return 0; // error: packet too short
		// An implementation MAY use Partial Body Lengths for data
		// packets, be they literal, compressed, or encrypted. The
		// first partial length MUST be at least 512 octets long.
		// Partial Body Lengths MUST NOT be used for any other packet
		// types.
		if (partlen && firstlen && (len < 512))
			return 0; // error: first partial length less than 512 octets
		if (partlen && (tag != 8) && (tag != 9) && (tag != 11) && (tag != 18))
			return 0; // error: no literal, compressed, or encrypted
		current_packet.insert(current_packet.end(), in.begin(), in.begin()+headlen+len); // copy length and content of the (partial) packet
		pkt.insert(pkt.end(), in.begin()+headlen, in.begin()+headlen+len);
		in.erase(in.begin(), in.begin()+headlen+len); // remove (partial) packet
		firstlen = false;
	}
	tmcg_byte_t sptype = 0xFF;
	tmcg_octets_t hspd, uspd, mpis;
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
			out.pkalgo = pkt[9];
			mpis.insert(mpis.end(), pkt.begin()+10, pkt.end());
			if ((out.pkalgo == 1) || (out.pkalgo == 2))
			{
				// Algorithm-Specific Fields for RSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.me);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 16)
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
			else
				return 0xFE; // warning: unsupported public-key algo
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
					return 0; // error: incorrect length of hashed material
				out.type = pkt[2];
				out.sigcreationtime = (pkt[3] << 24) + (pkt[4] << 16) + (pkt[5] << 8) + pkt[6];
				for (size_t i = 0; i < 8; i++)
					out.issuer[i] = pkt[7+i]; // Key ID of signer
				out.pkalgo = pkt[15];
				out.hashalgo = pkt[16];
				for (size_t i = 0; i < 2; i++)
					out.left[i] = pkt[17+i]; // left 16 bits of signed hash value
				mpis.insert(mpis.end(), pkt.begin()+19, pkt.end());
			}
			else if (out.version == 4)
			{
				if (pkt.size() < 12)
					return 0; // error: packet too short
				out.type = pkt[1];
				out.pkalgo = pkt[2];
				out.hashalgo = pkt[3];
				hspdlen = (pkt[4] << 8) + pkt[5];
				if (pkt.size() < (6 + hspdlen))
					return 0; // error: packet too short
				hspd.insert(hspd.end(), pkt.begin()+6, pkt.begin()+6+hspdlen);
				out.hspdlen = hspdlen;
				out.hspd = new tmcg_byte_t[out.hspdlen];
				for (size_t i = 0; i < out.hspdlen; i++)
					out.hspd[i] = pkt[6+i];
				while (hspd.size() && sptype)
                		{
					sptype = SubpacketDecode(hspd, out);
					if (sptype == 0)
						return 0; // error: incorrect subpacket
				}
				if (pkt.size() < (8 + hspdlen))
					return 0; // error: packet too short
				uspdlen = (pkt[6+hspdlen] << 8) + pkt[7+hspdlen];
				if (pkt.size() < (8 + hspdlen + uspdlen))
					return 0; // error: packet too short
				uspd.insert(uspd.end(), pkt.begin()+8+hspdlen, pkt.begin()+8+hspdlen+uspdlen);
				// If a subpacket is not hashed, then the information
				// in it cannot be considered definitive because it 
				// is not part of the signature proper.
				tmcg_openpgp_packet_ctx untrusted;
				while (uspd.size() && sptype)
                		{
					sptype = SubpacketDecode(uspd, untrusted);
					if (sptype == 0)
						return 0; // error: incorrect subpacket
					if (sptype == 16) // copy only the Issuer of signature
					{
						for (size_t i = 0; i < sizeof(out.issuer); i++)
							out.issuer[i] = untrusted.issuer[i];
					}					
				}
				if (pkt.size() < (10 + hspdlen + uspdlen))
					return 0; // error: packet too short
				for (size_t i = 0; i < 2; i++)
					out.left[i] = pkt[8+hspdlen+uspdlen+i]; // left 16 bits of signed hash value
				mpis.insert(mpis.end(), pkt.begin()+10+hspdlen+uspdlen, pkt.end());
			}
			else
				return 0xFE; // warning: version not supported
			if ((out.pkalgo == 1) || (out.pkalgo == 3))
			{
				// Algorithm-Specific Fields for RSA
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.md);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 17)
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
			else
				return 0xFE; // warning: unsupported public-key algo
			break;
		case 3: // Symmetric-Key Encrypted Session Key Packet
			if (pkt.size() < 4)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.symalgo = pkt[1];
			out.s2k_type = pkt[2];
			out.s2k_hashalgo = pkt[3];
			if (out.s2k_type == 0x00)
			{
				// Simple S2K -- not permitted by RFC 4880
				out.encdatalen = pkt.size() - 4;
				if (out.encdatalen == 0)
					break; // no encrypted session key
				out.encdata = new tmcg_byte_t[out.encdatalen];
				for (size_t i = 0; i < out.encdatalen; i++)
					out.encdata[i] = pkt[4+i];
			}
			else if (out.s2k_type == 0x01)
			{
				// Salted S2K
				if (pkt.size() < 12)
					return 0; // error: no salt
				for (size_t i = 0; i < 8; i++)
					out.s2k_salt[i] = pkt[4+i];
				out.encdatalen = pkt.size() - 12;
				if (out.encdatalen == 0)
					break; // no encrypted session key
				out.encdata = new tmcg_byte_t[out.encdatalen];
				for (size_t i = 0; i < out.encdatalen; i++)
					out.encdata[i] = pkt[12+i];
			}
			else if (out.s2k_type == 0x03)
			{
				// Iterated and Salted S2K
				if (pkt.size() < 12)
					return 0; // error: no salt
				for (size_t i = 0; i < 8; i++)
					out.s2k_salt[i] = pkt[4+i];
				if (pkt.size() < 13)
					return 0; // error: no count
				out.s2k_count = pkt[12];
				out.encdatalen = pkt.size() - 13;
				if (out.encdatalen == 0)
					break; // no encrypted session key
				out.encdata = new tmcg_byte_t[out.encdatalen];
				for (size_t i = 0; i < out.encdatalen; i++)
					out.encdata[i] = pkt[13+i];
			}
			else
				return 0; // unknown S2K specifier
			break;
		case 4: // One-Pass Signature Packet
			if (pkt.size() != 13)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 3)
				return 0; // error: version not supported
			out.type = pkt[1];
			out.hashalgo = pkt[2];
			out.pkalgo = pkt[3];
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
			out.keycreationtime = (pkt[1] << 24) + (pkt[2] << 16) + (pkt[3] << 8) + pkt[4];
			out.pkalgo = pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
			if ((out.pkalgo >= 1) && (out.pkalgo <= 3))
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
			else if (out.pkalgo == 16)
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
			else if (out.pkalgo == 17)
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
			else if (out.pkalgo == 107)
			{
				// Algorithm-Specific Fields for new tDSS keys
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
				if (get_gcry_mpi_ui(out.qualsize) > 255)
					return 0; // error: too many parties
				qual.resize(get_gcry_mpi_ui(out.qualsize));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.qualsize); j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				mlen = PacketMPIDecode(mpis, out.x_rvss_qualsize);
				if (!mlen || (mlen > mpis.size()))
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (get_gcry_mpi_ui(out.x_rvss_qualsize) > 255)
					return 0; // error: too many parties
				x_rvss_qual.resize(get_gcry_mpi_ui(out.x_rvss_qualsize));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.x_rvss_qualsize); j++)
				{
					mlen = PacketMPIDecode(mpis, x_rvss_qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				if ((get_gcry_mpi_ui(out.n) > 255) || (get_gcry_mpi_ui(out.t) > 128)
					|| (get_gcry_mpi_ui(out.i) >= get_gcry_mpi_ui(out.n)))
					return 0; // error: too many parties, bad threshold or bad index
				capl.clear();
				for (size_t j = 0; j < get_gcry_mpi_ui(out.n); j++)
				{
					std::string peerid;
					mlen = PacketStringDecode(mpis, peerid);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					capl.push_back(peerid);
				}
				c_ik.resize(get_gcry_mpi_ui(out.n));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.n); j++)
				{
					c_ik[j].resize(get_gcry_mpi_ui(out.t) + 1);
					for (size_t k = 0; k <= get_gcry_mpi_ui(out.t); k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error: bad or zero mpi
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
					}
				}
			}
			else if (out.pkalgo == 108)
			{
				// Algorithm-Specific Fields for tDSS keys
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
				if (get_gcry_mpi_ui(out.qualsize) > 255)
					return 0; // error: too many parties
				qual.resize(get_gcry_mpi_ui(out.qualsize));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.qualsize); j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				capl.clear();
				for (size_t j = 0; j < get_gcry_mpi_ui(out.qualsize); j++)
				{
					std::string peerid;
					mlen = PacketStringDecode(mpis, peerid);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					capl.push_back(peerid);
				}
				if ((get_gcry_mpi_ui(out.n) > 255) || (get_gcry_mpi_ui(out.t) > 128))
					return 0; // error: too many parties or bad threshold
				c_ik.resize(get_gcry_mpi_ui(out.n));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.n); j++)
				{
					c_ik[j].resize(get_gcry_mpi_ui(out.t) + 1);
					for (size_t k = 0; k <= get_gcry_mpi_ui(out.t); k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error: bad or zero mpi
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
					}
				}
			}
			else if (out.pkalgo == 109)
			{
				// Algorithm-Specific Fields for DKG keys
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
				if (get_gcry_mpi_ui(out.qualsize) > 255)
					return 0; // error: too many parties
				qual.resize(get_gcry_mpi_ui(out.qualsize));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.qualsize); j++)
				{
					mlen = PacketMPIDecode(mpis, qual[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				if ((get_gcry_mpi_ui(out.n) > 255) || (get_gcry_mpi_ui(out.t) > 128))
					return 0; // error: too many parties or bad threshold
				v_i.resize(get_gcry_mpi_ui(out.n));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.n); j++)
				{
					mlen = PacketMPIDecode(mpis, v_i[j]);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad or zero mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				c_ik.resize(get_gcry_mpi_ui(out.n));
				for (size_t j = 0; j < get_gcry_mpi_ui(out.n); j++)
				{
					c_ik[j].resize(get_gcry_mpi_ui(out.t) + 1);
					for (size_t k = 0; k <= get_gcry_mpi_ui(out.t); k++)
					{
						mlen = PacketMPIDecode(mpis, c_ik[j][k]);
						if (!mlen || (mlen > mpis.size()))
							return 0; // error: bad or zero mpi
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
				// not encrypted + checksum
				size_t chksum = 0;
				if ((out.pkalgo == 16) || (out.pkalgo == 17))
				{
					// Algorithm-Specific Fields for Elgamal
					// and DSA keys
					mlen = PacketMPIDecode(mpis, out.x, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else if ((out.pkalgo >= 1) && (out.pkalgo <= 3))
				{
					// Algorithm-Specific Fields for RSA keys
					mlen = PacketMPIDecode(mpis, out.d, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(mpis, out.p, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(mpis, out.q, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(mpis, out.u, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
				}
				else if ((out.pkalgo == 107) || (out.pkalgo == 108) || (out.pkalgo == 109))
				{
					// Algorithm-Specific Fields for tDSS/DKG keys
					mlen = PacketMPIDecode(mpis, out.x_i, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
					mpis.erase(mpis.begin(), mpis.begin()+mlen);
					mlen = PacketMPIDecode(mpis, out.xprime_i, chksum);
					if (!mlen || (mlen > mpis.size()))
						return 0; // error: bad mpi
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
				out.symalgo = mpis[0];
				mpis.erase(mpis.begin(), mpis.begin()+1);
				if (mpis.size() < 2)
					return 0; // error: bad S2K specifier
				out.s2k_type = mpis[0];
				out.s2k_hashalgo = mpis[1];
				mpis.erase(mpis.begin(), mpis.begin()+2);
				if (out.s2k_type == 0x00)
				{
					// Simple S2K
				}
				else if (out.s2k_type == 0x01)
				{
					// Salted S2K
					if (mpis.size() < 8)
						return 0; // error: no salt
					for (size_t i = 0; i < 8; i++)
						out.s2k_salt[i] = mpis[i];
					mpis.erase(mpis.begin(), mpis.begin()+8);
				}
				else if (out.s2k_type == 0x03)
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
				size_t ivlen = AlgorithmIVLength(out.symalgo);
				if (mpis.size() < ivlen)
					return 0; // error: no IV
				if (ivlen > sizeof(out.iv))
					return 0; // error: IV too long
				for (size_t i = 0; i < ivlen; i++)
					out.iv[i] = mpis[i];
				mpis.erase(mpis.begin(), mpis.begin()+ivlen);
				if (mpis.size() < 4)
					return 0; // error: bad encrypted data
				out.encdatalen = mpis.size();
				out.encdata = new tmcg_byte_t[out.encdatalen];
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
			out.keycreationtime = (pkt[1] << 24) + (pkt[2] << 16) + (pkt[3] << 8) + pkt[4];
			out.pkalgo = pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
			if ((out.pkalgo >= 1) && (out.pkalgo <= 3))
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
			else if (out.pkalgo == 16)
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
			else if (out.pkalgo == 17)
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
			else
				return 0xFE; // warning: unsupported public-key algo
			break;
		case 8: // Compressed Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.compalgo = pkt[0];
			if (out.compalgo > 3)
				return 0; // error: algorithm not supported
			out.compdatalen = pkt.size() - 1;
			out.compdata = new tmcg_byte_t[out.compdatalen];
			for (size_t i = 0; i < out.compdatalen; i++)
				out.compdata[i] = pkt[1+i];
			break;
		case 9: // Symmetrically Encrypted Data Packet
			if (pkt.size() == 0)
				return 0; // error: empty packet body
			out.encdatalen = pkt.size();
			out.encdata = new tmcg_byte_t[out.encdatalen];
			for (size_t i = 0; i < out.encdatalen; i++)
				out.encdata[i] = pkt[i];
			break;
		case 10: // Marker Packet
			if (pkt.size() != 3)
				return 0; // error: incorrect packet body
			if ((pkt[0] != 0x50) || (pkt[1] != 0x47) || (pkt[3] != 0x50))
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
			out.datatime = (pkt[3+out.datafilenamelen] << 24) + (pkt[4+out.datafilenamelen] << 16) +
				(pkt[5+out.datafilenamelen] << 8) + pkt[6+out.datafilenamelen];
			out.datalen = pkt.size() - (out.datafilenamelen + 6);
			out.data = new tmcg_byte_t[out.datalen];
			for (size_t i = 0; i < out.datalen; i++)
				out.data[i] = pkt[6+out.datafilenamelen+i];
			break;
		case 12: // Trust Packet -- not supported, ignore silently
			break;
		case 13: // User ID Packet
			if (pkt.size() >= sizeof(out.uid))
				return 0; // error: packet too long
			for (size_t i = 0; i < pkt.size(); i++)
				out.uid[i] = pkt[i];
			break;
		case 17: // User Attribute Packet -- not supported, ignore silently
			break;
		case 18: // Sym. Encrypted and Integrity Protected Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 1)
				return 0; // error: version not supported
			out.encdatalen = pkt.size() - 1;
			out.encdata = new tmcg_byte_t[out.encdatalen];
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
		default:
			return 0; // error: unknown packet tag
	}
	return tag;
}

// ===========================================================================

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHashV3
	(const std::string &filename, const tmcg_octets_t &trailer, 
	 const tmcg_byte_t hashalgo, tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

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
	if (!HashComputeFile(hashalgo, filename, hash_input, hash))
		return false;
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
	return true;
}

bool CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash
	(const std::string &filename, const tmcg_octets_t &trailer, 
	 const tmcg_byte_t hashalgo, tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

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
	PacketLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	if (!HashComputeFile(hashalgo, filename, hash_input, hash))
		return false;
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
	return true;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHashV3
	(const tmcg_octets_t &key, const std::string &uid, 
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo,
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.)
	hash_input.push_back(0x99);
	hash_input.push_back(key.size() >> 8);
	hash_input.push_back(key.size());
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
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash
	(const tmcg_octets_t &key, const std::string &uid, 
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo,
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;
	size_t uidlen = uid.length();

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.)
	hash_input.push_back(0x99);
	hash_input.push_back(key.size() >> 8);
	hash_input.push_back(key.size());
	hash_input.insert(hash_input.end(), key.begin(), key.end());
	// A certification signature (type 0x10 through 0x13) hashes the User
	// ID being bound to the key into the hash context after the above
	// data. [...] A V4 certification hashes the constant 0xB4 for User
	// ID certifications or the constant 0xD1 for User Attribute
	// certifications, followed by a four-octet number giving the length
	// of the User ID or User Attribute data, and then the User ID or 
	// User Attribute data. 
	hash_input.push_back(0xB4);
	hash_input.push_back(uidlen >> 24);
	hash_input.push_back(uidlen >> 16);
	hash_input.push_back(uidlen >> 8);
	hash_input.push_back(uidlen);
	for (size_t i = 0; i < uidlen; i++)
		hash_input.push_back(uid[i]);
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
	PacketLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHashV3
	(const tmcg_octets_t &primary, const tmcg_octets_t &subkey,
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo,
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet).
	hash_input.push_back(0x99);
	hash_input.push_back(primary.size() >> 8);
	hash_input.push_back(primary.size());
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
	hash_input.push_back(0x99);
	hash_input.push_back(subkey.size() >> 8);
	hash_input.push_back(subkey.size());
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
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash
	(const tmcg_octets_t &primary, const tmcg_octets_t &subkey,
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo,
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.) A subkey binding signature
	// (type 0x18) or primary key binding signature (type 0x19) then hashes
	// the subkey using the same format as the main key (also using 0x99 as
	// the first octet).
	hash_input.push_back(0x99);
	hash_input.push_back(primary.size() >> 8);
	hash_input.push_back(primary.size());
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
	hash_input.push_back(0x99);
	hash_input.push_back(subkey.size() >> 8);
	hash_input.push_back(subkey.size());
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
	PacketLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHash
	(const tmcg_octets_t &key,
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo, 
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

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
	hash_input.push_back(key.size() >> 8);
	hash_input.push_back(key.size());
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
	PacketLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHash
	(const tmcg_octets_t &primary, const tmcg_octets_t &subkey,
	 const tmcg_octets_t &trailer, const tmcg_byte_t hashalgo, 
	 tmcg_octets_t &hash, tmcg_octets_t &left)
{
	tmcg_octets_t hash_input;

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
	hash_input.push_back(primary.size() >> 8);
	hash_input.push_back(primary.size());
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
	hash_input.push_back(0x99);
	hash_input.push_back(subkey.size() >> 8);
	hash_input.push_back(subkey.size());
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
	PacketLengthEncode(trailer.size(), hash_input);
	// After all this has been hashed in a single hash context, the
	// resulting hash field is used in the signature algorithm and placed
	// at the end of the Signature packet.
	HashCompute(hashalgo, hash_input, hash);
	for (size_t i = 0; i < 2; i++)
		left.push_back(hash[i]);
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256
	(const tmcg_octets_t &in, tmcg_octets_t &seskey, tmcg_octets_t &prefix, const bool resync,
	 tmcg_octets_t &out)
{
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t chksum = 0;
	size_t bs = AlgorithmIVLength(9); // get block size of AES256
	size_t ks = AlgorithmKeyLength(9); // get key size of AES256
	tmcg_byte_t key[ks], pre[bs+2], b;

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	if (seskey.size() == (sizeof(key) + 3))
	{
		// reuse the provided session key and calculate checksum
		if (seskey[0] != 9)
			return -1; // error: algorithm is not AES256
		for (size_t i = 0; i < sizeof(key); i++)
		{
			key[i] = seskey[1+i]; // copy the session key
			chksum += key[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
			return -1; // error: checksum does not match
	}
	else if (seskey.size() == sizeof(key))
	{
		// use the provided session key and append checksum
		seskey.insert(seskey.begin(), 9); // constant for AES256
		for (size_t i = 0; i < sizeof(key); i++)
		{
			key[i] = seskey[1+i]; // copy the session key
			chksum += key[i];
		}
		chksum %= 65536;
		seskey.push_back(chksum >> 8); // checksum
		seskey.push_back(chksum);
	}
	else
	{
		// generate a random session key and the OpenPGP checksum
		gcry_randomize(key, sizeof(key), GCRY_STRONG_RANDOM);
		seskey.clear();
		seskey.push_back(9); // constant for AES256
		for (size_t i = 0; i < sizeof(key); i++)
		{
			seskey.push_back(key[i]);
			chksum += key[i];
		}
		chksum %= 65536;
		seskey.push_back(chksum >> 8); // checksum
		seskey.push_back(chksum);
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
	ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_ENABLE_SYNC);
	if (ret)
	{
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, key, sizeof(key));
	if (ret)
	{
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
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
		gcry_cipher_close(hd);
		return ret;
	}
	if (resync)
	{  	
		ret = gcry_cipher_sync(hd);
		if (ret)
		{
			gcry_cipher_close(hd);
			return ret;
		}
	}
	for (size_t i = 0; i < sizeof(pre); i++)
		out.push_back(pre[i]); // encrypted prefix
	for (size_t i = 0; i < in.size(); i++)
	{
		ret = gcry_cipher_encrypt(hd, &b, 1, &in[i], 1);
		if (ret)
		{
			gcry_cipher_close(hd);
			return ret;
		}
		out.push_back(b); // encrypted input
	}
	gcry_cipher_close(hd);

	return ret;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt
	(const tmcg_octets_t &in, tmcg_octets_t &seskey, tmcg_octets_t &prefix, const bool resync,
	 const tmcg_byte_t algo, tmcg_octets_t &out)
{
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t chksum = 0;
	size_t bs = AlgorithmIVLength(algo); // get block size of algorithm
	size_t ks = AlgorithmKeyLength(algo); // get key size of algorithm
	tmcg_byte_t key[ks], b;

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	if (seskey.size() == 0)
		return -1; // error: no session key provided
	else if (seskey.size() == (sizeof(key) + 3))
	{
		// use the provided session key and calculate checksum
		for (size_t i = 0; i < sizeof(key); i++)
		{
			key[i] = seskey[1+i]; // copy the session key
			chksum += key[i];
		}
		chksum %= 65536;
		size_t key_chksum = (seskey[33] << 8) + seskey[34];
		if (chksum != key_chksum)
			return -1; // error: checksum does not match
	}
	else if (seskey.size() == sizeof(key))
	{
		// use the provided session key and append checksum
		seskey.insert(seskey.begin(), algo); // specified algorithm
		for (size_t i = 0; i < sizeof(key); i++)
		{
			key[i] = seskey[1+i]; // copy the session key
			chksum += key[i];
		}
		chksum %= 65536;
		seskey.push_back(chksum >> 8); // checksum
		seskey.push_back(chksum);
	}
	else
		return -1; // error: bad session key provided
	if (in.size() < (bs + 2))
		return -1; // error: input too short (no encrypted prefix)
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
	ret = gcry_cipher_open(&hd, AlgorithmSymGCRY(algo), GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_ENABLE_SYNC);
	if (ret)
	{
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setkey(hd, key, sizeof(key));
	if (ret)
	{
		gcry_cipher_close(hd);
		return ret;
	}
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < (bs + 2); i++)
	{
		ret = gcry_cipher_decrypt(hd, &b, 1, &in[i], 1);
		if (ret)
		{
			gcry_cipher_close(hd);
			return ret;
		}
		prefix.push_back(b); // decrypted prefix
	}
	if ((prefix[bs] != prefix[bs-2]) || (prefix[bs+1] != prefix[bs-1]))
	{
		gcry_cipher_close(hd);
		return -1; // error: prefix corrupt
	}
	if (resync)
	{  	
		ret = gcry_cipher_sync(hd);
		if (ret)
		{
			gcry_cipher_close(hd);
			return ret;
		}
	}
	for (size_t i = 0; i < (in.size() - (bs + 2)); i++)
	{
		ret = gcry_cipher_decrypt(hd, &b, 1, &in[bs+2+i], 1);
		if (ret)
		{
			gcry_cipher_close(hd);
			return ret;
		}
		out.push_back(b); // decrypted input
	}
	gcry_cipher_close(hd);

	return ret;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecryptAES256
	(const tmcg_octets_t &in, tmcg_octets_t &seskey, tmcg_octets_t &prefix, const bool resync,
	 tmcg_octets_t &out)
{
	return CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt(in, seskey, prefix, resync, 9, out);
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal
	(const tmcg_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &gk, gcry_mpi_t &myk)
{
	tmcg_byte_t buffer[1024];
	gcry_sexp_t encryption, data;
	gcry_mpi_t v;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	memset(buffer, 0, sizeof(buffer));
	for (size_t i = 0; (i < in.size()) && (i < sizeof(buffer)); i++, buflen++)
		buffer[i] = in[i];
	ret = gcry_mpi_scan(&v, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&data, &erroff, "(data (flags pkcs1) (value %M))", v);
	gcry_mpi_release(v);
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
	 tmcg_octets_t &out)
{
	tmcg_byte_t buffer[1024];
	gcry_sexp_t decryption, data;
	gcry_mpi_t v;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	// This value is then encoded as described in PKCS#1 block encoding
	// EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the "m" value
	// used in the formulas above. See Section 13.1 of this document for
	// notes on OpenPGP's use of PKCS#1.
	ret = gcry_sexp_build(&data, &erroff, "(enc-val (flags pkcs1) (elg (a %M) (b %M)))", gk, myk);
	if (ret)
		return ret;
	ret = gcry_pk_decrypt(&decryption, data, key);
	gcry_sexp_release(data);
	if (ret)
		return ret;
	v = gcry_sexp_nth_mpi(decryption, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(decryption);
	if (v == NULL)
		return GPG_ERR_NOT_FOUND;
	memset(buffer, 0, sizeof(buffer));
	ret = gcry_mpi_print(GCRYMPI_FMT_USG, buffer, sizeof(buffer),
		&buflen, v);
	gcry_mpi_release(v);
	if (ret)
		return ret;
	for (size_t i = 0; (i < buflen) && (i < sizeof(buffer)); i++)
		out.push_back(buffer[i]);

	return 0;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA
	(const tmcg_octets_t &in, const gcry_sexp_t key, 
	 gcry_mpi_t &r, gcry_mpi_t &s)
{
	tmcg_byte_t buffer[1024];
	gcry_sexp_t sigdata, signature;
	gcry_mpi_t h;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	memset(buffer, 0, sizeof(buffer));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buffer))); i++, buflen++)
		buffer[i] = in[i];
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
	gcry_mpi_release(h);
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
	(const tmcg_octets_t &in, const gcry_sexp_t key, 
	 const gcry_mpi_t r, const gcry_mpi_t s)
{
	tmcg_byte_t buffer[1024];
	gcry_sexp_t sigdata, signature;
	gcry_mpi_t h;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	memset(buffer, 0, sizeof(buffer));
	for (size_t i = 0; ((i < in.size()) && (i < sizeof(buffer))); i++, buflen++)
		buffer[i] = in[i];
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
	gcry_mpi_release(h);
	if (ret)
		return ret;
	ret = gcry_sexp_build(&signature, &erroff, "(sig-val (dsa (r %M) (s %M)))", r, s);
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

