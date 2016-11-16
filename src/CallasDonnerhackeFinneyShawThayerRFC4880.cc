/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.cc, OpenPGP Message Format

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

#include "CallasDonnerhackeFinneyShawThayerRFC4880.hh"

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode
	(const OCTETS &in, std::string &out)
{
	size_t len = in.size();
	size_t i = 0, c = 1;

	// Each 6-bit group is used as an index into an array of 
	// 64 printable characters from the table below. The character
	// referenced by the index is placed in the output string.
	for(; len >= 3; len -= 3, i += 3)
	{
		BYTE l[4];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2) + ((in[i+2] & 0xC0) >> 6);
		l[3] = in[i+2] & 0x3F;
		for (size_t j = 0; j < 4; j++, c++)
		{
			out += tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if (((c % TMCG_OPENPGP_RADIX64_MC) == 0) &&
			    ((len >= 4) || (j < 3)))
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
		BYTE l[3];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4) + ((in[i+1] & 0xF0) >> 4);
		l[2] = ((in[i+1] & 0x0F) << 2);
		for (size_t j = 0; j < 3; j++, c++)
		{
			out += tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if ((c % TMCG_OPENPGP_RADIX64_MC) == 0)
				out += "\r\n"; // add a line delimiter
		}
		out += "=";
	}
	else if (len == 1)
	{
		BYTE l[2];
		l[0] = (in[i] & 0xFC) >> 2;
		l[1] = ((in[i] & 0x03) << 4);
		for (size_t j = 0; j < 2; j++, c++)
		{
			out += tRadix64[l[j]];
			// The encoded output stream must be represented
			// in lines of no more than 76 characters each.
			if ((c % TMCG_OPENPGP_RADIX64_MC) == 0)
				out += "\r\n"; // add a line delimiter
		}
		out += "=", c++;
		// The encoded output stream must be represented
		// in lines of no more than 76 characters each.
		if ((c % TMCG_OPENPGP_RADIX64_MC) == 0)
			out += "\r\n"; // add a line delimiter
		out += "=";
	}
    return;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Decode
	(std::string in, OCTETS &out)
{
	// remove whitespaces and delimiters
	in.erase(std::remove_if(in.begin(), in.end(), notRadix64()), in.end());

	size_t len = in.size();
	for (size_t j = 0; j < (4 - (len % 4)); j++)
		in += "="; // append pad until multiple of four

	for (size_t i = 0; i < len; i += 4)
	{
        	BYTE l[4];
		for (size_t j = 0; j < 4; j++)
			l[j] = fRadix64[(size_t)in[i+j]];
		BYTE t[3];
		t[0] = ((l[0] & 0x3F) << 2) + ((l[1] & 0x30) >> 4);
		t[1] = ((l[1] & 0x0F) << 4) + ((l[2] & 0x3C) >> 2);
		t[2] = ((l[2] & 0x03) << 6) + (l[3] & 0x3F);
		for (size_t j = 0; j < 3; j++)
			if (l[j+1] != 255) out.push_back(t[j]);
	}
    return;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CRC24Compute
	(const OCTETS &in, OCTETS &out)
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
	return;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::CRC24Encode
	(const OCTETS &in, std::string &out)
{
	OCTETS crc;

	// The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted
	// to four characters of radix-64 encoding by the same MIME base64
	// transformation, preceded by an equal sign (=).
	out += "=";
	CRC24Compute(in, crc);
	Radix64Encode(crc, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode
	(const BYTE type, const OCTETS &in, std::string &out)
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
	out += "Version: LibTMCG "VERSION"\r\n";

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
		case 5:
			out += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
			break;
		case 6:
			out += "-----END PGP PUBLIC KEY BLOCK-----\r\n";
			break;
	}
}

BYTE CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode
	(const std::string in, OCTETS &out)
{
	BYTE type = 0;
	size_t spos = 0, rpos = 0, cpos = 0, epos = 0;

	rpos = in.find("\r\n\r\n", 0);
	cpos = in.find("\r\n=", 0); // FIXME: does not work in all cases
	if ((rpos != in.npos) && (cpos != in.npos))
	{
		spos = in.find("-----BEGIN PGP MESSAGE-----", 0);
		epos = in.find("-----END PGP MESSAGE-----", 0);
		if ((spos != in.npos) && (epos != in.npos) && (epos > spos))
			type = 1;
		spos = in.find("-----BEGIN PGP PRIVATE KEY BLOCK-----", 0);
		epos = in.find("-----END PGP PRIVATE KEY BLOCK-----", 0);
		if ((spos != in.npos) && (epos != in.npos) && (epos > spos))
			type = 5;
		spos = in.find("-----BEGIN PGP PUBLIC KEY BLOCK-----", 0);
		epos = in.find("-----END PGP PUBLIC KEY BLOCK-----", 0);
		if ((spos != in.npos) && (epos != in.npos) && (epos > spos))
			type = 6;
	}	
	if ((type > 0) && (rpos > spos) && (rpos < epos) && (rpos < cpos))
	{
		if (in.find("-----", spos + 34) != epos)
			return 0; // nested armor block detected
		OCTETS decoded_data;
		std::string chksum = "";
		std::string data = in.substr(rpos + 4, cpos - rpos - 4);
		Radix64Decode(data, decoded_data);
		CRC24Encode(decoded_data, chksum);
		if (chksum != in.substr(cpos + 2, 5))
			return 0; // Checksum error detected
		out.insert(out.end(), decoded_data.begin(), decoded_data.end());
	}

	return type;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute
	(const OCTETS &in, OCTETS &out)
{
	BYTE *buffer = new BYTE[in.size() + 3]; // additional 3 bytes needed
	BYTE *hash = new BYTE[20]; // fixed output size of SHA-1

	// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	// followed by the two-octet packet length, followed by the entire
	// Public-Key packet starting with the version field.
	buffer[0] = 0x99;
	buffer[1] = in.size() >> 8;
	buffer[2] = in.size();
	for (size_t i = 0; i < in.size(); i++)
		buffer[i + 3] = in[i];
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, in.size() + 3); 
	for (size_t i = 0; i < 20; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute
	(const OCTETS &in, OCTETS &out)
{
	OCTETS fpr;

	// A Key ID is an eight-octet scalar that identifies a key.
	// Implementations SHOULD NOT assume that Key IDs are unique.
	// [...]
	// The Key ID is the low-order 64 bits of the fingerprint.
	FingerprintCompute(in, fpr);
	for (size_t i = 12; i < 20; i++)
		out.push_back(fpr[i]);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute
	(const BYTE algo, const OCTETS &in, OCTETS &out)
{
	int a = 0;
	switch (algo)
	{
		case 1:
			a = GCRY_MD_MD5;
			break;
		case 2:
			a = GCRY_MD_SHA1;
			break;
		case 3:
			a = GCRY_MD_RMD160;
			break;
		case 8:
			a = GCRY_MD_SHA256;
			break;
		case 9:
			a = GCRY_MD_SHA384;
			break;
		case 10:
			a = GCRY_MD_SHA512;
			break;
		case 11:
			a = GCRY_MD_SHA224;
			break;
		default:
			return;
	}
	size_t dlen = gcry_md_get_algo_dlen(a);
	BYTE *buffer = new BYTE[in.size()];
	BYTE *hash = new BYTE[dlen];
	for (size_t i = 0; i < in.size(); i++)
		buffer[i] = in[i];
	gcry_md_hash_buffer(a, hash, buffer, in.size()); 
	for (size_t i = 0; i < dlen; i++)
		out.push_back(hash[i]);
	delete [] buffer;
	delete [] hash;
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTagEncode
	(size_t tag, OCTETS &out)
{
	// use V4 packet format
	out.push_back(tag | 0x80 | 0x40);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketLengthEncode
	(size_t len, OCTETS &out)
{
	// use scalar length format
	out.push_back(0xFF);
	out.push_back(len >> 24);
	out.push_back(len >> 16);
	out.push_back(len >> 8);
	out.push_back(len);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(const time_t in, OCTETS &out)
{
	// A time field is an unsigned four-octet number containing the number
	// of seconds elapsed since midnight, 1 January 1970 UTC.
	out.push_back(in >> 24);
	out.push_back(in >> 16);
	out.push_back(in >> 8);
	out.push_back(in);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode
	(OCTETS &out)
{
	time_t current = time(NULL);
	PacketTimeEncode(current, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(gcry_mpi_t in, OCTETS &out, size_t &sum)
{
	gcry_error_t ret;
	size_t bitlen = gcry_mpi_get_nbits(in);
	size_t buflen = ((bitlen + 7) / 8) + 2;
	BYTE *buffer = new BYTE[buflen];

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
	}
	delete [] buffer;
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIEncode
	(gcry_mpi_t in, OCTETS &out)
{
	size_t sum = 0;
	PacketMPIEncode(in, out, sum);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const OCTETS &in, gcry_mpi_t &out, size_t &sum)
{
	gcry_error_t ret;
	size_t buflen = ((in[0] << 8) + in[1] + 7) / 8;
	BYTE *buffer = new BYTE[buflen];
	for (size_t i = 0; i < buflen; i++)
	{
		buffer[i] = in[2 + i];
		sum += buffer[i];
	}
	ret = gcry_mpi_scan(&out, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	delete [] buffer;
	if (ret)
		return 0; // error: could not read mpi
	else
		return (2 + buflen);
}

size_t CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode
	(const OCTETS &in, gcry_mpi_t &out)
{
	size_t sum = 0;
	return PacketMPIDecode(in, out, sum);
}

// ===========================================================================

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode
	(const OCTETS &keyid, gcry_mpi_t gk, gcry_mpi_t myk, OCTETS &out)
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
	(const OCTETS &hashing, const OCTETS &left, gcry_mpi_t r, gcry_mpi_t s,
	 OCTETS &out)
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
	(const BYTE type, bool critical, const OCTETS &in, OCTETS &out)
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

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare
	(const BYTE sigtype, const OCTETS &flags, const OCTETS &keyid, OCTETS &out)
{
	size_t subpkts = 6;
	size_t subpktlen = (subpkts * 6) + 4 + flags.size() + keyid.size() + 3;
	out.push_back(4); // V4 format
	out.push_back(sigtype); // type (eg 0x13 UID cert., 0x18 subkey bind.)
	out.push_back(17); // public-key algorithm: DSA
	out.push_back(8); // hash algorithm: SHA256
	// hashed subpacket area
	out.push_back(subpktlen >> 8); // length of hashed subpacket data
	out.push_back(subpktlen);
		// signature creation time
		OCTETS sigtime;
		PacketTimeEncode(sigtime);
		SubpacketEncode(2, false, sigtime, out);
		// key flags
		SubpacketEncode(27, false, flags, out);
		// issuer
		SubpacketEncode(16, false, keyid, out);
		// preferred symmetric algorithms
		OCTETS psa;
		psa.push_back(9); // AES256
		SubpacketEncode(11, false, psa, out);
		// preferred hash algorithms
		OCTETS pha;
		pha.push_back(8); // SHA256
		SubpacketEncode(21, false, pha, out);
		// preferred compression algorithms
		OCTETS pca;
		pca.push_back(0); // uncompressed
		SubpacketEncode(22, false, pca, out);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode
	(gcry_mpi_t p, gcry_mpi_t q, gcry_mpi_t g, gcry_mpi_t y, OCTETS &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;

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
	PacketLengthEncode(1+4+1+2+plen+2+qlen+2+glen+2+ylen, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(out); // current time
	out.push_back(17); // public-key algorithm: DSA
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(q, out); // MPI q
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(y, out); // MPI y
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode
	(gcry_mpi_t p, gcry_mpi_t q, gcry_mpi_t g, gcry_mpi_t y, gcry_mpi_t x,
	 OCTETS &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t qlen = (gcry_mpi_get_nbits(q) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;

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
	PacketLengthEncode(1+4+1+2+plen+2+qlen+2+glen+2+ylen+1+2+xlen+2, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(out); // current time
	out.push_back(17); // public-key algorithm: DSA
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(q, out); // MPI q
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(y, out); // MPI y
	out.push_back(0); // S2K convention: not encrypted
	size_t chksum = 0;	
	PacketMPIEncode(x, out, chksum); // MPI x
	chksum %= 65536;
	out.push_back(chksum >> 8); // checksum
	out.push_back(chksum);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode
	(gcry_mpi_t p, gcry_mpi_t g, gcry_mpi_t y, OCTETS &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;

	// A Public-Subkey packet (tag 14) has exactly the same format as a
	// Public-Key packet, but denotes a subkey. One or more subkeys may be
	// associated with a top-level key. By convention, the top-level key
	// provides signature services, and the subkeys provide encryption
	// services.
	// [...]
	//
	PacketTagEncode(14, out);
	PacketLengthEncode(1+4+1+2+plen+2+glen+2+ylen, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(out); // current time
	out.push_back(16); // public-key algorithm: Elgamal
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(y, out); // MPI y
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode
	(gcry_mpi_t p, gcry_mpi_t g, gcry_mpi_t y, gcry_mpi_t x, OCTETS &out)
{
	size_t plen = (gcry_mpi_get_nbits(p) + 7) / 8;
	size_t glen = (gcry_mpi_get_nbits(g) + 7) / 8;
	size_t ylen = (gcry_mpi_get_nbits(y) + 7) / 8;
	size_t xlen = (gcry_mpi_get_nbits(x) + 7) / 8;

	// A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
	// Key packet and has exactly the same format.
	PacketTagEncode(7, out);
	PacketLengthEncode(1+4+1+2+plen+2+glen+2+ylen+1+2+xlen+2, out);
	out.push_back(4); // V4 format
	PacketTimeEncode(out); // current time
	out.push_back(16); // public-key algorithm: Elgamal
	PacketMPIEncode(p, out); // MPI p
	PacketMPIEncode(g, out); // MPI g
	PacketMPIEncode(y, out); // MPI y
	out.push_back(0); // S2K convention: not encrypted
	size_t chksum = 0;	
	PacketMPIEncode(x, out, chksum); // MPI x
	chksum %= 65536;
	out.push_back(chksum >> 8); // checksum
	out.push_back(chksum);
}

void CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode
	(const OCTETS &in, OCTETS &out)
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
	(const OCTETS &in, OCTETS &out)
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
	(const std::string uid, OCTETS &out)
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
	(const OCTETS &in, OCTETS &out)
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
	(const OCTETS &in, OCTETS &out)
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

BYTE CallasDonnerhackeFinneyShawThayerRFC4880::SubpacketDecode
	(OCTETS &in, TMCG_OPENPGP_CONTEXT &out)
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
	size_t len = 0, headlen = 1;
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
	BYTE type = in[headlen-1];
	if ((type & 0x80) == 0x80)
	{
		out.critical = true;
		type -= 0x80;
std::cerr << "subpkt: critical bit set" << std::endl;
	}
std::cerr << "subpkt: len = " << len << " type = " << (int)type << std::endl;
	len -= 1;
	OCTETS pkt;
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
			if (pkt.size() > sizeof(out.trustregex))
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
			for (size_t i = 0; i < pkt.size(); i++)
				out.psa[i] = pkt[i]; 
			break;
		case 12: // Revocation Key
			if (pkt.size() != 22)
				return 0; // error: incorrect subpacket body
			out.revocationkey_class = pkt[0];
			out.revocationkey_pkalgo = pkt[1];
			for (size_t i = 0; i < pkt.size(); i++)
				out.revocationkey_fingerprint[i] = pkt[2+i]; 
			break;
		case 16: // Issuer
			if (pkt.size() != 8)
				return 0; // error: incorrect subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.issuer[i] = pkt[i]; 
			break;
		case 20: // Notation Data
			if (out.critical)
				return 0; // error: subpacket can't ignored
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
			if (pkt.size() > sizeof(out.keyserverpreferences))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.keyserverpreferences[i] = pkt[i]; 
			break;
		case 24: // Preferred Key Server
			if (pkt.size() > sizeof(out.preferedkeyserver))
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
			if (pkt.size() > sizeof(out.policyuri))
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
			if (pkt.size() > sizeof(out.revocationreason) + 1)
				return 0; // error: too long subpacket body
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
			if (pkt.size() > sizeof(out.signaturetarget_hash) + 2)
				return 0; // error: too long subpacket body
			out.signaturetarget_pkalgo = pkt[0];
			out.signaturetarget_hashalgo = pkt[1];
			for (size_t i = 0; i < (pkt.size() - 2); i++)
				out.signaturetarget_hash[i] = pkt[2+i]; 
			break;
		case 32: // Embedded Signature
			if (pkt.size() > sizeof(out.embeddedsignature))
				return 0; // error: too long subpacket body
			for (size_t i = 0; i < pkt.size(); i++)
				out.embeddedsignature[i] = pkt[i]; 
			break;
		default:
			return 0; // unknown subpacket type
	}
	in.erase(in.begin(), in.begin()+headlen+len); // remove subpacket
	return type;
}

BYTE CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode
	(OCTETS &in, TMCG_OPENPGP_CONTEXT &out)
{
	if (in.size() < 2)
		return 0; // error: incorrect packet header
	BYTE tag = in[0];
	if ((tag & 0x80) != 0x80)
		return 0; // error: leftmost bit of tag octet not set
	if ((tag & 0x40) != 0x40)
		return 0; // error: only new packet format supported
	tag -= (0x80 + 0x40);
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
	size_t len = 0, headlen = 1, hspdlen = 0, uspdlen = 0;
	if (in[1] < 192)
	{
		// A one-octet Body Length header encodes a length of 0 to
		// 191 octets. This type of length header is recognized
		// because the one octet value is less than 192.
		headlen += 1;
		len = in[1];
	}
	else if (in[1] < 224)
	{
		if (in.size() < 3)
			return 0; // error: too few octets of length encoding
		// A two-octet Body Length header encodes a length of 192 to
		// 8383 octets. It is recognized because its first octet is
		// in the range 192 to 223.
		headlen += 2;
		len = ((in[1] - 192) << 8) + in[2] + 192;
	}
	else if (in[1] == 255)
	{
		if (in.size() < 6)
			return 0; // error: too few octets of length encoding
		// A five-octet Body Length header consists of a single octet
		// holding the value 255, followed by a four-octet scalar.
		headlen += 5;
		len = (in[2] << 24) + (in[3] << 16) + (in[4] << 8) + in[5];
	}
	else
		return 0; // error: Partial Body Lengths are not supported
std::cerr << "pkt: len = " << len << " tag = " << (int)tag << std::endl;
	BYTE sptype = 0xFF;
	OCTETS pkt, hspd, uspd, mpis;
	pkt.insert(pkt.end(), in.begin()+headlen, in.begin()+headlen+len);
	memset(&out, 0, sizeof(out)); // clear output context
	// Exportable Certification: If this packet is not present, the
	// certification is exportable; it is equivalent to a flag 
	// containing a 1.
	out.exportablecertification = true; 
	// Revocable: If this packet is not present, the signature is
	// revocable.
	out.revocable = true;
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
				size_t mlen = PacketMPIDecode(mpis, out.me);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 16)
			{
				// Algorithm-Specific Fields for Elgamal
				size_t mlen = PacketMPIDecode(mpis, out.gk);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
				mlen = PacketMPIDecode(mpis, out.myk);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else
				return 0; // error: unknown public-key algo
			break;
		case 2: // Signature Packet
			if (pkt.size() < 12)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.type = pkt[1];
			out.pkalgo = pkt[2];
			out.hashalgo = pkt[3];
			hspdlen = (pkt[4] << 8) + pkt[5];
			hspd.insert(hspd.end(), 
				pkt.begin()+6, pkt.begin()+6+hspdlen); 
			while (hspd.size() && sptype)
                	{
				sptype = SubpacketDecode(hspd, out);
				if (out.critical && (sptype == 0))
					return 0; // error: critical bit set
			}
			uspdlen = (pkt[6+hspdlen] << 8) + pkt[7+hspdlen];
			uspd.insert(uspd.end(), pkt.begin()+8+hspdlen,
					 pkt.begin()+8+hspdlen+uspdlen);
			// If a subpacket is not hashed, then the information
			// in it cannot be considered definitive because it 
			// is not part of the signature proper.
			TMCG_OPENPGP_CONTEXT untrusted;
			while (uspd.size() && sptype)
                	{
				sptype = SubpacketDecode(uspd, untrusted);
				if (untrusted.critical && (sptype == 0))
					return 0; // error: critical bit set
			}
std::cerr << "BUG" << std::endl;
			out.left[0] = pkt[8+hspdlen+uspdlen];
			out.left[1] = pkt[9+hspdlen+uspdlen];
			mpis.insert(mpis.end(), pkt.begin()+10+hspdlen+uspdlen,
				pkt.end());
			if ((out.pkalgo == 1) || (out.pkalgo == 3))
			{
				// Algorithm-Specific Fields for RSA 
				size_t mlen = PacketMPIDecode(mpis, out.md);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 17)
			{
std::cerr << "BUG" << std::endl;
				// Algorithm-Specific Fields for DSA 
				size_t mlen = PacketMPIDecode(mpis, out.r);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				if (mpis.size() <= 2)
					return 0; // error: too few mpis
std::cerr << "BUG" << std::endl;
				mlen = PacketMPIDecode(mpis, out.s);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
std::cerr << "END" << std::endl;
			}
			else
				return 0; // error: unknown public-key algo
			break;
		case 3: // Symmetric-Key Encrypted Session Key Packet, ignore
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
			if (pkt.size() < 14)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.keycreationtime = (pkt[1] << 24) + (pkt[2] << 16)
				+ (pkt[3] << 8) + pkt[4];
			out.pkalgo = pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
			if ((out.pkalgo >= 1) && (out.pkalgo <= 3))
			{
				// Algorithm-Specific Fields for RSA keys
				size_t mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.e);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				// secret fields
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.d);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.u);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
			}
			else if (out.pkalgo == 16)
			{
				// Algorithm-Specific Fields for Elgamal keys
				size_t mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				// secret fields
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.x);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
			}
			else if (out.pkalgo == 17)
			{
				// Algorithm-Specific Fields for DSA keys
				size_t mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				// secret fields
				if (mpis[0] != 0)
					return 0; // error: S2K not supported
				mpis.erase(mpis.begin(), mpis.begin()+1);
				mlen = PacketMPIDecode(mpis, out.x);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mpis.erase(mpis.begin(), mpis.begin()+2);
			}
			break;
		case 6: // Public-Key Packet
		case 14: // Public-Subkey Packet
			if (pkt.size() < 14)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 4)
				return 0; // error: version not supported
			out.keycreationtime = (pkt[1] << 24) + (pkt[2] << 16)
				+ (pkt[3] << 8) + pkt[4];
			out.pkalgo = pkt[5];
			mpis.insert(mpis.end(), pkt.begin()+6, pkt.end());
std::cerr << "BUG" << std::endl;
			if ((out.pkalgo >= 1) && (out.pkalgo <= 3))
			{
std::cerr << "RSA" << std::endl;
				// Algorithm-Specific Fields for RSA keys
				size_t mlen = PacketMPIDecode(mpis, out.n);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.e);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 16)
			{
std::cerr << "Elg" << std::endl;
				// Algorithm-Specific Fields for Elgamal keys
				size_t mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
			else if (out.pkalgo == 17)
			{
std::cerr << "BUG" << std::endl;
				// Algorithm-Specific Fields for DSA keys
				size_t mlen = PacketMPIDecode(mpis, out.p);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
std::cerr << "BUG" << std::endl;
				mlen = PacketMPIDecode(mpis, out.q);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
std::cerr << "BUG" << std::endl;
				mlen = PacketMPIDecode(mpis, out.g);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
std::cerr << "BUG" << std::endl;
				mlen = PacketMPIDecode(mpis, out.y);
				if (!mlen)
					return 0; // error: bad or zero mpi
				mpis.erase(mpis.begin(), mpis.begin()+mlen);
			}
std::cerr << "END" << std::endl;
			break;
		case 8: // Compressed Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.compalgo = pkt[0];
			if (out.compalgo > 2)
				return 0; // error: algorithm not supported
			out.compresseddatalen = pkt.size();
			out.compresseddata = new BYTE[out.compresseddatalen];
			for (size_t i = 0; i < out.compresseddatalen; i++)
				out.compresseddata[i] = pkt[1+i];
			break;
		case 9: // Symmetrically Encrypted Data Packet
			if (pkt.size() == 0)
				return 0; // error: empty packet body
			out.encrypteddatalen = pkt.size();
			out.encrypteddata = new BYTE[out.encrypteddatalen];
			for (size_t i = 0; i < out.encrypteddatalen; i++)
				out.encrypteddata[i] = pkt[i];
			break;
		case 10: // Marker Packet
			if (pkt.size() != 3)
				return 0; // error: incorrect packet body
			break;
		case 11: // Literal Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.dataformat = pkt[0];
			out.datafilenamelen = pkt[1];
			for (size_t i = 0; i < out.datafilenamelen; i++)
				out.datafilename[i] = pkt[2+i];
			out.datatime = (pkt[3+out.datafilenamelen] << 24) +
				(pkt[4+out.datafilenamelen] << 16) +
				(pkt[5+out.datafilenamelen] << 8) +
				 pkt[6+out.datafilenamelen];
			out.datalen = pkt.size() - out.datafilenamelen - 6;
			out.data = new BYTE[out.datalen];
			for (size_t i = 0; i < out.datalen; i++)
				out.data[i] = pkt[6+out.datafilenamelen+i];
			break;
		case 12: // Trust Packet -- not supported, ignore
			break;
		case 13: // User ID Packet
			if (pkt.size() > sizeof(out.uid))
				return 0; // error: empty packet body
			for (size_t i = 0; i < pkt.size(); i++)
				out.uid[i] = pkt[i];
			break;
		case 17: // User Attribute Packet -- not supported, ignore
			break;
		case 18: // Sym. Encrypted and Integrity Protected Data Packet
			if (pkt.size() < 2)
				return 0; // error: incorrect packet body
			out.version = pkt[0];
			if (out.version != 1)
				return 0; // error: version not supported
			out.encrypteddatalen = pkt.size() - 1;
			out.encrypteddata = new BYTE[out.encrypteddatalen];
			for (size_t i = 0; i < out.encrypteddatalen; i++)
				out.encrypteddata[i] = pkt[1+i];
			break;
		case 19: // Modification Detection Code Packet
			if (pkt.size() != 20)
				return 0; // error: incorrect packet body
			for (size_t i = 0; i < pkt.size(); i++)
				out.mdc_hash[i] = pkt[i];
			break;
		default:
			return 0; // error: unknown packet tag
	}
	in.erase(in.begin(), in.begin()+headlen+len); // remove packet
	return tag;
}

// ===========================================================================

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash
	(const OCTETS &primary, std::string uid, const OCTETS &trailer, 
	 gcry_mpi_t &h, OCTETS &left)
{
	OCTETS hash_input;
	BYTE buffer[1024];
	size_t uidlen = uid.length(), buflen = 0;
	gcry_error_t ret;

	// When a signature is made over a key, the hash data starts with the
	// octet 0x99, followed by a two-octet length of the key, and then body
	// of the key packet. (Note that this is an old-style packet header for
	// a key packet with two-octet length.)
	hash_input.push_back(0x99);
	hash_input.push_back(primary.size() >> 8);
	hash_input.push_back(primary.size());
	hash_input.insert(hash_input.end(), primary.begin(), primary.end());
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
	HashCompute(8, hash_input, left);
	for (size_t i = 0; ((i < left.size()) && (i < 1024)); i++, buflen++)
		buffer[i] = left[i];
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	while (left.size() > 2)
		left.pop_back();

	return ret;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash
	(const OCTETS &primary, const OCTETS &subkey, const OCTETS &trailer,
	 gcry_mpi_t &h, OCTETS &left)
{
	OCTETS hash_input;
	BYTE buffer[1024];
	size_t buflen = 0;
	gcry_error_t ret;

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
	HashCompute(8, hash_input, left);
	for (size_t i = 0; ((i < left.size()) && (i < 1024)); i++, buflen++)
		buffer[i] = left[i];
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	while (left.size() > 2)
		left.pop_back();

	return ret;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256
	(const OCTETS &in, OCTETS &seskey, OCTETS &prefix, bool resync,
	 OCTETS &out)
{
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t chksum = 0;
	size_t bs = 16; // block size of AES256 is 128 bits
	BYTE key[32], pre[bs+2], b;

	// The symmetric cipher used may be specified in a Public-Key or
	// Symmetric-Key Encrypted Session Key packet that precedes the
	// Symmetrically Encrypted Data packet. In that case, the cipher
	// algorithm octet is prefixed to the session key before it is
	// encrypted.
	// [...]
	// Then a two-octet checksum is appended, which is equal to the
	// sum of the preceding session key octets, not including the
	// algorithm identifier, modulo 65536.
	if (seskey.size() != (sizeof(key) + 3))
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
	ret = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB,
		GCRY_CIPHER_ENABLE_SYNC);
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
		// generate a random prefix and it's checksum
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
		out.push_back(b);
	}
	gcry_cipher_close(hd);

	return ret;
}

gcry_error_t CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal
	(const OCTETS &in, const gcry_sexp_t key, gcry_mpi_t &gk, gcry_mpi_t &myk)
{
	BYTE buffer[1024];
	gcry_sexp_t encryption, data;
	gcry_mpi_t v;
	gcry_error_t ret;
	size_t buflen = 0, erroff;

	// TODO: Beschreibung
	for (size_t i = 0; ((i < in.size()) && (i < 1024)); i++, buflen++)
		buffer[i] = in[i];
	v = gcry_mpi_new(2048);
	ret = gcry_mpi_scan(&v, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
	{
		gcry_mpi_release(v);
		return ret;
	}
	ret = gcry_sexp_build(&data, &erroff,
		"(data (flags pkcs1) (value %M))", v);
	if (ret)
	{
		gcry_mpi_release(v);
		return ret;
	}

	ret = gcry_pk_encrypt(&encryption, data, key);
	if (ret)
	{
		gcry_mpi_release(v);
		gcry_sexp_release(encryption);
		gcry_sexp_release(data);
		return ret;
	}
	ret = gcry_sexp_extract_param(encryption, NULL, "ab", &gk, &myk, NULL);
	if (ret)
	{
		gcry_mpi_release(v);
		gcry_sexp_release(encryption);
		gcry_sexp_release(data);
		return ret;
	}
	gcry_mpi_release(v);
	gcry_sexp_release(encryption);
	gcry_sexp_release(data);

	return ret;
}

