/*******************************************************************************
  CallasDonnerhackeFinneyShawThayerRFC4880.hh, OpenPGP Message Format

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

#ifndef INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH
	#define INCLUDED_CallasDonnerhackeFinneyShawThayerRFC4880_HH
	
// C and STL header
#include <cstddef>
#include <ctime>
#include <inttypes.h>
#include <vector>
#include <map>
#include <utility>
#include <string>

// GNU crypto library
#include <gcrypt.h>

// STL-compliant allocator using libgcrypt's secure memory
template<class T> class TMCG_SecureAlloc
{
	public:
		typedef T			value_type;
		typedef size_t		size_type;
		typedef ptrdiff_t	difference_type;
		typedef T*			pointer;
		typedef const T*	const_pointer;
		typedef T&			reference;
		typedef const T&	const_reference;
		pointer address
			(reference r) const
		{
			return &r;
		}
		const_pointer address
			(const_reference r) const
		{
			return &r;
		}
		TMCG_SecureAlloc
			() throw()
		{
		}
		template<class U> TMCG_SecureAlloc
			(const TMCG_SecureAlloc<U>&) throw();
		pointer allocate
			(size_type n, const void* hint = 0)
		{
			if (hint)
				hint = 0; // dummy to supress compiler warning
			pointer adr = static_cast<pointer>(gcry_malloc_secure(n));
//std::cerr << "TMCG_SecureAlloc::allocate(" << n << ") at 0x" << std::hex <<
// (long int)adr << std::dec << std::endl;
			return adr;
		}
		void deallocate
			(pointer p, size_type n)
		{
//std::cerr << "TMCG_SecureAlloc::deallocate(" << n << ") at 0x" << std::hex <<
// (long int)p << std::dec << std::endl;
			if (n > 0)
				gcry_free(p);
		}
		void construct
			(pointer p, const T& value)
		{
			new (p) T(value);
		}
		void destroy
			(pointer p)
		{
			p->~T();
		}
		size_type max_size
			() const throw()
		{
			return 16384;
		}
		template<class U> struct rebind
		{
			typedef TMCG_SecureAlloc<U> other;
		};
		~TMCG_SecureAlloc
			() throw()
		{
		}
};
template<class T> bool operator==
	(const TMCG_SecureAlloc<T>&, const TMCG_SecureAlloc<T>&) throw()
{
	return true;
};
template<class T> bool operator!=
	(const TMCG_SecureAlloc<T>&, const TMCG_SecureAlloc<T>&) throw()
{
	return false;
};

// definition of types and constants for OpenPGP structures
typedef uint8_t
	tmcg_openpgp_byte_t;
typedef std::vector<tmcg_openpgp_byte_t>
	tmcg_openpgp_octets_t;
typedef std::vector<tmcg_openpgp_byte_t, TMCG_SecureAlloc<tmcg_openpgp_byte_t> >
	tmcg_openpgp_secure_octets_t;
typedef std::pair<tmcg_openpgp_octets_t, tmcg_openpgp_octets_t>
	tmcg_openpgp_notation_t;
typedef std::vector<tmcg_openpgp_notation_t>
	tmcg_openpgp_notations_t;
typedef std::basic_string<char, std::char_traits<char>, TMCG_SecureAlloc<char> >
	tmcg_openpgp_secure_string_t;
typedef std::basic_stringstream<char, std::char_traits<char>, TMCG_SecureAlloc<char> >
	tmcg_openpgp_secure_stringstream_t;

enum tmcg_openpgp_signature_t
{
	TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT			= 0x00,
	TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT	= 0x01,
	TMCG_OPENPGP_SIGNATURE_STANDALONE				= 0x02,
	TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION	= 0x10,
	TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION	= 0x11,
	TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION		= 0x12,
	TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION	= 0x13,
	TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING			= 0x18,
	TMCG_OPENPGP_SIGNATURE_PRIMARY_KEY_BINDING		= 0x19,
	TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY		= 0x1F,
	TMCG_OPENPGP_SIGNATURE_KEY_REVOCATION			= 0x20,
	TMCG_OPENPGP_SIGNATURE_SUBKEY_REVOCATION		= 0x28,
	TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION	= 0x30,
	TMCG_OPENPGP_SIGNATURE_TIMESTAMP				= 0x40,
	TMCG_OPENPGP_SIGNATURE_THIRD_PARTY_CONFIRMATION	= 0x50
};

enum tmcg_openpgp_revcode_t
{
	TMCG_OPENPGP_REVCODE_NO_REASON_SPECIFIED		= 0,
	TMCG_OPENPGP_REVCODE_KEY_SUPERSEDED				= 1,
	TMCG_OPENPGP_REVCODE_KEY_COMPROMISED			= 2,
	TMCG_OPENPGP_REVCODE_KEY_RETIRED				= 3,
	TMCG_OPENPGP_REVCODE_UID_NO_LONGER_VALID		= 32,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL0				= 100,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL1				= 101,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL2				= 102,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL3				= 103,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL4				= 104,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL5				= 105,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL6				= 106,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL7				= 107,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL8				= 108,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL9				= 109,
	TMCG_OPENPGP_REVCODE_EXPERIMENTAL10				= 110
};

enum tmcg_openpgp_armor_t
{
	TMCG_OPENPGP_ARMOR_UNKNOWN				= 0,
	TMCG_OPENPGP_ARMOR_MESSAGE				= 1,
	TMCG_OPENPGP_ARMOR_SIGNATURE			= 2,
	TMCG_OPENPGP_ARMOR_MESSAGE_PART_X		= 3,
	TMCG_OPENPGP_ARMOR_MESSAGE_PART_X_Y		= 4,
	TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK	= 5,
	TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK		= 6
};

enum tmcg_openpgp_stringtokey_t
{
	TMCG_OPENPGP_STRINGTOKEY_SIMPLE			= 0,
	TMCG_OPENPGP_STRINGTOKEY_SALTED			= 1,
	TMCG_OPENPGP_STRINGTOKEY_ITERATED		= 3,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL0	= 100,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL1	= 101,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL2	= 102,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL3	= 103,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL4	= 104,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL5	= 105,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL6	= 106,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL7	= 107,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL8	= 108,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL9	= 109,
	TMCG_OPENPGP_STRINGTOKEY_EXPERIMENTAL10	= 110
};

enum tmcg_openpgp_pkalgo_t
{
	TMCG_OPENPGP_PKALGO_RSA					= 1,
	TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY	= 2,
	TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY		= 3,
	TMCG_OPENPGP_PKALGO_ELGAMAL				= 16,
	TMCG_OPENPGP_PKALGO_DSA					= 17,
	TMCG_OPENPGP_PKALGO_ECDH				= 18, // added by RFC 6637
	TMCG_OPENPGP_PKALGO_ECDSA				= 19, // added by RFC 6637
	TMCG_OPENPGP_PKALGO_EDDSA				= 22, // added by draft RFC 4880bis
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL0		= 100,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL1		= 101,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL2		= 102,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL3		= 103,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL4		= 104,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL5		= 105,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL6		= 106,
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL7		= 107, // tDSS/DSA in LibTMCG
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL8		= 108, // (tDSS/DSA old format)
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL9		= 109, // tElG in LibTMCG
	TMCG_OPENPGP_PKALGO_EXPERIMENTAL10		= 110
};

enum tmcg_openpgp_skalgo_t
{
	TMCG_OPENPGP_SKALGO_PLAINTEXT			= 0,
	TMCG_OPENPGP_SKALGO_IDEA				= 1,
	TMCG_OPENPGP_SKALGO_3DES				= 2,
	TMCG_OPENPGP_SKALGO_CAST5				= 3,
	TMCG_OPENPGP_SKALGO_BLOWFISH			= 4,
	TMCG_OPENPGP_SKALGO_AES128				= 7,
	TMCG_OPENPGP_SKALGO_AES192				= 8,
	TMCG_OPENPGP_SKALGO_AES256				= 9,
	TMCG_OPENPGP_SKALGO_TWOFISH				= 10,
	TMCG_OPENPGP_SKALGO_CAMELLIA128			= 11, // added by RFC 5581
	TMCG_OPENPGP_SKALGO_CAMELLIA192			= 12, // added by RFC 5581
	TMCG_OPENPGP_SKALGO_CAMELLIA256			= 13, // added by RFC 5581
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL0		= 100,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL1		= 101,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL2		= 102,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL3		= 103,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL4		= 104,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL5		= 105,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL6		= 106,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL7		= 107,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL8		= 108,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL9		= 109,
	TMCG_OPENPGP_SKALGO_EXPERIMENTAL10		= 110
};

enum tmcg_openpgp_compalgo_t
{
	TMCG_OPENPGP_COMPALGO_UNCOMPRESSED		= 0,
	TMCG_OPENPGP_COMPALGO_ZIP				= 1,
	TMCG_OPENPGP_COMPALGO_ZLIB				= 2,
	TMCG_OPENPGP_COMPALGO_BZIP2				= 3,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL0		= 100,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL1		= 101,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL2		= 102,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL3		= 103,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL4		= 104,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL5		= 105,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL6		= 106,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL7		= 107,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL8		= 108,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL9		= 109,
	TMCG_OPENPGP_COMPALGO_EXPERIMENTAL10	= 110
};

enum tmcg_openpgp_hashalgo_t
{
	TMCG_OPENPGP_HASHALGO_UNKNOWN			= 0,
	TMCG_OPENPGP_HASHALGO_MD5				= 1,
	TMCG_OPENPGP_HASHALGO_SHA1				= 2,
	TMCG_OPENPGP_HASHALGO_RMD160			= 3,
	TMCG_OPENPGP_HASHALGO_SHA256			= 8,
	TMCG_OPENPGP_HASHALGO_SHA384			= 9,
	TMCG_OPENPGP_HASHALGO_SHA512			= 10,
	TMCG_OPENPGP_HASHALGO_SHA224			= 11,
	TMCG_OPENPGP_HASHALGO_SHA3_256			= 12, // added by draft RFC 4880bis
	TMCG_OPENPGP_HASHALGO_SHA3_512			= 14, // added by draft RFC 4880bis
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL0		= 100,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL1		= 101,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL2		= 102,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL3		= 103,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL4		= 104,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL5		= 105,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL6		= 106,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL7		= 107,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL8		= 108,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL9		= 109,
	TMCG_OPENPGP_HASHALGO_EXPERIMENTAL10	= 110
};

enum tmcg_openpgp_aeadalgo_t
{
	TMCG_OPENPGP_AEADALGO_UNKNOWN			= 0,
	TMCG_OPENPGP_AEADALGO_EAX				= 1,  // added by draft RFC 4880bis
	TMCG_OPENPGP_AEADALGO_OCB				= 2,  // added by draft RFC 4880bis
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL0		= 100,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL1		= 101,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL2		= 102,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL3		= 103,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL4		= 104,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL5		= 105,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL6		= 106,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL7		= 107,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL8		= 108,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL9		= 109,
	TMCG_OPENPGP_AEADALGO_EXPERIMENTAL10	= 110
};

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
	const char					*name;
	const tmcg_openpgp_byte_t	*oid;
} tmcg_openpgp_oid_t;
// OID for NIST curve P-256 [RFC 6637]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_nistp256[] =
	{ 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
// OID for NIST curve P-384 [RFC 6637]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_nistp384[] =
	{ 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
// OID for NIST curve P-521 [RFC 6637]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_nistp521[] =
	{ 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
// OID for Brainpool curve P256r1 [draft RFC 4880bis]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_brainpoolp256r1[] =
	{ 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
// OID for Brainpool curve P512r1 [draft RFC 4880bis]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_brainpoolp512r1[] =
	{ 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d };
// OID for curve Ed25519 [draft RFC 4880bis]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_ed25519[] =
	{ 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
// OID for Curve25519 [draft RFC 4880bis]
static const tmcg_openpgp_byte_t tmcg_openpgp_oid_cv25519[] =
	{ 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
static const tmcg_openpgp_oid_t tmcg_openpgp_oidtable[] =
{
	{ "NIST P-256", tmcg_openpgp_oid_nistp256 },
	{ "NIST P-384", tmcg_openpgp_oid_nistp384 },
	{ "NIST P-521", tmcg_openpgp_oid_nistp521 },
	{ "brainpoolP256r1", tmcg_openpgp_oid_brainpoolp256r1 },
	{ "brainpoolP512r1", tmcg_openpgp_oid_brainpoolp512r1 },
	{ "Ed25519", tmcg_openpgp_oid_ed25519 },
	{ "Curve25519", tmcg_openpgp_oid_cv25519 },
	{ NULL, NULL }
};

typedef struct
{
	bool						newformat;
	tmcg_openpgp_byte_t			tag;
	bool						indetlen;
	tmcg_openpgp_byte_t			version;
	tmcg_openpgp_byte_t			keyid[8]; // key ID
	tmcg_openpgp_pkalgo_t		pkalgo;
	gcry_mpi_t					me;
	gcry_mpi_t					gk;
	gcry_mpi_t					myk;
	gcry_mpi_t					ecepk;
	size_t						rkwlen;
	tmcg_openpgp_byte_t			rkw[256];
	tmcg_openpgp_signature_t	type;
	tmcg_openpgp_hashalgo_t		hashalgo;
	tmcg_openpgp_byte_t*		hspd; // allocated buffer with data
	size_t						hspdlen;
	bool						critical;
	uint32_t					sigcreationtime;
	tmcg_openpgp_byte_t			issuer[8]; // key ID
	bool						notation_human_readable;
	size_t						notation_name_length;
	tmcg_openpgp_byte_t			notation_name[2048];
	size_t						notation_value_length;
	tmcg_openpgp_byte_t			notation_value[2048];
	uint32_t					keyexpirationtime;
	size_t						psalen;
	tmcg_openpgp_byte_t			psa[32]; // array of 1-octet values
	size_t						phalen;
	tmcg_openpgp_byte_t			pha[32]; // array of 1-octet values
	size_t						pcalen;
	tmcg_openpgp_byte_t			pca[32]; // array of 1-octet values
	size_t						paalen;
	tmcg_openpgp_byte_t			paa[32]; // array of 1-octet values
	uint32_t					sigexpirationtime;
	bool						exportablecertification;
	bool						revocable;
	tmcg_openpgp_byte_t			trustlevel;
	tmcg_openpgp_byte_t			trustamount;
	tmcg_openpgp_byte_t			trustregex[2048]; // string
	tmcg_openpgp_byte_t			revocationkey_class;
	tmcg_openpgp_pkalgo_t		revocationkey_pkalgo;
	tmcg_openpgp_byte_t			revocationkey_fingerprint[32]; // SHA-1, SHA256
	tmcg_openpgp_byte_t			keyserverpreferences[2048]; // array
	tmcg_openpgp_byte_t			preferedkeyserver[2048]; // string
	bool						primaryuserid;
	tmcg_openpgp_byte_t			policyuri[2048]; // string
	size_t						keyflagslen;
	tmcg_openpgp_byte_t			keyflags[32]; // N octets of flags
	tmcg_openpgp_byte_t			signersuserid[2048]; // string
	tmcg_openpgp_revcode_t		revocationcode;
	tmcg_openpgp_byte_t			revocationreason[2048]; // string
	size_t						featureslen;
	tmcg_openpgp_byte_t			features[32]; // N octets of flags
	tmcg_openpgp_pkalgo_t		signaturetarget_pkalgo;
	tmcg_openpgp_hashalgo_t 	signaturetarget_hashalgo;
	tmcg_openpgp_byte_t			signaturetarget_hash[2048];
	tmcg_openpgp_byte_t*		embeddedsignature; // allocated buffer with data
	size_t						embeddedsignaturelen;
	tmcg_openpgp_byte_t			issuerkeyversion;
	tmcg_openpgp_byte_t			issuerfingerprint[32]; // SHA-1 or SHA256
	tmcg_openpgp_byte_t			left[2];
	gcry_mpi_t					md;
	gcry_mpi_t					r;
	gcry_mpi_t					s;
	tmcg_openpgp_byte_t			signingkeyid[8]; // key ID
	tmcg_openpgp_byte_t			nestedsignature;
	uint32_t					keycreationtime;
	tmcg_openpgp_byte_t			curveoid[256];
	size_t						curveoidlen;
	tmcg_openpgp_hashalgo_t		kdf_hashalgo;
	tmcg_openpgp_skalgo_t		kdf_skalgo;
	gcry_mpi_t					ecpk;
	gcry_mpi_t					ecsk;
	gcry_mpi_t					n;
	gcry_mpi_t					e;
	gcry_mpi_t					d;
	gcry_mpi_t					p;
	gcry_mpi_t					q;
	gcry_mpi_t					u;
	gcry_mpi_t					g;
	gcry_mpi_t					h;
	gcry_mpi_t					y;
	gcry_mpi_t					x;
	gcry_mpi_t					t;
	gcry_mpi_t					i;
	gcry_mpi_t					qualsize;
	gcry_mpi_t					x_rvss_qualsize;
	gcry_mpi_t					x_i;
	gcry_mpi_t					xprime_i;
	tmcg_openpgp_skalgo_t		skalgo;
	tmcg_openpgp_aeadalgo_t		aeadalgo;
	tmcg_openpgp_byte_t			s2kconv;
	tmcg_openpgp_stringtokey_t	s2k_type;
	tmcg_openpgp_hashalgo_t		s2k_hashalgo;
	tmcg_openpgp_byte_t			s2k_salt[8];
	tmcg_openpgp_byte_t			s2k_count;
	tmcg_openpgp_byte_t			iv[32];
	tmcg_openpgp_byte_t*		encdata; // allocated buffer with data
	size_t						encdatalen;
	tmcg_openpgp_compalgo_t		compalgo;
	tmcg_openpgp_byte_t*		compdata; // allocated buffer with data
	size_t						compdatalen;
	tmcg_openpgp_byte_t			dataformat;
	size_t						datafilenamelen;
	tmcg_openpgp_byte_t			datafilename[2048]; // string
	uint32_t					datatime;
	tmcg_openpgp_byte_t*		data; // allocated buffer with data
	size_t						datalen;
	tmcg_openpgp_byte_t*		uiddata; // allocated buffer with data
	size_t						uiddatalen;
	tmcg_openpgp_byte_t			mdc_hash[20]; // SHA-1
	tmcg_openpgp_byte_t*		uatdata; // allocated buffer with data
	size_t						uatdatalen;
	tmcg_openpgp_byte_t			chunksize;
} tmcg_openpgp_packet_ctx_t;

typedef struct
{
	tmcg_openpgp_byte_t			key_class;
	tmcg_openpgp_pkalgo_t		key_pkalgo;
	tmcg_openpgp_byte_t			key_fingerprint[32]; // SHA-1 or SHA256
} tmcg_openpgp_revkey_t;

// definition of own classes
class TMCG_OpenPGP_Signature
{
	private:
		gcry_error_t										ret;
		size_t												erroff;

	public:
		bool												valid;
		bool												revoked;
		bool												revocable;
		bool												exportable;
		tmcg_openpgp_pkalgo_t								pkalgo;
		tmcg_openpgp_hashalgo_t								hashalgo;
		tmcg_openpgp_signature_t							type;
		tmcg_openpgp_byte_t									version;
		time_t												creationtime;
		time_t												expirationtime;
		time_t												keyexpirationtime;
		tmcg_openpgp_revcode_t								revcode;
		gcry_sexp_t											signature;
		gcry_mpi_t											rsa_md;
		gcry_mpi_t											dsa_r;
		gcry_mpi_t											dsa_s;
		tmcg_openpgp_octets_t								packet;
		tmcg_openpgp_octets_t								hspd;
		tmcg_openpgp_octets_t								issuer;
		tmcg_openpgp_octets_t								issuerfpr;
		tmcg_openpgp_octets_t								keyflags;
		tmcg_openpgp_octets_t								keyfeatures;
		tmcg_openpgp_octets_t								keyprefs_psa;
		tmcg_openpgp_octets_t								keyprefs_pha;
		tmcg_openpgp_octets_t								keyprefs_pca;
		tmcg_openpgp_octets_t								keyprefs_paa;
		std::vector<tmcg_openpgp_revkey_t>					revkeys;
		tmcg_openpgp_octets_t								embeddedsig;

		TMCG_OpenPGP_Signature
			(const bool										revocable_in,
			 const bool										exportable_in,
			 const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const tmcg_openpgp_hashalgo_t					hashalgo_in,
			 const tmcg_openpgp_signature_t					type_in,
			 const tmcg_openpgp_byte_t						version_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const time_t									keyexptime_in,
			 const tmcg_openpgp_revcode_t					revcode_in,
			 const gcry_mpi_t								md,
			 const tmcg_openpgp_octets_t					&packet_in,
			 const tmcg_openpgp_octets_t					&hspd_in,
			 const tmcg_openpgp_octets_t					&issuer_in,
			 const tmcg_openpgp_octets_t					&issuerfpr_in,
			 const tmcg_openpgp_octets_t					&keyflags_in,
			 const tmcg_openpgp_octets_t					&keyfeatures_in,
			 const tmcg_openpgp_octets_t					&keyprefs_psa_in,
			 const tmcg_openpgp_octets_t					&keyprefs_pha_in,
			 const tmcg_openpgp_octets_t					&keyprefs_pca_in,
			 const tmcg_openpgp_octets_t					&keyprefs_paa_in,
			 const tmcg_openpgp_octets_t					&embeddedsig_in);
		TMCG_OpenPGP_Signature
			(const bool										revocable_in,
			 const bool										exportable_in,
			 const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const tmcg_openpgp_hashalgo_t					hashalgo_in,
			 const tmcg_openpgp_signature_t					type_in,
			 const tmcg_openpgp_byte_t						version_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const time_t									keyexptime_in,
			 const tmcg_openpgp_revcode_t					revcode_in,
			 const gcry_mpi_t								r,
			 const gcry_mpi_t								s,
			 const tmcg_openpgp_octets_t					&packet_in,
			 const tmcg_openpgp_octets_t					&hspd_in,
			 const tmcg_openpgp_octets_t					&issuer_in,
			 const tmcg_openpgp_octets_t					&issuerfpr_in,
			 const tmcg_openpgp_octets_t					&keyflags_in,
			 const tmcg_openpgp_octets_t					&keyfeatures_in,
			 const tmcg_openpgp_octets_t					&keyprefs_psa_in,
			 const tmcg_openpgp_octets_t					&keyprefs_pha_in,
			 const tmcg_openpgp_octets_t					&keyprefs_pca_in,
			 const tmcg_openpgp_octets_t					&keyprefs_paa_in,
			 const tmcg_openpgp_octets_t					&embeddedsig_in);
		bool Good
			() const;
		void PrintInfo
			() const;
		bool CheckValidity
			(const time_t									keycreationtime,
			 const int										verbose) const;
		bool CheckIntegrity
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&hash,
	 		 const int 										verbose) const;
		bool VerifyData
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&data,
	 		 const int 										verbose) const;		
		bool Verify
			(const gcry_sexp_t								key,
			 const std::string								&filename,
			 const int										verbose);
		bool Verify
			(const gcry_sexp_t								key,
			 const int										verbose);
		bool Verify
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&hashing,
			 const int										verbose);
		bool Verify
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&pub_hashing,
			 const tmcg_openpgp_octets_t					&sub_hashing,
			 const int										verbose);
		bool Verify
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&pub_hashing,
			 const std::string								&userid,
			 const int										verbose);
		bool Verify
			(const gcry_sexp_t								key,
			 const tmcg_openpgp_octets_t					&pub_hashing,
			 const tmcg_openpgp_octets_t					&userattribute,
			 const int										dummy,
			 const int										verbose);
		bool operator <
			(const TMCG_OpenPGP_Signature					&that) const;
		~TMCG_OpenPGP_Signature
			();
};

class TMCG_OpenPGP_Pubkey; // forward declaration

class TMCG_OpenPGP_UserID
{
	private:
		static char ClearForbiddenCharacter
			(const char c)
		{
			if ((c < 0x20) || (c == 0x7F))
				return ' ';
			else
				return c;
		};
	public:
		bool												valid;
		bool												revoked;
		std::string											userid;
		std::string											userid_sanitized;
		tmcg_openpgp_octets_t								packet;
		std::vector<TMCG_OpenPGP_Signature*>				selfsigs;
		std::vector<TMCG_OpenPGP_Signature*>				revsigs;
		std::vector<TMCG_OpenPGP_Signature*>				certsigs;

		TMCG_OpenPGP_UserID
			(const std::string								&userid_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Check
			(const TMCG_OpenPGP_Pubkey*						primary,
			 const int										verbose);
		~TMCG_OpenPGP_UserID
			();
};

class TMCG_OpenPGP_UserAttribute
{
	public:
		bool												valid;
		bool												revoked;
		tmcg_openpgp_octets_t								userattribute;
		tmcg_openpgp_octets_t								packet;
		std::vector<TMCG_OpenPGP_Signature*>				selfsigs;
		std::vector<TMCG_OpenPGP_Signature*>				revsigs;
		std::vector<TMCG_OpenPGP_Signature*>				certsigs;

		TMCG_OpenPGP_UserAttribute
			(const tmcg_openpgp_octets_t					&userattribute_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Check
			(const TMCG_OpenPGP_Pubkey*						primary,
			 const int										verbose);
		~TMCG_OpenPGP_UserAttribute
			();
};

class TMCG_OpenPGP_Keyring; // forward declaration

class TMCG_OpenPGP_Subkey
{
	private:
		gcry_error_t										ret;
		size_t												erroff;

	public:
		bool												valid;
		bool												revoked;
		tmcg_openpgp_pkalgo_t								pkalgo;
		time_t												creationtime;
		time_t												expirationtime;
		gcry_sexp_t											key;
		gcry_mpi_t											rsa_n;
		gcry_mpi_t											rsa_e;
		gcry_mpi_t											elg_p;
		gcry_mpi_t											elg_g;
		gcry_mpi_t											elg_y;
		gcry_mpi_t											dsa_p;
		gcry_mpi_t											dsa_q;
		gcry_mpi_t											dsa_g;
		gcry_mpi_t											dsa_y;
		gcry_mpi_t											ec_pk;
		tmcg_openpgp_octets_t								packet;
		tmcg_openpgp_octets_t								sub_hashing;
		tmcg_openpgp_octets_t								id;
		tmcg_openpgp_octets_t								fingerprint;
		tmcg_openpgp_octets_t								flags;
		tmcg_openpgp_octets_t								features;
		tmcg_openpgp_octets_t								psa;
		tmcg_openpgp_octets_t								pha;
		tmcg_openpgp_octets_t								pca;
		tmcg_openpgp_octets_t								paa;
		std::string											ec_curve;
		tmcg_openpgp_hashalgo_t								kdf_hashalgo;
		tmcg_openpgp_skalgo_t								kdf_skalgo;
		std::vector<TMCG_OpenPGP_Signature*>				selfsigs;
		std::vector<TMCG_OpenPGP_Signature*>				bindsigs;
		std::vector<TMCG_OpenPGP_Signature*>				pbindsigs;
		std::vector<TMCG_OpenPGP_Signature*>				keyrevsigs;
		std::vector<TMCG_OpenPGP_Signature*>				certrevsigs;
		std::vector<tmcg_openpgp_revkey_t>					revkeys;

		TMCG_OpenPGP_Subkey
			(); // this is a dummy constructor used for simple relinking
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								e,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Subkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const tmcg_openpgp_hashalgo_t					kdf_hashalgo_in,
			 const tmcg_openpgp_skalgo_t					kdf_skalgo_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Good
			() const;
		bool Weak
			(const int										verbose) const;
		size_t AccumulateFlags
			() const;
		size_t AccumulateFeatures
			() const;
		tmcg_openpgp_revcode_t AccumulateRevocationCodes
			() const;
		void UpdateProperties
			(const TMCG_OpenPGP_Signature*					sig,
			 const int										verbose);
		bool CheckValidity
			(const int										verbose) const;
		bool CheckValidityPeriod
			(const time_t									at,
			 const int										verbose) const;
		bool CheckExternalRevocation
			(TMCG_OpenPGP_Signature*						sig,
			 const TMCG_OpenPGP_Keyring*					ring,
			 const int										verbose);
		bool Check
			(const TMCG_OpenPGP_Pubkey*						primary,
			 const TMCG_OpenPGP_Keyring*					ring,
			 const int verbose);
		~TMCG_OpenPGP_Subkey
			();
};

class TMCG_OpenPGP_PKESK; // forward declaration

class TMCG_OpenPGP_PrivateSubkey
{
	private:
		gcry_error_t										ret;
		size_t												erroff;

	public:
		tmcg_openpgp_pkalgo_t								pkalgo;
		TMCG_OpenPGP_Subkey*								pub;
		gcry_sexp_t											private_key;
		gcry_mpi_t											rsa_p;
		gcry_mpi_t											rsa_q;
		gcry_mpi_t											rsa_u;
		gcry_mpi_t											rsa_d;
		gcry_mpi_t											elg_x;
		gcry_mpi_t											dsa_x;
		gcry_mpi_t											ec_sk;
		size_t												telg_n;
		size_t												telg_t;
		size_t												telg_i;
		gcry_mpi_t											telg_q;
		gcry_mpi_t											telg_h;
		gcry_mpi_t											telg_x_i;
		gcry_mpi_t											telg_xprime_i;
		std::vector<size_t>									telg_qual;
		std::vector<gcry_mpi_t>								telg_v_i;
		std::vector< std::vector<gcry_mpi_t> >				telg_c_ik;
		std::string											ec_curve;
		tmcg_openpgp_octets_t								packet;

		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								e,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								u,
			 const gcry_mpi_t								d,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								h,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x_i,
			 const gcry_mpi_t								xprime_i,
			 const gcry_mpi_t								n_in,
			 const gcry_mpi_t								t_in,
			 const gcry_mpi_t								i_in,
			 const std::vector<gcry_mpi_t>					&qual,
			 const std::vector<gcry_mpi_t>					&v_i,
			 const std::vector< std::vector<gcry_mpi_t> >	&c_ik,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const gcry_mpi_t								ecsk,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PrivateSubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const gcry_mpi_t								ecsk,
			 const tmcg_openpgp_hashalgo_t					kdf_hashalgo_in,
			 const tmcg_openpgp_skalgo_t					kdf_skalgo_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Good
			() const;
		bool Weak
			(const int										verbose) const;
		bool Decrypt
			(const TMCG_OpenPGP_PKESK*						&esk,
			 const int										verbose,
			 tmcg_openpgp_secure_octets_t					&out) const;
		~TMCG_OpenPGP_PrivateSubkey
			();
};

class TMCG_OpenPGP_Pubkey
{
	private:
		gcry_error_t										ret;
		size_t												erroff;

	public:
		bool												valid;
		bool												revoked;
		tmcg_openpgp_pkalgo_t								pkalgo;
		time_t												creationtime;
		time_t												expirationtime;
		gcry_sexp_t											key;
		gcry_mpi_t											rsa_n;
		gcry_mpi_t											rsa_e;
		gcry_mpi_t											dsa_p;
		gcry_mpi_t											dsa_q;
		gcry_mpi_t											dsa_g;
		gcry_mpi_t											dsa_y;
		gcry_mpi_t											ec_pk;
		tmcg_openpgp_octets_t								packet;
		tmcg_openpgp_octets_t								pub_hashing;
		tmcg_openpgp_octets_t								id;
		tmcg_openpgp_octets_t								fingerprint;
		tmcg_openpgp_octets_t								flags;
		tmcg_openpgp_octets_t								features;
		tmcg_openpgp_octets_t								psa;
		tmcg_openpgp_octets_t								pha;
		tmcg_openpgp_octets_t								pca;
		tmcg_openpgp_octets_t								paa;
		std::string											ec_curve;
		std::vector<TMCG_OpenPGP_Signature*>				selfsigs;
		std::vector<TMCG_OpenPGP_Signature*>				keyrevsigs;
		std::vector<TMCG_OpenPGP_Signature*>				certrevsigs;
		std::vector<TMCG_OpenPGP_UserID*>					userids;
		std::vector<TMCG_OpenPGP_UserAttribute*>			userattributes;
		std::vector<TMCG_OpenPGP_Subkey*>					subkeys;
		std::vector<tmcg_openpgp_revkey_t>					revkeys;

		TMCG_OpenPGP_Pubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								e,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Pubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Pubkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Good
			() const;
		bool Weak
			(const int										verbose) const;
		size_t AccumulateFlags
			() const;
		size_t AccumulateFeatures
			() const;
		tmcg_openpgp_revcode_t AccumulateRevocationCodes
			() const;
		void UpdateProperties
			(const TMCG_OpenPGP_Signature*					sig,
			 const int										verbose);
		bool CheckValidity
			(const int										verbose) const;
		bool CheckValidityPeriod
			(const time_t									at,
			 const int										verbose) const;
		bool CheckExternalRevocation
			(TMCG_OpenPGP_Signature*						sig,
			 const TMCG_OpenPGP_Keyring*					ring,
			 const int										verbose);
		bool CheckSelfSignatures
			(const TMCG_OpenPGP_Keyring*					ring,
			 const int										verbose,
			 const bool external = true);
		bool CheckSubkeys
			(const TMCG_OpenPGP_Keyring*					ring,
			 const int										verbose);
		void Reduce
			();
		void Export
			(tmcg_openpgp_octets_t							&out) const;
		~TMCG_OpenPGP_Pubkey
			();
};

class TMCG_OpenPGP_Prvkey
{
	private:
		gcry_error_t										ret;
		size_t												erroff;

	public:
		tmcg_openpgp_pkalgo_t								pkalgo;
		TMCG_OpenPGP_Pubkey*								pub;
		gcry_sexp_t											private_key;
		std::vector<TMCG_OpenPGP_PrivateSubkey*>			private_subkeys;
		gcry_mpi_t											rsa_p;
		gcry_mpi_t											rsa_q;
		gcry_mpi_t											rsa_u;
		gcry_mpi_t											rsa_d;
		gcry_mpi_t											dsa_x;
		gcry_mpi_t											ec_sk;
		size_t												tdss_n;
		size_t												tdss_t;
		size_t												tdss_i;
		gcry_mpi_t											tdss_h;
		gcry_mpi_t											tdss_x_i;
		gcry_mpi_t											tdss_xprime_i;
		std::vector<std::string>							tdss_capl;
		std::vector<size_t>									tdss_qual;
		std::vector<size_t>									tdss_x_rvss_qual;
		std::vector< std::vector<gcry_mpi_t> >				tdss_c_ik;
		std::map<size_t, size_t>							tdss_idx2dkg;
		std::map<size_t, size_t>							tdss_dkg2idx;
		std::string											ec_curve;
		tmcg_openpgp_octets_t								packet;

		TMCG_OpenPGP_Prvkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								e,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								u,
			 const gcry_mpi_t								d,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Prvkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_Prvkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								h,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x_i,
			 const gcry_mpi_t								xprime_i,
			 const gcry_mpi_t								n_in,
			 const gcry_mpi_t								t_in,
			 const gcry_mpi_t								i_in,
			 const std::vector<std::string>					&capl,
			 const std::vector<gcry_mpi_t>					&qual,
			 const std::vector<gcry_mpi_t>					&x_rvss_qual,
			 const std::vector< std::vector<gcry_mpi_t> >	&c_ik,
			 const tmcg_openpgp_octets_t					&packet_in);
	TMCG_OpenPGP_Prvkey
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const time_t									creationtime_in,
			 const time_t									expirationtime_in,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const gcry_mpi_t								ecsk,
			 const tmcg_openpgp_octets_t					&packet_in);
		bool Good
			() const;
		bool Weak
			(const int										verbose) const;
		bool Decrypt
			(const TMCG_OpenPGP_PKESK*						&esk,
			 const int										verbose,
			 tmcg_openpgp_secure_octets_t					&out) const;
		void RelinkPublicSubkeys
			();
		void RelinkPrivateSubkeys
			();
		bool tDSS_CreateMapping
			(const std::vector<std::string>					&peers,
			 const int										verbose);
		void Export
			(tmcg_openpgp_octets_t							&out) const;
		~TMCG_OpenPGP_Prvkey
			();
};

class TMCG_OpenPGP_Keyring
{
	private:
		std::map<std::string, TMCG_OpenPGP_Pubkey*>			keys;
		std::map<std::string, TMCG_OpenPGP_Pubkey*>			keys_by_keyid;

	public:
		TMCG_OpenPGP_Keyring
			();
		bool Add
			(TMCG_OpenPGP_Pubkey*							key);
		TMCG_OpenPGP_Pubkey* Find
			(const std::string								&fingerprint) const;
		TMCG_OpenPGP_Pubkey* FindByKeyid
			(const std::string								&keyid) const;
		size_t Size
			() const;
		size_t List
			(const std::string								&userid) const;
		size_t Check
			(const int verbose) const;
		void Reduce
			();
		~TMCG_OpenPGP_Keyring
			();
};

class TMCG_OpenPGP_PKESK
{
	public:
		tmcg_openpgp_pkalgo_t								pkalgo;
		tmcg_openpgp_octets_t								keyid;
		gcry_mpi_t											me;
		gcry_mpi_t											gk;
		gcry_mpi_t											myk;
		gcry_mpi_t											ecepk;
		size_t												rkwlen;
		tmcg_openpgp_byte_t									rkw[256];
		tmcg_openpgp_octets_t								packet;

		TMCG_OpenPGP_PKESK
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const tmcg_openpgp_octets_t					&keyid_in,
			 const gcry_mpi_t								me_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PKESK
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const tmcg_openpgp_octets_t					&keyid_in,
			 const gcry_mpi_t								gk_in,
			 const gcry_mpi_t								myk_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		TMCG_OpenPGP_PKESK
			(const tmcg_openpgp_pkalgo_t					pkalgo_in,
			 const tmcg_openpgp_octets_t					&keyid_in,
			 const gcry_mpi_t								ecepk_in,
			 const size_t									rkwlen_in,
			 const tmcg_openpgp_byte_t*						rkw_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		~TMCG_OpenPGP_PKESK
			();
};

class TMCG_OpenPGP_SKESK
{
	public:
		tmcg_openpgp_byte_t									version;
		tmcg_openpgp_skalgo_t								skalgo;
		tmcg_openpgp_aeadalgo_t								aeadalgo;
		tmcg_openpgp_stringtokey_t							s2k_type;
		tmcg_openpgp_hashalgo_t								s2k_hashalgo;
		tmcg_openpgp_octets_t								s2k_salt;
		tmcg_openpgp_byte_t									s2k_count;
		tmcg_openpgp_octets_t								iv;
		tmcg_openpgp_octets_t								encrypted_key;
		tmcg_openpgp_octets_t								packet;

		TMCG_OpenPGP_SKESK
			(const tmcg_openpgp_byte_t						version_in,
			 const tmcg_openpgp_skalgo_t					skalgo_in,
			 const tmcg_openpgp_aeadalgo_t					aeadalgo_in,
			 const tmcg_openpgp_stringtokey_t				s2k_type_in,
			 const tmcg_openpgp_hashalgo_t					s2k_hashalgo_in,
			 const tmcg_openpgp_octets_t					&s2k_salt_in,
			 const tmcg_openpgp_byte_t						s2k_count_in,
			 const tmcg_openpgp_octets_t					&iv_in,
			 const tmcg_openpgp_octets_t					&encrypted_key_in,
			 const tmcg_openpgp_octets_t					&packet_in);
		~TMCG_OpenPGP_SKESK
			();
};

class TMCG_OpenPGP_Message
{
	private:
		bool CheckMDC
			(const tmcg_openpgp_octets_t					&prefix,
			 const tmcg_openpgp_octets_t					&mdc,
			 const tmcg_openpgp_octets_t					&mdc_message,
			 const int										verbose) const;

	public:
		bool												have_sed;
		bool												have_seipd;
		bool												have_aead;
		tmcg_openpgp_compalgo_t								compalgo;
		tmcg_openpgp_byte_t									format;
		std::string											filename;
		time_t												timestamp;
		tmcg_openpgp_skalgo_t								skalgo;
		tmcg_openpgp_aeadalgo_t								aeadalgo;
		tmcg_openpgp_byte_t									chunksize;
		tmcg_openpgp_octets_t								iv;
		std::vector<const TMCG_OpenPGP_PKESK*>				PKESKs;
		std::vector<const TMCG_OpenPGP_SKESK*>				SKESKs;
		tmcg_openpgp_octets_t								encrypted_message;
		tmcg_openpgp_octets_t								signed_message;
		tmcg_openpgp_octets_t								compressed_message;
		tmcg_openpgp_octets_t								compressed_data;
		tmcg_openpgp_octets_t								literal_message;
		tmcg_openpgp_octets_t								literal_data;
		tmcg_openpgp_octets_t								mdc;	
		std::vector<const TMCG_OpenPGP_Signature*>			signatures;

		TMCG_OpenPGP_Message
			();
		bool Decrypt
			(const tmcg_openpgp_secure_octets_t				&key,
			 const int										verbose,
			 tmcg_openpgp_octets_t							&out) const;
		~TMCG_OpenPGP_Message
			();
};

class CallasDonnerhackeFinneyShawThayerRFC4880
{
	private:
		static unsigned long int tmcg_openpgp_mem_alloc; // memory guard accum.
		static bool NotRadix64
			(const char c)
		{
			for (size_t i = 0; i < sizeof(tmcg_openpgp_tRadix64); i++)
			{
				if (c == tmcg_openpgp_tRadix64[i])
					return false;
			}
			return true;
		};
		static void Release
			(std::vector<gcry_mpi_t>						&qual,
			 std::vector<gcry_mpi_t>						&v_i,
			 std::vector<gcry_mpi_t>						&x_rvss_qual,
			 std::vector< std::vector<gcry_mpi_t> >			&c_ik);
		static bool PublicKeyBlockParse_Tag2
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const bool										primary,
			 const bool										subkey,
			 const bool										badkey,
			 const bool										uid_flag,
			 const bool										uat_flag,
			 const tmcg_openpgp_octets_t					&current_packet,
			 tmcg_openpgp_octets_t							&embedded_pkt,
			 TMCG_OpenPGP_Pubkey*							&pub,
			 TMCG_OpenPGP_Subkey*							&sub,
			 TMCG_OpenPGP_UserID*							&uid,
			 TMCG_OpenPGP_UserAttribute*					&uat);
		static bool PublicKeyBlockParse_Tag6
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&primary,
			 TMCG_OpenPGP_Pubkey*							&pub);
		static bool PublicKeyBlockParse_Tag13
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const bool										primary,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&uid_flag,
			 bool											&uat_flag,
			 TMCG_OpenPGP_Pubkey*							&pub,
			 TMCG_OpenPGP_UserID*							&uid,
			 TMCG_OpenPGP_UserAttribute*					&uat);
		static bool PublicKeyBlockParse_Tag14
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const bool										primary,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&subkey,
			 bool											&badkey,
			 TMCG_OpenPGP_Pubkey*							&pub,
			 TMCG_OpenPGP_Subkey*							&sub);
		static bool PublicKeyBlockParse_Tag17
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const bool										primary,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&uid_flag,
			 bool											&uat_flag,
			 TMCG_OpenPGP_Pubkey*							&pub,
			 TMCG_OpenPGP_UserID*							&uid,
			 TMCG_OpenPGP_UserAttribute*					&uat);
		static bool PrivateKeyBlockParse_Decrypt
			(tmcg_openpgp_packet_ctx_t						&ctx,
			 const int										verbose,
			 const tmcg_openpgp_secure_string_t				&passphrase);
		static bool PrivateKeyBlockParse_Tag5
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&primary,
			 TMCG_OpenPGP_Prvkey*							&prv);
		static bool PrivateKeyBlockParse_Tag7
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const bool										primary,
			 const tmcg_openpgp_octets_t					&current_packet,
			 bool											&subkey,
			 bool											&badkey,
			 TMCG_OpenPGP_Prvkey*							&prv,
			 TMCG_OpenPGP_PrivateSubkey*					&sub);
		static bool MessageParse_Tag1
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag2
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag3
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag8
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag9
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag11
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag18
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag19
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse_Tag20
			(const tmcg_openpgp_packet_ctx_t				&ctx,
			 const int										verbose,
			 const tmcg_openpgp_octets_t					&current_packet,
			 TMCG_OpenPGP_Message*							&msg);
		static void PublicKeyringParse_Add
			(const int										verbose,
			 bool											&primary,
			 bool											&subkey,
			 bool											&badkey,
	 		 bool											&uid_flag,
			 bool											&uat_flag,
	 		 TMCG_OpenPGP_Pubkey*							&pub,
			 TMCG_OpenPGP_Subkey*							&sub,
	 		 TMCG_OpenPGP_UserID*							&uid,
			 TMCG_OpenPGP_UserAttribute*					&uat,
	 		 TMCG_OpenPGP_Keyring*							&ring);

	public:
		static void MemoryGuardReset
			();
		static unsigned long int MemoryGuardInfo
			();

		static size_t AlgorithmKeyLength
			(const tmcg_openpgp_skalgo_t					algo);
		static size_t AlgorithmIVLength
			(const tmcg_openpgp_skalgo_t					algo);
		static size_t AlgorithmIVLength
			(const tmcg_openpgp_aeadalgo_t					algo);
		static int AlgorithmSymGCRY
			(const tmcg_openpgp_skalgo_t					algo);
		static size_t AlgorithmHashLength
			(const tmcg_openpgp_hashalgo_t					algo);
		static int AlgorithmHashGCRY
			(const tmcg_openpgp_hashalgo_t					algo);
		static void AlgorithmHashGCRYName
			(const tmcg_openpgp_hashalgo_t					algo,
			 std::string									&out);
		static void AlgorithmHashTextName
			(const tmcg_openpgp_hashalgo_t					algo,
			 std::string									&out);
		static bool OctetsCompare
			(const tmcg_openpgp_octets_t					&in,
			 const tmcg_openpgp_octets_t					&in2);
		static bool OctetsCompareConstantTime
			(const tmcg_openpgp_secure_octets_t				&in,
			 const tmcg_openpgp_secure_octets_t				&in2);
		static bool OctetsCompareZero
			(const tmcg_openpgp_octets_t					&in);

		static void Radix64Encode
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out,
			 const bool										linebreaks = true);
		static void Radix64Decode
			(std::string									in,
			 tmcg_openpgp_octets_t							&out);
		static void CRC24Compute
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void CRC24Encode
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void ArmorEncode
			(const tmcg_openpgp_armor_t						type,
			 const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static tmcg_openpgp_armor_t ArmorDecode
			(std::string									in,
			 tmcg_openpgp_octets_t							&out);
		static bool DashEscapeFile
			(const std::string								&filename,
			 std::string									&out);
		static void FingerprintCompute
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void FingerprintConvertPlain
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void FingerprintConvertPretty
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void FingerprintCompute
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void FingerprintCompute
			(const std::string								&in,
			 std::string									&out);
		static void FingerprintComputePretty
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void KeyidCompute
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void KeyidConvert
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void KeyidCompute
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);
		static void HashCompute
			(const tmcg_openpgp_hashalgo_t					algo,
			 const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t HashCompute
			(const tmcg_openpgp_hashalgo_t					algo,
			 const tmcg_openpgp_secure_octets_t				&in,
			 tmcg_openpgp_secure_octets_t					&out);
		static void HashCompute
			(const tmcg_openpgp_hashalgo_t					algo,
			 const size_t									cnt,
			 const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t HashCompute
			(const tmcg_openpgp_hashalgo_t					algo,
			 const size_t									cnt,
			 const tmcg_openpgp_secure_octets_t				&in,
			 tmcg_openpgp_secure_octets_t					&out);
		static bool HashComputeFile
			(const tmcg_openpgp_hashalgo_t					algo,
			 const std::string								&filename,
			 const bool										text,
			 const tmcg_openpgp_octets_t					&trailer,
			 tmcg_openpgp_octets_t							&out);
		static void S2KCompute
			(const tmcg_openpgp_hashalgo_t					algo,
			 const size_t									sklen,
			 const tmcg_openpgp_secure_string_t				&in,
			 const tmcg_openpgp_octets_t					&salt, 
			 const bool										iterated,
			 const tmcg_openpgp_byte_t						octcnt,
			 tmcg_openpgp_secure_octets_t					&out);
		static gcry_error_t KDFCompute
			(const tmcg_openpgp_hashalgo_t					hashalgo,
			 const tmcg_openpgp_skalgo_t					skalgo,
			 const tmcg_openpgp_secure_octets_t				&ZB,
			 const std::string								&curve,
			 const tmcg_openpgp_octets_t					&rcpfpr,
			 tmcg_openpgp_secure_octets_t					&MB);

		static void PacketTagEncode
			(const tmcg_openpgp_byte_t						tag,
			 tmcg_openpgp_octets_t							&out); 
		static void PacketLengthEncode
			(const size_t									len,
			 tmcg_openpgp_octets_t							&out);
		static void FixedLengthEncode
			(const size_t									len,
			 tmcg_openpgp_octets_t							&out);
		static size_t PacketLengthDecode
			(const tmcg_openpgp_octets_t					&in,
			 const bool										newformat,
			 tmcg_openpgp_byte_t							lentype,
			 uint32_t										&len,
			 bool											&partlen);
		static void PacketTimeEncode
			(const time_t									in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketTimeEncode
			(tmcg_openpgp_octets_t							&out);
		static void PacketMPIEncode
			(const gcry_mpi_t								in,
			 tmcg_openpgp_octets_t							&out,
			 size_t											&sum);
		static void PacketMPIEncode
			(const gcry_mpi_t								in,
			 tmcg_openpgp_secure_octets_t					&out,
			 size_t											&sum);
		static void PacketMPIEncode
			(const gcry_mpi_t								in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketMPIEncode
			(const gcry_mpi_t								in,
			 tmcg_openpgp_secure_octets_t					&out);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_octets_t					&in,
			 gcry_mpi_t										&out,
			 size_t											&sum);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_secure_octets_t				&in,
			 gcry_mpi_t										&out,
			 size_t											&sum);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_octets_t					&in,
			 gcry_mpi_t										&out);
		static size_t PacketMPIDecode
			(const tmcg_openpgp_secure_octets_t				&in,
			 gcry_mpi_t										&out);
		static void PacketStringEncode
			(const std::string								&in,
			 tmcg_openpgp_octets_t							&out);
		static size_t PacketStringDecode
			(const tmcg_openpgp_octets_t					&in,
			 std::string									&out);

		static void PacketPkeskEncode
			(const tmcg_openpgp_octets_t					&keyid,
			 const gcry_mpi_t								gk,
			 const gcry_mpi_t								myk,
			 tmcg_openpgp_octets_t							&out);
		static void PacketPkeskEncode
			(const tmcg_openpgp_octets_t					&keyid,
			 const gcry_mpi_t								me,
			 tmcg_openpgp_octets_t							&out);
		static void PacketPkeskEncode
			(const tmcg_openpgp_octets_t					&keyid,
			 const gcry_mpi_t 								ecepk,
	 		 const size_t									rkwlen,
			 const tmcg_openpgp_byte_t						rkw[256],
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigEncode
			(const tmcg_openpgp_octets_t					&hashing,
			 const tmcg_openpgp_octets_t					&left,
			 const gcry_mpi_t								r,
			 const gcry_mpi_t								s,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigEncode
			(const tmcg_openpgp_octets_t					&hashing,
			 const tmcg_openpgp_octets_t					&left,
			 const gcry_mpi_t								s,
			 tmcg_openpgp_octets_t							&out);
		static void SubpacketEncode
			(const tmcg_openpgp_byte_t						type,
			 const bool										critical,
			 const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareSelfSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const time_t									keyexptime,
			 const tmcg_openpgp_octets_t					&flags,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareSelfSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_pkalgo_t					pkalgo, 
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 const time_t									sigtime,
			 const time_t									keyexptime,
			 const tmcg_openpgp_octets_t					&flags,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareDesignatedRevoker
			(const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const tmcg_openpgp_octets_t					&flags,
			 const tmcg_openpgp_octets_t					&issuer,
			 const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_octets_t					&revoker,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareDesignatedRevoker
			(const tmcg_openpgp_pkalgo_t					pkalgo, 
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const tmcg_openpgp_octets_t					&flags,
			 const tmcg_openpgp_octets_t					&issuer,
			 const tmcg_openpgp_pkalgo_t					pkalgo2,
			 const tmcg_openpgp_octets_t					&revoker,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareDetachedSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const time_t									sigexptime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareDetachedSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const time_t									sigexptime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareRevocationSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const tmcg_openpgp_revcode_t					revcode,
			 const std::string								&reason,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareRevocationSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const tmcg_openpgp_revcode_t					revcode,
			 const std::string								&reason,
			 const tmcg_openpgp_octets_t					&issuer, 
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareCertificationSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const time_t									sigexptime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareCertificationSignature
			(const tmcg_openpgp_signature_t					type,
			 const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 const time_t									sigtime,
			 const time_t									sigexptime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareTimestampSignature
			(const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 const time_t									sigtime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer,
			 const tmcg_openpgp_pkalgo_t					target_pkalgo,
			 const tmcg_openpgp_hashalgo_t					target_hashalgo,
			 const tmcg_openpgp_octets_t					&target_hash,
			 const tmcg_openpgp_notations_t					&notations,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSigPrepareTimestampSignature
			(const tmcg_openpgp_pkalgo_t					pkalgo,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 const time_t									sigtime,
			 const std::string								&policy,
			 const tmcg_openpgp_octets_t					&issuer,
			 const tmcg_openpgp_octets_t					&target_signature,
			 const tmcg_openpgp_notations_t					&notations,
			 tmcg_openpgp_octets_t							&out);
		static void PacketPubEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 tmcg_openpgp_octets_t							&out);
		static void PacketPubEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const tmcg_openpgp_hashalgo_t					kdf_hashalgo,
			 const tmcg_openpgp_skalgo_t					kdf_skalgo,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSecEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								x,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSecEncodeExperimental108
			(const time_t									keytime,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								h,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								t,
			 const gcry_mpi_t								i,
			 const gcry_mpi_t								qualsize,
			 const std::vector<gcry_mpi_t>					&qual,
			 const std::vector<std::string>					&capl,
			 const std::vector< std::vector<gcry_mpi_t> >	&c_ik,
			 const gcry_mpi_t								x_i,
			 const gcry_mpi_t								xprime_i,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSecEncodeExperimental107
			(const time_t									keytime,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								h,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								t,
			 const gcry_mpi_t								i,
			 const gcry_mpi_t								qualsize,
			 const std::vector<gcry_mpi_t>					&qual,
			 const gcry_mpi_t								x_rvss_qualsize,
			 const std::vector<gcry_mpi_t>					&x_rvss_qual,
			 const std::vector<std::string>					&capl,
			 const std::vector< std::vector<gcry_mpi_t> >	&c_ik,
			 const gcry_mpi_t								x_i,
			 const gcry_mpi_t								xprime_i,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSubEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSubEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const size_t									oidlen,
			 const tmcg_openpgp_byte_t*						oid,
			 const gcry_mpi_t								ecpk,
			 const tmcg_openpgp_hashalgo_t					kdf_hashalgo,
			 const tmcg_openpgp_skalgo_t					kdf_skalgo,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSsbEncode
			(const time_t									keytime,
			 const tmcg_openpgp_pkalgo_t					algo,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								y, 
			 const gcry_mpi_t								x,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSsbEncodeExperimental109
			(const time_t									keytime,
			 const gcry_mpi_t								p,
			 const gcry_mpi_t								q,
			 const gcry_mpi_t								g,
			 const gcry_mpi_t								h,
			 const gcry_mpi_t								y,
			 const gcry_mpi_t								n,
			 const gcry_mpi_t								t,
			 const gcry_mpi_t								i,
			 const gcry_mpi_t								qualsize,
			 const std::vector<gcry_mpi_t>					&qual,
			 const std::vector<gcry_mpi_t>					&v_i,
			 const std::vector< std::vector<gcry_mpi_t> >	&c_ik,
			 const gcry_mpi_t								x_i,
			 const gcry_mpi_t								xprime_i,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSedEncode
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketLitEncode
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketUidEncode
			(const std::string								&uid,
			 tmcg_openpgp_octets_t							&out);
		static void PacketSeipdEncode
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketMdcEncode
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);
		static void PacketAeadEncode
			(const tmcg_openpgp_skalgo_t					skalgo,
			 const tmcg_openpgp_aeadalgo_t					aeadalgo,
			 const tmcg_openpgp_byte_t						chunksize,
			 const tmcg_openpgp_octets_t					&iv,
			 const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_octets_t							&out);

		static tmcg_openpgp_byte_t SubpacketDecode
			(tmcg_openpgp_octets_t							&in,
			 const int										verbose,
			 tmcg_openpgp_packet_ctx_t						&out);
		static tmcg_openpgp_byte_t SubpacketParse
			(tmcg_openpgp_octets_t							&in,
			 const int										verbose,
			 tmcg_openpgp_packet_ctx_t						&out,
			 tmcg_openpgp_notations_t						&notations);
		static void PacketContextEvaluate
			(const tmcg_openpgp_packet_ctx_t				&in,
			 tmcg_openpgp_packet_ctx_t						&out);
		static tmcg_openpgp_byte_t PacketBodyExtract
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 tmcg_openpgp_octets_t							&out);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t							&in,
			 const int										verbose,
			 tmcg_openpgp_packet_ctx_t						&out,
			 tmcg_openpgp_octets_t							&current_packet,
			 std::vector<gcry_mpi_t>						&qual,
			 std::vector<gcry_mpi_t>						&x_rvss_qual,
			 std::vector<std::string>						&capl,
			 std::vector<gcry_mpi_t>						&v_i,
			 std::vector< std::vector<gcry_mpi_t> >			&c_ik,
			 tmcg_openpgp_notations_t						&notations);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t							&in,
			 const int										verbose,
			 tmcg_openpgp_packet_ctx_t						&out,
			 tmcg_openpgp_octets_t							&current_packet,
			 std::vector<gcry_mpi_t>						&qual,
			 std::vector<std::string>						&capl,
			 std::vector<gcry_mpi_t>						&v_i,
			 std::vector< std::vector<gcry_mpi_t> >			&c_ik,
			 tmcg_openpgp_notations_t						&notations);
		static tmcg_openpgp_byte_t PacketDecode
			(tmcg_openpgp_octets_t							&in,
			 const int										verbose,
			 tmcg_openpgp_packet_ctx_t						&out,
			 tmcg_openpgp_octets_t							&current_packet,
			 tmcg_openpgp_notations_t						&notations);
		static void PacketContextRelease
			(tmcg_openpgp_packet_ctx_t						&ctx);

		static bool BinaryDocumentHashV3
			(const std::string								&filename,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool BinaryDocumentHashV3
			(const tmcg_openpgp_octets_t					&data,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool BinaryDocumentHash
			(const std::string								&filename,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool BinaryDocumentHash
			(const tmcg_openpgp_octets_t					&data,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool TextDocumentHashV3
			(const std::string								&filename,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool TextDocumentHashV3
			(const tmcg_openpgp_octets_t					&data,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool TextDocumentHash
			(const std::string								&filename,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool TextDocumentHash
			(const tmcg_openpgp_octets_t					&data,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool StandaloneHashV3
			(const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static bool StandaloneHash
			(const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void CertificationHashV3
			(const tmcg_openpgp_octets_t					&key,
			 const std::string								&uid,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void CertificationHash
			(const tmcg_openpgp_octets_t					&key,
			 const std::string								&uid,
			 const tmcg_openpgp_octets_t					&uat,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void KeyHashV3
			(const tmcg_openpgp_octets_t					&key,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void KeyHash
			(const tmcg_openpgp_octets_t					&key,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void KeyHashV3
			(const tmcg_openpgp_octets_t					&primary,
			 const tmcg_openpgp_octets_t					&subkey,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);
		static void KeyHash
			(const tmcg_openpgp_octets_t					&primary,
			 const tmcg_openpgp_octets_t					&subkey,
			 const tmcg_openpgp_octets_t					&trailer,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 tmcg_openpgp_octets_t							&hash,
			 tmcg_openpgp_octets_t							&left);

		static gcry_error_t SymmetricEncryptAES256
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_secure_octets_t					&seskey,
			 tmcg_openpgp_octets_t							&prefix,
			 const bool										resync,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t SymmetricEncryptAEAD
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_secure_octets_t					&seskey,
			 const tmcg_openpgp_skalgo_t					skalgo,
			 const tmcg_openpgp_aeadalgo_t					aeadalgo,
			 const tmcg_openpgp_byte_t						chunksize,
			 const tmcg_openpgp_octets_t					&ad,
			 const int										verbose,
			 tmcg_openpgp_octets_t							&iv,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t SymmetricDecrypt
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_secure_octets_t					&seskey,
			 tmcg_openpgp_octets_t							&prefix,
			 const bool										resync,
			 const tmcg_openpgp_skalgo_t					algo,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t SymmetricDecryptAES256
			(const tmcg_openpgp_octets_t					&in,
			 tmcg_openpgp_secure_octets_t					&seskey,
			 tmcg_openpgp_octets_t							&prefix,
			 const bool										resync,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t SymmetricDecryptAEAD
			(const tmcg_openpgp_octets_t					&in,
			 const tmcg_openpgp_secure_octets_t				&seskey,
			 const tmcg_openpgp_skalgo_t					skalgo,
			 const tmcg_openpgp_aeadalgo_t					aeadalgo,
			 const tmcg_openpgp_byte_t						chunksize,
			 const tmcg_openpgp_octets_t					&iv,
			 const tmcg_openpgp_octets_t					&ad,
			 const int										verbose,
			 tmcg_openpgp_octets_t							&out);
		static gcry_error_t AsymmetricEncryptElgamal
			(const tmcg_openpgp_secure_octets_t				&in,
			 const gcry_sexp_t								key, 
			 gcry_mpi_t										&gk,
			 gcry_mpi_t										&myk);
		static gcry_error_t AsymmetricDecryptElgamal
			(const gcry_mpi_t								gk,
			 const gcry_mpi_t								myk,
			 const gcry_sexp_t								key,
			 tmcg_openpgp_secure_octets_t					&out);
		static gcry_error_t AsymmetricEncryptRSA
			(const tmcg_openpgp_secure_octets_t				&in,
			 const gcry_sexp_t								key,
			 gcry_mpi_t										&me);
		static gcry_error_t AsymmetricDecryptRSA
			(const gcry_mpi_t								me,
			 const gcry_sexp_t								key,
			 tmcg_openpgp_secure_octets_t					&out);
		static gcry_error_t AsymmetricEncryptECDH
			(const tmcg_openpgp_secure_octets_t				&in,
			 const gcry_sexp_t								key,
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 const tmcg_openpgp_skalgo_t					skalgo,
			 const std::string								&curve,
			 const tmcg_openpgp_octets_t					&rcpfpr,
			 gcry_mpi_t										&ecepk,
	 		 size_t											&rkwlen,
			 tmcg_openpgp_byte_t							rkw[256]);
		static gcry_error_t AsymmetricDecryptECDH
			(const gcry_mpi_t								ecepk,
			 const gcry_sexp_t								key,
			 const size_t									rkwlen,
			 const tmcg_openpgp_byte_t						rkw[256],
			 const tmcg_openpgp_hashalgo_t					hashalgo,
			 const tmcg_openpgp_skalgo_t					skalgo,
			 const std::string								&curve,
			 const tmcg_openpgp_octets_t					&rcpfpr,
			 tmcg_openpgp_secure_octets_t					&out);
		static gcry_error_t AsymmetricSignDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
			 gcry_mpi_t										&r,
			 gcry_mpi_t										&s);
		static gcry_error_t AsymmetricSignECDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
			 gcry_mpi_t										&r,
			 gcry_mpi_t										&s);
		static gcry_error_t AsymmetricSignEdDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
			 gcry_mpi_t										&r,
			 gcry_mpi_t										&s);
		static gcry_error_t AsymmetricVerifyDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
	 		 const gcry_mpi_t								r,
			 const gcry_mpi_t								s);
		static gcry_error_t AsymmetricVerifyECDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
	 		 const gcry_mpi_t								r,
			 const gcry_mpi_t								s);
		static gcry_error_t AsymmetricVerifyEdDSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
	 		 const gcry_mpi_t								r,
			 const gcry_mpi_t								s);
		static gcry_error_t AsymmetricSignRSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
			 gcry_mpi_t										&s);
		static gcry_error_t AsymmetricVerifyRSA
			(const tmcg_openpgp_octets_t					&in,
			 const gcry_sexp_t								key,
			 const tmcg_openpgp_hashalgo_t					hashalgo, 
	 		 const gcry_mpi_t								s);

		static bool PublicKeyBlockParse
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 TMCG_OpenPGP_Pubkey*							&pub);
		static bool PublicKeyBlockParse
			(const std::string								&in,
			 const int										verbose,
			 TMCG_OpenPGP_Pubkey*							&pub);
		static bool SignatureParse
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 TMCG_OpenPGP_Signature*						&sig);
		static bool SignatureParse
			(const std::string								&in,
			 const int										verbose,
			 TMCG_OpenPGP_Signature*						&sig);
		static bool PublicKeyringParse
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 TMCG_OpenPGP_Keyring*							&ring);
		static bool PublicKeyringParse
			(const std::string								&in,
			 const int										verbose,
			 TMCG_OpenPGP_Keyring*							&ring);
		static bool PrivateKeyBlockParse
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 TMCG_OpenPGP_Prvkey*							&prv);
		static bool PrivateKeyBlockParse
			(const std::string								&in,
			 const int										verbose,
			 const tmcg_openpgp_secure_string_t				&passphrase,
			 TMCG_OpenPGP_Prvkey*							&prv);
		static bool MessageParse
			(const tmcg_openpgp_octets_t					&in,
			 const int										verbose,
			 TMCG_OpenPGP_Message*							&msg);
		static bool MessageParse
			(const std::string								&in,
			 const int										verbose,
			 TMCG_OpenPGP_Message*							&msg);
};

#endif

