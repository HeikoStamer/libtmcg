/*******************************************************************************
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
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#include <iostream>
#include <cassert>

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
	OCTETS in, out;
	BYTE b;
	
	// testing ArmorEncode() and ArmorDecode()
	for (size_t j = 0; j < 10; j++)
	{
		std::string u = "Max Mustermann <maxi@moritz.de>", armor;

		if ((j != 1) && (j != 2) && (j != 5) && (j != 6))
			continue;
		in.clear(), out.clear();
		std::cout << "PackedUidEncode(\"" << u << "\", in)" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, in);
		std::cout << "ArmorEncode(" << j << ", in, armor)" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(j, in, armor);
		std::cout << armor << std::endl;

		std::cout << "ArmorDecode(armor, out) = ";
		b = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armor, out);
		std::cout << (int)b << std::endl;
		assert((int)b == j);
		assert(in.size() == out.size());
		for (size_t i = 0; i < in.size(); i++)
		{
			assert(in[i] == out[i]);
		}
	}

	// testing SymmetricEncryptAES256() and SymmetricDecryptAES256()
	size_t erroff;
	gcry_mpi_t gk, myk;
	gcry_sexp_t elgkey, elgparms;
	OCTETS lit, seskey, prefix, enc, subkeyid;
	std::string m = "This is a test message.", armored_message;
	in.clear();
	for (size_t i = 0; i < m.length(); i++)
		in.push_back(m[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(in, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit,
		seskey, prefix, true, enc);
	assert(!ret);
	out.clear();
	ret = gcry_sexp_build(&elgparms, &erroff, "(genkey (elg (nbits 4:2048)))");
	assert(!ret);
	ret = gcry_pk_genkey(&elgkey, elgparms);
	assert(!ret);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
	assert(!ret);
	for (size_t i = 0; i < 8; i++)
		subkeyid.push_back(0x00);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, gk, myk, out);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode(enc, out);
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(1, out, armored_message);
	std::cout << armored_message << std::endl;
	out.clear(), prefix.clear();
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecryptAES256(enc,
		seskey, prefix, true, out);
	assert(!ret);
	assert(lit.size() == out.size());
	for (size_t i = 0; i < in.size(); i++)
	{
		assert(lit[i] == out[i]);
	}
	
	return 0;
}
