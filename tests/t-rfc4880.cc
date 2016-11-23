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

#include <libTMCG.hh>

#include "test_helper.h"

#undef NDEBUG

int main
	(int argc, char **argv)
{
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
	
	return 0;
}
