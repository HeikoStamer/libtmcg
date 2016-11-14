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
	std::string u = "Max Mustermann <maxi@moritz.de>", armor;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, in);
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, in, armor);
	std::cout << armor << std::endl;

	b = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armor, out);
	assert(b == 6);
	assert(in.size() == out.size());
	for (size_t i = 0; i < in.size(); i++)
	{
		assert(in[i] == out[i]);
	}		
	
	return 0;
}
