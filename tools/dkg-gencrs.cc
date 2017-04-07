/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
#include <libTMCG.hh>

#include <cassert>

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());

	// create VTMF instance for CRS (common reference string)
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true);

	// check the instance
	if (!vtmf->CheckGroup())
	{
		std::cerr << "ERROR: Group G for CRS was not correctly generated!" << std::endl;
		exit(-1);
	}

	// export group parameters to stdout
	std::cout << "// setup CRS (common reference string) |p| = " << mpz_sizeinbase(vtmf->p, 2L) <<
		 " bit, |q| = " << mpz_sizeinbase(vtmf->q, 2L) << " bit" << std::endl;
	std::cout << "crs = \"crs|" << vtmf->p << "|" << vtmf->q << "|" << vtmf->g << "|" << vtmf->k << "|\"" << std::endl;

	// release
	delete vtmf;
	
	return 0;
}
