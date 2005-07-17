/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004  Heiko Stamer <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#include "VTMF_CardSecret.hh"

VTMF_CardSecret::VTMF_CardSecret
	()
{
	mpz_init(r);
}

VTMF_CardSecret::VTMF_CardSecret
	(const VTMF_CardSecret& that)
{
	mpz_init_set(r, that.r);
}

VTMF_CardSecret& VTMF_CardSecret::operator =
	(const VTMF_CardSecret& that)
{
	mpz_set(r, that.r);
	return *this;
}

bool VTMF_CardSecret::import
	(std::string s)
{
	try
	{
		// check magic
		if (!cm(s, "crs", '|'))
			throw false;
		
		// secret card data
		if ((mpz_set_str(r, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

VTMF_CardSecret::~VTMF_CardSecret
	()
{
	mpz_clear(r);
}

std::ostream& operator<<
	(std::ostream &out, const VTMF_CardSecret &cardsecret)
{
	return out << "crs|" << cardsecret.r << "|";
}
