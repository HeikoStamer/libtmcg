/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004 Heiko Stamer, <stamer@gaos.org>

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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include "VTMF_Card.hh"

VTMF_Card::VTMF_Card
	()
{
	mpz_init(c_1), mpz_init(c_2);
}

VTMF_Card::VTMF_Card
	(const VTMF_Card& that)
{
	mpz_init_set(c_1, that.c_1), mpz_init_set(c_2, that.c_2);
}

VTMF_Card& VTMF_Card::operator =
	(const VTMF_Card& that)
{
	mpz_set(c_1, that.c_1), mpz_set(c_2, that.c_2);
	return *this;
}

bool VTMF_Card::operator ==
	(const VTMF_Card& that) const
{
	if (mpz_cmp(c_1, that.c_1) || mpz_cmp(c_2, that.c_2))
		return false;
	return true;
}

bool VTMF_Card::operator !=
	(const VTMF_Card& that) const
{
	return !(*this == that);
}

bool VTMF_Card::import
	(std::string s)
{
	try
	{
		// check magic
		if (!cm(s, "crd", '|'))
			throw false;
		
		// card data
		if ((mpz_set_str(c_1, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		if ((mpz_set_str(c_2, gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!nx(s, '|')))
				throw false;
		
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

VTMF_Card::~VTMF_Card()
{
	mpz_clear(c_1), mpz_clear(c_2);
}

std::ostream& operator<< 
	(std::ostream &out, const VTMF_Card &card)
{
	out << "crd|" << card.c_1 << "|" << card.c_2 << "|";
	return out;
}
