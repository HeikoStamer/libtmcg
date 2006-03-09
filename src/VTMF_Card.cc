/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006  Heiko Stamer <stamer@gaos.org>

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
		if (!TMCG_ParseHelper::cm(s, "crd", '|'))
			throw false;
		
		// card data
		if ((mpz_set_str(c_1, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		if ((mpz_set_str(c_2, TMCG_ParseHelper::gs(s, '|').c_str(), 
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
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

std::ostream& operator <<
	(std::ostream& out, const VTMF_Card& card)
{
	out << "crd|" << card.c_1 << "|" << card.c_2 << "|";
	return out;
}

std::istream& operator >>
	(std::istream& in, VTMF_Card& card)
{
	char *tmp = new char[TMCG_MAX_CARD_CHARS];
	in.getline(tmp, TMCG_MAX_CARD_CHARS);
	if (!card.import(std::string(tmp)))
	{
		mpz_set_ui(card.c_1, 0L), mpz_set_ui(card.c_2, 0L);
		in.setstate(std::istream::iostate(std::istream::failbit));
	}
	delete [] tmp;
	return in;
}
