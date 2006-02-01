/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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

#include "mpz_helper.hh"

// iostream operators for mpz_t
std::ostream& operator <<
	(std::ostream &out, mpz_srcptr value)
{
	char *tmp = new char[TMCG_MAX_VALUE_CHARS];
	if (mpz_sizeinbase(value, TMCG_MPZ_IO_BASE) < TMCG_MAX_VALUE_CHARS)
		out << mpz_get_str(tmp, TMCG_MPZ_IO_BASE, value);
	delete [] tmp;
	return out;
}

std::istream& operator >>
	(std::istream &in, mpz_ptr value)
{
	char *tmp = new char[TMCG_MAX_VALUE_CHARS];
	in.getline(tmp, TMCG_MAX_VALUE_CHARS);
	if (mpz_set_str(value, tmp, TMCG_MPZ_IO_BASE) < 0)
	{
		mpz_set_ui(value, 0L);
		in.setstate(std::istream::iostate(std::istream::failbit));
	}
	delete [] tmp;
	return in;
}
