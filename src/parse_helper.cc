/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2004, 2006  Heiko Stamer <stamer@gaos.org>

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

#include "parse_helper.hh"

// simple methods for parsing
bool TMCG_ParseHelper::cm
	(std::string &s, const std::string &c, char p)
{
	size_t ei;
	if ((ei = s.find(p, 0)) != s.npos)
	{
		if (s.substr(0, ei) != c)
			return false;
		else
			s = s.substr(ei + 1, s.length() - ei - 1);
	}
	else
		return false;
	return true;
}

bool TMCG_ParseHelper::nx
	(std::string &s, char p)
{
	size_t ei;
	if ((ei = s.find(p, 0)) != s.npos)
		s = s.substr(ei + 1, s.length() - ei - 1);
	else
		return false;
	return true;
}

std::string TMCG_ParseHelper::gs
	(const std::string &s, char p)
{
	size_t ei;
	if ((ei = s.find(p, 0)) != s.npos)
		return s.substr(0, ei);
	else
		return std::string("ERROR");
}
