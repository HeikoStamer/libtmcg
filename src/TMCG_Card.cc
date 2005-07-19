/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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

#include "TMCG_Card.hh"

TMCG_Card::TMCG_Card
	()
{
	z.push_back(std::vector<MP_INT>(1));
	mpz_init(&z[0][0]);
}

TMCG_Card::TMCG_Card
	(size_t k, size_t w)
{
	assert((k > 0) && (w > 0));
	
	for (size_t i = 0; i < k; i++)
		z.push_back(std::vector<MP_INT>(w));
	for (size_t i = 0; i < z.size(); i++)
		for (size_t j = 0; j < z[i].size(); j++)
			mpz_init(&z[i][j]);
}

TMCG_Card::TMCG_Card
	(const TMCG_Card& that)
{
	for (size_t k = 0; k < that.z.size(); k++)
		z.push_back(std::vector<MP_INT>(that.z[k].size()));
	for (size_t k = 0; k < z.size(); k++)
		for (size_t w = 0; w < z[k].size(); w++)
			mpz_init_set(&z[k][w], &that.z[k][w]);
}

TMCG_Card& TMCG_Card::operator =
	(const TMCG_Card& that)
{
	resize(that.z.size(), that.z[0].size());
	for (size_t k = 0; k < z.size(); k++)
		for (size_t w = 0; w < z[k].size(); w++)
			mpz_set(&z[k][w], &that.z[k][w]);
	return *this;
}

bool TMCG_Card::operator ==
	(const TMCG_Card& that) const
{
	if ((z.size() != that.z.size()) || (z[0].size() != that.z[0].size()))
		return false;
	for (size_t k = 0; k < z.size(); k++)
		for (size_t w = 0; w < z[k].size(); w++)
			if (mpz_cmp(&z[k][w], &that.z[k][w]))
				return false;
	return true;
}

bool TMCG_Card::operator !=
	(const TMCG_Card& that) const
{
	return !(*this == that);
}

void TMCG_Card::resize
	(size_t k, size_t w)
{
	assert((k > 0) && (w > 0));
	
	// FIXME: should be done more efficiently
	for (size_t i = 0; i < z.size(); i++)
	{
		for (size_t j = 0; j < z[i].size(); j++)
			mpz_clear(&z[i][j]);
		z[i].clear();
	}
	z.clear();
	
	for (size_t i = 0; i < k; i++)
		z.push_back(std::vector<MP_INT>(w));
	for (size_t i = 0; i < z.size(); i++)
		for (size_t j = 0; j < z[i].size(); j++)
			mpz_init(&z[i][j]);
}

bool TMCG_Card::import
	(std::string s)
{
	char *ec;
	
	try
	{
		// check magic
		if (!cm(s, "crd", '|'))
			throw false;
		
		// card description
		if (gs(s, '|').length() == 0)
			throw false;
		size_t k = strtoul(gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (k < 1) || (k > TMCG_MAX_PLAYERS) || (!nx(s, '|')))
			throw false;
		if (gs(s, '|').length() == 0)
			throw false;
		size_t w = strtoul(gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (w < 1) || (w > TMCG_MAX_TYPEBITS) || (!nx(s, '|')))
			throw false;
		
		// resize this
		resize(k, w);
		
		// card data
		for (size_t i = 0; i < z.size(); i++)
		{
			for (size_t j = 0; j < z[i].size(); j++)
			{
				// z_ij
				if ((mpz_set_str(&z[i][j], gs(s, '|').c_str(), TMCG_MPZ_IO_BASE) < 0)
					|| (!nx(s, '|')))
						throw false;
			}
		}
		throw true;
	}
	catch (bool return_value)
	{
		return return_value;
	}
}

TMCG_Card::~TMCG_Card
	()
{
	for (size_t k = 0; k < z.size(); k++)
		for (size_t w = 0; w < z[k].size(); w++)
			mpz_clear(&z[k][w]);
}

std::ostream& operator<< 
	(std::ostream &out, const TMCG_Card &card)
{
	out << "crd|" << card.z.size() << "|" << card.z[0].size() << "|";
	for (size_t k = 0; k < card.z.size(); k++)
		for (size_t w = 0; w < card.z[k].size(); w++)
			out << &card.z[k][w] << "|";
	return out;
}
