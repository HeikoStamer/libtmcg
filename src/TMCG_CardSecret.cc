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

#include "TMCG_CardSecret.hh"

TMCG_CardSecret::TMCG_CardSecret
	()
{
	r.push_back(std::vector<MP_INT>(1)), b.push_back(std::vector<MP_INT>(1));
	mpz_init(&r[0][0]), mpz_init(&b[0][0]);
}

TMCG_CardSecret::TMCG_CardSecret
	(size_t k, size_t w)
{
	assert((k > 0) && (w > 0));
	
	for (size_t i = 0; i < k; i++)
		r.push_back(std::vector<MP_INT>(w)), b.push_back(std::vector<MP_INT>(w));
	for (size_t i = 0; i < r.size(); i++)
		for (size_t j = 0; j < r[i].size(); j++)
			mpz_init(&r[i][j]),
			mpz_init(&b[i][j]);
}

TMCG_CardSecret::TMCG_CardSecret
	(const TMCG_CardSecret& that)
{
	for (size_t k = 0; k < that.r.size(); k++)
		r.push_back(std::vector<MP_INT>(that.r[k].size())),
		b.push_back(std::vector<MP_INT>(that.b[k].size()));
	for (size_t k = 0; k < r.size(); k++)
		for (size_t w = 0; w < r[k].size(); w++)
			mpz_init_set(&r[k][w], &that.r[k][w]),
			mpz_init_set(&b[k][w], &that.b[k][w]);
}

TMCG_CardSecret& TMCG_CardSecret::operator =
	(const TMCG_CardSecret& that)
{
	resize(that.r.size(), that.r[0].size());
	for (size_t k = 0; k < r.size(); k++)
		for (size_t w = 0; w < r[k].size(); w++)
			mpz_set(&r[k][w], &that.r[k][w]),
			mpz_set(&b[k][w], &that.b[k][w]);
	return *this;
}

void TMCG_CardSecret::resize
	(size_t k, size_t w)
{
	assert((k > 0) && (w > 0));
	
	// FIXME: should be done more efficiently
	for (size_t i = 0; i < r.size(); i++)
	{
		for (size_t j = 0; j < r[i].size(); j++)
			mpz_clear(&r[i][j]),
			mpz_clear(&b[i][j]);
		r[i].clear(), b[i].clear();
	}
	r.clear(), b.clear();
	
	for (size_t i = 0; i < k; i++)
		r.push_back(std::vector<MP_INT>(w)), b.push_back(std::vector<MP_INT>(w));
	for (size_t i = 0; i < r.size(); i++)
		for (size_t j = 0; j < r[i].size(); j++)
			mpz_init(&r[i][j]),
			mpz_init(&b[i][j]);
}

bool TMCG_CardSecret::import
	(std::string s)
{
	char *ec;
	
	try
	{
		// check magic
		if (!TMCG_ParseHelper::cm(s, "crs", '|'))
			throw false;
		
		// public card data
		if (TMCG_ParseHelper::gs(s, '|').length() == 0)
			throw false;
		size_t k = 
		    std::strtoul(TMCG_ParseHelper::gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (k < 1) || (k > TMCG_MAX_PLAYERS) || 
			(!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		if (TMCG_ParseHelper::gs(s, '|').length() == 0)
			throw false;
		size_t w = 
		    std::strtoul(TMCG_ParseHelper::gs(s, '|').c_str(), &ec, 10);
		if ((*ec != '\0') || (w < 1) || (w > TMCG_MAX_TYPEBITS) || 
			(!TMCG_ParseHelper::nx(s, '|')))
				throw false;
		
		// resize this
		resize(k, w);
		
		// secret card data
		for (size_t i = 0; i < r.size(); i++)
		{
			for (size_t j = 0; j < r[i].size(); j++)
			{
				// r_ij
				if ((mpz_set_str(&r[i][j], TMCG_ParseHelper::gs(s, '|').c_str(), 
					TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
						throw false;
						
				// b_ij
				if ((mpz_set_str(&b[i][j], TMCG_ParseHelper::gs(s, '|').c_str(), 
					TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(s, '|')))
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

TMCG_CardSecret::~TMCG_CardSecret
	()
{
	for (size_t k = 0; k < r.size(); k++)
		for (size_t w = 0; w < r[k].size(); w++)
			mpz_clear(&r[k][w]),
			mpz_clear(&b[k][w]);
}

std::ostream& operator <<
	(std::ostream& out, const TMCG_CardSecret& cardsecret)
{
	out << "crs|" << cardsecret.r.size() << "|" << cardsecret.r[0].size() << "|";
	for (size_t k = 0; k < cardsecret.r.size(); k++)
		for (size_t w = 0; w < cardsecret.r[k].size(); w++)
			out << &cardsecret.r[k][w] << "|" << &cardsecret.b[k][w] << "|";
	return out;
}

std::istream& operator >>
	(std::istream& in, TMCG_CardSecret& cardsecret)
{
	char *tmp = new char[TMCG_MAX_CARD_CHARS];
	in.getline(tmp, TMCG_MAX_CARD_CHARS);
	if (!cardsecret.import(std::string(tmp)))
		in.setstate(std::istream::iostate(std::istream::failbit));
	delete [] tmp;
	return in;
}
