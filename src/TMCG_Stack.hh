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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#ifndef INCLUDED_TMCG_Stack_HH
	#define INCLUDED_TMCG_Stack_HH

	// config.h
	#if HAVE_CONFIG_H
		#include "config.h"
	#endif

	// C++/STL header
	#include <cstdlib>
	#include <cassert>
	#include <string>
	#include <iostream>
	#include <vector>
	#include <algorithm>
	#include <functional>
	
	#include "mpz_srandom.h"
	#include "parse_helper.hh"

template <typename CardType> struct TMCG_OpenStack;			// forward

template <typename CardType> struct TMCG_Stack
{
	std::vector<CardType>	stack;
	
	TMCG_Stack
		()
	{
	}
	
	TMCG_Stack& operator =
		(const TMCG_Stack& that)
	{
		clear();
		stack = that.stack;
		return *this;
	}
	
	bool operator ==
		(const TMCG_Stack& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	bool operator !=
		(const TMCG_Stack& that)
	{
		return !(*this == that);
	}
	
	const CardType& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	CardType& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	size_t size
		() const
	{
		return stack.size();
	}
	
	void push
		(const CardType& c)
	{
		stack.push_back(c);
	}
	
	void push
		(const TMCG_Stack& s)
	{
		std::copy(s.stack.begin(), s.stack.end(), back_inserter(stack));
	}
	
	void push
		(const TMCG_OpenStack<CardType>& s)
	{
		for (typename std::vector<std::pair<size_t, CardType> >::const_iterator
			si = s.stack.begin(); si != s.stack.end(); si++)
				stack.push_back(si->second);
	}
	
	bool empty
		()
	{
		return stack.empty();
	}
	
	bool pop
		(CardType& c)
	{
		if (stack.empty())
			return false;
		
		c = stack.back();
		stack.pop_back();
		return true;
	}
	
	void clear
		()
	{
		stack.clear();
	}
	
	bool find
		(const CardType& c) const
	{
		return (std::find(stack.begin(), stack.end(), c) != stack.end());
	}
	
	bool remove
		(const CardType& c)
	{
		typename std::vector<CardType>::iterator si =
			std::find(stack.begin(), stack.end(), c);
		
		if (si != stack.end())
		{
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	size_t removeAll
		(const CardType& c)
	{
		size_t counter = 0;
		while (remove(c))
			counter++;
		return counter;
	}
	
	bool import
		(std::string s)
	{
		size_t size = 0;
		char *ec;
		
		try
		{
			// check magic
			if (!cm(s, "stk", '^'))
				throw false;
			
			// size of stack
			if (gs(s, '^').length() == 0)
				throw false;
			size = strtoul(gs(s, '^').c_str(), &ec, 10);
			if ((*ec != '\0') || (size <= 0) || (!nx(s, '^')))
				throw false;
			
			// cards on stack
			for (size_t i = 0; i < size; i++)
			{
				CardType c;
				
				if (gs(s, '^').length() == 0)
					throw false;
				if ((!c.import(gs(s, '^'))) || (!nx(s, '^')))
					throw false;
				stack.push_back(c);
			}
			
			throw true;
		}
		catch (bool return_value)
		{
			return return_value;
		}
	}
	
	~TMCG_Stack
		()
	{
		stack.clear();
	}
};

template<typename CardType> std::ostream& operator<<
	(std::ostream &out, const TMCG_Stack<CardType> &s)
{
	out << "stk^" << s.size() << "^";
	for (size_t i = 0; i < s.size(); i++)
		out << s[i] << "^";
	return out;
}

#endif
