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

#ifndef INCLUDED_TMCG_OpenStack_HH
	#define INCLUDED_TMCG_OpenStack_HH

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

template <typename CardType> struct TMCG_OpenStack
{
	std::vector<std::pair<size_t, CardType> > stack;
	
	struct eq_first_component : public std::binary_function<
		std::pair<size_t, CardType>, std::pair<size_t, CardType>, bool>
	{
		bool operator() 
			(const std::pair<size_t, CardType>& p1, 
			const std::pair<size_t, CardType>& p2) const
		{
			return (p1.first == p2.first);
		}
	};
	
	TMCG_OpenStack
		()
	{
	}
	
	TMCG_OpenStack& operator =
		(const TMCG_OpenStack& that)
	{
		clear();
		stack = that.stack;
		return *this;
	}
	
	bool operator ==
		(const TMCG_OpenStack& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	bool operator !=
		(const TMCG_OpenStack& that)
	{
		return !(*this == that);
	}
	
	const std::pair<size_t, CardType>& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	std::pair<size_t, CardType>& operator []
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
		(const std::pair<size_t, CardType> &p)
	{
		stack.push_back(p);
	}
	
	void push
		(size_t type, const CardType& c)
	{
		stack.push_back(std::pair<size_t, CardType>(type, c));
	}
	
	void push
		(const TMCG_OpenStack& s)
	{
		std::copy(s.stack.begin(), s.stack.end(), std::back_inserter(stack));
	}
	
	size_t pop
		(CardType& c)
	{
		size_t type = 100000000L;		// set 'error code' to 100000000L
		
		if (stack.empty())
			return type;
		
		type = (stack.back())->first;
		c = (stack.back())->second;
		stack.pop_back();
		return type;
	}
	
	void clear
		()
	{
		stack.clear();
	}
	
	bool find
		(size_t type) const
	{
		return (std::find_if(stack.begin(), stack.end(),
			std::bind2nd(eq_first_component(), std::pair<size_t, CardType>
				(type, CardType()))) != stack.end());
	}
	
	bool remove
		(size_t type)
	{
		typename std::vector<std::pair<size_t, CardType> >::iterator si =
			std::find_if(stack.begin(), stack.end(),
				std::bind2nd(eq_first_component(), std::pair<size_t, CardType>
					(type, CardType())));
		
		if (si != stack.end())
		{
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	size_t removeAll
		(size_t type)
	{
		size_t counter = 0;
		while (remove(type))
			counter++;
		return counter;
	}
	
	bool move
		(size_t type, TMCG_Stack<CardType>& s)
	{
		typename std::vector<std::pair<size_t, CardType> >::iterator si =
			std::find_if(stack.begin(), stack.end(),
				std::bind2nd(eq_first_component(), std::pair<size_t, CardType>
					(type, CardType())));
		
		if (si != stack.end())
		{
			s.push(si->second);
			stack.erase(si);
			return true;
		}
		return false;
	}
	
	~TMCG_OpenStack
		()
	{
		stack.clear();
	}
};

#endif
