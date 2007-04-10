/*******************************************************************************
  Data structure for a stack of open cards. This file is part of LibTMCG.

 Copyright (C) 2004, 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_TMCG_OpenStack_HH
	#define INCLUDED_TMCG_OpenStack_HH
	
	// config.h
	#ifdef HAVE_CONFIG_H
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

/** @brief Data structure for a stack of open cards.
    
    This struct is a simple container for cards whose types are known.
    The elements are pairs where the first component is the type and the
    second component is the corresponding card. The card type is represented
    by a size_t integer.The cards can be either of type TMCG_Card or
    VTMF_Card depending on which kind of encoding scheme is used.
    
    @param CardType is the type of the stored cards. */
template <typename CardType> struct TMCG_OpenStack
{
	/** This member is the underlying container of the open stack. */
	std::vector<std::pair<size_t, CardType> > stack;
	
	/** This is a simple equality test for the first component of a pair. */
	struct eq_first_component : public std::binary_function<
		std::pair<size_t, CardType>, std::pair<size_t, CardType>, bool>
	{
		/** This is the comparator for equality. */
		bool operator() 
			(const std::pair<size_t, CardType>& p1, 
			const std::pair<size_t, CardType>& p2) const
		{
			return (p1.first == p2.first);
		}
	};
	
	/** This constructor initializes an empty open stack. */
	TMCG_OpenStack
		()
	{
	}
	
	/** A simple assignment-operator.
	    @param that is the open stack to be assigned. */
	TMCG_OpenStack& operator =
		(const TMCG_OpenStack<CardType>& that)
	{
		clear();
		stack = that.stack;
		return *this;
	}
	
	/** This operator tests two open stacks for equality of their types,
	    cards and sizes. */
	bool operator ==
		(const TMCG_OpenStack<CardType>& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	/** This operator tests two open stacks for inequality of their types,
	    cards or sizes. */
	bool operator !=
		(const TMCG_OpenStack<CardType>& that)
	{
		return !(*this == that);
	}
	
	/** This operator provides random access to the pairs of the open stack.
	    @returns The @a n th pair from the top of the open stack. */
	const std::pair<size_t, CardType>& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	/** This operator provides random access to the pairs of the open stack.
	    @returns The @a n th pair from the top of the open stack. */
	std::pair<size_t, CardType>& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	/** @returns The size of the open stack. */
	size_t size
		() const
	{
		return stack.size();
	}
	
	/** This method pushes a pair (type and card) to the back of the open stack.
	    @param p is the pair to be pushed. */
	void push
		(const std::pair<size_t, CardType>& p)
	{
		if (stack.size() < TMCG_MAX_CARDS)
			stack.push_back(p);
	}
	
	/** This method pushes a pair to the back of the open stack.
	    @param type is the type of the card (first component) to be pushed.
	    @param c is the card (second component) to be pushed. */
	void push
		(size_t type, const CardType& c)
	{
		if (stack.size() < TMCG_MAX_CARDS)
			stack.push_back(std::pair<size_t, CardType>(type, c));
	}
	
	/** This method pushes another open stack to the open stack.
	    @param s is pushed to the back of the open stack. */
	void push
		(const TMCG_OpenStack<CardType>& s)
	{
		if ((stack.size() + s.stack.size()) <= TMCG_MAX_CARDS)
			std::copy(s.stack.begin(), s.stack.end(), std::back_inserter(stack));
	}
	
	/** @returns True, if the stack is empty. */
	bool empty
		()
	{
		return stack.empty();
	}
	
	/** Get and remove a pair from the back of the open stack.
	    @param type is the card type of the removed card.
	    @param c is the card removed from the open stack.
	    @returns True, if the stack was not empty. */
	bool pop
		(size_t& type, CardType& c)
	{
		if (stack.empty())
			return false;
		
		type = (stack.back())->first;
		c = (stack.back())->second;
		stack.pop_back();
		return true;
	}
	
	/** Clears the open stack. */
	void clear
		()
	{
		stack.clear();
	}
	
	/** @returns True, if the @a type was found in the open stack. */
	bool find
		(size_t type) const
	{
		return (std::find_if(stack.begin(), stack.end(),
			std::bind2nd(eq_first_component(), std::pair<size_t, CardType>
				(type, CardType()))) != stack.end());
	}
	
	/** This method removes the first pair from the open stack whose type
	    is equal to @a type.
	    @param type will be removed.
	    @returns True, if the pair was successful removed. */
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
	
	/** This method removes all pairs of the given @a type from the open stack.
	    @param type will be removed.
	    @returns The number of removed pairs. */
	size_t removeAll
		(size_t type)
	{
		size_t counter = 0;
		while (remove(type))
			counter++;
		return counter;
	}
	
	/** This method moves the first card with the given @a type from the
	    open stack to regular stack.
	    @param type will be moved.
	    @param s is the stack where the card is moved to.
	    @returns True, if a card was moved. */
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
	
	/** This destructor releases all occupied resources. */
	~TMCG_OpenStack
		()
	{
		stack.clear();
	}
};

#endif
