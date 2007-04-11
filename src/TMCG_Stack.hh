/*******************************************************************************
  Data structure for a stack of cards. This file is part of LibTMCG.

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

#ifndef INCLUDED_TMCG_Stack_HH
	#define INCLUDED_TMCG_Stack_HH
	
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
	
	#include "mpz_srandom.h"
	#include "parse_helper.hh"

template <typename CardType> struct TMCG_OpenStack;		// forward declaration

/** @brief Data structure for a stack of cards.
    
    This struct is a simple container for cards. The elements can be
    either of type TMCG_Card or VTMF_Card depending on which kind of
    encoding scheme is used.
    
    @param CardType is the type of the stored elements. */
template <typename CardType> struct TMCG_Stack
{
	/** This member is the underlying container of the stack. */
	std::vector<CardType>	stack;
	
	/** This constructor initializes an empty stack. */
	TMCG_Stack
		()
	{
	}
	
	/** A simple assignment-operator.
	    @param that is the stack to be assigned. */
	TMCG_Stack& operator =
		(const TMCG_Stack<CardType>& that)
	{
		clear();
		stack = that.stack;
		return *this;
	}
	
	/** This operator tests two stacks for equality of their cards
	    and sizes. */
	bool operator ==
		(const TMCG_Stack<CardType>& that)
	{
		if (stack.size() != that.stack.size())
			return false;
		return std::equal(stack.begin(), stack.end(), that.stack.begin());
	}
	
	/** This operator tests two stacks for inequality of their cards
	    or sizes. */
	bool operator !=
		(const TMCG_Stack<CardType>& that)
	{
		return !(*this == that);
	}
	
	/** This operator provides random access to the cards of the stack.
	    @returns The @a n th card from the top of the stack. */
	const CardType& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	/** This operator provides random access to the cards of the stack.
	    @returns The @a n th card from the top of the stack. */
	CardType& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	/** @returns The size of the stack. */
	size_t size
		() const
	{
		return stack.size();
	}
	
	/** This method pushes a card to the stack.
	    @param c is pushed to the back of the stack. */
	void push
		(const CardType& c)
	{
		if (stack.size() < TMCG_MAX_CARDS)
			stack.push_back(c);
	}
	
	/** This method pushes another stack to the stack.
	    @param s is pushed to the back of the stack. */
	void push
		(const TMCG_Stack<CardType>& s)
	{
		if ((stack.size() + s.stack.size()) <= TMCG_MAX_CARDS)
			std::copy(s.stack.begin(), s.stack.end(), back_inserter(stack));
	}
	
	/** This method pushes the cards of a TMCG_OpenStack to the stack.
	    @param s is the open stack whose cards are pushed to the back
	    of the stack. */
	void push
		(const TMCG_OpenStack<CardType>& s)
	{
		if ((stack.size() + s.stack.size()) <= TMCG_MAX_CARDS)
		{
			for (typename std::vector<std::pair<size_t, CardType> >::const_iterator
				si = s.stack.begin(); si != s.stack.end(); si++)
					stack.push_back(si->second);
		}
	}
	
	/** @returns True, if the stack is empty. */
	bool empty
		()
	{
		return stack.empty();
	}
	
	/** Get and remove a card from the back of the stack.
	    @param c is the card removed from the stack.
	    @returns True, if the stack was not empty. */
	bool pop
		(CardType& c)
	{
		if (stack.empty())
			return false;
		
		c = stack.back();
		stack.pop_back();
		return true;
	}
	
	/** Clears the stack. */
	void clear
		()
	{
		stack.clear();
	}
	
	/** @returns True, if the card @a c was found in the stack. */
	bool find
		(const CardType& c) const
	{
		return (std::find(stack.begin(), stack.end(), c) != stack.end());
	}
	
	/** This method removes the first card from the stack which is
	    equal to @a c.
	    @param c is the card to be removed.
	    @returns True, if the card was successful removed. */
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
	
	/** This method removes all occurences of @a c from the stack.
	    @param c is the card to be removed.
	    @returns The number of removed cards. */
	size_t removeAll
		(const CardType& c)
	{
		size_t counter = 0;
		while (remove(c))
			counter++;
		return counter;
	}
	
	/** This function imports the stack.
	    @param s is correctly formated input string.
	    @returns True, if the import was successful. */
	bool import
		(std::string s)
	{
		size_t size = 0;
		char *ec;
		
		try
		{
			// check magic
			if (!TMCG_ParseHelper::cm(s, "stk", '^'))
				throw false;
			
			// size of stack
			if (TMCG_ParseHelper::gs(s, '^').length() == 0)
				throw false;
			size = 
			    std::strtoul(TMCG_ParseHelper::gs(s, '^').c_str(), &ec, 10);
			if ((*ec != '\0') || (size <= 0) || (size > TMCG_MAX_CARDS) || 
				(!TMCG_ParseHelper::nx(s, '^')))
					throw false;
			
			// cards on stack
			for (size_t i = 0; i < size; i++)
			{
				CardType c;
				
				if (TMCG_ParseHelper::gs(s, '^').length() == 0)
					throw false;
				if ((!c.import(TMCG_ParseHelper::gs(s, '^'))) || 
					(!TMCG_ParseHelper::nx(s, '^')))
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
	
	/** This destructor releases all occupied resources. */
	~TMCG_Stack
		()
	{
		stack.clear();
	}
};

/** @relates TMCG_Stack
    This operator prints a stack to an output stream.
    @param out is the output stream.
    @param stack is the stack to be printed. */
template<typename CardType> std::ostream& operator <<
	(std::ostream& out, const TMCG_Stack<CardType>& stack)
{
	out << "stk^" << stack.size() << "^";
	for (size_t i = 0; i < stack.size(); i++)
		out << stack[i] << "^";
	return out;
}

/** @relates TMCG_Stack
    This operator imports a stack from an input stream. It has to
    be delimited by a newline character.
    The failbit of the stream is set, if any parse error occured.
    @param in is the input stream.
    @param stack is the stack to be imported. */
template<typename CardType> std::istream& operator >>
	(std::istream& in, TMCG_Stack<CardType>& stack)
{
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	in.getline(tmp, TMCG_MAX_STACK_CHARS);
	if (!stack.import(std::string(tmp)))
		in.setstate(std::istream::iostate(std::istream::failbit));
	delete [] tmp;
	return in;
}

#endif
