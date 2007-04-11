/*******************************************************************************
  Data structure for the secrets of a stack. This file is part of LibTMCG.

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

#ifndef INCLUDED_TMCG_StackSecret_HH
	#define INCLUDED_TMCG_StackSecret_HH
	
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

/** @brief Data structure for the secrets of a stack of cards.
    
    This struct is a simple container for the secrets involved in the
    masking operation of cards. Additionally, the permutation of the
    corresponding shuffle of the stack is stored.
    The elements are pairs where the first component is a permutation
    index and the second component is the card secret. These secrets
    can be either of type TMCG_CardSecret or VTMF_CardSecret depending
    on which kind of encoding scheme is used.
    
    @param CardSecretType is the type of the stored card secrets. */
template <typename CardSecretType> struct TMCG_StackSecret
{
	/** This member is the underlying container of the stack secret. */
	std::vector<std::pair<size_t, CardSecretType> > stack;
	
	/** This is a simple equality test for the first component of a pair. */
	struct eq_first_component : public std::binary_function<
		std::pair<size_t, CardSecretType>,
		std::pair<size_t, CardSecretType>, bool>
	{
		/** This is the comparator for equality. */
		bool operator() 
			(const std::pair<size_t, CardSecretType>& p1,
			 const std::pair<size_t, CardSecretType>& p2) const
		{
			return (p1.first == p2.first);
		}
	};
	
	/** This constructor initializes an empty stack secret. */
	TMCG_StackSecret
		()
	{
	}
	
	/** A simple assignment-operator.
	    @param that is the stack secret to be assigned. */
	TMCG_StackSecret& operator =
		(const TMCG_StackSecret<CardSecretType>& that)
	{
		stack.clear();
		stack = that.stack;
		return *this;
	}
	
	/** This operator provides random access to the pairs of the stack secret.
	    @returns The @a n th pair from the top of the stack secret. */
	const std::pair<size_t, CardSecretType>& operator []
		(size_t n) const
	{
		return stack[n];
	}
	
	/** This operator provides random access to the pairs of the stack secret.
	    @returns The @a n th pair from the top of the stack secret. */
	std::pair<size_t, CardSecretType>& operator []
		(size_t n)
	{
		return stack[n];
	}
	
	/** @returns The size of the stack secret. */
	size_t size
		() const
	{
		return stack.size();
	}
	
	/** This method pushes a pair to the back of the stack secret.
	    @param index is the permutation index (first component) to be pushed.
	    @param cs is the card secret (second component) to be pushed. */
	void push
		(size_t index, const CardSecretType& cs)
	{
		if (stack.size() < TMCG_MAX_CARDS)
			stack.push_back(std::pair<size_t, CardSecretType>(index, cs));
	}
	
	/** Clears the stack secret. */
	void clear
		()
	{
		stack.clear();
	}
	
	/** This method searches for a permutation index in the stack secret.
	    @param index is the permutation index to be found.
	    @returns The position in the stack secret, if @a index was found.
	    Otherwise, it returns the size of the stack secret. */
	size_t find_position
		(size_t index) const
	{
		return distance(stack.begin(),
			std::find_if(stack.begin(), stack.end(),
				std::bind2nd(eq_first_component(),
					std::pair<size_t, CardSecretType>(index, CardSecretType()))));
	}
	
	/** This method searches for a permutation index in the stack secret.
	    @param index is the permutation index to be found.
	    @returns True, if @a index was found. */
	bool find
		(size_t index) const
	{
		return (find_position(index) == stack.size() ? false : true);
	}
	
	/** This function imports the stack secret.
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
			if (!TMCG_ParseHelper::cm(s, "sts", '^'))
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
				std::pair<size_t, CardSecretType> lej;
				
				// permutation index
				if (TMCG_ParseHelper::gs(s, '^').length() == 0)
					throw false;
				lej.first = std::strtoul(TMCG_ParseHelper::gs(s, '^').c_str(), 
					&ec, 10);
				if ((*ec != '\0') || (lej.first < 0) || (lej.first >= size) || 
					(!TMCG_ParseHelper::nx(s, '^')))
						throw false;
				
				// card secret
				if (TMCG_ParseHelper::gs(s, '^').length() == 0)
					throw false;
				if ((!lej.second.import(TMCG_ParseHelper::gs(s, '^'))) || 
					(!TMCG_ParseHelper::nx(s, '^')))
						throw false;
				
				// store pair
				stack.push_back(lej);
			}
			
			// check whether the index component is a correct permutation
			for (size_t i = 0; i < size; i++)
			{
				if (find_position(i) >= size)
					throw false;
			}
			
			throw true;
		}
		catch (bool return_value)
		{
			return return_value;
		}
	}
	
	/** This destructor releases all occupied resources. */
	~TMCG_StackSecret
		()
	{
		stack.clear();
	}
};

/** @relates TMCG_StackSecret
    This operator prints a stack secret to an output stream.
    @param out is the output stream.
    @param stacksecret is the stack secret to be printed. */
template<typename CardSecretType> std::ostream& operator <<
	(std::ostream& out, const TMCG_StackSecret<CardSecretType>& stacksecret)
{
	out << "sts^" << stacksecret.size() << "^";
	for (size_t i = 0; i < stacksecret.size(); i++)
		out << stacksecret[i].first << "^" << stacksecret[i].second << "^";
	return out;
}

/** @relates TMCG_StackSecret
    This operator imports a stack secret from an input stream. It has
    to be delimited by a newline character.
    The failbit of the stream is set, if any parse error occured.
    @param in is the input stream.
    @param stacksecret is the stack secret to be imported. */
template<typename CardSecretType> std::istream& operator >>
	(std::istream& in, TMCG_StackSecret<CardSecretType>& stacksecret)
{
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	in.getline(tmp, TMCG_MAX_STACK_CHARS);
	if (!stacksecret.import(std::string(tmp)))
		in.setstate(std::istream::iostate(std::istream::failbit));
	delete [] tmp;
	return in;
}

#endif
