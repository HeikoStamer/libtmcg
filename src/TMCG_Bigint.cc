/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include "TMCG_Bigint.hh"

// additional headers
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <exception>
#include <stdexcept>

TMCG_Bigint::TMCG_Bigint
	(const bool secret_in):
		secret(secret_in)
{
	if (secret)
	{
		secret_bigint = gcry_mpi_snew(8);
	}
	else
	{
		mpz_init(bigint);
	}
}

TMCG_Bigint::TMCG_Bigint
	(const TMCG_Bigint& that):
		secret(that.secret)
{
	if (secret)
	{
		secret_bigint = gcry_mpi_snew(8);
		gcry_mpi_set(secret_bigint, that.secret_bigint);
	}
	else
	{
		mpz_init_set(bigint, that.bigint);
	}
}

TMCG_Bigint& TMCG_Bigint::operator =
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
			gcry_mpi_set(secret_bigint, that.secret_bigint);
		else
		{
			throw std::invalid_argument("TMCG_Bitint::assignment not allowed");
// TODO: convert from non-secret bigint
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bitint::assignment not allowed");
		mpz_set(bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator =
	(const unsigned long int that)
{
	if (secret)
	{
		throw std::invalid_argument("TMCG_Bitint::assignment not allowed");
	}
	else
	{
		mpz_set_ui(bigint, that);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator =
	(const signed long int that)
{
	if (secret)
	{
		throw std::invalid_argument("TMCG_Bitint::assignment not allowed");
	}
	else
	{
		mpz_set_si(bigint, that);
	}
	return *this;
}

bool TMCG_Bigint::operator ==
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (!gcry_mpi_cmp(secret_bigint, that.secret_bigint));
		else
			throw std::invalid_argument("TMCG_Bitint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bitint::comparison not allowed");
		else
			return (!mpz_cmp(bigint, that.bigint));
	}
}

bool TMCG_Bigint::operator ==
	(const unsigned long int that) const
{
	if (secret)
	{
		throw std::invalid_argument("TMCG_Bitint::comparison not allowed");
	}
	else
	{
		return (!mpz_cmp_ui(bigint, that));
	}
}

bool TMCG_Bigint::operator ==
	(const signed long int that) const
{
	if (secret)
	{
		throw std::invalid_argument("TMCG_Bitint::comparison not allowed");
	}
	else
	{
		return (!mpz_cmp_si(bigint, that));
	}
}

bool TMCG_Bigint::operator !=
	(const TMCG_Bigint& that) const
{
	return (!(*this == that));
}

bool TMCG_Bigint::operator !=
	(const unsigned long int that) const
{
	return (!(*this == that));
}

bool TMCG_Bigint::operator !=
	(const signed long int that) const
{
	return (!(*this == that));
}

TMCG_Bigint::~TMCG_Bigint
	()
{
	if (secret)
	{
		gcry_mpi_release(secret_bigint);
	}
	else
	{
		mpz_clear(bigint);
	}
}

std::ostream& operator <<
	(std::ostream& out, const TMCG_Bigint& that)
{
	if (that.secret)
	{
		throw std::invalid_argument("TMCG_Bitint::output not allowed");
	}
	else
	{
		// two extra bytes are for a possible minus sign and the null-terminator
		size_t bufsize = mpz_sizeinbase(that.bigint, TMCG_MPZ_IO_BASE) + 2;
		char *buf = new char[bufsize];
		memset(buf, 0, bufsize);
		out << mpz_get_str(buf, TMCG_MPZ_IO_BASE, that.bigint);
		delete [] buf;
	}
	return out;
}

std::istream& operator >>
	(std::istream& in, TMCG_Bigint& that)
{
	if (that.secret)
	{
		throw std::invalid_argument("TMCG_Bitint::input not allowed");
	}
	else
	{
		char *buf = new char[TMCG_MAX_VALUE_CHARS];
		in.getline(buf, TMCG_MAX_VALUE_CHARS - 1);
		if (mpz_set_str(that.bigint, buf, TMCG_MPZ_IO_BASE) < 0)
		{
			in.setstate(std::istream::iostate(std::istream::failbit));
			throw std::invalid_argument("TMCG_Bitint::mpz_set_str failed");
		}
		delete [] buf;
	}
	return in;
}

