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
#include "mpz_helper.hh"

TMCG_Bigint::TMCG_Bigint
	(const bool secret_in):
		secret(secret_in)
{
	if (secret)
		secret_bigint = gcry_mpi_snew(8);
	else
		mpz_init(bigint);
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
		mpz_init_set(bigint, that.bigint);
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
			gcry_mpi_t tmp;
			tmcg_mpz_get_gcry_mpi(tmp, that.bigint);
			gcry_mpi_set(secret_bigint, tmp);
			gcry_mpi_release(tmp);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::assignment not allowed");
		mpz_set(bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator =
	(const unsigned long int that)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::assignment not allowed");
	else
		mpz_set_ui(bigint, that);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator =
	(const signed long int that)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::assignment not allowed");
	else
		mpz_set_si(bigint, that);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator +=
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
			gcry_mpi_add(secret_bigint, secret_bigint, that.secret_bigint);
		else
		{
			gcry_mpi_t tmp;
			tmcg_mpz_get_gcry_mpi(tmp, that.bigint);
			gcry_mpi_add(secret_bigint, secret_bigint, tmp);
			gcry_mpi_release(tmp);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not allowed");
		else
			mpz_add(bigint, bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator +=
	(const unsigned long int that)
{
	if (secret)
		gcry_mpi_add_ui(secret_bigint, secret_bigint, that);
	else
		mpz_add_ui(bigint, bigint, that);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator -
	()
{
	if (secret)
		gcry_mpi_neg(secret_bigint, secret_bigint);
	else
		mpz_neg(bigint, bigint);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator -=
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
			gcry_mpi_sub(secret_bigint, secret_bigint, that.secret_bigint);
		else
		{
			gcry_mpi_t tmp;
			tmcg_mpz_get_gcry_mpi(tmp, that.bigint);
			gcry_mpi_sub(secret_bigint, secret_bigint, tmp);
			gcry_mpi_release(tmp);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not allowed");
		else
			mpz_sub(bigint, bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator -=
	(const unsigned long int that)
{
	if (secret)
		gcry_mpi_sub_ui(secret_bigint, secret_bigint, that);
	else
		mpz_sub_ui(bigint, bigint, that);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator *=
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
			gcry_mpi_mul(secret_bigint, secret_bigint, that.secret_bigint);
		else
		{
			gcry_mpi_t tmp;
			tmcg_mpz_get_gcry_mpi(tmp, that.bigint);
			gcry_mpi_mul(secret_bigint, secret_bigint, tmp);
			gcry_mpi_release(tmp);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not allowed");
		else
			mpz_mul(bigint, bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator *=
	(const unsigned long int that)
{
	if (secret)
		gcry_mpi_mul_ui(secret_bigint, secret_bigint, that);
	else
		mpz_mul_ui(bigint, bigint, that);
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator /=
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
		{
			gcry_mpi_div(secret_bigint, NULL, secret_bigint,
				that.secret_bigint, 0);
		}
		else
		{
			gcry_mpi_t tmp;
			tmcg_mpz_get_gcry_mpi(tmp, that.bigint);
			gcry_mpi_div(secret_bigint, NULL, secret_bigint, tmp, 0);
			gcry_mpi_release(tmp);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not allowed");
		else
		{
			assert(mpz_divisible_p(bigint, that.bigint));
			mpz_divexact(bigint, bigint, that.bigint);
		}
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator /=
	(const unsigned long int that)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not allowed");
	else
	{
		assert(mpz_divisible_ui_p(bigint, that));
		mpz_divexact_ui(bigint, bigint, that);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator %=
	(const TMCG_Bigint& that)
{
	if (secret)
	{
		if (that.secret)
		{
			gcry_mpi_mod(secret_bigint, secret_bigint, that.secret_bigint);
		}
		else
		{
			gcry_mpi_t divisor;
			tmcg_mpz_get_gcry_mpi(divisor, that.bigint);
			gcry_mpi_mod(secret_bigint, secret_bigint, divisor);
			gcry_mpi_release(divisor);
		}
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not allowed");
		else
			mpz_mod(bigint, bigint, that.bigint);
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator %=
	(const unsigned long int that)
{
	if (secret)
	{
		gcry_mpi_t divisor = gcry_mpi_new(8);
		gcry_mpi_set_ui(divisor, that);
		gcry_mpi_mod(secret_bigint, secret_bigint, divisor);
		gcry_mpi_release(divisor);
	}
	else
		mpz_mod_ui(bigint, bigint, that);
	return *this;
}

bool TMCG_Bigint::operator ==
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) == 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) == 0);
	}
}

bool TMCG_Bigint::operator ==
	(const unsigned long int that) const
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	else
		return (mpz_cmp_ui(bigint, that) == 0);
}

bool TMCG_Bigint::operator ==
	(const signed long int that) const
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	else
		return (mpz_cmp_si(bigint, that) == 0);
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

bool TMCG_Bigint::operator >
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) > 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) > 0);
	}
}

bool TMCG_Bigint::operator >
	(const unsigned long int that) const
{
	if (secret)
		return (gcry_mpi_cmp_ui(secret_bigint, that) > 0);
	else
		return (mpz_cmp_ui(bigint, that) > 0);
}

bool TMCG_Bigint::operator <
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) < 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) < 0);
	}
}

bool TMCG_Bigint::operator <
	(const unsigned long int that) const
{
	if (secret)
		return (gcry_mpi_cmp_ui(secret_bigint, that) < 0);
	else
		return (mpz_cmp_ui(bigint, that) < 0);
}

bool TMCG_Bigint::operator >=
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) >= 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) >= 0);
	}
}

bool TMCG_Bigint::operator >=
	(const unsigned long int that) const
{
	if (secret)
		return (gcry_mpi_cmp_ui(secret_bigint, that) >= 0);
	else
		return (mpz_cmp_ui(bigint, that) >= 0);
}

bool TMCG_Bigint::operator <=
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret)
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) <= 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret)
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) <= 0);
	}
}

bool TMCG_Bigint::operator <=
	(const unsigned long int that) const
{
	if (secret)
		return (gcry_mpi_cmp_ui(secret_bigint, that) <= 0);
	else
		return (mpz_cmp_ui(bigint, that) <= 0);
}

void TMCG_Bigint::abs
	()
{
	if (secret)
		gcry_mpi_abs(secret_bigint);
	else
		mpz_abs(bigint, bigint);
}

void TMCG_Bigint::set_str
	(const std::string& that, const size_t base)
{
	if (secret)
	{
		throw std::invalid_argument("TMCG_Bigint::input not allowed");
	}
	else
	{
		if (mpz_set_str(bigint, that.c_str(), base) < 0)
			throw std::invalid_argument("TMCG_Bigint::mpz_set_str failed");
	}
}

bool TMCG_Bigint::probab_prime
	(const size_t reps)
{
	if (secret)
	{
		gcry_error_t ret = gcry_prime_check(secret_bigint, 0);
		if (ret == 0)
			return true;
		else if (ret == GPG_ERR_NO_PRIME)
			return false;
		else
			throw std::invalid_argument("TMCG_Bigint::gcry_prime_check failed");
	}
	else
		return mpz_probab_prime_p(bigint, reps);
}

void TMCG_Bigint::mul2exp
	(const size_t exp)
{
	if (secret)
		gcry_mpi_mul_2exp(secret_bigint, secret_bigint, exp);
	else
		mpz_mul_2exp(bigint, bigint, exp);
}

void TMCG_Bigint::div2exp
	(const size_t exp)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
		mpz_tdiv_q_2exp(bigint, bigint, exp);
}

unsigned long int TMCG_Bigint::get_ui
	()
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
		return mpz_get_ui(bigint);
}

size_t TMCG_Bigint::size
	(const size_t base)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
		return mpz_sizeinbase(bigint, base);
}

TMCG_Bigint::~TMCG_Bigint
	()
{
	if (secret)
		gcry_mpi_release(secret_bigint);
	else
		mpz_clear(bigint);
}

std::ostream& operator <<
	(std::ostream& out, const TMCG_Bigint& that)
{
	if (that.secret)
	{
		throw std::invalid_argument("TMCG_Bigint::output not allowed");
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
		throw std::invalid_argument("TMCG_Bigint::input not allowed");
	}
	else
	{
		char *buf = new char[TMCG_MAX_VALUE_CHARS];
		in.getline(buf, TMCG_MAX_VALUE_CHARS - 1);
		if (mpz_set_str(that.bigint, buf, TMCG_MPZ_IO_BASE) < 0)
		{
			in.setstate(std::istream::iostate(std::istream::failbit));
			throw std::invalid_argument("TMCG_Bigint::mpz_set_str failed");
		}
		delete [] buf;
	}
	return in;
}

