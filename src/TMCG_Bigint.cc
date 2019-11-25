/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "mpz_srandom.hh"
#include "mpz_spowm.hh"

TMCG_Bigint::TMCG_Bigint
	(const bool secret_in, const bool exportable_in):
		secret(secret_in), exportable(exportable_in)
{
	if (secret)
		secret_bigint = gcry_mpi_snew(8);
	else
		mpz_init(bigint);
}

TMCG_Bigint::TMCG_Bigint
	(const TMCG_Bigint& that):
		secret(that.secret), exportable(that.exportable)
{
	if (secret)
	{
		secret_bigint = gcry_mpi_snew(8);
		gcry_mpi_set(secret_bigint, that.secret_bigint);
	}
	else
		mpz_init_set(bigint, that.bigint);
}

TMCG_Bigint::TMCG_Bigint
	(const mpz_t that):
		secret(false), exportable(false)
{
	mpz_init_set(bigint, that);
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
			gcry_mpi_t tmp = gcry_mpi_new(that.size(2));
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
		gcry_mpi_set_ui(secret_bigint, that);
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
			gcry_mpi_t tmp = gcry_mpi_new(that.size(2));
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
			gcry_mpi_t tmp = gcry_mpi_new(that.size(2));
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
			gcry_mpi_t tmp = gcry_mpi_new(that.size(2));
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
			gcry_mpi_t tmp = gcry_mpi_new(that.size(2));
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
			if (mpz_cmp_ui(that.bigint, 0UL) == 0)
				throw std::domain_error("TMCG_Bigint::division by zero");
			if (mpz_divisible_p(bigint, that.bigint))
				mpz_divexact(bigint, bigint, that.bigint);
			else
				mpz_tdiv_q(bigint, bigint, that.bigint);
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
		if (that == 0UL)
			throw std::domain_error("TMCG_Bigint::division by zero");
		if (mpz_divisible_ui_p(bigint, that))
			mpz_divexact_ui(bigint, bigint, that);
		else
			mpz_tdiv_q_ui(bigint, bigint, that);
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
			gcry_mpi_t divisor = gcry_mpi_new(that.size(2));
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
		{
			if (mpz_cmp_ui(that.bigint, 0UL) == 0)
				throw std::domain_error("TMCG_Bigint::division by zero");
			mpz_mod(bigint, bigint, that.bigint);
		}
	}
	return *this;
}

TMCG_Bigint& TMCG_Bigint::operator %=
	(const unsigned long int that)
{
	if (that == 0UL)
		throw std::domain_error("TMCG_Bigint::division by zero");
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
		if (that.secret) // TODO: use constant-time compare strategy
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
		if (that.secret) // TODO: use constant-time compare strategy
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
	if (secret) // TODO: use constant-time compare strategy
		return (gcry_mpi_cmp_ui(secret_bigint, that) > 0);
	else
		return (mpz_cmp_ui(bigint, that) > 0);
}

bool TMCG_Bigint::operator <
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret) // TODO: use constant-time compare strategy
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
	if (secret) // TODO: use constant-time compare strategy
		return (gcry_mpi_cmp_ui(secret_bigint, that) < 0);
	else
		return (mpz_cmp_ui(bigint, that) < 0);
}

bool TMCG_Bigint::operator >=
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret) // TODO: use constant-time compare strategy
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
	if (secret) // TODO: use constant-time compare strategy
		return (gcry_mpi_cmp_ui(secret_bigint, that) >= 0);
	else
		return (mpz_cmp_ui(bigint, that) >= 0);
}

bool TMCG_Bigint::operator <=
	(const TMCG_Bigint& that) const
{
	if (secret)
	{
		if (that.secret) // TODO: use constant-time compare strategy
			return (gcry_mpi_cmp(secret_bigint, that.secret_bigint) <= 0);
		else
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
	}
	else
	{
		if (that.secret) // TODO: use constant-time compare strategy
			throw std::invalid_argument("TMCG_Bigint::comparison not allowed");
		else
			return (mpz_cmp(bigint, that.bigint) <= 0);
	}
}

bool TMCG_Bigint::operator <=
	(const unsigned long int that) const
{
	if (secret) // TODO: use constant-time compare strategy
		return (gcry_mpi_cmp_ui(secret_bigint, that) <= 0);
	else
		return (mpz_cmp_ui(bigint, that) <= 0);
}

void TMCG_Bigint::abs
	()
{
	if (secret) // TODO: use constant-time function
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
	if (secret) // TODO: use constant-time function
	{
		gcry_error_t ret = gcry_prime_check(secret_bigint, 0);
		if (ret == 0)
			return true;
		else if (gcry_err_code(ret) == GPG_ERR_NO_PRIME)
			return false;
		else
			throw std::invalid_argument("TMCG_Bigint::gcry_prime_check failed");
	}
	else
	{
		int ret = mpz_probab_prime_p(bigint, reps);
		if (ret == 0)
			return false; // definitely non-prime
		else if (ret == 1)
			return true; // probably prime
		else if (ret == 2)
			return true; // definitely prime
		else
			throw std::invalid_argument("TMCG_Bigint::mpz_probab_prime_p failed");
	}
}

void TMCG_Bigint::mul2exp
	(const size_t exp)
{
	if (secret) // TODO: use constant-time function
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

void TMCG_Bigint::ui_pow_ui
	(const unsigned long int base, const unsigned long int exp)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
		mpz_ui_pow_ui(bigint, base, exp); 
}

void TMCG_Bigint::powm
	(const TMCG_Bigint& base, const TMCG_Bigint& exp, const TMCG_Bigint& mod)
{
	if (secret) // TODO: use constant-time function
	{
		if (!base.secret || !exp.secret || !mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		gcry_mpi_powm(secret_bigint, base.secret_bigint, exp.secret_bigint,
			mod.secret_bigint);
	}
	else
	{
		if (base.secret || exp.secret || mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		mpz_powm(bigint, base.bigint, exp.bigint, mod.bigint);
	}
}

void TMCG_Bigint::spowm
	(const TMCG_Bigint& base, const TMCG_Bigint& exp, const TMCG_Bigint& mod)
{
	if (secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
	{
		if (base.secret || exp.secret || mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		tmcg_mpz_spowm(bigint, base.bigint, exp.bigint, mod.bigint);
	}
}

void TMCG_Bigint::powm_ui
	(const TMCG_Bigint& base, const unsigned long int exp, const TMCG_Bigint& mod)
{
	if (secret) // TODO: use constant-time function
	{
		gcry_mpi_t e = gcry_mpi_new(8);
		gcry_mpi_set_ui(e, exp);
		gcry_mpi_powm(secret_bigint, base.secret_bigint, e,	mod.secret_bigint);
		gcry_mpi_release(e);
	}
	else
	{
		if (base.secret || mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		mpz_powm_ui(bigint, base.bigint, exp, mod.bigint);
	}
}

unsigned long int TMCG_Bigint::get_ui
	()
{
	if (secret)
		return tmcg_get_gcry_mpi_ui(secret_bigint); // FIXME: replace later
	else
		return mpz_get_ui(bigint);
}

size_t TMCG_Bigint::size
	(const size_t base) const
{
	if (secret)
	{
		size_t bits = gcry_mpi_get_nbits(secret_bigint); // Note: 0, if value==0
		if (bits == 0)
			++bits;
		if (base == 2)
			return bits;
		else
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
	}
	else
		return mpz_sizeinbase(bigint, base);
}

void TMCG_Bigint::wrandomb
	(const size_t bits)
{
	if (secret)
	{
		gcry_mpi_randomize(secret_bigint, bits, GCRY_WEAK_RANDOM);
		gcry_mpi_clear_highbit(secret_bigint, bits);
	}
	else
		tmcg_mpz_wrandomb(bigint, bits); // FIXME: replace later
}

void TMCG_Bigint::srandomb
	(const size_t bits)
{
	if (secret)
	{
		gcry_mpi_randomize(secret_bigint, bits, GCRY_STRONG_RANDOM); // FIXME: add Botan
		gcry_mpi_clear_highbit(secret_bigint, bits);
	}
	else
		tmcg_mpz_srandomb(bigint, bits); // FIXME: replace later
}

void TMCG_Bigint::ssrandomb
	(const size_t bits)
{
	if (secret)
	{
		gcry_mpi_randomize(secret_bigint, bits, GCRY_VERY_STRONG_RANDOM); // FIXME: add Botan
		gcry_mpi_clear_highbit(secret_bigint, bits);
	}
	else
		tmcg_mpz_ssrandomb(bigint, bits); // FIXME: replace later
}

void TMCG_Bigint::wrandomm
	(const TMCG_Bigint& mod)
{
	// make bias negligible cf. BSI TR-02102-1, B.4 Verfahren 2
	const size_t bits = mod.size(2) + 64;
	if (secret)
	{
		if (mod.secret)
		{
			gcry_mpi_randomize(secret_bigint, bits, GCRY_WEAK_RANDOM);
			gcry_mpi_mod(secret_bigint, secret_bigint, mod.secret_bigint);
		}
		else
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
	}
	else
	{
		if (mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		else
			tmcg_mpz_wrandomm(bigint, mod.bigint); // FIXME: replace later
	}
}

void TMCG_Bigint::srandomm
	(const TMCG_Bigint& mod)
{
	if (secret)
	{
		const size_t bits = mod.size(2);
		if (mod.secret)
		{
			do
				gcry_mpi_randomize(secret_bigint, bits, GCRY_STRONG_RANDOM);
			while (gcry_mpi_cmp(secret_bigint, mod.secret_bigint) >= 0); // TODO: use constant-time compare strategy
		}
		else
		{
			gcry_mpi_t m = gcry_mpi_new(bits);
			tmcg_mpz_get_gcry_mpi(m, mod.bigint);
			do
				gcry_mpi_randomize(secret_bigint, bits, GCRY_STRONG_RANDOM);
			while (gcry_mpi_cmp(secret_bigint, m) >= 0);
			gcry_mpi_release(m);
		}
	}
	else
	{
		if (mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		else
			tmcg_mpz_srandomm(bigint, mod.bigint); // FIXME: replace later
	}
}

void TMCG_Bigint::ssrandomm
	(const TMCG_Bigint& mod)
{
	if (secret)
	{
		const size_t bits = mod.size(2);
		if (mod.secret)
		{
			do
				gcry_mpi_randomize(secret_bigint, bits, GCRY_VERY_STRONG_RANDOM);
			while (gcry_mpi_cmp(secret_bigint, mod.secret_bigint) >= 0); // TODO: use constant-time compare strategy
		}
		else
		{
			gcry_mpi_t m = gcry_mpi_new(bits);
			tmcg_mpz_get_gcry_mpi(m, mod.bigint);
			do
				gcry_mpi_randomize(secret_bigint, bits, GCRY_VERY_STRONG_RANDOM);
			while (gcry_mpi_cmp(secret_bigint, m) >= 0);
			gcry_mpi_release(m);
		}
	}
	else
	{
		if (mod.secret)
			throw std::invalid_argument("TMCG_Bigint::operation not supported");
		else
			tmcg_mpz_ssrandomm(bigint, mod.bigint); // FIXME: replace later
	}
}

void TMCG_Bigint::ssrandomm_cache_init
	(const TMCG_Bigint& mod, const size_t n)
{
	if (n == 0)
		throw std::invalid_argument("TMCG_Bigint:: n is zero");
	if (n > TMCG_MAX_SSRANDOMM_CACHE)
		throw std::invalid_argument("TMCG_Bigint:: n is too large");
	if (mod.secret)
		throw std::invalid_argument("TMCG_Bigint::operation not supported");
	else
		mpz_init_set(ssrandomm_cache_mod, mod.bigint);
	ssrandomm_cache_n = n;
	for (size_t i = 0; i < ssrandomm_cache_n; i++)
	{
		if (secret)
		{
			ssrandomm_cache_secret_cache[i] = gcry_mpi_snew(8);
			gcry_mpi_t m = gcry_mpi_new(mod.size(2));
			tmcg_mpz_get_gcry_mpi(m, mod.bigint);
			do
			{
				gcry_mpi_randomize(ssrandomm_cache_secret_cache[i], mod.size(2),
					GCRY_VERY_STRONG_RANDOM);
			}
			while (gcry_mpi_cmp(ssrandomm_cache_secret_cache[i], m) >= 0);
			gcry_mpi_release(m);
		}
		else
		{
			mpz_init(ssrandomm_cache_cache[i]);
			tmcg_mpz_ssrandomm(ssrandomm_cache_cache[i], mod.bigint); // FIXME: replace later
		}
	}
	ssrandomm_cache_avail = n;
}

void TMCG_Bigint::ssrandomm_cache
	()
{
	if (ssrandomm_cache_avail > 0)
	{
		ssrandomm_cache_avail--; // next cached random value
		if (secret)
		{
			gcry_mpi_set(secret_bigint,
				ssrandomm_cache_secret_cache[ssrandomm_cache_avail]);
		}
		else
			mpz_set(bigint, ssrandomm_cache_cache[ssrandomm_cache_avail]);
	}
	else
	{
		TMCG_Bigint m(ssrandomm_cache_mod);
		ssrandomm(m);
	}
}

void TMCG_Bigint::ssrandomm_cache_done
	()
{
	mpz_clear(ssrandomm_cache_mod);
	for (size_t i = 0; i < ssrandomm_cache_n; i++)
	{
		if (secret)
		{
			gcry_mpi_release(ssrandomm_cache_secret_cache[i]);
		}
		else
		{
			mpz_clear(ssrandomm_cache_cache[i]);
		}
	}
	ssrandomm_cache_n = 0;
	ssrandomm_cache_avail = 0;
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
		if (!that.exportable)
			throw std::invalid_argument("TMCG_Bigint::output not allowed");
		mpz_t tmp;
		mpz_init(tmp);
		if (tmcg_mpz_set_gcry_mpi(that.secret_bigint, tmp))
		{
			out << tmp;
		}
		else
		{
			mpz_clear(tmp);
			out.setstate(std::ostream::iostate(std::ostream::failbit));
			throw std::runtime_error("operator <<: tmcg_mpz_set_gcry_mpi failed");
		}
		mpz_clear(tmp);
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
			delete [] buf;
			in.setstate(std::istream::iostate(std::istream::failbit));
			throw std::invalid_argument("TMCG_Bigint::mpz_set_str failed");
		}
		delete [] buf;
	}
	return in;
}

