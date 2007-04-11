/*******************************************************************************
   libTMCG.hh, general header file of the library

   This file is part of LibTMCG.

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

#ifndef INCLUDED_libTMCG_HH
	#define INCLUDED_libTMCG_HH
	
	#ifndef TMCG_MR_ITERATIONS
		/* Define the number of iterations for the Miller-Rabin primality test.
		   (maximum soundness error probability 4^{-TMCG_MR_ITERATIONS}) */
		#define TMCG_MR_ITERATIONS 64
	#endif
	
	#ifndef TMCG_GROTH_L_E
		/* Define the security parameter for the soundness of the
		   interactive argument for Groth's VSSHE and SKC. */
		#define TMCG_GROTH_L_E 80
	#endif
	
	#ifndef TMCG_DDH_SIZE
		/* Define the security parameter of the DDH-hard group G;
		   Underlying assumptions: DDH, CDH, DLOG */
		#define TMCG_DDH_SIZE 1024
	#endif
	
	#ifndef TMCG_DLSE_SIZE
		/* Define the security parameter of the used exponents;
		   Underlying assumptions: DLSE (related to DDH), DLOG */
		#define TMCG_DLSE_SIZE 160
	#endif
	
	#ifndef TMCG_GCRY_MD_ALGO
		/* Define the message digest algorithm for signatures and FS-heuristic;
		   Underlying assumption: Random Oracle Model */
		#define TMCG_GCRY_MD_ALGO GCRY_MD_RMD160
	#endif
	
	#ifndef TMCG_KEYID_SIZE
		/* Define the size of the unique TMCG key ID (in characters) */
		#define TMCG_KEYID_SIZE 8 
	#endif
	
	#ifndef TMCG_KEY_NIZK_STAGE1
		/* Define the maximum soundness error probability of the TMCG public key;
		   NIZK proof (Gennaro, Micciancio, Rabin), Stage 1: m is square free;
		   d^{-TMCG_KEY_NIZK_STAGE1} with d = ... */
		#define TMCG_KEY_NIZK_STAGE1 16
	#endif
	
	#ifndef TMCG_KEY_NIZK_STAGE2
		/* Define the maximum soundness error probability of the TMCG public key;
		   NIZK proof (Gennaro, Micciancio, Rabin), Stage 2: m is prime power product;
		   2^{-TMCG_KEY_NIZK_STAGE2} */
		#define TMCG_KEY_NIZK_STAGE2 128
	#endif
	
	#ifndef TMCG_KEY_NIZK_STAGE3
		/* Define the maximum soundness error probability for the TMCG public key;
		   NIZK proof (Goldwasser, Micali); Stage 3: y \in NQR^\circ_m;
		   2^{-TMCG_KEY_NIZK_STAGE3} */
		#define TMCG_KEY_NIZK_STAGE3 128
	#endif
	
	#ifndef TMCG_LIBGCRYPT_VERSION
		/* Define the necessary version number of the GNU gcrypt library */
		#define TMCG_LIBGCRYPT_VERSION "1.2.0"
	#endif
	
	#ifndef TMCG_LIBGMP_VERSION
		/* Define the necessary version number of the GNU gmp library */
		#define TMCG_LIBGMP_VERSION "4.1.0"
	#endif
	
	#ifndef TMCG_MAX_CARDS
		/* Define the maximum number of stackable cards */
		#define TMCG_MAX_CARDS 128
	#endif
	
	#ifndef TMCG_MAX_CARD_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_CARD_CHARS (TMCG_MAX_PLAYERS * TMCG_MAX_TYPEBITS * TMCG_MAX_VALUE_CHARS)
	#endif
	
	#ifndef TMCG_MAX_KEYBITS
		/* Define a helping macro */
		#define TMCG_MAX_KEYBITS ((TMCG_DDH_SIZE > TMCG_QRA_SIZE) ? TMCG_DDH_SIZE : TMCG_QRA_SIZE)
	#endif
	
	#ifndef TMCG_MAX_PLAYERS
		/* Define the maximum number of players in the scheme of Schindelhauer */
		#define TMCG_MAX_PLAYERS 32
	#endif
	
	#ifndef TMCG_MAX_STACK_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_STACK_CHARS (TMCG_MAX_CARDS * TMCG_MAX_CARD_CHARS)
	#endif
	
	#ifndef TMCG_MAX_TYPEBITS
		/* Define the number of bits which represents the maximum number of
		   different card types in the scheme of Schindelhauer and the maximum
		   size of the message space in the scheme of Barnett and Smart */
		#define TMCG_MAX_TYPEBITS 8
	#endif
	
	#ifndef TMCG_MAX_VALUE_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_VALUE_CHARS (TMCG_MAX_KEYBITS / 2L)
	#endif
	
	#ifndef TMCG_MAX_KEY_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_KEY_CHARS (TMCG_MAX_KEYBITS * 1024L)
	#endif
	
	#ifndef TMCG_MPZ_IO_BASE
		/* Define the input/ouput base encoding of the iostream operators */
		#define TMCG_MPZ_IO_BASE 36
	#endif
	
	#ifndef TMCG_PRAB_K0
		/* Define the security parameter for the signature generation
		   with Rabin/PRab */
		#define TMCG_PRAB_K0 20
	#endif
	
	#ifndef TMCG_QRA_SIZE
		/* Define the security parameter of the TMCG public key;
		   Underlying assumptions: QRA, FACTOR */
		#define TMCG_QRA_SIZE 1024
	#endif
	
	#ifndef TMCG_SAEP_S0
		/* Define the security parameter for the encryption with Rabin/SAEP */
		#define TMCG_SAEP_S0 20
	#endif
	
	#ifndef TMCG_HASH_COMMITMENT
		/* Define whether hashed commitments (short values) should be used;
		   Underlying assumption: Random Oracle Model */
		#define TMCG_HASH_COMMITMENT true
	#endif
	
	#ifndef TMCG_MAX_FPOWM_T
		/* Define the maximum size of the exponent for fast exponentiation */
		#define TMCG_MAX_FPOWM_T 2048
	#endif
	
	// disable usage of config.h
	#ifdef HAVE_CONFIG_H
		#define TMCG_CONFIG_H
		#undef HAVE_CONFIG_H
	#endif
	
	#include <TMCG_SecretKey.hh>
	#include <TMCG_PublicKey.hh>
	#include <TMCG_PublicKeyRing.hh>
	
	#include <VTMF_Card.hh>
	#include <VTMF_CardSecret.hh>
	#include <TMCG_Card.hh>
	#include <TMCG_CardSecret.hh>
	#include <TMCG_Stack.hh>
	#include <TMCG_OpenStack.hh>
	#include <TMCG_StackSecret.hh>
	
	#include <SchindelhauerTMCG.hh>
	
	// enable usage of config.h
	#ifdef TMCG_CONFIG_H
		#define HAVE_CONFIG_H
		#undef TMCG_CONFIG_H
	#endif
	
	// config.h
	#ifdef HAVE_CONFIG_H
		#include "config.h"
	#endif
	
	#include <cstring>
	#include <string>
	
	// Initialization of LibTMCG
	bool init_libTMCG
		();
	
	// Returns the version of LibTMCG
	std::string version_libTMCG
		();
#endif
