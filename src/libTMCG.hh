/*******************************************************************************
   libTMCG.hh, general header of the library

   This file is part of libTMCG.

 Copyright (C) 2004, 2005  Heiko Stamer <stamer@gaos.org>

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

#ifndef INCLUDED_libTMCG_HH
	#define INCLUDED_libTMCG_HH
	
	#ifndef TMCG_DDH_SIZE
		/* Define the security parameter of the DDH-hard group G;
		   Underlying assumptions: DDH, CDH, DLOG */
		#define TMCG_DDH_SIZE 1024L
	#endif

	#ifndef TMCG_DLSE_SIZE
		/* Define the security parameter of the used exponents;
		   Underlying assumptions: DLSE (related to DDH), DLOG */
		#define TMCG_DLSE_SIZE 160L
	#endif

	#ifndef TMCG_GCRY_MD_ALGO
		/* Define the message digest algorithm for signatures and FS-heuristic;
		   Underlying assumption: Random Oracle Model */
		#define TMCG_GCRY_MD_ALGO GCRY_MD_RMD160
	#endif

	#ifndef TMCG_KEYID_SIZE
		/* Define the size of the unique TMCG key ID (in characters) */
		#define TMCG_KEYID_SIZE 5
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

	#ifndef TMCG_MAX_CARDS
		/* Define the maximum number of stackable cards */
		#define TMCG_MAX_CARDS 128L
	#endif

	#ifndef TMCG_MAX_CARD_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_CARD_CHARS (TMCG_MAX_PLAYERS * TMCG_MAX_TYPEBITS * TMCG_MAX_VALUE_CHARS)
	#endif

	#ifndef TMCG_MAX_KEYBITS
		/* Define a helping macro */
		#define TMCG_MAX_KEYBITS ((TMCG_DDH_SIZE > TMCG_QRA_SIZE)?TMCG_DDH_SIZE:TMCG_QRA_SIZE)
	#endif

	#ifndef TMCG_MAX_PLAYERS
		/* Define the maximum number of players in the scheme of Schindelhauer */
		#define TMCG_MAX_PLAYERS 32L
	#endif

	#ifndef TMCG_MAX_STACK_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_STACK_CHARS (TMCG_MAX_CARDS * TMCG_MAX_CARD_CHARS)
	#endif

	#ifndef TMCG_MAX_TYPEBITS
		/* Define the number of bits which represents the maximum number of
		   different card types in the scheme of Schindelhauer */
		#define TMCG_MAX_TYPEBITS 8L
	#endif

	#ifndef TMCG_MAX_VALUE_CHARS
		/* Define a helping macro */
		#define TMCG_MAX_VALUE_CHARS (TMCG_MAX_KEYBITS / 2L)
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
		   Underlying assumptions: QRA, FAKTOR */
		#define TMCG_QRA_SIZE 1024L
	#endif

	#ifndef TMCG_SAEP_S0
		/* Define the security parameter for the encryption with Rabin/SAEP */
		#define TMCG_SAEP_S0 20
	#endif

	#ifndef TMCG_STACK_EQUALITY_HASH
		/* Define whether short stack commitments (hash function) should be used;
		   Underlying assumption: Random Oracle Model */
		#define TMCG_STACK_EQUALITY_HASH 1
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
	
	bool init_libTMCG
		();
#endif
