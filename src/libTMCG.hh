/*******************************************************************************
   libTMCG.hh, general header of the |T|oolbox for |M|ental |C|ard |G|ames

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

#ifndef INCLUDED_libTMCG_HH
	#define INCLUDED_libTMCG_HH

	#ifndef TMCG_LIBGCRYPT_VERSION
		/* Define appropriate version number of the necessary gcrypt library */
		#define TMCG_LIBGCRYPT_VERSION "1.2.0"
	#endif

	#ifndef TMCG_MPZ_IO_BASE
		/* Define input/ouput base encoding of the iostream operators */
		#define TMCG_MPZ_IO_BASE 36
	#endif
	
	#ifndef TMCG_GCRY_MD_ALGO
		/* Define message digest algorithm for signatures and FS-heuristic
		 * Underlying assumptions: g behaves like a Random Oracle
		 */
		#define TMCG_GCRY_MD_ALGO GCRY_MD_RMD160
	#endif
	
	#ifndef TMCG_DDH_P_SIZE
		/* Define security parameter of the DDH-hard group G
		 * Underlying assumptions: DDH, CDH, DLOG
		 */
		#define TMCG_DDH_P_SIZE 1024L
	#endif
	
	#ifndef TMCG_DLSE_SIZE
		/* Define security parameter of the used exponents
		 * Underlying assumptions: DLSE (related to DDH)
		 */
		#define TMCG_DLSE_SIZE 160L
	#endif
	
	#ifndef TMCG_KEY_SIZE
		/* security parameter of the TMCG public key
		 * Underlying assumptions: QRA, FAKTOR
		 */
		#define TMCG_KEY_SIZE 1024L
	#endif
	
	#ifndef TMCG_KEYID_SIZE
		/* Define size of the unique TMCG key ID (in characters) */
		#define TMCG_KEYID_SIZE 5
	#endif

	#include <libTMCG.def>

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
#endif
