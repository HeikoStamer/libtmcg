/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2005, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/
#ifndef INCLUDED_test_helper_H
	#define INCLUDED_test_helper_H
	
	#include <stdio.h>
	#include <time.h>
	
	#if defined (__cplusplus)
		extern "C"
		{
	#endif
	
	void start_clock
		();
	void stop_clock
		();
	void save_clock
		();
	char *elapsed_time
		();
	char *current_time
		();
	int compare_time
		(clock_t diff);
	int compare_elapsed_time
		(clock_t diff);
	int compare_elapsed_time_saved
		(clock_t diff);
	
	#if defined(__cplusplus)
		}
	#endif

#endif
