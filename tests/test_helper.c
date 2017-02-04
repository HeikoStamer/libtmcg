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

#include "test_helper.h"

clock_t start, stop;
clock_t start_saved, stop_saved;
char buf[50];

void start_clock
	()
{
	start = clock(), stop = start;
}

void stop_clock
	()
{
	stop = clock();
}

void save_clock
	()
{
	start_saved = start;
	stop_saved = stop;
}

char *elapsed_time
	()
{
	snprintf(buf, sizeof(buf), "%8.0fms",
		(((double) (stop - start)) / CLOCKS_PER_SEC) * 1000);
	return buf;
}

char *current_time
	()
{
	snprintf(buf, sizeof(buf), "%8.0fms",
		(((double) (clock() - start)) / CLOCKS_PER_SEC) * 1000);
	return buf;
}

int compare_time
	(clock_t diff)
{
	if (start < (stop - diff))
		return 1;
	else if (start == (stop - diff))
		return 0;
	else
		return -1;
}

int compare_elapsed_time
	(clock_t diff)
{
	clock_t elapsed = stop - start;
	if (elapsed > diff)
		return 1;
	else if (elapsed == diff)
		return 0;
	else
		return -1;
}

int compare_elapsed_time_saved
	(clock_t diff)
{
	clock_t elapsed = stop - start;
	clock_t elapsed_saved = stop_saved - start_saved;
	if (elapsed < (elapsed_saved - diff))
		return 1;
	else if (elapsed == (elapsed_saved - diff))
		return 0;
	else
		return -1;
}

