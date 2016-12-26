/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dkg_gnunet_common_HH
	#define INCLUDED_dkg_gnunet_common_HH

	// include headers
	#include <iostream>
	#include <vector>
	#include <list>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <aiounicast.hh>

#ifdef FORKING

	#include <sys/wait.h>
	#include <signal.h>

	#undef NDEBUG
	#define MAX_N 1024

#ifdef GNUNET

	#undef HAVE_CONFIG_H
	#undef PACKAGE
	#undef PACKAGE_BUGREPORT
	#undef PACKAGE_NAME
	#undef PACKAGE_STRING
	#undef PACKAGE_TARNAME
	#undef PACKAGE_URL
	#undef PACKAGE_VERSION
	#undef VERSION
	#define HAVE_CONFIG_H 1
	#include <gnunet/platform.h>
	#include <gnunet/gnunet_util_lib.h>
	#include <gnunet/gnunet_transport_hello_service.h>
	#include <gnunet/gnunet_cadet_service.h>
	#undef HAVE_CONFIG_H

	void gnunet_hello_callback
		(void *cls, const struct GNUNET_MessageHeader *hello);
	int gnunet_data_callback
		(void *cls, struct GNUNET_CADET_Channel *channel,
		void **channel_ctx, const struct GNUNET_MessageHeader *message);
	size_t gnunet_data_ready
		(void *cls, size_t size, void *buf);
	void gnunet_data_abort
		(void *cls);
	size_t gnunet_data_ready_broadcast
		(void *cls, size_t size, void *buf);
	void gnunet_data_abort_broadcast
		(void *cls);
	void gnunet_pipe_ready
		(void *cls);
	void gnunet_broadcast_pipe_ready
		(void *cls);
	void gnunet_channel_ended
		(void *cls, const struct GNUNET_CADET_Channel *channel,
		void *channel_ctx);
	void* gnunet_channel_incoming
		(void *cls, struct GNUNET_CADET_Channel *channel,
		const struct GNUNET_PeerIdentity *initiator,
		const struct GNUNET_HashCode *port,
		enum GNUNET_CADET_ChannelOption options);
	void gnunet_shutdown_task
		(void *cls);
	void gnunet_io
		(void *cls);
	void gnunet_connect
		(void *cls);
	void gnunet_statistics
		(void *cls);
	void gnunet_init
		(void *cls);
	void gnunet_run
		(void *cls, char *const *args, const char *cfgfile, 
		const struct GNUNET_CONFIGURATION_Handle *cfg);
#endif

#endif

#endif

