/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-builtin-common.hh"

#ifdef FORKING

extern int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
extern pid_t				pid[MAX_N];
extern std::vector<std::string>		peers;
extern bool				instance_forked;
extern int				opt_verbose;
extern void				fork_instance(const size_t whoami);

typedef std::pair<size_t, char*>	DKG_Buffer;
typedef std::pair<size_t, DKG_Buffer>	DKG_BufferListEntry;
typedef std::list<DKG_BufferListEntry>	DKG_BufferList;
//DKG_BufferList			send_queue, send_queue_broadcast;
//static const size_t			pipe_buffer_size = 4096;

std::string 				builtin_thispeer;
std::map<std::string, size_t> 		builtin_peer2pipe;
std::map<size_t, std::string> 		builtin_pipe2peer;

void builtin_init
	(const std::string &hostname)
{
	// initialize peer identity
	builtin_thispeer = hostname;
	// initialize peer2pipe and pipe2peer mapping
	if (opt_verbose)
		std::cout << "INFO: using built-in service for message exchange instead of GNUnet CADET" << std::endl;
	if (std::find(peers.begin(), peers.end(), hostname) == peers.end())
	{
		std::cerr << "ERROR: cannot find hostname \"" << hostname << "\" of this peer within PEERS" << std::endl;
		exit(-1);
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		builtin_peer2pipe[peers[i]] = i;
		builtin_pipe2peer[i] = peers[i];
	}
	// open pipes to communicate with forked instance
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("dkg-builtin-common (pipe)");
				exit(-1);
			}
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("dkg-builtin-common (pipe)");
				exit(-1);
			}
		}
	}
}

void builtin_fork
	()
{
	// fork instance
	if (opt_verbose)
		std::cout << "INFO: forking the protocol instance ..." << std::endl;
	fork_instance(builtin_peer2pipe[builtin_thispeer]);
}

void builtin_done
	()
{
	int thispid = pid[builtin_peer2pipe[builtin_thispeer]];
	if (opt_verbose)
		std::cout << "kill(" << thispid << ", SIGTERM)" << std::endl;
	if(kill(thispid, SIGTERM))
		perror("dkg-builtin-common (kill)");
	if (opt_verbose)
		std::cout << "waitpid(" << thispid << ", NULL, 0)" << std::endl;
	if (waitpid(thispid, NULL, 0) != thispid)
		perror("dkg-builtin-common (waitpid)");
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-builtin-common (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-builtin-common (close)");
		}
	}
}

#endif


