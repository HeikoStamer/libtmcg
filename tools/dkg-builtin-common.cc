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
std::map<size_t, int>	 		builtin_pipe2socket, builtin_broadcast_pipe2socket;
std::map<size_t, int>	 		builtin_pipe2socket_out, builtin_broadcast_pipe2socket_out;
std::map<size_t, int>	 		builtin_pipe2socket_in, builtin_broadcast_pipe2socket_in;

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

void builtin_bindports
	(const int start, const bool broadcast)
{
	size_t i = 0;
	for (int port = start; port < (start + (int)peers.size()); port++, i++)
	{
		int sockfd;
		struct sockaddr_in sin = { 0 };
		sin.sin_port = htons(port);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("dkg-builtin-common (socket)");
			exit(-1);
		}
/*
		long socket_option = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) < 0)
		{
			perror("dkg-builtin-common (setsockopt)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			exit(-1);
		}
*/
		if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		{
			perror("dkg-builtin-common (bind)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			exit(-1);
		}
		if (listen(sockfd, SOMAXCONN) < 0)
		{
			perror("dkg-builtin-common (listen)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			exit(-1);
		}
		if (broadcast)
			builtin_broadcast_pipe2socket[i] = sockfd;
		else
			builtin_pipe2socket[i] = sockfd;
	}
}

void builtin_connect
	(const int start, const bool broadcast)
{
	size_t i = 0;
	for (int port = start; port < (start + (int)peers.size()); port++, i++)
	{
		int sockfd;
		struct hostent *hostinf;
		struct sockaddr_in sin = { 0 };
		sin.sin_port = htons(port);
		sin.sin_family = AF_INET;
		if ((hostinf = gethostbyname(peers[i].c_str())) != NULL)
		{
			memcpy((char*)&sin.sin_addr, hostinf->h_addr, hostinf->h_length);
		}
		else
		{
			std::cerr << "ERROR: resolving hostname \"" << peers[i] << "\" failed" << std::endl;
			if (h_errno == HOST_NOT_FOUND)
				std::cerr << "host not found" << std::endl;
			else if (h_errno == NO_ADDRESS)
				std::cerr << "no address data" << std::endl;
			else
				std::cerr << "unknown error" << std::endl;
			exit(-1);
		}
		if (opt_verbose)
			std::cout << "INFO: resolved hostname \"" << peers[i] << "\" to adress " << inet_ntoa(sin.sin_addr) << std::endl;
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("dkg-builtin-common (socket)");
			exit(-1);
		}
		if ((connect(sockfd, (struct sockaddr*)&sin, sizeof(sin))) < 0)
		{
			perror("dkg-builtin-common (connect)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			exit(-1);
		}
		if (broadcast)
			builtin_broadcast_pipe2socket_out[i] = sockfd;
		else
			builtin_pipe2socket_out[i] = sockfd;
	}
}

void builtin_accept
	()
{
	while ((builtin_pipe2socket_in.size() < peers.size()) || (builtin_broadcast_pipe2socket_in.size() < peers.size()))
	{
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket.begin(); pi != builtin_pipe2socket.end(); ++pi)
		{
			FD_SET(pi->second, &rfds);
			if (pi->second > maxfd)
				maxfd = pi->second;
		}
		for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket.begin(); pi != builtin_broadcast_pipe2socket.end(); ++pi)
		{
			FD_SET(pi->second, &rfds);
			if (pi->second > maxfd)
				maxfd = pi->second;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			perror("dkg-builtin-common (select)");
			exit(-1);
		}
		if (retval == 0)
			continue; // timeout
		for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket.begin(); pi != builtin_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_in sin = { 0 };
				socklen_t slen = (socklen_t)sizeof(sin);
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("dkg-builtin-common (accept)");
					exit(-1);
				}
				builtin_pipe2socket_in[pi->first] = connfd;
				if (opt_verbose)
					std::cout << "INFO: accept connection for P_" << pi->first << " from adress " <<
						inet_ntoa(sin.sin_addr) << std::endl;
			}
		}
		for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket.begin(); pi != builtin_broadcast_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_in sin = { 0 };
				socklen_t slen = (socklen_t)sizeof(sin);
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("dkg-builtin-common (accept)");
					exit(-1);
				}
				builtin_broadcast_pipe2socket_in[pi->first] = connfd;
				if (opt_verbose)
					std::cout << "INFO: accept broadcast connection for P_" << pi->first << " from adress " << 
						inet_ntoa(sin.sin_addr) << std::endl;
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

void builtin_close
	()
{
	for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket_in.begin(); pi != builtin_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
	for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket_out.begin(); pi != builtin_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
	for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket_in.begin(); pi != builtin_broadcast_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
	for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket_out.begin(); pi != builtin_broadcast_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
	for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket.begin(); pi != builtin_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
	for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket.begin(); pi != builtin_broadcast_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("dkg-builtin-common (close)");
	}
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


