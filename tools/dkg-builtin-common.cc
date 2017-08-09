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

static const size_t			builtin_pipe_buffer_size = 4096;

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
	int local_start = start + (builtin_peer2pipe[builtin_thispeer] * (MAX_N + 1));
	size_t i = 0;
	for (int port = local_start; port < (local_start + (int)peers.size()); port++, i++)
	{
		int sockfd;
		struct sockaddr_in sin = { 0 };
		sin.sin_port = htons(port);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("dkg-builtin-common (socket)");
			builtin_close();
			builtin_done();
			exit(-1);
		}
		if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		{
			perror("dkg-builtin-common (bind)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			builtin_close();
			builtin_done();
			exit(-1);
		}
		if (listen(sockfd, SOMAXCONN) < 0)
		{
			perror("dkg-builtin-common (listen)");
			if (close(sockfd) < 0)
				perror("dkg-builtin-common (close)");
			builtin_close();
			builtin_done();
			exit(-1);
		}
		if (broadcast)
			builtin_broadcast_pipe2socket[i] = sockfd;
		else
			builtin_pipe2socket[i] = sockfd;
	}
}

size_t builtin_connect
	(const int start, const bool broadcast)
{
	for (size_t i = 0; i < peers.size(); i++)
	{
		if ((broadcast && !builtin_broadcast_pipe2socket_out.count(i)) || (!broadcast && !builtin_pipe2socket_out.count(i)))
		{
			int port = start + (i * (MAX_N + 1)) + builtin_peer2pipe[builtin_thispeer];
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
				std::cerr << "ERROR: resolving hostname \"" << peers[i] << "\" failed: ";
				if (h_errno == HOST_NOT_FOUND)
					std::cerr << "host not found" << std::endl;
				else if (h_errno == NO_ADDRESS)
					std::cerr << "no address data" << std::endl;
				else
					std::cerr << "unknown error" << std::endl;
				builtin_close();
				builtin_done();
				exit(-1);
			}
			if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			{
				perror("dkg-builtin-common (socket)");
				builtin_close();
				builtin_done();
				exit(-1);
			}
			if ((connect(sockfd, (struct sockaddr*)&sin, sizeof(sin))) < 0)
			{
				if (errno == ECONNREFUSED)
				{
					if (close(sockfd) < 0)
						perror("dkg-builtin-common (close)");
					continue;
				}
				perror("dkg-builtin-common (connect)");
				if (close(sockfd) < 0)
					perror("dkg-builtin-common (close)");
				builtin_close();
				builtin_done();
				exit(-1);
			}
			if (opt_verbose)
				std::cout << "INFO: resolved hostname \"" << peers[i] << "\" to adress " << inet_ntoa(sin.sin_addr) << std::endl;
			if (opt_verbose)
				std::cout << "INFO: connected to hostname \"" << peers[i] << "\" on port " << port << std::endl;
			if (broadcast)
				builtin_broadcast_pipe2socket_out[i] = sockfd;
			else
				builtin_pipe2socket_out[i] = sockfd;
		}
	}
	if (broadcast)
		return builtin_broadcast_pipe2socket_out.size();
	else
		return builtin_pipe2socket_out.size();
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
			builtin_close();
			builtin_done();
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
					builtin_close();
					builtin_done();
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
	if ((builtin_pipe2socket_in.size() == peers.size()) && (builtin_broadcast_pipe2socket_in.size() == peers.size()))
	{
		// fork instance
		if (opt_verbose)
			std::cout << "INFO: forking the protocol instance ..." << std::endl;
		fork_instance(builtin_peer2pipe[builtin_thispeer]);
	}
	else
	{
		std::cerr << "ERROR: not enough connections established" << std::endl;
		builtin_close();
		builtin_done();
		exit(-1);
	}
}

int builtin_io
	()
{
	while (1)
	{
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket_in.begin(); pi != builtin_pipe2socket_in.end(); ++pi)
		{
			if (pi->first != builtin_peer2pipe[builtin_thispeer])
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
		}
		for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket_in.begin(); pi != builtin_broadcast_pipe2socket_in.end(); ++pi)
		{
			if (pi->first != builtin_peer2pipe[builtin_thispeer])
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (i != builtin_peer2pipe[builtin_thispeer])
			{
				FD_SET(pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], &rfds);
				if (pipefd[builtin_peer2pipe[builtin_thispeer]][i][0] > maxfd)
					maxfd = pipefd[builtin_peer2pipe[builtin_thispeer]][i][0];
				FD_SET(broadcast_pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], &rfds);
				if (broadcast_pipefd[builtin_peer2pipe[builtin_thispeer]][i][0] > maxfd)
					maxfd = broadcast_pipefd[builtin_peer2pipe[builtin_thispeer]][i][0];
			}
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			perror("dkg-builtin-common (select)");
			builtin_close();
			builtin_done();
			exit(-1);
		}
		if (retval == 0)
			continue; // timeout
		for (std::map<size_t, int>::const_iterator pi = builtin_pipe2socket_in.begin(); pi != builtin_pipe2socket_in.end(); ++pi)
		{
			if ((pi->first != builtin_peer2pipe[builtin_thispeer]) && FD_ISSET(pi->second, &rfds))
			{
				char buf[builtin_pipe_buffer_size];
				ssize_t len = read(pi->second, buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else
					{
						perror("dkg-builtin-common (read)");
						builtin_close();
						builtin_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else
				{
					if (opt_verbose)
						std::cout << "INFO: received " << len << " bytes on connection for P_" << pi->first << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(pipefd[pi->first][builtin_peer2pipe[builtin_thispeer]][1],
								buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "sleeping ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("dkg-builtin-common (write)");
								builtin_close();
								builtin_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
		}
		for (std::map<size_t, int>::const_iterator pi = builtin_broadcast_pipe2socket_in.begin(); pi != builtin_broadcast_pipe2socket_in.end(); ++pi)
		{
			if ((pi->first != builtin_peer2pipe[builtin_thispeer]) && FD_ISSET(pi->second, &rfds))
			{
				char buf[builtin_pipe_buffer_size];
				ssize_t len = read(pi->second, buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else
					{
						perror("dkg-builtin-common (read)");
						builtin_close();
						builtin_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else
				{
					if (opt_verbose)
						std::cout << "INFO: received " << len << " bytes on broadcast connection for P_" << pi->first << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(broadcast_pipefd[pi->first][builtin_peer2pipe[builtin_thispeer]][1],
								buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "sleeping ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("dkg-builtin-common (write)");
								builtin_close();
								builtin_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if ((i != builtin_peer2pipe[builtin_thispeer]) && FD_ISSET(pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], &rfds))
			{
				char buf[builtin_pipe_buffer_size];
				ssize_t len = read(pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else
					{
						perror("dkg-builtin-common (read)");
						builtin_close();
						builtin_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else
				{
					if (opt_verbose)
						std::cout << "INFO: sending " << len << " bytes on connection to P_" << i << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(builtin_pipe2socket_out[i], buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "sleeping ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("dkg-builtin-common (write)");
								builtin_close();
								builtin_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
			if ((i != builtin_peer2pipe[builtin_thispeer]) && FD_ISSET(broadcast_pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], &rfds))
			{
				char buf[builtin_pipe_buffer_size];
				ssize_t len = read(broadcast_pipefd[builtin_peer2pipe[builtin_thispeer]][i][0], buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else
					{
						perror("dkg-builtin-common (read)");
						builtin_close();
						builtin_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else
				{
					if (opt_verbose)
						std::cout << "INFO: sending " << len << " bytes on broadcast connection to P_" << i << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(builtin_broadcast_pipe2socket_out[i], buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "sleeping ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("dkg-builtin-common (write)");
								builtin_close();
								builtin_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
		}
		if (instance_forked)
		{
			// exit, if forked instance has terminated 
			int wstatus = 0;
			int thispid = pid[builtin_peer2pipe[builtin_thispeer]];
			int ret = waitpid(thispid, &wstatus, WNOHANG);
			if (ret < 0)
				perror("dkg-builtin-common (waitpid)");
			else if (ret == thispid)
			{
				instance_forked = false;
				if (!WIFEXITED(wstatus))
				{
					std::cerr << "ERROR: protocol instance ";
					if (WIFSIGNALED(wstatus))
						std::cerr << thispid << " terminated by signal " << WTERMSIG(wstatus) << std::endl;
					if (WCOREDUMP(wstatus))
						std::cerr << thispid << " dumped core" << std::endl;
					return -1;
				}
				else if (WIFEXITED(wstatus))
				{
					if (opt_verbose)
						std::cerr << "INFO: protocol instance " << thispid << " terminated with exit status " << WEXITSTATUS(wstatus) << std::endl;
					return WEXITSTATUS(wstatus);
				}
				return 0;
			}
		}
	}
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
	if (instance_forked)
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
	}
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


