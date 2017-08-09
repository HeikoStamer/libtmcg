/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-gnunet-common.hh"

#ifdef FORKING

extern int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
extern pid_t				pid[MAX_N];
extern std::vector<std::string>		peers;
extern bool				instance_forked;
extern void				fork_instance(const size_t whoami);

#ifdef GNUNET

typedef std::pair<size_t, char*>	DKG_Buffer;
typedef std::pair<size_t, DKG_Buffer>	DKG_BufferListEntry;
typedef std::list<DKG_BufferListEntry>	DKG_BufferList;
DKG_BufferList				send_queue, send_queue_broadcast;
static const size_t			pipe_buffer_size = 4096;

extern char				*gnunet_opt_port;
extern unsigned int			gnunet_opt_wait;
extern unsigned int			gnunet_opt_xtests;
extern int				gnunet_opt_verbose;

// 1080-1109 reserved for TMCG (see gnunet-developers, January 2017)
#define GNUNET_MESSAGE_TYPE_TMCG_DKG_CHANNEL_CHECK  1080
#define GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_UNICAST   1081
#define GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_BROADCAST 1082

static struct GNUNET_CADET_Handle		*mh = NULL;
static struct GNUNET_TRANSPORT_HelloGetHandle	*gh = NULL;
static struct GNUNET_HELLO_Message 		*ohello = NULL;
static struct GNUNET_CADET_Port 		*lp = NULL;
static struct GNUNET_SCHEDULER_Task 		*sd = NULL;
static struct GNUNET_SCHEDULER_Task 		*ft = NULL;
static struct GNUNET_SCHEDULER_Task 		*st = NULL;
static struct GNUNET_SCHEDULER_Task 		*io = NULL;
static struct GNUNET_SCHEDULER_Task 		*ct = NULL;
static struct GNUNET_SCHEDULER_Task 		*pt = NULL;
static struct GNUNET_SCHEDULER_Task		*pt_broadcast = NULL;
static struct GNUNET_SCHEDULER_Task		*job = NULL;
static struct GNUNET_PeerIdentity		opi;
static struct GNUNET_HashCode			porthash;

static bool 					pipes_created = false;
static bool 					channels_created = false;
std::string 					thispeer;
std::map<std::string, size_t> 			peer2pipe;
std::map<size_t, std::string> 			pipe2peer;
std::map<size_t, struct GNUNET_CADET_Channel*> 	pipe2channel_out;
std::map<size_t, struct GNUNET_CADET_Channel*> 	pipe2channel_in;

void gnunet_hello_callback(void *cls, const struct GNUNET_MessageHeader *hello)
{
	if (hello == NULL)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No hello message in callback\n");
		std::cerr << "ERROR: no hello message" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}
	ohello = (struct GNUNET_HELLO_Message *) GNUNET_copy_message(hello);
	if (GNUNET_HELLO_get_id(ohello, &opi) != GNUNET_OK)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "GNUNET_HELLO_get_id() failed\n");
		std::cerr << "ERROR: bad format of hello message" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}
	GNUNET_TRANSPORT_hello_get_cancel(gh);
	gh = NULL;
}

int check_gnunet_data_callback(void *cls, const struct GNUNET_MessageHeader *message)
{
	return GNUNET_OK;
}

void handle_gnunet_data_callback(void *cls, const struct GNUNET_MessageHeader *message)
{
	size_t peer_id = (size_t)cls;
	struct GNUNET_CADET_Channel *channel = pipe2channel_out.count(peer_id) ? pipe2channel_out[peer_id] : NULL;
	uint16_t cnt = 0;
	std::string peer;

	// check whether the used channel is (still) registered
	GNUNET_assert(channel != NULL);
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (pipe2channel_in.count(i) && (pipe2channel_in[i] == channel))
			peer = pipe2peer[i], cnt++;
		if (pipe2channel_out.count(i) && (pipe2channel_out[i] == channel))
			peer = pipe2peer[i], cnt++;
	}
	if (!cnt)
	{
		std::cerr << "WARNING: ignore incoming message from unregistered channel" << std::endl;
		return;
	}
	else if (cnt > 1)
	{
		std::cerr << "ERROR: this channel is registered more than once" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// initialize variables
	GNUNET_assert(ntohs(message->size) >= sizeof(*message));
	uint16_t len = ntohs(message->size) - sizeof(*message);
	if (gnunet_opt_verbose)
		GNUNET_log(GNUNET_ERROR_TYPE_MESSAGE, "Got message of type %u from %s with %u bytes\n", ntohs(message->type), peer.c_str(), len);
	const char *buf = (const char *)&message[1];
	int fd;
	if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_UNICAST)
		fd = pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_BROADCAST)
		fd = broadcast_pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else
	{
		// ignore unknown message types including channel check
		GNUNET_CADET_receive_done(channel);
		return;
	}

	// write payload into the corresponding pipe
	GNUNET_assert(buf != NULL);
	ssize_t wnum = 0;
	do
	{
		ssize_t num = write(fd, buf + wnum, len - wnum);
		if (num < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
			{
				if (gnunet_opt_verbose)
					std::cerr << "sleeping ..." << std::endl;
				sleep(1);
				continue;
			}
			else
			{
				perror("dkg-gnunet-common (write)");
				GNUNET_SCHEDULER_shutdown();
				return;
			}
		}
		else
			wnum += num;
	}
	while (wnum < len);

	// ready for receiving next message on this channel
	GNUNET_CADET_receive_done(channel);
	return;
}

void gnunet_pipe_ready(void *cls)
{
	pt = NULL;
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i != peer2pipe[thispeer])
		{
			char *th_buf = new char[pipe_buffer_size];
			ssize_t num = read(pipefd[peer2pipe[thispeer]][i][0], th_buf, pipe_buffer_size);
			if (num < 0)
			{
				delete [] th_buf;
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
				{
					continue;
				}
				else
				{
					perror("dkg-gnunet-common (read)");
					GNUNET_SCHEDULER_shutdown();
					return;
				}
			}
			else if (num == 0)
			{
				delete [] th_buf;
				continue;
			}
			else
			{
				DKG_BufferListEntry ble = DKG_BufferListEntry(i, DKG_Buffer(num, th_buf));
				send_queue.push_back(ble);
			}
		}
	}
	// reschedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

void gnunet_broadcast_pipe_ready(void *cls)
{
	pt_broadcast = NULL;
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i != peer2pipe[thispeer])
		{
			char *th_buf = new char[pipe_buffer_size];
			ssize_t num = read(broadcast_pipefd[peer2pipe[thispeer]][i][0], th_buf, pipe_buffer_size);
			if (num < 0)
			{
				delete [] th_buf;
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
				{
					continue;
				}
				else
				{
					perror("dkg-gnunet-common (read)");
					GNUNET_SCHEDULER_shutdown();
					return;
				}
			}
			else if (num == 0)
			{
				delete [] th_buf;
				continue;
			}
			else
			{
				DKG_BufferListEntry ble = DKG_BufferListEntry(i, DKG_Buffer(num, th_buf));
				send_queue_broadcast.push_back(ble);
			}
		}
	}
	// reschedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

void gnunet_channel_ended(void *cls, const struct GNUNET_CADET_Channel *channel)
{
	// deregister the ended channel	
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (pipe2channel_out.count(i) && (pipe2channel_out[i] == channel))
		{
			if (gnunet_opt_verbose)
				std::cerr << "WARNING: output channel ended for peer = " << pipe2peer[i] << std::endl;
			pipe2channel_out.erase(i);
			return;
		}
		if (pipe2channel_in.count(i) && (pipe2channel_in[i] == channel))
		{
			if (gnunet_opt_verbose)
				std::cerr << "WARNING: input channel ended for peer = " << pipe2peer[i] << std::endl;
			pipe2channel_in.erase(i);
			return;
		}
	}
	std::cerr << "WARNING: ended channel is not registered" << std::endl;
}

void* gnunet_channel_incoming(void *cls, struct GNUNET_CADET_Channel *channel,
	const struct GNUNET_PeerIdentity *initiator)
{
	if (gnunet_opt_verbose)
		std::cout << "INFO: incoming channel from " << GNUNET_i2s_full(initiator) << std::endl;
	// check whether peer identity is included in peer list
	std::string peer = GNUNET_i2s_full(initiator);
	if (peer2pipe.count(peer) == 0)
	{
		std::cerr << "WARNING: incoming channel from peer not included in PEERS ignored" << std::endl;
		return channel;
	}
	// register this channel, if not already done
	if (pipe2channel_in.count(peer2pipe[peer]) == 0)
	{
		pipe2channel_in[peer2pipe[peer]] = channel;
	}
	else
		std::cerr << "WARNING: incoming channel is already registered for this peer" << std::endl;
	return channel;
}

void gnunet_shutdown_task(void *cls)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
	// cancel scheduled tasks
	if (pt_broadcast != NULL)
	{
		GNUNET_SCHEDULER_cancel(pt_broadcast);
		pt_broadcast = NULL;
	}
	if (pt != NULL)
	{
		GNUNET_SCHEDULER_cancel(pt);
		pt = NULL;
	}
	if (io != NULL)
	{
		GNUNET_SCHEDULER_cancel(io);
		io = NULL;
	}
	if (ct != NULL)
	{
		GNUNET_SCHEDULER_cancel(ct);
		ct = NULL;
	}
	if (st != NULL)
	{
		GNUNET_SCHEDULER_cancel(st);
		st = NULL;
	}
	if (ft != NULL)
	{
		GNUNET_SCHEDULER_cancel(ft);
		ft = NULL;
	}
	if (job != NULL)
	{
		GNUNET_SCHEDULER_cancel(job);
		job = NULL;
	}
	// release buffered messages
	while (send_queue.size())
	{
		DKG_BufferListEntry ble = send_queue.front();
		DKG_Buffer qbuf = ble.second;
		delete [] qbuf.second;
		send_queue.pop_front();
	}
	while (send_queue_broadcast.size())
	{
		DKG_BufferListEntry ble = send_queue_broadcast.front();
		DKG_Buffer qbuf = ble.second;
		delete [] qbuf.second;
		send_queue_broadcast.pop_front();
	}
	// destroy remaining CADET channels
	for (size_t i = 0; ((i < peers.size()) && channels_created); i++)
	{
		if (i != peer2pipe[thispeer])
		{
			if (pipe2channel_out.count(i))
				GNUNET_CADET_channel_destroy(pipe2channel_out[i]);
			if (pipe2channel_in.count(i))
				GNUNET_CADET_channel_destroy(pipe2channel_in[i]);
		}
	}
	channels_created = false;
	// wait for forked instance and close pipes
	if (instance_forked)
	{
		int thispid = pid[peer2pipe[thispeer]];
		std::cout << "kill(" << thispid << ", SIGTERM)" << std::endl;
		if(kill(thispid, SIGTERM))
			perror("dkg-gnunet-common (kill)");
		std::cout << "waitpid(" << thispid << ", NULL, 0)" << std::endl;
		if (waitpid(thispid, NULL, 0) != thispid)
			perror("dkg-gnunet-common (waitpid)");
		instance_forked = false;
	}
	for (size_t i = 0; ((i < peers.size()) && pipes_created); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-gnunet-common (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-gnunet-common (close)");
		}
	}
	pipes_created = false;
	if (lp != NULL)
	{
		GNUNET_CADET_close_port(lp);
		lp = NULL;
	}
	if (mh != NULL)
	{
		GNUNET_CADET_disconnect(mh);
		mh = NULL;
	}
	if (ohello != NULL)
	{
		GNUNET_free(ohello);
		ohello = NULL;
	}
	// FIXME: I guess this exit-call is not correct. However, otherwise the program
	//        does not terminate, if GNUnet services are not running.
	exit(-1);
}

void gnunet_io(void *cls)
{
	io = NULL;

	// NOTE: We need a short pause here, otherwise GNUnet CADET will be disrupted.
//	sleep(1);

	// send messages to peers
	if (send_queue.size())
	{
		DKG_BufferListEntry ble = send_queue.front();
		DKG_Buffer buf = ble.second;
		struct GNUNET_MQ_Envelope *env;
		struct GNUNET_MessageHeader *msg;
		if (pipe2channel_in.count(ble.first)) // have input channel to this peer?
		{
			if (gnunet_opt_verbose)
				std::cout << "INFO: try to send " << buf.first << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
			env = GNUNET_MQ_msg_extra(msg, buf.first, GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_UNICAST);
			GNUNET_memcpy(&msg[1], buf.second, buf.first);
			GNUNET_MQ_send(GNUNET_CADET_get_mq(pipe2channel_in[ble.first]), env);
			// release buffered message
			delete [] buf.second;
			send_queue.pop_front();
		}
	}

	// send broadcast messages to peers
	if (send_queue_broadcast.size())
	{
		DKG_BufferListEntry ble = send_queue_broadcast.front();
		DKG_Buffer buf = ble.second;
		struct GNUNET_MQ_Envelope *env;
		struct GNUNET_MessageHeader *msg;
		if (pipe2channel_in.count(ble.first)) // have input channel to this peer?
		{
			if (gnunet_opt_verbose)
				std::cout << "INFO: try to broadcast " << buf.first << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
			env = GNUNET_MQ_msg_extra(msg, buf.first, GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_BROADCAST);
			GNUNET_memcpy(&msg[1], buf.second, buf.first);
			GNUNET_MQ_send(GNUNET_CADET_get_mq(pipe2channel_in[ble.first]), env);
			// release buffered message
			delete [] buf.second;
			send_queue_broadcast.pop_front();
		}
	}

	// reschedule I/O task, if further messages available
	if (send_queue.size() || send_queue_broadcast.size())
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);

	// schedule tasks for reading the input pipes 
	// TODO: use GNUNET_SCHEDULER_add_read_file() on corresponding pipe fd
	if (pt == NULL)
		pt = GNUNET_SCHEDULER_add_now(&gnunet_pipe_ready, NULL);
	if (pt_broadcast == NULL)
		pt_broadcast = GNUNET_SCHEDULER_add_now(&gnunet_broadcast_pipe_ready, NULL);

	// next: schedule (re)connect task
	if (ct == NULL)
		ct = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 1), &gnunet_connect, NULL);
}

void gnunet_connect(void *cls)
{
	ct = NULL;

	for (size_t i = 0; i < peers.size(); i++)
	{
		bool stabilized = true;
		if (!pipe2channel_out.count(i))
			stabilized = false;
//		else if (!pipe2channel_in.count(i))
//			stabilized = false;
// NOTE: reconnect not needed, if GNUnet CADET works correctly
		if ((i != peer2pipe[thispeer]) && !stabilized)
		{
			// destroy old CADET output channels, if exist
			if (pipe2channel_out.count(i))
				GNUNET_CADET_channel_destroy(pipe2channel_out[i]);
			// create new CADET output channels
			struct GNUNET_PeerIdentity pid;
			enum GNUNET_CADET_ChannelOption flags = GNUNET_CADET_OPTION_RELIABLE;
			struct GNUNET_CADET_Channel *ch;
			if (GNUNET_CRYPTO_eddsa_public_key_from_string(pipe2peer[i].c_str(), pipe2peer[i].length(), &pid.public_key) != GNUNET_OK)
			{
				std::cerr << "ERROR: bad public key of peer = " << pipe2peer[i] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			if (gnunet_opt_verbose)
				GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to `%s'\n", pipe2peer[i].c_str());
			static const struct GNUNET_MQ_MessageHandler handlers[] = {
				GNUNET_MQ_hd_var_size(gnunet_data_callback,
					GNUNET_MESSAGE_TYPE_TMCG_DKG_CHANNEL_CHECK,
					struct GNUNET_MessageHeader,
					NULL),
				GNUNET_MQ_hd_var_size(gnunet_data_callback,
					GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_UNICAST,
					struct GNUNET_MessageHeader,
					NULL),
				GNUNET_MQ_hd_var_size(gnunet_data_callback,
					GNUNET_MESSAGE_TYPE_TMCG_DKG_PIPE_BROADCAST,
					struct GNUNET_MessageHeader,
					NULL),
				GNUNET_MQ_handler_end()
			};
			ch = GNUNET_CADET_channel_create(mh, (void*)i, &pid, &porthash, flags, NULL, &gnunet_channel_ended, handlers);
			if (ch == NULL)
			{
				std::cerr << "ERROR: cannot create channel to peer = " << pipe2peer[i] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			else
				pipe2channel_out[i] = ch;
		}
	}
	channels_created = true;

	// next: schedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

void gnunet_statistics(void *cls)
{
	st = NULL;

	if (gnunet_opt_verbose)
		std::cout << "INFO: pipe2channel_out.size() = " << pipe2channel_out.size() << ", pipe2channel_in.size() = " << pipe2channel_in.size() << std::endl;
	if (gnunet_opt_verbose)
		std::cout << "INFO: send_queue.size() = " << send_queue.size() << ", send_queue_broadcast.size() = " << send_queue_broadcast.size() << std::endl;
	if (instance_forked)
	{
		// shutdown, if forked instance has terminated 
		int wstatus = 0;
		int thispid = pid[peer2pipe[thispeer]];
		int ret = waitpid(thispid, &wstatus, WNOHANG);
		if (ret < 0)
			perror("dkg-gnunet-common (waitpid)");
		else if (ret == thispid)
		{
			if (!WIFEXITED(wstatus))
			{
				std::cerr << "ERROR: instance ";
				if (WIFSIGNALED(wstatus))
					std::cerr << thispid << " terminated by signal " << WTERMSIG(wstatus) << std::endl;
				if (WCOREDUMP(wstatus))
					std::cerr << thispid << " dumped core" << std::endl;
			}
			else if (WIFEXITED(wstatus))
			{
				if (gnunet_opt_verbose)
					std::cerr << "INFO: DKG/tDSS instance " << thispid << " terminated with exit status " << WEXITSTATUS(wstatus) << std::endl;
			}
			instance_forked = false;
			GNUNET_SCHEDULER_shutdown();
		}
	}
	// reschedule statistics task
	st = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 45), &gnunet_statistics, NULL);
}

void gnunet_fork(void *cls)
{
	ft = NULL;

	if (pipe2channel_in.size() == (peers.size() - 1))
	{
		// fork instance
		if (gnunet_opt_verbose)
			std::cout << "INFO: forking the DKG/tDSS instance ..." << std::endl;
		fork_instance(peer2pipe[thispeer]);
	}
	else
	{
		std::cerr << "ERROR: not enough channels established" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}
}

void gnunet_init(void *cls)
{
	job = NULL;

	// wait until we got our own peer identity from TRANSPORT
	if (gh != NULL)
	{
		if (gnunet_opt_verbose)
			std::cerr << "waiting ..." << std::endl;
		sleep(1);
		job = GNUNET_SCHEDULER_add_now(&gnunet_init, NULL); // reschedule
		return;
	}

	// check whether own peer identity is included in peer list
	thispeer = GNUNET_i2s_full(&opi);
	if (gnunet_opt_verbose)
		std::cout << "INFO: my peer id = " << thispeer << std::endl;
	std::map<std::string, size_t>::const_iterator jt = peer2pipe.find(thispeer);
	if (jt == peer2pipe.end())
	{
		std::cerr << "ERROR: my peer id is not included in PEERS" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// open pipes to communicate with forked instance
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-gnunet-common (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-gnunet-common (pipe)");
		}
	}
	pipes_created = true;

	// next: schedule connect, fork and statistics tasks
	ct = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 1), &gnunet_connect, NULL);
	ft = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, gnunet_opt_wait), &gnunet_fork, NULL);
	st = GNUNET_SCHEDULER_add_now(&gnunet_statistics, NULL);
}

void gnunet_run(void *cls, char *const *args, const char *cfgfile,
	const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	// initialize peer2pipe and pipe2peer mapping
	for (size_t i = 0; i < peers.size(); i++)
	{
		peer2pipe[peers[i]] = i;
		pipe2peer[i] = peers[i];
	}

	// canonicalize CADET port string
	std::string port = "dkg-gnunet-common|";
	if (cls != NULL)
	{
		const char *last_slash = strrchr((const char*)cls, '/');
		if (last_slash != NULL)
			port += std::string((const char*)last_slash) + "|";
		else
			port += std::string((const char*)cls) + "|";
	}
	for (size_t i = 0; i < peers.size(); i++)
		port += peers[i] + "|";

	// add our shutdown task
	sd = GNUNET_SCHEDULER_add_shutdown(&gnunet_shutdown_task, NULL);

	// get our own peer identity
	gh = GNUNET_TRANSPORT_hello_get(cfg, GNUNET_TRANSPORT_AC_ANY, &gnunet_hello_callback, NULL);
	if (gh == NULL)
	{
		std::cerr << "ERROR: got no GNUnet hello callback handle" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// connect to CADET service
	if (gnunet_opt_verbose)
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to CADET service\n");
	mh = GNUNET_CADET_connect(cfg);	
	if (mh == NULL)
	{
		std::cerr << "ERROR: cannot connect to GNUnet CADET service" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// listen to a defined CADET port
	if (gnunet_opt_verbose)
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opening CADET listen port\n");
	if (gnunet_opt_port != NULL)
		GNUNET_CRYPTO_hash(gnunet_opt_port, strlen(gnunet_opt_port), &porthash);
	else
		GNUNET_CRYPTO_hash(port.c_str(), port.length(), &porthash);
	if (gnunet_opt_verbose)
		std::cout << "INFO: my CADET listen port hash = " << GNUNET_h2s_full(&porthash) << std::endl;
	static const struct GNUNET_MQ_MessageHandler handlers[] = {
		GNUNET_MQ_handler_end()
	};
	lp = GNUNET_CADET_open_port(mh, &porthash, &gnunet_channel_incoming, NULL, NULL, &gnunet_channel_ended, handlers);
	if (lp == NULL)
	{
		std::cerr << "ERROR: cannot open GNUnet CADET listen port" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// next: schedule initialization job
	job = GNUNET_SCHEDULER_add_now(&gnunet_init, NULL);
}

#endif

#endif


