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

extern void fork_instance(const size_t whoami);

#ifdef GNUNET

typedef std::pair<size_t, char*>	DKG_Buffer;
typedef std::pair<size_t, DKG_Buffer>	DKG_BufferListEntry;
typedef std::list<DKG_BufferListEntry>	DKG_BufferList;
DKG_BufferList				send_queue, send_queue_broadcast;

extern char				*gnunet_opt_port;

#define GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_CHANNEL_CHECK  10000
#define GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST   10001
#define GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST 10002

static struct GNUNET_CADET_Handle		*mh = NULL;
static struct GNUNET_CADET_TransmitHandle	*th = NULL;
static struct GNUNET_CADET_Channel		*th_ch = NULL;
static struct GNUNET_SCHEDULER_Task		*th_at = NULL;
static size_t 					th_datalen = 0;
static struct GNUNET_TRANSPORT_HelloGetHandle	*gh = NULL;
static struct GNUNET_HELLO_Message 		*ohello = NULL;
static struct GNUNET_CADET_Port 		*lp = NULL;
static struct GNUNET_SCHEDULER_Task 		*sd = NULL;
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
std::map<size_t, GNUNET_PeerIdentity> 		pipe2peerid;
std::map<size_t, GNUNET_CADET_Channel*> 	pipe2channel_out;
std::map<size_t, GNUNET_CADET_Channel*> 	pipe2channel_in;
std::map<GNUNET_CADET_Channel*, bool> 		channel_ready;

void gnunet_hello_callback(void *cls, const struct GNUNET_MessageHeader *hello)
{
	if (hello == NULL)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No hello message in callback\n");
		GNUNET_SCHEDULER_shutdown();
		return;
	}
	ohello = (struct GNUNET_HELLO_Message *) GNUNET_copy_message(hello);
	if (GNUNET_HELLO_get_id(ohello, &opi) != GNUNET_OK)
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "GNUNET_HELLO_get_id() failed\n");
		GNUNET_SCHEDULER_shutdown();
		return;
	}
	GNUNET_TRANSPORT_hello_get_cancel(gh);
	gh = NULL;
}

int gnunet_data_callback(void *cls, struct GNUNET_CADET_Channel *channel,
	void **channel_ctx, const struct GNUNET_MessageHeader *message)
{
	int fd;
	uint16_t len = 0, cnt = 0;
	ssize_t rnum = 0;
 	const char *buf;	
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
		return GNUNET_OK;
	}
	else if (cnt > 1)
	{
		std::cerr << "ERROR: this channel is registered more than once" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return GNUNET_SYSERR;
	}
	else
	{
		if (channel_ready.count(channel))
			channel_ready[channel] = true; // mark this channel as okay
	}
	GNUNET_assert(ntohs(message->size) >= sizeof(*message));
	len = ntohs(message->size) - sizeof(*message);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got message from %s with %u bytes\n", peer.c_str(), len);
	buf = (const char *)&message[1];
//std::cerr << "message of type " << ntohs(message->type) << " from " << peer << " with " << len << " bytes received" << std::endl;
	// write the payload into corresponding pipe
	if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST)
		fd = pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST)
		fd = broadcast_pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else
	{
		// ignore unknown message types including channel check message
		GNUNET_CADET_receive_done(channel);
		return GNUNET_OK;
	}
	GNUNET_assert(buf != NULL);
	do
	{
		ssize_t num = write(fd, buf + rnum, len - rnum);
		if (num < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
			{
				std::cerr << "sleeping ..." << std::endl;
				sleep(1);
				continue;
			}
			else
			{
				perror("dkg-gnunet-common (write)");
				GNUNET_SCHEDULER_shutdown();
				return GNUNET_SYSERR;
			}
		}
		else
			rnum += num;
	}
	while (rnum < len);

	// ready for receiving next message on this channel
	GNUNET_CADET_receive_done(channel);
	return GNUNET_OK;
}

size_t gnunet_channel_check_ready(void *cls, size_t size, void *buf)
{
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = true; // mark this channel as okay
	th = NULL, th_ch = NULL;
	if ((buf == NULL) || (size == 0))
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No message to transmit\n");
		GNUNET_SCHEDULER_shutdown();
		return 0;
	}
	struct GNUNET_MessageHeader *msg;
	size_t total_size = th_datalen + sizeof(struct GNUNET_MessageHeader);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "sending %u bytes\n", (unsigned int)th_datalen);
	GNUNET_assert(size >= total_size);
	msg = (struct GNUNET_MessageHeader*)buf;
	msg->size = htons(total_size);
	msg->type = htons(GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_CHANNEL_CHECK);
	GNUNET_memcpy(&msg[1], cls, th_datalen);
	// cancel abort task
	GNUNET_assert(th_at != NULL);
	GNUNET_SCHEDULER_cancel(th_at);
	th_at = NULL;
	// reschedule I/O task for next channel check
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
	return total_size;
}

void gnunet_channel_check_abort(void *cls)
{
std::cerr << "channel check abort called" << std::endl;
	th_at = NULL;
	GNUNET_assert(th != NULL);
	GNUNET_assert(th_ch != NULL);
	GNUNET_CADET_notify_transmit_ready_cancel(th);
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = false; // mark this channel as bad
	th = NULL, th_ch = NULL;
}

size_t gnunet_data_ready(void *cls, size_t size, void *buf)
{
//std::cerr << "data ready to send = " << size << std::endl;
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = true; // mark this channel as okay
	th = NULL, th_ch = NULL;
	if ((buf == NULL) || (size == 0))
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No message to transmit\n");
		GNUNET_SCHEDULER_shutdown();
		return 0;
	}
	struct GNUNET_MessageHeader *msg;
	size_t total_size = th_datalen + sizeof(struct GNUNET_MessageHeader);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "sending %u bytes\n", (unsigned int)th_datalen);
	GNUNET_assert(size >= total_size);
	msg = (struct GNUNET_MessageHeader*)buf;
	msg->size = htons(total_size);
	msg->type = htons(GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST);
	GNUNET_memcpy(&msg[1], cls, th_datalen);
	// cancel abort task
	GNUNET_assert(th_at != NULL);
	GNUNET_SCHEDULER_cancel(th_at);
	th_at = NULL;
	// release buffered message and reschedule I/O task, if further messages available
	GNUNET_assert(send_queue.size());
	DKG_BufferListEntry ble = send_queue.front();
	DKG_Buffer qbuf = ble.second;
	delete [] qbuf.second;
	send_queue.pop_front();
	if ((io == NULL) && (send_queue.size() || send_queue_broadcast.size()))
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
	return total_size;
}

void gnunet_data_abort(void *cls)
{
std::cerr << "abort task called" << std::endl;
	th_at = NULL;
	GNUNET_assert(th != NULL);
	GNUNET_assert(th_ch != NULL);
	GNUNET_CADET_notify_transmit_ready_cancel(th);
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = false; // mark this channel as bad
	th = NULL, th_ch = NULL;
	// requeue buffered message at end
	GNUNET_assert(send_queue.size());
	DKG_BufferListEntry ble = send_queue.front();
	send_queue.pop_front();
	send_queue.push_back(ble);
}

size_t gnunet_data_ready_broadcast(void *cls, size_t size, void *buf)
{
//std::cerr << "data ready to broadcast = " << size << std::endl;
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = true; // mark this channel as okay
	th = NULL, th_ch = NULL;
	if ((buf == NULL) || (size == 0))
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No message to transmit\n");
		GNUNET_SCHEDULER_shutdown();
		return 0;
	}
	struct GNUNET_MessageHeader *msg;
	size_t total_size = th_datalen + sizeof(struct GNUNET_MessageHeader);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "sending %u bytes\n", (unsigned int)th_datalen);
	GNUNET_assert(size >= total_size);
	msg = (struct GNUNET_MessageHeader*)buf;
	msg->size = htons(total_size);
	msg->type = htons(GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST);
	GNUNET_memcpy(&msg[1], cls, th_datalen);
	// cancel abort task
	GNUNET_assert(th_at != NULL);
	GNUNET_SCHEDULER_cancel(th_at);
	th_at = NULL;	
	// release buffered message and reschedule I/O task, if further messages available
	GNUNET_assert(send_queue_broadcast.size());
	DKG_BufferListEntry ble = send_queue_broadcast.front();
	DKG_Buffer qbuf = ble.second;
	delete [] qbuf.second;
	send_queue_broadcast.pop_front();
	if ((io == NULL) && (send_queue.size() || send_queue_broadcast.size()))
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
	return total_size;
}

void gnunet_data_abort_broadcast(void *cls)
{
std::cerr << "abort broadcast task called" << std::endl;
	th_at = NULL;
	GNUNET_assert(th != NULL);
	GNUNET_assert(th_ch != NULL);
	GNUNET_CADET_notify_transmit_ready_cancel(th);
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = false; // mark this channel as bad
	th = NULL, th_ch = NULL;
	// requeue buffered message at end
	GNUNET_assert(send_queue_broadcast.size());
	DKG_BufferListEntry ble = send_queue_broadcast.front();
	send_queue_broadcast.pop_front();
	send_queue_broadcast.push_back(ble);
}

void gnunet_pipe_ready(void *cls)
{
	pt = NULL;
	for (size_t i = 0; i < peers.size(); i++)
	{
		char *th_buf = new char[4096];
		ssize_t num = read(pipefd[peer2pipe[thispeer]][i][0], th_buf, 4096);
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
			if (i == peer2pipe[thispeer])
			{
std::cerr << "self: " << num << std::endl;
				delete [] th_buf;
				continue; // ignore pipe of this peer FIXME: write directly back into pipe
			}
			else
			{
//std::cerr << "queue added i = " << i << " with " << num << " bytes" << std::endl;
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
		char *th_buf = new char[4096];
		ssize_t num = read(broadcast_pipefd[peer2pipe[thispeer]][i][0], th_buf, 4096);
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
			if (i == peer2pipe[thispeer])
			{
std::cerr << "self broadcast: " << num << std::endl;
				delete [] th_buf;
				continue; // ignore pipe of this peer FIXME: write directly back into pipe
			}
			else
			{
//std::cerr << "queue added broadcast i = " << i << " with " << num << " bytes" << std::endl;
				DKG_BufferListEntry ble = DKG_BufferListEntry(i, DKG_Buffer(num, th_buf));
				send_queue_broadcast.push_back(ble);
			}
		}
	}
	// reschedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

void gnunet_channel_ended(void *cls, const struct GNUNET_CADET_Channel *channel,
	void *channel_ctx)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "CADET channel ended!\n");
	// cancel pending transmission on this channel and abort task
	if ((th != NULL) && (th_at != NULL) && (th_ch == channel))
	{
		GNUNET_CADET_notify_transmit_ready_cancel(th);
		GNUNET_SCHEDULER_cancel(th_at);
		th = NULL, th_at = NULL, th_ch = NULL;
	}
	// deregister the ended channel	
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (pipe2channel_out.count(i) && (pipe2channel_out[i] == channel))
		{
			std::cerr << "WARNING: output channel ended for peer = " << pipe2peer[i] << std::endl;
			channel_ready.erase(pipe2channel_out[i]);
			pipe2channel_out.erase(i);
			return;
		}
		if (pipe2channel_in.count(i) && (pipe2channel_in[i] == channel))
		{
			std::cerr << "WARNING: input channel ended for peer = " << pipe2peer[i] << std::endl;
			channel_ready.erase(pipe2channel_in[i]);
			pipe2channel_in.erase(i);
			return;
		}
	}
	std::cerr << "WARNING: ended channel is not registered" << std::endl;
}

void* gnunet_channel_incoming(void *cls, struct GNUNET_CADET_Channel *channel,
	const struct GNUNET_PeerIdentity *initiator, const struct GNUNET_HashCode *port,
	enum GNUNET_CADET_ChannelOption options)
{
	GNUNET_log(GNUNET_ERROR_TYPE_MESSAGE, "Connected from %s\n", GNUNET_i2s_full(initiator));
	GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Incoming channel %p on port %s\n", channel, GNUNET_h2s(port));
	if (GNUNET_CRYPTO_hash_cmp(&porthash, port))
	{
		GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Not listening to this port\n");
		GNUNET_SCHEDULER_shutdown();
		return NULL;
	}
	// check whether peer identity is included in peer list
	std::string peer = GNUNET_i2s_full(initiator);
	if (peer2pipe.count(peer) == 0)
	{
		std::cerr << "WARNING: incoming channel from peer not included in PEERS" << std::endl;
		GNUNET_CADET_channel_destroy(channel);
		return NULL;
	}
	// check whether channel is reliable
	if (options != GNUNET_CADET_OPTION_RELIABLE)
	{
		std::cerr << "WARNING: incoming channel is not reliable" << std::endl;
		GNUNET_CADET_channel_destroy(channel);
		return NULL;
	}
	// register this channel
	if (pipe2channel_in.count(peer2pipe[peer]) == 0)
	{
		pipe2channel_in[peer2pipe[peer]] = channel;
		channel_ready[channel] = false; // mark this channel initially as bad until we receive data
	}
	else
	{
		std::cerr << "WARNING: incoming channel already registered for this peer" << std::endl;
	}
	return NULL;
}

void gnunet_shutdown_task(void *cls)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
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
	if (job != NULL)
	{
		GNUNET_SCHEDULER_cancel(job);
		job = NULL;
	}
	if (th != NULL)
	{
		GNUNET_CADET_notify_transmit_ready_cancel(th);
		th = NULL, th_ch = NULL;
	}
	if (th_at != NULL)
	{
		GNUNET_SCHEDULER_cancel(th_at);
		th_at = NULL;
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
		std::cout << "kill(" << pid[peer2pipe[thispeer]] << ", SIGTERM)" << std::endl;
		if(kill(pid[peer2pipe[thispeer]], SIGTERM))
			perror("dkg-gnunet-common (kill)");
		std::cout << "waitpid(" << pid[peer2pipe[thispeer]] << ", NULL, 0)" << std::endl;
		if (waitpid(pid[peer2pipe[thispeer]], NULL, 0) != pid[peer2pipe[thispeer]])
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
	// FIXME: I guess this is not correct. However, otherwise the program
	//        does not terminate, if GNUnet services are not running.
	exit(-1);
}

void gnunet_io(void *cls)
{
	io = NULL;

	// FIXME: We need a short pause here, otherwise GNUnet CADET will be disrupted.
	sleep(1);

	// send messages to peers
	if ((th == NULL) && (th_at == NULL) && send_queue.size())
	{
		DKG_BufferListEntry ble = send_queue.front();
		DKG_Buffer buf = ble.second;
		if (pipe2channel_in.count(ble.first)) // have input channel to this peer?
		{
			th_datalen = buf.first;
std::cerr << "try to send " << th_datalen << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
			th_ch = pipe2channel_in[ble.first];
			th = GNUNET_CADET_notify_transmit_ready(th_ch, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
				sizeof(struct GNUNET_MessageHeader) + th_datalen, &gnunet_data_ready, buf.second);
			if (th == NULL)
			{
				std::cerr << "ERROR: cannot transmit data to peer = " << pipe2peer[ble.first] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			// schedule abort task
			th_at = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, aiounicast::aio_timeout_middle),
				&gnunet_data_abort, NULL);
		}
	}

	// send broadcast messages to peers
	if ((th == NULL) && (th_at == NULL) && send_queue_broadcast.size())
	{
		DKG_BufferListEntry ble = send_queue_broadcast.front();
		DKG_Buffer buf = ble.second;
		if (pipe2channel_in.count(ble.first)) // have input channel to this peer?
		{
			th_datalen = buf.first;
std::cerr << "try to broadcast " << th_datalen << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
			th_ch = pipe2channel_in[ble.first];
			th = GNUNET_CADET_notify_transmit_ready(th_ch, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
				sizeof(struct GNUNET_MessageHeader) + th_datalen, &gnunet_data_ready_broadcast, buf.second);
			if (th == NULL)
			{
				std::cerr << "ERROR: cannot transmit data to peer = " << pipe2peer[ble.first] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			// schedule abort task
			th_at = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, aiounicast::aio_timeout_middle),
				&gnunet_data_abort_broadcast, NULL);
		}
	}

	// send channel check messages on output channel
	if ((th == NULL) && (th_at == NULL))
	{
		size_t i = mpz_wrandom_mod(peers.size());
		if (pipe2channel_out.count(i))
		{
			char buf[2];
			memset(buf, 0, sizeof(buf));
			th_datalen = 2;
std::cerr << "try to send channel check on output channel to " << i << std::endl;
			th_ch = pipe2channel_out[i];
			th = GNUNET_CADET_notify_transmit_ready(th_ch, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
				sizeof(struct GNUNET_MessageHeader) + th_datalen, &gnunet_channel_check_ready, buf);
			if (th == NULL)
			{
				std::cerr << "ERROR: cannot transmit data to peer = " << pipe2peer[i] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			// schedule abort task
			th_at = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, aiounicast::aio_timeout_short),
				&gnunet_channel_check_abort, NULL);

		}
	}

	// schedule select tasks for reading the input pipes
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
		bool stabilized;
		if (pipe2channel_out.count(i) == 0)
			stabilized = false;
		else
		{
			GNUNET_assert(channel_ready.count(pipe2channel_out[i]));
			stabilized = channel_ready[pipe2channel_out[i]];
			channel_ready[pipe2channel_out[i]] = false; // mark this channel again as bad until we can send data
		}
		if ((i != peer2pipe[thispeer]) && !stabilized)
		{
			// destroy old CADET output channels
			if (pipe2channel_out.count(i))
			{
				// cancel pending transmission and abort task
				if ((th != NULL) && (th_at != NULL) && (th_ch == pipe2channel_out[i]))
				{
					GNUNET_CADET_notify_transmit_ready_cancel(th);
					GNUNET_SCHEDULER_cancel(th_at);
					th = NULL, th_ch = NULL, th_at = NULL;
				}
				channel_ready.erase(pipe2channel_out[i]);
				GNUNET_CADET_channel_destroy(pipe2channel_out[i]);
			}
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
			GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to `%s'\n", pipe2peer[i].c_str());
			ch = GNUNET_CADET_channel_create(mh, NULL, &pid, &porthash, flags);
			if (ch == NULL)
			{
				std::cerr << "ERROR: cannot create channel to peer = " << pipe2peer[i] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			else
			{
				pipe2channel_out[i] = ch;
				channel_ready[ch] = false; // mark this channel initially as bad until we are ready to send data
			}
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
	size_t channel_ready_true = 0;
	for (std::map<GNUNET_CADET_Channel*, bool>::const_iterator it = channel_ready.begin(); it != channel_ready.end(); ++it)
		if ((*it).second == true)
			channel_ready_true++;
	std::cerr << "pipe2channel_out.size() = " << pipe2channel_out.size() << ", pipe2channel_in.size() = " << pipe2channel_in.size() << std::endl;
	std::cerr << "channel_ready_true = " << channel_ready_true << std::endl;
	std::cerr << "send_queue.size() = " << send_queue.size() << ", send_queue_broadcast.size() = " << send_queue_broadcast.size() << std::endl;
	// reschedule statistics task
	st = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 45), &gnunet_statistics, NULL);
}

void gnunet_init(void *cls)
{
	job = NULL;

	// wait until we got our own peer identity from TRANSPORT
	if (gh != NULL)
	{
		std::cerr << "waiting ..." << std::endl;
		sleep(1);
		job = GNUNET_SCHEDULER_add_now(&gnunet_init, NULL); // reschedule
		return;
	}

	// check whether own peer identity is included in peer list
	thispeer = GNUNET_i2s_full(&opi);
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

	// fork instance
	fork_instance(peer2pipe[thispeer]);

	// next: schedule connect and statistics tasks
	ct = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 1), &gnunet_connect, NULL);
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

	// add our shutdown task
	sd = GNUNET_SCHEDULER_add_shutdown(&gnunet_shutdown_task, NULL);

	// get our own peer identity
	gh = GNUNET_TRANSPORT_hello_get(cfg, GNUNET_TRANSPORT_AC_ANY, &gnunet_hello_callback, NULL);
	if (gh == NULL)
	{
		std::cerr << "ERROR: no GNUnet hello callback handle" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// connect to CADET service
	static const struct GNUNET_CADET_MessageHandler handlers[] = {
		{&gnunet_data_callback, GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_CHANNEL_CHECK, 0},
		{&gnunet_data_callback, GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST, 0},
		{&gnunet_data_callback, GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST, 0},
		{NULL, 0, 0}
	};
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to CADET service\n");
	mh = GNUNET_CADET_connect(cfg, NULL, &gnunet_channel_ended, handlers);
	if (mh == NULL)
	{
		std::cerr << "ERROR: cannot connect to GNUnet CADET service" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// listen to a defined CADET port
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opening CADET listen port\n");
	if (gnunet_opt_port != NULL)
		GNUNET_CRYPTO_hash(gnunet_opt_port, strlen(gnunet_opt_port), &porthash);
	else
		GNUNET_CRYPTO_hash("42742", 5, &porthash); // set our default port
	lp = GNUNET_CADET_open_port(mh, &porthash, &gnunet_channel_incoming, NULL);
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


