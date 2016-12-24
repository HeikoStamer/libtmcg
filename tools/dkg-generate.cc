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
#include <libTMCG.hh>
#include <aiounicast_nonblock.hh>

#ifdef FORKING

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
//#include <gnunet/gnunet_peerinfo_service.h>
#include <gnunet/gnunet_transport_hello_service.h>
#include <gnunet/gnunet_cadet_service.h>
#undef HAVE_CONFIG_H
#endif

#include <sstream>
#include <fstream>
#include <vector>
#include <list>
#include <map>
#include <algorithm>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include "pipestream.hh"

#undef NDEBUG
#define MAX_N 1024

int				pipefd[MAX_N][MAX_N][2], broadcast_pipefd[MAX_N][MAX_N][2];
pid_t				pid[MAX_N];
size_t				N, T;
std::stringstream 		crs;
std::string			uid, passphrase;
std::vector<std::string>	peers;
bool				instance_forked = false;

void start_instance
	(const size_t whoami, std::istream &crs_in, const std::string u, const std::string pp, const time_t keytime)
{
	if ((pid[whoami] = fork()) < 0)
		perror("dkg-generate (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			
			// create pipe streams and handles for all players
			std::vector<ipipestream*> P_in;
			std::vector<opipestream*> P_out;
			std::vector<int> uP_in, uP_out, bP_in, bP_out;
			std::vector<std::string> uP_key, bP_key;
			for (size_t i = 0; i < N; i++)
			{
				std::stringstream key;
				key << "dkg-generate::P_" << (i + whoami); // choose a simple HMAC key
				P_in.push_back(new ipipestream(pipefd[i][whoami][0]));
				P_out.push_back(new opipestream(pipefd[whoami][i][1]));
				uP_in.push_back(pipefd[i][whoami][0]);
				uP_out.push_back(pipefd[whoami][i][1]);
				uP_key.push_back(key.str());
				bP_in.push_back(broadcast_pipefd[i][whoami][0]);
				bP_out.push_back(broadcast_pipefd[whoami][i][1]);
				bP_key.push_back(key.str());
			}
			
			// create VTMF instance
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crs_in);
			// check VTMF instance constructed from CRS (common reference string)
			if (!vtmf->CheckGroup())
			{
				std::cout << "P_" << whoami << ": " <<
					"Group G was not correctly generated!" << std::endl;
				exit(-1);
			}

			// create asynchronous authenticated unicast channels
			aiounicast_nonblock *aiou = new aiounicast_nonblock(N, whoami, uP_in, uP_out, uP_key);

			// create asynchronous authenticated unicast channels
			aiounicast_nonblock *aiou2 = new aiounicast_nonblock(N, whoami, bP_in, bP_out, bP_key);
			
			// create an instance of a reliable broadcast protocol (RBC)
			std::string myID = "dkg-generate";
			CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(N, T, whoami, aiou2);
			rbc->setID(myID);
			
			// create and exchange VTMF keys FIXME: async. operations needed; otherwise VTMF key could be stored in DHT 
			vtmf->KeyGenerationProtocol_GenerateKey();
			for (size_t i = 0; i < N; i++)
			{
				if (i != whoami)
					vtmf->KeyGenerationProtocol_PublishKey(*P_out[i]);
			}
			for (size_t i = 0; i < N; i++)
			{
				if (i != whoami)
				{
					if (!vtmf->KeyGenerationProtocol_UpdateKey(*P_in[i]))
					{
						std::cout << "P_" << whoami << ": " << "Public key of P_" <<
							i << " was not correctly generated!" << std::endl;
						exit(-1);
					}
				}
			}
			vtmf->KeyGenerationProtocol_Finalize();

			// create an instance of DKG
			GennaroJareckiKrawczykRabinDKG *dkg;
			std::cout << "GennaroJareckiKrawczykRabinDKG(" << N << ", " << T << ", " << whoami << ", ...)" << std::endl;
			dkg = new GennaroJareckiKrawczykRabinDKG(N, T, whoami,
				vtmf->p, vtmf->q, vtmf->g, vtmf->h);
			if (!dkg->CheckGroup())
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG parameters are not correctly generated!" << std::endl;
				exit(-1);
			}
			
			// generating $x$ and extracting $y = g^x \bmod p$
			std::stringstream err_log;
			std::cout << "P_" << whoami << ": dkg.Generate()" << std::endl;
			if (!dkg->Generate(aiou, rbc, err_log))
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG Generate() failed" << std::endl;
				std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();
				exit(-1);
			}
			std::cout << "P_" << whoami << ": log follows " << std::endl << err_log.str();

			// check the generated key share
			std::cout << "P_" << whoami << ": dkg.CheckKey()" << std::endl;
			if (!dkg->CheckKey())
			{
				std::cout << "P_" << whoami << ": " <<
					"DKG CheckKey() failed" << std::endl;
				exit(-1);
			}

			// at the end: deliver some more rounds for waiting parties
			mpz_t m;
			mpz_init(m);
			time_t start_time = time(NULL);
			while (time(NULL) < (start_time + 5))
				rbc->DeliverFrom(m, whoami);
			mpz_clear(m);

			// create an OpenPGP DSA-based primary key and Elgamal-based subkey based on parameters from DKG
			char buffer[2048];
			std::string out, crcout, armor;
			OCTETS all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
			OCTETS pub_hashing, sub_hashing;
			OCTETS uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
			OCTETS hash;
			time_t sigtime;
			gcry_sexp_t key;
			gcry_mpi_t p, q, g, y, x, r, s;
			gcry_error_t ret;
			size_t erroff;
			mpz_t dsa_y, dsa_x;
			mpz_init(dsa_y), mpz_init(dsa_x);
			mpz_srandomm(dsa_x, vtmf->q);
			mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
			
			p = gcry_mpi_new(2048);
			q = gcry_mpi_new(2048);
			g = gcry_mpi_new(2048);
			y = gcry_mpi_new(2048);
			x = gcry_mpi_new(2048);
			r = gcry_mpi_new(2048);
			s = gcry_mpi_new(2048);
				mpz_get_str(buffer, 16, vtmf->p);
				ret = gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret); 
				mpz_get_str(buffer, 16, vtmf->q);
				ret = gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret); 
				mpz_get_str(buffer, 16, vtmf->g);
				ret = gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
				mpz_get_str(buffer, 16, dsa_y);
				ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
				mpz_get_str(buffer, 16, dsa_x);
				ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			ret = gcry_sexp_build(&key, &erroff, "(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
				" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))", p, q, g, y, p, q, g, y, x);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(keytime, p, q, g, y, pub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(keytime, p, q, g, y, x, pp, sec);
			for (size_t i = 6; i < pub.size(); i++)
				pub_hashing.push_back(pub[i]);
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, uid);
			dsaflags.push_back(0x01 | 0x02 | 0x20);
			sigtime = time(NULL); // current time
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x13, sigtime, dsaflags, keyid, uidsig_hashing);
			CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, 8, hash, uidsig_left);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
			hash.clear();
				mpz_get_str(buffer, 16, dkg->y);			
				ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
				mpz_get_str(buffer, 16, dkg->z_i[dkg->i]);			
				ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
				assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(keytime, p, g, y, sub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(keytime, p, g, y, x, pp, ssb);
			elgflags.push_back(0x04 | 0x10);
			sigtime = time(NULL); // current time
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x18, sigtime, elgflags, keyid, subsig_hashing);
			for (size_t i = 6; i < sub.size(); i++)
				sub_hashing.push_back(sub[i]);
			CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, 8, hash, subsig_left);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
			// export generated public key in OpenPGP armor format
			std::stringstream pubfilename;
			pubfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				pubfilename << (int)keyid[i];
			pubfilename << "_dkg-pub.asc";
			armor = "", all.clear();
			all.insert(all.end(), pub.begin(), pub.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), sub.begin(), sub.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, all, armor);
			std::cout << armor << std::endl;
			std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
			pubofs << armor;
			pubofs.close();
			// export generated private key in OpenPGP armor format
			std::stringstream secfilename;
			secfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				secfilename << (int)keyid[i];
			secfilename << "_dkg-sec.asc";
			armor = "", all.clear();
			all.insert(all.end(), sec.begin(), sec.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), ssb.begin(), ssb.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
			std::cout << armor << std::endl;
			std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
			secofs << armor;
			secofs.close();
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			// export state of DKG including the secret shares into a file
			std::stringstream dkgfilename;
			dkgfilename << whoami << "_" << std::hex;
			for (size_t i = 0; i < keyid.size(); i++)
				dkgfilename << (int)keyid[i];
			dkgfilename << ".dkg";
			std::ofstream dkgofs((dkgfilename.str()).c_str(), std::ofstream::out);
			dkg->PublishState(dkgofs);
			dkgofs.close();

			// release DKG
			delete dkg;

			// release RBC			
			delete rbc;

			// release VTMF instances
			delete vtmf;
			
			// release pipe streams (private channels)
			size_t numRead = 0, numWrite = 0;
			for (size_t i = 0; i < N; i++)
			{
				numRead += P_in[i]->get_numRead() + P_out[i]->get_numRead();
				numWrite += P_in[i]->get_numWrite() + P_out[i]->get_numWrite();
				delete P_in[i], delete P_out[i];
			}
			std::cout << "P_" << whoami << ": numRead = " << numRead <<
				" numWrite = " << numWrite << std::endl;

			// release handles (unicast channel)
			uP_in.clear(), uP_out.clear(), uP_key.clear();
			std::cout << "P_" << whoami << ": aiou.numRead = " << aiou->numRead <<
				" aiou.numWrite = " << aiou->numWrite << std::endl;

			// release handles (broadcast channel)
			bP_in.clear(), bP_out.clear(), bP_key.clear();
			std::cout << "P_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
				" aiou2.numWrite = " << aiou2->numWrite << std::endl;

			// release asynchronous unicast and broadcast
			delete aiou, delete aiou2;
			
			std::cout << "P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
		}
		else
		{
			std::cout << "fork() = " << pid[whoami] << std::endl;
			instance_forked = true;
		}
	}
}

#ifdef GNUNET
#define GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST   10001
#define GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST 10002
static char *gnunet_opt_port = NULL;
static unsigned int gnunet_opt_t_resilience = 0;
static struct GNUNET_CADET_Handle *mh = NULL;
static struct GNUNET_CADET_TransmitHandle *th = NULL;
static struct GNUNET_CADET_Channel *th_ch = NULL;
static struct GNUNET_SCHEDULER_Task *th_at = NULL;
static size_t th_datalen = 0;
static struct GNUNET_NETWORK_FDSet *rs = NULL, *rs_broadcast = NULL;
static struct GNUNET_TRANSPORT_HelloGetHandle *gh = NULL;
static struct GNUNET_HELLO_Message *ohello = NULL;
static struct GNUNET_CADET_Port *lp = NULL;
static struct GNUNET_SCHEDULER_Task *sd = NULL;
static struct GNUNET_SCHEDULER_Task *st = NULL;
static struct GNUNET_SCHEDULER_Task *io = NULL;
static struct GNUNET_SCHEDULER_Task *ct = NULL;
static struct GNUNET_SCHEDULER_Task *pt = NULL, *pt_broadcast = NULL;
static struct GNUNET_SCHEDULER_Task *job = NULL;
static struct GNUNET_PeerIdentity opi;
static struct GNUNET_HashCode porthash;

static bool pipes_created = false;
static bool channels_created = false;
std::string thispeer;
std::map<std::string, size_t> peer2pipe;
std::map<size_t, std::string> pipe2peer;
std::map<size_t, GNUNET_PeerIdentity> pipe2peerid;
std::map<size_t, GNUNET_CADET_Channel*> pipe2channel_out, pipe2channel_in;
std::map<GNUNET_CADET_Channel*, bool> channel_ready;
typedef std::pair<size_t, char*>	DKG_Buffer;
typedef std::pair<size_t, DKG_Buffer>	DKG_BufferListEntry;
typedef std::list<DKG_BufferListEntry>	DKG_BufferList;
DKG_BufferList send_queue, send_queue_broadcast;

static void gnunet_hello_callback(void *cls, const struct GNUNET_MessageHeader *hello)
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

static int gnunet_data_callback(void *cls, struct GNUNET_CADET_Channel *channel,
	void **channel_ctx, const struct GNUNET_MessageHeader *message)
{
	int fd; 	
	uint16_t len;
	ssize_t rnum = 0;
 	const char *buf;
	std::string peer = "unknown";

	// check whether the used channel is (still) registered
	for (size_t i = 0; i < N; i++)
	{
		if ((pipe2channel_in.count(i) > 0) && (channel == pipe2channel_in[i]))
			peer = pipe2peer[i];
		if ((pipe2channel_out.count(i) > 0) && (channel == pipe2channel_out[i]))
			peer = pipe2peer[i];
	}
	if (peer == "unknown")
	{
		std::cerr << "WARNING: ignore incoming message from unregistered channel" << std::endl;
		return GNUNET_OK;
	}
	len = ntohs(message->size) - sizeof(*message);
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got message from %s with %u bytes\n", peer.c_str(), len);
	buf = (const char *)&message[1];
std::cerr << "message of type " << ntohs(message->type) << " from " << peer << " with " << len << " bytes received" << std::endl;
	// write the payload into corresponding pipe
	if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_UNICAST)
		fd = pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else if (ntohs(message->type) == GNUNET_MESSAGE_TYPE_LIBTMCG_DKG_GENERATE_PIPE_BROADCAST)
		fd = broadcast_pipefd[peer2pipe[peer]][peer2pipe[thispeer]][1];
	else
	{
		// ignore unknown types
		GNUNET_CADET_receive_done(channel);
		return GNUNET_OK;
	}

	do
	{
		ssize_t num = write(fd, buf, len - rnum);
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
				perror("dkg-generate (write)");
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

static void gnunet_io(void *cls);

static size_t gnunet_data_ready(void *cls, size_t size, void *buf)
{
//std::cerr << "data ready to send = " << size << std::endl;
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = true;
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
	DKG_BufferListEntry ble = send_queue.front();
	DKG_Buffer qbuf = ble.second;
	delete [] qbuf.second;
	send_queue.pop_front();
	if ((io == NULL) && (send_queue.size() || send_queue_broadcast.size()))
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
	return total_size;
}

static void gnunet_data_abort(void *cls)
{
	th_at = NULL;
	GNUNET_assert(th != NULL);
	GNUNET_assert(th_ch != NULL);
	GNUNET_CADET_notify_transmit_ready_cancel(th);
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = false;
	th = NULL, th_ch = NULL;
	// requeue buffered message at end
	DKG_BufferListEntry ble = send_queue.front();
	send_queue.pop_front();
	send_queue.push_back(ble);
}

static size_t gnunet_data_ready_broadcast(void *cls, size_t size, void *buf)
{
//std::cerr << "data ready to broadcast = " << size << std::endl;
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = true;
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
	DKG_BufferListEntry ble = send_queue_broadcast.front();
	DKG_Buffer qbuf = ble.second;
	delete [] qbuf.second;
	send_queue_broadcast.pop_front();
	if ((io == NULL) && (send_queue.size() || send_queue_broadcast.size()))
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
	return total_size;
}

static void gnunet_data_abort_broadcast(void *cls)
{
	th_at = NULL;
	GNUNET_assert(th != NULL);
	GNUNET_assert(th_ch != NULL);
	GNUNET_CADET_notify_transmit_ready_cancel(th);
	if (channel_ready.count(th_ch))
		channel_ready[th_ch] = false;
	th = NULL, th_ch = NULL;
	// requeue buffered message at end
	DKG_BufferListEntry ble = send_queue_broadcast.front();
	send_queue_broadcast.pop_front();
	send_queue_broadcast.push_back(ble);
}

static void gnunet_pipe_ready(void *cls)
{
	pt = NULL;

	for (size_t i = 0; i < N; i++)
	{
		if (i == peer2pipe[thispeer])
			continue; // ignore pipe of this peer FIXME: write directly back in ouput pipe
		if (GNUNET_NETWORK_fdset_test_native(rs, pipefd[peer2pipe[thispeer]][i][0]) == GNUNET_YES)
		{
			char *th_buf = new char[64000];
			ssize_t num = read(pipefd[peer2pipe[thispeer]][i][0], th_buf, 64000);
			if (num < 0)
			{
				delete [] th_buf;
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
				{
					continue;
				}
				else
				{
					perror("dkg-generate (read)");
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
std::cerr << "added i = " << i << " with " << num << " bytes" << std::endl;
				DKG_BufferListEntry ble = DKG_BufferListEntry(i, DKG_Buffer(num, th_buf));
				send_queue.push_back(ble);
			}
		}	
	}

	GNUNET_NETWORK_fdset_destroy(rs);
	// reschedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

static void gnunet_broadcast_pipe_ready(void *cls)
{
	pt_broadcast = NULL;

	for (size_t i = 0; i < N; i++)
	{
		if (i == peer2pipe[thispeer])
			continue; // ignore pipe of this peer FIXME: write directly back in ouput pipe
		if (GNUNET_NETWORK_fdset_test_native(rs, broadcast_pipefd[peer2pipe[thispeer]][i][0]) == GNUNET_YES)
		{
			char *th_buf = new char[64000];
			ssize_t num = read(broadcast_pipefd[peer2pipe[thispeer]][i][0], th_buf, 64000);
			if (num < 0)
			{
				delete [] th_buf;
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
				{
					continue;
				}
				else
				{
					perror("dkg-generate (read)");
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

	GNUNET_NETWORK_fdset_destroy(rs_broadcast);
	// reschedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

static void gnunet_channel_ended(void *cls, const struct GNUNET_CADET_Channel *channel,
	void *channel_ctx)
{
	GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "CADET channel ended!\n");
	// cancel pending transmission on this channel and abort task
	if ((th != NULL) && (th_at != NULL) && (channel == th_ch))
	{
		GNUNET_CADET_notify_transmit_ready_cancel(th);
		GNUNET_SCHEDULER_cancel(th_at);
		th = NULL, th_ch = NULL, th_at = NULL;
	}
	// deregister the ended channel	
	for (size_t i = 0; i < N; i++)
	{
		if ((pipe2channel_out.count(i) > 0) && (channel == pipe2channel_out[i]))
		{
			std::cerr << "WARNING: output channel ended for peer = " << pipe2peer[i] << std::endl;
			channel_ready.erase(pipe2channel_out[i]);
			pipe2channel_out.erase(i);
			return;
		}
		if ((pipe2channel_in.count(i) > 0) && (channel == pipe2channel_in[i]))
		{
			std::cerr << "WARNING: input channel ended for peer = " << pipe2peer[i] << std::endl;
			pipe2channel_in.erase(i);
			return;
		}
	}
	std::cerr << "WARNING: ended channel is not registered" << std::endl;
}

static void* gnunet_channel_incoming(void *cls, struct GNUNET_CADET_Channel *channel,
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
	if (!peer2pipe.count(peer))
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
		pipe2channel_in[peer2pipe[peer]] = channel;
	else
	{
		std::cerr << "WARNING: incoming channel already registered for this peer" << std::endl;
		GNUNET_CADET_channel_destroy(channel);
	}
	return NULL;
}

static void gnunet_shutdown_task(void *cls)
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
	for (size_t i = 0; ((i < N) && channels_created); i++)
	{
		if (i != peer2pipe[thispeer])
		{
			if (pipe2channel_out.count(i) > 0)
				GNUNET_CADET_channel_destroy(pipe2channel_out[i]);
			if (pipe2channel_in.count(i) > 0)
				GNUNET_CADET_channel_destroy(pipe2channel_in[i]);
		}
	}
	channels_created = false;
	// wait for forked instance and close pipes
	if (instance_forked)
	{
		std::cout << "kill(" << pid[peer2pipe[thispeer]] << ", SIGTERM)" << std::endl;
		if(kill(pid[peer2pipe[thispeer]], SIGTERM))
			perror("dkg-generate (kill)");
		std::cout << "waitpid(" << pid[peer2pipe[thispeer]] << ", NULL, 0)" << std::endl;
		if (waitpid(pid[peer2pipe[thispeer]], NULL, 0) != pid[peer2pipe[thispeer]])
			perror("dkg-generate (waitpid)");
		instance_forked = false;
	}
	for (size_t i = 0; ((i < N) && pipes_created); i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
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

static void gnunet_connect(void *cls);

static void gnunet_io(void *cls)
{
	io = NULL;

//std::cerr << "I/O task" << std::endl;
//sleep(1);

	// send messages to peers
	if ((th == NULL) && (th_at == NULL) && send_queue.size())
	{
		DKG_BufferListEntry ble = send_queue.front();
		DKG_Buffer buf = ble.second;
		if (((pipe2channel_out.count(ble.first) > 0) && channel_ready[pipe2channel_out[ble.first]]) || (pipe2channel_in.count(ble.first) > 0))
		{
			th_datalen = buf.first;
			if ((pipe2channel_out.count(ble.first) > 0) && channel_ready[pipe2channel_out[ble.first]])
			{
std::cerr << "try to send " << th_datalen << " bytes on output channel to " << pipe2peer[ble.first] << std::endl;
				th_ch = pipe2channel_out[ble.first];
			}
			else if (pipe2channel_in.count(ble.first) > 0)
			{
std::cerr << "try to send " << th_datalen << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
				th_ch = pipe2channel_in[ble.first];
			}
			th = GNUNET_CADET_notify_transmit_ready(th_ch, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
				sizeof(struct GNUNET_MessageHeader) + th_datalen, &gnunet_data_ready, buf.second);
			if (th == NULL)
			{
				std::cerr << "ERROR: cannot transmit data to peer = " << pipe2peer[ble.first] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			// schedule abort task
			th_at = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1), &gnunet_data_abort, NULL);
		}
	}

	// send broadcast messages to peers
	if ((th == NULL) && (th_at == NULL) && send_queue_broadcast.size())
	{
		DKG_BufferListEntry ble = send_queue_broadcast.front();
		DKG_Buffer buf = ble.second;
		if (((pipe2channel_out.count(ble.first) > 0) && channel_ready[pipe2channel_out[ble.first]]) || (pipe2channel_in.count(ble.first) > 0))
		{
			th_datalen = buf.first;
			if ((pipe2channel_out.count(ble.first) > 0) && channel_ready[pipe2channel_out[ble.first]])
			{
std::cerr << "try to broadcast " << th_datalen << " bytes on output channel to " << pipe2peer[ble.first] << std::endl;
				th_ch = pipe2channel_out[ble.first];
			}
			else if (pipe2channel_in.count(ble.first) > 0)
			{
std::cerr << "try to broadcast " << th_datalen << " bytes on input channel to " << pipe2peer[ble.first] << std::endl;
				th_ch = pipe2channel_in[ble.first];
			}
			th = GNUNET_CADET_notify_transmit_ready(th_ch, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
				sizeof(struct GNUNET_MessageHeader) + th_datalen, &gnunet_data_ready_broadcast, buf.second);
			if (th == NULL)
			{
				std::cerr << "ERROR: cannot transmit data to peer = " << pipe2peer[ble.first] << std::endl;
				GNUNET_SCHEDULER_shutdown();
				return;
			}
			// schedule cancel task
			th_at = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1), &gnunet_data_abort_broadcast, NULL);
		}
	}

	// schedule select tasks for reading the input pipes
	if (pt == NULL)
	{
		rs = GNUNET_NETWORK_fdset_create();
		for (size_t i = 0; i < N; i++)
			GNUNET_NETWORK_fdset_set_native(rs, pipefd[peer2pipe[thispeer]][i][0]);
		pt = GNUNET_SCHEDULER_add_select(GNUNET_SCHEDULER_PRIORITY_DEFAULT, GNUNET_TIME_UNIT_FOREVER_REL, rs, NULL,
			&gnunet_pipe_ready, NULL);
	}
	if (pt_broadcast == NULL)
	{
		rs_broadcast = GNUNET_NETWORK_fdset_create();
		for (size_t i = 0; i < N; i++)
			GNUNET_NETWORK_fdset_set_native(rs_broadcast, broadcast_pipefd[peer2pipe[thispeer]][i][0]);
		pt_broadcast = GNUNET_SCHEDULER_add_select(GNUNET_SCHEDULER_PRIORITY_DEFAULT, GNUNET_TIME_UNIT_FOREVER_REL, rs_broadcast, NULL,
			&gnunet_broadcast_pipe_ready, NULL);
	}

	// next: schedule (re)connect task
	if (ct == NULL)
		ct = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 1), &gnunet_connect, NULL);
}

static void gnunet_connect(void *cls)
{
	ct = NULL;
	for (size_t i = 0; i < N; i++)
	{
		bool stabilized;
		if (pipe2channel_out.count(i) == 0)
			stabilized = false;
		else
		{
			GNUNET_assert(channel_ready.count(pipe2channel_out[i]));
			stabilized = channel_ready[pipe2channel_out[i]];
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
				GNUNET_CADET_channel_destroy(pipe2channel_out[i]);
				channel_ready.erase(pipe2channel_out[i]);
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
				channel_ready[ch] = false;
			}
		}
	}
	channels_created = true;

	// next: schedule I/O task
	if (io == NULL)
		io = GNUNET_SCHEDULER_add_now(&gnunet_io, NULL);
}

static void gnunet_statistics(void *cls)
{
	st = NULL;
	size_t channel_ready_true = 0;
	for (std::map<GNUNET_CADET_Channel*, bool>::const_iterator it = channel_ready.begin(); it != channel_ready.end(); ++it)
		if ((*it).second == true)
			channel_ready_true++;
	std::cerr << "channel_ready_true = " << channel_ready_true << std::endl;
	std::cerr << "send_queue.size() = " << send_queue.size() << ", send_queue_broadcast.size() = " << send_queue_broadcast.size() << std::endl;
	// reschedule statistics task
	st = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 1), &gnunet_statistics, NULL);
}

static void gnunet_init(void *cls)
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
	std::map<std::string, size_t>::iterator jt = peer2pipe.find(thispeer);
	if (jt == peer2pipe.end())
	{
		std::cerr << "ERROR: my peer id is not included in PEERS" << std::endl;
		GNUNET_SCHEDULER_shutdown();
		return;
	}

	// open pipes to communicate with forked instance
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
		}
	}
	pipes_created = true;

	// fork instance
	time_t keytime = time(NULL); // current time
	start_instance(peer2pipe[thispeer], crs, uid, passphrase, keytime);

	// next: schedule connect and statistics tasks
	ct = GNUNET_SCHEDULER_add_now(&gnunet_connect, NULL);
	st = GNUNET_SCHEDULER_add_now(&gnunet_statistics, NULL);
}

static void gnunet_run(void *cls, char *const *args, const char *cfgfile,
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

int main
	(int argc, char *const *argv)
{
	// setup CRS (common reference string) |p| = 2048 bit, |q| = 256 bit
	crs << "W8o8gvA20jfDUDcVBS250oR0uObgSsG9Lwj7HekVkgjr0ZGOSfEqFLIUTqTXE"
		"pGbrYROsq0T0UMI4QWW89B8Xv0O8G9xoQfOn2yO1ZdqamWLMcOR0zYUSVdWh"
		"GntzQwshVR8rsqzditokxyshQTkQcZ2RSASrTXtT6J8MRqbzsjwZpCvSLh3k"
		"BwI3Gqn4d5MJeTFOEES9OnfCXJ8EBXBuKevdwF35HIB8ofPmoAuWgVupLniH"
		"xd2cdRcofthSvV5NNahjJXuVtNbiEveqrKwFh9mhJolPTleDLPb2Bz3Wqpu2"
		"RkpAKz7swD5vv2ImYtFH8d1sr1r1riyZJLjczmRu83T" << std::endl <<
		"fEor5mR9DcBxVvzojzYEqiCAzuzclIysxR1jlSS10i9" << std::endl <<
		"L98HZrvso7jiECZCUbqrNOlvjwJDeOfTJhOM6rl4k28XWfjC7XSOuuMuLfOt"
		"JzkkC9xU9BkhN3QZ8KPBBb8NrqmMzXdq2KX2spindKUt5qx3nnuyN2rgmyvr"
		"BoiJuQdFQ7s0iLjwesaKkfV9LmAheDIHtqrOShJS87W44cWebwSxeSMvDNsl"
		"rGBvdMM0ynEZxpeYaE7uqSHUV8IYNoKTZcLyzUneVO7idKUdHZt92LXQxUta"
		"xHP7cjdTv3eVRuipvrYxfRGqdjDlU20Z5xexzEUcG2ZATJyaBt82j9nf0boA"
		"VmYxD00mXDdHb2RWhfDCot5czPfueGK5BAfJPHcr6yLE" << std::endl <<
		"mK2zCAnD2Z0WqJ22yaIOLnO1zHU0BAgpVNX3XEUloWVKpfmDs5nVEJDSSDxz"
		"gEWV6V9YNYudvt819CLDytfNwfVkYiEtL0oOPeh9spw7q1dmy2Cqr687A2rj"
		"C0HPrQV3FwP27Lb5paPvipaGRPCngedxykaBK4WB52XoDF8FyogzF475EccG"
		"DeaaTRZmotj3HdiDsVO7Nb66Q8G6Wm1zwwrtEzLOXYKQBJZlwWKRqs23021j"
		"eVQRQ2I9exPnO1GYF8nigzAexQdBsmSAX8sNZsCuEK1htM0djsb0PmeGW6eY"
		"A" << std::endl;

#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		{'p', "port", NULL, "GNUnet cadet port to listen/connect",
			GNUNET_YES, &GNUNET_GETOPT_set_string, &gnunet_opt_port},
		{'t', "t-resilience", NULL, "t-resilience of DKG",
			GNUNET_YES, &GNUNET_GETOPT_set_uint, &gnunet_opt_t_resilience},
		GNUNET_GETOPT_OPTION_END
	};
#endif

	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (argc < 2)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << argv[0] << " [OPTIONS] PEERS" << std::endl;
		return -1;
	}
	else
	{
		// create peer list
		for (size_t i = 0; i < (size_t)(argc - 1); i++)
		{
			std::string arg = argv[i+1];
			// ignore options
			if ((arg.find("-c", 0) == 0) || (arg.find("-p", 0) == 0) || (arg.find("-t", 0) == 0) || (arg.find("-L", 0) == 0) || (arg.find("-l", 0) == 0))
			{
				i++;
				continue;
			}
			else if ((arg.find("--", 0) == 0) || (arg.find("-v", 0) == 0) || (arg.find("-h", 0) == 0))
				continue;
			else if (arg.find("-", 0) == 0)
			{
				std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
				return -1;
			}
			peers.push_back(arg);
		}
		// canonicalize peer list
		std::sort(peers.begin(), peers.end());
		std::vector<std::string>::iterator it = std::unique(peers.begin(), peers.end());
		peers.resize(std::distance(peers.begin(), it));
		N = peers.size();
		std::cout << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < N; i++)
			std::cout << peers[i] << std::endl;
	}
	if ((N < 4)  || (N > MAX_N))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	};

	T = (N / 3) - 1; // assume maximum asynchronous t-resilience
#ifdef GNUNET
	T = gnunet_opt_t_resilience; // get T from GNUnet options
#endif
	if (T == 0)
		T++; // RBC will not work with 0-resilience
	std::cout << "1. Please enter an OpenPGP-style user ID (name <email>): ";
	std::getline(std::cin, uid);
	std::cout << "2. Choose a passphrase to protect your private key: ";
	std::getline(std::cin, passphrase);

#ifdef GNUNET
	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
    		return -1;
	int ret = GNUNET_PROGRAM_run(argc, argv, "dkg-generate [OPTIONS] PEERS", "distributed ElGamal key generation with OpenPGP-output",
                            options, &gnunet_run, NULL);

	GNUNET_free ((void *) argv);

	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#endif

	// open pipes
	for (size_t i = 0; i < N; i++)
	{
		for (size_t j = 0; j < N; j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
				perror("dkg-generate (pipe)");
		}
	}
	
	// start childs
	time_t keytime = time(NULL); // current time
	for (size_t i = 0; i < N; i++)
		start_instance(i, crs, uid, passphrase, keytime);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < N; i++)
	{
		std::cerr << "waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], NULL, 0) != pid[i])
			perror("dkg-generate (waitpid)");
		for (size_t j = 0; j < N; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("dkg-generate (close)");
		}
	}
	
	return 0;
}

#else

int main
	(int argc, char **argv)
{
	std::cout << "fork(2) needed" << std::endl;
	return 77;
}

#endif
