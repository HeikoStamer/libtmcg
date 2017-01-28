/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.cc,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     [CKPS01] Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

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
#include "CachinKursawePetzoldShoupSEABP.hh"

CachinKursawePetzoldShoupRBC::CachinKursawePetzoldShoupRBC
	(const size_t n_in, const size_t t_in, const size_t j_in,
	aiounicast *aiou_in, const size_t aio_default_scheduler_in,
	const time_t aio_default_timeout_in)
{
	assert(t_in <= n_in);
	assert(j_in < n_in);

	// initialize basic parameters
	n = n_in, t = t_in, j = j_in;

	// checking maximum asynchronous t-resilience
	if ((3 * t) >= n)
		std::cerr << "RBC(" << j << ") WARNING: maximum asynchronous t-resilience exceeded" << std::endl;
	// checking minimum number of parties
	if (n < 2)
		std::cerr << "RBC(" << j << ") WARNING: more than one party needed; RBC will not work" << std::endl;

	// initialize asynchonous unicast
	aio_default_scheduler = aio_default_scheduler_in;
	aio_default_timeout = aio_default_timeout_in;
	aiou = aiou_in;

	// initialize ID
	mpz_init_set_ui(ID, 0L);

	// initialize whoami (this variable is called $j$ in the paper)
	mpz_init_set_ui(whoami, j);

	// initialize sequence counter
	mpz_init_set_ui(s, 0L);

	// initialize message action types
	mpz_init_set_ui(r_send, 1L);
	mpz_init_set_ui(r_echo, 2L);
	mpz_init_set_ui(r_ready, 3L);
	mpz_init_set_ui(r_request, 4L);
	mpz_init_set_ui(r_answer, 5L);

	// initialize message counters
	for (size_t i = 0; i < n; i++)
	{
		RBC_TagCheck *mtmp = new RBC_TagCheck;
		send.push_back(*mtmp);
		RBC_TagCheck *mtmp2 = new RBC_TagCheck;
		echo.push_back(*mtmp2);
		RBC_TagCheck *mtmp3 = new RBC_TagCheck;
		ready.push_back(*mtmp3);
		RBC_TagCheck *mtmp4 = new RBC_TagCheck;
		request.push_back(*mtmp4);
		RBC_TagCheck *mtmp5 = new RBC_TagCheck;
		answer.push_back(*mtmp5);
	}

	// initialize message and deliver buffers
	for (size_t i = 0; i < n; i++)
	{
		RBC_BufferList *ltmp = new RBC_BufferList;
		buf_mpz.push_back(*ltmp);
		RBC_BufferList *ltmp2 = new RBC_BufferList;
		buf_msg.push_back(*ltmp2);
		deliver_error.push_back(false);
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, 1L); // initialize sequence counter by 1
		deliver_s.push_back(tmp);
	}
}

void CachinKursawePetzoldShoupRBC::setID
	(const std::string ID_in)
{
	// save the last ID
	mpz_ptr tmp = new mpz_t();
	mpz_init_set(tmp, ID);
	last_IDs.push_back(tmp);

	// set new ID
	std::stringstream myID;
	myID << "CachinKursawePetzoldShoupRBC called from [" << ID_in << "] with last ID = " << ID;
	mpz_shash(ID, myID.str());
}

void CachinKursawePetzoldShoupRBC::unsetID
	()
{
	// set last ID
	if (last_IDs.size() > 0)
	{
		mpz_ptr tmp = last_IDs.back();
		mpz_set(ID, tmp);
		mpz_clear(tmp);
		delete [] tmp;
		last_IDs.pop_back();
	}
	else
		mpz_set_ui(ID, 0L);
}

void CachinKursawePetzoldShoupRBC::Broadcast
	(mpz_srcptr m, const bool simulate_faulty_behaviour)
{
	mpz_add_ui(s, s, 1L); // increase sequence counter

	// prepare message $(ID.j.s, r-send, m)$
	RBC_ConstMessage message;
	message.push_back(ID);
	message.push_back(whoami);
	message.push_back(s);
	message.push_back(r_send);
	message.push_back(m);

	// send message to all parties (zero timeout)
	for (size_t i = 0; i < n; i++)
	{
		size_t simulate_faulty_randomizer = mpz_wrandom_ui() % n;
		if (simulate_faulty_behaviour)
			mpz_add_ui((mpz_ptr)message[4], (mpz_ptr)message[4], 1L);
		if (simulate_faulty_behaviour && !simulate_faulty_randomizer)
			aiou->Send(message, mpz_wrandom_ui() % n, 0);
		else
		{
			if (!aiou->Send(message, i, 0))
				std::cerr << "RBC(" << j << "): sending r-send failed for " << i << std::endl;
		}
	}

	// release message
	message.clear();
}

bool CachinKursawePetzoldShoupRBC::Deliver
	(mpz_ptr m, size_t &i_out,
	size_t scheduler, time_t timeout)
{
	// set aio default values
	if (scheduler == aiounicast::aio_scheduler_default)
		scheduler = aio_default_scheduler;
	if (timeout == aiounicast::aio_timeout_default)
		timeout = aio_default_timeout;
	// prepare foo and tag
	mpz_t foo, tag;
	mpz_init(foo), mpz_init(tag);
	// prepare message $(ID.j.s, action, m)$
	RBC_Message message;
	for (size_t mm = 0; mm < 5; mm++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		message.push_back(tmp);
	}
	// process messages according to the RBC protocol of [CKPS01] extended with a FIFO-ordered deliver strategy
	try
	{
		time_t entry_time = time(NULL);
		do
		{
			for (size_t rounds = 0; rounds < (((t + 2) * n * n * n) + n); rounds++)
			{
				// first, process the delivery buffer
				for (std::list<RBC_Message>::iterator lit = deliver_buf.begin(); lit != deliver_buf.end(); ++lit)
				{
					// compute hash of identifying tag $ID.j.s$
					mpz_shash(tag, 3, (*lit)[0], (*lit)[1], (*lit)[2]);
					std::stringstream tag_ss;
					tag_ss << tag;
					std::string tag_string = tag_ss.str();
					size_t who = mpz_get_ui((*lit)[1]);
					// check for matching tag and sequence counter before delivering
					if (!mpz_cmp((*lit)[0], ID) && !mpz_cmp((*lit)[2], deliver_s[who]))
					{
						assert(mbar.count(tag_string));
						mpz_set(m, mbar[tag_string]);
//std::cerr << "RBC: restores deliver from " << who << " m = " << m << std::endl;
						mpz_add_ui(deliver_s[who], deliver_s[who], 1L); // increase sequence counter
						i_out = who;
						for (size_t mm = 0; mm < lit->size(); mm++)
						{
							mpz_clear((*lit)[mm]);
							delete [] (*lit)[mm];
						}
						lit->clear();
						deliver_buf.erase(lit);
						throw true;
					}
				}
				size_t l = n;
				// second, anything buffered from previous calls/rounds?
				for (size_t i = 0; i < n; i++)
				{
					if (buf_msg[i].size() >= message.size())
					{
						for (size_t mm = 0; mm < message.size(); mm++)
						{
							mpz_set(message[mm], buf_msg[i].front());
							mpz_clear(buf_msg[i].front());
							delete [] buf_msg[i].front();
							buf_msg[i].pop_front();
						}
						l = i;
						break;
					}
				}
				// third, nothing buffered
				if (l == n)
				{
					// receive a message from an arbitrary party $P_l$ (given scheduler, zero timeout)
					if (!aiou->Receive(message, l, scheduler, 0))
					{
if (l < n)
std::cerr << "RBC(" << j << "): error in Receive(l) = " << l << std::endl;
						continue; // next round
					}
				}
				// compute hash of identifying tag $ID.j.s$
				mpz_shash(tag, 3, message[0], message[1], message[2]);
				std::stringstream tag_ss;
				tag_ss << tag;
				std::string tag_string = tag_ss.str();

				// discard misformed messages
				if ((mpz_cmp_ui(message[1], (n - 1)) > 0) || (mpz_cmp_ui(message[1], 0) < 0))
				{
					std::cerr << "RBC(" << j << "): wrong j in tag from " << l << std::endl;
					continue;
				}
				if (mpz_cmp_ui(message[2], 1L) < 0)
				{
					std::cerr << "RBC(" << j << "): wrong s in tag from " << l << std::endl;
					continue;
				}
				if ((mpz_cmp(message[3], r_send) < 0) || (mpz_cmp(message[3], r_answer) > 0))
				{
					std::cerr << "RBC(" << j << "): wrong action in tag from " << l << std::endl;
					continue;
				}

				// upon receiving message $(ID.j.s, r-send, m)$ from $P_l$
				if (!mpz_cmp(message[3], r_send) && !send[l].count(tag_string))
				{
//std::cerr << "RBC: r-send from " << l << " with m = " << message[4] << std::endl;
					send[l].insert(std::pair<std::string, bool>(tag_string, true));
					if (!mpz_cmp_ui(message[1], l) && (mbar.count(tag_string) == 0))
					{
						mpz_ptr tmp = new mpz_t();
						mpz_init_set(tmp, message[4]); // $\bar{m} \gets m$
						mbar.insert(std::pair<std::string, mpz_ptr>(tag_string, tmp));
						// prepare message $(ID.j.s, r-echo, H(m))$
						RBC_ConstMessage message2;
						message2.push_back(message[0]);
						message2.push_back(message[1]);
						message2.push_back(message[2]);
						message2.push_back(r_echo);
						mpz_shash(message[4], 1, tmp);
						message2.push_back(message[4]);
						// send to all parties by unicast transmission (zero timeout)
						for (size_t i = 0; i < n; i++)
						{
							if (!aiou->Send(message2, i, 0))
								std::cerr << "RBC(" << j << "): sending r-echo failed for " << i << std::endl;
						}
						message2.clear();
					}
					continue;
				}
				else if (!mpz_cmp(message[3], r_send) && send[l].count(tag_string))
					std::cerr << "RBC(" << j << "): received r-send for same tag more than once from " << l << std::endl;
				// upon receiving message $(ID.j.s, r-echo, d)$ from $P_l$
				if (!mpz_cmp(message[3], r_echo) && !echo[l].count(tag_string))
				{
//std::cerr << "RBC: r-echo from " << l << " with d = " << message[4] << std::endl;
					echo[l].insert(std::pair<std::string, bool>(tag_string, true));
					std::stringstream d_ss;
					d_ss << message[4];
					std::string d_string = d_ss.str();
					if (e_d.find(tag_string) == e_d.end())
					{
						RBC_TagCount *mmm = new RBC_TagCount;
						e_d.insert(std::pair<std::string, RBC_TagCount >(tag_string, *mmm));
					}
					RBC_TagCount::iterator eit = e_d[tag_string].find(d_string);
					if (eit == e_d[tag_string].end())
						eit = (e_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 1))).first;
					else
						(*eit).second++;
					if (r_d.find(tag_string) == r_d.end())
					{
						RBC_TagCount *mmm = new RBC_TagCount;
						r_d.insert(std::pair<std::string, RBC_TagCount >(tag_string, *mmm));
					}
					RBC_TagCount::iterator rit = r_d[tag_string].find(d_string);
					if (rit == r_d[tag_string].end())
						rit = (r_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 0))).first;
					if (((*eit).second == (n - t)) && ((*rit).second <= t))
					{
						// prepare message $(ID.j.s, r-ready, d)$
						RBC_ConstMessage message2;
						message2.push_back(message[0]);
						message2.push_back(message[1]);
						message2.push_back(message[2]);
						message2.push_back(r_ready);
						message2.push_back(message[4]);
						// send to all parties by unicast transmission (zero timeout)
						for (size_t i = 0; i < n; i++)
						{
							if (!aiou->Send(message2, i, 0))
								std::cerr << "RBC(" << j << "): sending r-ready failed for " << i << std::endl;
						}
						message2.clear();
					}
					continue;
				}
				else if (!mpz_cmp(message[3], r_echo) && echo[l].count(tag_string))
					std::cerr << "RBC(" << j << "): received r-echo for same tag more than once from " << l << std::endl;
				// upon receiving message $(ID.j.s, r-ready, d)$ from $P_l$
				if (!mpz_cmp(message[3], r_ready) && !ready[l].count(tag_string))
				{
//std::cerr << "RBC: r-ready from " << l << " with d = " << message[4] << std::endl;
					ready[l].insert(std::pair<std::string, bool>(tag_string, true));
					std::stringstream d_ss;
					d_ss << message[4];
					std::string d_string = d_ss.str();
					if (e_d.find(tag_string) == e_d.end())
					{
						RBC_TagCount *mmm = new RBC_TagCount;
						e_d.insert(std::pair<std::string, RBC_TagCount>(tag_string, *mmm));
					}
					if (r_d.find(tag_string) == r_d.end())
					{
						RBC_TagCount *mmm = new RBC_TagCount;
						r_d.insert(std::pair<std::string, RBC_TagCount>(tag_string, *mmm));
					}
					RBC_TagCount::iterator rit = r_d[tag_string].find(d_string);
					if (rit == r_d[tag_string].end())
						rit = (r_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 1))).first;
					else
						(*rit).second++;
					RBC_TagCount::iterator eit = e_d[tag_string].find(d_string);
					if (eit == e_d[tag_string].end())
						eit = (e_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 0))).first;
//std::cerr << "RBC: r_d = " << (*rit).second << " e_d = " << (*eit).second << std::endl;
					if (((*rit).second == (t + 1)) && ((*eit).second < (n - t)))
					{
						// prepare message $(ID.j.s, r-ready, d)$
						RBC_ConstMessage message2;
						message2.push_back(message[0]);
						message2.push_back(message[1]);
						message2.push_back(message[2]);
						message2.push_back(r_ready);
						message2.push_back(message[4]);
						// send to all parties by unicast transmission (zero timeout)
						for (size_t i = 0; i < n; i++)
						{
							if (!aiou->Send(message2, i, 0))
								std::cerr << "RBC(" << j << "): sending r-ready failed for " << i << std::endl;
						}
						message2.clear();
					}
					else if ((*rit).second == ((2 * t) + 1))
					{
						mpz_ptr tmp = new mpz_t();
						mpz_init_set(tmp, message[4]); // $\bar{d} \gets d$
						dbar.insert(std::pair<std::string, mpz_ptr>(tag_string, tmp));
						if (mbar.count(tag_string) > 0)
							mpz_shash(foo, 1, mbar[tag_string]);
						else
						{
							mpz_set_ui(foo, 0L);
//std::cerr << "RBC: r-send not received yet for this tag by " << j << std::endl;
						}
						if (mpz_cmp(foo, message[4])) // $H(\bar{m}) \neq \bar{d}$
						{
							// prepare message $(ID.j.s, r-request)$
							RBC_ConstMessage message2;
							message2.push_back(message[0]);
							message2.push_back(message[1]);
							message2.push_back(message[2]);
							message2.push_back(r_request);
							message2.push_back(message[4]);
							// send to some parties by unicast transmission (zero timeout)
							for (size_t i = 0; i < ((2 * t) + 1); i++)
							{
								if (!aiou->Send(message2, i, 0))
									std::cerr << "RBC(" << j << "): sending r-request failed for " << i << std::endl;
							}
							message2.clear();
							// wait for a message $(ID.j.s, r_answer, m)$
							do
							{
								// prepare
								RBC_Message message3;
								for (size_t mm = 0; mm < 5; mm++)
								{
									mpz_ptr tmp = new mpz_t();
									mpz_init(tmp);
									message3.push_back(tmp);
								}
								// receive an answer from an arbitrary party (given scheduler, zero timeout)
								size_t l2;
								if (aiou->Receive(message3, l2, scheduler, 0))
								{
									// compute hash of identifying tag $ID.j.s$
									mpz_shash(tag, 3, message3[0], message3[1], message3[2]);
									std::stringstream tag3_ss;
									tag3_ss << tag;
									std::string tag3_string = tag3_ss.str();
									if ((tag_string != tag3_string) || mpz_cmp(message3[3], r_answer))
									{
										// store message for later processing
										for (size_t mm = 0; mm < message3.size(); mm++)
											buf_msg[l2].push_back(message3[mm]);
										continue;
									}
									else if (!answer[l2].count(tag_string)) // for the first time?
									{
//std::cerr << "RBC: r-answer from " << l2 << " for " << j << " with m = " << message3[4] << std::endl;
										answer[l2].insert(std::pair<std::string, bool>(tag_string, true));
										mpz_shash(foo, 1, message3[4]); // compute $H(m)$
										if (mbar.count(tag_string) == 0)
										{
											mpz_ptr tmp = new mpz_t();
											mpz_init(tmp);
											mbar.insert(std::pair<std::string, mpz_ptr>(tag_string, tmp));
										}
										mpz_set(mbar[tag_string], message3[4]); // $\bar{m} \gets m$
									}
									else
										std::cerr << "RBC(" << j << "): this should never happen" << std::endl;
								}
								else
								{
if (l2 < n)
std::cerr << "RBC(" << j << "): error in Receive(l2) = " << l2 << std::endl;
								}
								// release
								for (size_t mm = 0; mm < message3.size(); mm++)
								{
									mpz_clear(message3[mm]);
									delete [] message3[mm];
								}
								message3.clear();
							}
							while (mpz_cmp(foo, message[4]) && (time(NULL) < (entry_time + aiounicast::aio_timeout_very_long)));
							if (mpz_cmp(foo, message[4])) // still $H(\bar{m}) \neq \bar{d}$
								break; // no correct r-answer received and timeout exceeded
						}
//std::cerr << "RBC: deliver from " << mpz_get_ui(message[1]) << " m = " << mbar[tag_string] << std::endl;
						size_t who = mpz_get_ui(message[1]);
						// check for matching tag and sequence counter before delivering
						if (!mpz_cmp(message[0], ID) && !mpz_cmp(message[2], deliver_s[who]))
						{
							assert(mbar.count(tag_string));
							mpz_set(m, mbar[tag_string]);
							mpz_add_ui(deliver_s[who], deliver_s[who], 1L); // increase sequence counter
							i_out = who;
							throw true;
						}
						else
						{
							// buffer the message for later delivery
							RBC_Message *vtmp = new RBC_Message;
							for (size_t mm = 0; mm < 5; mm++)
							{
								mpz_ptr tmp = new mpz_t();
								mpz_init_set(tmp, message[mm]);
								vtmp->push_back(tmp);
							}
							deliver_buf.push_back(*vtmp);
//std::cerr << "RBC: P_" << j << " buffers deliver from " << who << " m = " << mbar[tag_string] << std::endl;
						}
						continue;
					}
					continue;
				}
				else if (!mpz_cmp(message[3], r_ready) && ready[l].count(tag_string))
					std::cerr << "RBC(" << j << "): received r-ready for same tag more than once from " << l << std::endl;
				// upon receiving message $(ID.j.s, r-request) from $P_l$ for the first time
				if (!mpz_cmp(message[3], r_request) && !request[l].count(tag_string))
				{
//std::cerr << "RBC: r-request from " << l << std::endl;
					request[l].insert(std::pair<std::string, bool>(tag_string, true));
					if (mbar.find(tag_string) != mbar.end())
					{
						// prepare message $(ID.j.s, r-answer, \bar{m})$
						RBC_ConstMessage message2;
						message2.push_back(message[0]);
						message2.push_back(message[1]);
						message2.push_back(message[2]);
						message2.push_back(r_answer);
						message2.push_back(mbar[tag_string]);
						// send only to requesting party by unicast transmission (zero timeout)
						if (!aiou->Send(message2, l, 0))
							std::cerr << "RBC(" << j << "): sending r-answer failed for " << l << std::endl;
						message2.clear();
					}
					continue;
				}
				else if (!mpz_cmp(message[3], r_request) && request[l].count(tag_string))
					std::cerr << "RBC(" << j << "): received r-request for same tag more than once from " << l << std::endl;
				if (mpz_cmp(message[3], r_answer))
					std::cerr << "RBC(" << j << "): discard message of action = " << message[3] << " from " << l << std::endl;
			}
		}
		while (time(NULL) < (entry_time + timeout));
		i_out = n; // timeout for all parties
		throw false;
	}
	catch (bool return_value)
	{
		// release foo and tag
		mpz_clear(foo), mpz_clear(tag);
		// release message
		for (size_t mm = 0; mm < message.size(); mm++)
		{
			mpz_clear(message[mm]);
			delete [] message[mm];
		}
		message.clear();
		// return
		return return_value;
	}
}

bool CachinKursawePetzoldShoupRBC::DeliverFrom
	(mpz_ptr m, const size_t i_in,
	size_t scheduler, time_t timeout)
{
	// set aio default values
	if (scheduler == aiounicast::aio_scheduler_default)
		scheduler = aio_default_scheduler;
	if (timeout == aiounicast::aio_timeout_default)
		timeout = aio_default_timeout;
//std::cerr << "RBC(" << j << "): want mpz from " << i_in << std::endl;
	time_t entry_time = time(NULL);
	do
	{
		// anything buffered?
		if (buf_mpz[i_in].size() > 0)
		{
			mpz_set(m, buf_mpz[i_in].front());
			mpz_clear(buf_mpz[i_in].front());
			delete [] buf_mpz[i_in].front();
			buf_mpz[i_in].pop_front();
//std::cerr << "RBC(" << j << "): got buffered mpz from " << i_in << std::endl;
			return true;
		}
		else
		{
			// store mpz in corresponding buffer
			size_t l;
			mpz_ptr tmp = new mpz_t();
			mpz_init(tmp);
			if (Deliver(tmp, l, scheduler, 0))
			{
//std::cerr << "RBC(" << j << "): got mpz from " << l << std::endl;
				buf_mpz[l].push_back(tmp);
				if (l == i_in)
					continue;
			}
			else
			{
				mpz_clear(tmp);
				delete [] tmp;
			}
		}
	}
	while (time(NULL) < (entry_time + timeout));
	if (i_in != j)
		std::cerr << "RBC(" << j << "): timeout delivering from " << i_in << std::endl;
	return false;
}

CachinKursawePetzoldShoupRBC::~CachinKursawePetzoldShoupRBC
	()
{
	mpz_clear(ID), mpz_clear(whoami), mpz_clear(s);
	for (RBC_BufferList::iterator lit = last_IDs.begin(); lit != last_IDs.end(); ++lit)
	{
		mpz_clear(*lit);
		delete [] *lit;
	}
	last_IDs.clear();
	mpz_clear(r_send);
	mpz_clear(r_echo);
	mpz_clear(r_ready);
	mpz_clear(r_request);
	mpz_clear(r_answer);
	for (size_t i = 0; i < n; i++)
	{
		send[i].clear();
		echo[i].clear();
		ready[i].clear();
		request[i].clear();
		answer[i].clear();
	}
	send.clear(), echo.clear(), ready.clear(), request.clear(), answer.clear();
	for (RBC_TagMpz::iterator mit = mbar.begin(); mit != mbar.end(); ++mit)
	{
		mpz_clear((*mit).second);
		delete [] (*mit).second;
	}
	for (RBC_TagMpz::iterator mit = dbar.begin(); mit != dbar.end(); ++mit)
	{
		mpz_clear((*mit).second);
		delete [] (*mit).second;
	}
	mbar.clear(), dbar.clear();
	for (std::map<std::string, RBC_TagCount>::iterator mit = e_d.begin(); mit != e_d.end(); ++mit)
	{
		((*mit).second).clear();
	}
	for (std::map<std::string, RBC_TagCount>::iterator mit = r_d.begin(); mit != r_d.end(); ++mit)
	{
		((*mit).second).clear();
	}	
	e_d.clear(), r_d.clear();
	for (size_t i = 0; i < n; i++)
	{
		for (RBC_BufferList::iterator lit = buf_mpz[i].begin(); lit != buf_mpz[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete [] *lit;
		}
		buf_mpz[i].clear();
		for (RBC_BufferList::iterator lit = buf_msg[i].begin(); lit != buf_msg[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete [] *lit;
		}
		buf_msg[i].clear();
		mpz_clear(deliver_s[i]);
		delete [] deliver_s[i];
	}
	buf_mpz.clear(), buf_msg.clear();
	for (std::list<RBC_Message>::iterator lit = deliver_buf.begin(); lit != deliver_buf.end(); ++lit)
	{
		for (RBC_Message::iterator vit = lit->begin(); vit != lit->end(); ++vit)
		{
			mpz_clear(*vit);
			delete [] *vit;
		}
		lit->clear();
	}	
	deliver_error.clear(), deliver_buf.clear(), deliver_s.clear();
}

