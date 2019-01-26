/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.cc,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     [CKPS01] Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

// additional headers
#include <iostream>
#include <sstream>
#include <utility>
#include <algorithm>
#include <stdexcept>
#include "mpz_srandom.hh"
#include "mpz_helper.hh"
#include "mpz_shash.hh"
#include "aiounicast.hh"

CachinKursawePetzoldShoupRBC::CachinKursawePetzoldShoupRBC
	(const size_t n_in, const size_t t_in, const size_t j_in,
	aiounicast *aiou_in, const size_t scheduler_in,
	const time_t timeout_in):
		aio_timeout_vs(aiou_in->aio_timeout_very_short) // timeout for sending
{
	if (t_in > n_in)
		throw std::invalid_argument("RBC: t > n");
	if (j_in >= n_in)
		throw std::invalid_argument("RBC: j >= n");

	// initialize basic parameters
	n = n_in, t = t_in, j = j_in;

	// checking maximum asynchronous t-resilience
	if ((3 * t) >= n)
	{
		std::cerr << "RBC(" << j << ") WARNING: maximum asynchronous " <<
			"t-resilience exceeded" << std::endl;
	}
	// checking minimum number of parties
	if (n < 2)
	{
		std::cerr << "RBC(" << j << ") WARNING: more than one party needed; " <<
			"RBC will not work" << std::endl;
		throw std::invalid_argument("RBC: n < 2");
	}

	// initialize asynchonous unicast
	aio_default_scheduler = scheduler_in;
	aio_default_timeout = timeout_in;
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
	send.resize(n);
	echo.resize(n);
	ready.resize(n);
	request.resize(n);
	answer.resize(n);

	// initialize message and deliver buffers
	buf_mpz.resize(n);
	buf_id.resize(n);
	buf_msg.resize(n);
	for (size_t i = 0; i < n; i++)
	{
		deliver_error.push_back(false);
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, 1L); // initialize sequence counter by 1
		deliver_s.push_back(tmp);
	}
}

void CachinKursawePetzoldShoupRBC::setID
	(const std::string &ID_in)
{
	// save the last ID
	mpz_ptr tmp1 = new mpz_t();
	mpz_init_set(tmp1, ID);
	last_IDs.push_back(tmp1);

	// save the last sequence counter
	mpz_ptr tmp2 = new mpz_t();
	mpz_init_set(tmp2, s);
	last_s.push_back(tmp2);

	// save deliver sequence counters
	last_deliver_s.resize(last_deliver_s.size() + 1);
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp3 = new mpz_t();
		mpz_init_set(tmp3, deliver_s[i]);
		(last_deliver_s.back()).push_back(tmp3);
	}

	// set new ID
	std::stringstream myID;
	myID << "CachinKursawePetzoldShoupRBC called from [" << ID_in << "]" <<
		" with last ID = " << ID;
	tmcg_mpz_shash(ID, myID.str());

	// reset sequence counter
	mpz_set_ui(s, 0L);

	// reset deliver sequence counters
	for (size_t i = 0; i < n; i++)
		mpz_set_ui(deliver_s[i], 1L);
}

void CachinKursawePetzoldShoupRBC::unsetID
	()
{
	// set last ID
	if (!last_IDs.empty())
	{
		mpz_ptr tmp = last_IDs.back();
		mpz_set(ID, tmp);
		mpz_clear(tmp);
		delete [] tmp;
		last_IDs.pop_back();
	}
	else
		mpz_set_ui(ID, 0L);

	// set last sequence counter
	if (!last_s.empty())
	{
		mpz_ptr tmp = last_s.back();
		mpz_set(s, tmp);
		mpz_clear(tmp);
		delete [] tmp;
		last_s.pop_back();
	}
	else
		mpz_set_ui(s, 0L);

	// set last deliver sequence counters
	if (!last_deliver_s.empty())
	{
		std::vector<mpz_ptr> vtmp = last_deliver_s.back();
		for (size_t i = 0; i < n; i++)
		{
			mpz_set(deliver_s[i], vtmp[i]);
			mpz_clear(vtmp[i]);
			delete [] vtmp[i];
		}
		last_deliver_s.pop_back();
	}
	else
	{
		for (size_t i = 0; i < n; i++)
			mpz_set_ui(deliver_s[i], 1L);
	}
}

void CachinKursawePetzoldShoupRBC::InitializeMessage
	(RBC_Message &message)
{
	for (size_t mm = 0; mm < 5; mm++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		message.push_back(tmp);
	}
}

void CachinKursawePetzoldShoupRBC::InitializeMessage
	(RBC_Message &message, const RBC_ConstMessage &source)
{
	if (source.size() != 5)
		throw std::invalid_argument("RBC::InitializeMessage(): bad message");
	InitializeMessage(message);
	for (size_t mm = 0; mm < source.size(); mm++)
		mpz_set(message[mm], source[mm]);
}

void CachinKursawePetzoldShoupRBC::InitializeMessage
	(RBC_Message &message, const RBC_Message &source)
{
	if (source.size() != 5)
		throw std::invalid_argument("RBC::InitializeMessage(): bad message");
	InitializeMessage(message);
	for (size_t mm = 0; mm < source.size(); mm++)
		mpz_set(message[mm], source[mm]);
}

void CachinKursawePetzoldShoupRBC::AssignMessage
	(RBC_ConstMessage &message, const RBC_Message &source)
{
	if (source.size() != 5)
		throw std::invalid_argument("RBC::AssignMessage(): bad message");
	message.clear();
	for (size_t mm = 0; mm < source.size(); mm++)
		message.push_back(source[mm]);
}

void CachinKursawePetzoldShoupRBC::TagMessage
	(std::string &tag, const RBC_Message &message)
{
	if (message.size() != 5)
		throw std::invalid_argument("RBC::TagMessage(): bad message");
	mpz_t tag_val;
	mpz_init(tag_val);
	tmcg_mpz_shash(tag_val, 3, message[0], message[1], message[2]);
	std::stringstream tag_ss;
	tag_ss << tag_val;
	tag = tag_ss.str();
	mpz_clear(tag_val);
}

void CachinKursawePetzoldShoupRBC::ReleaseMessage
	(RBC_Message &message)
{
	for (size_t mm = 0; mm < message.size(); mm++)
	{
		mpz_clear(message[mm]);
		delete [] message[mm];
	}
	message.clear();
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

	// initialize and copy the prepared message
	RBC_Message modified_message;
	InitializeMessage(modified_message, message);

	// send message to all parties (very short timeout)
	for (size_t i = 0; i < n; i++)
	{
		size_t simulate_faulty_randomizer = tmcg_mpz_wrandom_ui() % n; // p. 1/n
		size_t simulate_faulty_randomizer1 = tmcg_mpz_wrandom_ui() % 2;
		size_t simulate_faulty_randomizer2 = tmcg_mpz_wrandom_ui() % 2;
		size_t simulate_faulty_randomizer3 = tmcg_mpz_wrandom_ui() % 2;
		if (simulate_faulty_behaviour && !simulate_faulty_randomizer &&
			simulate_faulty_randomizer1)
		{
			mpz_add_ui(modified_message[4],
				modified_message[4], 1L); // modify the message
		}
		if (simulate_faulty_behaviour && !simulate_faulty_randomizer &&
			simulate_faulty_randomizer2)
		{
			mpz_add_ui(modified_message[1], modified_message[1],
				tmcg_mpz_wrandom_ui() % n); // modify the sender
		}
		AssignMessage(message, modified_message); // assign the modified message
		if (simulate_faulty_behaviour && !simulate_faulty_randomizer &&
			simulate_faulty_randomizer3)
		{
			if (!aiou->Send(message, tmcg_mpz_wrandom_ui() % n, aio_timeout_vs))
			{
				std::cerr << "RBC(" << j << "): sending r-send failed for " <<
					"random party" << std::endl;
			}
		}
		else
		{
			if (!aiou->Send(message, i, aio_timeout_vs))
			{
				std::cerr << "RBC(" << j << "): sending r-send failed for " <<
					i << std::endl;
			}
		}
	}

	// release message
	ReleaseMessage(modified_message);
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
	// initialize foo
	mpz_t foo;
	mpz_init(foo);
	// initialize message $(ID.j.s, action, m)$
	RBC_Message message;
	InitializeMessage(message);
	// process messages according to the RBC protocol described in [CKPS01]
	// extended with a simple FIFO-order deliver mechanism
	time_t entry_time = time(NULL);
	do
	{
		// first, process the delivery buffer
		for (RBC_VectorList::iterator lit = deliver_buf.begin();
			lit != deliver_buf.end(); ++lit)
		{
			// compute hash of identifying tag $ID.j.s$
			std::string tag;
			TagMessage(tag, *lit);
			size_t who = mpz_get_ui((*lit)[1]);
			// check for matching tag and sequence counter before delivering
			if (!mpz_cmp((*lit)[0], ID) && !mpz_cmp((*lit)[2], deliver_s[who]))
			{
				if (mbar.count(tag) == 0)
					throw std::runtime_error("RBC::Deliver(): no mbar found");
				mpz_set(m, mbar[tag]);
//std::cerr << "RBC: restores deliver from " << who << " m = " << m << std::endl;
				// increase sequence counter
				mpz_add_ui(deliver_s[who], deliver_s[who], 1L);
				i_out = who;
				ReleaseMessage(*lit);
				deliver_buf.erase(lit);
				// release foo
				mpz_clear(foo);
				// release message
				ReleaseMessage(message);
				return true;
			}
		}
		// second, anything buffered from previous calls/rounds?
		size_t l = n;
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
		// third, receive message, if nothing else is buffered
		if (l == n)
		{
			// receive a message from an arbitrary party $P_l$
			if (!aiou->Receive(message, l, scheduler, 0))
				continue; // next round
		}
		// compute hash of identifying tag $ID.j.s$
		std::string tag;
		TagMessage(tag, message);

		// discard and report misformed messages
		if ((mpz_cmp_ui(message[1], (n - 1)) > 0) ||
			(mpz_cmp_ui(message[1], 0) < 0))
		{
			std::cerr << "RBC(" << j << "): wrong j in tag from " << l <<
				std::endl;
			continue;
		}
		if (mpz_cmp_ui(message[2], 1L) < 0)
		{
			std::cerr << "RBC(" << j << "): wrong s in tag from " << l <<
				std::endl;
			continue;
		}
		if ((mpz_cmp(message[3], r_send) < 0) ||
			(mpz_cmp(message[3], r_answer) > 0))
		{
			std::cerr << "RBC(" << j << "): wrong action in tag from " << l <<
				std::endl;
			continue;
		}

		// upon receiving message $(ID.j.s, r-send, m)$ from $P_l$
		if (!mpz_cmp(message[3], r_send) && !send[l].count(tag))
		{
			send[l].insert(std::pair<std::string, bool>(tag, true));
			if (mpz_cmp_ui(message[1], l))
			{
				std::cerr << "RBC(" << j << "): received wrong r-send" <<
					" message of " << message[1] << " from " << l << std::endl;
			}
			else
			{
				if (mbar.count(tag) == 0)
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init_set(tmp, message[4]); // $\bar{m} \gets m$
					mbar.insert(std::pair<std::string, mpz_ptr>(tag, tmp));
				}
				else if (mpz_cmp(mbar[tag], message[4]))
				{
					std::cerr << "RBC(" << j << "): received bad r-send" <<
						" message from " << l << std::endl;
					continue;
				}
				// prepare message $(ID.j.s, r-echo, H(m))$
				RBC_ConstMessage message2;
				message2.push_back(message[0]);
				message2.push_back(message[1]);
				message2.push_back(message[2]);
				message2.push_back(r_echo);
				tmcg_mpz_shash(message[4], 1, message[4]);
				message2.push_back(message[4]);
				// send to all parties by unicast transmission (very short timeout)
				for (size_t i = 0; i < n; i++)
				{
					if (!aiou->Send(message2, i, aio_timeout_vs))
					{
						std::cerr << "RBC(" << j << "): sending r-echo" <<
							" failed for " << i << std::endl;
					}
				}
				message2.clear();
			}
			continue;
		}
		else if (!mpz_cmp(message[3], r_send) && send[l].count(tag))
		{
			std::cerr << "RBC(" << j << "): received r-send for same tag" <<
				" more than once from " << l << std::endl;
		}
		// upon receiving message $(ID.j.s, r-echo, d)$ from $P_l$
		if (!mpz_cmp(message[3], r_echo) && !echo[l].count(tag))
		{
//std::cerr << "RBC: r-echo from " << l << " with d = " << message[4] << std::endl;
			std::stringstream d_ss;
			d_ss << message[4];
			std::string d_string = d_ss.str();
			if (d_string.length() > (2 * tag.length()))
			{
				std::cerr << "RBC(" << j << "): size of d exceeded in r-echo" <<
					" from " << l << std::endl;
				continue;
			}
			echo[l].insert(std::pair<std::string, bool>(tag, true));
			if (e_d.find(tag) == e_d.end())
			{
				RBC_TagCount mmm;
				e_d.insert(std::pair<std::string, RBC_TagCount>(tag, mmm));
			}
			RBC_TagCount::iterator eit = e_d[tag].find(d_string);
			if (eit == e_d[tag].end())
			{
				eit = (e_d[tag].insert(
					std::pair<std::string, size_t>(d_string, 1))).first; // = 1
			}
			else
				(*eit).second++;
			if (r_d.find(tag) == r_d.end())
			{
				RBC_TagCount mmm;
				r_d.insert(std::pair<std::string, RBC_TagCount>(tag, mmm));
			}
			RBC_TagCount::iterator rit = r_d[tag].find(d_string);
			if (rit == r_d[tag].end())
			{
				rit = (r_d[tag].insert(
					std::pair<std::string, size_t>(d_string, 0))).first; // = 0
			}
//std::cerr << "RBC: [" << tag << "] r-echo-branch with r_d = " << (*rit).second << " e_d = " << (*eit).second << std::endl;
			if (((*eit).second == (n - t)) && ((*rit).second <= t))
			{
//std::cerr << "RBC(" << j << "): [" << tag << "] send r-ready message" << std::endl;
				// prepare message $(ID.j.s, r-ready, d)$
				RBC_ConstMessage message2;
				message2.push_back(message[0]);
				message2.push_back(message[1]);
				message2.push_back(message[2]);
				message2.push_back(r_ready);
				message2.push_back(message[4]);
				// send to all parties by unicast transmission (very short timeout)
				for (size_t i = 0; i < n; i++)
				{
					if (!aiou->Send(message2, i, aio_timeout_vs))
					{
						std::cerr << "RBC(" << j << "): sending r-ready" <<
							" failed for " << i << std::endl;
					}
				}
				message2.clear();
			}
			continue;
		}
		else if (!mpz_cmp(message[3], r_echo) && echo[l].count(tag))
		{
			std::cerr << "RBC(" << j << "): received r-echo for same tag" <<
				" more than once from " << l << std::endl;
		}
		// upon receiving message $(ID.j.s, r-ready, d)$ from $P_l$
		if (!mpz_cmp(message[3], r_ready) && !ready[l].count(tag))
		{
//std::cerr << "RBC: r-ready from " << l << " with d = " << message[4] << std::endl;
			std::stringstream d_ss;
			d_ss << message[4];
			std::string d_string = d_ss.str();
			if (d_string.length() > (2 * tag.length()))
			{
				std::cerr << "RBC(" << j << "): size of d exceeded in" <<
					" r-ready from " << l << std::endl;
				continue;
			}
			ready[l].insert(std::pair<std::string, bool>(tag, true));
			if (e_d.find(tag) == e_d.end())
			{
				RBC_TagCount mmm;
				e_d.insert(std::pair<std::string, RBC_TagCount>(tag, mmm));
			}
			if (r_d.find(tag) == r_d.end())
			{
				RBC_TagCount mmm;
				r_d.insert(std::pair<std::string, RBC_TagCount>(tag, mmm));
			}
			RBC_TagCount::iterator rit = r_d[tag].find(d_string);
			if (rit == r_d[tag].end())
			{
				rit = (r_d[tag].insert(
					std::pair<std::string, size_t>(d_string, 1))).first; // = 1
			}
			else
				(*rit).second++;
			RBC_TagCount::iterator eit = e_d[tag].find(d_string);
			if (eit == e_d[tag].end())
			{
				eit = (e_d[tag].insert(
					std::pair<std::string, size_t>(d_string, 0))).first; // = 0
			}
//std::cerr << "RBC: [" << tag << "] r-ready-branch with r_d = " << (*rit).second << " e_d = " << (*eit).second << std::endl;
			if ((t > 0) && ((*rit).second == (t + 1)) && ((*eit).second < (n - t)))
			{
//std::cerr << "RBC(" << j << "): [" << tag << "] send r-ready message" << std::endl;
				// prepare message $(ID.j.s, r-ready, d)$
				RBC_ConstMessage message2;
				message2.push_back(message[0]);
				message2.push_back(message[1]);
				message2.push_back(message[2]);
				message2.push_back(r_ready);
				message2.push_back(message[4]);
				// send to all parties by unicast transmission (very short timeout)
				for (size_t i = 0; i < n; i++)
				{
					if (!aiou->Send(message2, i, aio_timeout_vs))
					{
						std::cerr << "RBC(" << j << "): sending r-ready" <<
							" failed for " << i << std::endl;
					}
				}
				message2.clear();
			}
			else if (((t > 0) && ((*rit).second == ((2 * t) + 1))) ||
				((t == 0) && ((*rit).second == 1))) // NOTE: artificial case where $t = 0$, not considered by [CKPS01]
			{
				mpz_ptr tmp = new mpz_t();
				mpz_init_set(tmp, message[4]); // $\bar{d} \gets d$
				dbar.insert(std::pair<std::string, mpz_ptr>(tag, tmp));
				if (mbar.count(tag) > 0)
					tmcg_mpz_shash(foo, 1, mbar[tag]);
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
					// send to some parties by unicast transmission (very short timeout)
					size_t howmany = ((2 * t) + 1); // TODO: optionally to all
					for (size_t i = 0; i < howmany; i++)
					{
						if (!aiou->Send(message2, i, aio_timeout_vs))
							std::cerr << "RBC(" << j << "): sending" <<
								" r-request failed for " << i << std::endl;
					}
					message2.clear();
					continue; // waiting for r-answer is done in main loop
				}
//std::cerr << "RBC: deliver from " << mpz_get_ui(message[1]) << " m = " << mbar[tag] << std::endl;
				size_t who = mpz_get_ui(message[1]);
				if (who >= n)
					throw std::runtime_error("RBC::Deliver(): who >= n");
				// check for matching tag and sequence counter before delivering
				if (!mpz_cmp(message[0], ID) &&
					!mpz_cmp(message[2], deliver_s[who]))
				{
					if (mbar.count(tag) == 0)
						throw std::runtime_error("RBC::Deliver(): no mbar");
					mpz_set(m, mbar[tag]); // set the result to $\bar{m}$
					mpz_add_ui(deliver_s[who], deliver_s[who], 1L); // increase sequence counter
					i_out = who;
					// release foo
					mpz_clear(foo);
					// release message
					ReleaseMessage(message);
					return true;
				}
				if (!mpz_cmp(message[0], ID) &&
					mpz_cmp(message[2], deliver_s[who]))
				{
					std::cerr << "RBC(" << j << "): sequence counter does" <<
						" not match for " << who << std::endl;
				}
				// buffer the acknowledged message for later delivery
				RBC_Message vtmp;
				InitializeMessage(vtmp, message);
				deliver_buf.push_back(vtmp);
//std::cerr << "RBC: P_" << j << " buffers deliver from " << who << " m = " << mbar[tag] << std::endl;
				continue;
			}
			continue;
		}
		else if (!mpz_cmp(message[3], r_ready) && ready[l].count(tag))
			std::cerr << "RBC(" << j << "): received r-ready for same tag more than once from " << l << std::endl;
		// upon receiving message $(ID.j.s, r-request) from $P_l$ for the first time
		if (!mpz_cmp(message[3], r_request) && !request[l].count(tag))
		{
//std::cerr << "RBC: r-request from " << l << std::endl;
			request[l].insert(std::pair<std::string, bool>(tag, true));
			if (mbar.count(tag))
			{
				// prepare message $(ID.j.s, r-answer, \bar{m})$
				RBC_ConstMessage message2;
				message2.push_back(message[0]);
				message2.push_back(message[1]);
				message2.push_back(message[2]);
				message2.push_back(r_answer);
				message2.push_back(mbar[tag]);
				// send only to requesting party by unicast transmission (very short timeout)
				if (!aiou->Send(message2, l, aio_timeout_vs))
				{
					std::cerr << "RBC(" << j << "): sending r-answer failed" <<
						" for " << l << std::endl;
				}
				message2.clear();
			}
			continue;
		}
		else if (!mpz_cmp(message[3], r_request) && request[l].count(tag))
		{
			std::cerr << "RBC(" << j << "): received r-request for same tag" <<
				" more than once from " << l << std::endl;
		}
		// upon receiving message $(ID.j.s, r-answer, m) from $P_l$ for the first time
		if (!mpz_cmp(message[3], r_answer) && !answer[l].count(tag))
		{
//std::cerr << "RBC: r-answer from " << l << std::endl;
			answer[l].insert(std::pair<std::string, bool>(tag, true));
			if (!dbar.count(tag))
			{
				std::cerr << "RBC(" << j << "): no request for r-answer" <<
					" from " << l << std::endl;
				continue;
			}
			tmcg_mpz_shash(foo, 1, message[4]); // compute $H(m)$
			if (!mpz_cmp(foo, dbar[tag]))
			{
				if (mbar.count(tag) == 0)
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init(tmp);
					mbar.insert(std::pair<std::string, mpz_ptr>(tag, tmp));
				}
				else if (mpz_cmp(mbar[tag], message[4]))
				{
					std::cerr << "RBC(" << j << "): bad r-answer from " <<
						l << std::endl;
					continue;
				}
				mpz_set(mbar[tag], message[4]); // $\bar{m} \gets m$
			}
			else
			{
				std::cerr << "RBC(" << j << "): bad r-answer from " <<
					l << std::endl;
				continue;
			}
//std::cerr << "RBC: deliver from " << mpz_get_ui(message[1]) << " m = " << mbar[tag] << std::endl;
			size_t who = mpz_get_ui(message[1]);
			if (who >= n)
				throw std::runtime_error("RBC::Deliver(): who >= n");

			// check for matching tag and sequence counter before delivering
			if (!mpz_cmp(message[0], ID) && !mpz_cmp(message[2], deliver_s[who]))
			{
				if (mbar.count(tag) == 0)
					throw std::runtime_error("RBC::Deliver(): no mbar found");
				mpz_set(m, mbar[tag]); // set the result to $\bar{m}$
				mpz_add_ui(deliver_s[who], deliver_s[who], 1L); // increase sequence counter
				i_out = who;
				// release foo
				mpz_clear(foo);
				// release message
				ReleaseMessage(message);
				return true;
			}
			if (!mpz_cmp(message[0], ID) && mpz_cmp(message[2], deliver_s[who]))
			{
				std::cerr << "RBC(" << j << "): squence counter does not" <<
					" match for " << who << std::endl;
			}
			// buffer the acknowledged message for later delivery
			RBC_Message vtmp;
			InitializeMessage(vtmp, message);
			deliver_buf.push_back(vtmp);
			continue;
		}
		else if (!mpz_cmp(message[3], r_answer) && answer[l].count(tag))
		{
			std::cerr << "RBC(" << j << "): received r-answer for same tag" <<
				" more than once from " << l << std::endl;
		}
		// report on discarded messages
		std::cerr << "RBC(" << j << "): WARNING - discard message of" <<
			" action = " << message[3] << " from " << l << std::endl;
	}
	while (time(NULL) < (entry_time + timeout));
	i_out = n; // timeout for all parties
	// release foo
	mpz_clear(foo);
	// release message
	ReleaseMessage(message);
	return false;
}

bool CachinKursawePetzoldShoupRBC::DeliverFrom
	(mpz_ptr m, const size_t i_in,
	size_t scheduler, time_t timeout)
{
	// sanity check
	if (i_in >= n)
	{
		std::cerr << "RBC(" << j << "): DeliverFrom() with " << i_in <<
			" >= " << n << std::endl;
		return false;
	}
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
		if ((buf_mpz[i_in].size() > 0) && (buf_id[i_in].size() > 0))
		{
			for (RBC_BufferList::iterator lit = buf_mpz[i_in].begin(),
				litid = buf_id[i_in].begin();
				((lit != buf_mpz[i_in].end()) && (litid != buf_id[i_in].end()));
				++lit, ++litid)
			{
				if (!mpz_cmp(*litid, ID))
				{
					mpz_set(m, *lit);
					mpz_clear(*lit), mpz_clear(*litid);
					delete [] *lit, delete [] *litid;
					buf_mpz[i_in].erase(lit), buf_id[i_in].erase(litid);
//std::cerr << "RBC(" << j << "): got buffered mpz from " << i_in << std::endl;
					return true;
				}
			}
		}
		else
		{
			// store mpz in corresponding buffer
			size_t l;
			mpz_ptr tmp = new mpz_t(), tmpID = new mpz_t();
			mpz_init(tmp), mpz_init_set(tmpID, ID);
			if (Deliver(tmp, l, scheduler, 0))
			{
//std::cerr << "RBC(" << j << "): got mpz from " << l << std::endl;
				buf_mpz[l].push_back(tmp);
				buf_id[l].push_back(tmpID);
//				if (l == i_in)
//					continue;
			}
			else
			{
				mpz_clear(tmp), mpz_clear(tmpID);
				delete [] tmp, delete [] tmpID;
			}
		}
	}
	while (time(NULL) < (entry_time + timeout));
	if (i_in != j)
	{
		std::cerr << "RBC(" << j << "): timeout delivering from " <<
			i_in << std::endl;
	}
	return false;
}

bool CachinKursawePetzoldShoupRBC::Sync
	(time_t timeout, const std::string tag)
{
	// set aio default values w.r.t. number of potentially corrupted parties
	if (timeout == aiounicast::aio_timeout_default)
		timeout = (t + 1) * aio_default_timeout;
	else
		timeout *= (t + 1);
	// set common channel ID for synchronization
	std::stringstream myID;
	myID << "CachinKursawePetzoldShoupRBC::Sync(" << timeout << ", " <<
		tag << ")";
	setID(myID.str());
	// initialize
	time_t max_timeout = timeout;
	time_t slice_timeout = (timeout / sync_slices) + 1;
	time_t entry_time = time(NULL);
	long int last_diff = 42424242;
	mpz_t mtv;
	mpz_init(mtv);
	do
	{
		time_t slice_entry_time = time(NULL);
		if (timeout > (slice_entry_time - entry_time))
		{
			mpz_set_ui(mtv, timeout - (slice_entry_time - entry_time));
			Broadcast(mtv);
		}
		else
			break;
		std::map<size_t, time_t> tvs;
		tvs[j] = timeout - (slice_entry_time - entry_time);
		do
		{
			size_t l;
			if (Deliver(mtv, l, aio_default_scheduler, 0))
			{
				time_t utv;
				utv = (time_t)mpz_get_ui(mtv);
				if (utv <= max_timeout)
					tvs[l] = utv;
				else
					std::cerr << "RBC(" << j << "): bad sync timestamp " <<
						utv << " received from " << l << std::endl;
			}
		}
		while (time(NULL) < (slice_entry_time + slice_timeout));
		std::vector<time_t> vtvs;
		for (std::map<size_t, time_t>::const_iterator ti = tvs.begin();
			ti != tvs.end(); ++ti)
		{
			vtvs.push_back(ti->second);
		}
		std::sort(vtvs.begin(), vtvs.end());
		if (vtvs.size() < (n - t))
		{
			std::cerr << "RBC(" << j << "): not enough sync timestamps" <<
				" received" << std::endl;
		}
		else
		{
			// use a median value as some kind of gentle agreement
			time_t median_timeout = vtvs[vtvs.size()/2];
			time_t slice_diff = (slice_entry_time - entry_time);
			long int diff = median_timeout - (timeout - slice_diff);
			last_diff = diff;
			if (std::abs(diff) > 0)
			{
				std::cerr << "RBC(" << j << "): sync diff = " <<
					diff << std::endl;
			}
			if (std::abs(diff) <= max_timeout)
			{
				timeout += diff;
			}
			else
			{
				std::cerr << "RBC(" << j << "): time jump detected with" <<
					" diff = " << diff << std::endl;
			}
		}
	}
	while (time(NULL) < (entry_time + timeout));
	// release
	mpz_clear(mtv);
	unsetID();
	if (std::abs(last_diff) <= slice_timeout)
		return true;
	else
	{
		std::cerr << "RBC(" << j << "): synchroniziation failed with diff = " <<
			last_diff << std::endl;
		return false;
	}
}

CachinKursawePetzoldShoupRBC::~CachinKursawePetzoldShoupRBC
	()
{
	mpz_clear(ID), mpz_clear(whoami), mpz_clear(s);
	for (RBC_BufferList::iterator lit = last_IDs.begin();
		lit != last_IDs.end(); ++lit)
	{
		mpz_clear(*lit);
		delete [] *lit;
	}
	last_IDs.clear();
	for (RBC_BufferList::iterator lit = last_s.begin();
		lit != last_s.end(); ++lit)
	{
		mpz_clear(*lit);
		delete [] *lit;
	}
	last_s.clear();
	for (RBC_VectorList::iterator lit = last_deliver_s.begin();
		lit != last_deliver_s.end(); ++lit)
	{
		for (size_t i = 0; i < lit->size(); i++)
		{
			mpz_clear((*lit)[i]);
			delete [] (*lit)[i];
		}
	}
	last_deliver_s.clear();
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
	for (std::map<std::string, RBC_TagCount>::iterator mit = e_d.begin();
		mit != e_d.end(); ++mit)
	{
		((*mit).second).clear();
	}
	for (std::map<std::string, RBC_TagCount>::iterator mit = r_d.begin();
		mit != r_d.end(); ++mit)
	{
		((*mit).second).clear();
	}	
	e_d.clear(), r_d.clear();
	for (size_t i = 0; i < n; i++)
	{
		for (RBC_BufferList::iterator lit = buf_mpz[i].begin();
			lit != buf_mpz[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete [] *lit;
		}
		buf_mpz[i].clear();
		for (RBC_BufferList::iterator lit = buf_id[i].begin();
			lit != buf_id[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete [] *lit;
		}
		buf_id[i].clear();
		for (RBC_BufferList::iterator lit = buf_msg[i].begin();
			lit != buf_msg[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete [] *lit;
		}
		buf_msg[i].clear();
		mpz_clear(deliver_s[i]);
		delete [] deliver_s[i];
	}
	buf_mpz.clear(), buf_id.clear(), buf_msg.clear(), deliver_s.clear();
	for (RBC_VectorList::iterator lit = deliver_buf.begin();
		lit != deliver_buf.end(); ++lit)
	{
		for (RBC_Message::iterator vit = lit->begin(); vit != lit->end(); ++vit)
		{
			mpz_clear(*vit);
			delete [] *vit;
		}
		lit->clear();
	}	
	deliver_buf.clear(), deliver_error.clear();
}

