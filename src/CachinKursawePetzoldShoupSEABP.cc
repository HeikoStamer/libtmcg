/*******************************************************************************
  CachinKursawePetzoldShoupSEABP.cc,
              |S|ecure and |E|fficient |A|synchronous |B|roadcast |P|rotocols

     Christian Cachin, Klaus Kursawe, Frank Petzold, and Victor Shoup:
       'Secure and Efficient Asynchronous Broadcast Protocols',
     Proceedings of CRYPTO 2001, LNCS 2139, pp. 524--541, Springer 2001.
     Full length version of extended abstract: http://shoup.net/papers/ckps.pdf

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

#include "CachinKursawePetzoldShoupSEABP.hh"

CachinKursawePetzoldShoupRBC::CachinKursawePetzoldShoupRBC
	(size_t n_in, size_t t_in, size_t j_in,
	aiounicast *aiou_in, std::string ID_in)
{
	assert(t_in <= n_in);
	assert((3 * t_in) < n_in);
	assert(j_in < n_in);
	assert(n_in == aiou_in->in.size());
	assert(aiou_in->in.size() == aiou_in->out.size());

	// initialize basic parameters
	n = n_in, t = t_in, j = j_in;

	// initialize asynchonous unicast
	aiou = aiou_in;

	// initialize ID
	std::string myID = "CachinKursawePetzoldShoupRBC." + ID_in;
	mpz_shash(ID, myID);

	// initialize whoami (called $j$ in the paper)
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
		std::map<std::string, bool> *mtmp = new std::map<std::string, bool>;
		send.push_back(*mtmp);
		std::map<std::string, bool> *mtmp2 = new std::map<std::string, bool>;
		echo.push_back(*mtmp2);
		std::map<std::string, bool> *mtmp3 = new std::map<std::string, bool>;
		ready.push_back(*mtmp3);
		std::map<std::string, bool> *mtmp4 = new std::map<std::string, bool>;
		request.push_back(*mtmp4);
		std::map<std::string, bool> *mtmp5 = new std::map<std::string, bool>;
		answer.push_back(*mtmp5);
	}

	// initialize message and deliver buffers
	for (size_t i = 0; i < n; i++)
	{
		std::list<mpz_ptr> *ltmp = new std::list<mpz_ptr>;
		buf_mpz.push_back(*ltmp);
		std::list<mpz_ptr> *ltmp2 = new std::list<mpz_ptr>;
		buf_msg.push_back(*ltmp2);
		deliver_error.push_back(false);
	}
}

void CachinKursawePetzoldShoupRBC::Broadcast
	(mpz_srcptr m)
{
	mpz_add_ui(s, s, 1L); // increase sequence counter

	// prepare message $(ID.j.s, r-send, m)$
	std::vector<mpz_srcptr> message;
	message.push_back(ID);
	message.push_back(whoami);
	message.push_back(s);
	message.push_back(r_send);
	message.push_back(m);

	// send message to all parties
	for (size_t i = 0; i < n; i++)
		aiou->Send(message, i);

	// release message
	message.clear();
}

bool CachinKursawePetzoldShoupRBC::Deliver
	(mpz_ptr m, size_t &i_out)
{
	// prepare foo and tag
	mpz_t foo, tag;
	mpz_init(foo), mpz_init(tag);
	// prepare message $(ID.j.s, action, m)$
	std::vector<mpz_ptr> message;
	for (size_t mm = 0; mm < 5; mm++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init(tmp);
		message.push_back(tmp);
	}
	// process messages according to the RBC protocol of [CKPS01]
	try
	{
		for (size_t rounds = 0; rounds < (8 * n); rounds++)
		{
			size_t l = n;
			// anything buffered from previous calls/rounds?
			for (size_t i = 0; i < n; i++)
			{
				if (buf_msg[i].size() >= message.size())
				{
					for (size_t mm = 0; mm < message.size(); mm++)
					{
						mpz_set(message[mm], buf_msg[i].front());
						mpz_clear(buf_msg[i].front());
						delete buf_msg[i].front();
						buf_msg[i].pop_front();
					}
					l = i;
					break;
				}
			}
			if (l == n) // nothing buffered
			{
				// receive a message from an arbitrary party $P_l$ (round-robin)
				if (!aiou->Receive(message, l))
				{
//std::cerr << "RBC: timeout of party " << j << " from " << l << " in Deliver()" << std::endl;
					continue; // next round
				} 
			}
			// compute hash of identifying tag $ID.j.s$
			mpz_shash(tag, 3, message[0], message[1], message[2]);
			std::stringstream tag_ss;
			tag_ss << tag;
			std::string tag_string = tag_ss.str();

			// discard misformed messages
			if (mpz_cmp(message[0], ID))
			{
				std::cerr << "RBC: wrong ID in tag from " << l << std::endl;
				continue;
			}
			if ((mpz_cmp_ui(message[1], (n - 1)) > 0) || (mpz_cmp_ui(message[1], 0) < 0))
			{
				std::cerr << "RBC: wrong j in tag from " << l << std::endl;
				continue;
			}
			if (mpz_cmp_ui(message[2], 1) < 0) // TODO: check against global message counter
			{
				std::cerr << "RBC: wrong s in tag from " << l << std::endl;
				continue;
			}
			if ((mpz_cmp(message[3], r_send) < 0) || (mpz_cmp(message[3], r_answer) > 0))
			{
				std::cerr << "RBC: wrong action in tag from " << l << std::endl;
				continue;
			}

			// upon receiving message $(ID.j.s, r-send, m)$ from $P_l$
			if (!mpz_cmp(message[3], r_send) && !send[l].count(tag_string))
			{
//std::cerr << "RPC: r-send from " << l << " with m = " << message[4] << std::endl;
				send[l].insert(std::pair<std::string, bool>(tag_string, true));
				if (!mpz_cmp_ui(message[1], l) && (mbar.find(tag_string) == mbar.end()))
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init_set(tmp, message[4]); // $\bar{m} \gets m$
					mbar.insert(std::pair<std::string, mpz_ptr>(tag_string, tmp));
					// prepare message $(ID.j.s, r-echo, H(m))$
					std::vector<mpz_srcptr> message2;
					message2.push_back(message[0]);
					message2.push_back(message[1]);
					message2.push_back(message[2]);
					message2.push_back(r_echo);
					mpz_shash(message[4], 1, tmp);
					message2.push_back(message[4]);
					for (size_t i = 0; i < n; i++)
						aiou->Send(message2, i);
					message2.clear();
				}
				continue;
			}
			// upon receiving message $(ID.j.s, r-echo, d)$ from $P_l$
			if (!mpz_cmp(message[3], r_echo) && !echo[l].count(tag_string))
			{
//std::cerr << "RPC: r-echo from " << l << " with d = " << message[4] << std::endl;
				echo[l].insert(std::pair<std::string, bool>(tag_string, true));
				std::stringstream d_ss;
				d_ss << message[4];
				std::string d_string = d_ss.str();
				if (e_d.find(tag_string) == e_d.end())
				{
					std::map<std::string, size_t> *mmm = new std::map<std::string, size_t>;
					e_d.insert(std::pair<std::string, std::map<std::string, size_t> >(tag_string, *mmm));
				}
				std::map<std::string, size_t>::iterator eit = e_d[tag_string].find(d_string);
				if (eit == e_d[tag_string].end())
					eit = (e_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 1))).first;
				else
					(*eit).second++;
				if (r_d.find(tag_string) == r_d.end())
				{
					std::map<std::string, size_t> *mmm = new std::map<std::string, size_t>;
					r_d.insert(std::pair<std::string, std::map<std::string, size_t> >(tag_string, *mmm));
				}
				std::map<std::string, size_t>::iterator rit = r_d[tag_string].find(d_string);
				if (rit == r_d[tag_string].end())
					rit = (r_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 0))).first;
				if (((*eit).second == (n - t)) && ((*rit).second <= t))
				{
					// prepare message $(ID.j.s, r-ready, d)$
					std::vector<mpz_srcptr> message2;
					message2.push_back(message[0]);
					message2.push_back(message[1]);
					message2.push_back(message[2]);
					message2.push_back(r_ready);
					message2.push_back(message[4]);
					for (size_t i = 0; i < n; i++)
						aiou->Send(message2, i);
					message2.clear();
				}
				continue;
			}
			// upon receiving message $(ID.j.s, r-ready, d)$ from $P_l$
			if (!mpz_cmp(message[3], r_ready) && !ready[l].count(tag_string))
			{
//std::cerr << "RPC: r-ready from " << l << " with d = " << message[4] << std::endl;
				ready[l].insert(std::pair<std::string, bool>(tag_string, true));
				std::stringstream d_ss;
				d_ss << message[4];
				std::string d_string = d_ss.str();
				if (e_d.find(tag_string) == e_d.end())
				{
					std::map<std::string, size_t> *mmm = new std::map<std::string, size_t>;
					e_d.insert(std::pair<std::string, std::map<std::string, size_t> >(tag_string, *mmm));
				}
				if (r_d.find(tag_string) == r_d.end())
				{
					std::map<std::string, size_t> *mmm = new std::map<std::string, size_t>;
					r_d.insert(std::pair<std::string, std::map<std::string, size_t> >(tag_string, *mmm));
				}
				std::map<std::string, size_t>::iterator rit = r_d[tag_string].find(d_string);
				if (rit == r_d[tag_string].end())
					rit = (r_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 1))).first;
				else
					(*rit).second++;
				std::map<std::string, size_t>::iterator eit = e_d[tag_string].find(d_string);
				if (eit == e_d[tag_string].end())
					eit = (e_d[tag_string].insert(std::pair<std::string, size_t>(d_string, 0))).first;
//std::cerr << "RPC: r_d = " << (*rit).second << " e_d = " << (*eit).second << std::endl;
				if (((*rit).second == (t + 1)) && ((*eit).second < (n - t)))
				{
					// prepare message $(ID.j.s, r-ready, d)$
					std::vector<mpz_srcptr> message2;
					message2.push_back(message[0]);
					message2.push_back(message[1]);
					message2.push_back(message[2]);
					message2.push_back(r_ready);
					message2.push_back(message[4]);
					for (size_t i = 0; i < n; i++)
						aiou->Send(message2, i);
					message2.clear();
				}
				else if ((*rit).second == ((2 * t) + 1))
				{
					mpz_ptr tmp = new mpz_t();
					mpz_init_set(tmp, message[4]); // $\bar{d} \gets d$
					dbar.insert(std::pair<std::string, mpz_ptr>(tag_string, tmp));
					if (mbar.find(tag_string) != mbar.end())
						mpz_shash(foo, 1, mbar[tag_string]);
					else
						mpz_set_ui(foo, 0L);
					if (mpz_cmp(foo, message[4]))
					{
						// prepare message $(ID.j.s, r-request)$
						std::vector<mpz_srcptr> message2;
						message2.push_back(message[0]);
						message2.push_back(message[1]);
						message2.push_back(message[2]);
						message2.push_back(r_request);
						message2.push_back(message[4]);
						for (size_t i = 0; i < ((2 * t) + 1); i++)
							aiou->Send(message2, i);
						message2.clear();
						// wait for a message $(ID.j.s, r_answer, m)$
						do
						{
							// prepare
							std::vector<mpz_ptr> message3;
							for (size_t mm = 0; mm < 5; mm++)
							{
								mpz_ptr tmp = new mpz_t();
								mpz_init(tmp);
								message3.push_back(tmp);
							}
							// receive
							size_t l2;
							if (aiou->Receive(message3, l2))
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
//std::cerr << "RPC: r-answer from " << l2 << " with m = " << message3[4] << std::endl;
									answer[l2].insert(std::pair<std::string, bool>(tag_string, true));
									mpz_shash(foo, 1, message3[4]); // compute $H(m)$
									mpz_set(mbar[tag_string], message3[4]); // $\bar{m} \gets m$
								}
								// release
								for (size_t mm = 0; mm < message3.size(); mm++)
								{
									mpz_clear(message3[mm]);
									delete message3[mm];
								}
								message3.clear();
							}
							else
							{
								// release
								for (size_t mm = 0; mm < message3.size(); mm++)
								{
									mpz_clear(message3[mm]);
									delete message3[mm];
								}
								message3.clear();
							}
						}
						while (mpz_cmp(foo, message[4])); // $H(m) = \bar{d}$
					}
//std::cerr << "RPC: deliver from " << mpz_get_ui(message[1]) << " m = " << mbar[tag_string] << std::endl;
// TODO: check sequence counter before delivering
					mpz_set(m, mbar[tag_string]);
					i_out = mpz_get_ui(message[1]);
					throw true;
				}
				continue;
			}
			// upon receiving message $(ID.j.s, r-request) from $P_l$ for the first time
			if (!mpz_cmp(message[3], r_request) && !request[l].count(tag_string))
			{
//std::cerr << "RPC: r-request from " << l << std::endl;
				request[l].insert(std::pair<std::string, bool>(tag_string, true));
				if (mbar.find(tag_string) != mbar.end())
				{
					// prepare message $(ID.j.s, r-answer, \bar{m})$
					std::vector<mpz_srcptr> message2;
					message2.push_back(message[0]);
					message2.push_back(message[1]);
					message2.push_back(message[2]);
					message2.push_back(r_answer);
					message2.push_back(mbar[tag_string]);
					aiou->Send(message2, l);
					message2.clear();
				}
				continue;
			}
			std::cerr << "RPC: discard message of action " << message[3] << " from " << l << std::endl;
		}
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
			delete message[mm];
		}
		message.clear();
		// return
		return return_value;
	}
}

bool CachinKursawePetzoldShoupRBC::DeliverFrom
	(mpz_ptr m, size_t i_in)
{
	std::vector<size_t> sleep_counter;
	for (size_t i = 0; i <= n; i++)
		sleep_counter.push_back(0);
	for (size_t rounds = 0; rounds < (n * n * n); rounds++) // FIXME: determine correct upper bound
	{
		// anything buffered?
		if (buf_mpz[i_in].size() > 0)
		{
			mpz_set(m, buf_mpz[i_in].front());
			mpz_clear(buf_mpz[i_in].front());
			delete buf_mpz[i_in].front();
			buf_mpz[i_in].pop_front();
			return true;
		}
		else
		{
			// deliver a message and store them in the corresponding buffer
			size_t l;
			mpz_ptr tmp = new mpz_t();
			mpz_init(tmp);
			if (Deliver(tmp, l))
			{
				buf_mpz[l].push_back(tmp);
				sleep_counter[l] = 0;
				sleep_counter[n] = 0;
			}
			else
			{
				mpz_clear(tmp);
				delete tmp;
				if (sleep_counter[l] < aiou->timeout)
				{
					sleep(1);
					sleep_counter[l] = sleep_counter[l] + 1;
				}
			}
		}
	}
	std::cerr << "RBC: timeout of party " << j << " from " << i_in << " in DeliverFrom()" << std::endl;
	return false;
}

CachinKursawePetzoldShoupRBC::~CachinKursawePetzoldShoupRBC
	()
{
	mpz_clear(ID), mpz_clear(whoami), mpz_clear(s);
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
	for (std::map<std::string, mpz_ptr>::iterator mit = mbar.begin(); mit != mbar.end(); ++mit)
	{
		mpz_clear((*mit).second);
		delete (*mit).second;
	}
	for (std::map<std::string, mpz_ptr>::iterator mit = dbar.begin(); mit != dbar.end(); ++mit)
	{
		mpz_clear((*mit).second);
		delete (*mit).second;
	}
	mbar.clear(), dbar.clear();
	for (std::map<std::string, std::map<std::string, size_t> >::iterator mit = e_d.begin(); mit != e_d.end(); ++mit)
	{
		((*mit).second).clear();
	}
	for (std::map<std::string, std::map<std::string, size_t> >::iterator mit = r_d.begin(); mit != r_d.end(); ++mit)
	{
		((*mit).second).clear();
	}	
	e_d.clear(), r_d.clear();
	for (size_t i = 0; i < n; i++)
	{
		for (std::list<mpz_ptr>::iterator lit = buf_mpz[i].begin(); lit != buf_mpz[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete *lit;
		}
		buf_mpz[i].clear();
		for (std::list<mpz_ptr>::iterator lit = buf_msg[i].begin(); lit != buf_msg[i].end(); ++lit)
		{
			mpz_clear(*lit);
			delete *lit;
		}
		buf_msg[i].clear();
	}
	buf_mpz.clear(), buf_msg.clear(), deliver_error.clear();
}

