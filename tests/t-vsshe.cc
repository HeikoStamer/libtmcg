/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

#include <sstream>
#include <vector>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include <libTMCG.hh>
#include "pipestream.hh"

#undef NDEBUG

// create a random permutation (naive algorithm)
void random_permutation
	(size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
	{
		pi.push_back(0);
		bool ok;
		do
		{
			ok = true;
			pi[i] = mpz_srandom_mod(n);
			for (size_t j = 0; j < i; j++)
			{
				if (pi[i] == pi[j])
				{
					ok = false;
					break;
				}
			}
		}
		while (!ok);
	}
}

// create a random permutation (Knuth or Fisher-Yates algorithm)
void random_permutation_fast
	(size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
		pi.push_back(i);
	
	for (size_t i = 0; i < (n - 1); i++)
	{
		size_t tmp = pi[i], rnd = i + mpz_srandom_mod(n - i);
		pi[i] = pi[rnd];
		pi[rnd] = tmp;
	}
}

bool equal_permutations
	(const std::vector<size_t> &pi, const std::vector<size_t> &xi)
{
	if (pi.size() != xi.size())
		return false;
	for (size_t i = 0; i < pi.size(); i++)
		if (pi[i] != xi[i])
			return false;
	return true;
}

int main
	(int argc, char **argv)
{
	mpz_t a, b, aa, bb;
	assert(init_libTMCG());
	
	size_t pi_check_factor = 256;
	size_t pi_check_n = 3, pi_check_size = 6 * pi_check_factor, cnt = 0;
	std::vector<size_t> delta, alpha[pi_check_size], beta[pi_check_size];
	for (size_t i = 0; i < pi_check_n; i++)
		delta.push_back(i);
	
	std::cout << "random_permutation(" << pi_check_n << ", pi)" << std::endl;
	start_clock();
	for (size_t i = 0; i < pi_check_size; i++)
		random_permutation(pi_check_n, alpha[i]);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	cnt = 0;
	for (size_t i = 0; i < pi_check_size; i++)
		if (equal_permutations(delta, alpha[i]))
			cnt++;
	std::cout << cnt << " out of " << pi_check_size << 
		" are trivial (should be around " << pi_check_factor << ")" << std::endl;
	
	std::cout << "random_permutation_fast(" << pi_check_n << ", pi)" << std::endl;
	start_clock();
	for (size_t i = 0; i < pi_check_size; i++)
		random_permutation_fast(pi_check_n, beta[i]);
	stop_clock();
	std::cout << elapsed_time() << std::endl;
	cnt = 0;
	for (size_t i = 0; i < pi_check_size; i++)
		if (equal_permutations(delta, beta[i]))
			cnt++;
	std::cout << cnt << " out of " << pi_check_size << 
		" are trivial (should be around " << pi_check_factor << ")" << std::endl;
	
	mpz_init(a), mpz_init(b), mpz_init(aa), mpz_init(bb);
	size_t n = 32;
	
	PedersenCommitmentScheme *com, *com2;
	std::stringstream foo;
	std::vector<mpz_ptr> mp;
	
	std::cout << "PedersenCommitmentScheme(" << n << ")" << std::endl;
	com = new PedersenCommitmentScheme(n);
	std::cout << "*.CheckGroup()" << std::endl;
	assert(com->CheckGroup());
	
	// create a clone instance
	std::cout << "*.PublishGroup(foo)" << std::endl;
	com->PublishGroup(foo);
	std::cout << "PedersenCommitmentScheme(" << n << ", foo)" << std::endl;
	com2 = new PedersenCommitmentScheme(n, foo);
	std::cout << "*.CheckGroup()" << std::endl;
	assert(com2->CheckGroup());
	
	// create messages
	for (size_t i = 0; i < n; i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, i);
		mp.push_back(tmp);
	}
	
	// commit
	std::cout << "*.Commit(...)" << std::endl;
	com->Commit(a, b, mp);
	std::cout << "*.CommitBy(...)" << std::endl;
	com->CommitBy(aa, b, mp);
	assert(!mpz_cmp(a, aa));
	
	// TestMembership
	std::cout << "*.TestMembership(...)" << std::endl;
	assert(com->TestMembership(a));
	assert(com->TestMembership(aa));
	assert(!com->TestMembership(com->p));
	
	// verify
	std::cout << "*.Verify(...)" << std::endl;
	assert(com->Verify(a, b, mp));
	assert(com2->Verify(a, b, mp));
	mpz_add_ui(mp[0], mp[0], 1L);
	assert(!com->Verify(a, b, mp));
	assert(!com2->Verify(a, b, mp));
	
	// release
	for (size_t i = 0; i < n; i++)
	{
		mpz_clear(mp[i]);
		delete mp[i];
	}
	mp.clear();
	delete com, delete com2;
	
	pid_t pid = 0;
	int pipe1fd[2], pipe2fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
		perror("t-vsshe (pipe)");
	else if ((pid = fork()) < 0)
		perror("t-vsshe (fork)");
	else
	{
		if (pid == 0)
		{
			/* BEGIN child code: Prover */
			ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
			opipestream *pipe_out = new opipestream(pipe2fd[1]);
			
			PedersenCommitmentScheme *com = 
				new PedersenCommitmentScheme(n);
			mpz_t c, r;
			std::vector<mpz_ptr> m, m_pi, R;
			std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
			std::vector<size_t> pi, xi;
			std::stringstream lej, lej2;
			
			mpz_init(c), mpz_init(r);
			com->PublishGroup(*pipe_out), com->PublishGroup(lej);
			GrothSKC *skc = new GrothSKC(n, lej);
			// create the public messages for SKC
			for (size_t i = 0; i < n; i++)
			{
				mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
					tmp4 = new mpz_t(), tmp5 = new mpz_t(), tmp6 = new mpz_t(),
					tmp7 = new mpz_t();
				mpz_init_set_ui(tmp, i), mpz_init(tmp2), mpz_init(tmp3),
					mpz_init_set_ui(tmp4, 1L), mpz_init_set_ui(tmp5, 0L),
					mpz_init_set_ui(tmp6, 1L), mpz_init_set_ui(tmp7, 0L);
				m.push_back(tmp), m_pi.push_back(tmp2), R.push_back(tmp3),
					e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5)),
					E.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp6, tmp7));
			}
			// create the secret permutation
			random_permutation(n, pi);
			// commit
			std::cout << "P: m_pi = " << std::flush;
			for (size_t i = 0; i < n; i++)
			{
				mpz_set(m_pi[i], m[pi[i]]);
				std::cout << m_pi[i] << " " << std::flush;
			}
			start_clock();
			std::cout << std::endl << "P: com.Commit(...)" << std::endl;
			com->Commit(c, r, m_pi);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			*pipe_out << c << std::endl;
			// prove SKC
			start_clock();
			std::cout << "P: skc.Prove_interactive(...)" << std::endl;
			skc->Prove_interactive(pi, r, m, *pipe_in, *pipe_out);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			// create a different permutation
			do
				random_permutation(n, xi);
			while (equal_permutations(pi, xi));
			// prove SKC wrong
			start_clock();
			std::cout << "P: !skc.Prove_interactive(...)" << std::endl;
			skc->Prove_interactive(xi, r, m, *pipe_in, *pipe_out);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			// prove SKC
			start_clock();
			std::cout << "P: skc.Prove_interactive(...)" << std::endl;
			skc->Prove_interactive(pi, r, m, *pipe_in, *pipe_out);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			
			// initialize VSSHE
			lej2 << com->p << std::endl << com->q << std::endl << com->g[0] << 
				std::endl << com->h << std::endl;
			com->PublishGroup(lej2);
			GrothVSSHE *vsshe = new GrothVSSHE(n, lej2);
			// create the encrypted messages for VSSHE
			for (size_t i = 0; i < n; i++)
			{
				// create e[i]
				mpz_set_ui(e[i].first, 1L);
				mpz_powm_ui(e[i].second, com->h, i, com->p);
			}
			for (size_t i = 0; i < n; i++)
			{
				// create E[i]
				mpz_srandomm(R[i], com->q);
				mpz_powm(E[i].first, com->g[0], R[i], com->p);
				mpz_mul(E[i].first, E[i].first, e[pi[i]].first);
				mpz_mod(E[i].first, E[i].first, com->p);
				mpz_powm(E[i].second, com->h, R[i], com->p);
				mpz_mul(E[i].second, E[i].second, e[pi[i]].second);
				mpz_mod(E[i].second, E[i].second, com->p);
			}
			// send the messages to the verifier
			for (size_t i = 0; i < n; i++)
			{
				*pipe_out << e[i].first << std::endl << e[i].second << std::endl << 
					E[i].first << std::endl << E[i].second << std::endl;
			}
			// prove VSSHE
			start_clock();
			std::cout << "P: vsshe.Prove_interactive(...)" << std::endl;
			vsshe->Prove_interactive(pi, R, e, E, *pipe_in, *pipe_out);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			// prove VSSHE wrong
			start_clock();
			std::cout << "P: !vsshe.Prove_interactive(...)" << std::endl;
			vsshe->Prove_interactive(xi, R, e, E, *pipe_in, *pipe_out);
			stop_clock();
			std::cout << "P: " << elapsed_time() << std::endl;
			
			// release
			for (size_t i = 0; i < n; i++)
			{
				mpz_clear(m[i]), mpz_clear(m_pi[i]), mpz_clear(R[i]);
				delete m[i], delete m_pi[i], delete R[i];
				mpz_clear(e[i].first), mpz_clear(e[i].second);
				delete e[i].first, delete e[i].second;
				mpz_clear(E[i].first), mpz_clear(E[i].second);
				delete E[i].first, delete E[i].second;
			}
			m.clear(), m_pi.clear(), R.clear(), e.clear(), E.clear();
			mpz_clear(c), mpz_clear(r);
			delete vsshe, delete skc, delete com;
			
			delete pipe_in, delete pipe_out;
			exit(0);
			/* END child code: Prover */
		}
		else
		{
			std::cout << "fork() = " << pid << std::endl;
			/* Verifier */
			ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
			opipestream *pipe_out = new opipestream(pipe1fd[1]);
			PedersenCommitmentScheme *com = 
				new PedersenCommitmentScheme(n, *pipe_in);
			std::vector<mpz_ptr> m;
			std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
			std::stringstream lej, lej2;
			
			// create the public messages for SKC
			for (size_t i = 0; i < n; i++)
			{
				mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t(), tmp3 = new mpz_t(),
					tmp4 = new mpz_t(), tmp5 = new mpz_t();
				mpz_init_set_ui(tmp, i), mpz_init(tmp2), mpz_init(tmp3),
					mpz_init(tmp4), mpz_init(tmp5);
				m.push_back(tmp);
				e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp2, tmp3)),
				E.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5));
			}
			// check the commitment scheme and initialize SKC
			assert(com->CheckGroup());
			com->PublishGroup(lej);
			GrothSKC *skc = new GrothSKC(n, lej);
			// receive the commitment
			*pipe_in >> a;
			std::cout << "V: c = " << a << std::endl;
			// verify SKC
			start_clock();
			std::cout << "V: skc.Verify_interactive(...)" << std::endl;
			assert(skc->Verify_interactive(a, m, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "V: " << elapsed_time() << std::endl;
			// verify SKC wrong
			start_clock();
			std::cout << "V: !skc.Verify_interactive(...)" << std::endl;
			assert(!skc->Verify_interactive(a, m, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "V: " << elapsed_time() << std::endl;
			// verify SKC
			start_clock();
			std::cout << "V: skc.Verify_interactive(...)" << std::endl;
			assert(skc->Verify_interactive(a, m, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "V: " << elapsed_time() << std::endl;
			
			// initialize VSSHE
			lej2 << com->p << std::endl << com->q << std::endl << com->g[0] << 
				std::endl << com->h << std::endl;
			com->PublishGroup(lej2);
			GrothVSSHE *vsshe = new GrothVSSHE(n, lej2);
			// receive the messages from the prover
			for (size_t i = 0; i < n; i++)
				*pipe_in >> e[i].first >> e[i].second >> E[i].first >> 
					E[i].second;
			// prove VSSHE
			start_clock();
			std::cout << "V: vsshe.Verify_interactive(...)" << std::endl;
			assert(vsshe->Verify_interactive(e, E, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "V: " << elapsed_time() << std::endl;
			// prove VSSHE wrong
			start_clock();
			std::cout << "V: !vsshe.Verify_interactive(...)" << std::endl;
			assert(!vsshe->Verify_interactive(e, E, *pipe_in, *pipe_out));
			stop_clock();
			std::cout << "V: " << elapsed_time() << std::endl;
			
			// release
			for (size_t i = 0; i < n; i++)
			{
				mpz_clear(m[i]);
				mpz_clear(e[i].first), mpz_clear(e[i].second);
				mpz_clear(E[i].first), mpz_clear(E[i].second);
				delete m[i];
				delete e[i].first, delete e[i].second;
				delete E[i].first, delete E[i].second;
			}
			m.clear(), e.clear(), E.clear();
			delete vsshe, delete skc, delete com;
			
			delete pipe_in, delete pipe_out;
		}
		if (waitpid(pid, NULL, 0) != pid)
			perror("t-vsshe (waitpid)");
		close(pipe1fd[0]), close(pipe1fd[1]), close(pipe2fd[0]), close(pipe2fd[1]);
	}

	mpz_clear(a), mpz_clear(b), mpz_clear(aa), mpz_clear(bb);
	return 0;
}
