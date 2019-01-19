/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007, 2009, 
               2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifdef FORKING

#include <exception>
#include <sstream>
#include <vector>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "test_helper.h"
#include "pipestream.hh"

#undef NDEBUG

// create a random permutation (naive algorithm)
void random_permutation
	(const size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
	{
		pi.push_back(0);
		bool ok;
		do
		{
			ok = true;
			pi[i] = tmcg_mpz_srandom_mod(n);
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
	(const size_t n, std::vector<size_t> &pi)
{
	pi.clear();
	for (size_t i = 0; i < n; i++)
		pi.push_back(i);
	
	for (size_t i = 0; i < (n - 1); i++)
	{
		size_t tmp = pi[i], rnd = i + tmcg_mpz_srandom_mod(n - i);
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
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());

	try
	{
		const size_t pi_check_factor = 256;
		const size_t pi_check_n = 3, pi_check_size = 6 * pi_check_factor; 
		size_t cnt = 0;
		std::vector<size_t> delta, alpha[pi_check_size], beta[pi_check_size];
		for (size_t i = 0; i < pi_check_n; i++)
			delta.push_back(i);
	
		std::cout << "random_permutation(" << pi_check_n << ", pi)" <<
			std::endl;
		start_clock();
		for (size_t i = 0; i < pi_check_size; i++)
			random_permutation(pi_check_n, alpha[i]);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		cnt = 0;
		for (size_t i = 0; i < pi_check_size; i++)
		{
			if (equal_permutations(delta, alpha[i]))
				cnt++;
		}
		std::cout << cnt << " out of " << pi_check_size << " are trivial" <<
			" (should be around " << pi_check_factor << ")" << std::endl;
	
		std::cout << "random_permutation_fast(" << pi_check_n << ", pi)" <<
			std::endl;
		start_clock();
		for (size_t i = 0; i < pi_check_size; i++)
			random_permutation_fast(pi_check_n, beta[i]);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		cnt = 0;
		for (size_t i = 0; i < pi_check_size; i++)
		{
			if (equal_permutations(delta, beta[i]))
				cnt++;
		}
		std::cout << cnt << " out of " << pi_check_size << " are trivial" <<
			" (should be around " << pi_check_factor << ")" << std::endl;

		mpz_t a, b, aa, bb;
		mpz_init(a), mpz_init(b), mpz_init(aa), mpz_init(bb);
		size_t n = 32;
	
		// check PedersenCOM
		PedersenCommitmentScheme *com, *com2;
		std::stringstream foo;
		std::vector<mpz_ptr> mp;
	
		std::cout << "PedersenCommitmentScheme(" << n << ")" << std::endl;
		com = new PedersenCommitmentScheme(n);
		std::cout << "*.CheckGroup()" << std::endl;
		assert(com->CheckGroup());
	
		// create a cloned instance
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
			delete [] mp[i];
		}
		mp.clear();
		delete com, delete com2;

		// attack PedersenCOM
		std::stringstream bar;
		std::cout << "attack PedersenCommitmentScheme(1)" << std::endl;
		com = new PedersenCommitmentScheme(1);
		std::cout << "*.CheckGroup()" << std::endl;
		assert(com->CheckGroup());
		tmcg_mpz_wrandomm(bb, com->q);
		mpz_powm(b, com->h, bb, com->p);
		bar << com->p << std::endl << com->q << std::endl << com->k <<
			std::endl << com->h << std::endl;
		bar << b << std::endl;
		com2 = new PedersenCommitmentScheme(1, bar);
		std::cout << "*.CheckGroup(modified g)" << std::endl;
		assert(com2->CheckGroup());
		{
			mpz_ptr tmp = new mpz_t();
			mpz_init_set_ui(tmp, 42L);
			mp.push_back(tmp);
		}
		tmcg_mpz_wrandomm(aa, com->q);
		mpz_powm(a, com2->h, aa, com2->p);
		std::cout << "c = " << a << std::endl;
		std::cout << "*.TestMembership(c)" << std::endl;
		assert(com2->TestMembership(a));
		std::cout << "*.Verify(c, r, mp)" << std::endl;
		mpz_mul(b, bb, mp[0]);
		mpz_mod(b, b, com2->q);
		mpz_sub(b, aa, b);
		mpz_mod(b, b, com2->q);
		std::cout << "r = " << b << std::endl;
		assert(com2->Verify(a, b, mp));
		std::cout << "*.Verify(c, r, mp + 1)" << std::endl;
		mpz_add_ui(mp[0], mp[0], 1L);
		mpz_mul(b, bb, mp[0]);
		mpz_mod(b, b, com2->q);
		mpz_sub(b, aa, b);
		mpz_mod(b, b, com2->q);
		std::cout << "r = " << b << std::endl;
		assert(com2->Verify(a, b, mp));
		{
			mpz_clear(mp[0]);
			delete [] mp[0];
		}
		mp.clear();
		delete com, delete com2;

		// interactive VSSHE checks
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
				try
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
					std::stringstream lej, lej2, lej3;
			
					mpz_init(c), mpz_init(r);
					com->PublishGroup(*pipe_out), com->PublishGroup(lej);
					GrothSKC *skc = new GrothSKC(n, lej);
					// create the public messages for SKC
					for (size_t i = 0; i < n; i++)
					{
						mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t();
						mpz_ptr tmp3 = new mpz_t(), tmp4 = new mpz_t();
						mpz_ptr tmp5 = new mpz_t(), tmp6 = new mpz_t(),
							tmp7 = new mpz_t();
						mpz_init_set_ui(tmp, i), mpz_init(tmp2), mpz_init(tmp3);
						mpz_init_set_ui(tmp4, 1L), mpz_init_set_ui(tmp5, 0L);
						mpz_init_set_ui(tmp6, 1L), mpz_init_set_ui(tmp7, 0L);
						m.push_back(tmp), m_pi.push_back(tmp2);
						R.push_back(tmp3);
						e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5));
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
					// prove SKC wrong
					start_clock();
					std::cout << "P: !skc.Prove_interactive(...)" << std::endl;
					mpz_add_ui(r, r, 1L);
					skc->Prove_interactive(pi, r, m, *pipe_in, *pipe_out);
					mpz_sub_ui(r, r, 1L);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove SKC
					start_clock();
					std::cout << "P: skc.Prove_noninteractive(...)" << std::endl;
					skc->Prove_noninteractive(pi, r, m, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove SKC wrong
					start_clock();
					std::cout << "P: !skc.Prove_noninteractive(...)" << std::endl;
					skc->Prove_noninteractive(xi, r, m, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove SKC
					start_clock();
					std::cout << "P: skc.Prove_noninteractive(...)" << std::endl;
					skc->Prove_noninteractive(pi, r, m, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove SKC wrong
					start_clock();
					std::cout << "P: !skc.Prove_noninteractive(...)" << std::endl;
					mpz_add_ui(r, r, 1L);
					skc->Prove_noninteractive(pi, r, m, *pipe_out);
					mpz_sub_ui(r, r, 1L);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;

					// initialize EDCF
					JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2,
						0, com->p, com->q, com->g[0], com->h);
					// initialize VSSHE
					lej2 << com->p << std::endl << com->q << std::endl <<
						com->g[0] << std::endl << com->h << std::endl;
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
						tmcg_mpz_srandomm(R[i], com->q);
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
						*pipe_out << e[i].first << std::endl << e[i].second <<
							std::endl << E[i].first << std::endl <<
							E[i].second << std::endl;
					}
					// prove VSSHE
					start_clock();
					std::cout << "P: vsshe.Prove_interactive(...)" << std::endl;
					vsshe->Prove_interactive(pi, R, e, E, *pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VSSHE wrong
					start_clock();
					std::cout << "P: !vsshe.Prove_interactive(...)" <<
						std::endl;
					vsshe->Prove_interactive(xi, R, e, E, *pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VSSHE public-coin
					start_clock();
					std::cout << "P: vsshe.Prove_interactive_publiccoin(...)" <<
						std::endl;
					vsshe->Prove_interactive_publiccoin(pi, R, e, E, edcf,
						*pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VSSHE public-coin wrong
					start_clock();
					std::cout << "P: !vsshe.Prove_interactive_publiccoin" <<
						"(...)" << std::endl;
					vsshe->Prove_interactive_publiccoin(xi, R, e, E, edcf,
						*pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VSSHE non-interactive
					start_clock();
					std::cout << "P: vsshe.Prove_noninteractive(...)" <<
						std::endl;
					vsshe->Prove_noninteractive(pi, R, e, E, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VSSHE non-interactive wrong
					start_clock();
					std::cout << "P: !vsshe.Prove_noninteractive(...)" <<
						std::endl;
					vsshe->Prove_noninteractive(xi, R, e, E, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;

					// NSHVZKA
					vsshe->Prove_noninteractive(pi, R, e, E, lej3);
					std::string NSHVZKA = lej3.str();
					std::cout << "NSHVZKA(" << NSHVZKA.size() << " bytes)" <<
						std::endl;
					assert(vsshe->Verify_noninteractive(e, E, lej3));
			
					// release
					for (size_t i = 0; i < n; i++)
					{
						mpz_clear(m[i]), mpz_clear(m_pi[i]), mpz_clear(R[i]);
						delete [] m[i], delete [] m_pi[i], delete [] R[i];
						mpz_clear(e[i].first), mpz_clear(e[i].second);
						delete [] e[i].first, delete [] e[i].second;
						mpz_clear(E[i].first), mpz_clear(E[i].second);
						delete [] E[i].first, delete [] E[i].second;
					}
					m.clear(), m_pi.clear(), R.clear(), e.clear(), E.clear();
					mpz_clear(c), mpz_clear(r);
					delete vsshe, delete edcf, delete skc, delete com;
			
					delete pipe_in, delete pipe_out;
					exit(0);
					/* END child code: Prover */
				}
				catch (std::exception& e)
				{
					std::cerr << "exception catched with what = " << e.what() <<
						std::endl;
					exit(-1);
				}
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
					mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t();
					mpz_ptr tmp3 = new mpz_t(), tmp4 = new mpz_t();
					mpz_ptr tmp5 = new mpz_t();
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
				std::cout << "V: skc.Verify_interactive(..., false)" <<
					std::endl;
				assert(skc->Verify_interactive(a, m, *pipe_in, *pipe_out,
					false));
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
				// verify SKC wrong
				start_clock();
				std::cout << "V: !skc.Verify_interactive(...)" << std::endl;
				assert(!skc->Verify_interactive(a, m, *pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify SKC
				start_clock();
				std::cout << "V: skc.Verify_noninteractive(..., false)" <<
					std::endl;
				assert(skc->Verify_noninteractive(a, m, *pipe_in, false));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify SKC wrong
				start_clock();
				std::cout << "V: !skc.Verify_noninteractive(...)" << std::endl;
				assert(!skc->Verify_noninteractive(a, m, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify SKC
				start_clock();
				std::cout << "V: skc.Verify_noninteractive(...)" << std::endl;
				assert(skc->Verify_noninteractive(a, m, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify SKC wrong
				start_clock();
				std::cout << "V: !skc.Verify_noninteractive(...)" << std::endl;
				assert(!skc->Verify_noninteractive(a, m, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;

				// initialize EDCF
				JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2, 0,
						com->p, com->q, com->g[0], com->h);	
				// initialize VSSHE
				lej2 << com->p << std::endl << com->q << std::endl <<
					com->g[0] << std::endl << com->h << std::endl;
				com->PublishGroup(lej2);
				GrothVSSHE *vsshe = new GrothVSSHE(n, lej2);
				// receive the messages from the prover
				for (size_t i = 0; i < n; i++)
				{
					*pipe_in >> e[i].first >> e[i].second >>
						E[i].first >> E[i].second;
				}
				// verify VSSHE
				start_clock();
				std::cout << "V: vsshe.Verify_interactive(...)" << std::endl;
				assert(vsshe->Verify_interactive(e, E, *pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VSSHE wrong
				start_clock();
				std::cout << "V: !vsshe.Verify_interactive(...)" << std::endl;
				assert(!vsshe->Verify_interactive(e, E, *pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VSSHE public-coin
				start_clock();
				std::cout << "V: vsshe.Verify_interactive_publiccoin(...)" <<
					std::endl;
				assert(vsshe->Verify_interactive_publiccoin(e, E, edcf,
					*pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VSSHE public-coin wrong
				start_clock();
				std::cout << "V: !vsshe.Verify_interactive_publiccoin(...)" <<
					std::endl;
				assert(!vsshe->Verify_interactive_publiccoin(e, E, edcf,
					*pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VSSHE non-interactive
				start_clock();
				std::cout << "V: vsshe.Verify_noninteractive(...)" << std::endl;
				assert(vsshe->Verify_noninteractive(e, E, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VSSHE non-interactive wrong
				start_clock();
				std::cout << "V: !vsshe.Verify_noninteractive(...)" <<
					std::endl;
				assert(!vsshe->Verify_noninteractive(e, E, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
			
				// release
				for (size_t i = 0; i < n; i++)
				{
					mpz_clear(m[i]);
					mpz_clear(e[i].first), mpz_clear(e[i].second);
					mpz_clear(E[i].first), mpz_clear(E[i].second);
					delete [] m[i];
					delete [] e[i].first, delete [] e[i].second;
					delete [] E[i].first, delete [] E[i].second;
				}
				m.clear(), e.clear(), E.clear();
				delete vsshe, delete edcf, delete skc, delete com;
			
				delete pipe_in, delete pipe_out;
			}
			if (waitpid(pid, NULL, 0) != pid)
				perror("t-vsshe (waitpid)");
			close(pipe1fd[0]), close(pipe1fd[1]);
			close(pipe2fd[0]), close(pipe2fd[1]);
		}

		mpz_clear(a), mpz_clear(b), mpz_clear(aa), mpz_clear(bb);
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() << std::endl;
		return -1;
	}
}

#else

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	std::cout << "test skipped" << std::endl;
	return 77;
}

#endif

