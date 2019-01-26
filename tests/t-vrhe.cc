/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2015, 2016, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

// create a random rotation (naive algorithm)
size_t random_rotation
	(const size_t n, std::vector<size_t> &pi)
{
	size_t r = tmcg_mpz_srandom_mod(n);
	pi.clear();
	for (size_t i = 0; i < n; i++)
		pi.push_back((r + i) % n);
	if (n > 0)
		return ((n - r) % n);
	else
		return 0;
}

bool equal_rotations
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
		const size_t pi_check_factor = 512;
		const size_t pi_check_n = 3, pi_check_size = 3 * pi_check_factor;
		long double V = 0.0;
		std::vector<size_t> cntn, delta[pi_check_n], alpha[pi_check_size];
		// construct all possible rotations and store them in delta	
		for (size_t n = 0; n < pi_check_n; n++)
		{
			for (size_t i = 0; i < pi_check_n; i++)
				delta[n].push_back((i + n) % pi_check_n);
		}
	
		std::cout << "random_rotation(" << pi_check_n << ", pi)" << std::endl;
		start_clock();
		for (size_t i = 0; i < pi_check_size; i++)
			random_rotation(pi_check_n, alpha[i]);
		stop_clock();
		std::cout << elapsed_time() << std::endl;
		for (size_t n = 0; n < pi_check_n; n++)
			cntn.push_back(0);
		for (size_t i = 0; i < pi_check_size; i++)
		{
			for (size_t n = 0; n < pi_check_n; n++)
			{
				if (equal_rotations(delta[n], alpha[i]))
					cntn[n]++;
			}
		}
		for (size_t n = 0; n < pi_check_n; n++)
		{
			std::cout << cntn[n] << " out of " << pi_check_size << 
				" are of type " << n << " (should be around " <<
				pi_check_factor << ")" << std::endl;
		}
		// compute chi-square test value [TAOCP, Section 3.3.1]
		for (size_t n = 0; n < pi_check_n; n++)
		{
			long double Yp = (long double)(cntn[n] * cntn[n]) /
				(1.0 / (long double)pi_check_n);
			V = V + Yp;	
		}
		V = ((1.0 / (long double)pi_check_size) * V) -
			(long double)pi_check_size;
		std::cout << "chi-square test value is " << V << std::endl;
		assert(V < 42.0);

		size_t n = 32;	
		pid_t pid = 0;
		int pipe1fd[2], pipe2fd[2];
		if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0))
			perror("t-vrhe (pipe)");
		else if ((pid = fork()) < 0)
			perror("t-vrhe (fork)");
		else
		{
			if (pid == 0)
			{
				try
				{
					// BEGIN child code: Prover
					ipipestream *pipe_in = new ipipestream(pipe1fd[0]);
					opipestream *pipe_out = new opipestream(pipe2fd[1]);
			
					std::vector<mpz_ptr> m, m_pi, R;
					std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
					std::vector<size_t> pi, xi;
					std::stringstream lej, lej2, lej3;
			
					// create the public messages
					for (size_t i = 0; i < n; i++)
					{
						mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t();
						mpz_ptr tmp3 = new mpz_t(), tmp4 = new mpz_t();
						mpz_ptr tmp5 = new mpz_t(), tmp6 = new mpz_t(),
							tmp7 = new mpz_t();
						mpz_init_set_ui(tmp, i);
						mpz_init(tmp2), mpz_init(tmp3);
						mpz_init_set_ui(tmp4, 1L), mpz_init_set_ui(tmp5, 0L);
						mpz_init_set_ui(tmp6, 1L), mpz_init_set_ui(tmp7, 0L);
						m.push_back(tmp);
						m_pi.push_back(tmp2), R.push_back(tmp3);
						e.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp4, tmp5));
						E.push_back(std::pair<mpz_ptr, mpz_ptr>(tmp6, tmp7));
					}
					// create the secret rotation
					size_t r = random_rotation(n, pi);
					for (size_t i = 0; i < n; i++)
						std::cout << pi[i] << " ";
					std::cout << std::endl;
					std::cout << "r = " << r << std::endl;
					// create a different rotation
					size_t r_wrong = 0;
					do
						r_wrong = random_rotation(n, xi);
					while (equal_rotations(pi, xi));
					std::cout << "r_wrong = " << r_wrong << std::endl;

					// initialize VRHE
					HooghSchoenmakersSkoricVillegasVRHE *vrhe =
						new HooghSchoenmakersSkoricVillegasVRHE();
					vrhe->PublishGroup(*pipe_out);
					// initialize EDCF
					JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2,
						0, vrhe->p, vrhe->q, vrhe->g, vrhe->h);

					// create the encrypted messages for VRHE
					for (size_t i = 0; i < n; i++)
					{
						// create e[i]
						mpz_set_ui(e[i].first, 1L);
						mpz_powm_ui(e[i].second, vrhe->h, i, vrhe->p);
					}
					for (size_t i = 0; i < n; i++)
					{
						// create E[i]
						tmcg_mpz_srandomm(R[i], vrhe->q);
						mpz_powm(E[i].first, vrhe->g, R[i], vrhe->p);
						mpz_mul(E[i].first, E[i].first, e[pi[i]].first);
						mpz_mod(E[i].first, E[i].first, vrhe->p);
						mpz_powm(E[i].second, vrhe->h, R[i], vrhe->p);
						mpz_mul(E[i].second, E[i].second, e[pi[i]].second);
						mpz_mod(E[i].second, E[i].second, vrhe->p);
					}
					// send the messages to the verifier
					for (size_t i = 0; i < n; i++)
					{
						*pipe_out << e[i].first << std::endl <<
							e[i].second << std::endl << 
							E[i].first << std::endl << E[i].second << std::endl;
					}
					// prove VRHE
					start_clock();
					std::cout << "P: vrhe.Prove_interactive(...)" << std::endl;
					vrhe->Prove_interactive(r, R, e, E, *pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VRHE wrong
					start_clock();
					std::cout << "P: !vrhe.Prove_interactive(...)" << std::endl;
					vrhe->Prove_interactive(r_wrong, R, e, E,
						*pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VRHE public-coin
					start_clock();
					std::cout << "P: vrhe.Prove_interactive_publiccoin(...)" <<
						std::endl;
					vrhe->Prove_interactive_publiccoin(r, R, e, E, edcf,
						*pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VRHE public-coin wrong
					start_clock();
					std::cout << "P: !vrhe.Prove_interactive_publiccoin(...)" <<
						std::endl;
					vrhe->Prove_interactive_publiccoin(r_wrong, R, e, E, edcf,
						*pipe_in, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VRHE non-interactive
					start_clock();
					std::cout << "P: vrhe.Prove_noninteractive(...)" <<
						std::endl;
					vrhe->Prove_noninteractive(r, R, e, E, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;
					// prove VRHE non-interactive wrong
					start_clock();
					std::cout << "P: !vrhe.Prove_noninteractive(...)" <<
						std::endl;
					vrhe->Prove_noninteractive(r_wrong, R, e, E, *pipe_out);
					stop_clock();
					std::cout << "P: " << elapsed_time() << std::endl;

					// NSHVZKP
					vrhe->Prove_noninteractive(r, R, e, E, lej3);
					std::string NSHVZKP = lej3.str();
					std::cout << "NSHVZKP(" << NSHVZKP.size() << " bytes)" <<
						std::endl;
					assert(vrhe->Verify_noninteractive(e, E, lej3));
			
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
					delete edcf, delete vrhe;
			
					delete pipe_in, delete pipe_out;
					exit(0);
					// END child code: Prover
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
				// Verifier
				ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
				opipestream *pipe_out = new opipestream(pipe1fd[1]);
				std::vector<mpz_ptr> m;
				std::vector<std::pair<mpz_ptr, mpz_ptr> > e, E;
				std::stringstream lej, lej2;

				// create the public messages
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

				// initialize VRHE
				HooghSchoenmakersSkoricVillegasVRHE *vrhe =
					new HooghSchoenmakersSkoricVillegasVRHE(*pipe_in);	
				assert(vrhe->CheckGroup());
				// initialize EDCF
				JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(2, 0,
						vrhe->p, vrhe->q, vrhe->g, vrhe->h);
				assert(edcf->CheckGroup());

				// receive the messages from the prover
				for (size_t i = 0; i < n; i++)
				{
					*pipe_in >> e[i].first >> e[i].second >> E[i].first >> 
						E[i].second;
				}
				// verify VRHE
				start_clock();
				std::cout << "V: vrhe.Verify_interactive(...)" << std::endl;
				assert(vrhe->Verify_interactive(e, E, *pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VRHE wrong
				start_clock();
				std::cout << "V: !vrhe.Verify_interactive(...)" << std::endl;
				assert(!vrhe->Verify_interactive(e, E, *pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VRHE public-coin
				start_clock();
				std::cout << "V: vrhe.Verify_interactive_publiccoin(...)" <<
					std::endl;
				assert(vrhe->Verify_interactive_publiccoin(e, E, edcf,
					*pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VRHE public-coin wrong
				start_clock();
				std::cout << "V: !vrhe.Verify_interactive_publiccoin(...)" <<
					std::endl;
				assert(!vrhe->Verify_interactive_publiccoin(e, E, edcf,
					*pipe_in, *pipe_out));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VRHE non-interactive
				start_clock();
				std::cout << "V: vrhe.Verify_noninteractive(...)" << std::endl;
				assert(vrhe->Verify_noninteractive(e, E, *pipe_in));
				stop_clock();
				std::cout << "V: " << elapsed_time() << std::endl;
				// verify VRHE non-interactive wrong
				start_clock();
				std::cout << "V: !vrhe.Verify_noninteractive(...)" << std::endl;
				assert(!vrhe->Verify_noninteractive(e, E, *pipe_in));
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
				delete edcf, delete vrhe;
			
				delete pipe_in, delete pipe_out;
			}
			if (waitpid(pid, NULL, 0) != pid)
				perror("t-vrhe (waitpid)");
			close(pipe1fd[0]), close(pipe1fd[1]);
			close(pipe2fd[0]), close(pipe2fd[1]);
		}

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

