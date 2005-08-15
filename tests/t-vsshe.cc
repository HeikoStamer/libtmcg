/*******************************************************************************
   This file is part of libTMCG.

 Copyright (C) 2005  Heiko Stamer <stamer@gaos.org>

   libTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   libTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libTMCG; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#include <sstream>
#include <vector>
#include <cassert>
#include <unistd.h>
#include <sys/wait.h>

#include <libTMCG.hh>
#include "pipestream.hh"

#undef NDEBUG

int main
	(int argc, char **argv)
{
	mpz_t a, b, aa, bb;
	assert(init_libTMCG());
	
	mpz_init(a), mpz_init(b), mpz_init(aa), mpz_init(bb);
/*	
	for (size_t n = 1; n <= 32; n++)
	{
		PedersenCommitmentScheme *com, *com2;
		std::stringstream foo;
		std::vector<mpz_ptr> m;
		
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
			m.push_back(tmp);
		}
		
		// commit
		std::cout << "*.Commit(...)" << std::endl;
		com->Commit(a, b, m);
		std::cout << "*.CommitBy(...)" << std::endl;
		com->CommitBy(aa, b, m);
		assert(!mpz_cmp(a, aa));
		
		// verify
		std::cout << "*.Verify(...)" << std::endl;
		assert(com->Verify(a, b, m));
		assert(com2->Verify(a, b, m));
		mpz_add_ui(m[0], m[0], 1L);
		assert(!com->Verify(a, b, m));
		assert(!com2->Verify(a, b, m));
		
		// release
		for (size_t i = 0; i < n; i++)
		{
			mpz_clear(m[i]);
			delete m[i];
		}
		m.clear();
		delete com, delete com2;
	}
*/
	size_t n = 32;
	
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
			std::vector<mpz_ptr> m, m_pi;
			std::vector<size_t> pi;
			std::stringstream lej;
			
			mpz_init(c), mpz_init(r);
			com->PublishGroup(*pipe_out), com->PublishGroup(lej);
			GrothSKC *skc = new GrothSKC(n, lej);
			// create the public messages
			for (size_t i = 0; i < n; i++)
			{
				mpz_ptr tmp = new mpz_t(), tmp2 = new mpz_t();
				mpz_init_set_ui(tmp, i), mpz_init_set_ui(tmp2, i);
				m.push_back(tmp), m_pi.push_back(tmp2);
			}
			// create the secret permutation
			for (size_t i = 0; i < n; i++)
			{
				pi.push_back(0);
				bool ok;
				do
				{
					ok = true;
					pi[i] = mpz_srandom_ui() % n;
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
			// commit
			std::cout << "P: m_pi = " << std::flush;
			for (size_t i = 0; i < n; i++)
			{
				mpz_set(m_pi[i], m[pi[i]]);
				std::cout << m_pi[i] << " " << std::flush;
			}
			std::cout << std::endl << "P: com.Commit(...)" << std::endl;
			com->Commit(c, r, m_pi);
			*pipe_out << c << std::endl;
			// prove
			std::cout << "P: skc.Prove_interactive(...)" << std::endl;
			skc->Prove_interactive(pi, r, c, m, *pipe_in, *pipe_out);
			
			// release
			for (size_t i = 0; i < n; i++)
			{
				mpz_clear(m[i]), mpz_clear(m_pi[i]);
				delete m[i], delete m_pi[i];
			}
			m.clear(), m_pi.clear();
			mpz_clear(c), mpz_clear(r);
			delete skc, delete com;
			
			delete pipe_in, delete pipe_out;
			exit(0);
			/* END child code: Prover */
		}
		else
		{
			/* Verifier */
			ipipestream *pipe_in = new ipipestream(pipe2fd[0]);
			opipestream *pipe_out = new opipestream(pipe1fd[1]);
			PedersenCommitmentScheme *com = 
				new PedersenCommitmentScheme(n, *pipe_in);
			std::vector<mpz_ptr> m;
			std::stringstream lej;
			
			// create the public messages
			for (size_t i = 0; i < n; i++)
			{
				mpz_ptr tmp = new mpz_t();
				mpz_init_set_ui(tmp, i);
				m.push_back(tmp);
			}
			// check the commitment scheme and initalize SKC
			assert(com->CheckGroup());
			com->PublishGroup(lej);
			GrothSKC *skc = new GrothSKC(n, lej);
			// receive the commitment
			*pipe_in >> a;
			std::cout << "V: c = " << a << std::endl;
			// verify
			std::cout << "V: skc.Verify_interactive(...)" << std::endl;
			assert(skc->Verify_interactive(a, m, *pipe_in, *pipe_out));
			// release
			for (size_t i = 0; i < n; i++)
			{
				mpz_clear(m[i]);
				delete m[i];
			}
			m.clear();
			delete skc, delete com;
			
			delete pipe_in, delete pipe_out;
		}
		waitpid(pid, NULL, 0);
	}

	mpz_clear(a), mpz_clear(b), mpz_clear(aa), mpz_clear(bb);
	return 0;
}
