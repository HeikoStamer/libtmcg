/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 1999, 2000 Kevin Birch <kbirch@pobox.com>,
               2002, 2004, 2005, 2007 Heiko Stamer <stamer@gaos.org>

   LibTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_pipestream_HH
	#define INCLUDED_pipestream_HH

/*!
 * @module pipestream
 * @author Kevin Birch <kbirch@pobox.com>,
 *         Heiko Stamer <stamer@gaos.org>
 * @version 1.0, 01/15/00
 * This C++ class is designed to allow the use of BSD-style
 * pipe/file descriptors by applications that use iostreams.
 */

/**
 * This structure defines the behavior of the pipestream class.
 * If you wish to modify the behavior of pipestream, you should derive
 * from this struct and change the return values of its methods. */
struct pipebuf_traits
{
	/** @returns True, if output is buffered. */
	static inline bool buffer_output
		()
	{
		return false;
	}
	/** @returns the maximum size in bytes of the output buffer. */
	static inline size_t o_buffer_sz
		()
	{
		return 512;
	}
	/** @returns the maximum size in bytes of the input buffer. */
	static inline size_t i_buffer_sz
		()
	{
		return 1024;
	}
	/** @returns the size in bytes of the putback area of the
	    input buffer, used by unget. */
	static inline size_t putback_sz
		()
	{
		return 4;
	}
};

/** This is used by basic_pipebuf to comply with streambuf. */
typedef int int_type;

/** This is the class that drives the ability to attach a pipe to
    an iostream. It handles input and output buffers, and reading
    from and writing to a pipe. */
template <class traits = pipebuf_traits> class basic_pipebuf :
	public std::streambuf
{
	protected:
		/** The pipe to operate on. */
		int mPipe;
		/** The read buffer. */
		char *mRBuffer;
		/** The write buffer. */
		char *mWBuffer;
		
		size_t numWrite, numRead;
	
	public:
		/** This is a convenience for instatiations. */
		typedef traits traits_type;
		
		/** The primary constructor, which takes an open pipe as its only argument.
		    @param iPipe is an open pipe. */
		basic_pipebuf
			(int iPipe) : mPipe(iPipe)
		{
			mRBuffer = new char[traits_type::i_buffer_sz()];
			mWBuffer = new char[traits_type::o_buffer_sz()];
			if (traits_type::buffer_output())
			{
				setp(mWBuffer, mWBuffer+(traits_type::o_buffer_sz()-1));
			}
			char *pos = mRBuffer+traits_type::putback_sz();
			setg(pos, pos, pos);
			numWrite = 0, numRead = 0;
		}
		
		/** This destructor releases all occupied resources. */
		~basic_pipebuf
			()
		{
			delete [] mRBuffer;
			delete [] mWBuffer;
			sync();
		}
	
	protected:
		/** Flushes the write buffer to the pipe, and resets the write buffers
		    head pointer.
		    @returns The number of bytes written to the pipe. */
		int flushOutput
			()
		{
			int num = pptr() - pbase();
			if (write(mPipe, mWBuffer, num) != num)
				return EOF;
			pbump(-num);
			numWrite += num;
			return num;
		}
		
		/** This method is called by streambuf when the write buffer is full.
		    @param c is the character that overflowed the write buffer.
		    @returns The character that overflowed the write buffer. */
		virtual int_type overflow
			(int_type c)
		{
			if (traits_type::buffer_output())
			{
				*pptr() = c;
				pbump(1);
				if (flushOutput() == EOF)
					return EOF;
				return c;
			}
			else
			{
				if (c != EOF)
				{
					char z = c;
					if (write(mPipe, &z, 1) != 1)
						return EOF;
					numWrite += 1;
				}
				return c;
			}
		}
		
		/** This method is called by streambuf when the endl or flush operators
		    are used.
		    @returns -1, if the write buffer flush failed. */
		virtual int sync
			()
		{
			if (flushOutput() == EOF)
				return -1;
			return 0;
		}
		
		/** This method is called by streambuf to write a buffer to the output
		    device, i.e. the pipe.
		    @param s is the buffer to be written.
		    @param num is the size of @a s.
		    @returns The number of bytes written. */
		virtual std::streamsize xsputn
			(const char *s, std::streamsize num)
		{
			numWrite += num;
			return (write(mPipe, s, num));
		}
		
		/** This method is called by streambuf when the read buffer is empty.
		    @returns The next character to be read or EOF on failure. */
		virtual int_type underflow
			()
		{
			if (gptr() < egptr())
				return *gptr();
			
			size_t numPutBack = gptr() - eback();
			if (numPutBack > traits_type::putback_sz())
				numPutBack = traits_type::putback_sz();
			std::memcpy(mRBuffer+(traits_type::putback_sz() - numPutBack),
				gptr() - numPutBack, numPutBack);
			
			size_t bufsiz = traits_type::i_buffer_sz() - 
				traits_type::putback_sz();
			int count;
			while (1)
			{
				count = read(mPipe, mRBuffer+traits_type::putback_sz(),
					bufsiz);
				numRead += count;
				if (count == 0)
					return EOF;
				else if (count == -1)
				{
					if (errno == EAGAIN || errno == EINTR)
						continue;
					else
						return EOF;
				}
				else
					break;
			}
			setg(mRBuffer+(traits_type::putback_sz()-numPutBack),
				mRBuffer+traits_type::putback_sz(), 
				mRBuffer+traits_type::putback_sz()+count);
			
			return *gptr();
		}
		
	public:
		size_t get_numRead
			()
		{
			return numRead;
		}
		size_t get_numWrite
			()
		{
			return numWrite;
		}
};

/** Make the name pipebuf a basic_pipebuf with the default traits. */
typedef basic_pipebuf<> pipebuf;

/** An istream subclass that uses a pipebuf. Create one if you wish to
    have a read-only pipe attached to an istream. */
class ipipestream : public std::istream
{
	protected:
		/** The corresponding basic_pipebuf. */
		pipebuf buf;
	
	public:
		/** The primary constructor, which takes an open pipe as its only argument.
		    @param iPipe is an open pipe. */
		ipipestream
			(int iPipe) : std::istream(&buf), buf(iPipe)
		{
		}
		
		size_t get_numRead
			()
		{
			return buf.get_numRead();
		}
		size_t get_numWrite
			()
		{
			return buf.get_numWrite();
		}
};

/** An ostream subclass that uses a pipebuf. Create one if you wish to
    have a write-only pipe attached to an ostream. */
class opipestream : public std::ostream
{
	protected:
		/** The corresponding basic_pipebuf. */
		pipebuf buf;
	
	public:
		/** The primary constructor, which takes an open pipe as its only argument.
		    @param oPipe is an open pipe. */
		opipestream
			(int oPipe) : std::ostream(&buf), buf(oPipe)
		{
		}
		
		size_t get_numRead
			()
		{
			return buf.get_numRead();
		}
		size_t get_numWrite
			()
		{
			return buf.get_numWrite();
		}
};

/** An iostream subclass that uses a pipebuf. Create one if you wish to
    have a read and write pipe attached to an iostream. */
class iopipestream : public std::iostream
{
	protected:
		/** The corresponding basic_pipebuf. */
		pipebuf buf;
	
	public:
		/** The primary constructor, which takes an open pipe as its only argument.
		    @param ioPipe is an open pipe. */
		iopipestream
			(int ioPipe) : std::iostream(&buf), buf(ioPipe)
		{
		}
		
		size_t get_numRead
			()
		{
			return buf.get_numRead();
		}
		size_t get_numWrite
			()
		{
			return buf.get_numWrite();
		}
};

#endif
