/*******************************************************************************
   This file is part of SecureSkat.

 Copyright (C) 1999, 2000 Kevin Birch <kbirch@pobox.com>,
               2002, 2004 Heiko Stamer <stamer@gaos.org>

   SecureSkat is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*******************************************************************************/

#ifndef INCLUDED_pipestream_HH
	#define INCLUDED_pipestream_HH

/*!
 * @module pipestream
 * @author Kevin Birch <kbirch@pobox.com>, Heiko Stamer <stamer@gaos.org>
 * @version 1.0, 01/15/00
 * This C++ class is designed to allow the use of BSD-style
 * pipe descriptors by applications that use iostreams.
 */

/*!
 * @struct pipebuf_traits
 * This structure defines the behavior of the pipestream class.<P>
 * If you wish to modify the behavior of pipestream, you should subclass
this struct
 * and change the return values of its methods.
 * @method buffer_output
 * @return true of output is buffered
 * @method o_buffer_sz
 * @return maximum size in bytes of the output buffer
 * @method i_buffer_sz
 * @return maximum size in bytes of the input buffer
 * @method putback_sz
 * @return size in bytes of the putback area of the input buffer, used by
unget
 */
struct pipebuf_traits {
    static inline bool buffer_output() { return false; }
    static inline size_t o_buffer_sz() { return 512; }
    static inline size_t i_buffer_sz() { return 1024; }
    static inline size_t putback_sz() { return 4; }
};

/*!
 * @typedef int_type
 * used by basic_pipebuf to comply with streambuf
 */
typedef int int_type;

/*!
 * @class basic_pipebuf
 * This is the class that drives the ability to attach a pipe to an
iostream.  It
 * handles input and output buffers, and reading from and writing to the
 * network
 */
template <class traits = pipebuf_traits>
class basic_pipebuf : public std::streambuf {
protected:
    int mPipe;    /*! @member mPipe The pipe to operate on */
    char *mRBuffer; /*! @member mRBuffer the read buffer */
    char *mWBuffer; /*! @member mWBuffer the write buffer */
    
public:
    typedef traits traits_type; /*! @typedef traits_type a convenience for
clients */

        /*! @method basic_pipebuf
         * The primary constructor, which takes an open pipe as its only
argument
         * @param iPipe an open pipe
         */
    basic_pipebuf(int iPipe) : mPipe(iPipe) {
        mRBuffer = new char[traits_type::i_buffer_sz()];
        mWBuffer = new char[traits_type::o_buffer_sz()];
        if (traits_type::buffer_output()) {
            setp(mWBuffer, mWBuffer+(traits_type::o_buffer_sz()-1));
        }
        char *pos = mRBuffer+traits_type::putback_sz();
        setg(pos, pos, pos);
    }

        /*! @method ~basic_pipebuf()
         * The destructor
         */
    ~basic_pipebuf() {
        delete [] mRBuffer;
        delete [] mWBuffer;
        sync();
    }
    
protected:
        /*! @method flushOutput
         * flushes the write buffer to the pipe, and resets the write
buffer head
         * pointer
         * @return number of bytes written to the pipe
         */
    int flushOutput() {
        int num = pptr()-pbase();
        if(write(mPipe, mWBuffer, num) != num) {
            return EOF;
        }
        pbump(-num);
        return(num);
    }

    /*! @method overflow
         * called by std::streambuf when the write buffer is full
         * @param c the character that overflowed the write buffer
         * @return the character that overflowed the write buffer
         */
    virtual int_type overflow(int_type c) {
        if(traits_type::buffer_output()) {
            *pptr() = c;
            pbump(1);
            
            if(flushOutput() == EOF) {
                return EOF;
            }
            return c;
        } else {
            if(c != EOF) {
                char z = c;
                if(write(mPipe, &z, 1) != 1) {
                    return EOF;
                }
            }
            return c;
        }
    }

        /*! @method sync
         * called by std::streambuf when the endl or flush operators are
used
         * @return -1 if the write buffer flush failed
         */
    virtual int sync() {
        if(flushOutput() == EOF) {
            return -1;
        }
        return 0;
    }

    /*! @method xsputn
         * called by std::streambuf to write a buffer to the output device
         * @param s the buffer to be written
         * @param num the size of s
         * @return the number of bytes written
         */
    virtual std::streamsize xsputn(const char *s, std::streamsize num) {
        return(write(mPipe, s, num));
    }

        /*! @method underflow
         * called by std::streambuf when the read buffer is empty
         * @return the next character to be read or EOF on failure
         */
    virtual int_type underflow() {
        if(gptr() < egptr()) {
            return *gptr();
        }
        
        size_t numPutBack = gptr() - eback();
        if(numPutBack > traits_type::putback_sz()) {
            numPutBack = traits_type::putback_sz();
        }
        
        std::memcpy(mRBuffer+(traits_type::putback_sz()-numPutBack),
gptr()-numPutBack, 
                    numPutBack);
        
        size_t bufsiz = traits_type::i_buffer_sz() -
traits_type::putback_sz();
        int count;
        while(1) {
            count = read(mPipe, mRBuffer+traits_type::putback_sz(),
bufsiz);
            if(count == 0) {
                return EOF;
            } else if(count == -1) {
                if(errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    return EOF;
            } else {
                break;
            }
        }
        
        setg(mRBuffer+(traits_type::putback_sz()-numPutBack), 
             mRBuffer+traits_type::putback_sz(), 
             mRBuffer+traits_type::putback_sz()+count);
        
        return *gptr();
    } 
};

/*! @typedef pipebuf
 * make the name pipebuf a basic_pipebuf with the default traits
 */
typedef basic_pipebuf<> pipebuf;

/*! @class ipipestream
 * An istream subclass that uses a pipebuf.  Create one if you wish to
have
 * a read-only pipe attached to an istream.
 */
class ipipestream : public std::istream {
protected:
    pipebuf buf; /*! @member buf the pipebuf */
    
public:
        /*! @method ipipestream
         * The primary constructor, which takes an open pipe as its only
argument
         * @param iPipe an open pipe
         */
    ipipestream(int iPipe) : std::istream(&buf), buf(iPipe) {}

};

/*! @class opipestream
 * An ostream subclass that uses a pipebuf.  Create one if you wish to
have
 * a write-only pipe attached to an ostream.
 */
class opipestream : public std::ostream {
protected:
    pipebuf buf; /*! @member buf the pipebuf */
    
public:
        /*! @method opipestream
         * The primary constructor, which takes an open pipe as its only
argument
         * @param iPipe an open pipe
         */
    opipestream(int iPipe) : std::ostream(&buf), buf(iPipe) {}
};

/*! @class iopipestream
 * An iostream subclass that uses a pipebuf.  Create one if you wish to
have
 * a read/write pipe attached to an iostream.
 */
class iopipestream : public std::iostream {
protected:
    pipebuf buf; /*! @member buf the pipebuf */
    
public:
        /*! @method iopipestream
         * The primary constructor, which takes an open pipe as its only
argument
         * @param iPipe an open pipe
         */
    iopipestream(int iPipe) : std::iostream(&buf), buf(iPipe) {}

};

#endif
