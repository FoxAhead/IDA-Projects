//
//  fstream.h	File I/O streams
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _FSTREAM_H_INCLUDED

#ifndef __cplusplus
#error fstream.h is for use with C++
#endif

#include <iostream.h>

// POSIX file handle:
typedef int filedesc;

// **************************** FILEBUF **************************************
#pragma pack(1);
class filebuf : public streambuf {
public:
    static int const openprot;	// default file protection

    filebuf();
    filebuf( filedesc __fd );
    filebuf( filedesc __fd, char *__buf, int __len );
    ~filebuf();

    int       is_open() const;
    filedesc  fd() const;
    filebuf  *attach( filedesc __fd );
    filebuf  *open( char const    *__name,
                    ios::openmode  __mode,
                    int            __prot = openprot );
    filebuf  *close();

    virtual int        pbackfail( int __c );
    virtual int        overflow( int = EOF );
    virtual int        underflow();
    virtual streambuf *setbuf( char *__buf, int __len );
    virtual streampos  seekoff( streamoff     __offset,
                                ios::seekdir  __direction,
                                ios::openmode __ignored );
    virtual int        sync();

private:
    filedesc      __file_handle;
    ios::openmode __file_mode;
    char	  __unbuffered_get_area[ DEFAULT_PUTBACK_SIZE+1 ];
    char          __attached : 1;
    int		  : 0;
};
#pragma pack();

inline filedesc filebuf::fd() const {
    return( __file_handle );
}

inline int filebuf::is_open() const {
    return( __file_handle != EOF );
}

// **************************** FSTREAMBASE **********************************
#pragma pack(1);
class fstreambase : virtual public ios {
public:
    int       is_open() const;
    filedesc  fd() const;
    void      attach( filedesc __fd );
    void      open( char const    *__name,
                    ios::openmode  __mode,
                    int            __prot = filebuf::openprot );
    void      close();
    filebuf  *rdbuf() const;
    void      setbuf( char *__buf, int __len );

protected:
    fstreambase();
    fstreambase( char const    *__name,
                 ios::openmode  __mode,
                 int            __prot = filebuf::openprot );
    fstreambase( filedesc __fd );
    fstreambase( filedesc __fd, char *__buf, int __len );
    ~fstreambase();

private:
    filebuf   __flbuf;
};
#pragma pack();

inline filedesc fstreambase::fd() const {
    __lock_it( __i_lock );
    filebuf *__fb = rdbuf();
    return( (__fb == NULL) ? EOF : __fb->fd() );
}

inline int fstreambase::is_open() const {
    __lock_it( __i_lock );
    filebuf *__fb = rdbuf();
    return( (__fb == NULL) ? 0 : __fb->is_open() );
}

inline filebuf *fstreambase::rdbuf() const {
    return( (filebuf *) ios::rdbuf() );
}

// **************************** IFSTREAM *************************************
#pragma pack(1);
class ifstream : public fstreambase, public istream {
public:
    ifstream();
    ifstream( char const    *__name,
              ios::openmode  __mode = ios::in,
              int            __prot = filebuf::openprot );
    ifstream( filedesc __fd );
    ifstream( filedesc __fd, char *__buf, int __len );
    ~ifstream();

    void open( char const    *__name,
               ios::openmode  __mode = ios::in,
               int            __prot = filebuf::openprot );
};
#pragma pack();

inline void ifstream::open( char const *__n, ios::openmode __m, int __p ) {
    fstreambase::open( __n, __m, __p );
}

// **************************** OFSTREAM *************************************
#pragma pack(1);
class ofstream : public fstreambase, public ostream {
public:
    ofstream();
    ofstream( char const    *__name,
              ios::openmode  __mode = ios::out,
              int            __prot = filebuf::openprot );
    ofstream( filedesc __fd );
    ofstream( filedesc __fd, char *__buf, int __len );
    ~ofstream();

    void open( char const    *__name,
               ios::openmode  __mode = ios::out,
               int            __prot = filebuf::openprot );
};
#pragma pack();

inline void ofstream::open( char const *__n, ios::openmode __m, int __p ) {
    fstreambase::open( __n, __m, __p );
}

// **************************** FSTREAM **************************************
#pragma pack(1);
class fstream : public fstreambase, public iostream {
public:
    fstream();
    fstream( char const    *__name,
             ios::openmode  __mode = ios::in|ios::out,
             int            __prot = filebuf::openprot );
    fstream( filedesc __fd );
    fstream( filedesc __fd, char *__buf, int __len );
    ~fstream();

    void open( char const    *__name,
               ios::openmode  __mode = ios::in|ios::out,
               int            __prot = filebuf::openprot );
};
#pragma pack();

inline void fstream::open( char const *__n, ios::openmode __m, int __p ) {
    fstreambase::open( __n, __m, __p );
}

#define _FSTREAM_H_INCLUDED
#endif
