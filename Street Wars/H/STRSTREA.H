//
//  strstrea.h	String streams
//
//  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
//
#ifndef _STRSTREAM_H_INCLUDED
#define _STRSTREAM_H_INCLUDED
#if !defined(_ENABLE_AUTODEPEND)
  #pragma read_only_file;
#endif

#ifndef __cplusplus
#error strstrea.h is for use with C++
#endif

#ifndef _COMDEF_H_INCLUDED
 #include <_comdef.h>
#endif
#ifndef _IOSTREAM_H_INCLUDED
 #include <iostream.h>
#endif

// **************************** STRSTREAMBUF *********************************
#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif
class _WPRTLINK strstreambuf : public streambuf {
public:
    strstreambuf();
    strstreambuf( int __allocation_size );
    strstreambuf( void *(*__alloc_fn)( long ), void (*__free_fn)( void * ) );
    strstreambuf( char *__str, int __size, char *__pstart = NULL );
    ~strstreambuf();

    int   alloc_size_increment( int __increment );
    void  freeze( int __freeze = 1 );
    char *str();

    virtual int        overflow( int = EOF );
    virtual int        underflow();
    virtual streambuf *setbuf( char *__ignored, int __allocation_size );
    virtual streampos  seekoff( streamoff     __offset,
                                ios::seekdir  __direction,
                                ios::openmode __mode );
    virtual int        sync();

protected:
    virtual int doallocate();

private:
    void  __strstreambuf( char *, int, char * );

    void *(*__alloc_fn)( long );
    void  (*__free_fn)( void * );
    int   __allocation_size;
    int   __minbuf_size;
    unsigned  __frozen    : 1;
    unsigned  __dynamic   : 1;
    unsigned  __unlimited : 1;
};
#pragma pack(__pop);

inline strstreambuf::strstreambuf() {
    __strstreambuf( NULL, 0, NULL );
}

inline strstreambuf::strstreambuf( char *__ptr, int __size, char *__pstart ) {
    __strstreambuf( __ptr, __size, __pstart );
}

inline int strstreambuf::alloc_size_increment( int __increment ) {
    __lock_it( __b_lock );
    int __old_allocation_size = __allocation_size;
    __allocation_size        += __increment;
    return( __old_allocation_size );
}

inline void strstreambuf::freeze( int __freeze ) {
    __frozen = __freeze ? 1 : 0;
}

// **************************** STRSTREAMBASE ********************************
#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif
class _WPRTLINK strstreambase : public virtual ios {
public:
    strstreambuf *rdbuf() const;

protected:
    strstreambase();
    strstreambase( char *__str, int __size, char *__pstart = NULL );
    ~strstreambase();

private:
    strstreambuf __strstrmbuf;
};
#pragma pack(__pop);

inline strstreambuf *strstreambase::rdbuf() const {
    return( (strstreambuf *) ios::rdbuf() );
}

// ***************************** ISTRSTREAM **********************************
#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif
class _WPRTLINK istrstream : public strstreambase, public istream {
public:
    istrstream(          char *__str );
    istrstream(   signed char *__str );
    istrstream( unsigned char *__str );
    istrstream(          char *__str, int __size );
    istrstream(   signed char *__str, int __size );
    istrstream( unsigned char *__str, int __size );
    ~istrstream();
};
#pragma pack(__pop);

// ***************************** OSTRSTREAM **********************************
#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif
class _WPRTLINK ostrstream : public strstreambase, public ostream {
public:
    ostrstream();
    ostrstream( char          *__str,
                int            __size,
		ios::openmode  __mode = ios::out );
    ostrstream( signed char   *__str,
                int            __size,
		ios::openmode  __mode = ios::out );
    ostrstream( unsigned char *__str,
                int            __size,
		ios::openmode  __mode = ios::out );
    ~ostrstream();

    int   pcount() const;
    char *str();
};
#pragma pack(__pop);

inline char *ostrstream::str() {
    __lock_it( __i_lock );
    return( rdbuf()->str() );
}

inline int ostrstream::pcount() const {
    __lock_it( __i_lock );
    return( rdbuf()->out_waiting() );
}

// ***************************** STRSTREAM ***********************************
#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif
class _WPRTLINK strstream : public strstreambase, public iostream {
public:
    strstream();
    strstream( char          *__str,
               int            __size,
	       ios::openmode  __mode = ios::in|ios::out );
    strstream( signed char   *__str,
               int            __size,
	       ios::openmode  __mode = ios::in|ios::out );
    strstream( unsigned char *__str,
               int            __size,
	       ios::openmode  __mode = ios::in|ios::out );
    ~strstream();

    char *str();
};
#pragma pack(__pop);

inline char *strstream::str() {
    __lock_it( __i_lock );
    return( rdbuf()->str() );
}

#endif
