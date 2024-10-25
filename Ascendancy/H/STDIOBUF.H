//
//  stdiobuf.h	Standard I/O streams
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _STDIOBUF_H_INCLUDED

#ifndef __cplusplus
#error stdiobuf.h is for use with C++
#endif

#include <stdio.h>
#include <iostream.h>

// **************************** STDIOBUF *************************************
#pragma pack(1);
class stdiobuf : public streambuf {
public:
    stdiobuf();
    stdiobuf( FILE *__fptr );
    ~stdiobuf();

    FILE *stdiofile();
    
    virtual int overflow( int = EOF );
    virtual int underflow();
    virtual int	sync();

private:
    FILE *__file_pointer;
    char __unbuffered_get_area[ DEFAULT_PUTBACK_SIZE+1 ];
    int : 0;
};
#pragma pack();

inline FILE *stdiobuf::stdiofile() {
    return __file_pointer;
}

#define _STDIOBUF_H_INCLUDED
#endif
