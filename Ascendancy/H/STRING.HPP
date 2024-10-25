//
//  string.h	Strings
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _STRING_HPP_INCLUDED

#ifndef __cplusplus
#error string.hpp is for use with C++
#endif

#include <ctype.h>
#include <stddef.h>
#include <iostream.h>

const size_t NPOS = (size_t) -1;
    
// Define a typedef for a "C" function
extern "C" {
typedef int (*__zapcase_t)( int );
};

class String {
public:

    typedef enum {
	default_size,
	reserve
    } capacity;
                                                // constructors
    String();                                   //   default
    String( size_t, capacity );                 //   with specified size
    String( String const &,                     //   from another String
	    size_t __pos = 0,
	    size_t __n = NPOS );
    String( char const *, size_t __n = NPOS );  //   from C string
    String( char, size_t __rep = 1 );           //   from single character

    ~String();                                  // destructor

                                                // conversion operators
    operator char const * ();			//   to C string
    operator char const * () const;             //   to C string
    operator char () const;                     //   to single character

                                                // assignment operators
    String & operator = ( String const & );     //   from another String
    String & operator = ( char const * );       //   from a C string

                                                // append operators
    String & operator += ( String const & );    //   a String
    String & operator += ( char const * );      //   a C string

    String operator () ( size_t __pos,          // substring operator
                         size_t __len ) const;

    char & operator () ( size_t __pos );        // reference-to-char operator
    char const & operator ()
		       ( size_t __pos ) const;  // reference-to-char operator
    char & operator [] ( size_t __pos );        // subscript operator
    char const & operator []
		       ( size_t __pos ) const;  // subscript operator

                                                // comparison operators
    friend int operator == ( String const &,
                             String const & );  //   String == String?
    friend int operator == ( String const &,
                             char const * );    //   String == C string?
    friend int operator == ( char const *,
                             String const & );  //   C string == String?
    friend int operator == ( String const &,
                             char );            //   String == character?
    friend int operator == ( char,
                             String const & );  //   character == String?

    friend int operator != ( String const &,
                             String const & );  //   String != String?
    friend int operator != ( String const &,
                             char const * );    //   String != C string?
    friend int operator != ( char const *,
                             String const & );  //   C string != String?
    friend int operator != ( String const &,
                             char );            //   String != character?
    friend int operator != ( char,
                             String const & );  //   character != String?

    friend int operator < ( String const &,
                            String const & );   //   String < String?
    friend int operator < ( String const &,
                            char const * );     //   String < C string?
    friend int operator < ( char const *,
                            String const & );   //   C string < String?
    friend int operator < ( String const &,
                            char );             //   String < character?
    friend int operator < ( char,
                            String const & );   //   character < String?

    friend int operator <= ( String const &,
                             String const & );  //   String <= String?
    friend int operator <= ( String const &,
                             char const * );    //   String <= C string?
    friend int operator <= ( char const *,
                             String const & );  //   C string <= String?
    friend int operator <= ( String const &,
                             char );            //   String <= character?
    friend int operator <= ( char,
                             String const & );  //   character <= String?

    friend int operator > ( String const &,
                            String const & );   //   String > String?
    friend int operator > ( String const &,
                            char const * );     //   String > C string?
    friend int operator > ( char const *,
                            String const & );   //   C string > String?
    friend int operator > ( String const &,
                            char );             //   String > character?
    friend int operator > ( char,
                            String const & );   //   character > String?

    friend int operator >= ( String const &,
                             String const & );  //   String >= String?
    friend int operator >= ( String const &,
                             char const * );    //   String >= C string?
    friend int operator >= ( char const *,
                             String const & );  //   C string >= String?
    friend int operator >= ( String const &,
                             char );            //   String >= character?
    friend int operator >= ( char,
                             String const & );  //   character >= String?

                                                // concatenate string operators
    friend String operator + ( String const &,
                               String const & );//   String + String
    friend String operator + ( String const &,
                               char const * );  //   String + C string
    friend String operator + ( char const *,
                               String const & );//   C string + String
    friend String operator + ( String const &,
                               char );          //   String + character
    friend String operator + ( char,
                               String const & );//   character + String

                                                // input/output operators
    friend istream & operator >> ( istream &, String & );	// input
    friend ostream & operator << ( ostream &, String const & ); // output

// Member functions:
    size_t length() const;                  // length of String

    char const & get_at( size_t ) const;    // get the n'th character
    void put_at( size_t, char );	    // replace the n'th character

                                            // find differing character loc
    int match( String const & ) const;      //   search string is a String
    int match( char const *   ) const;      //   search string is a C string

                                            // find substring location
    int index( String const &,              //   search string is a String
               size_t __pos = 0 ) const;
    int index( char const *,                //   search string is a C string
               size_t __pos = 0 ) const;

                                            // letter case conversion
    String upper() const;                   //   to upper case
    String lower() const;                   //   to lower case

    int operator ! () const;                // invalid String?
    int valid() const;                      // valid String?
    friend int valid( String const & );     // valid String?

    int alloc_mult_size() const;            // get string_mult_size
    int alloc_mult_size( int __mult );      // get/set string_mult_size

private:

    class StringRep {
    public:
	size_t  __refcount;
	size_t  __avail_length;
	size_t  __used_length;
	char    __value[1];           // variable length
    };

    StringRep	*__srep;
    size_t	__offset;
    size_t	__slength;
    char	*__c_string;

    // Memory for StringRep's is allocated in multiples of string_mult_size
    static size_t __string_mult_size;
    static char   __ref_char;

    static StringRep *__AllocStringRep( StringRep *, size_t );
    static int	      __CompareStrings( String const &, String const & );
    void   __AppendToStringRep( String const &, char const *, size_t );
    void   __FreeStringRep();
    void   __JoinStrings( char const *, size_t, char const *, size_t );
    String __ZapCase( __zapcase_t ) const;
};

inline char &String::operator [] ( size_t __pos ) {
    return( this->operator()( __pos ) );
}

inline char const &String::operator [] ( size_t __pos ) const {
    return( this->operator()( __pos ) );
}

inline char const &String::get_at( size_t __pos ) const {
    return( this->operator()( __pos ) );
}

inline void String::put_at( size_t __pos, char __c ) {
    if( __pos < __slength ) {
	this->operator()( __pos ) = __c;
    } else if( __pos == __slength ) {
	*this += __c;
    }
}

inline String String::upper() const {
    return( __ZapCase( &::toupper ) );
}

inline String String::lower() const {
    return( __ZapCase( &::tolower ) );
}

inline int String::operator ! () const {
    return( __srep == NULL );
}

inline int String::valid() const {
    return( __srep != NULL );
}

inline int valid( String const &__s ) {
    return( __s.__srep != NULL );
}

inline size_t String::length() const {
    return( __slength );
}

inline int String::alloc_mult_size() const {
    return( String::__string_mult_size );
}

#define _STRING_HPP_INCLUDED
#endif
