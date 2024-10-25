//
//  complex.h	Complex Numbers
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _COMPLEX_H_INCLUDED

#ifndef __cplusplus
#error complex.h is for use with C++
#endif

#if defined(__SW_FPC)
#if defined(__386__)
#if defined(__3S__)
#pragma library ( "cplx3s.lib" )
#else
#pragma library ( "cplx3r.lib" )
#endif
#else
#if defined(__MEDIUM__)
#pragma library ( "cplxm.lib" )
#elif defined(__COMPACT__)
#pragma library ( "cplxc.lib" )
#elif defined(__LARGE__)
#pragma library ( "cplxl.lib" )
#elif defined(__HUGE__)
#pragma library ( "cplxh.lib" )
#else
#pragma library ( "cplxs.lib" )
#endif
#endif
#else
#if defined(__386__)
#if defined(__3S__)
#pragma library ( "cplx73s.lib" )
#else
#pragma library ( "cplx73r.lib" )
#endif
#else
#if defined(__MEDIUM__)
#pragma library ( "cplx7m.lib" )
#elif defined(__COMPACT__)
#pragma library ( "cplx7c.lib" )
#elif defined(__LARGE__)
#pragma library ( "cplx7l.lib" )
#elif defined(__HUGE__)
#pragma library ( "cplx7h.lib" )
#else
#pragma library ( "cplx7s.lib" )
#endif
#endif
#endif

#include <iostream.h>
#pragma pack(1);
class Complex {
    double  __r;
    double  __i;

public:
    Complex();
    Complex( Complex const & );
    Complex( double __real, double __imag = 0.0 );

    Complex &operator = ( Complex const & );
    Complex &operator = ( double );
    Complex &operator += ( Complex const & );
    Complex &operator += ( double );
    Complex &operator -= ( Complex const & );
    Complex &operator -= ( double );
    Complex &operator *= ( Complex const & );
    Complex &operator *= ( double );
    Complex &operator /= ( Complex const & );
    Complex &operator /= ( double );

    Complex operator + () const;
    Complex operator - () const;

    double imag () const;
    double real () const;

    friend istream &operator >> ( istream &__strm, Complex &__cv );
    friend ostream &operator << ( ostream &__strm, Complex const &__cv );
};
#pragma pack();

typedef Complex complex;	// for compatibility

Complex operator + ( Complex const &, Complex const & );
Complex operator + ( Complex const &, double );
Complex operator + ( double,	      Complex const & );
Complex operator - ( Complex const &, Complex const & );
Complex operator - ( Complex const &, double );
Complex operator - ( double,	      Complex const & );
Complex operator * ( Complex const &, Complex const & );
Complex operator * ( Complex const &, double );
Complex operator * ( double,	      Complex const & );
Complex operator / ( Complex const &, Complex const & );
Complex operator / ( Complex const &, double );
Complex operator / ( double,	      Complex const & );

int operator == ( Complex const &, Complex const & );
int operator == ( Complex const &, double );
int operator == ( double,	   Complex const & );
int operator != ( Complex const &, Complex const & );
int operator != ( Complex const &, double );
int operator != ( double,	   Complex const & );

double  abs  ( Complex const & );	    // magnitude of vector
Complex acos ( Complex const & );	    // arccosine
Complex acosh( Complex const & );	    // hyperbolic arccosine
double  arg  ( Complex const & );	    // angle of vector
Complex asin ( Complex const & );	    // arcsin
Complex asinh( Complex const & );	    // hyperbolic arcsin
Complex atan ( Complex const & );	    // arctangent
Complex atanh( Complex const & );	    // hyperbolic arctangent
Complex conj ( Complex const & );	    // conjugate
Complex cos  ( Complex const & );	    // cosine
Complex cosh ( Complex const & );	    // hyperbolic cosine
Complex exp  ( Complex const & );	    // e raised to a power
double  imag ( Complex const & );	    // imaginary part
Complex log  ( Complex const & );	    // log base e
Complex log10( Complex const & );	    // log base 10
double  norm ( Complex const & );	    // square of magnitude
Complex polar( double __mag,
	       double __angle = 0 );	    // polar to Complex
Complex pow  ( Complex const &__base,	    // Complex ** Complex
	       Complex const &__power );
Complex pow  ( Complex const &__base,	    // Complex ** double
	       double         __power );
Complex pow  ( double	      __base,	    // double ** Complex
	       Complex const &__power );
Complex pow  ( Complex const &__base,	    // Complex ** int
	       int            __power );
double  real ( Complex const & );	    // real part
Complex sin  ( Complex const & );	    // sin
Complex sinh ( Complex const & );	    // hyperbolic sin
Complex sqrt ( Complex const & );	    // square root
Complex tan  ( Complex const & );	    // tan
Complex tanh ( Complex const & );	    // hyperbolic tangent

inline Complex::Complex() {
    __r = 0.0;
    __i = 0.0;
}

inline Complex::Complex( Complex const &__cv ) {
    __r = __cv.__r;
    __i = __cv.__i;
}

inline Complex::Complex( double __real, double __imag ) {
    __r = __real;
    __i = __imag;
}

inline Complex &Complex::operator = ( Complex const &__cv ) {
    __r = __cv.__r;
    __i = __cv.__i;
    return( *this );
}

inline Complex &Complex::operator = ( double __dv ) {
    __r = __dv;
    __i = 0.0;
    return( *this );
}

inline Complex &Complex::operator += ( Complex const &__cv ) {
    __r += __cv.__r;
    __i += __cv.__i;
    return( *this );
}

inline Complex &Complex::operator += ( double __dv ) {
    __r += __dv;
    return( *this );
}

inline Complex &Complex::operator -= ( Complex const &__cv ) {
    __r -= __cv.__r;
    __i -= __cv.__i;
    return( *this );
}

inline Complex &Complex::operator -= ( double __dv ) {
    __r -= __dv;
    return( *this );
}

inline Complex &Complex::operator *= ( double __dv ) {
    __r *= __dv;
    __i *= __dv;
    return( *this );
}

inline Complex &Complex::operator /= ( double __dv ) {
    __r /= __dv;
    __i /= __dv;
    return( *this );
}

inline Complex operator + ( Complex const &__cv1, Complex const &__cv2 ) {
    return Complex( __cv1.real() + __cv2.real(), __cv1.imag() + __cv2.imag() );
}

inline Complex operator + ( Complex const &__cv, double __dv ) {
    return Complex( __cv.real() + __dv, __cv.imag() );
}

inline Complex operator + ( double __dv, Complex const &__cv ) {
    return Complex( __dv + __cv.real(), __cv.imag() );
}

inline Complex operator - ( Complex const &__cv1, Complex const &__cv2 ) {
    return Complex( __cv1.real() - __cv2.real(), __cv1.imag() - __cv2.imag() );
}

inline Complex operator - ( Complex const &__cv, double __dv ) {
    return Complex( __cv.real() - __dv, __cv.imag() );
}

inline Complex operator - ( double __dv, Complex const &__cv ) {
    return Complex( __dv - __cv.real(), - __cv.imag() );
}

inline Complex operator * ( Complex const &__cv1, Complex const &__cv2 ) {
    return Complex( __cv1.real()*__cv2.real() - __cv1.imag()*__cv2.imag(),
		    __cv1.imag()*__cv2.real() + __cv1.real()*__cv2.imag() );
}

inline Complex operator * ( Complex const &__cv, double __dv ) {
    return Complex( __cv.real() * __dv, __cv.imag() * __dv );
}

inline Complex operator * ( double __dv, Complex const &__cv ) {
    return Complex( __dv * __cv.real(), __dv * __cv.imag() );
}

inline Complex operator / ( Complex const &__cv, double __dv ) {
    return Complex( __cv.real() / __dv, __cv.imag() / __dv );
}

inline Complex Complex::operator + () const {
    return( *this );
}

inline Complex Complex::operator - () const {
    return Complex( -__r, -__i );
}

inline int operator == ( Complex const &__cv1, Complex const &__cv2 ) {
    return( __cv1.real() == __cv2.real()  &&  __cv1.imag() == __cv2.imag() );
}

inline int operator == ( Complex const &__cv, double __dv ) {
    return( __cv.imag() == 0.0  &&  __cv.real() == __dv );
}

inline int operator == ( double __dv, Complex const &__cv ) {
    return( __cv.imag() == 0.0  &&  __dv == __cv.real() );
}

inline int operator != ( Complex const &__cv1, Complex const &__cv2 ) {
    return( __cv1.real() != __cv2.real()  ||  __cv1.imag() != __cv2.imag() );
}

inline int operator != ( Complex const &__cv, double __dv ) {
    return( __cv.imag() != 0.0  ||  __cv.real() != __dv );
}

inline int operator != ( double __dv, Complex const &__cv ) {
    return( __cv.imag() != 0.0  ||  __dv != __cv.real() );
}

inline Complex conj( Complex const &__cv ) {
    return Complex( __cv.real(), -__cv.imag() );
}

inline double Complex::real() const {
    return( __r );
}

inline double real( Complex const &__cv ) {
    return( __cv.real() );
}

inline double Complex::imag() const {
    return( __i );
}

inline double imag( Complex const &__cv ) {
    return( __cv.imag() );
}

inline double norm( Complex const &__cv ) {
    return( __cv.real() * __cv.real() + __cv.imag() * __cv.imag() );
}


#define _COMPLEX_H_INCLUDED
#endif
