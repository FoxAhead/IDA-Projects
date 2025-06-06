/****************************************************************************
*
*						   The Zen Timer Library
*
*							   From the book
*						 "Zen of Assembly Language"
*							Volume 1, Knowledge
*
*							 by Michael Abrash
*
*					  Modifications by Kendall Bennett
*                   Copyright (C) 1993-4 SciTech Software
*
* Filename:		$RCSfile: ztimer.h $
* Version:		$Revision: 1.11 $
*
* Language:		ANSI C, C++ 2.1
* Environment:	IBM PC (MS DOS)
*
* Description:	Header file for the Zen Timer library. Provides a number
*				of routines to accurately time segments of code. A long
*				period timer is provided to time code that takes up to
*				one hour to execute, with microsecond precision, and an
*				ultra long period timer for timing code that takes up to
*				24 hours to execute (raytracing etc).
*
*				We also provide a set of C++ classes to manipulate
*				the Zen Timers. Note that you can only have one LZTimer
*				running at a time (you can have multiple ULZTimers however),
*				and that the total aggregate time of thr ULZTimer is about
*				65,000 hours, which should suit most timing purposes.
*
*				Note that the precision Zen Timer is no longer supported.
*				This time doesn't work properly in 32 bit protected mode,
*				and we found that in practice it never got used, since we
*				always used the LZTimer instead.
*
* $Id: ztimer.h 1.11 1994/08/22 11:56:19 kjb release $
*
****************************************************************************/

#ifndef	__ZTIMER_H
#define	__ZTIMER_H

#ifndef __DEBUG_H
#include "debug.h"
#endif

/*-------------------------- Function Prototypes --------------------------*/

#define	LZTIMER_RES		1e-6			/* Seconds in a tick			*/
#define	ULZTIMER_RES	0.054925		/* Seconds in a tick			*/

#ifdef	__cplusplus
extern "C" {			/* Use "C" linkage when in C++ mode	*/
#endif

/* Routine to initialise the library - you MUST call this first! */

void	ZTimerInit(void);

/* Long period timing routines in LZTIMER.ASM (times up to 1 hour) */

void 	_cdecl LZTimerOn(void);
ulong	_cdecl LZTimerLap(void);
void 	_cdecl LZTimerOff(void);
ulong 	_cdecl LZTimerCount(void);

/* Ultra long period timing routines in ULZTIMER.C (up to 65,000 hours) */

void	ULZTimerOn(void);
ulong	ULZTimerLap(void);
void	ULZTimerOff(void);
ulong	ULZTimerCount(void);
ulong	ULZReadTime(void);
ulong	ULZElapsedTime(ulong start,ulong finish);

#ifdef	__cplusplus
}						/* End of "C" linkage for C++	*/
#endif

/*--------------------------- Class Definitions ---------------------------*/

#ifdef	__cplusplus

#ifndef	__IOSTREAM_H
#include <iostream.h>
#endif

//---------------------------------------------------------------------------
// Long Period Zen Timer class. This can be used to time code that takes up
// to 1 hour to execute between calls to start() and stop() or lap(). The
// aggregate count can be up to 2^32 - 1 microseconds (about 1 hour
// and 10 mins).
//---------------------------------------------------------------------------

class LZTimer {
protected:
	ulong	_count;
	short	_overflow;

			// Compute the current count
			void computeTime();

public:
			// Constructor
			LZTimer()		{ _count = 0; _overflow = false; };

			// Method to start the timer
			void start()	{ LZTimerOn(); };

			// Method to restart the timer
			void restart()	{ reset(); start(); };

			// Method to return the current count without stop timer
			ulong lap()		{ return _count + LZTimerLap(); };

			// Method to stop the timer
			void stop()		{ LZTimerOff(); computeTime(); };

			// Method to return the current count
			ulong count()	{ return _count; };

			// Method to reset the timer to a zero count
			void reset()	{ _count = 0; _overflow = false; };

			// Method to determine if overflow occurred
			bool overflow()	{ return _overflow; };

			// Method to return timer resolution (seconds in a count).
			float resolution()	{ return LZTIMER_RES; };

			// Method to display the timed count in seconds
	friend	ostream& operator << (ostream& o,LZTimer& timer);
	};

//---------------------------------------------------------------------------
// Ultra Long Period Zen Timer class. This can be used to time code that
// takes up 24 hours total to execute between calls to start() and stop().
// The aggregate count can be up to 2^32 - 1 1/18ths of a second, which
// is about 65,000 hours! Should be enough for most applications.
//---------------------------------------------------------------------------

class ULZTimer {
protected:
	ulong	_count,_start,_finish;

public:
			// Constructor
			ULZTimer()		{ _count = 0; };

			// Method to start the timer
			void start()	{ _start = ULZReadTime(); };

			// Method to restart the timer
			void restart()	{ reset(); start(); };

			// Method to return the current count without stoping timer
			ulong lap()		{ return ULZElapsedTime(_start,ULZReadTime()); };

			// Method to stop the timer
			void stop();

			// Method to return the current count
			ulong count()	{ return _count; };

			// Method to reset the timer to a zero count
			void reset()	{ _count = 0; };

			// Method to return timer resolution (seconds in a count).
			float resolution()	{ return ULZTIMER_RES; };

			// Method to display the timed count in seconds
	friend	ostream& operator << (ostream& o,ULZTimer& timer);
	};

#endif

#endif
