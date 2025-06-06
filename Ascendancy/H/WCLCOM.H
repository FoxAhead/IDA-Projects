//
//  wclcom.h    Definitions for some common list classes used by
//              the WATCOM Container List Classes
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//

#ifndef _WCLCOM_H_INCLUDED

#ifndef __cplusplus
#error wclcom.h is for use with C++
#endif



//
//  The techniques for specifying the list classes are from
//  'The C++ Programming Language', 2nd Edition, Bjarne Stroustrup.
//




//
//  The WCSLink class is used as a basis for manipulating a number of
//  different containers.  In an intrusive container, this class provides
//  the base for the user defined class of single linked lists.
//
//  This class is intended to be a base class.  Objects of this type should
//  not be created.
//
//  constructor: set the 'next' link field to 0 (will be reset when inserted
//		 into the list).
//  destructor: nothing needs to be explicitly destroyed in WCSLink.
//		It is not virtual, to save the size cost of storing a virtual
//		table pointer in every node.
//

class WCSLink {
public:
    WCSLink *       link;

    inline WCSLink() : link( 0 ) {};
    inline ~WCSLink() {};
};




//
//  The WCDLink class is used as a basis for manipulating a number of
//  different containers.  In an intrusive container, this class provides
//  the base for the user defined class of double linked lists.  The
//  WCSLink class is used as a base for this class.
//
//  This class is intended to be a base class.  Objects of this type should
//  not be created.
//
//  constructor: the 'prev' link field is set up by the WCSLink constructor.
//  destructor: nothing needs to be explicitly destroyed in WCDLink.
//		It is not virtual, to save the size cost of storing a virtual
//		table pointer in every node.
//

class WCDLink : public WCSLink {
public:
    WCSLink         prev;


    inline WCDLink() {};
    inline ~WCDLink() {};
};




#define _WCLCOM_H_INCLUDED
#endif
