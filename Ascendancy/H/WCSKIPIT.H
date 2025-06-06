//
//  wcskipit.h  Definitions for the WATCOM Container Skip List Iterator
//              Classes
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//

#ifndef _WCSKIPIT_H_INCLUDED

#ifndef __cplusplus
#error wcskipit.h is for use with C++
#endif

#include <wcdefs.h>
#include <wcexcept.h>
#include <wcskip.h>
#include <wcsibase.h>




//
// The WCValSkipListIter is the iterator for the WCValSkipList class
//

template<class Type>
class WCValSkipListIter : public WCSkipListIterBase<Type> {
public:
    inline WCValSkipListIter() {};

    inline WCValSkipListIter( const WCValSkipList<Type>& skip_list )
                : WCSkipListIterBase( skip_list ) {};

    inline ~WCValSkipListIter() {};

    inline const WCValSkipList<Type> *container() const {
        return (const WCValSkipList<Type> *)WCSkipListIterBase::container();
    };

    inline void reset() {
        WCSkipListIterBase::reset();
    };

    inline void reset( const WCValSkipList<Type> &skip_list ) {
        WCSkipListIterBase::reset( skip_list );
    };
};



//
// The WCPtrSkipListIter is the iterator for the WCPtrSkipList class.
//

template<class Type>
class WCPtrSkipListIter : public WCSkipListIterBase<void *> {
public:
    inline WCPtrSkipListIter() {};

    inline WCPtrSkipListIter( const WCPtrSkipList<Type>& skip_list )
                : WCSkipListIterBase( skip_list ) {};

    inline ~WCPtrSkipListIter() {};

    inline const WCPtrSkipList<Type> *container() const {
        return( (const WCPtrSkipList<Type> *)WCSkipListIterBase::container() );
    };

    inline Type *current() const {
        return( (Type *)WCSkipListIterBase::current() );
    };

    inline void reset() {
        WCSkipListIterBase::reset();
    };

    inline void reset( const WCPtrSkipList<Type> &skip_list ) {
        WCSkipListIterBase::reset( skip_list );
    };
};




//
// The WCValSkipListSetIter is the iterator for the WCValSkipListSet class
//

template<class Type>
class WCValSkipListSetIter : public WCSkipListIterBase<Type> {
public:
    inline WCValSkipListSetIter() {};

    inline WCValSkipListSetIter( const WCValSkipListSet<Type>& skip_list )
                : WCSkipListIterBase( skip_list ) {};

    inline ~WCValSkipListSetIter() {};

    inline const WCValSkipListSet<Type> *container() const {
        return (const WCValSkipListSet<Type> *)WCSkipListIterBase::container();
    };

    inline void reset() {
        WCSkipListIterBase::reset();
    };

    inline void reset( const WCValSkipListSet<Type> &skip_list ) {
        WCSkipListIterBase::reset( skip_list );
    };
};



//
// The WCPtrSkipListSetIter is the iterator for the WCPtrSkipListSet class.
//

template<class Type>
class WCPtrSkipListSetIter : public WCSkipListIterBase<void *> {
public:
    inline WCPtrSkipListSetIter() {};

    inline WCPtrSkipListSetIter( const WCPtrSkipListSet<Type>& skip_list )
                : WCSkipListIterBase( skip_list ) {};

    inline ~WCPtrSkipListSetIter() {};

    inline const WCPtrSkipListSet<Type> *container() const {
        return( (const WCPtrSkipListSet<Type> *)WCSkipListIterBase
                                                        ::container() );
    };

    inline Type *current() const {
        return( (Type *)WCSkipListIterBase::current() );
    };

    inline void reset() {
        WCSkipListIterBase::reset();
    };

    inline void reset( const WCPtrSkipListSet<Type> &skip_list ) {
        WCSkipListIterBase::reset( skip_list );
    };
};




//
// The WCValSkipListDictIter is the iterator for the WCValSkipListDict class.
//
// private inheritance is used to hide the current member function.
//

template<class Key, class Value>
class WCValSkipListDictIter
        : private WCSkipListIterBase<WCSkipListDictKeyVal<Key, Value> > {
public:
    inline WCValSkipListDictIter() {};

    inline WCValSkipListDictIter( const WCValSkipListDict<Key, Value>& hash )
                : WCSkipListIterBase( hash ) {};

    inline ~WCValSkipListDictIter() {};

    inline const WCValSkipListDict<Key, Value> *container() const {
        return( (const WCValSkipListDict<Key, Value> *)WCSkipListIterBase
                        ::container() );
    };

    inline wciter_state exceptions() const {
        return( WCSkipListIterBase::exceptions() );
    };

    inline wciter_state exceptions( wciter_state const set_flags ) {
        return( WCSkipListIterBase::exceptions( set_flags ) );
    };

    Key key() const;

    inline void reset() {
        WCSkipListIterBase::reset();
    };

    inline void reset( const WCValSkipListDict<Key, Value> &hash ) {
        WCSkipListIterBase::reset( hash );
    };

    Value value() const;

    inline WCbool operator++() {
        return( WCSkipListIterBase::operator++() );
    };

    inline WCbool operator()() {
        return( WCSkipListIterBase::operator()() );
    };
};


template <class Key, class Value>
Key WCValSkipListDictIter<Key, Value>::key() const {
    if( curr == 0 ) {
        base_throw_undef_item();
        Key temp;
        return( temp );
    }
    return( base_curr_node()->data.key );
};


template <class Key, class Value>
Value WCValSkipListDictIter<Key, Value>::value() const {
    if( curr == 0 ) {
        base_throw_undef_item();
        Value temp;
        return( temp );
    }
    return( base_curr_node()->data.value );
};




//
// The WCPtrSkipListDictIter is the iterator for the WCPtrSkipListDict class.
//

template<class Key, class Value>
class WCPtrSkipListDictIter
        : public WCValSkipListDictIter<void *, void *> {
public:
    inline WCPtrSkipListDictIter() {};

    inline WCPtrSkipListDictIter( const WCPtrSkipListDict<Key, Value>& hash )
                : WCValSkipListDictIter( hash ) {};

    inline ~WCPtrSkipListDictIter() {};

    inline const WCPtrSkipListDict<Key, Value> *container() const {
        return( (const WCPtrSkipListDict<Key, Value> *)WCValSkipListDictIter
                                                        ::container() );
    };

    inline Key * key() const {
        return( (Key *)WCValSkipListDictIter::key() );
    };

    inline void reset() {
        WCValSkipListDictIter::reset();
    };

    inline void reset( const WCPtrSkipListDict<Key, Value> &hash ) {
        WCValSkipListDictIter::reset( hash );
    };

    Value *value() const {
        return( (Value *)WCValSkipListDictIter::value() );
    };
};

#define _WCSKIPIT_H_INCLUDED
#endif
