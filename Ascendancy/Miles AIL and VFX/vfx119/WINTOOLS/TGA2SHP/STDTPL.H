//****************************************************************************
//*                                                                          *
//*  STDTPL.H: Standard utility templates                                    *
//*                                                                          *
//****************************************************************************

#ifndef STDTPL_H
#define STDTPL_H

#include "typedefs.h"
#include <assert.h>

#include <stdlib.h>
#include <malloc.h>   

//
// Simple iteration macros for LLists and CLists
//
// FOR_ITERATE creates a for() loop which is executed once for every item in 
// list
//
//   lst = name of list variable
//   idx = name of index variable (such as "i")
//   var = name of variable to receive each list entry in succession
//

#define FOR_ITERATE(lst,idx,var) for (idx = 0, (var) = (lst).first(); \
                                      idx < (lst).count();            \
                                    ++idx, (var) = (lst).next((var)))

//
// ITERATE creates a while() loop which is executed once for every item in
// list, without using an index variable
//
//   lst = name of list variable
//   var = name of variable to receive each list entry in succession
//

#define ITERATE(lst,var) (var)=NULL; \
                         while (((var) = (lst).next(var)) != NULL)

//****************************************************************************
//
// LList
//
// Template used to represent doubly-linked list
//
// Use LList when:
//
//    - You want to maintain a linked list of arbitrary size
//
//    - You don't mind incurring heap-function overhead when allocating
//      and deleting entries         
//
//    - Fast random-access searchability is not important
//
//    - You want linear, not circular, list traversal (traversal stops when
//      end of list reached)
//
//****************************************************************************

template <class T> class LList
{
   T  *first_entry;
   T  *last_entry;
   S32 cnt;

public:

   //
   // Constructor initializes empty list
   //

   LList()
      {
      reset();
      }

   //
   // Reset list to empty state by abandoning contents
   //

   void reset(void)
      {
      first_entry = NULL;
      last_entry  = NULL;
      cnt         = 0;
      }

   //
   // Return entry count
   //

   S32 count(void) const
      {
      return cnt;
      }

   //
   // Return first list entry (NULL if list empty)
   //

   T *first(void) const
      {
      return first_entry;
      }

   //
   // Return last list entry (NULL if list empty)
   //

   T *last(void) const
      {
      return last_entry;
      }

   //
   // Return next list entry (NULL if end of list reached)
   //
   // Return first list entry if current==NULL
   //

   T *next(T *current) const
      {
      if (current == NULL)
         {
         return first();
         }

      return current->next;
      }

   //
   // Return previous list entry (NULL if beginning of list reached)
   //
   // Return last list entry if current==NULL
   //

   T *prev(T *current) const
      {
      if (current == NULL)
         {
         return last();
         }

      return current->prev;
      }

   //
   // Link new item into list before specified entry
   // If specified entry==NULL, insert at end of list
   //

   T *link(T *entry, T *next = NULL)
      {
      T *prev;

      if (next == NULL)
         {
         prev = last_entry;
         last_entry = entry;
         }
      else
         {
         prev = next->prev;
         next->prev = entry;
         }

      if (prev == NULL)
         {
         first_entry = entry;
         }
      else
         {
         prev->next = entry;
         }

      entry->next = next;
      entry->prev = prev;

      ++cnt;

      return entry;
      }

   //
   // Unlink item from list (without destroying it)
   //

   void unlink(T *entry)
      {
      if (entry->prev == NULL)
         {
         first_entry = entry->next;
         }
      else
         {
         entry->prev->next = entry->next;
         }

      if (entry->next == NULL)
         {
         last_entry = entry->prev;
         }
      else
         {
         entry->next->prev = entry->prev;
         }

      --cnt;
      }

   //
   // Allocate entry and insert before specified entry
   // If specified entry==NULL, insert at end of list
   //

   T *alloc(T *next = NULL)
      {
      T *entry;

      entry = new T;

      if (entry == NULL)
         {
         return NULL;
         }

      return link(entry, next);
      }

   //
   // Unlink item from list and destroy it
   //

   void free(T *entry)
      {
      unlink(entry);
      delete entry;
      }

   //
   // Unlink and destroy all list items
   //

   void free(void)
      {
      T  *t;
      T  *next;

      t = first_entry;

      while (cnt)
         {
         next = t->next;
         free(t);
         t = next;
         }
      }
};

//****************************************************************************
//
// CList
//
// Template used to represent circular doubly-linked list with storage
// count
//
// Use CList when:
//
//    - You want to maintain a linked list of arbitrary size
//
//    - You don't mind incurring heap-function overhead when allocating
//      and deleting entries         
//
//    - Fast random-access searchability is not important
//
//    - You want circular, not linear, list traversal (traversal wraps from
//      last to first entry in list)
//
//****************************************************************************

template <class T> class CList
{
   T  *first_entry;
   S32 cnt;

public:

   //
   // Constructor initializes empty list
   //

   CList()
      {
      reset();
      }

   //
   // Reset list to empty state by abandoning contents
   //

   void reset(void)
      {
      first_entry = NULL;
      cnt         = 0;
      }

   //
   // Return entry count
   //

   S32 count(void) const
      {
      return cnt;
      }

   //
   // Return arbitrary "first" list entry (NULL if list empty)
   //

   T *first(void) const
      {
      return first_entry;
      }

   //
   // Return arbitrary "last" list entry (NULL if list empty)
   //

   T *last(void) const
      {
      if (first_entry == NULL)
         {
         return NULL;
         }

      return first_entry->prev;
      }

   //
   // Return next list entry
   //
   // Return "first" list entry if current==NULL
   //

   T *next(T *current) const
      {
      if (current == NULL)
         {
         return first();
         }

      return current->next;
      }

   //
   // Return previous list entry
   //
   // Return "last" list entry if current==NULL
   //

   T *prev(T *current) const
      {
      if (current == NULL)
         {
         return last();
         }

      return current->prev;
      }

   //
   // Link new item into list before specified entry
   // If specified entry==NULL, insert at end of list
   //

   T *link(T *entry, T *next = NULL)
      {
      T *prev;

      if (first_entry == NULL)
         {
         //
         // List is currently empty -- insert first entry
         //

         next = prev = first_entry = entry;
         }
      else
         {
         //
         // Insert subsequent entries into list
         //

         if (next == NULL)
            {
            next = first_entry;
            }

         prev = next->prev;
         }

      //
      // Insert new entry between prev and next
      //

      if (next != NULL)
         {
         next->prev = entry;
         }

      if (prev != NULL)
         {
         prev->next = entry;
         }

      entry->next = next;
      entry->prev = prev;

      ++cnt;

      return entry;
      }

   //
   // Unlink item from list (without destroying it)
   //

   void unlink(T *entry)
      {
      if (entry == first_entry)
         {
         //
         // Are we deleting the only entry in the list?
         // If so, set first_entry to NULL
         //

         if (entry->next == entry)
            {
            first_entry = NULL;
            }
         else
            {
            first_entry = entry->next;
            }
         }

      entry->prev->next = entry->next;
      entry->next->prev = entry->prev;

      --cnt;
      }

   //
   // Allocate entry and insert before specified entry
   // If specified entry==NULL, insert at "end" of list
   //

   T *alloc(T *next = NULL)
      {
      T *entry;

      entry = new T;

      if (entry == NULL)
         {
         return NULL;
         }

      return link(entry, next);
      }

   //
   // Unlink item from list and destroy it
   //

   void free(T *entry)
      {
      unlink(entry);
      delete entry;
      }

   //
   // Unlink and delete all items in list
   //

   void free(void)
      {
      T  *t;
      T  *next;

      t = first_entry;

      while (cnt)
         {
         next = t->next;
         free(t);
         t = next;
         }
      }
};

//****************************************************************************
//
// HashPool
//
// Template used to maintain a dynamically-expandable list of structures for
// fast allocation and reference
//
// WARNING: HashPool elements may be moved in memory by the allocate() 
// method.  Do not rely on stored pointers to HashPool elements!  Use array
// indices instead for persistent references.
//
// Methods:
//   allocate()
//   unlink()
//   reset()
//   search()
//   spew()
//
// HashPool makes use of the following members of class T:
//
//   U32           hash_key;    // For internal use only
//   MESSAGE_TYPE *hash_next;   
//   MESSAGE_TYPE *hash_prev;  
//   MESSAGE_TYPE *next;          
//   MESSAGE_TYPE *prev;       
//                             
//   S32           index;       // Index of this entry in linear array
//
//   U32    hash      (void *)  // Derive key from object stored in T
//   BOOL32 compare   (void *)  // Compared object with object stored in T
//   void   initialize(void *)  // Store indicated object in T
//   void   shutdown  (void)    // Called when unlinked from pool
//   void   display   (void)    // Optionally display contents of T
//
// Class T may be thought of as a "package" that allows an object of any
// desired type (string, structure, etc...) to be stored in a dynamically-
// expandable linear array which is indexed by a hash table.  Along with the
// mandatory data and code members above, class T should also contain one
// or more user data fields representing the object being stored in T.
// 
// 
// Use HashPool when:
//
//    - You need to insert and remove entries in a list whose capacity needs 
//      to be determined at runtime
//
//    - You don't mind (potentially) incurring C heap overhead when 
//      allocating entries
//
//    - You don't mind storing indexes to pool entries, rather than pointers
// 
//    - Fast random-access searchability is required
//
// Example usage of HashPool to store a list of ASCII strings for fast 
// access:
//
//       class STRING_LIST
//       {
//       public:
//          //
//          // Data and methods required by HashPool template
//          //
//       
//          U32           hash_key;  // Hash key for this entry
//       
//          MESSAGE_TYPE *hash_next; // Next/prev pointers in each hash bucket,
//          MESSAGE_TYPE *hash_prev; // organized for access speed
//       
//          MESSAGE_TYPE *next;      // Next/prev pointers in allocation list or  
//          MESSAGE_TYPE *prev;      // free list, depending on entry's status
//       
//          S32           index;     // Index of this entry in linear array,
//                                   // or -1 if not currently allocated
//       
//          //
//          // HashPool hash function to derive 8-bit key from string
//          // by XOR'ing the first two characters together
//       
//          static inline U32 hash(void *object)
//             {
//             return (U32) (((C8 *) object)[0] ^ ((C8 *) object)[1]);
//             }
//       
//          //
//          // HashPool search comparison function -- returns TRUE if match
//          // found
//          //
//       
//          inline BOOL32 compare(void *object)
//             {
//             return !strcmp(name, (C8 *) object);
//             }
//       
//          //
//          // HashPool initialization function -- called when allocating new 
//          // entry
//          //
//       
//          inline void initialize(void *object)
//             {
//             strcpy(name, (C8 *) object);
//             }
//
//          //
//          // HashPool shutdown function -- called when unlinking entry from
//          // pool
//          //
//
//          inline void shutdown(void)
//             {
//             }
//       
//          //
//          // HashPool diagnostic display function
//          //
//       
//          void display(void)
//             {
//             printf("Entry #%d: [%s]",name, index);
//             }
//       
//          //
//          // User data
//          //
//       
//          C8 name[64];             // 64-character ASCII message name
//       };
// 
//****************************************************************************

template <class T, S32 grow_size, S32 hash_size=256> class HashPool
{
   T   *last_alloc;              // Pointer to most-recently-allocated entry
   T   *first_free;              // Pointer to first-available entry
   T   *hash_table[hash_size];   // Hash bucket array for fast searches

public:
   
   T   *list;              // List of user-specified structures
   S32  list_size;         // # of structures in list

   //
   // Create structure pool
   //

   HashPool(void)
      {
      //
      // Allocate initial list entries
      // 

      list_size = grow_size;

      list = new T[list_size];

      reset();
      }

   //
   // Destroy structure pool
   //                         

   void free (void);

   ~HashPool(void)
      {
      free ();
      }


   //
   // Reset list to empty state by abandoning contents
   //

   void reset(void)
      {
      //
      // Chain all list entries together in 'free' list
      //

      for (S32 i=0; i < list_size; i++)
         {
         list[i].index = -1;
         list[i].prev  = &list[i-1];
         list[i].next  = &list[i+1];
         }

      list[0          ].prev = NULL;
      list[list_size-1].next = NULL;

      last_alloc = NULL;
      first_free = &list[0];

      //
      // Initialize hash table
      //

      for (i=0; i < hash_size; i++)
         {
         hash_table[i] = NULL;
         }
      }

   //
   // Allocate pool entry to represent *object, growing pool if necessary
   // to accomodate new allocation
   //                                                               

   S32 allocate(const void *object=NULL)
      {
      U32 key = T::hash(object);
      T  *entry;

      //
      // Grow list if necessary
      //

      if (first_free == NULL)
         {
         //
         // No free entries left, must grow list by one block of grow_size
         // entries
         // 

         U32 fixup;
         S32 i;

         S32 old_size = list_size;
         S32 new_size = old_size + grow_size;

         T *old_list = list;
         T *new_list = new T[new_size];

         if (new_list == NULL)
            {
            //
            // Allocation failed (should not normally happen)
            //

            return NULL;
            }

         fixup = ((U32) new_list) - ((U32) old_list);

         //
         // Copy existing entries from old list to new list, adjusting
         // links to new base address
         //

         for (i=0; i < old_size; i++)
            {
            new_list[i] = old_list[i];

            if (new_list[i].hash_next != NULL)
               {
               new_list[i].hash_next = (T *) 
                                       (((U32) new_list[i].hash_next) + fixup);
               }

            if (new_list[i].hash_prev != NULL)
               {
               new_list[i].hash_prev = (T *) 
                                       (((U32) new_list[i].hash_prev) + fixup);
               }

            if (new_list[i].next != NULL)
               {
               new_list[i].next = (T *) 
                                  (((U32) new_list[i].next) + fixup);
               }

            if (new_list[i].prev != NULL)
               {
               new_list[i].prev = (T *) 
                                  (((U32) new_list[i].prev) + fixup);
               }
            }

         //
         // Fix up hash table
         //

         for (i=0; i < hash_size; i++)
            {
            if (hash_table[i] != NULL)
               {
               hash_table[i] = (T *) (((U32) hash_table[i]) + fixup);
               }
            }

         //
         // Chain all newly-appended list entries together in 'free' list
         //

         for (i=old_size; i < new_size; i++)
            {
            new_list[i].index = -1;
            new_list[i].prev  = &new_list[i-1];
            new_list[i].next  = &new_list[i+1];
            }

         new_list[old_size  ].prev = NULL;
         new_list[new_size-1].next = NULL;

         //
         // Adjust pool pointers
         //

         last_alloc = (T *) (((U32) last_alloc) + fixup);
         first_free = &new_list[old_size];

         list      = new_list;
         list_size = new_size;

         //
         // Finally, delete old list
         //

         delete [] old_list;
         }

      //
      // Allocate new entry from existing list
      //
      // Get pointer to free entry
      //

      entry = first_free;

      first_free = entry->next;

      //
      // Insert new entry in allocation-order list, from the beginning
      //

      entry->next = last_alloc;
      entry->prev = NULL;

      if (last_alloc != NULL)
         {
         last_alloc->prev = entry;
         }

      last_alloc = entry;

      //
      // Insert entry into hash bucket, from the beginning
      //
      // Associate hash key with entry for ease of reference
      //

      entry->hash_key  = key;
      entry->hash_next = hash_table[key];
      entry->hash_prev = NULL;

      if (hash_table[key] != NULL)
         {
         hash_table[key]->hash_prev = entry;
         }

      hash_table[key] = entry;

      entry->index = (S32) ((U32(entry) - U32(list)) / sizeof(T));

      //
      // Initialize newly-allocated entry with object
      //

      entry->initialize(object);

      //
      // Return entry's position in linear array
      //

      return entry->index;
      }

   //
   // Unlink existing entry from hash list and allocation list
   //

   void unlink(T *entry)
      {
      //
      // Call deallocation routine before unlinking object
      //

      entry->shutdown();

      //
      // Unlink from hash table
      //

      if (entry->hash_next != NULL)
         {
         entry->hash_next->hash_prev = entry->hash_prev;
         }

      if (entry->hash_prev != NULL)
         {
         entry->hash_prev->hash_next = entry->hash_next;
         }

      //
      // Unlink from allocation-order list
      //

      entry->index = -1;

      if (entry->next != NULL)
         {
         entry->next->prev = entry->prev;
         }

      if (entry->prev != NULL)
         {
         entry->prev->next = entry->next;
         }

      //
      // Adjust pool list pointers, if deleting first entry
      //

      if (last_alloc == entry)
         {
         last_alloc = entry->next;
         }

      if (hash_table[entry->hash_key] == entry)
         {
         hash_table[entry->hash_key] = entry->hash_next;
         }

      //
      // Finally, add this entry to the beginning of the free list
      //

      entry->next = first_free;
      entry->prev = NULL;

      if (first_free != NULL)
         {
         first_free->prev = entry;
         }

      first_free = entry;
      }

   //
   // Unlink existing entry by index #, if index # is valid and 
   // entry has not already been unlinked
   //

   void unlink(S32 index)
      {
      if ((index != -1) && (list[index].index != -1))
         {
         unlink(&list[index]);
         }
      }

   //
   // Search pool for entry which represents *object
   //
   // Return entry index, or -1 if object not found
   //

   S32 search(const void *object) const
      {
      T *result;

      result = hash_table[T::hash(object)];

      while (result != NULL)
         {
         if (result->compare(object))
            {
            break;
            }

         result = result->hash_next;
         }

      if (result)
         {
         return result->index;
         }

      return -1;
      }

   //
   // Perform diagnostic dump of all objects in list
   //

   void spew(void)
      {
      S32 i;

      for (i=0; i < list_size; i++)
         {
         if (list[i].index != -1)
            {
            list[i].display();
            }
         }
      }
};

template <class T, S32 grow_size, S32 hash_size> void HashPool<T, grow_size, hash_size>::free (void)
{
   if (list != NULL)
   {
      //
      // Unlink and shut down all objects in list, in
      // their reverse order of allocation
      //

      while (last_alloc != NULL)
      {
         unlink(last_alloc);
      }

      //
      // Free memory used by pool
      //

      delete [] list;
      list = NULL;

      list_size = 0;
   }
}

//****************************************************************************
//
// Pool
//
// Template used to maintain a dynamically-expandable list of structures for
// fast allocation and reference
//
// WARNING: Pool elements may be moved in memory by the allocate() 
// method.  Do not rely on stored pointers to Pool elements!  Use array
// indices instead for persistent references.
//
// Methods:
//   allocate()
//   unlink()
//   reset()
//   spew()
//
// HashPool makes use of the following members of class T:
//
//   MESSAGE_TYPE *next;        // For internal use only
//   MESSAGE_TYPE *prev;       
//                             
//   S32           index;       // Index of this entry in linear array
//
//   void   initialize(void *)  // Store indicated object in T
//   void   shutdown  (void)    // Called when unlinked from pool
//   void   display   (void)    // Optionally display contents of T
//
// Class T may be thought of as a "package" that allows an object of any
// desired type (string, structure, etc...) to be stored in a dynamically-
// expandable linear array.  Along with the mandatory data and code members 
// above, class T should also contain one or more user data fields 
// representing the object being stored in T.
// 
// Use Pool when:
//
//    - You need to insert and remove entries in a list whose capacity needs 
//      to be determined at runtime
//
//    - You don't mind (potentially) incurring C heap overhead when 
//      allocating entries
//
//    - You don't mind storing indexes to pool entries, rather than pointers
//
//    - You will keep track of entry indexes separately, so random-access 
//      searchability is not required (otherwise, use HashPool)
//
// Example usage of Pool to store an expandable list of ASCII strings:
//
//       class STRING_LIST
//       {
//       public:
//          //
//          // Data and methods required by HashPool template
//          //
//       
//          MESSAGE_TYPE *next;      // Next/prev pointers in allocation list or  
//          MESSAGE_TYPE *prev;      // free list, depending on entry's status
//       
//          S32           index;     // Index of this entry in linear array,
//                                   // or -1 if not currently allocated
//       
//          //
//          // Pool initialization function -- called when allocating new 
//          // entry
//          //
//       
//          inline void initialize(void *object)
//             {
//             strcpy(name, (C8 *) object);
//             }
//
//          //
//          // Pool shutdown function -- called when unlinking entry from
//          // pool
//          //
//
//          inline void shutdown(void)
//             {
//             }
//       
//          //
//          // Pool diagnostic display function
//          //
//       
//          void display(void)
//             {
//             printf("Entry #%d: [%s]",name, index);
//             }
//       
//          //
//          // User data
//          //
//       
//          C8 name[64];             // 64-character ASCII message name
//       };
// 
//****************************************************************************

template <class T, S32 grow_size> class Pool
{
   T   *last_alloc;        // Pointer to most-recently-allocated entry
   T   *first_free;        // Pointer to first-available entry

public:
   
   T   *list;              // List of user-specified structures
   S32  list_size;         // # of structures in list

   //
   // Create structure pool
   //

   Pool(void)
      {
      //
      // Allocate initial list entries
      // 

      list_size = grow_size;

      list = new T[list_size];

      reset();
      }

   //
   // Destroy structure pool
   //                         

   ~Pool(void)
      {
      if (list != NULL)
         {
         //
         // Unlink and shut down all objects in list, in
         // their reverse order of allocation
         //

         while (last_alloc != NULL)
            {
            unlink(last_alloc);
            }

         //
         // Free memory used by pool
         //

         delete [] list;
         }
      }

   //
   // Reset list to empty state by abandoning contents
   //

   void reset(void)
      {
      //
      // Chain all list entries together in 'free' list
      //

      for (S32 i=0; i < list_size; i++)
         {
         list[i].index = -1;
         list[i].prev  = &list[i-1];
         list[i].next  = &list[i+1];
         }

      list[0          ].prev = NULL;
      list[list_size-1].next = NULL;

      last_alloc = NULL;
      first_free = &list[0];
      }

   //
   // Allocate pool entry to represent *object, growing pool if necessary
   // to accomodate new allocation
   //                                                               

   S32 allocate(const void *object=NULL)
      {
      T *entry;

      //
      // Grow list if necessary
      //

      if (first_free == NULL)
         {
         //
         // No free entries left, must grow list by one block of grow_size
         // entries
         // 

         U32 fixup;
         S32 i;

         S32 old_size = list_size;
         S32 new_size = old_size + grow_size;

         T *old_list = list;
         T *new_list = new T[new_size];

         if (new_list == NULL)
            {
            //
            // Allocation failed (should not normally happen)
            //

            return NULL;
            }

         fixup = ((U32) new_list) - ((U32) old_list);

         //
         // Copy existing entries from old list to new list, adjusting
         // links to new base address
         //

         for (i=0; i < old_size; i++)
            {
            new_list[i] = old_list[i];

            if (new_list[i].next != NULL)
               {
               new_list[i].next = (T *) 
                                  (((U32) new_list[i].next) + fixup);
               }

            if (new_list[i].prev != NULL)
               {
               new_list[i].prev = (T *) 
                                  (((U32) new_list[i].prev) + fixup);
               }
            }

         //
         // Chain all newly-appended list entries together in 'free' list
         //

         for (i=old_size; i < new_size; i++)
            {
            new_list[i].index = -1;
            new_list[i].prev  = &new_list[i-1];
            new_list[i].next  = &new_list[i+1];
            }

         new_list[old_size  ].prev = NULL;
         new_list[new_size-1].next = NULL;

         //
         // Adjust pool pointers
         //

         last_alloc = (T *) (((U32) last_alloc) + fixup);
         first_free = &new_list[old_size];

         list      = new_list;
         list_size = new_size;

         //
         // Finally, delete old list
         //

         delete [] old_list;
         }

      //
      // Allocate new entry from existing list
      //
      // Get pointer to free entry
      //

      entry = first_free;

      first_free = entry->next;

      //
      // Set index member to entry's position in linear array
      //

      entry->index = (S32) ((U32(entry) - U32(list)) / sizeof(T));

      //
      // Insert new entry in allocation-order list, from the beginning
      //

      entry->next = last_alloc;
      entry->prev = NULL;

      if (last_alloc != NULL)
         {
         last_alloc->prev = entry;
         }

      last_alloc = entry;

      entry->index = (S32) ((U32(entry) - U32(list)) / sizeof(T));

      //
      // Initialize newly-allocated entry with object
      //

      entry->initialize(object);

      //
      // Return entry's position in linear array
      //

      return entry->index;
      }

   //
   // Unlink existing entry from hash list and allocation list
   //

   void unlink(T *entry)
      {
      //
      // Call deallocation routine before unlinking object
      //

      entry->shutdown();

      //
      // Unlink from allocation-order list
      //

      entry->index = -1;

      if (entry->next != NULL)
         {
         entry->next->prev = entry->prev;
         }

      if (entry->prev != NULL)
         {
         entry->prev->next = entry->next;
         }

      //
      // Adjust pool list pointers, if deleting first entry
      //

      if (last_alloc == entry)
         {
         last_alloc = entry->next;
         }

      //
      // Finally, add this entry to the beginning of the free list
      //

      entry->next = first_free;
      entry->prev = NULL;

      if (first_free != NULL)
         {
         first_free->prev = entry;
         }

      first_free = entry;
      }

   //
   // Unlink existing entry by index #, if index # is valid and 
   // entry has not already been unlinked
   //

   void unlink(S32 index)
      {
      if ((index != -1) && (list[index].index != -1))
         {
         unlink(&list[index]);
         }
      }

   //
   // Perform diagnostic dump of all objects in list
   //

   void spew(void)
      {
      S32 i;

      for (i=0; i < list_size; i++)
         {
         if (list[i].index != -1)
            {
            list[i].display();
            }
         }
      }
};

//****************************************************************************
//
// List
//
// Template used to represent list of object instances for rapid allocation/
// traversal/deletion
//
// Use List when:
//
//    - You need to insert and remove entries in a list without using 
//      potentially-slow heap functions, or incurring heap-entry overhead
//
//    - You don't mind being limited to a fixed number of entries (declared
//      at time of list creation)
//
//    - Fast traversal is important, but random-access searchability is not
//
//****************************************************************************

template <class T, S32 size> class List
{     
   T *alloc_list;        // Pointer to first allocated entry
   T *last_alloc;        // Last-allocated entry
   T *free_list;         // Pointer to first-available entry
   T *list;              // Pool of entries

public:
   
   //
   // Create fixed-size list
   //

   List(void)
      {
      //
      // Allocate list array from heap
      //

      list = new T[size];

      //
      // Link all entries into "free" list
      //

      last_alloc = NULL;
      alloc_list = NULL;
      free_list  = &list[0];

      list[0].prev = NULL;
      list[0].next = &list[1];

      for (S32 i=1; i < (size-1); i++)
         {
         list[i].prev = &list[i-1];
         list[i].next = &list[i+1];
         }

      list[size-1].prev = &list[size-2];
      list[size-1].next = NULL;
      }

   //
   // Destroy list
   //

   ~List()
      {
      delete[] list;
      }

   //
   // Return last allocated list entry (NULL if list empty)
   //

   T *last(void) const
      {
      return last_alloc;
      }

   //
   // Return first allocated list entry (NULL if list empty)
   //

   T *first(void) const
      {
      return alloc_list;
      }

   //
   // Return nth entry in list (slow -- use Pool or HashPool if you
   // need fast random indexing!)
   //

   T *nth(S32 n) const
      {
      T *result = alloc_list;

      while ((result != NULL) && n)
         {
         --n;
         result = result->next;
         }

      return result;
      }

   //
   // Allocate an entry
   //
   // Returns NULL if list already full
   //

   T *allocate(void)
      {
      T *entry = free_list;

      if (entry == NULL)
         {
         return NULL;
         }

      //
      // Unlink first entry from beginning of free list
      // 

      free_list = free_list->next;

      if (free_list != NULL)
         {
         free_list->prev = NULL;
         }

      //
      // Relink as last entry in allocated list
      // 

      if (alloc_list == NULL)
         {
         alloc_list = entry;
         }

      if (last_alloc != NULL)
         {
         last_alloc->next = entry;
         }

      entry->prev = last_alloc;
      entry->next = NULL;

      //
      // Return pointer to entry
      //

      last_alloc = entry;

      return entry;
      }

   //
   // Free an entry (move it from the allocated list to the free list)
   //

   void free(T *entry)
      {
      //
      // If freeing last-allocated entry, back off last_alloc pointer to
      // previous entry
      //

      if (entry == last_alloc)
         {
         last_alloc = entry->prev;
         }

      //
      // Unlink specified entry from allocated list
      //

      if (entry->next != NULL)
         {
         entry->next->prev = entry->prev;
         }

      if (entry->prev == NULL)   
         {
         alloc_list = entry->next;
         }
      else
         {
         entry->prev->next = entry->next;
         }

      //
      // Relink as first entry in free list
      //

      entry->next = free_list;

      if (free_list != NULL)
         {
         free_list->prev = entry;
         }

      free_list = entry;
      }

   const T ** pfirst (void)
   {
      return (const T **) &alloc_list;
   }
};

#endif
