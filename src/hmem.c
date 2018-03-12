/*
   High memory manager.

   Digi, 2017.
*/

#include <types.h>
#include <memory.h>
#define INCL_DOSMEMMGR
#define INCL_DOSERRORS
#define INCL_DOSPROCESS
#include <os2.h>
#include "hmem.h"

//#define DEBUG_FILE

#ifdef DEBUG_FILE
#include <stdio.h>
#define debugPCP(s) printf( __FILE__"#%u %s() [control point] "s"\n", __LINE__, __func__ )
#else
#define debugPCP(s)
#endif

#define _END_TAG                 (~0)
#define _MIN_HEAPBLOCK_SIZE      (32 * 1024 * 1024)

#pragma pack(4)
typedef struct _FREEBLOCK {
  ULONG                ulLen;
  struct _FREEBLOCK    *pPrev;
  struct _FREEBLOCK    *pNext;
} FREEBLOCK, *PFREEBLOCK;

typedef struct _HEAPBLOCK {
  ULONG                ulLen;
  struct _HEAPBLOCK    **ppSelf;
  struct _HEAPBLOCK    *pNext;
  PFREEBLOCK           pRover;
  ULONG                ulB4Rover;
  ULONG                ulLargest;
  ULONG                cAlloc;
  ULONG                cFree;
  FREEBLOCK            stFreeHead;
} HEAPBLOCK, *PHEAPBLOCK;
#pragma pack()

static PHEAPBLOCK      pFirst = NULL;
static PHEAPBLOCK      pRover = NULL;


/*
 *  Memory manager mutex.
 *
 *  System mutex semaphores are too slow for us. We will use our own
 *  non-recursive fast mutex.
 */

static ULONG           ulOwner = 0;        // Owner thread id.
static ULONG           aWaitTID[128];      // TIDs which waits on lock.
static ULONG           cWaitTID = 0;       // Numer of TIDs in aWaitTID.
static volatile int    iLock;              // SpinLock variable.

// Lock memory manager for exclusive work.
static BOOL _hmemLock()
{
  PTIB       ptib;
  ULONG      ulTID;

  DosGetInfoBlocks( &ptib, NULL );
  ulTID = ptib->tib_ptib2->tib2_ultid;     // Get current thread Id.

  while( TRUE )
  {
    while( __sync_lock_test_and_set( &iLock, 1 ) );

    if ( ulOwner != 0 )                    // Memory manager is locked?
    {
      if ( cWaitTID == 127 )               // Too many waiting locks.
      {
        __sync_lock_release( &iLock );     // Release spinlock.
        return FALSE;                      // Failed.
      }

      aWaitTID[cWaitTID] = ulTID;          // Add current TID to pending list.
      cWaitTID++;
      __sync_lock_release( &iLock );       // Release spinlock.
      DosSuspendThread( ulTID );           // Sleep, wait for unlock.
    }
    else
    {                                      // Not locked, we can work.
      ulOwner = ulTID;                     // We are owner of the mem. manager.
      __sync_lock_release( &iLock );       // Release spinlock.
      break;                               // Let's go do our job.
    }
  }

  return TRUE;                             // Success.
}

// Unlock memory manager.
static VOID _hmemUnlock()
{
  ULONG      ulTID = 0;
  ULONG      ulRC;

  while( __sync_lock_test_and_set( &iLock, 1 ) );

  ulOwner = 0;                             // There is no owner anymore.
  if ( cWaitTID != 0 )                     // Somebody wait for unlock?
  {
    cWaitTID--;                            // Cut id of the waiting thread.
    ulTID = aWaitTID[cWaitTID];            //
  }
  __sync_lock_release( &iLock );           // Release spinlock.

  if ( ulTID != 0 )
  {                                        // We have thread to wake up.
    do
      ulRC = DosResumeThread( ulTID );     // Wake up the waiting thread.
    while ( ulRC == ERROR_NOT_FROZEN );    // There wasn't enough time to going
                                           // to sleep after adding to list?

    // It was asleep, now awakened.
  }
}


/*
 *  High memory heap blocks.
 */

static VOID APIENTRY _memOnExit(ULONG ulCode)
{
  PHEAPBLOCK pHeapBlock, pNext;

  pHeapBlock = pFirst;
  while( pHeapBlock != NULL )
  {
    pNext = pHeapBlock->pNext;
    DosFreeMem( (PVOID)pHeapBlock );
    pHeapBlock = pNext;
  }

  DosExitList( EXLST_EXIT, (PFNEXITLIST)NULL );
}

static PHEAPBLOCK __memHeapAlloc(ULONG ulSize)
{
  PHEAPBLOCK           pHeapBlock;
  ULONG                ulRC;
  PFREEBLOCK           pFree;
  PHEAPBLOCK           pCur;

  if ( ulSize > -(sizeof(HEAPBLOCK) + sizeof(ULONG) + sizeof(ULONG)) )
    return NULL;

  //                            Length of free  End tag
  ulSize += sizeof(HEAPBLOCK) + sizeof(ULONG) + sizeof(ULONG);
  ulSize = (ulSize + 0x0FFF) & ~0x0FFF;    // Round up to 4096

  // First, try to allocate block in high memory.
  ulRC = DosAllocMem( (PVOID *)&pHeapBlock, ulSize,
                      PAG_COMMIT | PAG_READ | PAG_WRITE | OBJ_ANY );
  if ( ulRC != NO_ERROR )
  {
    // Failed - try to allocate block in low memory.
    ulRC = DosAllocMem( (PVOID *)&pHeapBlock, ulSize,
                        PAG_COMMIT | PAG_READ | PAG_WRITE );
    if ( ulRC != NO_ERROR )
      return NULL;
  }

  pFree = (PFREEBLOCK)( (PCHAR)pHeapBlock + sizeof(HEAPBLOCK) );

  pHeapBlock->ulLen      = ulSize;
  pHeapBlock->pRover     = pFree;
  pHeapBlock->ulB4Rover  = 0;
  pHeapBlock->ulLargest  = ulSize - sizeof(HEAPBLOCK) - sizeof(ULONG);
  pHeapBlock->cAlloc     = 0;
  pHeapBlock->cFree      = 1;
  pHeapBlock->stFreeHead.ulLen  = 0;
  pHeapBlock->stFreeHead.pPrev  = pFree;
  pHeapBlock->stFreeHead.pNext  = pFree;

  pFree->ulLen = pHeapBlock->ulLargest;
  pFree->pPrev = &pHeapBlock->stFreeHead;
  pFree->pNext = &pHeapBlock->stFreeHead;

  *((PULONG)&((PCHAR)pHeapBlock)[ulSize - sizeof(ULONG)]) = _END_TAG;

  // Insert new heap block to the list sorted by block address.

  if ( pFirst == NULL )
  {
    // First heap block allocated - high memory manager initialization.

    pFirst = pHeapBlock;
    pHeapBlock->ppSelf = &pFirst;
    pHeapBlock->pNext = NULL;

    DosExitList( EXLST_ADD | 0xE000, (PFNEXITLIST)_memOnExit );
  }
  else
  {
    pCur = pFirst;
    while( TRUE )
    {
      if ( pHeapBlock < pCur )
      {
        *pCur->ppSelf = pHeapBlock;
        pHeapBlock->pNext = pCur;
        pCur->ppSelf = &pHeapBlock->pNext;
        break;
      }

      if ( pCur->pNext == NULL )
      {
        pCur->pNext = pHeapBlock;
        pHeapBlock->ppSelf = &pCur->pNext;
        pHeapBlock->pNext = NULL;
        break;
      }

      pCur = pCur->pNext;
    }
  }

  pRover = pHeapBlock;

  return pHeapBlock;
}


/*
 *  Works on heap.
 */

static PVOID _memAllocator(PHEAPBLOCK pHeapBlock, ULONG ulSize)
{
  ULONG      ulNewSize, ulLargest, ulLen;
  PFREEBLOCK pCur, pPrev, pNext;

  if ( ulSize == 0 )
    return NULL;

  // Increment size to length field size and round up to 4 bytes.
  ulNewSize = sizeof(ULONG) + ( (ulSize + 3) & ~3 );
  if ( ulNewSize < ulSize )
    return NULL;                           // Overflowed.

  ulSize = ulNewSize < sizeof(FREEBLOCK) ? sizeof(FREEBLOCK) : ulNewSize;
  if ( ulSize > pHeapBlock->ulLargest )
    return NULL;

  pCur = pHeapBlock->pRover;               // Start at rover.
  ulLargest = pHeapBlock->ulB4Rover;

  if ( ulSize < ulLargest )                // Check size with rover.
  {
    pCur = pHeapBlock->stFreeHead.pNext;   // Start at beginning.
    ulLargest = 0;
  }

  while( TRUE )                            // Search free list.
  {
    ulLen = pCur->ulLen;
    if ( ulSize <= ulLen )                 // Found one.
      break;

    if ( ulLen > ulLargest )               // Update largest block size.
      ulLargest = ulLen;

    pCur = pCur->pNext;                    // Advance to next entry.

    if ( pCur == &pHeapBlock->stFreeHead ) // If back at start.
    {
      pHeapBlock->ulLargest = ulLargest;
      return NULL;
    }
  }

  pHeapBlock->ulB4Rover = ulLargest;       // Update rover size.
  pHeapBlock->cAlloc++;                    // Udpate allocation count.
  ulLen -= ulSize;                         // Compute leftover size.
  pPrev = pCur->pPrev;                     // Before current.
  pNext = pCur->pNext;                     // After current.
  if ( ulLen >= sizeof(FREEBLOCK) )        // If leftover big enough -
  {                                        //   split into two chunks.
    PFREEBLOCK    pNew =                   // Start of new piece.
                    (PFREEBLOCK)((PCHAR)pCur + ulSize);

    pHeapBlock->pRover = pNew;             // Update rover.
    pNew->ulLen = ulLen;                   // Set new size.
    pCur->ulLen = ulSize;                  // Reset current size.
    pNew->pPrev = pPrev;                   // Update next/prev links.
    pNew->pNext = pNext;
    pPrev->pNext = pNew;
    pNext->pPrev = pNew;
  }
  else                                     // Just use this chunk.
  {
    pHeapBlock->cFree--;                   // 1 fewer entries in free list.
    pHeapBlock->pRover = pPrev;            // Update rover.
    pPrev->pNext = pNext;                  // Update next/prev links.
    pNext->pPrev = pPrev;
  }

  pCur->ulLen |= 1;                        // Mark as allocated.

  return (PCHAR)pCur + sizeof(ULONG);
}

static VOID _memFree(PHEAPBLOCK pHeapBlock, PVOID pPointer)
{
  PFREEBLOCK pFree, pPrev, pNext, pPtr;
  ULONG      ulLen, ulAverage, ulNumFree;

  if ( pPointer == NULL )                  // Quit if pointer is NULL.
    return;

  pFree = (PFREEBLOCK)((PCHAR)pPointer - sizeof(ULONG));
  if ( (pFree->ulLen & 1) == 0 )           // Quit if storage is free.
  {
    debugPCP( "free on not allocated block" );
    return;
  }

  do                                       // This allows break statement.
  {
    // Look at next block to try and coalesce.
    ulLen = pFree->ulLen & ~1;
    pNext = (PFREEBLOCK)((PCHAR)pFree + ulLen);
    if ( (pNext->ulLen & 1) == 0 )         // If it is free.
    {
      ulLen += pNext->ulLen;               // Include the length.
      pFree->ulLen = ulLen;                // Update pFree length.
      if ( pNext == pHeapBlock->pRover )   // Check for rover.
        pHeapBlock->pRover = pFree;        // Update rover.
      pPrev = pNext->pPrev;                // Fixup next/prev links.
      pNext = pNext->pNext;
      pPrev->pNext = pNext;
      pNext->pPrev = pPrev;
      pHeapBlock->cFree--;                 // Reduce numfree.
      break;                               // Proceed to coalesce code.
    }

    // Following block is not free. We must now try to figure out where pFree
    // is in relation to the entries in the free list.

    pFree->ulLen = ulLen;                  // Remove allocated marker.

    // Check a few special places, see if pFree is:
    // - just before or just after the rover
    // - at the very beginning or very end of the heap
    pNext = pHeapBlock->pRover;            // Get rover.
    if ( pFree < pNext )                   // Where is pFree?
    {                                      // pFree is before rover.
      if ( pFree > pNext->pPrev )          // Where is pfree?
      {                                    // pPree is next to rover,
        break;                             //   proceed to coalesce code,
      }
      pNext = pHeapBlock->stFreeHead.pNext;// Get start of free list.
      if( pFree < pNext )                  // Where is pfree?
      {                                    // Pfree is at start of list,
        break;                             //   proceed to coalesce code.
      }
    }
    else                                   // pFree is after rover.
    {
      pNext = pNext->pNext;                // pNext is after rover.
      if ( pFree < pNext )                 // where is pfree?
      {                                    // pFree is just after rover,
        break;                             //   proceed to coalesce code.
      }

      pNext = &pHeapBlock->stFreeHead;     // Get end of free list.
      pPrev = pNext->pPrev;
      if ( pFree > pPrev )                 // Where is pFree?
      {                                    // pFree is at end of list,
        break;                             //   proceed to coalesce code.
      }
    }  // if ( pFree < pNext ) else

    // Calculate the average number of allocated blocks we may
    // have to skip until we expect to find a free block.  If
    // this number is less than the total number of free blocks,
    // chances are that we can find the correct position in the
    // free list by scanning ahead for a free block and linking
    // this free block before the found free block.  We protect
    // ourself against the degenerate case where there is an
    // extremely long string of allocated blocks by limiting the
    // number of blocks we will search to twice the calculated
    // average.

    ulNumFree = pHeapBlock->cFree;
    ulAverage = pHeapBlock->cAlloc / ( ulNumFree + 1 );
    if ( ulAverage < ulNumFree )
    {
      // There are lots of allocated blocks and lots of free
      // blocks.  On average we should find a free block
      // quickly by following the allocated blocks, but the
      // worst case can be very bad.  So, we try scanning the
      // allocated blocks and give up once we have looked at
      // twice the average.

      ULONG  ulWorst = pHeapBlock->cAlloc - ulNumFree;

      if ( ulWorst > ulNumFree )
        ulAverage *= 2;                    // Give up after this many.
      else
        ulAverage = ~0; /* UINT_MAX */     // We won't give up loop.

                                           // Point at next allocated.
      pNext = (PFREEBLOCK)((PCHAR)pFree + pFree->ulLen);
      while( TRUE )
      {
        ulLen = pNext->ulLen;
        if ( (ulLen & 1) != 0 )            // pNext is allocated.
        {
          if ( ulLen != _END_TAG )          // Check for end TAG
          {
            ulLen &= ~1;                   // Advance pNext.
            pNext = (PFREEBLOCK)((PCHAR)pNext + ulLen);
            ulAverage--;
            if ( ulAverage == 0 )          // Give up search.
              break;
          }
          else
            break;                         // Stop at end tag.
        }
        else                               // Break twice!
          goto found_it;                   // We have the spot.
      }  // while( TRUE )
    }  // if ( ulAverage < ulNumFree )

    // When all else fails, search the free list.
    pNext = pHeapBlock->pRover;            // Begin at rover.
    if ( pFree < pNext )                   // Is pFree before rover?
      pNext = pHeapBlock->stFreeHead.pNext;// Then begin at start.
    while( TRUE )
    {
      if ( pFree < pNext )                 // If pFree before pNext -
          break;                           //   we found it.

      pNext = pNext->pNext;                // Advance pNext.

      if ( pFree < pNext )                 // If pfree before pNext -
          break;                           //   we found it.

      pNext = pNext->pNext;                // Advance pNext.
      if ( pFree < pNext )                 // If pfree before pNext -
          break;                           //   we found it.

      pNext = pNext->pNext;                // Advance pNext.
    }
  }
  while( FALSE );

found_it:
  // If we are here, then we found the spot.
  pPrev = pNext->pPrev;                    // Setup pPrev.

  // pPrev, pFree, pNext are all setup.
  ulLen = pFree->ulLen;
                                           // Check pprev and pFree.
  pPtr = (PFREEBLOCK)((PCHAR)pPrev + pPrev->ulLen);
  if ( pPtr == pFree )                     // Are they adjacent?
  {                                        // Coalesce pprev and pFree.
    ulLen += pPrev->ulLen;                 // Udpate len.
    pPrev->ulLen = ulLen;
    if ( pHeapBlock->pRover == pFree )     // Check rover impact.
      pHeapBlock->pRover = pPrev;          // Update rover.
    pFree = pPrev;                         // Now work with coalesced blk.
  }
  else
  {
    pHeapBlock->cFree++;                   // One more free entry.
    pFree->pNext = pNext;                  // Update next/prev entries.
    pFree->pPrev = pPrev;
    pPrev->pNext = pFree;
    pNext->pPrev = pFree;
  }
  pHeapBlock->cAlloc--;                    // One fewer allocated.

  if ( ( pFree < pHeapBlock->pRover ) &&   // Check rover impact,
       ( ulLen > pHeapBlock->ulB4Rover ) ) // is len bigger than ulB4Rover
    pHeapBlock->ulB4Rover = ulLen;         // then update ulB4Rover.

  if ( ulLen > pHeapBlock->ulLargest )     // Check largest block.
    pHeapBlock->ulLargest = ulLen;
}

static BOOL _memResize(PHEAPBLOCK pHeapBlock, PVOID pPointer, ULONG ulSize)
{
  PFREEBLOCK           p1, p2;
  PFREEBLOCK           pNext, pPrev;
  ULONG                ulNewSize, ulOldSize, ulFreeSize, ulGrowthSize;

  //          ulLen           Round up to 4 bytes.
  ulNewSize = sizeof(ULONG) + ( (ulSize + 3) & ~3 );
  if ( ulNewSize < ulSize )
    ulNewSize = ~0;                         // Go for maximum.
  if ( ulNewSize < sizeof(FREEBLOCK) )
    ulNewSize = sizeof(FREEBLOCK);

  p1 = (PFREEBLOCK)( (PCHAR)pPointer - sizeof(ULONG) );
  ulOldSize = p1->ulLen & ~1;

  if ( ulNewSize > ulOldSize )
  {                                        // Enlarging the current allocation.
    p2 = (PFREEBLOCK)( (PCHAR)p1 + ulOldSize );
    ulGrowthSize = ulNewSize - ulOldSize;

    while( TRUE )
    {
      ulFreeSize = p2->ulLen;
      if ( /*( ulFreeSize == _END_TAG ) || // It was last block in heap block*/
           ( (ulFreeSize & 1) != 0 ) )       // Next piece is allocated or it
        return FALSE;                        //   was last block in heap block.

      pNext = p2->pNext;
      pPrev = p2->pPrev;

      if ( pHeapBlock->pRover == p2 )
        pHeapBlock->pRover = pPrev;

      if ( ( ulFreeSize < ulGrowthSize )  ||
           ( ulFreeSize - ulGrowthSize ) < sizeof(FREEBLOCK) )
      {                                    // Unlink small next (free) block.
        pPrev->pNext = pNext;
        pNext->pPrev = pPrev;
        p1->ulLen += ulFreeSize;
        pHeapBlock->cFree--;

        if ( ulFreeSize >= ulGrowthSize )
          return TRUE;

        ulGrowthSize -= ulFreeSize;
        p2 = (PFREEBLOCK)( (PCHAR)p2 + ulFreeSize );
      }
      else
      {                                    // Expand our block, shrinking next.
        p1->ulLen += ulGrowthSize;
        p2 = (PFREEBLOCK)( (PCHAR)p2 + ulGrowthSize );
        p2->ulLen = ulFreeSize - ulGrowthSize;
        p2->pPrev = pPrev;
        p2->pNext = pNext;
        pPrev->pNext = p2;
        pNext->pPrev = p2;

        return TRUE;
      }
    }  // while( TRUE )

    return FALSE;                          // We will never get here.

  }  // if ( ulNewSize > ulOldSize )
  else if ( ( ulOldSize - ulNewSize ) >=
            sizeof(FREEBLOCK) )            // Allocation big enough to split.
  {                           
    p1->ulLen = ulNewSize | 1;             // Shrinking the current allocation.

    // Free the top portion.
    p1 = (PFREEBLOCK)( (PCHAR)p1 + ulNewSize );
    p1->ulLen = ( ulOldSize - ulNewSize ) | 1;

    pHeapBlock->cAlloc++;                  // _memFree will decrement cAlloc.
    _memFree( pHeapBlock, (PCHAR)p1 + sizeof(ULONG) );
  }

  return TRUE;
}

static void *_hmalloc(size_t ulSize)
{
  PHEAPBLOCK pHeapBlock;
  PVOID      pPointer;

  if ( pFirst == NULL )
    pPointer = NULL;
  else
  {
    pHeapBlock = pRover;
    do
    {
      pPointer = _memAllocator( pHeapBlock, ulSize );
      if ( pPointer != NULL )
      {
        pRover = pHeapBlock;
        break;
      }

      pHeapBlock = pHeapBlock->pNext;
      if ( pHeapBlock == NULL )
        pHeapBlock = pFirst;
    }
    while( pHeapBlock != pRover );
  }

  if ( pPointer == NULL )
  {
    ULONG    ulHeapSize = ulSize < _MIN_HEAPBLOCK_SIZE
                            ? _MIN_HEAPBLOCK_SIZE : ulSize;

    do
    {
      pHeapBlock = __memHeapAlloc( ulHeapSize );
      if ( pHeapBlock != NULL )
      {
        pPointer = _memAllocator( pHeapBlock, ulSize );
        if ( pPointer != NULL )
          pRover = pHeapBlock;
        break;
      }
      ulHeapSize /= 2;
    }
    while( ulHeapSize > ulSize );
  }

  return pPointer;
}



/*
 *  Public routines.
 */

void *hmalloc(size_t ulSize)
{
  PVOID      pPointer;

  if ( ulSize == 0 )
    return NULL;

  if ( !_hmemLock() )
    return NULL;

  pPointer = _hmalloc( ulSize );

  _hmemUnlock();

  return pPointer;
}

void hfree(void *pPointer)
{
  PHEAPBLOCK pHeapBlock;

#ifdef DEBUG_FILE
  if ( pPointer == NULL )
    debugPCP( "hfree(NULL)" );
#endif

  while( !_hmemLock() )
    DosSleep( 1 );                         // I hope this never happens.

  pHeapBlock = (PCHAR)pPointer < (PCHAR)pRover ? pFirst : pRover;
  do
  {
    if ( (PCHAR)pPointer < &((PCHAR)pHeapBlock)[pHeapBlock->ulLen] )
    {
      _memFree( pHeapBlock, pPointer );
      pRover = pHeapBlock;
      break;
    }

    pHeapBlock = pHeapBlock->pNext;
  }
  while( pHeapBlock != NULL );

  _hmemUnlock();

  if ( pHeapBlock == NULL )
    debugPCP( "heap block not found" );
}

void *hrealloc(void *pPointer, size_t ulSize)
{
  PHEAPBLOCK pHeapBlock;

  if ( pPointer == NULL )
    return hmalloc( ulSize );

  if ( ulSize == 0 )
  {
    hfree( pPointer );
    return NULL;
  }

  while( !_hmemLock() )
    DosSleep( 1 );                         // I hope this never happens.

  pHeapBlock = (PCHAR)pPointer < (PCHAR)pRover ? pFirst : pRover;
  do
  {
    if ( (PCHAR)pPointer < &((PCHAR)pHeapBlock)[pHeapBlock->ulLen] )
    {
      if ( _memResize( pHeapBlock, pPointer, ulSize ) )
        pRover = pHeapBlock;
      else
      {
        void *pNew = _hmalloc( ulSize );

        if ( pNew != NULL )
        {
#if 0
          memcpy( pNew, pPointer,
                  ( *(PULONG)( (PCHAR)pPointer - sizeof(ULONG) ) ) & ~1 );
#else
          // All memory block sizes are rounded up to 4 bytes, we can use movsl
	  int d0, d1;
          __asm__ __volatile__ (
            "mov -4(%%esi), %%ecx\n\t"     // Get source size from [pPointer-4].
            "shrl $2, %%ecx\n\t"           // Divide size by four.
            "cld\n\t"                      // Clear flag to copy forward.
            "rep movsl"                    // Copy source_size/4 double words.
            : "=&D" (d0), "=&S" (d1)
            : "0" (pNew), "1" (pPointer)   // pNew -> edi, pPointer -> esi.
            : "%ecx"                       // We change ecx.
          );
#endif
          _memFree( pHeapBlock, pPointer );
        }

        pPointer = pNew;
      }

      _hmemUnlock();
      return pPointer;
    }

    pHeapBlock = pHeapBlock->pNext;
  }
  while( pHeapBlock != NULL );

  _hmemUnlock();

  debugPCP( "heap block not found" );
  return NULL;
}

char *hstrdup(char *pcStr)
{
  ULONG      cbStr;
  PCHAR      pcNew;

  if ( ( pcStr == NULL ) || ( *pcStr == '\0' ) )
  {
    debugPCP( "null pointer or empty string given" );
    return NULL;
  }

  cbStr = strlen( pcStr ) + 1;
  pcNew = hmalloc( cbStr );
  if ( pcNew != NULL )
    memcpy( pcNew, pcStr, cbStr );

  return pcNew;
}

void *hcalloc(size_t ulN, size_t ulSize)
{
  void       *pPointer;

  ulSize *= ulN;
  pPointer = hmalloc( ulSize );
  if ( pPointer != NULL )
  {
#if 1
    bzero( pPointer, ulSize );
#else
    int d0, d1;
    __asm__ __volatile__(
      "shrl $2, %%ecx\n\t"
      "xor %%eax, %%eax\n\t"
      "cld\n\t"
      "rep\n\t"
      "stosl"
      : "=&D" (d1), "=&c" (d0)
      : "0" (pPointer), "1" (ulSize)
      : "%eax"
    );
#endif
  }

  return pPointer;
}

/*
VOID __memHeapDebug(PHEAPBLOCK pHeapBlock)
{
  PFREEBLOCK           pFree = pHeapBlock->stFreeHead.pNext;

  printf( "Heap block: 0x%X\n", pHeapBlock );
  printf( "  ulLen = %u\n", pHeapBlock->ulLen );
  printf( "  pRover = 0x%X\n", pHeapBlock->pRover );
  printf( "  ulB4Rover = %u\n", pHeapBlock->ulB4Rover );
  printf( "  ulLargest = %u\n", pHeapBlock->ulLargest );
  printf( "  cAlloc = %u\n", pHeapBlock->cAlloc );
  printf( "  cFree = %u\n", pHeapBlock->cFree );

  while( TRUE )
  {
    printf( "  Free: 0x%X, %u bytes\n", pFree, pFree->ulLen );

    pFree = pFree->pNext;                  // Advance to next entry.

    if ( pFree == &pHeapBlock->stFreeHead )// If back at start.
      break;
  }
}

VOID hdebug()
{
  PHEAPBLOCK pHeapBlock;

  DosRequestMutexSem( hmtxHighMem, SEM_INDEFINITE_WAIT );

  pHeapBlock = pFirst;
  while( pHeapBlock != NULL )
  {
    __memHeapDebug( pHeapBlock );
    pHeapBlock = pHeapBlock->pNext;
  }

  DosReleaseMutexSem( hmtxHighMem );
}
*/
