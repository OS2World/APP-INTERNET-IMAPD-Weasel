#ifndef DEBUG_H
#define DEBUG_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define DBGCNT_INC	1
#define DBGCNT_DEC	-1

#ifdef DEBUG_FILE

#define DEBUG_CODE

#define debugInit() debug_init(DEBUG_FILE)
#define debugDone() debug_done()
// Write the record with time
#define debug(s,...) debug_write(__FILE__"/%s(): "s"\n", __func__, ##__VA_ARGS__)
// Write the formatted text
#define debugText(s,...) debug_text(""s ,##__VA_ARGS__)
#define debugTextBuf(buf,buflen,crlf_fl) debug_textbuf(buf, buflen, crlf_fl)
// Make zero-terminated string from given buffer and lenght of buffer
#define debugBufPSZ(buf, buflen) debug_buf2psz(buf, buflen)
// Output to STDOUT message s: source_file#source_line_number func() [control point] message
#define debugPCP(s) printf( __FILE__"#%u %s() [control point] "s"\n", __LINE__, __func__ )
// Same as debugPCP() for debug file
#define debugCP(s) debug_write( __FILE__"#%u %s() [control point] "s"\n", __LINE__, __func__ )
#define debugInc(cnt) debug_counter(cnt,DBGCNT_INC)
#define debugDec(cnt) do {\
  if ( debug_counter( cnt, DBGCNT_DEC ) )\
    debug_write( __FILE__"#%u %s(): Decrement a zero-counter "cnt"\n", __LINE__, __func__ );\
} while( 0 )
#define debugIncNumb(cnt,numb) debug_counter(cnt,numb)
#define debugMAlloc(size) debug_malloc(size, __FILE__, __LINE__)
#define debugCAlloc(n,size) debug_calloc(n, size, __FILE__, __LINE__)
#define debugFree(ptr) debug_free(ptr, __FILE__, __LINE__)
#define debugReAlloc(ptr,size) debug_realloc(ptr,size, __FILE__, __LINE__)
#define debugStrDup(src) debug_strdup(src, __FILE__, __LINE__)
#define debugMemUsed() debug_memused()
#define debugStat() debug_state()

# if !defined(DEBUG_C)
#  define malloc(size) debug_malloc(size, __FILE__, __LINE__)
#  define calloc(n,size) debug_calloc(n, size, __FILE__, __LINE__)
#  define free(ptr) debug_free(ptr, __FILE__, __LINE__)
#  define realloc(ptr,size) debug_realloc(ptr,size, __FILE__, __LINE__)
#  define strdup(src) debug_strdup(src, __FILE__, __LINE__)

#  define socket(domain, type, protocol) debug_socket(domain, type, protocol)
#  define accept(s, name, namelen) debug_accept(s, name, namelen)
#  define soclose(s) debug_soclose(s)

#  define _beginthread(start_address, stack_bottom, stack_size, arglist) \
          debug_beginthread(start_address, stack_bottom, stack_size, arglist)
#  define _endthread() debug_endthread()
# endif

#else // DEBUG_FILE

#define debugInit()
#define debugDone()
#define debug(s,...) do { } while( 0 )
#define debugText(s,...)
#define debugTextBuf(buf,buflen,crlf_fl)
#define debugBufPSZ(buf, buflen)
#define debugPCP(s)
#define debugCP(s)
#define debugInc(cnt)
#define debugDec(cnt)
#define debugIncNumb(cnt,numb)
#define debugMAlloc(size) malloc(size)
#define debugCAlloc(n,size) calloc(n,size)
#define debugFree(ptr) free(ptr)
#define debugReAlloc(ptr,size) realloc(ptr,size)
#define debugStrDup(src) strdup(src)
#define debugMemUsed() -1
#define debugStat()

#endif // DEBUG_FILE

#ifdef __OS2__
#define DBGLIBENTRY _System
#else
#define DBGLIBENTRY _cdecl
#endif

void debug_init(char *pcDebugFile);
void debug_done();

// Write the record with time
void debug_write(char *pcFormat, ...);
// Write the formatted text
void debug_text(char *pcFormat, ...);
void debug_textbuf(char *pcBuf, unsigned int cbBuf, int fCRLF);
// Make zero-terminated string from given buffer and lenght of buffer
char *debug_buf2psz(char *pcBuf, unsigned int cbBuf);
// Change counter value, iDelta: DBGCNT_INC / DBGCNT_DEC
// Return 1 if decrement when current value is zero.
int debug_counter(char *pcName, int iDelta);

// Memory allocations debug
void *debug_malloc(size_t size, char *pcFile, int iLine);
void *debug_calloc(size_t n, size_t size, char *pcFile, int iLine);
void debug_free(void *ptr, char *pcFile, int iLine);
void *debug_realloc(void *old_blk, size_t size, char *pcFile, int iLine);
char *debug_strdup(const char *src, char *pcFile, int iLine);

// Sockets debug
int debug_socket(int domain, int type, int protocol);
int debug_accept(int s, void *name, int *namelen);
int debug_soclose(int s);

// Threads
int debug_beginthread(void (*start_address)(void *), void *stack_bottom,
                      unsigned stack_size, void *arglist);
void debug_endthread();

int debug_memused();

// Output counters to the debug file
void DBGLIBENTRY debug_state();

#endif //  DEBUG_H
