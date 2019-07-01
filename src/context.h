#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdarg.h>
#include <os2.h>
#include "utils.h"

#define CTX_ALL        ULONG_MAX

// ctxSetReadPos(,ulOrigin,)
#define CTX_RPO_BEGIN    0
#define CTX_RPO_CURRENT  1
#define CTX_RPO_END      2

typedef struct _CTX    *PCTX;
typedef LONG (*PCTXWRITEFILTER)(ULONG cbBuf, PVOID pBuf, PVOID pData);

PCTX ctxNew();
VOID ctxFree(PCTX pCtx);
VOID ctxSetWriteFilter(PCTX pCtx, PCTXWRITEFILTER pfnFilter, PVOID pFilterData);
BOOL ctxWrite(PCTX pCtx, LONG cbData, PVOID pData);

// ULONG ctxRead(PCTX pCtx, ULONG cbBuf, PVOID pBuf, BOOL fPeek);
//
// Reads up to cbData bytes from the context object pCtx to the buffer pointed
// by pData. Read position will not be changed of fPeek is TRUE. If pData is
// NULL and fPeek is FALSE the read position moves forward up to cbData bytes.
ULONG ctxRead(PCTX pCtx, ULONG cbData, PVOID pData, BOOL fPeek);

ULLONG ctxQuerySize(PCTX pCtx);
ULLONG ctxQueryAvailForRead(PCTX pCtx);

// ulOrigin - CTX_RPO_xxxxx
BOOL ctxSetReadPos(PCTX pCtx, ULONG ulOrigin, LLONG llPos);
#if 0
// deprecated
BOOL ctxTruncate(PCTX pCtx, LLONG llNewSize);
#endif

BOOL ctxWriteFmtV(PCTX pCtx, BOOL fCRLF, PSZ pszFmt, va_list arglist);
BOOL ctxWriteFmt(PCTX pCtx, PSZ pszFmt, ...);
BOOL ctxWriteFmtLn(PCTX pCtx, PSZ pszFmt, ...);
BOOL ctxWriteStrLn(PCTX pCtx, PSZ pszStr);
// Writes up to ullMaxBytes bytes or full context if ullMaxBytes is CTX_ALL.
BOOL ctxWriteCtx(PCTX pCtx, PCTX pCtxSrc, ULLONG ullMaxBytes);

PCTX ctxNewFromTemplate(LONG cbText, PCHAR pcText,
                        BOOL (*fnSubset)(PCTX pCtx, ULONG cbKey, PSZ pszKey,
                                         PVOID pData),
                        PVOID pData);

// Returns system API error code (DOS Error value).
ULONG ctxFileWrite(PCTX pCtx, HFILE hFile);
ULONG ctxFileRead(PCTX pCtx, HFILE hFile);

#endif // CONTEXT_H
