#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdarg.h>
#include <os2.h>
#include "utils.h"

#define CTX_ALL        ULONG_MAX

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
BOOL ctxSetReadPos(PCTX pCtx, ULLONG ullPos);
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
BOOL ctxFileWrite(PCTX pCtx, HFILE hFile);
BOOL ctxFileRead(PCTX pCtx, HFILE hFile);

#endif // CONTEXT_H
