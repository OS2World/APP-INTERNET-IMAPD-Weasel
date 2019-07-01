#ifndef CONTROL_H
#define CONTROL_H

typedef struct _EXQUOTARCPT *PEXQUOTARCPT;

// Structure describing the session. Located in user memory space.
typedef struct _CTLSESS {
  ULONG                cExQuotaRcpt;
  PEXQUOTARCPT         *ppExQuotaRcpt;
} CTLSESS, *PCTLSESS;


VOID ctlInit(PCTLSESS pCtlSess);
VOID ctlDone(PCTLSESS pCtlSess);
BOOL ctlRequest(PCTLSESS pCtlSess, PCTX pCtx, LONG cbInput, PCHAR pcInput);

#endif // CONTROL_H
