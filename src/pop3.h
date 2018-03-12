#ifndef POP3_H
#define POP3_H

// Flag for protocol user value ( see netsrvClntGetUserPtr() ).
#define POP3_LOGINDISABLED       0x0001

BOOL pop3Init();
VOID pop3Done();
BOOL pop3Lock(PSZ pszHomePath, BOOL fLock);

#endif // POP3_H
