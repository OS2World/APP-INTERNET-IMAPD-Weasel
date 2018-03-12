#ifndef WLOG_H
#define WLOG_H

BOOL wlogInit(BOOL fScreenOutput);
VOID wlogDone();
VOID wlogRead();
BOOL wlogIsConnected();

#endif // WLOG_H
