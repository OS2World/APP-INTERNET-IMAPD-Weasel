#ifndef INIFILES_H
#define INIFILES_H

#define INITYPE_INI    0
#define INITYPE_TNI    1

typedef LHANDLE APIENTRY (*IFNOPEN)(LHANDLE, PSZ pcFileName);
typedef BOOL APIENTRY (*IFNCLOSE)(LHANDLE hObj);
typedef BOOL APIENTRY (*IFNQUERYSIZE)(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                      PULONG pulReqLen);
typedef BOOL APIENTRY (*IFNQUERYDATA)(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                      PVOID pBuf, PULONG pulBufLen);
typedef ULONG APIENTRY (*IFNQUERYSTRING)(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                             PSZ pszDefault, PVOID pBuffer, ULONG ulBufferMax);
/*typedef LONG APIENTRY (*IFNQUERYINT)(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                     LONG lDefault);*/


typedef struct _INICLASS {
  IFNOPEN              fnOpen;
  IFNCLOSE             fnClose;
  IFNQUERYSIZE         fnQuerySize;
  IFNQUERYDATA         fnQueryData;
  IFNQUERYSTRING       fnQueryString;
//  IFNQUERYINT          fnQueryInt;
} INICLASS, *PINICLASS;

typedef struct _INI {
  PINICLASS  pClass;
  LHANDLE    hObj;
} INI, *PINI;


BOOL iniOpen(PINI pINI, ULONG ulType, PSZ pszFile);

#define iniClose(_pINI) (_pINI)->pClass->fnClose( (_pINI)->hObj )

#define iniQuerySize(_pINI,_pcApp,_pcKey,_pulReqLen) \
 (_pINI)->pClass->fnQuerySize( (_pINI)->hObj,(_pcApp),(_pcKey),(_pulReqLen) )

#define iniQueryData(_pINI,_pcApp,_pcKey,_pBuf,_pulBufLen) \
 (_pINI)->pClass->fnQueryData( (_pINI)->hObj,(_pcApp),(_pcKey),(_pBuf),\
                               (_pulBufLen) )

#define iniQueryString(_pINI,_pcApp,_pcKey,_pcDef,_pBuf,_ulBufMax) \
 (_pINI)->pClass->fnQueryString( (_pINI)->hObj,(_pcApp),(_pcKey),(_pcDef), \
                                 (_pBuf),(_ulBufMax) )

/*#define iniQueryInt(_pINI,_pcApp,_pcKey,_lDef) \
 (_pINI)->pClass->fnQueryInt( (_pINI)->hObj,(_pcApp),(_pcKey),(_lDef) )*/

#endif // INIFILES_H
