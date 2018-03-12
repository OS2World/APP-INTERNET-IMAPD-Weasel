#ifndef MESSAGE_H
#define MESSAGE_H

#include <os2.h>
#include "context.h"

// Message fields
// --------------

typedef struct _FIELD {
  struct _FIELD        *pNext;
  ULONG                cbName;
  CHAR                 acField[1];
} FIELD, *PFIELD;

VOID fldFree(PFIELD pFields);
PFIELD fldRead(FILE *pfMsg, PSZ pszBoundary);
PFIELD fldReadHeader(PSZ pszFile);
PSZ fldFind(PFIELD pFields, PSZ pszName);

// PCHAR fldGetParam(PSZ pszValue, PSZ pszName, PULONG pcbVal)
//
// Reads 'param' from string like 'value; a="Aaa"; b=0.1; param="text"'
// Returns pointer to the value ('text') and length of value at pcbVal.
//
PCHAR fldVGetParam(PSZ pszValue, PSZ pszName, PULONG pcbVal);

// PSZ fldGetParamNew(PSZ pszValue, PSZ pszName)
//
// Reads 'param' from string like 'value; a="Aaa"; b=0.1; param="text"'
// Returns pointer to the allocated memory contains ASCIIZ value ('text').
// Pointer should be destroyed with free().
//
PSZ fldVGetParamNew(PSZ pszValue, PSZ pszName);

// PCHAR fldGetContentSubtype(PSZ pszValue, PULONG pcbVal)
//
// Reads subtype from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the subtype name and length of subtype name at pcbVal.
//
PCHAR fldVGetContentSubtype(PSZ pszValue, PULONG pcbVal);

// PSZ fldGetContentSubtypeNew(PSZ pszValue, BOOL fUppercase)
//
// Reads subtype from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the allocated memory contains ASCIIZ subtype name.
// Pointer should be destroyed with free().
//
PSZ fldVGetContentSubtypeNew(PSZ pszValue, BOOL fUppercase);

// PCHAR fldGetContentType(PSZ pszValue, PULONG pcbVal)
//
// Reads content type from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the type name and length of type name at pcbVal.
//
PCHAR fldVGetContentType(PSZ pszValue, PULONG pcbVal);

// PSZ fldGetContentTypeNew(PSZ pszValue, BOOL fUppercase)
//
// Reads content type from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the allocated memory contains ASCIIZ type name.
// Pointer should be destroyed with free().
//
PSZ fldVGetContentTypeNew(PSZ pszValue, BOOL fUppercase);

// PCHAR fldGetValue(PSZ pszValue, PULONG pcbVal)
//
// Reads value of sructured field: "value; param1=val1, param2=val2".
// Returns pointer to the 'value' and length of 'value' at pcbVal.
//
PCHAR fldVGetValue(PSZ pszValue, PULONG pcbVal);


// Address list parser
// -------------------

// Output flags
#define IMFAP_GROUP              0x0001
#define IMFAP_GROUPEND           0x0002
#define IMFAP_GROUPBEGIN         0x0004
#define IMFAP_ERROR              0x0008
#define IMFAP_PUTPUT_MASK        0x00FF
// Input flags: flgVAddrLstBegin(,ulFlags,,)
#define IMFAP_NONAMES            0x0100

typedef struct _IMFADDRPARSER {
  PSZ        pszInput;
  PSZ        pszCharset;
  ULONG      ulFlags;            // IMFAP_xxxxx
  ULONG      cbName;
  PCHAR      pcName;             // ZERO-ended. With IMFAP_GROUPBEGIN - name of
                                 // the group.
  ULONG      cbAddr;
  PCHAR      pcAddr;             // ZERO-ended, may be NULL.
} IMFADDRPARSER, *PIMFADDRPARSER;

/*
  Address list parser for the values of fields:
    "To", "Resent-To", "cc", "Resent-cc", "bcc", "Resent-bcc", "From",
    "Sender", "From", "Resent-From", "Resent-Sender" and "Resent-From".

  IMFADDRPARSER        stParser;
  flgVAddrLstBegin( &stParser, pszFieldValue, "UTF-16" );
  while( flgVAddrLstNext( &stParser ) )
    ...
  flgVAddrLstEnd( &stParser );
*/
VOID flgVAddrLstBegin(PIMFADDRPARSER pParser, ULONG ulFlags, PSZ pszInput, PSZ pszCharset);
VOID flgVAddrLstEnd(PIMFADDRPARSER pParser);
BOOL flgVAddrLstNext(PIMFADDRPARSER pParser);


// Search text in fields
// ---------------------

// BOOL fldIsContainsSubstr(PFIELD pFields, PSZ pszField, BOOL fAddrOnly,
//                          PSZ pszSubstr, PSZ pszCharset);
//
// Searches text pszSubstr in the field pszField which listed in pFields.
// pszCharset is charset of pszSubstr, if it is NULL then string pszSubstr
// should be uppercase UTF-16.
// fAddrOnly is TRUE - look for substring only in addresses if field is one
// of address-list field (From, To, Sender, e.t.c.), not in names.
// Returns TRUE if value of the field pszField from the list pFields contains
// substring pszSubstr.
//
BOOL fldIsContainsSubstr(PFIELD pFields, PSZ pszField, BOOL fAddrOnly,
                         PSZ pszText, PSZ pszCharset);

// BOOL fldHdrIsContainsSubstr(PFIELD pFields, PSZ pszSubstr, PSZ pszCharset);
//
// Same as fldIsContainsSubstr() but for all fields in the field list pFields.
//
BOOL fldHdrIsContainsSubstr(PFIELD pFields, PSZ pszText, PSZ pszCharset);


// Message format
// --------------

#define IMFFL_HEADER             0x01
// IMFFL_NOTFIELDS uses with IMFFL_HEADER
#define IMFFL_NOTFIELDS          0x02
#define IMFFL_TEXT               0x04
// IMFFL_CONTENT equals IMFFL_TEXT but it uses to prepare reply n1.n2..nN
// (without .TEXT) at imap.c/_writeFetchBodyReply().
#define IMFFL_CONTENT            (IMFFL_TEXT | 0x08)
// IMFFL_FULL - header and text of the section.
#define IMFFL_FULL               (IMFFL_HEADER | IMFFL_NOTFIELDS | IMFFL_CONTENT)
#define IMFFL_PSTART             0x10
#define IMFFL_PLENGTH            0x20

typedef struct _IMFBODYPARAM {
  ULONG      cPart;
  PULONG     paPart;
  ULONG      ulFlags;         // IMFFL_xxxxx
  PSZ        pszFields;
  ULLONG     ullStart;        // in (with IMFFL_PSTART) / out
  ULLONG     ullLength;       // in (with IMFFL_PLENGTH) / out
} IMFBODYPARAM, *PIMFBODYPARAM;

PCTX imfGetBody(PSZ pszFile, PIMFBODYPARAM pBody);
PCTX imfGetEnvelope(PSZ pszFile);
PCTX imfGetBodyStruct(PSZ pszFile, BOOL fExtData);
BOOL imfSearchText(PSZ pszFile, PSZ pszText, PSZ pszCharset);
LONG imfGenerateMsgId(ULONG cbBuf, PCHAR pcBuf, PSZ pszDomain);

#endif // MESSAGE_H
