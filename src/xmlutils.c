/*
  XML format helpers for libxml2.
*/

#include <ctype.h>
#include <string.h>
#include <os2.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "utils.h"
#include "log.h"
#include "xmlutils.h"
#include "debug.h"               // Should be last.

xmlDocPtr xmluReadFile(PSZ pszFName, PSZ pszRoot, xmlNodePtr *ppxmlRoot)
{
  xmlDocPtr   pxmlDoc = xmlReadFile( pszFName, "UTF-8",
                                     XML_PARSE_NOERROR + XML_PARSE_NOWARNING );
  if ( pxmlDoc == NULL )
  {
    CHAR               acBuf[512];
    PCHAR              pcBuf;
    xmlErrorPtr        pError = xmlGetLastError();
    LONG               cb;

    if ( ( pError != NULL ) && ( pError->code != 1549 ) )
                               // 1549 - file does not exist.
    {
      pcBuf = &acBuf[ sprintf( acBuf, "Error parsing file: %s", pszFName ) ];

      if ( pError->line != 0 )
        pcBuf += sprintf( pcBuf, ":%d", pError->line );

      cb = _snprintf( pcBuf, sizeof(acBuf) - (pcBuf - acBuf) - 1, ", %s",
                      pError->message );
      if ( cb < 0 )
      {
        pcBuf = &acBuf[sizeof(acBuf) - 1];
        *pcBuf = '\0';
      }
      else
        pcBuf += cb;
      
      while( (pcBuf > acBuf) && isspace( *(pcBuf - 1) ) ) pcBuf--;
      *pcBuf = '\0';

      logs( 0, acBuf );
    }

    xmlResetLastError();

    return NULL;
  }

  *ppxmlRoot = xmlDocGetRootElement( pxmlDoc );
  if ( ( *ppxmlRoot == NULL ) ||
       ( xmlStrcmp( (*ppxmlRoot)->name, pszRoot ) != 0 ) )
  {
    logf( 0, "Unknown root node <%s> in %s", (*ppxmlRoot)->name, pszFName );
    xmlFreeDoc( pxmlDoc );
    return NULL;
  }

  return pxmlDoc;
}

PSZ xmluGetNodeText(xmlNodePtr pxmlNode)
{
  PSZ        pszText;

  if ( ( pxmlNode == NULL ) || ( pxmlNode->children == NULL ) ||
       ( pxmlNode->children->content == NULL ) )
    return NULL;

  pszText = pxmlNode->children->content;
  STR_SKIP_SPACES( pszText );

  return pszText;
}

LONG xmluGetNodeValue(xmlNodePtr pxmlNode, ULONG cbBuf, PCHAR pcBuf)
{
  PCHAR      pcVal = xmluGetNodeText( pxmlNode );
  PCHAR      pcEnd;
  LONG       cbVal;

  if ( cbBuf == 0 )
    return -1;

  pcBuf[0] = '\0';

  if ( pcVal == NULL )
    return 0;

  // Remove trailing spaces.
  pcEnd = strchr( pcVal, '\0' );
  while( ( pcEnd > pcVal ) && isspace( *(pcEnd-1) ) )
    pcEnd--;

  // Copy result to the user buffer.
  cbVal = pcEnd - pcVal;
  if ( cbVal >= cbBuf )
    cbVal = -1;
  else
  {
    memcpy( pcBuf, pcVal, cbVal );
    pcBuf[cbVal] = '\0';
  }

  return cbVal;
}

ULLONG xmluGetNodeLLong(xmlNodePtr pxmlNode, LLONG llDefault)
{
  PSZ        pszText;
  PCHAR      pcEnd;
  LLONG      llRes;

  if ( ( pxmlNode == NULL ) || ( pxmlNode->children == NULL ) ||
       ( pxmlNode->children->content == NULL ) )
    return NULL;

  pszText = pxmlNode->children->content;
  STR_SKIP_SPACES( pszText );

  llRes = strtoll( pszText, &pcEnd, 0 );

  return (PCHAR)pszText == pcEnd ? llDefault : llRes;
}

ULLONG xmluGetNodeULLong(xmlNodePtr pxmlNode, ULLONG ullDefault)
{
  PSZ        pszText;
  PCHAR      pcEnd;
  ULLONG     ullRes;

  if ( ( pxmlNode == NULL ) || ( pxmlNode->children == NULL ) ||
       ( pxmlNode->children->content == NULL ) )
    return NULL;

  pszText = pxmlNode->children->content;
  STR_SKIP_SPACES( pszText );
  if ( *pszText == '-' )
    return ullDefault;

  ullRes = strtoull( pszText, &pcEnd, 0 );

  return (PCHAR)pszText == pcEnd ? ullDefault : ullRes;
}

xmlNodePtr xmluGetChildNode(xmlNodePtr pxmlNode, PSZ pszNode)
{
  if ( pxmlNode == NULL )
    return NULL;

  for( pxmlNode = pxmlNode->children; pxmlNode != NULL;
       pxmlNode = pxmlNode->next )
  {
    if ( !xmlIsBlankNode( pxmlNode ) &&
         ( xmlStrcmp( pxmlNode->name, pszNode ) == 0 ) )
      break;
  }

  return pxmlNode;
}

xmlNodePtr xmluGetNextNode(xmlNodePtr pxmlNode, PSZ pszNode)
{
  while( TRUE )
  {
    pxmlNode = pxmlNode->next;

    if ( ( pxmlNode == NULL ) ||
         ( !xmlIsBlankNode( pxmlNode ) &&
           ( xmlStrcmp( pxmlNode->name, pszNode ) == 0 ) ) )
      break;
  }

  return pxmlNode;
}

ULONG xmluChildElementCount(xmlNodePtr xmlParent, PSZ pszName)
{
  ULONG      ulRet = 0;
  xmlNodePtr xmlCur;

  if ( xmlParent == NULL )
    return 0;

  switch( xmlParent->type )
  {
    case XML_ELEMENT_NODE:
    case XML_ENTITY_NODE:
    case XML_DOCUMENT_NODE:
    case XML_DOCUMENT_FRAG_NODE:
    case XML_HTML_DOCUMENT_NODE:
      xmlCur = xmlParent->children;
      break;

    default:
      return 0;
  }

  for( ; xmlCur != NULL; xmlCur = xmlCur->next )
  {
    if ( ( xmlCur->type == XML_ELEMENT_NODE ) &&
         (
           ( pszName == NULL )
         ||
           ( ( xmlCur->name != NULL ) &&
             ( stricmp( xmlCur->name, pszName ) == 0 ) )
         )
       )
      ulRet++;
  }

  return ulRet;
}

xmlXPathObjectPtr xmluGetNodeSet(xmlDocPtr pxmlDoc, PSZ pszXPath)
{
  xmlXPathContextPtr   pContext;
  xmlXPathObjectPtr    pXPathObj;

  pContext = xmlXPathNewContext( pxmlDoc );
  if ( pContext == NULL )
  {
    debugCP( "xmlXPathNewContext() failed" );
    return NULL;
  }

  pXPathObj = xmlXPathEvalExpression( BAD_CAST pszXPath, pContext );
  xmlXPathFreeContext( pContext );
  if ( pXPathObj == NULL )
  {
    debug( "xmlXPathEvalExpression(\"%s\",) failed", pszXPath );
    return NULL;
  }

  if ( xmlXPathNodeSetIsEmpty( pXPathObj->nodesetval ) )
  {
    xmlXPathFreeObject( pXPathObj );
    return NULL;
  }

  return pXPathObj;
}

LONG xmluGetPathValue(xmlDocPtr pxmlDoc, ULONG cbBuf, PCHAR pcBuf,
                      PSZ pszXPathFmt, ...)
{
  va_list              arglist;
  xmlXPathObjectPtr    pXPathObj;
  PSZ                  pszXPath;
  LONG                 cbVal;

  if ( cbBuf == 0 )
    return -1;

  pcBuf[0] = '\0';

  pszXPath = malloc( 65536 );
  if ( pszXPath == NULL )
    return 0;

  // Make XPath string.
  va_start( arglist, pszXPathFmt ); 
  cbVal = vsnprintf( pszXPath, 65536, pszXPathFmt, arglist ); 
  va_end( arglist );
  if ( pszXPath == NULL )
  {
    debug( "Result string for \"%s\" is too long", pszXPathFmt );
    free( pszXPath );
    return 0;
  }

  // Get nodeset.
  pXPathObj = xmluGetNodeSet( pxmlDoc, pszXPath );
  free( pszXPath );
  if ( pXPathObj == NULL )
    return 0;

  // Get node text.
  cbVal = xmluGetNodeValue( pXPathObj->nodesetval->nodeTab[0], cbBuf, pcBuf );

  xmlXPathFreeObject( pXPathObj );

  return cbVal;
}
