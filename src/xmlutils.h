#ifndef XMLUTILS_H
#define XMLUTILS_H

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#define xmluGetChildNodeText(__pxmlNode, __pszSubNode) \
  xmluGetNodeText( xmluGetChildNode(  __pxmlNode, __pszSubNode ) )

#define xmluGetChildNodeULLong(__pxmlNode, __pszSubNode, __def) \
  xmluGetNodeULLong( xmluGetChildNode(  __pxmlNode, __pszSubNode ), __def )

#define xmluGetChildNodeLLong(__pxmlNode, __pszSubNode, __def) \
  xmluGetNodeLLong( xmluGetChildNode(  __pxmlNode, __pszSubNode ), __def )

xmlDocPtr xmluReadFile(PSZ pszFName, PSZ pszRoot, xmlNodePtr *ppxmlRoot);
PSZ xmluGetNodeText(xmlNodePtr pxmlNode);
LONG xmluGetNodeValue(xmlNodePtr pxmlNode, ULONG cbBuf, PCHAR pcBuf);
ULLONG xmluGetNodeLLong(xmlNodePtr pxmlNode, LLONG llDefault);
ULLONG xmluGetNodeULLong(xmlNodePtr pxmlNode, ULLONG ullDefault);
xmlNodePtr xmluGetChildNode(xmlNodePtr pxmlNode, PSZ pszNode);
xmlNodePtr xmluGetNextNode(xmlNodePtr pxmlNode, PSZ pszNode);
ULONG xmluChildElementCount(xmlNodePtr xmlParent, PSZ pszName);

// Creates XPath string from pszXPathFmt and variable arguments,
// finds a node by this path and stores node's text to user buffer pcBuf.
// Returns: length of result string without ZERO or 0 if node not found/empty
//          or -1 if not enough space in the output buffer.
LONG xmluGetPathValue(xmlDocPtr pxmlDoc, ULONG cbBuf, PCHAR pcBuf,
                      PSZ pszXPathFmt, ...);

#endif // XMLUTILS_H
