#ifndef UTILS_H
#define UTILS_H

#define BUF_SKIP_SPACES(cb, pc) \
  while( (cb > 0) && isspace( *pc ) ) { cb--; pc++; }
#define BUF_MOVE_TO_SPACE(cb, pc) \
  while( (cb > 0) && !isspace( *pc ) ) { cb--; pc++; }
#define BUF_RTRIM(cb, pc) \
  while( (cb > 0) && ( isspace( pc[cb - 1] ) ) ) cb--

#define ARRAYSIZE(a) ( sizeof(a) / sizeof(a[0]) )

BOOL utilBufCutWord(PULONG pcbText, PCHAR *ppcText,
                    PULONG pcbWord, PCHAR *ppcWord);
LONG utilStrWordIndex(PSZ pszList, LONG cbWord, PCHAR pcWord);

#endif // UTILS_H
