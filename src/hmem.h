#ifndef HMEM_H
#define HMEM_H

void *hmalloc(size_t ulSize);
void hfree(void *pPointer);
void *hrealloc(void *pPointer, size_t ulSize);
char *hstrdup(char *pcStr);
void *hcalloc(size_t ulN, size_t ulSize);

#endif // HMEM_H
