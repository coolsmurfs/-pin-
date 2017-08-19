#ifndef __THREAD_H__
#define __THREAD_H__
#include "struct.h"
#include "stack.h"
extern REG RegStack;
extern ADDRINT PEB_BASE;
extern bool Peb_Getted;
extern FILE *flog;
VOID _ThreadStart(THREADID threadid,CONTEXT *ctxt,INT32 flags,VOID *v);
VOID _ThreadFini(THREADID threadid,const CONTEXT *ctxt,INT32 code,VOID *v);
#endif
