#include "Thread.h"
/*=======================================================================
*function:rountine that by called when a thread start
*================================================================*/
VOID _ThreadStart(THREADID threadid,CONTEXT *ctxt,INT32 flags,VOID *v)
{
	//这个结构体用来保存和栈相关的结构信息，在栈退出时应该将这个结构体删除掉。//在每个线程开始的时候为线程申请一个栈，用来保存相关信息。
	TEB_INFO *tebinfo=new TEB_INFO;
	UINT32 fs_base;
	UINT32 Stack_top=0;
	UINT32 Stack_base=0;
	int bytes;
	if(tebinfo==NULL)
	{
		return;
	}
	_asm
	{
		push eax
		MOV eax,fs:[0x18]
		MOV fs_base,eax
		POP eax
	}
	PIN_SafeCopy(&Stack_base,(BYTE *)(fs_base+4),sizeof(ADDRINT));//fs寄存器偏移4的位置为线程栈的底部
	PIN_SafeCopy(&Stack_top,(BYTE *)(fs_base+8),sizeof(ADDRINT));
	ADDRINT espValue=PIN_GetContextReg(ctxt,REG_ESP);
	if(Peb_Getted==false)
	{
		bytes=PIN_SafeCopy(&PEB_BASE,(BYTE *)(fs_base+0x30),sizeof(UINT32));//fs偏移0x30的位置为指向PEB的指针。
		if(bytes==0)
		{
			Peb_Getted=false;//如果获取到0个字节则表示获取数据失败。
		}
		else
		{
			Peb_Getted=true;
		}
	}
	tebinfo->fs_imageaddress=fs_base;
	tebinfo->stack_base=Stack_base;
	tebinfo->stack_top=Stack_top;
	tebinfo->thread_id=threadid;
	PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(tebinfo));//将栈的相关信息保存到线程寄存器中。
	tebinfo=NULL;
}


/*========================================================
*funtion:routine that be called when a thread exit
*=========================================================*/
VOID _ThreadFini(THREADID threadid,const CONTEXT *ctxt,INT32 code,VOID *v)
{
	TEB_INFO *tebinfo=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));
	delete tebinfo;
	tebinfo=NULL;
}