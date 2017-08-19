#include "Thread.h"
/*=======================================================================
*function:rountine that by called when a thread start
*================================================================*/
VOID _ThreadStart(THREADID threadid,CONTEXT *ctxt,INT32 flags,VOID *v)
{
	//����ṹ�����������ջ��صĽṹ��Ϣ����ջ�˳�ʱӦ�ý�����ṹ��ɾ������//��ÿ���߳̿�ʼ��ʱ��Ϊ�߳�����һ��ջ���������������Ϣ��
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
	PIN_SafeCopy(&Stack_base,(BYTE *)(fs_base+4),sizeof(ADDRINT));//fs�Ĵ���ƫ��4��λ��Ϊ�߳�ջ�ĵײ�
	PIN_SafeCopy(&Stack_top,(BYTE *)(fs_base+8),sizeof(ADDRINT));
	ADDRINT espValue=PIN_GetContextReg(ctxt,REG_ESP);
	if(Peb_Getted==false)
	{
		bytes=PIN_SafeCopy(&PEB_BASE,(BYTE *)(fs_base+0x30),sizeof(UINT32));//fsƫ��0x30��λ��Ϊָ��PEB��ָ�롣
		if(bytes==0)
		{
			Peb_Getted=false;//�����ȡ��0���ֽ����ʾ��ȡ����ʧ�ܡ�
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
	PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(tebinfo));//��ջ�������Ϣ���浽�̼߳Ĵ����С�
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