#include "Image.h"
static bool bRet=false;

VOID ImageLoad(IMG img, VOID *v)
{ 
	if(!IMG_Valid(img))
	{
		return;
	}
	BYTE* address=(BYTE *)IMG_StartAddress(img);
	//BYTE *addressIAT;
	//UINT32 count=0;
	UINT32 positon=0;
	UINT32 realcount=0;
	//count=_GetImageIATcount(address,&addressIAT,&realcount);
	//unsigned int *ptr=new unsigned int [count];
	IMAGEINFO* imageinfo = new IMAGEINFO;
	//imageinfo->_countImportIAT=count;//Get the count of the import function;
	imageinfo->_imageID=IMG_Id(img);
	imageinfo->_imagemapSize=IMG_SizeMapped(img);
	imageinfo->_imageName=IMG_Name(img);
	imageinfo->_isExecutable=!(IMG_IsStaticExecutable(img));
	//imageinfo->IATprt = ptr;
	positon=imageinfo->_imageName.rfind('\\');
	if(positon==0)
	{
		return;
	}
	if(IMG_IsMainExecutable(img))
	{
		if(!stringCompareIgnoreCase(imageinfo->_imageName.substr(positon+1,imageinfo->_imageName.length()-positon),"Acrord32.dll"))
		{
			IsAdeobeOrIE=true;
		}
	}
	imageinfo->_isSystem=_IsSystemDll(imageinfo->_imageName);
	imageinfo->_loadAddress=(ADDRINT)address;//IMG_StartAddress(img);
//	if(addressIAT!=NULL)
	//{
	//	_GetImageFunction((BYTE *)addressIAT,realcount,imageinfo->IATprt);
	//}
	g_ModuleInfo[imageinfo->_imageID] = imageinfo;
	bool Ret=stringCompareIgnoreCase(imageinfo->_imageName.substr(positon+1,imageinfo->_imageName.length()-positon),"NTDLL.dll");
	if(!stringCompareIgnoreCase(imageinfo->_imageName.substr(positon+1,imageinfo->_imageName.length()-positon),"NTDLL.dll"))
	{
		InsertKiUserExceptionDispatcher(img,imageinfo->_imageName);
	}
	if(!stringCompareIgnoreCase(imageinfo->_imageName.substr(positon+1,imageinfo->_imageName.length()-positon),"kernel32.dll"))
	{
		InsertGetProcAddress(img,imageinfo->_imageName);
	}
	return;
}

/* ===================================================================== */

/*======================================================================
*Image_Unload rountine
*=====================================================================*/
VOID _Image_Unload(IMG img,VOID *v)
{
	if(!IMG_Valid(img))
	{
		return;
	}
	UINT32 imgId=IMG_Id(img);
	std::map<int , IMAGEINFO*>::iterator iter = g_ModuleInfo.find(imgId);
	if (iter !=g_ModuleInfo.end())
	{
		//delete g_ModuleInfo[imgId]->IATprt;
		delete g_ModuleInfo[imgId];
		g_ModuleInfo.erase(iter);
	}
	return;
}

void ReportCheckResult(THREADID id,CONTEXT *ctxt,ADDRINT Value,int flag,EXCEPTION_REG *ExceptionReg)
{
	int bytes;
	ADDRINT EspValue,StackValue;
	EspValue=PIN_GetContextReg(ctxt,REG_ESP);
	switch(flag)
	{
	case 0:
			fprintf(flog,"This Document is not safee,We deteached the GetProcAddress's return address is in Stack\n");
			fprintf(flog,"The return value is 0x%08x\n",Value);
			fprintf(flog,"Inorder to prevent the malicious code to be executed,we kill this process\n");

			break;
	case 1:
			fprintf(flog,"This Document is not safee,We deteached the GetProcAddress's return address is in Heap\n");
			fprintf(flog,"The return value is 0x%08x\n",Value);
			fprintf(flog,"Inorder to prevent the malicious code to be executed,we kill this process\n");
			break;
	case 2:
			fprintf(flog,"We deteach at KiUserExceptionDispatcher\n");
			fprintf(flog,"here has deteatch a bufferover flow.the SEH chain has been changed\n");
			fprintf(flog,"the Seh next has been change to:%08X，and the handler has been changed at:%08X\n",ExceptionReg->prev,ExceptionReg->handler);
 			fprintf(flog,"in order to prevent the Malicious code to be executed,we will kill the process\n");
			break;
	default:
			return;
	}
	fprintf(flog,"Stack Value:\n");
	for(int j=0;j<0x30;j++)
	{
		bytes=PIN_SafeCopy(&StackValue,(ADDRINT *)(EspValue+j*4),sizeof(ADDRINT));
		if(j%0x4==0)
		{
			fprintf(flog,"0x%08x:",EspValue+j/0x10);
		}
		if(bytes==0)
		{
			fprintf(flog," %08x",0x0C0C0C0C);
		}
		else
		{
			fprintf(flog," %08x",StackValue);
		}
		if(j%4==3)
		{
			fprintf(flog,"\n");
		}
	}
	fprintf(flog,"The Preverious Call Instruction is:\n");
	int i=queueInst->front;
	while (i != queueInst->rear)  
	{  
		if(strlen(queueInst->base[i].InstStr)<0x10)
		{
			fprintf(flog,"EIP:0x%08x  %s\t\t\t%s+%08x\n",queueInst->base[i].Eip,queueInst->base[i].InstStr,
				queueInst->base[i].ModuleName,queueInst->base[i].InstOffset);
		}
		else if (0x10<strlen(queueInst->base[i].InstStr) && strlen(queueInst->base[i].InstStr)<0x18)
		{
			fprintf(flog,"EIP:0x%08x  %s\t\t%s+%08x\n",queueInst->base[i].Eip,queueInst->base[i].InstStr,
				queueInst->base[i].ModuleName,queueInst->base[i].InstOffset);
		}
		else{
			fprintf(flog,"EIP:0x%08x  %s\t%s+%08x\n",queueInst->base[i].Eip,queueInst->base[i].InstStr,
				queueInst->base[i].ModuleName,queueInst->base[i].InstOffset);
		}
		fprintf(flog,"EAX=0x%08x,EBX=0x%08x,ECX=0x%08x,EDX=0x%08x\n",queueInst->base[i].EAX_V,queueInst->base[i].EBP_V,queueInst->base[i].EBX_V,queueInst->base[i].EDX_V);
		fprintf(flog,"ESI=0x%08x,EDI=0x%08x,EBP=0x%08x,ESP=0x%08x\n\n",queueInst->base[i].EAX_V,queueInst->base[i].EAX_V,queueInst->base[i].EAX_V,queueInst->base[i].EAX_V);
		i = (i+1)%MAX_QSIZE;  
	} 
	if(flog!=NULL)
	{
		fclose(flog);
	}
	PIN_ExitProcess(0);//结束进程
	return;
}


/*===========================================================*/
static UINT32 _GetImageIATcount(BYTE *LoadAddress,BYTE **IATaddress,UINT32 *_ImportIATReal)
{
	UINT32 count=0;
	UINT32 temp=0;
	UINT16 _Dos_Magic;//=*(UINT16 *)LoadAddress;//Get the Dos magicL
	PIN_SafeCopy(&_Dos_Magic,LoadAddress,sizeof(UINT16));
	if(_Dos_Magic!=0x5A4D)
	{
		return 0;
	}
	UINT32 e_lfanew=0;
	PIN_SafeCopy(&e_lfanew,LoadAddress+0x3C,sizeof(UINT32));
	BYTE *_PE_Header=LoadAddress+e_lfanew;
	UINT16 _Pe_Magic;
	PIN_SafeCopy(&_Pe_Magic,_PE_Header,sizeof(UINT16));
	if(_Pe_Magic!=0x4550)
	{
		return 0;
	}
	UINT32 _ImportDesc_offset;
	PIN_SafeCopy(&_ImportDesc_offset,_PE_Header+0xD8,sizeof(UINT32));
	UINT32 _ImportDesc_size;
	PIN_SafeCopy(&_ImportDesc_size,_PE_Header+0xD8+4,sizeof(UINT32));
	BYTE *_ImportDesc=LoadAddress+_ImportDesc_offset;
	*IATaddress=_ImportDesc;
	(*_ImportIATReal)=_ImportDesc_size/4;
	for(UINT32 i=0;i<(_ImportDesc_size)/4;i++)
	{
		PIN_SafeCopy(&temp,_ImportDesc+i*4,sizeof(UINT32));
		if(temp!=0)
		{
			count++;
		}
	}
	return count;
}
/**********************************************************************
*functon:get the address of the IAT
para:addressIAT the address of the IAT type:ADDRINT					IN
	 count The number of function that import,type UINT32			IN
	 Func:the result of the addresss,type UINT32					OUT
return:void
*************************************************************************/
static VOID _GetImageFunction(BYTE *addressIAT,UINT32 count,UINT32 *Func)
{
	if(count<0 || addressIAT==NULL)
	{
		return;
	}
	UINT32 j=0;
	UINT32 temp=0;
	for(UINT32 i=0;i<count;i++)
	{
		PIN_SafeCopy(&temp,addressIAT+i*4,sizeof(UINT32));
		if(temp!=0)
		{
			Func[j]=temp;
			j++;
		}
	}
	return;
}
static BOOL _IsSystemDll(string img_name)
{
	bool ret;
	int postion;
	postion=img_name.rfind('.');
	if(postion==0)
	{
		return false;
	}
	ret=stringCompareIgnoreCase(img_name.substr(postion+1,img_name.length()-postion+1),"exe");//如果后缀为.exe的文件，则直接返回true.
	if(!ret)
	{
		return false;
	}
	postion=img_name.rfind('\\');
	if(postion==0)
	{
		return false;
	}
	int length=img_name.length()-postion+1;
	string tmp=img_name.substr(postion+1,length);
	ret=stringCompareIgnoreCase(img_name.substr(postion+1,length),"MSO.dll")&
		stringCompareIgnoreCase(img_name.substr(postion+1,length),"MSCOMCTL.OCX")&
		stringCompareIgnoreCase(img_name.substr(postion+1,length),"mshtml.dll");
	if(!ret)
	{
		return false;
	}
	ret=stringCompareIgnoreCase(img_name.substr(postion+1,length),"MSVCR100.dll");
	if(!ret)
	{
		return true;
	}
	tmp=img_name.substr(0,postion);
	postion=tmp.rfind('\\');
	if(postion==0)
	{
		return false;
	}
	ret=stringCompareIgnoreCase(tmp.substr(postion+1,tmp.length()-postion),"system32")&
		stringCompareIgnoreCase(tmp.substr(postion+1,tmp.length()-postion),"WinSxS");
	if(!ret)
	{
		return true;
	}
	return false;
}

/*===========================================================
*function:Determine the image is a system dll or not
para:img_name the image's name:type String
*==============================================================*/
static BOOL _IsSystemDll_tm(string img_name)
{
	//首先判断是否是dll文件。
	bool ret;
	int position;
	string img_MainName;
	position=img_name.rfind('.');
	if(position==0)
	{
		return false;//如果没有找到，则认为非系统dll文件。
	}
/*	ret=stringCompareIgnoreCase(img_name.substr(position,img_name.length()-position),ExeExtension.c_str());*/
	if(!ret)
	{
		return false;//如果是.exe文件，则立即返回。
	}//如果扩展名是.dll则继续进行。
	img_MainName=img_name.substr(0,position);
	position=img_MainName.rfind('\\');
	if(position==0)
	{
		return false;//if not found ,then it will not a system dll
	}
	if(!strcmp(img_MainName.c_str()+position+1,"MSCOMCTL"))//这个模块在0158中存在漏洞。
	{
		return false;
	}
	position=img_MainName.find("32");
	if(position==0)//表示没有查找到这个字符串，说明肯定不是system32下面的字符串。
	{
		return false;
	}
	else
	{
		string tmp=img_name.substr(0,position);
		if(!ret)
		{

			return true;//返回时false的话则表示是system32下面的dll.
		}
		else
		{
			position=img_MainName.find("WinSxS");
			if(position==0)
			{
				return false;
			}
			else
			{
				string st1=img_MainName.substr(0,position-1);
				if(!ret)
				{
					return true;
				}
				else
				{
					return false;
				}
			}
		}
	}
}


/*========================================================
*function:compare function
*========================================================*/
int comparefunc(VOID *data,VOID *user_data)
{
	IMAGEINFO *imageinfo=(IMAGEINFO *)data;
	UINT32 imgId=imageinfo->_imageID;
	if(imgId==(*(UINT32 *)user_data))
	{
		return true;
	}
	else
	{
		return false;
	}
}
bool InsertGetProcAddress(IMG img,string imgname)
{
	RTN GetProcAddressRtn=RTN_FindByName(img,GETPROCADDRESS);
	if(RTN_Valid(GetProcAddressRtn))
	{
		RTN_Open(GetProcAddressRtn);
		KiUserExceptionDispatcher_Address=RTN_Address(GetProcAddressRtn);
		RTN_InsertCall(GetProcAddressRtn,
			IPOINT_BEFORE,
			AFUNPTR(CheckSafeRET),
			IARG_THREAD_ID,
			IARG_CONTEXT,
			IARG_END);
		RTN_Close(GetProcAddressRtn);
		return true;
	}
	else
	{
		return false;
	}
}
bool InsertKiUserExceptionDispatcher(IMG img,string modulename)
{
	RTN KiUserExceptionDispatcherRtn=RTN_FindByName(img,KIEXCEPTION);
	if(RTN_Valid(KiUserExceptionDispatcherRtn))
	{
		RTN_Open(KiUserExceptionDispatcherRtn);
		KiUserExceptionDispatcher_Address=RTN_Address(KiUserExceptionDispatcherRtn);
		RTN_InsertCall(
			KiUserExceptionDispatcherRtn,
			IPOINT_BEFORE,
			(AFUNPTR)CheckSafeSEH,
			IARG_THREAD_ID,
			IARG_CONTEXT,
			IARG_END);
		RTN_Close(KiUserExceptionDispatcherRtn);
		return true;
	}
	else
	{
		return false;
	}
}
//这个函数主要通过检测seh链表的完整性来实现缓冲区溢出的检测。
VOID CheckSafeSEH(THREADID id,CONTEXT *ctxt)//对这个函数进行插桩主要是为了计算出是否利用溢出处理的方式来进行缓冲区溢出。
{
	ADDRINT firstExceiptionPointer;
	UINT32 handler;
	//TEB_INFO *tebinfo=new TEB_INFO;
	UINT32 FS_base;
	UINT32 Stack_Top;
	UINT32 Stack_Base;
	ADDRINT EspValue;
	EXCEPTION_REG exception_rg;
	EspValue=PIN_GetContextReg(ctxt,REG_ESP);
	_asm
	{
		PUSH EAX
		MOV EAX,fs:[0x18]
		MOV FS_base,EAX
		POP EAX
	}
	PIN_SafeCopy(&Stack_Base,(ADDRINT *)(FS_base+4),sizeof(ADDRINT));
	PIN_SafeCopy(&Stack_Top,(ADDRINT *)(FS_base+8),sizeof(ADDRINT));
	{
		return;
	}
	if(!PIN_SafeCopy(&firstExceiptionPointer,(ADDRINT *)FS_base,sizeof(ADDRINT)))
	{
		//tebinfo=NULL;
		return;
	}
	if(firstExceiptionPointer<EspValue || firstExceiptionPointer>Stack_Base)
	{
		ReportCheckResult(id,ctxt,EspValue,2,(EXCEPTION_REG *)firstExceiptionPointer);
	}
	if(!PIN_SafeCopy(&exception_rg,(VOID *)firstExceiptionPointer,sizeof(EXCEPTION_REG)))
	{
		return;
	}
	if(exception_rg.prev==0xFFFFFFFF)
	{
		//这个地方还需要检查
		if(Stack_Top<=exception_rg.handler && exception_rg.handler<=Stack_Base)
		{
			ReportCheckResult(id,ctxt,EspValue,2,&exception_rg);
		}
		else if((0x0C0C0C0C-0x7070707)<=exception_rg.handler && exception_rg.handler<=(0x0C0C0C0C+0x500))
		{
			ReportCheckResult(id,ctxt,EspValue,2,&exception_rg);
		}
		else
		{
			return;
		}
	}
	do
	{
		if(exception_rg.prev<EspValue|| exception_rg.prev>Stack_Base)
		{
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		}
		//the end of the record must be on the stack
		if((exception_rg.prev+sizeof(EXCEPTION_REG))>(Stack_Base))
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		//the record must be 4 bytes aligned
		if((exception_rg.prev & 3)!=0)
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		handler=exception_rg.handler;
		//the handler must not be on the stack.
		if(handler>=Stack_Top && handler<=Stack_Base)
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		if(!PIN_SafeCopy(&exception_rg,(VOID *)exception_rg.prev,sizeof(EXCEPTION_REG)))
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		EspValue=exception_rg.prev;
	}while(exception_rg.prev!=0xFFFFFFFF);
	if(exception_rg.prev==0xFFFFFFFF)
	{
		if(Stack_Top<=exception_rg.handler && exception_rg.handler<=Stack_Base)
		{
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		}
		else if((0x0C0C0C0C-0x7070707)<=exception_rg.handler && exception_rg.handler<=(0x0C0C0C0C+0x500))
		{
			ReportCheckResult(id,ctxt,EspValue,3,&exception_rg);
		}
		else
		{
			return;
		}
	}
	return;
}
/**************************************
***************************************/
VOID CheckSafeRET(THREADID id,CONTEXT *ctxt)
{
	ADDRINT EspValue=PIN_GetContextReg(ctxt,REG_ESP);
	ADDRINT ReturnValue;
	ADDRINT Stack_Base,Stack_Top;
	UINT32 FS_base;
	_asm
	{
		PUSH EAX
		MOV EAX,fs:[0x18]
		MOV FS_base,EAX
		POP EAX
	}
	PIN_SafeCopy(&Stack_Base,(ADDRINT *)(FS_base+4),sizeof(ADDRINT));
	PIN_SafeCopy(&Stack_Top,(ADDRINT *)(FS_base+8),sizeof(ADDRINT));
	{
		return;
	}
	if(!PIN_SafeCopy(&ReturnValue,(ADDRINT *)EspValue,sizeof(EspValue)))
	{
		return;
	}
	if(Stack_Top<=ReturnValue && ReturnValue<=Stack_Base)
	{
		ReportCheckResult(id,ctxt,EspValue,0,NULL);
		return;
	}
	if((0x0C0C0C0C-0x500)<=ReturnValue && ReturnValue<=(0x0C0C0C0C+0x500))
	{
		ReportCheckResult(id,ctxt,EspValue,1,NULL);
		return;
	}
	return;
}