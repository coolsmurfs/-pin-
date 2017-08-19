/* ===================================================================== */
/* This example demonstrates finding a function by name on Windows.      */
/* ===================================================================== */
#include "image.h"
#include "Thread.h"
namespace WINDOWS
{
	#include<Windows.h>
	#include <DbgHelp.h>
}
#include"common.h"
#include <iostream>
#include <fstream>
//#include "queue.h"
#define MAX_OFFSET 0x500
//global varibles
std::map<int, IMAGEINFO*> g_ModuleInfo;
SqQueue *queueInst=NULL;
REG RegStack;
ADDRINT PEB_BASE;
PIN_LOCK WriteFilelock;
PIN_LOCK QueueLock;
PIN_LOCK Threadlock;
bool IsAdeobeOrIE=false;
bool Peb_Getted=false;
string ExeCuldeMdName;
FILE *flog=NULL;
bool batEntryPoint=false;
bool queueInstIsFull=false;
ADDRINT KiUserExceptionDispatcher_Address=0;
/*=======================================================*
*function declaration
==========================================================*/
VOID Fini(INT32 code, VOID *v);
VOID _Instruction(INS ins,VOID *v);
INSSTATUS _GetInsPara(INS ins);
void ReportBufferOverFlow(CONTEXT *ctxt,THREADID threadid,ADDRINT ip,OverFlowType,REG reg,ADDRINT memaddr,string inststr,int flagt);//Report the Buffer overflow
//VOID _IsOccurBufferOverflow(ADDRINT ip,ADDRINT NextIP,THREADID pid,TINFO *tinfo,ADDRINT esp,OPCODETYPE optype);
/*****************************************
在缓冲区溢出检测中处理call指令
****************************************/
/****************************************
在缓冲区溢出检测中处理ret指令
******************************************/
VOID HandleRetInstruction(THREADID id,CONTEXT *ctxt,ADDRINT ip,string *str);
UINT32 StringToInt(char *p,int length);
VOID Handle_JmpInst(THREADID id,CONTEXT *ctxt,ADDRINT ip,UINT32 JmpFlagReg);
VOID Detach_BufferoverFlow(INS ins);
int ByteToInt(char *p,int length);
bool GetInstInfoByAddress(ADDRINT address,INST_INFORMATION *instinfo);
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "execulde", "specify output file name");
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{

	char *ProgramPath=NULL;
	char *postion=NULL;
	int DirectoryLength;
	int documentNLength;
	char* tlength=0;
	//char *NewArgv[8];
	if(argc<2)
	{
		return 0;
	}
	if(!strcmp(KnobInputModuleName.Value.c_str(),"execulde"))
	{
		ExeCuldeMdName=NULL;
	}
	else
	{
		ExeCuldeMdName=new char[strlen(argv[argc-1])];
		if(ExeCuldeMdName==NULL)
		{
			return 0;
		}
		strcpy(ExeCuldeMdName,argv[argc-1]);
	}
	//ExeCuldeMdName=KnobInputModuleName.Value();
	//ExeCuldeMdName=KnobInputModuleName.Cmd();
	postion=strrchr(argv[argc-1],'\\');
	if(postion==NULL)
	{
		return 0;
	}
	postion++;
	tlength=strrchr(postion,'.');
	if(tlength==NULL)
	{
		documentNLength=strlen(argv[argc-1])-(postion-argv[argc-1]);
	}
	else
	{
		documentNLength=tlength-postion;
	}
	postion[documentNLength]=0;
	DirectoryLength=(strrchr(argv[0],'\\'))-argv[0];
	DirectoryLength=(strrchr(argv[0],'\\'))-argv[0]+documentNLength+strlen(".txt")+strlen("\\Logs\\")+1;
	ProgramPath=new char[DirectoryLength];
	if(ProgramPath==NULL)
	{
		return 0;
	}
	memset(ProgramPath,0,DirectoryLength);
	memcpy(ProgramPath,argv[0],strrchr(argv[0],'\\')-argv[0]);
	strcat(ProgramPath,"\\Logs\\");
	strcat(ProgramPath,postion);
	strcat(ProgramPath,".txt");
	flog=fopen(ProgramPath,"w");
	if(flog==NULL)
	{
		return 0;
	}
	//接下来进行初始化队列操作。
	//初始化队列失败则返回。
	queueInst=new SqQueue;
	if(queueInst==NULL)
	{
		return 0;
	}
	if(InitQueue(queueInst)==FALSE)
	{
		return 0;
	}
	PIN_InitSymbols();
	InitLock(&WriteFilelock);
	InitLock(&Threadlock);
	InitLock(&QueueLock);//这里初始化所有的所链表。
	if( PIN_Init(argc,argv))
	{
		return 0;
	}
	RegStack=PIN_ClaimToolRegister();
	if (!REG_valid(RegStack))//如果注册不成功，则返回。
	{
		return 1;
	}
	ADDRINT value1=4;//this flag is use to determint instruction or deteach bufferoverflow
	// Register Image to be called to instrument functions.
	IMG_AddInstrumentFunction(ImageLoad, 0);
	//register a function that be called when a image unload
	IMG_AddUnloadFunction(_Image_Unload,0);
	//register a function the be called when a thread start
	PIN_AddThreadStartFunction(_ThreadStart,0);
	//register a call-back function that be called when a thread fini
	PIN_AddThreadFiniFunction(_ThreadFini,0);
	//register the instruction routine
	INS_AddInstrumentFunction(_Instruction,&value1);
	//register a function will be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Never returns
	PIN_StartProgram();
	return 0;
}
/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */


/*=============================================================*/
VOID Fini(INT32 code, VOID *v)
{
	g_ModuleInfo.clear();
	delete queueInst;
	queueInst=NULL;
	fprintf(flog,"Don't detech any Vulinunitys in the Document,This document May be is Safe");
	if(flog!=NULL)
	{
		fclose(flog);
	}
	return;
}
UINT32 StringToInt(char *p,int length)
{
	UINT32 returnValue=0;
	for(int i=0;i<length;i++)
	{
		if(0x30<=p[i]&& p[i]<=0x39)
		{
			returnValue=returnValue*16+(p[i]-0x30);
		}
		else
		{
			returnValue=returnValue*16+(p[i]-87);
		}
	}
	return returnValue;
}
/*=================================================================
*function:Instruction routine
*this function will be called when every instuction is executed
para:1 instruction INS 2 .v VOID
/* ===================================================================== */
VOID _Instruction(INS ins,VOID *v)
{

	//COMMAND command=*(COMMAND *)(&v);
	COMMAND command=DETEACH_BUFOVERFLOW;
	switch(command)
	{
	case INST_INSTRUMENT:
		//InstructionInstrument(ins);//指令级别插桩
		break;
	case DETEACH_BUFOVERFLOW:
		Detach_BufferoverFlow(ins);//缓冲区溢出检测
		break;
	default:break;
	}
	return;
}

bool  GetInstInfoByAddress(ADDRINT address,INST_INFORMATION *instinfo)
{
	std::map<int,IMAGEINFO *>::iterator iter;
	for(iter=g_ModuleInfo.begin();iter!=g_ModuleInfo.end();iter++)
	{
		if(iter->second->_loadAddress<=address && address<=(iter->second->_loadAddress+iter->second->_imagemapSize))
		{
			break;
		}
	}
	if(iter!=g_ModuleInfo.end())
	{
		instinfo->ModuleNameByInst=iter->second->_imageName;
		instinfo->offsetByTheInst=address-iter->second->_loadAddress;
		instinfo->BelongSysOrNot=iter->second->_isSystem;
		return true;
	}
	return false;
	
}
void ReportBufferOverFlow(CONTEXT *ctxt,THREADID threadid,ADDRINT ip,OverFlowType flag,REG reg,ADDRINT memaddr,string inststr,int flagt)
{
	INST_INFORMATION instinfo;
	int bytes;
	ADDRINT EspValue;
	ADDRINT MemValue=0;
	ADDRINT StackValue;
	char *type=NULL;
	int i;
	if(flagt==1)
	{
		if(!GetInstInfoByAddress(ip,&instinfo))
		{
			return;
		}
		if(flag==RET_TYPE)
		{
			if(!PIN_SafeCopy(&MemValue,(ADDRINT *)memaddr,sizeof(ADDRINT)))
			{
				MemValue=0x0C0C0C0C;
			}
			fprintf(flog,"EIP=:0x%08x,Module:%s Offset:0x%08X has a buffer over flow\n",
			ip,instinfo.ModuleNameByInst.c_str()+instinfo.ModuleNameByInst.rfind('\\')+1,
			instinfo.offsetByTheInst);
			fprintf(flog,"0x%08x:%s %s=0x%08x\n",ip,inststr.c_str(),hexstr(memaddr).c_str(),MemValue);
		}
		if(flag==CALL_REG)
		{

			fprintf(flog,"EIP=:0x%08x,Module:%s Offset:0x%08X has a buffer over flow\n",
			ip,instinfo.ModuleNameByInst.c_str()+instinfo.ModuleNameByInst.rfind('\\')+1,
			instinfo.offsetByTheInst);
			fprintf(flog,"0x%08x:%s %s=0x%08x\n",ip,inststr.c_str(),REG_StringShort(reg).c_str(),PIN_GetContextReg(ctxt,reg));
		}
		if(flag==CALL_MEM)
		{
			if(PIN_SafeCopy(&MemValue,(ADDRINT *)memaddr,sizeof(ADDRINT)))
			{
				MemValue=0x0C0C0C0C;
			}
			fprintf(flog,"EIP=:0x%08x,Module:%s Offset:0x%08X has a buffer over flow\n",
			ip,instinfo.ModuleNameByInst.c_str()+instinfo.ModuleNameByInst.rfind('\\')+1,
			instinfo.offsetByTheInst);
			fprintf(flog,"0x%08x:%s %s=0x%08x\n",ip,inststr.c_str(),hexstr(memaddr).c_str(),MemValue);
		}
		if(flag==JMP_REG)
		{
			fprintf(flog,"EIP=:0x%08x,Module:%s Offset:0x%08X has a buffer over flow\n",
			ip,instinfo.ModuleNameByInst.c_str()+instinfo.ModuleNameByInst.rfind('\\')+1,
			instinfo.offsetByTheInst);
			fprintf(flog,"0x%08x:%s %s=0x%08x\n",ip,inststr.c_str(),REG_StringShort(reg).c_str(),PIN_GetContextReg(ctxt,reg));
		}
	}
	else
	{
		fprintf(flog,"0x%08x:%s has occur buffer over flow\n",ip,inststr.c_str());
	}
	//这里遍历所有的队列，将队列中的数据写到文件中，只记录500条指令。
	i=queueInst->front;
	EspValue=PIN_GetContextReg(ctxt,REG_ESP);
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
	delete queueInst;
	queueInst=NULL;
	PIN_ExitProcess(0);
	return;
}

void WriteInstInfoToqueue(CONTEXT *ctxt,ADDRINT ip,THREADID id,string *str)
{
	QElemType queuedata;
	int position=0;
	INST_INFORMATION instInfo;
	if(!GetInstInfoByAddress(ip,&instInfo))
	{
		return;
	}
	position=instInfo.ModuleNameByInst.rfind('\\');
	if(position==0)
	{
		return;
	}
	memset(&queuedata,0,sizeof(QElemType));
	memcpy(queuedata.ModuleName,instInfo.ModuleNameByInst.substr(position+1,instInfo.ModuleNameByInst.length()).c_str(),
		instInfo.ModuleNameByInst.substr(position+1,instInfo.ModuleNameByInst.length()).length());
	memcpy(queuedata.InstStr,(*str).c_str(),(*str).length());
	queuedata.Eip=ip;
	queuedata.InstOffset=instInfo.offsetByTheInst;
	queuedata.EAX_V=PIN_GetContextReg(ctxt,REG_EAX);
	queuedata.EBX_V=PIN_GetContextReg(ctxt,REG_EBX);
	queuedata.ECX_V=PIN_GetContextReg(ctxt,REG_ECX);
	queuedata.EDX_V=PIN_GetContextReg(ctxt,REG_EDX);
	queuedata.ESI_V=PIN_GetContextReg(ctxt,REG_ESI);
	queuedata.EDI_V=PIN_GetContextReg(ctxt,REG_EDI);
	queuedata.ESP_V=PIN_GetContextReg(ctxt,REG_ESP);
	queuedata.EBP_V=PIN_GetContextReg(ctxt,REG_EBP);
	GetLock(&WriteFilelock,id+1);
	if(queueInstIsFull)
	{
		DeQueue(queueInst);//先删除一条，然后再记录一条。
		EnQueue(queueInst,queuedata);
	}
	else
	{

		if(EnQueue(queueInst,queuedata)==FAILED)//如果未满则直接记录
		{
			queueInstIsFull=true;
			DeQueue(queueInst);
			EnQueue(queueInst,queuedata);
		}
	}
	ReleaseLock(&WriteFilelock);
	return;
}
/*=================================
function:Get param of an instruction
param:INS the insturciont					IN
instparam	the struct of an inst		OUT
*=================================*/
INSSTATUS _GetInsPara(INS ins)
{
	if(!INS_Valid(ins))
	{
		return INVALID;
	}
	IMAGEINFO *imgInfo=NULL;
	UINT32 positon;
	ADDRINT ptr=INS_Address(ins);
	IMG Imgtemp=IMG_FindByAddress(ptr);//get the image that contain the address;
	UINT32 imgId=IMG_Id(Imgtemp);
	if(!IMG_Valid(Imgtemp))
	{
		return UNKNOWN;
	}
	std::map<int , IMAGEINFO*>::iterator iter = g_ModuleInfo.find(imgId);
	if (iter !=g_ModuleInfo.end())
	{
		positon=g_ModuleInfo[imgId]->_imageName.rfind('\\');
		if(positon==0)
		{
			return UNKNOWN;
		}
		if(!stringCompareIgnoreCase(g_ModuleInfo[imgId]->_imageName.substr(positon+1,g_ModuleInfo[imgId]->_imageName.length()-positon),KnobOutputFile.Value()))
		{
			return CHECKED;
		}
		if(g_ModuleInfo[imgId]->_isSystem)
		{
			
			return ISSYSTEM;
		}
		else
		{
			return NOTSYSY;
		}
	}
	else
	{
		return UNKNOWN;
	}
}

/*************************************************************
VOID HandleCallMemInstruction(THREADID id,CONTEXT *ctxt,ADDRINT ip,UINT32 targetAddress,UINT32 NextIstOffset,UINT32 Flag,
	UINT32 FlagReg,UINT32 SecondReg,ADDRINT taregtaddress_temp,string *tempInst)
{
	TEB_INFO *teb_info=NULL;
	UINT32 TargetAddress;
	ADDRINT tempAddress;
	ADDRINT tempAddress1;
	INST_INFORMATION instinfo;
	int bytes;
	string imgname;
	char Reg1Str[4]={0};
	char Reg2Str[4]={0};
	//ADDRINT instBelongImagBase;
	char instpt[0x20]={0};
	KList *gTailList=NULL;
	ADDRINT nextinstaddress=ip+NextIstOffset;
	//将返回地址压入自定义的硬件堆栈。
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(teb_info==NULL  || teb_info->SHdStack==NULL)
	{
		return;
	}
	if(!GetInstInfoByAddress(ip,&instinfo))
	{
		return;
	}
	const char *p=(instinfo.ModuleNameByInst.c_str());
	switch((Flag &0xF0000000))
	{
	case 0x20000000:
		{
			if((Flag&0xF0F00000)==0x20000000)//表示call寄存器指令
			{
				GetRegVaule(ctxt,FlagReg,&tempAddress);
				GetRegString(FlagReg,Reg1Str);
				sprintf(instpt,"Call [%s]",Reg1Str);
				if(!PIN_SafeCopy(&TargetAddress,(ADDRINT *)tempAddress,sizeof(ADDRINT)))
				{
					PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
					teb_info=NULL;
					return;
				}
			}
			else if((Flag&0xF0F00000)==0x20200000)//表示是call 内存指令
			{
				//GetRegVaule(ctxt,FlagReg,&tempAddress);
				sprintf(instpt,"Call [0x%08x]",targetAddress);
				if(!PIN_SafeCopy(&TargetAddress,(ADDRINT *)targetAddress,sizeof(ADDRINT)))
				{
					PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
					teb_info=NULL;
					return;
				}
			}
			else if((Flag&0xF0F00000)==0x20100000)
			{

				GetRegVaule(ctxt,FlagReg,&tempAddress);
				if((Flag&0xF0F0F000)==0x20101000)
				{
					GetRegString(FlagReg,Reg1Str);
					GetRegString(FlagReg,Reg2Str);
					sprintf(instpt,"Call [%s+%s*0x%02x]",Reg1Str,Reg2Str,targetAddress);
					GetRegVaule(ctxt,SecondReg,&tempAddress1);
					bytes=PIN_SafeCopy(&TargetAddress,(ADDRINT *)(tempAddress+SecondReg*targetAddress),sizeof(ADDRINT));
				}
				else if((Flag&0xF0F0F000)==0x20102000)
				{
					GetRegString(FlagReg,Reg1Str);
					GetRegString(FlagReg,Reg2Str);
					sprintf(instpt,"Call [%s+%s+0x%02x]",Reg1Str,Reg2Str,targetAddress);
					GetRegVaule(ctxt,SecondReg,&tempAddress1);
					bytes=PIN_SafeCopy(&TargetAddress,(ADDRINT *)(tempAddress+SecondReg+targetAddress),sizeof(ADDRINT));
				}
				else if((Flag&0xF0F0F0)==0x20103000)
				{
					GetRegString(FlagReg,Reg1Str);
					sprintf(instpt,"Call %S+0x%04x",Reg1Str,targetAddress);
					bytes=PIN_SafeCopy(&TargetAddress,(ADDRINT *)(tempAddress+targetAddress),sizeof(ADDRINT));
				}
				else
				{
					PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
					teb_info=NULL;
					return;
				}
				if(bytes==0)
				{
					PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
					teb_info=NULL;
					return;
				}
			}	
			else
			{
				PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
				teb_info=NULL;
				return;
			}
			break;
		}	
	default:return;
	}
	if(gloop==0)
	{
		gloop=200;
		memcpy(&Inststruct[200],&Inststruct[0],sizeof(QElemType)*200);
	}
	int positon=instinfo.ModuleNameByInst.rfind('\\')+1;
	memcpy(Inststruct[gloop].ModuleNmae,instinfo.ModuleNameByInst.c_str()+positon,0x30);
	memcpy(Inststruct[gloop].InstStr,instpt,0x20);
	Inststruct[gloop].InstOffset=instinfo.offsetByTheInst;
	Inststruct[gloop].EAX_V=PIN_GetContextReg(ctxt,REG_EAX);
	Inststruct[gloop].EBX_V=PIN_GetContextReg(ctxt,REG_EAX);
	Inststruct[gloop].EBP_V=PIN_GetContextReg(ctxt,REG_EAX);
	Inststruct[gloop].ESP_V=PIN_GetContextReg(ctxt,REG_EAX);
	gloop--;
	if(TargetAddress==0x0c0c0c0c)//表示是缓冲区溢出发生了。
	{
		ReportBufferOverFlow(id,ip,1,TargetAddress);
		return;
	}
	if(TargetAddress==0x7ffa4512)
	{
		ReportBufferOverFlow(id,ip,1,TargetAddress);
		return;
	}
	if(teb_info->stack_top<TargetAddress && TargetAddress<teb_info->stack_base)
	{
		ReportBufferOverFlow(id,ip,1,TargetAddress);
		return;
	}
	call_address_info.CallFlag=0x00;
	call_address_info.EIP=ip;
	call_address_info.TargetAddress=TargetAddress;
	PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));
	teb_info=NULL;
	return;
}
******************************************/
VOID HandleRetInstruction(THREADID id,CONTEXT *ctxt,ADDRINT ip,string *str)
{
	unsigned int getReturnAddress=0;
	unsigned int *pt=NULL;
	INST_INFORMATION instinfo;
	TEB_INFO *teb_info=NULL;
	int bytes;
	//从硬件堆栈中获取返回地址的值。
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(teb_info==NULL)
	{
		return;
	}
	ADDRINT esp=PIN_GetContextReg(ctxt,REG_ESP);
	bytes=PIN_SafeCopy(&getReturnAddress,(ADDRINT *)(esp),sizeof(ADDRINT));//获取返回地址
	if(bytes==0)
	{
		teb_info=NULL;
		return;
	}
	if(getReturnAddress==0x7FFA4512)
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,1);
		return;
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=getReturnAddress && getReturnAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=getReturnAddress && getReturnAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,1);
		return;
	}
	if((teb_info->stack_top<=getReturnAddress) && (getReturnAddress<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,1);
		return;
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=ip && ip<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	if((teb_info->stack_top<=ip) && (ip<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	teb_info=NULL;
	return;
}
VOID HandleCallReg(THREADID id,CONTEXT *ctxt,ADDRINT ip,REG Reg,string *str)
{
	if(!REG_valid(Reg))
	{
		return;//如果REG的值为无效，则应该立即返回
	}
	ADDRINT esp;
	ADDRINT TargetAddress=PIN_GetContextReg(ctxt,Reg);
	TEB_INFO *teb_info=NULL;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(teb_info==NULL)
	{
		return;//如果获取到的堆栈结构体指针为空则应该立即返回。
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=TargetAddress&& TargetAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=TargetAddress && TargetAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);
		return;
	}
	if(TargetAddress==0x7FFA4512)
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);;
	}
	if((teb_info->stack_top<=TargetAddress) && (TargetAddress<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);
	}
	esp=PIN_GetContextReg(ctxt,REG_ESP);
	if((0x0C0C0C0C-MAX_OFFSET)<=ip && ip<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	if((teb_info->stack_top<=ip) && (ip<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	WriteInstInfoToqueue(ctxt,ip,id,str);
	teb_info=NULL;
	return;
}

VOID HandleJmpReg(THREADID id,CONTEXT *ctxt,ADDRINT ip,REG Reg,string *str)
{
	if(!REG_valid(Reg))
	{
		return;//如果REG的值为无效，则应该立即返回
	}
	ADDRINT esp;
	ADDRINT TargetAddress=PIN_GetContextReg(ctxt,Reg);
	TEB_INFO *teb_info=NULL;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(teb_info==NULL)
	{
		return;//如果获取到的堆栈结构体指针为空则应该立即返回。
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=TargetAddress&& TargetAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,JMP_REG,Reg,0,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=TargetAddress && TargetAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,JMP_REG,Reg,0,*str,1);
		return;
	}
	if(TargetAddress==0x7FFA4512)
	{
		ReportBufferOverFlow(ctxt,id,ip,JMP_REG,Reg,0,*str,1);
		return;
	}
	if(teb_info->stack_top<=TargetAddress && TargetAddress<=teb_info->stack_base)
	{
		ReportBufferOverFlow(ctxt,id,ip,JMP_REG,Reg,0,*str,1);
		return;
	}
	esp=PIN_GetContextReg(ctxt,REG_ESP);
	if((0x0C0C0C0C-MAX_OFFSET)<=ip && ip<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	if((teb_info->stack_top<=ip) && (ip<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	teb_info=NULL;
	return;
}

/******************************************
*******************************************/
VOID HandleIndirectCall(THREADID id,CONTEXT *ctxt,ADDRINT ip,ADDRINT MEMaddr,string *str)
{
	ADDRINT TargetAddress=0;
	TEB_INFO *teb_info=NULL;
	ADDRINT esp;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(!PIN_SafeCopy(&TargetAddress,(ADDRINT *)MEMaddr,sizeof(ADDRINT)))
	{
		return;
	}
	if(teb_info==NULL)
	{
		return;//如果获取到的堆栈结构体指针为空则应该立即返回。
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=MEMaddr&& MEMaddr<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=MEMaddr && MEMaddr<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=TargetAddress&& TargetAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=TargetAddress && TargetAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if(TargetAddress==0x7FFA4512)
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
	}
	if(teb_info->stack_top<TargetAddress && TargetAddress<teb_info->stack_base)
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
	}
	esp=PIN_GetContextReg(ctxt,REG_ESP);
	if((0x0C0C0C0C-MAX_OFFSET)<=ip && ip<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	if((teb_info->stack_top<=ip) && (ip<=teb_info->stack_base))
	{
		ReportBufferOverFlow(ctxt,id,ip,RET_TYPE,REG(0),esp,*str,0);
		return;
	}
	WriteInstInfoToqueue(ctxt,ip,id,str);//将指令加入队列中
	teb_info=NULL;
	return;
}
VOID HandleCallRegAdobe(THREADID id,CONTEXT *ctxt,ADDRINT ip,REG Reg,string *str)
{

	if(!REG_valid(Reg))
	{
		return;//如果REG的值为无效，则应该立即返回
	}
	ADDRINT TargetAddress=PIN_GetContextReg(ctxt,Reg);
	TEB_INFO *teb_info=NULL;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(teb_info==NULL)
	{
		return;//如果获取到的堆栈结构体指针为空则应该立即返回。
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=TargetAddress	&& TargetAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=TargetAddress && TargetAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_REG,Reg,0,*str,1);
		return;
	}
	WriteInstInfoToqueue(ctxt,ip,id,str);
	teb_info=NULL;
	return;
}

VOID HandleIndirectCallAdobe(THREADID id,CONTEXT *ctxt,ADDRINT ip,ADDRINT MEMaddr,string *str)
{

	ADDRINT TargetAddress=0;
	TEB_INFO *teb_info=NULL;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(!PIN_SafeCopy(&TargetAddress,(ADDRINT *)MEMaddr,sizeof(ADDRINT)))
	{
		return;
	}
	if(teb_info==NULL)
	{
		return;//如果获取到的堆栈结构体指针为空则应该立即返回。
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=MEMaddr&& MEMaddr<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=MEMaddr && MEMaddr<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0C0C0C0C-MAX_OFFSET)<=TargetAddress&& TargetAddress<=(0x0C0C0C0C+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	if((0x0A0A0A0A-MAX_OFFSET)<=TargetAddress && TargetAddress<=(0x0A0A0A0A+MAX_OFFSET))
	{
		ReportBufferOverFlow(ctxt,id,ip,CALL_MEM,REG(0),MEMaddr,*str,1);
		return;
	}
	WriteInstInfoToqueue(ctxt,ip,id,str);//将指令加入队列中
	teb_info=NULL;
	return;
}

/******************************************
**函数功能：用于缓冲区溢出的检测
**函数参数：INS
**函数返回：无
*****************************************/
VOID Detach_BufferoverFlow(INS ins)
{
	const char *p=NULL;
	char *temp=NULL;
	ADDRINT instaddress=0;
	INSSTATUS statusInfo;
	string InstString;
	REG callreg;
	OPCODE op=INS_Opcode(ins);
	if(!INS_Valid(ins))
	{
		return;
	}
	statusInfo=_GetInsPara(ins);
	if(stringCompareIgnoreCase(KnobOutputFile.Value(),"inscount.out"))
	{
		if(statusInfo!=CHECKED)
		{
			return;
		}
	}
	else
	{
		if(statusInfo==INVALID ||statusInfo==UNKNOWN || statusInfo==ISSYSTEM)
		{
			return;
		}
	}
	InstString=INS_Disassemble(ins);
	if(IsAdeobeOrIE==true)
	{
		unsigned char opcode[10]={0};
		if(INS_IsCall(ins))
		{
			if(INS_OperandIsReg(ins,0))
			{
				callreg=REG(INS_OperandReg(ins,0));
				if(!REG_valid(callreg))
				{
					return;
				}
				INS_InsertCall(ins,IPOINT_BEFORE,
					(AFUNPTR)HandleCallRegAdobe,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_UINT32,callreg,
					IARG_PTR,new string(InstString),
					IARG_END
					);
				return;
			}
			else if(INS_IsDirectCall(ins))
			{
				return;
			}
			else
			{
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)HandleIndirectCallAdobe,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA,0,
					IARG_PTR,new string(InstString),
					IARG_END);
				return;
			}
		}
		return;
	}
	if(INS_IsCall(ins))
	{
		statusInfo=_GetInsPara(ins);
		if(statusInfo==INVALID ||statusInfo==UNKNOWN || statusInfo==ISSYSTEM)
		{
			return;
		}
		unsigned char opcode[10]={0};
		if(INS_IsDirectCall(ins))
		{
			return;
		}
		else if(INS_OperandIsReg(ins,0))
		{
			callreg=REG(INS_OperandReg(ins,0));
			if(!REG_valid(callreg))
			{
				return;
			}
			INS_InsertCall(ins,IPOINT_BEFORE,
				(AFUNPTR)HandleCallReg,
				IARG_THREAD_ID,
				IARG_CONTEXT,
				IARG_INST_PTR,
				IARG_UINT32,callreg,
				IARG_PTR,new string(InstString),
				IARG_END
				);
			return;
		}
		else//直接call内存地址的方式。
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)HandleIndirectCall,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA,0,
					IARG_PTR,new string(InstString),
					IARG_END);
			return;
		}
	}
	else if(INS_IsRet(ins))
	{
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)HandleRetInstruction,
			IARG_THREAD_ID,
			IARG_CONTEXT,
			IARG_INST_PTR,
			IARG_PTR,new string(InstString),
			IARG_END);
		return;
	}
	else if((op== XED_ICLASS_JMP) && INS_OperandIsReg(ins,0))
	{
		callreg=REG(INS_OperandReg(ins,0));
		if(!REG_valid(callreg))
		{
			return;
		}
		INS_InsertCall(ins,IPOINT_BEFORE,
			(AFUNPTR)HandleJmpReg,
			IARG_THREAD_ID,
			IARG_CONTEXT,
			IARG_INST_PTR,
			IARG_UINT32,callreg,
			IARG_PTR,new string(InstString),
			IARG_END
			);
		return;
	}
	else
	{
		return;
	}
}

/************************************
函数说明：call指令对应的分析函数
参数说明：ctxt:线程上下文结构体
ip：EIP指针，Flag，标志，指示是哪类call指令
offset:指令中对应的偏移。
***************************************/
/***********************************************
VOID _InstCall(THREADID id,CONTEXT *ctxt,ADDRINT ip,UINT32 Flag,UINT32 offset,UINT32 targetAddress,UINT32 flagreg)
{
	unsigned int theRetAddress;
	unsigned int getReturnAddress;
	INT32 bytes;
	TEB_INFO *teb_info=NULL;
	UINT32 TargetAddress;
	INST_INFORMATION instinfo;
	string tmp;
	//KList *head=NULL;
	teb_info=reinterpret_cast<TEB_INFO *>(PIN_GetContextReg(ctxt,RegStack));//获取存放的头节点的指针。
	if(((Flag&0xf0)!=0x00) && ((Flag&0xF0)!=0x10))
	{;
	return;
	}
	if((Flag&0xf0)==0x00)//表示是call指令
	{

		if((Flag&0x0f)==0x00)//表示是直接call目标地址的指令。
		{
			TargetAddress=targetAddress;
		}
		if((Flag&0x0f)==0x01)//表示这是call 寄存器类型指令。
		{
			switch(flagreg)
			{
				case 0:TargetAddress=PIN_GetContextReg(ctxt,REG_EAX);break;
				case 1:TargetAddress=PIN_GetContextReg(ctxt,REG_EBX);break;
				case 2:TargetAddress=PIN_GetContextReg(ctxt,REG_ECX);break;
				case 3:TargetAddress=PIN_GetContextReg(ctxt,REG_EDX);break;
				case 4:TargetAddress=PIN_GetContextReg(ctxt,REG_ESI);break;
				case 5:TargetAddress=PIN_GetContextReg(ctxt,REG_EDI);break;
				case 6:TargetAddress=PIN_GetContextReg(ctxt,REG_ESP);break;
				case 7:TargetAddress=PIN_GetContextReg(ctxt,REG_EBP);break;
				default:TargetAddress=0;
			}
		}
		if((Flag&0x0f)==0x02)//表示是对内存的操作。
		{
			if(targetAddress==0)
			{
				return;
			}
		}
		if(teb_info->stack_top<=TargetAddress && TargetAddress<=teb_info->stack_base)
		{
			ReportBufferOverFlow(ctxt,id,ip,1,TargetAddress);
			return;
		}
		if(TargetAddress==0x0c0c0c0c)//表示是缓冲区溢出发生了。
		{
			ReportBufferOverFlow(ctxt,id,ip,1,TargetAddress);
			return;
		}
		ADDRINT nextinstaddress=ip+offset;
		//将返回地址压入自定义的硬件堆栈。
		Push(teb_info->SHdStack,nextinstaddress);
		PIN_SetContextReg(ctxt,RegStack,reinterpret_cast<ADDRINT>(teb_info));

	}
	if((Flag&0xf0)==0x10)//表示是ret指令
	{
		//从硬件堆栈中获取返回地址的值。
		int ret=Pop(teb_info->SHdStack,(unsigned int &)theRetAddress);//获取填入的返回地址。
		if(ret==-1)
		{
			return;
		}
		ADDRINT esp=PIN_GetContextReg(ctxt,REG_ESP);
		bytes=PIN_SafeCopy(&getReturnAddress,(ADDRINT *)(esp),sizeof(ADDRINT));//获取返回地址
		if(bytes==0)
		{
			return;
		}
		if(getReturnAddress==0x7FFA4512)
		{
			//ReportBufferOverFlow(id,ip,0,TargetAddress);
			return;
		}
		//这个地方建立轮训方式是为了保证出现不匹配的情况发生。
		/**********************************************************************
		unsigned int *pt=teb_info->SHdStack->top;
		findflag=false;
		while(pt>=teb_info->SHdStack->base)//这个地方注意，就是堆栈的top在高地址，而堆栈的base在低地址段
		{
		if((*pt)==getReturnAddress)
		{
		findflag=true;
		teb_info->SHdStack->top=pt;
		break;
		}
		else
		{
		pt--;
		}
		}
		pt=NULL;
		if(findflag==false)
		{
		if(!GetInstInfoByAddress(ip,&instinfo))
		{
		//	ReportBufferOverFlow(id,ip,0);
		return;
		}
		else
		{
		tmp=instinfo.ModuleNameByInst.substr(instinfo.ModuleNameByInst.rfind('\\')+1,instinfo.ModuleNameByInst.length());
		string excludedll0="mso.dll";	
		string excludedll1="kernel32.dll";
		string excludedll2="ntdll.dll";
		string excludedll3="kernelbase.dll";
		string excludedll4="SYMINPUT.DLL";
		bool bret=stringCompareIgnoreCase1(tmp.c_str(),excludedll0)&
		stringCompareIgnoreCase1(tmp.c_str(),excludedll1) &
		stringCompareIgnoreCase1(tmp.c_str(),excludedll2) &
		stringCompareIgnoreCase1(tmp.c_str(),excludedll3) &
		stringCompareIgnoreCase1(tmp.c_str(),excludedll4);
		if(bret)
		{
			ReportBufferOverFlow(id,ip,0);
		}

		}
		}
		****************************************************************************/
/**********************************	
}
	teb_info=NULL;
	return;
}
**********************************/



