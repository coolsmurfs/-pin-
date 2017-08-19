#ifndef __STRUCT_H__
#define __STRUCT_H__
#include "pin.H"
#include "klist.h"
#include "stack.h"
namespace WINDOWS
{
#include <windows.h>
}
typedef unsigned char BYTE;
typedef struct ImageInfo
{
	string _imageName;					//Image name
	ADDRINT _loadAddress;				//Image load address
	BOOL _isSystem;						//The image is a system module or not
	BOOL _isExecutable;					//The image is executeable or not
	INT32 _imagemapSize;				//The image mapped size in the memory
	UINT32 _imageID;					//The id of the image that can use identify the image
	//	UINT32 _countDeport;				//The number of deport function
	//UINT32 _countImportIAT;				//The number of the import function that this image has
	//	FUNCTIONINFO _DeportInfo[1];				//
	//UINT32 _ImportInfo[1];				//This array is used to save the IAT
	//unsigned int *IATprt;
}IMAGEINFO;


typedef enum
{
	OPCODE_CALL_REG=0,OPCODE_CALL_MEM=1,OPCODE_RET=2
}OPCODETYPE;


typedef enum
{
	RET_TYPE=0,CALL_REG=1,CALL_MEM=2,JMP_REG=3
}OverFlowType;

typedef enum
{
	INST_INSTRUMENT=0,TRACE_INSTRUMENT=1,FUNC_INSTRUMENT=3,DETEACH_BUFOVERFLOW=4
}COMMAND;


typedef struct 
{
	string ModuleNameByInst;
	UINT32 offsetByTheInst;
	bool BelongSysOrNot;
}INST_INFORMATION;

typedef struct
{
	char InstStr[40];
	ADDRINT InstBelongImgLoadAddress;
	int ImgID;
	bool IsExceclude;//����Ƿ���Ҫ�ų���kernel32��kernelbase������ntdll�����ָ�
}INSTPARM;

typedef struct 
{
	UINT32 stack_top;
	UINT32 stack_base;
	UINT32 thread_id;
	UINT32 fs_imageaddress;
}TEB_INFO;
//Ԥ�⴦����ע��ṹ��
typedef struct 
{
	UINT32 prev;
	UINT32 handler;
}EXCEPTION_REG;



typedef struct  
{
	ADDRINT EIP;
	UINT32 CallFlag;
	ADDRINT TargetAddress;
}CALL_ADDRESS_INFO;


typedef struct  
{
	ADDRINT IP;
	ADDRINT TargetAddress;
}RET_ADDRESS_INFO;

typedef enum
{
	ISSYSTEM=0,NOTSYSY=1,UNKNOWN=3,INVALID=4,CHECKED=5,
}INSSTATUS;


typedef struct 
{
	char ModuleName[0x30];
	char InstStr[0x22];
	ADDRINT Eip;
	int InstOffset;
	int EAX_V;
	int EBX_V;
	int ECX_V;
	int EDX_V;
	int ESI_V;
	int EDI_V;
	int ESP_V;
	int EBP_V;
}QElemType;


struct SqQueue  
{  
	QElemType   *base;      // ��ʼ���Ķ�̬����洢�ռ�  
	int         front;      // ͷָ�룬�����в��գ�ָ�����ͷԪ��  
	int         rear;       // βָ�룬�����в��գ�ָ���βԪ�ص���һ��λ��  
};  
typedef enum
{
	OK=1,FAILED=0,
}Status;

#endif
