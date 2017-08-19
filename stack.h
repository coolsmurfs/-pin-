#ifndef __STACK_H__
#define __STACK_H__
#include<stdio.h>
#include<stdlib.h>
#define STACK_INIT_SIZE 500//栈空间大小定位0x500个元素
#define STACKINCREMENT 10//假定每个元素大小为4
typedef int SElemType;
typedef struct  
{
	SElemType *base;
	SElemType *top;
	int stacksize;
}SqStack;//这个数据结构用来存放栈的相关内容。
int InitStack(SqStack *S);//初始化栈函数
int GetTop(SqStack *S,SElemType &e);//获取栈顶数据
int Push(SqStack *S,SElemType e);//往栈中压入数据
int Pop(SqStack *S,SElemType &e);//从栈中出数据
void ClearStack(SqStack *S);//清除栈数据

#endif