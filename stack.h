#ifndef __STACK_H__
#define __STACK_H__
#include<stdio.h>
#include<stdlib.h>
#define STACK_INIT_SIZE 500//ջ�ռ��С��λ0x500��Ԫ��
#define STACKINCREMENT 10//�ٶ�ÿ��Ԫ�ش�СΪ4
typedef int SElemType;
typedef struct  
{
	SElemType *base;
	SElemType *top;
	int stacksize;
}SqStack;//������ݽṹ�������ջ��������ݡ�
int InitStack(SqStack *S);//��ʼ��ջ����
int GetTop(SqStack *S,SElemType &e);//��ȡջ������
int Push(SqStack *S,SElemType e);//��ջ��ѹ������
int Pop(SqStack *S,SElemType &e);//��ջ�г�����
void ClearStack(SqStack *S);//���ջ����

#endif