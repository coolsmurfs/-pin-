#include"stack.h"
int InitStack(SqStack *S)
{
	S->base=(SElemType *)malloc(STACK_INIT_SIZE*sizeof(SElemType));
	if(!S->base)
	{
		return -1;
	}
	S->top=S->base;
	S->stacksize=STACK_INIT_SIZE;
	return 0;
}

int GetTop(SqStack *S,SElemType &e)
{
	if(S->top==S->base)
	{
		return -1;
	}
	e=*(S->top-1);
	return 0;
}
int Push(SqStack *S,SElemType e)
{
	if(S->top-S->base>=S->stacksize)
	{
		S->base=(SElemType *)realloc(S->base,(S->stacksize+STACKINCREMENT)*sizeof(SElemType));//如果空间不够则继续增加空间。
		if(!S->base)
		{
			return -1;
		}
		S->top=S->base+S->stacksize;
		S->stacksize+=STACKINCREMENT;
	}
	*S->top++=e;
	return 0;
}
int Pop(SqStack *S,SElemType &e)
{
	if(S->top==S->base)
	{
		return -1;
	}
	e=*--S->top;
	return 0;
}
void ClearStack(SqStack *S)
{
	if(S->base!=NULL)
	{
		free(S->base);
	}
	return;
}