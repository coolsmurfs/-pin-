#include"queue.h"
  
Status InitQueue(SqQueue *Q)  
{  
    Q->base = (QElemType*)malloc(sizeof(QElemType) * MAX_QSIZE);  
    if (!Q->base) return FAILED;  
      
    Q->front = Q->rear = 0;  
	return OK;
}  
void DestroyQueue(SqQueue *Q)  
{  
    if (Q->base)  
        free(Q->base);  
    Q->base = NULL;  
    Q->front = Q->rear = 0;  
}  
// 将Q清为空队列  
void ClearQueue(SqQueue *Q)  
{  
    Q->front = Q->rear = 0;  
}  
Status QueueEmpty(SqQueue *Q)  
{  
    if (Q->front == Q->rear)  
        return OK;  
    else  
        return FAILED;  
}  
int QueueLength(SqQueue *Q)  
{  
    return (Q->rear - Q->front + MAX_QSIZE)%MAX_QSIZE;  
}  
Status GetHead(SqQueue *Q, QElemType &e)  
{  
    if (Q->front == Q->rear)  
        return FAILED;  
    memcpy(&e, Q->base + Q->front, sizeof(QElemType));  
    return OK;  
}  
Status EnQueue(SqQueue *Q, QElemType e)  
{  
    if ((Q->rear + 1)%MAX_QSIZE == Q->front)  
        return FAILED;  
	//(Q->base+Q->rear)-
    memcpy(Q->base+Q->rear, &e, sizeof(QElemType));  
    Q->rear = (Q->rear + 1)%MAX_QSIZE;  
      
    return OK;  
}  
Status DeQueue(SqQueue *Q)  
{  
    if (!Q->base || Q->front == Q->rear)  
        return FAILED;  
      
  //  memcpy(&e, Q->base + Q->front, sizeof(QElemType));  
    Q->front = (Q->front + 1)%MAX_QSIZE;  
    return OK;  
}  
void QueueTraverse(SqQueue *Q, void(*vi)(QElemType))  
{  
    int i = Q->front;  
    while (i != Q->rear)  
    {  
        vi(Q->base[i]);  
        i = (i+1)%MAX_QSIZE;  
    }    
}  