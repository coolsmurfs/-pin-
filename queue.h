#ifndef __QUEUE_H__
#define __QUEUE_H__
#include"common.h"
#include<string.h>
#include<stdlib.h>
#include"struct.h"
#define MAX_QSIZE 150

Status InitQueue(SqQueue *Q);
void DestroyQueue(SqQueue *Q);
void ClearQueue(SqQueue *Q);
Status QueueEmpty(SqQueue *Q);
int QueueLength(SqQueue *Q);
Status GetHead(SqQueue *Q, QElemType &e);
Status EnQueue(SqQueue *Q, QElemType e);
Status DeQueue(SqQueue *Q);
void QueueTraverse(SqQueue *Q, void(*vi)(QElemType));
#endif;