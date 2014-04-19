#ifndef _WORKER_H
#define _WORKER_H
#include "communicate.h"
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
struct worker
{
	pthread_t pid;
	pthread_mutex_t mutex;
	int flags;
	int sock;
};
enum STATUS{ WORKER_INITED, WORKER_RUNNING,WORKER_DETACHING, WORKER_DETACHED,WORKER_IDEL };
extern void Worker_ScheduleRun(void *);
#endif
