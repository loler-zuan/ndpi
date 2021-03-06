#include <search.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "detection.h"
#include "communicate.h"
#include "worker.h"
#include "parameters.h"
pthread_t deal_request_id;
void terminateDetection();
void sigproc(int sig)
{
  static int called=0;
  if(called) return;
  else called=1;
  int res=fork();
  if(res==0)
  	execlp("iptables","iptables","-t","filter","--flush",NULL);
	res=fork();
	if(res==0)
		execlp("iptables","iptables","-t","mangle","--flush",NULL);
	terminateDetection();
	unlink(conf.sockPath);
  exit(0);
}
void terminateDetection()
{
	int i,j;
	freeDetection();
	freeWorker();
}
void deamon()
{

}
void prepareDetection()
{
	setupDetection();
	init_netlink();
}
void run()
{
	prepareDetection();
	pthread_create(&deal_request_id,NULL,(void *)Worker_ScheduleRun,(void *)conf.sockPath);
	doingDetection();
	pthread_join(deal_request_id,NULL);
  terminateDetection();
}
int main(int argc, const char *argv[])
{
	Para_Init(argc,argv);
	deamon();
	signal(SIGPIPE,SIG_IGN);
	signal(SIGINT,sigproc);
  int res=fork();
  if(res==0)
		execlp("iptables","iptables","-t","mangle","-I","PREROUTING","-j","QUEUE",NULL);
	res=fork();
	if(res==0)
		execlp("iptables","iptables","-I","OUTPUT","-j","QUEUE",NULL);
	run();
  return 0;
}

