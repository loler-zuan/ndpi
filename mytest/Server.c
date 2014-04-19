#include <search.h>
#include <signal.h>
#include "../config.h"
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "detection.h"
#include "communicate.h"
#include "worker.h"
void sigproc(int sig)
{
  static int called=0;
  if(called) return;
  else called=1;
  int res=fork();
  if(res==0)
  	execlp("iptables","iptables","-t","filter","--flush",NULL);
	unlink("ndpi.sock");
  exit(0);
}
void terminateDetection()
{
	sigproc(0);
}
void deamon()
{

}
pthread_t recieve_quest_id;
char *path="ndpi.sock";
void prepareDetection()
{
	setupDetection();
	init_netlink();
}
void run()
{
	prepareDetection();
	pthread_create(&recieve_quest_id,NULL,(void *)Worker_ScheduleRun,(void *)path);
	doingDetection();
	pthread_join(recieve_quest_id,NULL);
  terminateDetection();
}
int main(int argc, const char *argv[])
{
	deamon();
	signal(SIGPIPE,SIG_IGN);
	signal(SIGINT,sigproc);
  int res=fork();
  if(res==0)
		execlp("iptables","iptables","-I","INPUT","-j","QUEUE",NULL);
	if(res==0)
		execlp("iptables","iptables","-I","OUTPUT","-j","QUEUE",NULL);
	run();
  return 0;
}

