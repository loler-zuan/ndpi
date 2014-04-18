#include "ndpi_main.h"
#include <search.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <curses.h>
#include <stddef.h>
#define MAXROW 1000
#define MAXCOL 500
static pthread_t printid;
static int serversock;
static int flag=1;
WINDOW* scrn;
char results[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10][256];
int ncmdlines; // cmdoutlines 的行数
int nwinlines; // xterm 或 equiv. 窗口中 'ps ax' 输出的行数
int winrow; // 屏幕上当前行的位置
int cmdstartrow; // 显示的 cmdoutlines 的第一行的索引
int cmdlastrow; // 显示的 cmdoutlines 的最后一行的索引
// 在 winrow 上用黑体重写
/*void changelight(int before)
{
	if(before!=-1)
		mvaddstr(before,0,results[cmdstartrow+before]);
	int clinenum;
	attron(A_BOLD);
	clinenum = cmdstartrow + selected;
	mvaddstr(selected, 0, results[clinenum]);
	attroff(A_BOLD);
	refresh();
}*/
int reciveResults(int flag)
{
//	int row;
//	printf("flag :%d\n",flag);
	if(send(serversock,&flag,sizeof(flag),0)<0)
	{
		printf("send request error\n");
		return -1;
	}
//	printf("have send\n");
	if(recv(serversock,&ncmdlines,sizeof(ncmdlines),0)<0)
	{
		printf("receive ncmdlines error\n");
		return -1;
	}
	printf("ncmdlines:%d\n",ncmdlines);
	if(recv(serversock,results,sizeof(results),0)<0)
	{
		printf("receive results error\n");
		return -1;
	}
/*
	cmdstartrow=0;
	nwinlines=ncmdlines;
	cmdlastrow=cmdstartrow+nwinlines-1;
	for(row=cmdstartrow,winrow=0;row<=cmdlastrow;row++)
	{
		if(results[row][0]!='\0')
		{   
				printf("%s\n",results[row]);
		}   
 	}
*/
	return 0;
}
int initChannel(char *servername)
{
	int sock,len;
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		printf("can not create socket\n");
		return(-1);
	}  
	struct sockaddr_un un;            
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	sprintf(un.sun_path, "scktmp%05d", getpid());
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	unlink(un.sun_path);
	if (bind(sock, (struct sockaddr *)&un, len) < 0)  
  {
		printf("can not bind\n");
		return -1;   
	}
	else
	{
		memset(&un, 0, sizeof(un));
		un.sun_family = AF_UNIX;   
		strcpy(un.sun_path, servername);   
	  len = offsetof(struct sockaddr_un, sun_path) + strlen(servername);
		if (connect(sock, (struct sockaddr *)&un, len) < 0)
		{
			printf("can not connect\n");
			return -1;
		}
	}
	return sock;
}
static showlastpart()
{
	int row;
	clear();
	cmdstartrow=0;
	nwinlines=ncmdlines;
	cmdlastrow=cmdstartrow+nwinlines-1;
	for(row=cmdstartrow,winrow=0;row<=cmdlastrow;row++)
	{
		if(results[row][0]!='\0')
		{
			mvaddstr(winrow,5,results[row]);
			winrow++;
		}
	}
	refresh();
//	changelight(-1);   因为空行太多，所以略过，那么就不能按照row输出结果，以后再实现。
}
void reprint()
{
	if(reciveResults(flag)<0)
	{
		printf("receive results error\n");
		return;
  }
	reciveResults(flag);
	showlastpart();
//	changelight(-1);
}
void sigint(int sigio)
{
	endwin();
	exit(0);
}
void sigalarm(int sigio)
{
	alarm(1);
	reprint();
}
/*void updown(int inc)
{
	  int tmp = selected + inc;
		if (tmp >= 0 && tmp < LINES)
		{
				selected = tmp;
				changelight(selected-inc);
		}
}*/
void *
printthread(void *arg)
{
	char c;
	scrn=initscr();
	noecho();
	cbreak();
	serversock=initChannel("ndpi.sock");
	reciveResults(flag);
	showlastpart();
	signal(SIGALRM,sigalarm);
	alarm(1);
	while(1)
	{
		sleep(10000000);//一直循环没有编译优化的时候极大占用CPU
	}
	endwin();
}
int verbose=1;
int main(int argc,const char *argv[])
{
	if(verbose==1)
	{
		pthread_create(&printid,NULL,printthread,NULL);
		pthread_join(printid,NULL);
	}
	return 0;
}
