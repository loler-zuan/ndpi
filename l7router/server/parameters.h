#ifndef _PARAMETERS_H
#define _PARAMETERS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
#include <fcntl.h>
#include <getopt.h>
#define  JUMPOVER_CHAR(p,over) for(;*p==over;p++);
#define JUMPTO_CHAR(p,to) for(;*p!=to;p++);
#define OFFSET(x)   offsetof(struct headers, x)



struct conf_options
{
	char sockPath[128];
	char logFile[128];
	char configFile[128];
	int maxClient;
	int initClient;
};
void Para_Init(int,char *[]);
extern struct conf_options conf;
extern struct rule *rules;
#endif
