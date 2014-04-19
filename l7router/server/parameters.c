#include "parameters.h"
#include "rules.h"
struct rule *rules;

struct conf_options conf={
	"/var/run/l7router.sock",
	"/var/log/l7router.log",
	"/etc/l7router/service.conf",
	10,
	5
};
static void help(void)
{
	printf("l7-router-server -i number  -m number -g filename -l filename -s filename -h -v\n");
	printf("       --initClient number\n");
	printf("       --maxClient number\n");
	printf("       --configFile filename\n");
	printf("       --logFile filename\n");
	printf("       --sockPath filename\n");
	exit(0);
}

static void display_para()
{
	printf("l7-router-server InitClient: %d\n",conf.initClient);  
	printf("       MaxClient: %d\n", conf.maxClient);
	printf("       ConfigFile:%s\n",conf.configFile);
	printf("       LogFile:%s\n",conf.logFile);
	printf("       SockPath:%s\n",conf.sockPath);
}
void version()
{
	printf("l7-router-server 1.0 by Lingzhi.Li\n");
	exit(0);
}
void Cmd_Analyse(int argc,char *argv[])
{
	char *ops="i:m:g:l:hv";
	int c;
	struct option options[]=
	{
		{"configFile",1,NULL,'g'},
		{"maxClient",1,NULL,'m'},
		{"initClient",1,NULL,'i'},
		{"help",0,NULL,'h'},
		{"version",0,NULL,'v'},
		{"sockPath",1,NULL,'s'},
		{"logFile",1,NULL,'l'},
		{0,0,0,0}
	};
	while((c=getopt_long(argc,argv,ops,options,NULL))!=-1)
	{
		switch(c)
		{
			case 'g':strcpy(conf.configFile,optarg);break;//optarg全是字符串
			case 'm':conf.maxClient=strtol(optarg,NULL,10);break;
			case 'i':conf.initClient=strtol(optarg,NULL,10);break;
			case 'l':strcpy(conf.logFile,optarg);break;
			case 's':strcpy(conf.sockPath,optarg);break;
			case 'h':help();break;
			case 'v':version();break;
			default :help();break;
		}
	};
	return;
}

int readline(int fd,char *buf,int len)
{
	int i;
	int n=-1;
	for(i=0;i<len;i++)
	{
		n=read(fd,buf+i,1);
		if(n==0)
		{
			*(buf+i)='\0';
			break;
		}
		else if(*(buf+i) == '\r' || *(buf+i) == '\n')
		{
			*(buf+i)='\n';
			break;
		}
	}
	return i;
}
void File_Analyse()
{
	char bytes[256];
	char *p=NULL;
	char *name,*value;
	int fd=-1;
	int i;
	fd = open(conf.configFile,O_RDONLY);
	if(fd == -1)
	{
		printf("cant open the configFile\n");
		return;
	}
	memset(bytes,0,sizeof(bytes));
	while(readline(fd,bytes,sizeof(bytes))>0)
	{
		p=bytes;
		JUMPOVER_CHAR(p,32);
		if(*p=='#')
		{
			continue;
		}
		else
		{
			name=p;
			while(*p!='='&& *p!=' ')
			{
				p++;
			}
			*p=0;
			p++;
			JUMPOVER_CHAR(p,32);
			JUMPOVER_CHAR(p,'=');
			JUMPOVER_CHAR(p,32);
			value=p;
			while(*p!=' '&& *p!='\n')
			{
				p++;
			}
			*p=0;
			if(strncmp("logFile",name,8)==0)
				memcpy(conf.logFile,value,strlen(value)+1);
			else if(strncmp("sockPath",name,8)==0)
				memcpy(conf.sockPath,value,strlen(value)+1);
			else if(strncmp("initClient",name,10)==0)
				conf.maxClient=strtol(value,NULL,10);
			else if(strncmp("maxClient",name,9)==0)
				conf.maxClient=strtol(value,NULL,10);
			else if(strncmp("Nic",name,3)==0)
			{
				praseNic(&rules,value);
			}
			for(i=0;i<rulesNumber;i++)
			{
				if(strncmp((rules+i)->nic,name,strlen((rules+i)->nic))==0)
					praseProtocol(rules+i,value);
			}

		}
		memset(bytes,0,sizeof(bytes));
	}
	close(fd);
}

void Para_Init(int argc,char *argv[])
{
	Cmd_Analyse(argc,argv);
	File_Analyse();
}
