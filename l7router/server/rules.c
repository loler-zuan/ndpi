#include "rules.h"
int rulesNumber=0;
void praseNic(struct rule *(*prules),char *str)
{
	char *p;
	int flag=0;
	int length=1;
	int count=0;
	for(p=str;*p!='\0';p++)
	{
		if(*p!=',' && flag==0)
		{
			flag=1;
			rulesNumber++;
		}
		else if(*p==','&&flag==1)
		{
			flag=0;
		}
	}
	*prules=(struct rule*)(malloc(sizeof(struct rule)*rulesNumber));
	for(p=str,flag=0;*p!='\0';p++,length++)
	{
		if(*p!=',' && flag==0)
		{
				flag=1;
				length=0;
				count++;
		}
		else if(*p==',' && flag==1)
		{
		  (*prules+count-1)->nic=(char *)malloc(sizeof(char)*(length+1));
			memcpy((*prules+count-1)->nic,p-length,length);
			*((*prules+count-1)->nic+length)='\0';
			flag=0;
		}
	}
	length++;
	p++;
	(*prules+count-1)->nic=(char *)malloc(sizeof(char)*(length+1));
	memcpy((*prules+count-1)->nic,p-length,length);
	*((*prules+count-1)->nic+length)='\0';
	//print(rules);
}

void praseProtocol(struct rule *rule,char *str)
{
	
	char *p;
	int flag=0;
	int length=1;
	int count=0;
	for(p=str;*p!='\0';p++)
	{
		if(*p!=',' && flag==0)
		{
			flag=1;
			rule->number++;
		}
		else if(*p==','&&flag==1)
		{
			flag=0;
		}
	}
	rule->protocols=(char **)(malloc(sizeof(char *)*(rule->number)));
	for(p=str,flag=0;*p!='\0';p++,length++)
	{
		if(*p!=',' && flag==0)
		{
				flag=1;
				length=0;
				count++;
		}
		else if(*p==',' && flag==1)
		{
		  *(rule->protocols+count-1)=(char *)malloc(sizeof(char)*(length+1));
			memcpy(*(rule->protocols+count-1),p-length,length);
			*(*(rule->protocols+count-1)+length)='\0';
			flag=0;
		}
	}
	length++;
	p++;
	*(rule->protocols+count-1)=(char *)malloc(sizeof(char)*(length+1));
	memcpy(*(rule->protocols+count-1),p-length,length);
	*(*(rule->protocols+count-1)+length)='\0';
	//print(rule);
}
/*void print(struct rule *rule)
{
	int i;
	for(i=0;i<rule->number;i++)
	{
		printf("%s\n",*(rule->protocols+i));
	}
}*/
