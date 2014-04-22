#ifndef _RULE_H
#define _RULE_H
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
struct rule
{
	int number;
	char *nic;
	char **protocols;
};
extern int rulesNumber;
#endif
