#ifndef _RULE_H
#define _RULE_H
struct rule
{
	int number;
	char *nic;
	char **protocols;
};
extern int rulesNumber;
#endif
