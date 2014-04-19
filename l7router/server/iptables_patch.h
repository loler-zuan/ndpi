#ifndef _IPTABLES_H
#define _IPTABLES_H

#include "libipq.h"
#include <search.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
static ssize_t ipq_netlink_sendto(const struct ipq_handle *h,const void *msg, size_t len);
int ipq_set_mark(const struct ipq_handle *h,ipq_id_t id,unsigned long mark_value);

#endif
