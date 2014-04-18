#include "iptables_patch.h"
int mark_err;
static ssize_t ipq_netlink_sendto(const struct ipq_handle *h,
		 const void *msg, size_t len)
{
	 int status = sendto(h->fd, msg, len, 0,(struct sockaddr *)&h->peer, sizeof(h->peer));
	  if (status < 0)
			mark_err = 16;
		return status;
}

int ipq_set_mark(const struct ipq_handle *h,ipq_id_t id,unsigned long mark_value)
{
	struct {
		struct nlmsghdr nlh;
		ipq_peer_msg_t pm;
	} req;  
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_type = IPQM_MARK;
	req.nlh.nlmsg_pid = h->local.nl_pid;
	req.pm.msg.mark.id = id;
	req.pm.msg.mark.mark_value = mark_value;
	return ipq_netlink_sendto(h, (void *)&req, req.nlh.nlmsg_len);
}
