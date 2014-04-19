#include "detection.h"
#include "parameters.h"
#include "rules.h"

u_int64_t raw_packet_count;
u_int64_t ip_packet_count;
u_int64_t total_bytes;
u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS +NDPI_MAX_NUM_CUSTOM_PROTOCOLS +1];
u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];

struct ndpi_detection_module_struct *ndpi_struct;
u_int32_t ndpi_flow_count;

struct ipq_handle *h=NULL;
static u_int32_t detection_tick_resolution = 1000;
static struct ndpi_flow *ndpi_flows_root[NUM_ROOTS]={NULL};
static u_int32_t size_flow_struct = 0;
static u_int32_t size_id_struct = 0;
static u_int32_t enable_protocol_guess = 1;
unsigned char buf[1024*1024];
void markAndRoute(struct ipq_handle *h,ipq_id_t id,int protocol);


static int node_cmp(const void *a, const void *b)
{
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;
  if(fa->lower_ip < fb->lower_ip) 
		return(-1); 
	else
	{ 
		if(fa->lower_ip > fb->lower_ip) return(1); 
	}
  if(fa->lower_port < fb->lower_port) 
		return(-1); 
	else 
	{ 
		if(fa->lower_port > fb->lower_port) 
			return(1); 
	}
  if(fa->upper_ip < fb->upper_ip) 
		return(-1); 
	else
	{ 
		if(fa->upper_ip > fb->upper_ip) 
			return(1); 
	}
  if(fa->upper_port < fb->upper_port) 
		return(-1); 
	else
	{ 
		if(fa->upper_port > fb->upper_port) return(1); 
	}
  if(fa->protocol < fb->protocol) 
		return(-1);
	else
	{ 
		if(fa->protocol > fb->protocol) return(1); 
	}
  return(0);
}

static void *malloc_wrapper(unsigned long size)
{
  return malloc(size);
}
static void free_wrapper(void *freeable)
{
  free(freeable);
}
void setupDetection()
{
//printf("in setup\n");
  NDPI_PROTOCOL_BITMASK all;
  ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
      malloc_wrapper,free_wrapper,NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct,&all);
//  ndpi_load_protocols_file(ndpi_struct,);
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  raw_packet_count = ip_packet_count = total_bytes = 0;
//printf("out setup\n");
	memset(protocol_counter, 0, sizeof(protocol_counter));
	memset(protocol_counter_bytes, 0, sizeof(protocol_counter_bytes));
	memset(protocol_flows, 0, sizeof(protocol_flows));
}
static void free_ndpi_flow(struct ndpi_flow *flow)
{
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       } 	
}

struct ndpi_flow *get_ndpi_flow(const struct ndpi_iphdr *iph,
				       u_int16_t ipsize,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto)
{
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;
  if(ipsize < 20)
    return NULL;
  if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len) || (iph->frag_off & htons(0x1FFF)) != 0)
    return NULL;
  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4_offset = iph->ihl * 4;
  if(iph->protocol == 6) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
    }
  } else if(iph->protocol == 17) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

	//printf("before access flow\n");
  flow.protocol = iph->protocol;
  flow.lower_ip = lower_ip;
  flow.upper_ip = upper_ip;
  flow.lower_port = lower_port;
  flow.upper_port = upper_port;
	//printf("here can access flow\n");

  if(0)
    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
	ret = ndpi_tfind(&flow, (void*)&ndpi_flows_root[idx], node_cmp);
  if(ret == NULL) {
    if(ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;

	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));

      if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
	printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      //这行有问题
	    ndpi_tsearch(newflow, (void*)&ndpi_flows_root[idx], node_cmp); /* Add */

      ndpi_flow_count += 1;
      *src = newflow->src_id, *dst = newflow->dst_id;
      return(newflow);
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}
int init_netlink()
{
  h = ipq_create_handle(0, PF_INET);
   if(h == NULL){
     printf("%s\n", ipq_errstr());
     return 0;
   }
   unsigned char mode = IPQ_COPY_PACKET;
   int range = sizeof(buf);
   int ret = ipq_set_mode(h, mode, range);
}
int doingDetection()
{
   int status;
   struct nlmsghdr *nlh;
   struct ndpi_ethher *ethernet;
   struct ndpi_iphdr *iph;
   ipq_packet_msg_t *ipq_packet;
   int ip_len;
   struct ndpi_id_struct *src, *dst;
   struct ndpi_flow *flow;
   struct ndpi_flow_struct *ndpi_flow = NULL;
   u_int32_t protocol = 0;
   u_int8_t proto;
   u_int64_t time;
   static u_int64_t lasttime=0;
   unsigned char payload[1024*1024];
	 while(1)
   {
     status = ipq_read(h, buf, sizeof(buf),0);
     if(status==0||status==-1)continue;
     memset(payload, 0x00, sizeof(payload));
     if(status > sizeof(struct nlmsghdr))
     {
       nlh = (struct nlmsghdr *)buf;//测试是否和ndpi_ethher一致。
       ipq_packet = ipq_get_packet(buf);
       ip_len=ipq_packet->data_len;
       time = ((uint64_t) ipq_packet->timestamp_sec) * detection_tick_resolution +ipq_packet->timestamp_usec / (1000000 / detection_tick_resolution);
			 memcpy(payload + ETH_HDRLEN, ipq_packet->payload, ip_len);
// 			printf("2\n");
 			 if(lasttime > time) {
        time = lasttime;
       }
       lasttime = time;
       iph = (struct ndpi_iphdr *)(&(ipq_packet->payload[0]));//需要测试是否和pcap来的一致
       if(iph)
			 {
//				 printf("before get_ndpi_flow\n");
         flow = get_ndpi_flow(iph, ip_len,&src, &dst, &proto);
//				 printf("after get_ndpi_flow\n");
			 }
			 if(flow != NULL) 
       {
         ndpi_flow = flow->ndpi_flow;
         flow->packets++, flow->bytes += ip_len;
       } else
         continue;
//			 printf("3\n");
       ip_packet_count++;
       total_bytes+=ip_len+24;
       if(flow->detection_completed) 
			 {

			//	 ipq_set_mark(h,ipq_packet->packet_id,1);
			   markAndRoute(h,ipq_packet->packet_id,flow->detected_protocol);
				 continue;
			 }
       protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_struct, ndpi_flow,(char *)iph,ip_len, time, src, dst);
//			 printf("4\n");
       if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
           || ((proto == IPPROTO_UDP) && (flow->packets > 8))
           || ((proto == IPPROTO_TCP) && (flow->packets > 10)))
       {
         if(flow->detected_protocol==NDPI_PROTOCOL_UNKNOWN)
				 		flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));
         flow->detection_completed = 1;
				 protocol_counter[flow->detected_protocol]+=flow->packets;
				 protocol_flows[flow->detected_protocol]++;
				 protocol_counter_bytes[flow->detected_protocol]+=flow->bytes;
         snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
       }
			 //ipq_set_mark(h,ipq_packet->packet_id,1);
			 markAndRoute(h,ipq_packet->packet_id,flow->detected_protocol);
       snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
	    }
   }
}

void markAndRoute(struct ipq_handle *h,ipq_id_t id,int protocol)
{
	int i,j;
	for(i=0;i<rulesNumber;i++)
	{
		for(j=0;j<(rules+i)->number;j++)
			if(strcmp(
						ndpi_get_proto_name(ndpi_struct, protocol),
						*((rules+i)->protocols)+j
						)==0)
			{
				printf("%d",i+1);
				ipq_set_mark(h,id,i+1);
				return;
			}
	}
	ipq_set_mark(h,id,0); 
}
