//wlp18s0
#include "libipq.h"
#include "linux_compat.h"
#include "ndpi_main.h"
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include "../config.h"
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct ipq_handle *h = NULL;
unsigned char buf[1024];
static struct ndpi_detection_module *ndpi_struct = NULL;
static u_int32_t detection_tick_resolution = 1000;

typedef struct ndpi_id {
  u_int8_t ip[4];
  struct ndpi_id_struct *ndpi_id;
} ndpi_id_t;

typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int16_t packets, bytes;
  // result only, not used for flow identification
  u_int32_t detected_protocol;
  char host_server_name[256];

  void *src_id, *dst_id;
} ndpi_flow_t;

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;
  if(fa->lower_ip < fb->lower_ip) return(-1); else { if(fa->lower_ip > fb->lower_ip) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip < fb->upper_ip) return(-1); else { if(fa->upper_ip > fb->upper_ip) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol < fb->protocol) return(-1); else { if(fa->protocol > fb->protocol) return(1); }

  return(0);
}

static void *malloc_wrapper(unsigned long size)
{
  return malloc(size);
}
static void free_wrapper(void *freeable)
{
  free(freeabla);
}
void setupDetection()
{
  NDPI_PROTOCOL_BITMASK all;
  ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
      malloc_wrapper,free_wrapper,NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct,&all);
//  ndpi_load_protocols_file(ndpi_struct,);
}
void printResults(int i)
{

}
void sigproc(int sig)
{
  static int called=0;
  if(called) return;
  else called=1;
  printResults(0);
  exit(0);
}
//释放资源
static void terminateDetection()
{

}
static struct ndpi_flow *get_ndpi_flow(const struct ndpi_iphdr *iph,
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

  flow.protocol = iph->protocol;
  flow.lower_ip = lower_ip;
  flow.upper_ip = upper_ip;
  flow.lower_port = lower_port;
  flow.upper_port = upper_port;


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

      if(version == 4) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

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

      ndpi_tsearch(newflow, (void*)&ndpi_flows_root[idx], node_cmp); /* Add */

      ndpi_flow_count += 1;

      //printFlow(newflow);

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
static int init_netlink()
{
  h = ipq_create_handle(0, PF_INET);
   if(h == NULL){
     printf("%s\n", ipq_errstr());
     return 0;
   }
   printf("ipq_creat_handle success!\n");
   unsigned char mode = IPQ_COPY_PACKET;
   int range = sizeof(buf);
   int ret = ipq_set_mode(h, mode, range);
   printf("ipq_set_mode: send bytes =%d, range=%d\n", ret,range);
   signal(SIGINT, sigproc);
}
//需要传入时间参数。
static int processing()
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
   while(1)
   {
     status = ipq_read(h, buf, sizeof(buf));
     if(status > sizeof(struct nlmsghdr))
     {
       nlh = (struct nlmsghdr *)buf;//测试是否和ndpi_ethher一致。
       ipq_packet = ipq_get_packet(buf);
       ip_len=ipq_packet->data_len;
       time = ((uint64_t) ipq_packet->timestamp_sec) * detection_tick_resolution +ipq_packet->timestamp_usec / (1000000 / detection_tick_resolution);
       if(lasttime > time) {
        // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", lasttime - time);
        time = lasttime;
       }
       lasttime = time;
       
       iph = (struct ndpi_iphdr *iph)&ipq_packet->payload[0];//需要测试是否和pcap来的一致
       if(iph)
         flow = get_ndpi_flow(iph, ip_len,&src, &dst, &proto);
       if(flow != NULL) 
       {
         ndpi_flow = flow->ndpi_flow;
         flow->packets++, flow->bytes += ip_len;
       } else
         continue;
       if(flow->detection_completed) continue;
       protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_struct, ndpi_flow,iph,ip_len, time, src, dst);flow->detected_protocol = protocol;
       if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
           || ((proto == IPPROTO_UDP) && (flow->packets > 8))
           || ((proto == IPPROTO_TCP) && (flow->packets > 10)))
       {
         flow->detection_completed = 1;
         snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
         free_ndpi_flow(flow);
         char buf1[32], buf2[32];
         if(enable_protocol_guess)
         {
           if(flow->detected_protocol == 0 /* UNKNOWN */)
           {
             protocol = node_guess_undetected_protocol(flow);
           }
         }
//可以设置verbose参数，如果满足，就输出流     printFlow(flow);
       }
     }
   }
}
void test_lib()
{
  init_netlink();
  processing();
  terminateDetection();
  printResults();
}




int main(int argc, const char *argv[])
{
  test_lib();
  return 0;
}
