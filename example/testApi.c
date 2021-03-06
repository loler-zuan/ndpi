//wlp18s0
#include "libipq.h"
#include "linux_compat.h"
#include "ndpi_main.h"
#include <search.h>
#include <signal.h>
#include <linux/netfilter.h>
#include "../config.h"
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <curses.h>
#define MAX_NDPI_FLOWS 2000000
#define NUM_ROOTS 512
#define ETH_HDRLEN 14

struct ipq_handle *h = NULL;
unsigned char buf[1024*1024];
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u_int32_t detection_tick_resolution = 1000;
//static u_int32_t ndpi_flows_root[NUM_ROOTS]= { NULL };
static unsigned long long ndpi_flows_root[NUM_ROOTS]={NULL};
static u_int32_t ndpi_flow_count= 0 ;

static u_int32_t size_flow_struct = 0;
static u_int32_t size_id_struct = 0;

static u_int32_t enable_protocol_guess = 1;

static u_int64_t raw_packet_count = 0;
static u_int64_t ip_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS +NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static int counta=0;

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
char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}
char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
        snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
        snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}
void sigproc(int sig)
{
  static int called=0;
  if(called) return;
  else called=1;
  int res=fork();
  if(res==0)
  	execlp("iptables","iptables","-t","filter","--flush",NULL);
//printResults(0);
  exit(0);
}
static void free_ndpi_flow(struct ndpi_flow *flow)
{
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       } 	
}
//释放资源
static void terminateDetection()
{

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
  //printf("flow.lower_ip:%d,idx:%d,\n",flow.lower_ip,idx);
	ret = ndpi_tfind(&flow, (void*)&ndpi_flows_root[idx], node_cmp);
	//printf("here after ndpi_tfind\n");
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
//printf("in netlink\n");
  h = ipq_create_handle(0, PF_INET);
   if(h == NULL){
     printf("%s\n", ipq_errstr());
     return 0;
   }
   //printf("ipq_creat_handle success!\n");
   unsigned char mode = IPQ_COPY_PACKET;
   int range = sizeof(buf);
   int ret = ipq_set_mode(h, mode, range);
   //printf("ipq_set_mode: send bytes =%d, range=%d\n", ret,range);
   signal(SIGINT, sigproc);
//printf("out netlink\n");
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
   unsigned char payload[1024*1024];
   //counta<40
	 while(1)
   {
     counta++;
//		 printf("1\n");
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
				 ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,payload + ETH_HDRLEN);
				 continue;
			 }
       protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_struct, ndpi_flow,iph,ip_len, time, src, dst);
//			 printf("4\n");
			 flow->detected_protocol = protocol;
       if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
           || ((proto == IPPROTO_UDP) && (flow->packets > 8))
           || ((proto == IPPROTO_TCP) && (flow->packets > 10)))
       {
         flow->detection_completed = 1;
				 protocol_counter[flow->detected_protocol]+=flow->packets;
				 protocol_flows[flow->detected_protocol]++;
				 protocol_counter_bytes[flow->detected_protocol]+=flow->bytes;
         snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
 /*        free_ndpi_flow(flow);
         char buf1[32], buf2[32];
         if(enable_protocol_guess)
         {
           if(flow->detected_protocol == 0 )
           {
           //  protocol = node_guess_undetected_protocol(flow);
           }
         }
可以设置verbose参数，如果满足，就输出流     printFlow(flow);*/
       }
//			 printf("5");
			 ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,payload + ETH_HDRLEN);
       snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
	    }
   }
}



/*--------------for print------------------------------*/
#define MAXROW 1000
#define MAXCOL 500
static pthread_t printid;
WINDOW* scrn;
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
char results[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10][256];
int ncmdlines; // cmdoutlines 的行数
int nwinlines; // xterm 或 equiv. 窗口中 'ps ax' 输出的行数
int winrow; // 屏幕上当前行的位置
int cmdstartrow; // 显示的 cmdoutlines 的第一行的索引
int cmdlastrow; // 显示的 cmdoutlines 的最后一行的索引
// 在 winrow 上用黑体重写
static void prepareResults(/*u_int64_t tot_usec*/)
{
  u_int32_t i;
	int row=0;
  int m = 0;	/* Default output mode: color (0) */
	memset(results,0,sizeof(results));
  if (m) {
    printf("\n");
  } else {
    printf("\x1b[2K\n");
  }
  if (m) {
    sprintf(results[row++],"\tIP packets:   %-13llu of %llu packets total\n",
           (long long unsigned int)ip_packet_count,
           (long long unsigned int)raw_packet_count);
    if(total_bytes > 0)
      sprintf(results[row++],"\tIP bytes:     %-13llu (avg pkt size %u bytes)\n",
             (long long unsigned int)total_bytes,raw_packet_count>0?0:
             (unsigned int)(total_bytes/raw_packet_count));
    sprintf(results[row++],"\tUnique flows: %-13u\n", ndpi_flow_count);
  } else {
    sprintf(results[row++],"\tIP packets:   \x1b[33m%-13llu\x1b[0m of %llu packets total\n",
           (long long unsigned int)ip_packet_count,
           (long long unsigned int)raw_packet_count);
    sprintf(results[row++],"\tIP bytes:     \x1b[34m%-13llu\x1b[0m (avg pkt size %u bytes)\n",
           (long long unsigned int)total_bytes,/*raw_packet_count>0?0:(unsigned int)(total_bytes/ip_packet_count)*/0);
		sprintf(results[row++],"\tUnique flows: \x1b[36m%-13u\x1b[0m\n", ndpi_flow_count);
	}
/*
  if(tot_usec > 0) {
    char buf[32], buf1[32];
    float t = (float)(ip_packet_count*1000000)/(float)tot_usec;
    float b = (float)(total_bytes * 8 *1000000)/(float)tot_usec;

    if (m) {
      printf("\tnDPI throughout: %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1)); } else {
      //printf("\tGuessed flow protocols: \x1b[35m%-13u\x1b[0m\n", guessed_flow_protocols);
    }
  }
*/
  sprintf(results[row++],"\n\nDetected protocols:\n");
  for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_struct) && row < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10; i++,row++) {
    if(protocol_counter[i] > 0) {
      if (m) {
        sprintf(results[row],"\t\%-20s packets: %-13llu bytes: %-13llu "
               "flows: %-13u\n",
               ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
               (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
      } else {
        sprintf(results[row],"\t\x1b[31m%-20s\x1b[0m packets: \x1b[33m%-13llu\x1b[0m bytes: \x1b[34m%-13llu\x1b[0m "
               "flows: \x1b[36m%-13u\x1b[0m\n",
               ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
               (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
      }
    }
  }
	ncmdlines = row;
/*  if(verbose && (protocol_counter[0] > 0)) {
    printf("\n");

    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_flows_root[i], node_print_known_proto_walker, NULL);

    printf("\n\nUndetected flows:\n");
    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_flows_root[i], node_print_unknown_proto_walker, NULL);
  }*/
}
static int selected=0;

void changelight(int before)
{
	if(before!=-1)
		mvaddstr(before,0,results[cmdstartrow+before]);
	int clinenum;
	attron(A_BOLD);
	clinenum = cmdstartrow + selected;
	mvaddstr(selected, 0, results[clinenum]);
	attroff(A_BOLD);
	refresh();
}

static showlastpart()
{
	int row;
	clear();
	if(ncmdlines<=LINES)
	{
		cmdstartrow=0;
		nwinlines=ncmdlines;
	}
	else
	{
		cmdstartrow=0;
		nwinlines=LINES;
	}
	cmdlastrow=cmdstartrow+nwinlines-1;
	for(row=cmdstartrow,winrow=0;row<=cmdlastrow;row++,winrow++)
	{
		mvaddstr(winrow,5,results[row]);
		//mvaddstr(winrow,5,"fffffffffffffffffff");
	}
	changelight(-1);
}
void reprint()
{
	prepareResults();	
	showlastpart();
	changelight(-1);
}
void sigalarm(int sigio)
{
	reprint();
	alarm(1);
}
void updown(int inc)
{
	  int tmp = selected + inc;
		if (tmp >= 0 && tmp < LINES)
		{
				selected = tmp;
				changelight(selected-inc);
		}
}
void *
printthread(void *arg)
{
	char c;
	scrn=initscr();
	noecho();
	cbreak();
	//mvaddstr(1,0,"hello");
	prepareResults();
	showlastpart();
	signal(SIGALRM,sigalarm);
	while(1)
	{
		//memset(results,0,sizeof(results));
		c = getch();
		if (c == 'u')
			updown(-1);
		else if (c == 'd')
			updown(1);
		else if (c == 'r')
			reprint();
	}
	endwin();
}
/*--------------will move to client--------------------*/
void test_lib()
{
  setupDetection();
  init_netlink();
	pthread_create(&printid,NULL,printthread,NULL);
  processing();
	pthread_join(printid,NULL);
  terminateDetection();
  //printResults(0);
}






int main(int argc, const char *argv[])
{
  int res=fork();
  if(res==0)
	execlp("iptables","iptables","-I","INPUT","-p","tcp","--sport","80","-j","QUEUE",NULL);
//	execlp("iptables","iptables","-I","INPUT","-j","QUEUE",NULL);
  test_lib();
  return 0;
}
