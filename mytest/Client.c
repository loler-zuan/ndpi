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
static struct ndpi_flow *ndpi_flows_root[NUM_ROOTS]={NULL};
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
static int mark_err=0;
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
    sprintf(results[row++],"\tIP packets:   %-13llu of %llu packets total\n",
           (long long unsigned int)ip_packet_count,
           (long long unsigned int)raw_packet_count);
    sprintf(results[row++],"\tIP bytes:     %-13llu (avg pkt size %u bytes)\n",
           (long long unsigned int)total_bytes,/*raw_packet_count>0?0:(unsigned int)(total_bytes/ip_packet_count)*/0);
		sprintf(results[row++],"\tUnique flows: %-13u\n", ndpi_flow_count);
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
	sprintf(results[row++],"\n");
	sprintf(results[row++],"\n");
  sprintf(results[row++],"\tDetected protocols:");
	sprintf(results[row++],"\n");
	sprintf(results[row++],"\n");
  for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_struct) /*&& row < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10*/; i++,row++) {
    if(protocol_counter[i] > 0) {
      if (m) {
        sprintf(results[row],"\t\%-20s packets: %-13llu bytes: %-13llu "
               "flows: %-13u\n",
               ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
               (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
      } else {
				printf("%d\n",row);
        sprintf(results[row],"\t%-20s packets: %-13llu bytes: %-13llu "
               "flows: %-13u\n",
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
	cmdstartrow=0;
	nwinlines=ncmdlines;
	cmdlastrow=cmdstartrow+nwinlines-1;
	for(row=cmdstartrow,winrow=0;row<=cmdlastrow;row++)
	{
		if(results[row][0]!='\0')
		{
			mvaddstr(winrow,5,results[row]);
			winrow++;
		}
	}
	refresh();
//	changelight(-1);   因为空行太多，所以略过，那么就不能按照row输出结果，以后再实现。
}
void reprint()
{
	prepareResults();	
	showlastpart();
//	changelight(-1);
}
void sigint(int sigio)
{
	endwin();
	exit(0);
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
	prepareResults();
	showlastpart();
	signal(SIGALRM,sigalarm);
	alarm(1);
	while(1)
	{
		sleep(10000000);//一直循环没有编译优化的时候极大占用CPU
		//memset(results,0,sizeof(results));
	//	c = getch();
	//	if (c == 'u')
	//		updown(-1);
	//	else if (c == 'd')
	//		updown(1);
	//	else if (c == 'r')
	//		reprint();
	}
	endwin();
}

int main()
{
	return 0;
}
