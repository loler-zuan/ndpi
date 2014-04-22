#ifndef _DETECTION_H 
#define _DETECTION_H


#include <stdlib.h> 
#include <stdio.h> 
#include <netinet/in.h>
#include "linux_compat.h"
#include "ndpi_main.h"
#include "iptables_patch.h"
#define MAX_NDPI_FLOWS 2000000
#define NUM_ROOTS 512
#define ETH_HDRLEN 14

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
	int flag;//判断是不是guess出来的。
	int mark;
} ndpi_flow_t;


extern u_int64_t total_bytes;
extern u_int64_t raw_packet_count;
extern u_int64_t ip_packet_count;
extern u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS +NDPI_MAX_NUM_CUSTOM_PROTOCOLS +1];
extern u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
extern u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
extern struct ndpi_detection_module_struct *ndpi_struct;
extern u_int32_t ndpi_flow_count;
extern int init_netlink();
extern int doingDetection();
extern void freeDetection();
#endif
