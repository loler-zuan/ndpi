#include "communicate.h"
/*--if client request the info prepare for it------*/
extern int ncmdlines;
extern char results[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10][256];
extern struct conf_options conf; 
int client_len;
struct sockaddr_un client_un;
int client_sock;
pthread_rwlock_t protectResults=PTHREAD_RWLOCK_INITIALIZER;
void prepareResults()
{
	  u_int32_t i;
		pthread_rwlock_wrlock(&protectResults);
		int row=0;
		memset(results,0,sizeof(results));
		sprintf(results[row++],"\tIP packets:   %-13llu of %llu packets total\n",(long long unsigned int)ip_packet_count,(long long unsigned int)raw_packet_count);
		sprintf(results[row++],"\tIP bytes:     %-13llu (avg pkt size %u bytes)\n",(long long unsigned int)total_bytes,/*raw_packet_count>0?0:(unsigned int)(total_bytes/ip_packet_count)*/0);
		sprintf(results[row++],"\tUnique flows: %-13u\n", ndpi_flow_count);
		sprintf(results[row++],"\n");
	  sprintf(results[row++],"\n");
		sprintf(results[row++],"\tDetected protocols:");
		sprintf(results[row++],"\n");
		sprintf(results[row++],"\n");
		for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_struct); i++,row++) 
		{
			if(protocol_counter[i] > 0) 
			{
					sprintf(results[row],"\t\%-20s packets: %-13llu bytes: %-13llu "
 "flows: %-13u\n",ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],(long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
			}
	}
  ncmdlines = row;
	pthread_rwlock_unlock(&protectResults);
}
int sendResults(int sock)
{
		pthread_rwlock_rdlock(&protectResults);
	  if(send(sock,&ncmdlines,sizeof(ncmdlines),0)<0)
			{
				perror("send ncmdlines error\n");
				return -1;
			}
		if(send(sock,results,sizeof(results),0)<0)
		{
			printf("send results error\n");
			return -1;
		}
		pthread_rwlock_unlock(&protectResults);
		return 0;
}
int dealRequest(int sock)
{
	int flag=0;
	int length=0;
	while(1)
	{
		length=recv(sock,&flag,sizeof(flag),0);
		switch(flag)
		{
			case 1:
				prepareResults();
				sendResults(sock);
				break;
			case 10:
				close(sock);
			default:
				return 0;
		}
	}
}


int do_listen(void *str)
{
	  int size;
		struct sockaddr_un un;
		int sock,clientsock;
		if(str==NULL)
		{
			printf("have not set socket path\n");
			return 0;
		}
		un.sun_family=AF_UNIX;
		strcpy(un.sun_path,(char *)str);
		if((sock=socket(AF_UNIX,SOCK_STREAM,0))<0)
		{
			printf("can't create unix sock\n");
			return 0;
		}
		size=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);
		if(bind(sock,(struct sockaddr*)&un,size)<0)
		{
			perror("error:");
			//printf("error:%d\n",errno);
			printf("unix socket bind error\n    size:%d,un.sun_path:%s\n",size,un.sun_path);
			return 0;
		}
		if(listen(sock,10)<0)
		{
			printf("unix socket listen failed\n");
			return 0;
		}
		return sock;
}
