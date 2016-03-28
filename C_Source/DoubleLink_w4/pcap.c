/**
* @file			pcap.c  
* @brief		IP分片包重组 \n
* IP分片包的重组操作，可以从网卡以及文件中读入，筛选，重组。
* @author		Sugarguo  & dosxiong
* @email    	sugarguo@live.com
* @date			2016/03/28 20:00
* @version		v1.0.0 
* @copyright	EmbedWay 恒为科技武汉研发中心 By:Sugarguo
*/
#include <stdio.h>  
#include <string.h>
#include <stdlib.h>  
#include <unistd.h>  
#include <pcap/pcap.h>  
#include <arpa/inet.h>
#include "DoubleLink.h"
#include <time.h>
#include <pthread.h>

typedef struct Sniff_ip
{
	u_int   ip_v:4;                 ///<版本
	u_int   ip_hl:4;				///<头部长度
	u_char  ip_tos:8;               ///<协议类型
	u_short ip_len:16;				///<总长度
	u_short ip_id:16;               ///<标示符id
	u_short ip_off:16;				///<标志位加偏移量
	u_char  ip_ttl:8;				///<生存时间
	u_char  ip_p:8;					///<协议
	u_short ip_sum:16;				///<校验和
	struct in_addr ip_src;
	struct in_addr ip_dst;
}sniff_ip;

typedef struct second_link
{
	int id;							///<数据包的id
	int df;							///<数据包的df位
	int mf;							///<数据包的mf位
	int offset;						///<数据包的偏移量
	int len;						///<数据报包的长度
	u_char *packet;					///<数据包的指针
}netpacket;

typedef struct information
{
	time_t start;		    		///<时间标志位
	int tol_len;		    		///<总长度
	int cap_len;		    		///<<已捕获部分的长度
	int id;				    		///<本分支的id
	int first_fregment;	    		///<第一片是否到达
	int last_fregment;	    		///<最后一片是否到达
	DLNode *Two_List;
}Info;


///全局变量
DLNode *head = NULL;
u_char *new_packet = NULL;
static pthread_mutex_t thread_lock;
pthread_t pthread_do;
int cap_count = 0, handle_count = 0;
int insert_count = 0, delete_count = 0;
int thread_flag =1;


///函数声明
void ip_recombination(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int id_compare(const void *a, const void *b);
int offset_compare(const void *a, const void *b);
void deletepacket(DLNode *head);
void *thread_do();


/**
 * @brief main \n
 * 通过getopt，实现程序通过参数进行运行目的
 * @date   2016-03-16
 * @author Sugarguo  & dosxiong
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * argc      | int       |参数个数
 * **argv    | char      |参数保存
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | int       | EXIT_SUCCESS
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
int main(int argc,char *argv[]){  
	char *dev, errbuf[PCAP_ERRBUF_SIZE];  
	int i = 0;
	struct bpf_program filter;
	char filter_app[] = "(ip[6:2] > 0) and (not ip[6] = 64)";
	bpf_u_int32 net;
	pcap_t *handle = NULL;
	pcap_dumper_t *pcap_dumper = NULL;
	DLNode *p = NULL, *p1 = NULL;

	head = CreateList();
	insert_count ++;
	pthread_mutex_init(&thread_lock, NULL);
	pthread_create(&pthread_do, NULL, test, NULL);

	/*dev = pcap_lookupdev(errbuf);  
	  if(dev == NULL)
	  {  
	  fprintf(stderr, "couldn't find default device: %s\n", errbuf);  
	  return(2);  
	  }  

	  printf("Device: %s\n",dev);  
	  pcap_lookupnet(dev, &net, &mask, errbuf);
	  handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);*/
	handle = pcap_open_offline("frag_gn5-10.pcap", errbuf);

	pcap_compile(handle,&filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);

	pcap_dumper = pcap_dump_open(handle, "output.pcap");

	i = pcap_loop(handle, -1, ip_recombination, (u_char *)pcap_dumper);

	pcap_dump_flush(pcap_dumper);
	pcap_dump_close(pcap_dumper);
	thread_flag = 0;
	for(p = head->next; p != head; )
	{
		p1 = p->next;
		delete_count ++;
		pthread_mutex_lock(&thread_lock); 
		DeleteList(p, deletepacket);
		pthread_mutex_unlock(&thread_lock); 

		p = p1;
	}
	delete_count ++;
	pthread_mutex_lock(&thread_lock);
	DropList(head, CallBackDropList);
	pthread_mutex_unlock(&thread_lock); 
	p = NULL;
	p1 = NULL;

	pcap_freecode(&filter);
	pcap_close(handle);
	pthread_join(pthread_do,NULL); 
	pthread_mutex_destroy(&thread_lock); 

	return(0);  
}  


/**
 * @brief ip_recombination \n
 * ip数据报捕获以及分片重组
 * @date   2016-03-28
 * @author Sugarguo  & dosxiong
 * @param  : 参数说明如下表：
 * name      | type                  |description of param 
 * ----------|-----------------------|--------------------
 * arg       | u_char                |null
 * pkthdr    | struct pcap_pkthdr    |pcap文件需要的参数
 * packet    | u_char                |ip数据包
 * @return    返回值说明如下：
 * name      | type                  | description of value
 * ----------|-----------------------|----------------------
 * void      | void                  |null
 * @warning   null
 * @attention null
 * @note      每当捕获一个包后就会插入双向链表，并判断是否所有的分片都到齐，如果到齐则重组分片，写入文件。
 * @todo      null
 */
void ip_recombination(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	sniff_ip *ip_head = NULL, *new_head = NULL;
	netpacket *npacket = NULL, *temp_npacket = NULL;
	DLNode *p = NULL, *drop_p = NULL;
	u_char *temp_uchar = NULL, *new_uchar = NULL;
	int i = 0;
	struct pcap_pkthdr temp_pkthdr;
	int checksum = 0;
	Info *info = NULL;

	cap_count++;
	/*if(cap_count % 1000 == 0)
	  {
	  printf("cap_count:%-10d\n",cap_count);
	  }*/

	npacket = (netpacket *)malloc(sizeof(netpacket));
	ip_head = (sniff_ip *) (packet + 14);
	npacket->id = ntohs(ip_head-> ip_id);
	npacket->df = ((ntohs(ip_head->ip_off) & 0x4000)  >>13);
	npacket->mf = ((ntohs(ip_head->ip_off) & 0x2000) >> 13);
	npacket->offset = (ntohs(ip_head-> ip_off) & 0x01fff)*8;
	npacket->len = (ntohs(ip_head->ip_len));

	new_uchar = (u_char *)malloc((sizeof(u_char)*npacket->len + 14));
	if(new_uchar != NULL)
	{
		memcpy(new_uchar, packet, (npacket->len + 14));
	}
	else
	{
		printf("new_uchar NULL\n");
	}
	npacket->packet = (u_char *)new_uchar;

	p = SearchList(head, (void *)npacket, id_compare);
	drop_p = p;
	if(p == head)
	{
		info = (Info *)malloc(sizeof(Info));
		info->id = npacket->id;
		info->first_fregment = 0;
		info->last_fregment = 0;
		info->tol_len = -1;
		info->cap_len = 0;
		info->Two_List = CreateList();

		pthread_mutex_lock(&thread_lock); 
		insert_count ++;
		InsertList(head, (void *)info);
		pthread_mutex_unlock(&thread_lock); 

		drop_p = drop_p->next;

		pthread_mutex_lock(&thread_lock); 
		InsertList(info->Two_List, (void *)npacket);
		pthread_mutex_unlock(&thread_lock); 
	}
	else
	{
		info = (Info *)(p->data);
		p = SearchList(info->Two_List, (void *)npacket, offset_compare);

		pthread_mutex_lock(&thread_lock); 
		InsertList(p->back, (void *)npacket);
		pthread_mutex_unlock(&thread_lock); 
	}

	info->start = clock();
	if(npacket->mf == 0)
	{
		info->tol_len = npacket->offset + npacket->len - 20;
		info->last_fregment = 1;
	}
	if(npacket->offset == 0)
	{
		info->first_fregment = 1;
	}
	info->cap_len += npacket->len - 20;

	///判断是否所有的分片都到齐
	if((info->tol_len == info->cap_len) && (info->first_fregment == 1) && (info->last_fregment == 1))
	{
		handle_count ++;
		/*if(handle_count % 100 == 0)
		  {
		  printf("handle_count:%-10d\n",handle_count);
		  }*/
		new_packet = (u_char *)malloc(sizeof(u_char)*(info->tol_len + 34));

		for(i = 0;i < 14;i ++)
		{
			new_packet[i] = packet[i];
		}

		new_head = (sniff_ip *)malloc((sizeof(sniff_ip)));
		memcpy(new_head, (packet + 14), 20);
		new_head->ip_len = htons(info->tol_len + 20);
		new_head->ip_off = 0;
		new_head->ip_sum = 0;
		temp_uchar = (u_char *)new_head;

		///检验和计算
		for(i = 0; i < 20; i = i+2)
		{
			checksum += (((temp_uchar[i]) << 8) | temp_uchar[i + 1]);
		}
		checksum = (checksum >> 16) + (checksum & 0xffff);     
		checksum += (checksum >> 16);     
		checksum = 0xffff - checksum; 
		/*checksum = ((checksum >> 16) & 0x00001)+(checksum & 0x0ffff);     
		  checksum=0xffff-checksum;*/   
		new_head->ip_sum = htons(checksum);

		memcpy((new_packet + 14), new_head, 20);
		temp_uchar = new_packet+34;

		for(p = (info->Two_List->next); p != info->Two_List; p = p->next)
		{
			temp_npacket = (netpacket *)(p->data);
			memcpy(temp_uchar, (temp_npacket->packet + 34), (temp_npacket->len - 20));
			temp_uchar = temp_uchar + temp_npacket->len -20;
		}

		temp_pkthdr.ts = pkthdr->ts;
		temp_pkthdr.caplen = info->cap_len;
		temp_pkthdr.len = info->cap_len;

		///将拼接完成的数据报写入pcap文件
		pcap_dump(arg, &temp_pkthdr, new_packet);

		free(new_packet);
		free(new_head);
		pthread_mutex_lock(&thread_lock); 
		delete_count ++;
		DeleteList(drop_p, deletepacket);
		pthread_mutex_unlock(&thread_lock);


	}
	temp_uchar = NULL;
	temp_npacket = NULL;
	ip_head = NULL;

}


/**
 * @brief id_compare \n
 * 按照id进行比较
 * @date   2016-03-28
 * @author Sugarguo  & dosxiong
 * @param  : 参数说明如下表：
 * name      | type                  |description of param 
 * ----------|-----------------------|--------------------
 * a         | void                  |待比较的数据
 * b         | void                  |待比较的数据
 * @return    返回值说明如下：
 * name      | type                  | description of value
 * ----------|-----------------------|----------------------
 * result    | int                   |相同返回0
 * @warning   null
 * @attention null
 * @note      比较两个的id如果相同则返回0
 * @todo      null
 */
int id_compare(const void *a, const void *b)
{
	int result = 0;
	Info *temp_a = NULL;
	netpacket *temp_b = NULL;

	temp_a = (Info *)a;
	temp_b = (netpacket *)b;
	result = (temp_a->id - temp_b->id);
	temp_a = NULL;
	temp_b = NULL;
	return result;
}


/**
 * @brief offset_compare \n
 * 按照offset进行比较
 * @date   2016-03-28
 * @author Sugarguo  & dosxiong
 * @param  : 参数说明如下表：
 * name      | type                  |description of param 
 * ----------|-----------------------|--------------------
 * a         | void                  |待比较的数据
 * b         | void                  |待比较的数据
 * @return    返回值说明如下：
 * name      | type                  | description of value
 * ----------|-----------------------|----------------------
 * result    | int                   |大于返回0
 * @warning   null
 * @attention null
 * @note      比较两个的offset如果a大于b的offset则返回0
 * @todo      null
 */
int offset_compare(const void *a, const void *b)
{
	netpacket *temp_a = NULL, *temp_b = NULL;
	int result = 0;

	temp_a = (netpacket *)a;
	temp_b = (netpacket *)b;
	result = (temp_a->offset - temp_b->offset);
	temp_a = NULL;
	temp_b = NULL;
	if(result > 0)
	{
		return 0;
	}
	return 1;
}


/**
 * @brief deletepacket \n
 * 删除数据包
 * @date   2016-03-28
 * @author Sugarguo  & dosxiong
 * @param  : 参数说明如下表：
 * name      | type                  |description of param 
 * ----------|-----------------------|--------------------
 * head      | DLNode                |二层链表的头
 * @return    void
 * @warning   null
 * @attention null
 * @note       
 * @todo      null
 */
void deletepacket(DLNode *head)
{
	DLNode *p = NULL, *p1 = NULL, *temp_head = NULL;
	netpacket *temp_npacket = NULL;
	Info *temp_info = NULL;

	temp_info = (Info *)(head->data);
	temp_head = temp_info->Two_List;
	for(p = temp_head->next;p != temp_head;)
	{
		temp_npacket = (netpacket *)(p->data);
		free(temp_npacket->packet);
		free(temp_npacket);
		temp_npacket = NULL;
		p1 = p;
		p = p->next;
		free(p1);
	}
	free(temp_info);
	free(temp_head);
}


/**
 * @brief thread_do \n
 * 超时检测线程
 * @date   2016-03-28
 * @author Sugarguo  & dosxiong
 * @param  : void
 * @return    void
 * @warning   null
 * @attention null
 * @note      周期性扫描链表，删除超时的ip包
 * @todo      null
 */
void *thread_do()
{
	DLNode *p = NULL,*p1 = NULL;

	int i = 0;
	while(thread_flag == 1)
	{
		pthread_mutex_lock(&thread_lock);
		p = head->next;
		while(p != head)
		{
			i++;
			if( (float)(clock() - ((Info *)(p->data))->start) / CLOCKS_PER_SEC > 0.001 )
			{
				p1 = p->next;
				DeleteList(p, deletepacket);
				p = p1;
			}
			else
			{
				p = p->next;
				continue;
			}
		}
		i = 0;
		pthread_mutex_unlock(&thread_lock);
		sleep(2);
	}
	pthread_exit(0);
}
