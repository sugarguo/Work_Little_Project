/**
* @file			DoubleLinkTest.c  
* @brief		通用双向链表测试程序 \n
* 使用DoubleLink.h这个sugarguo编写的通用双向链表的头文件接口，进行双向链表的操作测试。
* @author		Sugarguo
* @email    	sugarguo@live.com
* @date			2016/03/01 20:00
* @version		v1.0.0 
* @copyright	Sugarguo
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <windows.h> //win请用这个头文件
#include <unistd.h>
#include "DoubleLink.h"

/**
* @brief main \n
* 测试程序的主函数，进行int以及char的创建、增、删、改、查、排序、清空操作。
* @param[in]	argc		带int参数形式
* @param[in]	*argv[]		带char参数形式
* @return		函数默认返回值
*/
int main( int argc, char *argv[] )
{
	DLNode *List;
	/* 进行int 数组测试 */
	int judge = 0;
	int num[1000],i = 0;
	for(i = 0; i < 1000; i++)
	{
		//srand(time(NULL));
		num[i] = rand();
	}
	List = CreateList();
	if (List == NULL)
		printf("Error!\n");
	else
		printf("OK!Create OK!\n");
	for(i = 0; i < 1000; i++)
		InsertList(List,(void *)&num[i]);//(num + i));
	ShowList(List,judge);
	sleep(1);
	SequenceList(List,judge,CallBackSequence);
	ShowList(List,judge);
	sleep(1);
	SearchList(List,&num[1],judge,CallBackSearch);
	UpdateList(List,&num[1],&num[5],judge);
	ShowList(List,judge);
	sleep(1);
	DeleteList(List,&num[5],judge);
	ShowList(List,judge);
	sleep(1);
	DropList(List);
	ShowList(List,judge);
	sleep(1);
	/* 进行char * 字符串测试 */
	char *test1 = "test1";
	char *test2 = "test2";
	char *test3 = "test3";
	char *test5 = "test5";
	List = CreateList();
	if (List == NULL)
		printf("Error!\n");
	else
		printf("OK!Create OK!\n");
	InsertList(List,test1);
	InsertList(List,test2);
	InsertList(List,test3);
	ShowList(List,2);
	sleep(1);
	SequenceList(List,2,CallBackSequence);
	SearchList(List,test2,2,CallBackSearch);
	UpdateList(List,test1,test5,2);
	ShowList(List,2);
	sleep(1);
	DeleteList(List,test5,2);
	ShowList(List,2);
	sleep(1);
	DropList(List);
	ShowList(List,2);
	sleep(1);
	/* 进行char 字符测试 */
	char ch[1000];
	int chascii;
	for(i = 0; i< 1000; i++)
	{
		//srand(time(NULL));
		chascii = rand()%25; //生成0-25的值
		ch[i] = chascii + 'a';
	}
	for(i = 0; i < 1000; i++)
		InsertList(List,(void *)&ch[i]);//(num + i));
	ShowList(List,1);
	sleep(1);
	SequenceList(List,1,CallBackSequence);
	ShowList(List,1);
	sleep(1);
	SearchList(List,&ch[1],1,CallBackSearch);
	UpdateList(List,&ch[1],&ch[5],1);
	ShowList(List,1);
	sleep(1);
	DeleteList(List,&ch[5],1);
	ShowList(List,1);
	sleep(1);
	DropList(List);
	ShowList(List,1);
	
	return 0;
}
