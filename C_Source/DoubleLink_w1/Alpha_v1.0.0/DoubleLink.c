/**
* @file			DoubleLink.h  
* @brief		通用双向链表 \n
* 双向链表的动态创建，支持多种数据格式。
* @author		Sugarguo
* @email    	sugarguo@live.com
* @date			2016/03/01 20:00
* @version		v1.0.0 
* @copyright	Sugarguo
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

///@brief 定义双向链表的结构体
typedef struct _DoubleLink
{
	void *data; ///<双向链表中的数据
	struct _DoubleLink *back;  ///<双向链表的前区
	struct _DoubleLink *next;  ///<双向链表的后区
}DLNode;

/**
* CreateList	创建双向链表
* @return		返回值为List 为DLNode的空链表，首尾相连
*/
DLNode *CreateList()
{
	DLNode *List;
	List = (DLNode *)malloc(sizeof(DLNode));
	if( List == NULL)
		printf ("Create MEM ERROR!\n");
	List->back = List;
	List->next = List;
	return List;
}

/**
* @brief CallBackSearch \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @param[in]	judge		提供接口，让用户定义具体比较函数
* @return		返回值为0 为查询到相同数据，若返回为1，则没有查询到数据
*/
int CallBackSearch(void *one, void *two, int judge)
{
	if(judge == 0)
	{
		if(*(int *)one == *(int *)two && one == two )
			return 0;
		else
			return 1;	
	}
	else if(judge == 1)
	{
		if(*(char *)one == *(char *)two )
			return 0;
		else
			return 1;	
	}
	else if(judge == 2)
	{
		if(strcmp((char *)one , (char *)two) == 0 )
			return 0;
		else
			return 1;	
	}
	else
		printf("请使用0:int 1:float 2:char ，目前仅支持这三种！\n");	
}

/**
* @brief CallBackShow \n
* 回调函数，显示内容
* @param[in]	*one	需要显示的内容
* @param[in]	judge		提供接口，让用户定义具体比较函数
*/
int CallBackShow(void *one, int judge)
{
	if(judge == 0)
		printf("%d\n", *(int *)one);
	else if(judge == 1)
		printf("%c\n", *(char *)one);
	else if(judge == 2)
		printf("%s\n", (char *)one);
	else
		printf("请使用0:int 1:float 2:char ，目前仅支持这三种！\n");	
}

/**
* @brief CallBackSequence \n
* 回调函数，对不同类型数据进行排序
* @param[in]	*List	双向链表默认链表接口
* @param[in]	*p_one	比较的第一个数据指针
* @param[in]	*p_two	比较的第二个数据指针
* @param[in]	judge	提供接口，让用户定义具体比较函数
* @return		返回值为0 为正确排序
*/
int CallBackSequence(DLNode *List, DLNode *p_one, DLNode *p_two, int judge)
{
	DLNode *temp=NULL;
	void *temp_data;
	if(judge == 0)
	{
		for(p_one = p_one; p_one->next != List; p_one = p_one->next)
		{
			temp=p_one;
			for(p_two = p_one->next; p_two != List; p_two = p_two->next)
			{
				if(*(int *)p_two->data > *(int *)temp->data )
					temp = p_two;
			}
			if (temp != p_one)
			{
				temp_data=p_one->data;
				p_one->data=temp->data;
				temp->data=temp_data;
			}
		}
		return 0;
	}
	else if(judge == 1)
	{
		for(p_one = p_one; p_one->next != List; p_one = p_one->next)
		{
			temp=p_one;
			for(p_two = p_one->next; p_two != List; p_two = p_two->next)
			{
				if(strcmp((char *)p_two->data , (char *)temp->data) < 0 )
					temp = p_two;
			}
			if (temp != p_one)
			{
				temp_data=p_one->data;
				p_one->data=temp->data;
				temp->data=temp_data;
			}
		}
		return 0;
	}
	else if(judge == 2)
	{
		for(p_one = p_one; p_one->next != List; p_one = p_one->next)
		{
			temp=p_one;
			for(p_two = p_one->next; p_two != List; p_two = p_two->next)
			{
				if(strcmp((char *)p_two->data , (char *)temp->data) > 0 )
					temp = p_two;
			}
			if (temp != p_one)
			{
				temp_data=p_one->data;
				p_one->data=temp->data;
				temp->data=temp_data;
			}
		}
		return 0;
	}
	else
		printf("请使用0:int 1:float 2:char ，目前仅支持这三种！\n");
}

/**
* @brief SearchList \n
* 排列双向链表函数通过judge的flag，选择合适的排序方法
* @param[in]	*List			双向链表默认链表接口
* @param[in]	judge					提供接口，让用户定义具体比较函数
* @param[out]	*CallBackSequence	排序的回调函数接口
*/
DLNode *SequenceList(DLNode *List, int judge, int (*CallBackSequence)(DLNode *,DLNode *, DLNode *, int judge))
{
	DLNode *p_one;
	DLNode *p_two;
	p_one = List->next;
	p_two = List->next;
	CallBackSequence( List, p_one, p_two, judge );
	printf("Done\n");
}

/**
* @brief SearchList \n
* 查询双向链表，通过给定的默认双向链表，判断数据以及数据地址是否存在
* @param[in]	*List					双向链表默认链表接口
* @param[in]	*data					需要查询的无类型数据指针
* @param[in]	judge					提供接口，让用户定义具体比较函数
* @param[out]	*CallBackSearch	查询的回调函数接口
*/
DLNode *SearchList(DLNode *List, void *data, int judge, int (*CallBackSearch)(void *, void *, int judge))
{
	DLNode *p;
	p = List;
	p = p->next;
	while(p != List)
	{
		//CallBackShow(p->data, judge);
		if ( CallBackSearch( p->data, data, judge ) == 0 )
			return p;
		p = p->next;
	}	
}

/**
* @brief InsertList \n
* 插入双向链表，根据双向链表的接口插入数据
* @param[in]	*List		双向链表默认链表接口
* @param[in]	*data		需要插入的无类型数据指针
*/
void InsertList(DLNode *List, void *data)
{
	DLNode *p;
	p = (DLNode *)malloc(sizeof(DLNode));
	if( p == NULL )
		printf ("Create MEM ERROR!\n");
	else
	{
		p->back = List;
		p->next = List->next;
		List->next->back = p;
		List->next = p;
		p->data = data;
	}
}

/**
* @brief UpdateList \n
* 更新双向链表，通过查询原始的节点位置，修改数据
* @param[in]	*List				双向链表默认链表接口
* @param[in]	*data_search		需要被更新的初始无类型数据指针
* @param[in]	*data_change		需要更新的无类型数据指针
* @param[in]	judge				提供接口，让用户定义具体比较函数
*/
void UpdateList(DLNode *List, void *data_search, void *data_change, int judge)
{
	DLNode *p;
	p = (DLNode *)malloc(sizeof(DLNode));
	if( p == NULL )
		printf ("Create MEM ERROR!\n");
	else
	{
		p = SearchList(List, data_search, judge, CallBackSearch);
		p->data = data_change;
		printf("Update OK!\n");
	}
}

/**
* @brief DeleteList \n
* 删除双向链表，查询节点位置，将前后地址相连接，然后free此节点位置
* @param[in]	*List	双向链表默认链表接口
* @param[in]	*data	需要被删除的无类型数据指针
* @param[in]	judge	提供接口，让用户定义具体比较函数
*/
void DeleteList(DLNode *List, void *data, int judge)
{
	DLNode *p;
	p = (DLNode *)malloc(sizeof(DLNode));
	if( p == NULL )
		printf ("Create MEM ERROR!\n");
	else
	{
		p = SearchList(List, data, judge, CallBackSearch);
		p->back->next = p->next;
		p->next->back = p->back;
		free(p);
		if( SearchList(List, data, judge, CallBackSearch) == 0)
			printf("Delete Error!\n");
		else
			printf("Delete OK!\n");	
	}
}

/**
* @brief ShowList \n
* 遍历双向链表
* @param[in]	*List	双向链表默认链表接口
* @param[in]	judge	提供接口，让用户定义具体比较函数
*/
void ShowList(DLNode *List, int judge)
{
	printf("Start Show List!\n");
	DLNode *p;
	p = List->next;
	while(p != List)
	{
		CallBackShow(p->data, judge);
		p = p->next;
	}
}

/**
* @brief DropList \n
* 删除双向链表，全部删除，释放内存空间
* @param[in]	*List	双向链表默认链表接口
*/
void DropList(DLNode *List)
{
	DLNode *p;
	p = (DLNode *)malloc(sizeof(DLNode));
	if( p == NULL )
		printf ("Create MEM ERROR!\n");
	else
	{
		p = List;
		p = p->next;
		while(p != List)
		{
			p->back->next = p->next;
			p->next->back = p->back;
			free(p);
			p = p->next;
		}
	}
}

