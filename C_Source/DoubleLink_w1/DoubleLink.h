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

#ifndef __DOUBLELINK_H__
#define __DOUBLELINK_H__

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
DLNode *CreateList();

/**
* @brief CallBackSearch \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @param[in]	judge		提供接口，让用户定义具体比较函数
* @return		返回值为0 为查询到相同数据，若返回为1，则没有查询到数据
*/
int CallBackSearch(void *one, void *two, int judge);

/**
* @brief CallBackShow \n
* 回调函数，显示内容
* @param[in]	*one	需要显示的内容
* @param[in]	judge		提供接口，让用户定义具体比较函数
*/
int CallBackShow(void *one, int judge);

/**
* @brief CallBackSequence \n
* 回调函数，对不同类型数据进行排序
* @param[in]	*List	双向链表默认链表接口
* @param[in]	*p_one	比较的第一个数据指针
* @param[in]	*p_two	比较的第二个数据指针
* @param[in]	judge	提供接口，让用户定义具体比较函数
* @return		返回值为0 为正确排序
*/
int CallBackSequence(DLNode *List, DLNode *p_one, DLNode *p_two, int judge);

/**
* @brief SearchList \n
* 排列双向链表函数通过judge的flag，选择合适的排序方法
* @param[in]	*List			双向链表默认链表接口
* @param[in]	judge					提供接口，让用户定义具体比较函数
* @param[out]	*CallBackSequence	排序的回调函数接口
*/
DLNode *SequenceList(DLNode *List, int judge, int (*CallBackSequence)(DLNode *,DLNode *, DLNode *, int judge));

/**
* @brief SearchList \n
* 查询双向链表，通过给定的默认双向链表，判断数据以及数据地址是否存在
* @param[in]	*List					双向链表默认链表接口
* @param[in]	*data					需要查询的无类型数据指针
* @param[in]	judge					提供接口，让用户定义具体比较函数
* @param[out]	*CallBackSearch	查询的回调函数接口
*/
DLNode *SearchList(DLNode *List, void *data, int judge, int (*CallBackSearch)(void *, void *, int judge));

/**
* @brief InsertList \n
* 插入双向链表，根据双向链表的接口插入数据
* @param[in]	*List		双向链表默认链表接口
* @param[in]	*data		需要插入的无类型数据指针
*/
void InsertList(DLNode *List, void *data);

/**
* @brief UpdateList \n
* 更新双向链表，通过查询原始的节点位置，修改数据
* @param[in]	*List				双向链表默认链表接口
* @param[in]	*data_search		需要被更新的初始无类型数据指针
* @param[in]	*data_change		需要更新的无类型数据指针
* @param[in]	judge				提供接口，让用户定义具体比较函数
*/
void UpdateList(DLNode *List, void *data_search, void *data_change, int judge);

/**
* @brief DeleteList \n
* 删除双向链表，查询节点位置，将前后地址相连接，然后free此节点位置
* @param[in]	*List	双向链表默认链表接口
* @param[in]	*data	需要被删除的无类型数据指针
* @param[in]	judge	提供接口，让用户定义具体比较函数
*/
void DeleteList(DLNode *List, void *data, int judge);

/**
* @brief ShowList \n
* 遍历双向链表
* @param[in]	*List	双向链表默认链表接口
* @param[in]	judge	提供接口，让用户定义具体比较函数
*/
void ShowList(DLNode *List, int judge);

/**
* @brief DropList \n
* 删除双向链表，全部删除，释放内存空间
* @param[in]	*List	双向链表默认链表接口
*/
void DropList(DLNode *List);

#endif
