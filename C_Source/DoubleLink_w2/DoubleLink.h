/**
* @file			DoubleLink.h  
* @brief		通用双向链表 \n
* 双向链表的动态创建，增删改查，支持多种数据格式，提供冒泡 快排方法。
* @author		Sugarguo
* @email    	sugarguo@live.com
* @date			2016/03/08 20:00
* @version		v2.0.0 
* @copyright	EmbedWay 恒为科技武汉研发中心 By:Sugarguo
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
* @brief CallBackCmpInt \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个数的减法结果，根据等于大小零判断
*/
int CallBackCmpInt(const void *one, const void *two);

/**
* @brief CallBackCmpChar \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个字母比较结果
*/
int CallBackCmpChar(const void *one, const void *two);

/**
* @brief CallBackCmpStr \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个单词比较结果
*/
int CallBackCmpStr(const void *one, const void *two);

/**
* @brief CallBackCmpStr_K \n
* 回调函数，比较内容是否相同
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个单词比较结果
*/
int CallBackCmpStr_K(const void *one, const void *two);

/**
* @brief CallBackShow \n
* 回调函数，显示内容
* @param[in]	*one		需要显示的内容
* @param[in]	flag		提供接口，flag = 0: int显示 1: char字符显示 2: char * 字符串显示
*/
int CallBackShow(void *one, int flag);

/**
* @brief  Partition\n
* 快速排序 
* @param[in]	*List					双向链表默认链表接口
* @param[in]	*one					比较的第一个内容
* @param[in]	*two					比较的第二个内容
* @param[in]	*CallBackCmp			各种类型的回调函数接口
*/
static DLNode *Partion(DLNode * List, DLNode * p_one, DLNode * p_two, int (*CallBackCmp)(const void *, const void *));

/**
* @brief  QuickSort\n
* 快速排序 
* @param[in]	*List					双向链表默认链表接口
* @param[in]	*one					比较的第一个内容
* @param[in]	*two					比较的第二个内容
* @param[in]	*CallBackCmp			各种类型的回调函数接口
*/
static void QuickSort(DLNode * List, DLNode * p_one, DLNode * p_two, int (*CallBackCmp)(const void *, const void *));

/**
* @brief SearchList \n
* 查询双向链表，通过给定的默认双向链表，判断数据以及数据地址是否存在
* @param[in]	*List					双向链表默认链表接口
* @param[in]	*data					需要查询的无类型数据指针
* @param[in]	*CallBackCmp			各种类型的回调函数接口
*/
DLNode *SearchList(DLNode *List, void *data, int (*CallBackCmp)(const void *, const void *));

/**
* @brief SequenceList \n
* 排列双向链表函数通过flag的flag，选择合适的排序方法
* @param[in]	*List			双向链表默认链表接口
* @param[in]	flag			提供接口，让用户定义具体比较函数 flag = 0: 采用冒泡排序 1: 系统快排 2: 自写快排（默认采用）
* @param[in]	*CallBackCmp	各种类型的回调函数接口
*/
DLNode *SequenceList(DLNode *List, int flag, int (*CallBackCmp)(const void *,const void *));

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
* @param[in]	*CallBackCmp		各种类型的回调函数接口
*/
void UpdateList(DLNode *List, void *data_search, void *data_change, int (*CallBackCmp)(const void *, const void *));

/**
* @brief DeleteList \n
* 删除双向链表，查询节点位置，将前后地址相连接，然后free此节点位置
* @param[in]	*List			双向链表默认链表接口
* @param[in]	*data			需要被删除的无类型数据指针
* @param[in]	*CallBackCmp	各种类型的回调函数接口
*/
void DeleteList(DLNode *List, void *data, int (*CallBackCmp)(const void *, const void *));

/**
* @brief ShowList \n
* 遍历双向链表
* @param[in]	*List	双向链表默认链表接口
* @param[in]	flag	提供接口，flag = 0: int显示 1: char字符显示 2: char * 字符串显示
* @param[in]	judge	提供接口，judge = 1: 不显示遍历结果  !=1: 显示遍历结果
* @return		返回值为遍历结果，有多少个
*/
int ShowList(DLNode *List, int flag, int judge);

/**
* @brief DropList \n
* 删除双向链表，全部删除，释放内存空间
* @param[in]	*List	双向链表默认链表接口
*/
void DropList(DLNode *List);

#endif
