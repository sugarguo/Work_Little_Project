/**
* @file			DoubleLinkTest.c  
* @brief		通用双向链表测试程序 \n
* 使用DoubleLink.h这个sugarguo编写的通用双向链表的头文件接口，进行双向链表的操作测试。
* @author		Sugarguo
* @email    	sugarguo@live.com
* @date			2016/03/01 20:00
* @version		v1.0.0 
* @copyright	EmbedWay 恒为科技武汉研发中心 By:Sugarguo
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <windows.h> //win请用这个头文件
#include <unistd.h>
#include <time.h>
#include "DoubleLink.h"

///@brief 定义默认信息的结构体
struct globalArgs_t{
	char *filename;			///<默认数据的文件名
	char *outfilename;		///<默认输出的文件名
	int hflag;				///<是否快速排序的flag
	int sflag;				///<是否显示排序结果的flag
	int pflag;				///<是否显示最终结果的flag
	int lflag;				///<是否显示行号的flag
	int oflag;				///<是否采用默认文件的flag
	int fflag;				///<是否采用默认文件的flag
	int lines;				///<数据文件的行数
	int words;				///<数据文件中拥有词数
	int allwords;			///<数据文件中总词数
	int bytes;				///<数据文件中字节数
}globalArgs;

static const char *optString = "hplso:v?";

/**
 * @brief ShowLine \n
 * 显示文件或者返回行数
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *filename | char      |输入的文件名
 * @return    返回值说明如下：
 * name      | type     | description of value
 * ----------|----------|----------------------
 * null      | int      | 0
 * @warning   该接口单独遍历文件，耗费系统资源
 * @attention 该接口单独遍历文件，耗费系统资源
 * @note      文件遍历读取行号，可修改为显示文件内容
 * @todo      未整合到主程序，耗费系统资源
 */
int ShowLine(char *filename)
{
	FILE *fp;
	int ch;  

	if((fp = fopen(filename ,"r")) == NULL)
		printf("ERROR! File can't be Opened!\n");

	while((ch = fgetc(fp)) != EOF) 
	{  
		if(ch == '\n')
			globalArgs.lines++;
	}  

	fclose(fp); 
	return 0; 
}

/**
 * @brief VS_StrRTrim \n
 * 去除字符串右边空格
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *pStr     | char      |输入的字符串
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention 该接口需要传入字符串指针
 * @note      传入字符串指针，去除字符串右边空格
 * @todo      null
 */
void VS_StrRTrim(char *pStr)  
{  
    char *pTmp = pStr+strlen(pStr)-1;  
      
    while (*pTmp == ' ')   
    {  
        *pTmp = '\0';  
        pTmp--;  
    }  
}  

/**
 * @brief VS_StrLTrim \n
 * 去除字符串左边空格
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *pStr     | char      |输入的字符串
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention 该接口需要传入字符串指针
 * @note      传入字符串指针，去除字符串左边空格
 * @todo      null
 */
void VS_StrLTrim(char *pStr)  
{  
    char *pTmp = pStr;  
      
    while (*pTmp == ' ')   
    {  
        pTmp++;  
    }  
    while(*pTmp != '\0')  
    {  
        *pStr = *pTmp;  
        pStr++;  
        pTmp++;  
    }
    *pStr = '\0';
    *pStr = '\0';  
}

/**
 * @brief StatisticsShow \n
 * 统计词频，仅显示获取词频结果，不写入文件
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *List     | DLNode    |输入的双向链表指针
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention 该接口需要传入双向链表指针
 * @note      传入双向链表指针，仅显示获取词频结果，不写入文件
 * @todo      有显示和写文件俩个函数，待整合
 */
DLNode *StatisticsShow(DLNode *List)
{
	DLNode *p = NULL;
	int i = 1;

	p = List->next;
	while(p->next != List)
	{
		if( strcasecmp((char *)p->data , (char *)p->next->data) == 0)
			i++;
		else
		{
			printf("Word : %s\t\t\t\t  Show : %d \n",(char *)p->data,i);
			globalArgs.words++;
	
			i = 1;
		}
		globalArgs.allwords++;
		p = p->next;
	}
}

/**
 * @brief StatisticsContent \n
 * 统计词频，不显示获取词频结果，写入文件
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *List     | DLNode    |输入的双向链表指针
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention 该接口需要传入双向链表指针
 * @note      传入双向链表指针，不显示获取词频结果，写入文件
 * @todo      有显示和写文件俩个函数，待整合
 */
DLNode *StatisticsContent(DLNode *List)
{
	FILE *fp = NULL;
	DLNode *p = NULL;
	int i = 1;

	if(((fp = fopen(globalArgs.outfilename,"w")) == NULL))
	{
		printf("ERROR! OutFile can't be Opened!\n");
		exit(1);
	}
	p = List->next;
	while(p->next != List)
	{
		if( strcasecmp((char *)p->data , (char *)p->next->data) == 0)
			i++;
		else
		{
			if(globalArgs.pflag == 0)
				printf("Word : %s\t\t\t\t  Show : %d \n",(char *)p->data,i);
			fprintf(fp,"Word :\t%-20s\t|\tShow :\t%-20d \n",(char *)p->data,i);
			globalArgs.words++;
	
			i = 1;
		}
		globalArgs.allwords++;
		p = p->next;
	}
	//free(p);
	printf("\n%s Write OK!Please See it!\n\n", globalArgs.outfilename);
	fclose(fp);
}

/**
 * @brief GetFileContent \n
 * 获取文件内容，按字符读入，以a-z&&A-Z为判断条件选取单词
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *List     | DLNode    |输入的双向链表指针
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   按字节读入，准确率MAX，效率LOW
 * @attention 该接口需要传入双向链表指针
 * @note      传入双向链表指针，读取文件并写到双向链表中
 * @todo      按字节读入，准确率MAX，效率LOW
 */
DLNode *GetFileContent(DLNode *List)
{
	FILE *novelfile;
	int i = 0, word = 0;
	char str[100];

	if((novelfile = fopen(globalArgs.filename ,"r")) == NULL)
	{
		printf("ERROR! File can't be Opened!\n");
		exit(1);
	}
	while(( word = fgetc(novelfile)) != EOF)	//判断文件是否结束
	{
		globalArgs.bytes++;
		if((word >= 'A' && word <= 'Z') || (word >= 'a' && word <= 'z'))
		{
			str[i] = (char)tolower(word);
			i++;
		}
		else
		{
			if(strlen(str) == 0 )
				continue;
			str[i] = '\0';
			char *wordstr = NULL;
			wordstr = (char *)malloc((strlen(str) + 1) * sizeof(char));
			if( wordstr == NULL )
				printf ("Create MEM ERROR!\n");
			else
			{
				VS_StrLTrim(str);
				VS_StrRTrim(str);
				strcpy(wordstr,str);
				InsertList(List,(void *)wordstr);
				i = 0;
				memset(str,'\0',sizeof(str));
			}
		}
	}
	fclose(novelfile);
	return List;
}

/**
 * @brief GetStatistics \n
 * 词频统计测试文件主要运行函数，通过flag判断是否需要显示运行结果
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * hflag     | int       |是否采用高速快速排序方法
 * sflag     | int       |是否显示排序结果
 * oflag     | int       |屏幕显示词频结果或输入文件
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | int       | 0
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
int GetStatistics( int hflag, int sflag, int oflag)
{
	DLNode *List = NULL;

	List = CreateList();

	if (List == NULL)
	{
		printf("Error!\n");
		exit(1);
	}
	else
		printf("OK!Create OK!\n");

	int start_time = 0, end_time = 0;

	start_time = clock();
	List = GetFileContent(List);
	end_time = clock();
	printf("Read time :  %f \n", (float)(end_time - start_time) / CLOCKS_PER_SEC  );

	start_time = clock();
	if(hflag == 0)
		SequenceList(List, 1, CallBackCmpStr_K);
	else
		SequenceList(List, 2, CallBackCmpStr);
	end_time = clock();
	printf("Sequence time :  %f \n", (float)(end_time - start_time) / CLOCKS_PER_SEC  );

	if(sflag == 0)
		ShowList(List, 2, 0);
	start_time = clock();
	if(oflag == 0)
		StatisticsShow(List);
	else
		StatisticsContent(List );
	end_time = clock();
	printf("Statistics time : %f \n\n", (float)(end_time - start_time) / CLOCKS_PER_SEC  );

	DropList(List);
	free(List);
	
	return 0;

}

/**
 * @brief display_usage \n
 * 词频统计测试文件通过getopt函数的错误回显
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * null      | null      |null
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void display_usage( void )
{
	puts("Such as -f \"filename\" -o \"outfilename\" -h (high Sequence) -l (Show Line) -s (Shwo SequenceList) -p (Show EndContent)\n\n");
	exit(EXIT_FAILURE);
}

/**
 * @brief convert_document \n
 * 词频统计测试文件通过getopt函数的配置函数
 * @date   2016-03-11
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * null      | null      |null
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void convert_document( void )
{
	int choose = 0;
	char getfilename[100] = "outFile.txt";
	if(globalArgs.filename == NULL)
	{
		printf("Don't have filename!\nPlease use -f \"filename\"\n ");
		exit(1);
	}
	if( globalArgs.outfilename == NULL)
	{
		printf("\nDo you want create outfile:\n0: Create Default file.\n1: Only Show!\n2: File name\n3: Exit!\nYou choose:");
		scanf("%d",&choose);
		if(choose == 0)
		{
			printf("Don't have outfilename!\nUse default name --> outFile.dat\n");
			globalArgs.outfilename = "outFile.dat";
		}
		else if(choose == 1)
		{
			globalArgs.oflag = 0;
		}
		else if(choose == 2)
		{
			printf("Filename:\n ");
			scanf("%s",getfilename);
			globalArgs.outfilename = getfilename;
		}
		else if(choose == 3)
		{
			exit(1);
		}
		else
		{
			printf("Error choose!\n");
			exit(1);
		}
	}
	GetStatistics(globalArgs.hflag, globalArgs.sflag, globalArgs.oflag);
	printf("Bytes is: %d\n", globalArgs.bytes);
	printf("AllWords is: %d\n", globalArgs.allwords);
	printf("SimpleWords is: %d\n", globalArgs.words);
	if(globalArgs.lflag == 0)
	{
		ShowLine(globalArgs.filename);
		printf("Lines is: %d\n",globalArgs.lines);
	}

}

/**
 * @brief main \n
 * 通过getopt，实现程序通过参数进行运行目的
 * @date   2016-03-11
 * @author Sugarguo
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
int main(int argc, char **argv)
{
	int opt = 0;


	globalArgs.hflag = 1;
	globalArgs.sflag = 1;
	globalArgs.pflag = 1;
	globalArgs.lflag = 1;
	globalArgs.oflag = 1;
	globalArgs.fflag = 0;
	globalArgs.bytes = 0;
	globalArgs.words = 0;
	globalArgs.lines = 0;
	globalArgs.allwords = 0;

	globalArgs.filename = NULL;
	globalArgs.outfilename = NULL;

	opt = getopt(argc, argv, optString);
	while( opt != -1)
	{
		switch(opt)
		{
			case 'o':
				globalArgs.fflag = globalArgs.fflag + 2;
				globalArgs.outfilename = optarg;
				break;
			case 'h':
				globalArgs.fflag++;
				globalArgs.hflag = 0;
				break;
			case 's':
				globalArgs.fflag++;
				globalArgs.sflag = 0;
				break;
			case 'p':
				globalArgs.fflag++;
				globalArgs.pflag = 0;
				break;
			case 'l':
				globalArgs.fflag++;
				globalArgs.lflag = 0;
				break;
			case 'v':
				globalArgs.fflag++;
				printf("\nVersion: 1.0.0\n");
				break;
			case '?':
				display_usage();
				break;
			case ':':
				printf("Don't have parameter!\nPlease check!\n");
				break;
			default:
				break;
		}
		
		opt = getopt(argc, argv, optString);
	}

	for(opt = globalArgs.fflag + 1; opt < argc; opt++)
	{
		printf("Read file %d: %s  \n", opt,argv[opt]);
		globalArgs.filename = argv[opt];
		globalArgs.bytes = 0;
		globalArgs.words = 0;
		globalArgs.lines = 0;
		globalArgs.allwords = 0;
		convert_document();
    }
    return EXIT_SUCCESS;
}
