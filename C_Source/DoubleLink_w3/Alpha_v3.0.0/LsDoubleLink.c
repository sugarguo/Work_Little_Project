/**
* @file			LsDoubleLink.c
* @brief		通用双向链表测试程序——shell命令ls的基本实现 \n
* 使用DoubleLink.h这个sugarguo编写的通用双向链表的头文件接口，进行双向链表的操作测试。
* @author		Sugarguo
* @email    	sugarguo@live.com
* @date			2016/03/15 20:00
* @version		v1.0.0 
* @copyright	EmbedWay 恒为科技武汉研发中心 By:Sugarguo
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <windows.h> //win请用这个头文件
#include <unistd.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>
#include<sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ioctl.h> 
#include "DoubleLink.h"

///@brief 定义默认信息的结构体
struct globalArgs_t{
	char path[1024];		///<文件绝对路径
	int iflag;				///<是否的flag
	int cflag;				///<是否采用修改时间排序的flag
	int kflag;				///<是否采用字节排序结果的flag
	int tflag;				///<是否显示最终结果的flag
	int mflag;				///<是否横向输出的flag
	int lflag;				///<是否长格式显示文件的flag
	int aflag;				///<是否显示隐藏文件的flag
	int rflag;				///<是否递归显示文件的flag
	int pflag;				///<文件个数标量
	int pnflag;				///<文件个数标量
	int plflag;				///<字符长度标量
	int pzlflag;			///<字符长度标量
}globalArgs;

static const char *optString = "cktmlarv?";

///@brief 定义默认文件信息的结构体
struct FileInfo
{
	char filename[1024];	///<文件文件名
	int bytes;				///<文件字节数
	int link;				///<文件链接数
	char username[255];		///<文件用户
	char groupname[255];	///<文件组
	char mode[12];			///<文件的权限
	char ctime[20];			///<文件的ctime
	char mtime[20];			///<文件的mtime
	char atime[20];			///<文件的atime
};

struct winsize size;


/**
* @brief CallBackCmpChar \n
* 回调函数，比较内容是否相同，比较内容为文件信息结构体中的文件名
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个字母比较结果
*/
int CallBackCmpFilename(const void *one,const void *two)
{
	return(strcasecmp(((struct FileInfo *)one)->filename, ((struct FileInfo *)two)->filename));
}

/**
* @brief CallBackCmpChar \n
* 回调函数，比较内容是否相同，比较内容为文件信息结构体中的文件名长短
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个字母比较结果
*/
int CallBackCmpFilenameLong(const void *one,const void *two)
{
	return((int)strlen(((struct FileInfo *)two)->filename) - (int)strlen(((struct FileInfo *)one)->filename));
}

/**
* @brief CallBackCmpChar \n
* 回调函数，比较内容是否相同，比较内容为文件信息结构体中的时间
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个字母比较结果
*/
int CallBackCmpTime(const void *one,const void *two)
{
	return(strcasecmp(((struct FileInfo *)one)->atime, ((struct FileInfo *)two)->atime));
}


/**
* @brief CallBackCmpChar \n
* 回调函数，比较内容是否相同，比较内容为文件信息结构体中的字节数
* @param[in]	*one	比较的第一个内容
* @param[in]	*two	比较的第二个内容
* @return		返回值为两个字母比较结果
*/
int CallBackCmpBytes(const void *one,const void *two)
{
	return(((struct FileInfo *)one)->bytes - ((struct FileInfo *)two)->bytes);
}



/**
 * @brief CallBackShowFileInfo_a \n
 * 显示隐藏文件
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *datashow | void      |传入的文件信息
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void CallBackShowFileInfo_a(const void *datashow)
{

	struct FileInfo *data;
	data = (struct FileInfo *)datashow;
	if(data->filename[0] & 0x80)
	{
		globalArgs.pzlflag = globalArgs.plflag + 4;
		if(strstr(data->mode,"d"))
			printf("\033[1;34m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->mode,"x"))
			printf("\033[1;32m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("\033[1;31m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else	
			printf("%*s",-(globalArgs.pzlflag),data->filename);

		if(globalArgs.pnflag < globalArgs.pflag)
		{
			globalArgs.pnflag ++;
		}
		else
		{
			globalArgs.pnflag = 1;
			printf("\n");
		}
	}
	else
	{
		globalArgs.pzlflag = globalArgs.plflag + 2;
		if(strstr(data->mode,"d"))
			printf("\033[1;34m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->mode,"x"))
			printf("\033[1;32m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("\033[1;31m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else	
			printf("%*s",-(globalArgs.pzlflag),data->filename);

		if(globalArgs.pnflag < globalArgs.pflag)
		{
			globalArgs.pnflag ++;
		}
		else
		{
			globalArgs.pnflag = 1;
			printf("\n");
		}
	}
}


/**
 * @brief CallBackShowFileInfo \n
 * 不显示隐藏文件
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *datashow | void      |传入的文件信息
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void CallBackShowFileInfo(const void *datashow)
{

	struct FileInfo *data;
	data = (struct FileInfo *)datashow;
	if(data->filename[0] == '.')
	{;}
	else if(data->filename[0] & 0x80)
	{
		globalArgs.pzlflag = globalArgs.plflag + 4;
		if(strstr(data->mode,"d"))
			printf("\033[1;34m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->mode,"x"))
			printf("\033[1;32m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("\033[1;31m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else	
			printf("%*s",-(globalArgs.pzlflag),data->filename);

		if(globalArgs.pnflag < globalArgs.pflag)
		{
			globalArgs.pnflag ++;
		}
		else
		{
			globalArgs.pnflag = 1;
			printf("\n");
		}
	}
	else
	{
		globalArgs.pzlflag = globalArgs.plflag + 2;
		if(strstr(data->mode,"d"))
			printf("\033[1;34m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->mode,"x"))
			printf("\033[1;32m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("\033[1;31m%*s\033[0m",-(globalArgs.pzlflag),data->filename);
		else	
			printf("%*s",-(globalArgs.pzlflag),data->filename);

		if(globalArgs.pnflag < globalArgs.pflag)
		{
			globalArgs.pnflag ++;
		}
		else
		{
			globalArgs.pnflag = 1;
			printf("\n");
		}
	}
}


/**
 * @brief CallBackShowFileInfoLong \n
 * 长格式显示文件信息
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * *datashow | void      |传入的文件信息
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void CallBackShowFileInfoLong(const void *datashow)
{
	struct FileInfo *data;
	data = (struct FileInfo *)datashow;
	if(globalArgs.aflag == 1)
	{

		if(strstr(data->mode,"d"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;34m%-s/ \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else if(strstr(data->mode,"x"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;32m%-s \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;31m%-s \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else	
			printf("%10s %3d %4s %4s %7d  %10s %-10s\n",data->mode, \
					data->link,data->username,data->groupname,data->bytes, \
					data->mtime,data->filename);
	}
	else if(globalArgs.aflag != 1 && data->filename[0] == '.')
	{;}
	else
	{
		if(strstr(data->mode,"d"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;34m%-s/ \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else if(strstr(data->mode,"x"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;32m%-s \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else if(strstr(data->filename,"tar.gz") || strstr(data->filename,".zip") || strstr(data->filename,".tgz"))
			printf("%10s %3d %4s %4s %7d  %10s \033[1;31m%-s \033[0m\n", \
					data->mode,data->link,data->username,data->groupname, \
					data->bytes,data->mtime,data->filename);
		else	
			printf("%10s %3d %4s %4s %7d  %10s %-10s\n",data->mode, \
					data->link,data->username,data->groupname,data->bytes, \
					data->mtime,data->filename);
	}
}


/**
 * @brief FromUidToUserName \n
 * 通过getgrgid函数，读取文件所属组
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * uid         | uid_t     |传入的文件权限
 * groupname[] | char      |文件属于的用户名
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * username[]| char      |文件属于的用户
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
char *FromUidToUserName(uid_t uid,char username[])
{
	struct passwd *pwd;
	pwd = getpwuid(uid);
	if(pwd == NULL)
	{
		printf("errorno : %d\n", errno);
		return NULL;
	}
	strcpy(username,pwd->pw_name);
	return pwd->pw_name;
}


/**
 * @brief FromGidToGName \n
 * 通过getgrgid函数，读取文件所属组
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * gid         | gid_t     |传入的文件权限
 * groupname[] | char      |文件属于的组
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * groupname[] | char      |文件属于的组
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
char *FromGidToGName(gid_t gid,char groupname[])
{
	struct group *grp;
	grp = getgrgid(gid);
	if(grp == NULL)
	{
		printf("errorno : %d\n", errno);
		return NULL;
	}
	strcpy(groupname,grp->gr_name);
	return grp->gr_name;
}


/**
 * @brief BackModeCompetence \n
 * 通过st_mode与S_IF* 想与，然后与S_IF* 判断，如果是则存在此权限，与下方不同，此为传出数字权限
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * st_mode   | mode_t    |传入的文件权限
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * 0         | int       | 传出值为777 类型的权限
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
int BackModeCompetence(mode_t st_mode)
{
	int userrwx = 0;
	int grouprwx = 0;
	int otherrwx = 0;

	if ((st_mode & S_IRUSR) == S_IRUSR)
		userrwx += 4;
	if ((st_mode & S_IWUSR) == S_IWUSR)
		userrwx += 2;
	if ((st_mode & S_IXUSR) == S_IXUSR)
		userrwx += 1;


	if ((st_mode & S_IRGRP) == S_IRGRP)
		grouprwx += 4;
	if ((st_mode & S_IWGRP) == S_IWGRP)
		grouprwx += 2;
	if ((st_mode & S_IXGRP) == S_IXGRP)
		grouprwx += 1;


	if ((st_mode & S_IROTH) == S_IROTH)
		otherrwx += 4;
	if ((st_mode & S_IWOTH) == S_IWOTH)
		otherrwx += 2;
	if ((st_mode & S_IXOTH) == S_IXOTH)
		otherrwx += 1;

	return userrwx * 100 + grouprwx * 10 + otherrwx; 
}



/**
 * @brief BackMode \n
 * 通过st_mode与S_IF* 想与，然后与S_IF* 判断，如果是则存在此权限
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * st_mode   | mode_t    |传入的文件权限
 * mode[]    | char      |文件权限的保存数组
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * 0         | int       | 判断是否为目录
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
int BackMode(mode_t st_mode,char mode[])
{

	strcpy(mode , "+_________");

	if(S_ISDIR(st_mode))
	{
		mode[0] = 'd';
	}
	else if(S_ISSOCK(st_mode))
	{
		mode[0] = 's';
	}
	else if(S_ISLNK(st_mode))
	{
		mode[0] = 'l';
	}
	else if(S_ISREG(st_mode))
	{
		mode[0] = '-';
	}
	else if(S_ISBLK(st_mode))
	{
		mode[0] = 'b';
	}
	else
	{
		mode[0] = '+';
	}
	/*
	if ((st_mode & S_IFSOCK) == S_IFSOCK)
		mode[0] = 's';
	else if((st_mode & S_IFLNK) == S_IFLNK)
		mode[0] = 'l';
	else if((st_mode & S_IFREG) == S_IFREG)
		mode[0] = '-';
	else if((st_mode & S_IFBLK) == S_IFBLK)
		mode[0] = 'b';
	else if((st_mode & S_IFDIR) == S_IFDIR) //S_ISDIR(statbuf.st_mode)
		mode[0] = 'd';
	else
		mode[0] = '+';
	*/

	if ((st_mode & S_IRUSR) == S_IRUSR)
		mode[1] = 'r';
	if ((st_mode & S_IWUSR) == S_IWUSR)
		mode[2] = 'w';
	if ((st_mode & S_IXUSR) == S_IXUSR)
		mode[3] = 'x';


	if ((st_mode & S_IRGRP) == S_IRGRP)
		mode[4] = 'r';
	if ((st_mode & S_IWGRP) == S_IWGRP)
		mode[5] = 'w';
	if ((st_mode & S_IXGRP) == S_IXGRP)
		mode[6] = 'x';


	if ((st_mode & S_IROTH) == S_IROTH)
		mode[7] = 'r';
	if ((st_mode & S_IWOTH) == S_IWOTH)
		mode[8] = 'w';
	if ((st_mode & S_IXOTH) == S_IXOTH)
		mode[9] = 'x';
	
	if (mode[0] == 'd')
		return 0;
	return 1;
}


char *BackAllTime(time_t time, char timeback[])
{
	strftime(timeback,128,"%Y-%m-%d %H:%M",localtime(&time));//:%S\n",localtime(&time));
	return timeback;
}



/**
 * @brief GetDoubleLink \n
 * 读取文件名以及各种信息，创建结构体插入到双向链表
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * path[]    | char      |文件目录绝对路径（支持. ..）
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * *List     | DLNode    | 返回的List指针
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
DLNode *GetDoubleLink(char path[])  
{  
	DIR *dirptr = NULL;  
	struct dirent *entry;  
	struct stat buf;
	struct FileInfo *fileinfo;
	char allpath[255];

	DLNode *List = NULL;

	List = CreateList();

	if((dirptr = opendir(path)) == NULL)  
	{  
		printf("Open Directory %s Error！\n",  path); 
	}  
	else  
	{  
		while ((entry = readdir(dirptr)) != NULL)  
		{
			memset(&buf,0,sizeof(struct stat));
			fileinfo = malloc(sizeof(struct FileInfo));
			strcpy(allpath,globalArgs.path);
			strcat(allpath,(char *)entry->d_name);
			if (stat(allpath,&buf) != 0 )
			{
				perror("stat");
			}
			BackMode(buf.st_mode, fileinfo->mode);
			//if(strstr(buf.st_mode,"d") == 0 &&  globalArgs.rflag == 0)
				//GetDoubleLink(allpath);
			strcpy(fileinfo->filename , entry->d_name);
			fileinfo->bytes = buf.st_size;
			fileinfo->link = (int)buf.st_nlink;
			FromUidToUserName(buf.st_uid,fileinfo->username);
			FromGidToGName(buf.st_gid,fileinfo->groupname);
			BackAllTime(buf.st_ctime,fileinfo->ctime);
			BackAllTime(buf.st_ctime,fileinfo->atime);
			BackAllTime(buf.st_ctime,fileinfo->mtime);

			InsertList(List,fileinfo);
			
		}  
		closedir(dirptr);
	}  
	return List;  
}


/**
 * @brief listAllFiles \n
 * 递归输出文件
 * @date   2016-03-16
 * @author Sugarguo
 * @param  : 参数说明如下表：
 * name      | type      |description of param 
 * ----------|-----------|--------------------
 * dirname[] | char      |文件目录绝对路径（支持. ..）
 * @return    返回值说明如下：
 * name      | type      | description of value
 * ----------|-----------|----------------------
 * null      | null      | null
 * @warning   null
 * @attention null
 * @note      null
 * @todo      null
 */
void listAllFiles(char dirname[])
{
	DIR *dirptr = NULL;  
	struct dirent *entry;
	struct stat buf;
  	char allpath[255];

	dirptr = opendir(dirname);
	if(dirptr == NULL)
	{
		printf("open dir %s error!\n",dirname);
		exit(1);
	}

	while((entry = readdir(dirptr)) != NULL)
	{
		if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))
			continue;
		sprintf(allpath,"%s/%s",dirname,entry->d_name);

		
		memset(&buf,0,sizeof(struct stat));
		//lstat(allpath,&buf);
		if (stat(allpath,&buf) != 0 )
		{
			perror("stat");
		}

		if(S_ISDIR(buf.st_mode))
		{
			printf("\n\033[1;34m%s\033[0m\n",entry->d_name);
			listAllFiles(allpath);
		}
		else
		{
			printf("%s,  ",entry->d_name);
		}
	}
	closedir(dirptr);
}


/**
 * @brief display_usage \n
 * 词频统计测试文件通过getopt函数的错误回显
 * @date   2016-03-16
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
	puts("Such as -c -k -t -m -l -a -v\n\n");
	exit(EXIT_FAILURE);
}

/**
 * @brief convert_document \n
 * shell 中 仿ls命令测试文件通过getopt函数的配置函数，并通过flag选择合适方式输出
 * @date   2016-03-16
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
	DLNode *List = NULL;

	List = GetDoubleLink(globalArgs.path);


	SequenceList(List, 2, CallBackCmpFilenameLong);
	if (isatty(STDOUT_FILENO) == 0)  
	{
		exit(1);  
	}
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &size)<0) 
	{
		perror("ioctl TIOCGWINSZ error");
		exit(1);
	}

	globalArgs.plflag = ((int)strlen(((struct FileInfo *)(List->next->data))->filename));
	globalArgs.pflag = (size.ws_col / ((int)strlen(((struct FileInfo *)(List->next->data))->filename) + 2));
	/*printf("p->next : %s\n",((struct FileInfo *)(List->next->data))->filename);
	printf("pflag : %d\n",globalArgs.pflag);
	printf("%d rows, %d columnsn\n", size.ws_row, size.ws_col); 
	printf("strlen : %d\n",(int)strlen(((struct FileInfo *)(List->next->data))->filename) + 2);*/

	SequenceList(List, 2, CallBackCmpFilename);
	
	if(globalArgs.kflag == 0)
	{
		SequenceList(List, 2, CallBackCmpBytes);
	}
	if(globalArgs.tflag == 0)
	{
		SequenceList(List, 2, CallBackCmpTime);
	}
	if(globalArgs.lflag == 0)
	{
		ShowList(List,0,CallBackShowFileInfoLong);
	}
	else if(globalArgs.aflag == 0)
	{
		ShowList(List,0,CallBackShowFileInfo_a);
	}
	else
	{
		//printf("\n");
		ShowList(List,0,CallBackShowFileInfo);
		
	}
	printf("\n");
	DropList(List);

}

/**
 * @brief main \n
 * 通过getopt，实现程序通过参数进行运行目的
 * @date   2016-03-16
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

	globalArgs.cflag = 1;
	globalArgs.kflag = 1;
	globalArgs.tflag = 1;
	globalArgs.mflag = 1;
	globalArgs.lflag = 1;
	globalArgs.iflag = 0;
	globalArgs.aflag = 1;
	globalArgs.rflag = 1;
	globalArgs.pflag = 0;
	globalArgs.pnflag = 1;
	globalArgs.plflag = 0;
	globalArgs.pzlflag = 0;

	opt = getopt(argc, argv, optString);
	while( opt != -1)
	{
		switch(opt)
		{
			case 'c':
				globalArgs.iflag++;
				globalArgs.cflag = 0;
				break;
			case 'k':
				globalArgs.iflag++;
				globalArgs.kflag = 0;
				break;
			case 't':
				globalArgs.iflag++;
				globalArgs.tflag = 0;
				break;
			case 'm':
				globalArgs.iflag++;
				globalArgs.mflag = 0;
				break;
			case 'l':
				globalArgs.iflag++;
				globalArgs.lflag = 0;
				break;
			case 'a':
				globalArgs.iflag++;
				globalArgs.aflag = 0;
				break;
			case 'r':
				globalArgs.iflag++;
				globalArgs.rflag = 0;
				break;
			case 'v':
				globalArgs.iflag++;
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

	if( optind == argc )
		strcpy(globalArgs.path , "./");
	else
		strcpy(globalArgs.path , argv[globalArgs.iflag + 1]);


	if(globalArgs.rflag == 0)
	{
		listAllFiles(globalArgs.path);
	}
	else
	{
		convert_document();
	}
	return EXIT_SUCCESS;
}
