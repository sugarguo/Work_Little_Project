#****************************************************************************

# Copyright        :   EmbedWay 恒为科技武汉研发中心 By:Sugarguo

# Author           :   sugarguo

# Date             :   2016-03-01

# Version          :   Link静态链接库

# Description 	   :   DoubleLinkTestMakefile

#

#****************************************************************************/

CC = gcc

AR = ar rcs

RM = rm -fr *.o *.a *.out

LsDoubleLink : LsDoubleLink.o libDoubleLink.a
	$(CC)	-o	LsDoubleLink LsDoubleLink.o libDoubleLink.a

LsDoubleLink.o : LsDoubleLink.c DoubleLink.h
	$(CC)	-c	LsDoubleLink.c

libDoubleLink.a : DoubleLink.o
	$(AR)		libDoubleLink.a DoubleLink.o

DoubleLink.o :  DoubleLink.c
	$(CC)	-c	DoubleLink.c


.PHONY: clean
clean :
	$(RM)		LsDoubleLink
