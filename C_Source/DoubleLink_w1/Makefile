#*****************************************************************************

# Copyright        :  

# Author           :   sugarguo

# Date             :   2016-03-01

# Version          :   Link静态链接库

# Description 	   :   DoubleLinkTestMakefile

#

#****************************************************************************/

CC = gcc

AR = ar rcs

DoubleLinkTest : DoubleLinkTest.o libDoubleLink.a
	$(CC)	-o	DoubleLinkTest DoubleLinkTest.o libDoubleLink.a

DoubleLinkTest.o : DoubleLinkTest.c DoubleLink.h
	$(CC)	-c	DoubleLinkTest.c

libDoubleLink.a : DoubleLink.o
	$(AR)		libDoubleLink.a DoubleLink.o

DoubleLink.o :  DoubleLink.c
	$(CC)	-c	DoubleLink.c


.PHONY: clean
clean :
	$(RM) = rm -fr *.o *.a *.out
