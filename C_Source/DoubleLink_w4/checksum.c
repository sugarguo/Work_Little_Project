#include<stdio.h>
void main()     
{     
	int buff[10]={0x4500,0x0e2c,0xbd18,0x0000,0x4001,0x1d54,0xc0a8,0x0890,0xc0a8,0x0884};     
	int checksum=0,i=0;     
	for(i=0;i<10;i++)     
	{     
		checksum+=buff[i];     
	}     
	printf("checksum=%x\n",checksum);     
	checksum=(checksum>>16)+(checksum & 0xffff);     
	checksum+=(checksum>>16);     
	checksum=0xffff-checksum;     
	printf("checksum=%04x\n",checksum);     
}   
