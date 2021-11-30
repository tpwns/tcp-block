#pragma once

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <cstring>
#include "iphdr.h"
#include "tcphdr.h"

using namespace std;

#pragma pack(push,1)

struct Pseudoheader{
    Ip srcIP;
    Ip destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};

void dump(char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02hhx ", buf[i]);
	}
	printf("\n");
}

#pragma pack(pop)
#define CARRY 65536

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {
        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;

    }

    result=tempChecksum;
    return result;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct IpHdr *iph=(struct IpHdr*)data;
    struct TcpHdr *tcph=(struct TcpHdr*)(data+iph->hl());

    memcpy(&pseudoheader.srcIP,&iph->src_,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->dst_,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol_;
    pseudoheader.TCPLen=htons(dataLen-iph->hl());

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->sum_=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=checksum^0xffff; //xor checksum

    return checksum;
}



uint16_t calIPChecksum(uint8_t* data)
{
    struct IpHdr* iph=(struct IpHdr*)data;
    iph->sum_=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,(uint32_t)iph->hl());

    checksum = checksum ^ 0xffff;

    return checksum;
}
