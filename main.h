#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ethhdr.h"
#include <iostream>
#include <time.h>   


void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"test.gilgil.net\"\n");
}


/* 디바이스 이름을 입력받아 맥주소를 가져오는 함수*/
Mac GetInterfaceMacAddress(const char *ifname)
{
    uint8_t *mac_addr; struct ifreq ifr; int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        exit;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);  
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      exit;
    }
    mac_addr = (uint8_t *)(ifr.ifr_hwaddr.sa_data); 
    close(sockfd);

    return Mac(mac_addr);
}

/* 디바이스 이름을 입력받아 ip주소를 가져오는 함수*/
Ip GetInterfaceIPAddress(const char *ifname)
{
    char ip_addr[40];   struct ifreq ifr;   int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        exit;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      exit;
    }
    close(sockfd);
    
    inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ip_addr,sizeof(struct sockaddr));
    return Ip(ip_addr);
}



