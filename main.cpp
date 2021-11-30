#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "checksum.h"
#include "main.h"
#include <thread>
#include <signal.h>
#include <iostream>
#include <string.h>
#include <arpa/inet.h>
using namespace std;

#pragma pack(push, 1)
#pragma pack(pop)

Mac mymac;
Ip myip;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

struct TcpIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
};

struct BackPkt {
		TcpIpPacket header;
		char fin_message[256] = "HTTP/1.0 302 Redirect\r\nLocation: http://korea.ac.kr\r\n";
	};

BackPkt make_backwardPkt(EthHdr *ethhdr, IpHdr *iphdr, TcpHdr *tcphdr, uint32_t org_tcpDataSize)
{
	BackPkt packet;

	packet.header.eth_.type_ = htons(packet.header.eth_.Ip4);
	packet.header.eth_.smac_ = mymac;
	packet.header.eth_.dmac_ = ethhdr->smac_;

	packet.header.ip_.v_hl_ = iphdr->v_hl_;
	packet.header.ip_.tos_ = iphdr->tos_;
	packet.header.ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr) + strlen(packet.fin_message));
	packet.header.ip_.id_ = iphdr->id_;
	packet.header.ip_.off_= iphdr->off_;
	packet.header.ip_.ttl_ = 128;
	packet.header.ip_.protocol_ = packet.header.ip_.tcp;
	packet.header.ip_.src_ = iphdr->dst_;
	packet.header.ip_.dst_ = iphdr->src_;
	packet.header.ip_.sum_ = htons(calIPChecksum((uint8_t *)&packet.header.ip_));

	packet.header.tcp_.sport_ = tcphdr->dport_;
	packet.header.tcp_.dport_ = tcphdr->sport_;
	packet.header.tcp_.seq_ = tcphdr->ack_;
	packet.header.tcp_.ack_ = htonl(tcphdr->seq() + org_tcpDataSize);
	packet.header.tcp_.off_ = 5 << 4;
	packet.header.tcp_.flags_ = 0x00;
	packet.header.tcp_.flags_ |= tcphdr->fin_f;
	packet.header.tcp_.flags_ |= tcphdr->ack_f;
	packet.header.tcp_.win_ = tcphdr->win_;
	packet.header.tcp_.urp_ = tcphdr->urp_;
	packet.header.tcp_.sum_ = htons(calTCPChecksum((uint8_t *)&(packet.header.ip_),packet.header.ip_.len()));

	return packet;
}

TcpIpPacket make_forwardPkt(EthHdr *ethhdr, IpHdr *iphdr, TcpHdr *tcphdr, uint32_t org_tcpDataSize)
{
	TcpIpPacket packet;
	
	packet.eth_.type_ = htons(packet.eth_.Ip4);
	packet.eth_.smac_ = mymac;
	packet.eth_.dmac_ = ethhdr->dmac_;

	packet.ip_.v_hl_ = iphdr->v_hl_;
	packet.ip_.tos_ = iphdr->tos_;
	packet.ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
	packet.ip_.id_ = iphdr->id_;
	packet.ip_.off_= iphdr->off_;
	packet.ip_.ttl_ = iphdr->ttl_;
	packet.ip_.protocol_ = packet.ip_.tcp;
	packet.ip_.src_ = iphdr->src_;
	packet.ip_.dst_ = iphdr->dst_;
	packet.ip_.sum_ = htons(calIPChecksum((uint8_t *)&packet.ip_));

	packet.tcp_.sport_ = tcphdr->sport_;
	packet.tcp_.dport_ = tcphdr->dport_;
	packet.tcp_.seq_ = htonl(tcphdr->seq() + org_tcpDataSize);
	packet.tcp_.ack_ = tcphdr->ack_;
	packet.tcp_.off_ = (5<<4);
	packet.tcp_.flags_ = 0x00;
	packet.tcp_.flags_ |= tcphdr->rst_f;
	//packet.tcp_.flags_ |= tcphdr->ack_f;
	packet.tcp_.win_ = tcphdr->win_;
	packet.tcp_.urp_ = tcphdr->urp_;
	packet.tcp_.sum_ = htons(calTCPChecksum((uint8_t *)&(packet.ip_),packet.ip_.len()));

	return packet;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char* pattern = argv[2];

	pcap_t* handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);	//pcap을 여는 함수, (패킷을오픈할디바이스, 패킷최대크기, promiscuous, timeout, 에러버퍼)
	if (handler == NULL) {
		perror("pcap_open_live");
		return -1;
	}
	
	mymac = GetInterfaceMacAddress(dev);
	myip = GetInterfaceIPAddress(dev);

	printf("my address information\n");
	printf("mymac: %s\n",std::string(mymac).data());
	printf("myip: %s\n\n",std::string(myip).data());
	printf("pattern\n");
	printf("%s\n\n",pattern);
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;		
		int res = pcap_next_ex(handler, &header, &packet);	
		if (res == 0) continue;	
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {	
			perror("pcap_next_ex");
			return -1;
		}

		struct EthHdr *ethhdr = (struct EthHdr *) (packet);
		struct IpHdr *iphdr = (struct IpHdr *) (ethhdr +1);
		struct TcpHdr *tcphdr = (struct TcpHdr *) (iphdr +1);

		uint32_t tcpDataLen = iphdr->len() - (iphdr->hl() + tcphdr->hl());	//잡은 패킷의 tcp data length
		
		const char *TcpData = (const char *)(tcphdr);
		TcpData = TcpData + tcphdr->hl();

		if(iphdr->protocol()!=iphdr->tcp || tcpDataLen < strlen(pattern)){
			continue;		//tcp가 아니거나, tcp Data 길이가 pattern보다 작은 경우는 패턴이 존재할 수 없으므로 continue
		}

		bool isBlock = false;
		for (int i=0; i< tcpDataLen-strlen(pattern); i++){
			if(strncmp((char *)TcpData,pattern,strlen(pattern)) == 0){
				isBlock = true;		//tcp data에 패턴이 존재하면 true
				break;
			}
			TcpData ++;
		}
		if(isBlock == false){
			continue;
		}

		cout << "[pattern]" << pattern << " is found!" << "\n";

		BackPkt backwardPkt = make_backwardPkt(ethhdr,iphdr,tcphdr,tcpDataLen);
		TcpIpPacket forwardPkt = make_forwardPkt(ethhdr,iphdr,tcphdr,tcpDataLen);
		/*
		dump((char *)&backwardPkt,(sizeof(backwardPkt.header)+(strlen(backwardPkt.fin_message))));
		cout << "\n";
		dump((char *)&forwardPkt,sizeof(forwardPkt));
		*/
		if(pcap_sendpacket(handler, reinterpret_cast<const u_char *>(&backwardPkt), (sizeof(backwardPkt.header) + strlen(backwardPkt.fin_message)))!=0){
					perror("pcap_sendpacket");
					return -1;
		}
		
		if(pcap_sendpacket(handler, reinterpret_cast<const u_char *>(&forwardPkt), sizeof(forwardPkt))!=0){
					perror("pcap_sendpacket");
					return -1;
		}

		cout << "block packet sended\n\n";
	}

	pcap_close(handler);
}
