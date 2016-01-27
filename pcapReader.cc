#include "include.h"
#include "util.h"
#include "pcapReader.h"

#include "ethernet.h"
#include "tcp.h"
#include "udp.h"
#include "ip.h"



//#######################################################################
void PcapReader::offlineFileOpen(char *infile)
{
	char				ebuf[MAXSTR];

//	printf("void PcapReader::offlineFileOpen(char [%s]) \n", infile);
	if( (m_pcap_input = pcap_open_offline(infile, ebuf)) == NULL ) {printf("ERROR: File Open ... [%s]\n\n", infile); 
	//exit(0);
	}
	//printf("void PcapReader::offlineFileOpen(char *outfile) \n");

}

//#######################################################################
void PcapReader::offlineFileClose()
{
//	printf("void PcapReader::offlineFileClose()\n");
	pcap_close(m_pcap_input);
	//printf("void PcapReader::offlineFileClose()\n");
}


//#######################################################################
unsigned char* PcapReader::readPkt(PacketStoredInfo *pktInfo)
{
	EtherHdr *ether_h;
	struct pcap_pkthdr	pcap_h;	
	unsigned char		*payload;

	pktInfo->reset();

	while( (payload = (unsigned char*)pcap_next(m_pcap_input, &pcap_h)) != NULL)
	{
		ether_h = (EtherHdr*)payload;
		if(ntohs(ether_h->ether_type) != ETHERTYPE_IP) continue;
		
		pktInfo->tv_sec     = pcap_h.ts.tv_sec;
		pktInfo->tv_usec    = pcap_h.ts.tv_usec;
		pktInfo->pkt_len    = pcap_h.len + CRC_LENGTH;
		pktInfo->stored_len = pcap_h.caplen - ETHER_LENGTH;

		return payload + ETHER_LENGTH;
	}
	return NULL;
}




//#######################################################################
void PcapReader::print()
{
	struct in_addr addr;
	char srcip[20], dstip[20];
/*
	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &src_addr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dst_addr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );
*/

}


//#######################################################################
void PcapReader::printDetail()
{
	struct in_addr addr;
	char srcip[20], dstip[20];

/*	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &src_addr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dst_addr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	
	//if( strcmp("210.107.108.84", srcip) || strcmp("163.152.229.115", dstip)) return;
	//if( src_port == 10001 ) return;




	printf("################### PcapReader Info #######################\n");

	printf("time_sec           : %12d [%3d]\n", time_sec, time_sec%60);
	printf("time_usec          : %12d [%3d]\n", time_usec, time_usec/1000);
	printf("\n");

	memcpy(&addr, &(src_addr), 4);
	printf("src_addr           : %s\n", inet_ntoa(addr) );
	memcpy(&addr, &(dst_addr), 4);
	printf("dst_addr           : %s\n", inet_ntoa(addr) );
	printf("src_port           : %d\n", src_port);
	printf("dst_port           : %d\n", dst_port);
	printf("ip_proto           : %d\n", ip_proto);
	printf("ip_offset          : [%5u][0x%04X] \n", ip_offset,  ip_offset);
	printf("\n");

	printf("real_pkt_len       : %5d\n",		real_pkt_len);
	printf("real_payload_len   : %5d\n",		real_payload_len);
	printf("stored_pkt_len	   : %5d\n",		stored_pkt_len);
	printf("stored_payload_len : %5d\n",		stored_payload_len);
	printf("\n");

	printf("ip_hlen            : %5d\n",		ip_hlen);
	printf("tcp_hlen           : %5d\n",		tcp_hlen);
	printf("udp_hlen           : %5d\n",		udp_hlen);
	printf("\n");

	printf("ip_tos             : %d\n",		ip_tos);
	printf("ip_ttl             : %d\n",		ip_ttl);
	
	printf("tcp_window         : %d\n",		tcp_window);
	printf("tcp_sn             : %u [0x%06X]\n",tcp_sn, tcp_sn);
	printf("tcp_an             : %u [0x%06X]\n",tcp_an, tcp_an);
	printf("tcp_flags          : 0x%02X\n",	tcp_flags);
*/
	printf("#######################################################\n");

	//getchar();

}
