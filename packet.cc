#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "include.h"
#include "util.h"
#include "packet.h"

#include "tcp.h"
#include "udp.h"
#include "ip.h"

#define DEFAULT_TCP_HEADER_LEN	20
#define DEFAULT_UDP_HEADER_LEN	8
//#######################################################################
void Packet::set(PacketStoredInfo *pktInfo, unsigned char *p)
{
	IPHdr			*iph	= NULL;
	TCPHdr			*tcph	= NULL;
	UDPHdr			*udph	= NULL;
	unsigned char	*data	= NULL;
	unsigned int	ip_tlen; 

	this->reset();
	
	time_sec		= pktInfo->tv_sec;
	time_usec		= pktInfo->tv_usec;
	real_pkt_len	= pktInfo->pkt_len;
	stored_pkt_len	= pktInfo->stored_len;

	iph		= (IPHdr *)p;

	src_addr	= iph->ip_src.s_addr;
	dst_addr	= iph->ip_dst.s_addr;
	ip_tos		= iph->ip_tos ;
	ip_proto	= iph->ip_proto ;
	ip_ttl		= iph->ip_ttl ;
	ip_offset	= ntohs(iph->ip_off);

	ip_hlen		= iph->ip_hl * 4;
	ip_tlen		= ntohs(iph->ip_len);	

	if (ip_proto == IPPROTO_TCP && stored_pkt_len >= (ip_hlen + DEFAULT_TCP_HEADER_LEN) )			
	{
		tcph				= (TCPHdr *)(p+ip_hlen);
		tcp_hlen			= tcph->d_offset * 4;
		tcp_hlen			= tcp_hlen >= DEFAULT_TCP_HEADER_LEN ? tcp_hlen : DEFAULT_TCP_HEADER_LEN;

		src_port			= ntohs(tcph->src_port) ;
		dst_port			= ntohs(tcph->dst_port) ;
		tcp_flags			= tcph->flags ;
		tcp_window			= ntohs(tcph->window);
		tcp_sn				= ntohl(tcph->seq_num);
		tcp_an				= ntohl(tcph->ack_num);
	
		real_payload_len	= ip_tlen - (ip_hlen + tcp_hlen);
	}
	
	if (ip_proto == IPPROTO_UDP && stored_pkt_len >= (ip_hlen + DEFAULT_UDP_HEADER_LEN) )	
	{
		udph				= (UDPHdr *)(p+ip_hlen); 
		udp_hlen			= DEFAULT_UDP_HEADER_LEN;

		src_port			= ntohs(udph->src_port) ;
		dst_port			= ntohs(udph->dst_port) ;

		real_payload_len	= ip_tlen - (ip_hlen + udp_hlen);
	} 

	stored_payload_len	= pktInfo->stored_len - (ip_hlen + tcp_hlen + udp_hlen);
	stored_pkt			= p;
	stored_payload		= p + (ip_hlen + tcp_hlen + udp_hlen);
}

//#######################################################################
void Packet::print()
{
struct in_addr addr;
	char srcip[20], dstip[20];
	struct tm stTargetTime;
	time_t tempTime;

	tempTime = time_sec;
	
	memcpy(&stTargetTime, localtime(&tempTime), sizeof(struct tm) );

	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &src_addr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dst_addr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	/*
	
	printf("%04d_%02d_%02d_%02d_%02d %2d.%d : seq:%10u ack:%10u : %-15s : %5d -- %2d --> %-15s : %5d =>  [pkt_len:%6d]  [data_len:%6d] [%c%c%c%c%c%c]\n", 
		stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min,
		time_sec%60, time_usec, 
		tcp_sn, tcp_an,
		srcip, src_port, ip_proto, dstip, dst_port, 
		real_pkt_len, real_payload_len,
		tcp_flags & TCP_FLAG_SYN ? 'S':' ',
		tcp_flags & TCP_FLAG_ACK ? 'A':' ',
		tcp_flags & TCP_FLAG_RST ? 'R':' ',
		tcp_flags & TCP_FLAG_FIN ? 'F':' ',
		tcp_flags & TCP_FLAG_PSH ? 'P':' ',
		tcp_flags & TCP_FLAG_URG ? 'U':' '
	);


	*/
	printf("%04d %02d-%02d %02d:%02d %2d.%dsec : seq:%10u ack:%10u : %-15s : %5d -- %2d --> %-15s : %5d =>  [pkt_len:%6d]  [data_len:%6d] [%c%c%c%c%c%c]\n", 
		stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min,
		time_sec%60, time_usec, 
		tcp_sn, tcp_an,
		srcip, src_port, ip_proto, dstip, dst_port, 
		real_pkt_len, real_payload_len,
		tcp_flags & TCP_FLAG_SYN ? 'S':' ',
		tcp_flags & TCP_FLAG_ACK ? 'A':' ',
		tcp_flags & TCP_FLAG_RST ? 'R':' ',
		tcp_flags & TCP_FLAG_FIN ? 'F':' ',
		tcp_flags & TCP_FLAG_PSH ? 'P':' ',
		tcp_flags & TCP_FLAG_URG ? 'U':' '
	);

}
//#######################################################################
void Packet::print(FILE *p_fp)
{
struct in_addr addr;
	char srcip[20], dstip[20];
	struct tm stTargetTime;
	time_t tempTime;

	tempTime = time_sec;
	
	memcpy(&stTargetTime, localtime(&tempTime), sizeof(struct tm) );

	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &src_addr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dst_addr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	/*
	
	printf("%04d_%02d_%02d_%02d_%02d %2d.%d : seq:%10u ack:%10u : %-15s : %5d -- %2d --> %-15s : %5d =>  [pkt_len:%6d]  [data_len:%6d] [%c%c%c%c%c%c]\n", 
		stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min,
		time_sec%60, time_usec, 
		tcp_sn, tcp_an,
		srcip, src_port, ip_proto, dstip, dst_port, 
		real_pkt_len, real_payload_len,
		tcp_flags & TCP_FLAG_SYN ? 'S':' ',
		tcp_flags & TCP_FLAG_ACK ? 'A':' ',
		tcp_flags & TCP_FLAG_RST ? 'R':' ',
		tcp_flags & TCP_FLAG_FIN ? 'F':' ',
		tcp_flags & TCP_FLAG_PSH ? 'P':' ',
		tcp_flags & TCP_FLAG_URG ? 'U':' '
	);


	*/
	fprintf(p_fp,"%02d_%02d %2d.%d : seq:%10u ack:%10u : %-15s : %5d -- %2d --> %-15s : %5d =>  [pkt_len:%6d]  [data_len:%6d] [%c%c%c%c%c%c]\n", 
		stTargetTime.tm_hour, stTargetTime.tm_min,
		time_sec%60, time_usec, 
		tcp_sn, tcp_an,
		srcip, src_port, ip_proto, dstip, dst_port, 
		real_pkt_len, real_payload_len,
		tcp_flags & TCP_FLAG_SYN ? 'S':' ',
		tcp_flags & TCP_FLAG_ACK ? 'A':' ',
		tcp_flags & TCP_FLAG_RST ? 'R':' ',
		tcp_flags & TCP_FLAG_FIN ? 'F':' ',
		tcp_flags & TCP_FLAG_PSH ? 'P':' ',
		tcp_flags & TCP_FLAG_URG ? 'U':' '
	);

}


//#######################################################################
void Packet::printDetail()
{
	struct in_addr addr;
	char srcip[20], dstip[20];

	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &src_addr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dst_addr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	
	//if( strcmp("210.107.108.84", srcip) || strcmp("163.152.229.115", dstip)) return;
	//if( src_port == 10001 ) return;




	printf("################### Packet Info #######################\n");
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

	printf("#######################################################\n");

	//getchar();

}
//#######################################################################
void PacketContainer::printPayload()
{
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
	{
		if (payload[i] >= ' ' && payload[i] <= '}')
		{
			printf("%c", payload[i]);
		}
		else
			printf(".");
		
	}
	printf("\r\n");

}
//#######################################################################
void PacketContainer::printPayload(FILE *p_fp)
{
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
	{
		if (payload[i] >= ' ' && payload[i] <= '}')
		{
			fprintf(p_fp, "%c", payload[i]);
		}
		else
			fprintf(p_fp, ".");
		
	}
	fprintf(p_fp, "\r\n");

}
//#######################################################################
void PacketContainer::printPayloadByHex()
{
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
		printf("%02X ", payload[i]);
	printf("\r\n\r\n");
}
//#######################################################################
void PacketContainer::printPayloadByHex(FILE *p_fp)
{
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
		fprintf(p_fp, "%02X ", payload[i]);
	fprintf(p_fp, "\r\n\r\n");
}

//#######################################################################
void PacketContainer::printPayload(int p_iOffset)
{
	int iCount=0;
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i <  pkt.stored_pkt_len;  i++ )
	{
		iCount++;
		if (iCount > p_iOffset)
			break;
		
/*		if (payload[i] >= ' ' && payload[i] <= '}')
		{
			printf("%c", payload[i]);
		}
		else
			printf(".");
*/
		if (payload[i] >= ' ' && payload[i] <= '}' && (payload[i] != ';') && (payload[i] != '\\') && (payload[i] != '"'))
		{
			printf("%c", payload[i]);
		}
		else
			printf("|%02x|", payload[i]);
		
	}
	printf("\r\n");

}
//#######################################################################
void PacketContainer::printPayload(int p_iOffset, FILE *p_fp)
{
	int iCount=0;
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i <  pkt.stored_pkt_len;  i++ )
	{
		iCount++;
		if (iCount > p_iOffset)
			break;

		if (payload[i] >= ' ' && payload[i] <= '}')
		{
			fprintf(p_fp,"%c", payload[i]);
		}
		else
			fprintf(p_fp,".");
		
	}
	fprintf(p_fp,"\r\n");

}
//#######################################################################
void PacketContainer::printPayloadByHex(int p_iOffset)
{
	int iCount=0;
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
	{
		iCount++;
		if (iCount > p_iOffset)
			break;

		printf("%02X ", payload[i]);
	}
	printf("\r\n\r\n");
}
//#######################################################################
void PacketContainer::printPayloadByHex(int p_iOffset, FILE *p_fp)
{
	int iCount=0;
	for ( int i = pkt.stored_pkt_len - pkt.stored_payload_len;  i < pkt.stored_pkt_len;  i++ )
	{
		iCount++;
		if (iCount > p_iOffset)
			break;
		fprintf(p_fp,"%02X ", payload[i]);
	}
	fprintf(p_fp,"\r\n\r\n");
}