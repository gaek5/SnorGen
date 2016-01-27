//#####################################################################
//
//		twowayFlow.h
//		programmed by tmskim
//		2008.11.07
//
//######################################################################
#include "include.h"
#include "twowayFlow.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ethernet type
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_IPX           0x8137  /* IPX family */
#define ETHERTYPE_NETBIOS		0x8191  /* NetBios Protocol*/
#define ETHERTYPE_OTHERS		0x0000

// IP protocol type
#define IP_PROTO_ICMP		1		/* control message protocol */
#define IP_PROTO_IGMP		2		/* group mgmt protocol */
#define IP_PROTO_TCP		6		/* tcp */
#define IP_PROTO_UDP		17		/* user datagram protocol */
#define IP_PROTO_EIGRP		88


// TCP flag type
#define TCP_FLAG_URG		0x20		/* tcp urg */
#define TCP_FLAG_PSH		0x08		/* tcp psh */
#define TCP_FLAG_SYN		0x02		/* tcp syn */
#define TCP_FLAG_ACK		0x10		/* tcp ack */
#define TCP_FLAG_RST		0x04		/* tcp rst */
#define TCP_FLAG_FIN		0x01		/* tcp fin */


//#######################################################################
double FlowStat::calcDuration()
{
	return ( (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec) ) / 1000000.0;
}


//#######################################################################
int FlowStat::isContinue()
{
	return con;
}

//#######################################################################
void FlowStat::print( )
{
	
	printf("%2d.%02d->%2d.%02d [%5.2fsec] [%5dp %10db] => [%3d][%2d][%c%c%c%c%c] [%c%c%c] \n", 
		start.tv_sec%60, start.tv_usec/10000,
		end.tv_sec%60,   end.tv_usec/10000,
		calcDuration(), 

		dPkts, dOctets, 

		con,
		payload,
			
		syn==0? ' ':'S',
		ack==0? ' ':'A',
		rst==0? ' ':'R',
		fin==0? ' ':'F',
		psh==0? ' ':'P',
		

			
		flag & PAYLOAD_EXIST ? 'P' : ' ',
		flag & FRAG_PKT      ? 'F' : ' ',		
		flag & HTTP_PKT      ? 'H' : ' '
		
		);
}
//#######################################################################
void FlowStat::print(FILE *fp )
{
	
	fprintf(fp,"%2d.%02d->%2d.%02d [%5.2fsec] [%5dp %10db] => [%3d][%2d][%c%c%c%c%c] [%c%c%c] \n", 
		start.tv_sec%60, start.tv_usec/10000,
		end.tv_sec%60,   end.tv_usec/10000,
		calcDuration(), 

		dPkts, dOctets, 

		con,
		payload,
			
		syn==0? ' ':'S',
		ack==0? ' ':'A',
		rst==0? ' ':'R',
		fin==0? ' ':'F',
		psh==0? ' ':'P',
		

			
		flag & PAYLOAD_EXIST ? 'P' : ' ',
		flag & FRAG_PKT      ? 'F' : ' ',		
		flag & HTTP_PKT      ? 'H' : ' '
		
		);
}
//#######################################################################
int FlowBasic::serverPort()
{
	if(prot != IP_PROTO_TCP )			return 0x00;
	if(flag & 0x01 &&  flag & 0x02)		return 0x00;	//	0x00	don't know
	if(flag & 0x01)						return 0x01;	//  0x01	client port is source port;
	if(flag & 0x02)						return 0x02;	//	0x02	client port is destination port;

	return 0x00;										//	0x00	don't know
}

//#######################################################################
int FlowBasic::clientPort()
{
	if(prot != IP_PROTO_TCP )			return 0x00;
	if(flag & 0x01 &&  flag & 0x02)		return 0x00;	//	0x00	don't know
	if(flag & 0x01)						return 0x01;	//  0x01	server port is destination port;
	if(flag & 0x02)						return 0x02;	//	0x02	server port is soruce port;

	return 0x00;										//	0x00	don't know
}

//#######################################################################
void FlowBasic::print( )
{
	struct in_addr addr;
	char srcip[20], dstip[20];

	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &srcaddr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dstaddr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	
	printf("%-15s : %5d -- %2d -- %-15s : %5d [%c%c%c%c]\n", 
		srcip, srcport, prot, dstip, dstport,
		serverPort() & 0x02 ? 'S': ' ', serverPort() & 0x01 ? 'D': ' ',
		flag & HTTP ? 'H': ' ', flag & ABNORMAL ? 'A': ' '
	);
}
//#######################################################################
void FlowBasic::print(FILE *fp )
{
	struct in_addr addr;
	char srcip[20], dstip[20];

	memset(&addr, 0, sizeof(struct in_addr) );
	memcpy(&addr, &srcaddr, 4);
	strcpy(srcip, (const char *)inet_ntoa(addr) );
	memcpy(&addr, &dstaddr, 4);
	strcpy(dstip, (const char *)inet_ntoa(addr) );

	
	fprintf(fp,"%-15s : %5d -- %2d -- %-15s : %5d [%c%c%c%c]\n", 
		srcip, srcport, prot, dstip, dstport,
		serverPort() & 0x02 ? 'S': ' ', serverPort() & 0x01 ? 'D': ' ',
		flag & HTTP ? 'H': ' ', flag & ABNORMAL ? 'A': ' '
	);
}
//#######################################################################
void AnalCode::print( )
{
	if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_HEADER)
		printf("H  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_DNS)
		printf("D  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_STATISTIC)
		printf("S  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_BEHAVIOR)
		printf("B  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_PAYLOAD)
		printf("P  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_INTEGRATION)
		printf("I  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_CORRELATION)
		printf("C  ");
	else
		printf("?  ");

	printf("%015llu	%08d	%08d	%04d	%04d	%010d\n",
		m_iSigCode, m_iSCode, m_iACode, m_iPCode, m_iFCode,m_iProCode);
}
//#######################################################################
void AnalCode::print(FILE *fp )
{
	if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_HEADER)
		fprintf(fp,"H  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_DNS)
		fprintf(fp,"D  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_STATISTIC)
		fprintf(fp,"S  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_BEHAVIOR)
		fprintf(fp,"B  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_PAYLOAD)
		fprintf(fp,"P  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_INTEGRATION)
		fprintf(fp,"I  ");
	else if (m_iSigCode/SIGGENERATORIDENTIFIER == SIGCODE_CORRELATION)
		fprintf(fp,"C  ");
	else
		fprintf(fp,"?  ");

	fprintf(fp,"%015llu	%08d	%08d	%04d	%04d	%010d\n",
		m_iSigCode, m_iSCode, m_iACode, m_iPCode, m_iFCode,m_iProCode);
}
//#######################################################################
void FlowAnal::setCode(u_int64_t p_iSigCode, u_int32_t p_iSCode, u_int32_t p_iACode, u_int32_t p_iPCode, u_int32_t p_iFCode, u_int32_t p_iProCode)
{
	int iIndex;

	for (iIndex=0; iIndex<m_iCount; iIndex++)	//동일한 데이터 있으면 skip 2011-08-10
	{
		if (m_caAnalCodeList[m_iCount].m_iSigCode == p_iSigCode)
			if (m_caAnalCodeList[m_iCount].m_iSCode == p_iSCode)
				if (m_caAnalCodeList[m_iCount].m_iACode == p_iACode)
					if (m_caAnalCodeList[m_iCount].m_iPCode == p_iPCode)
						if (m_caAnalCodeList[m_iCount].m_iFCode == p_iFCode)
							if (m_caAnalCodeList[m_iCount].m_iProCode == p_iProCode)
								return;
	}

	if ( m_iCount >= FLOWANAL_CODE_COUNT)
	{
		m_iFlag |= LIST_OVER_FLOW;
		m_caAnalCodeList[m_iCount-1].m_iSigCode = p_iSigCode;
		m_caAnalCodeList[m_iCount-1].m_iSCode = p_iSCode;
		m_caAnalCodeList[m_iCount-1].m_iACode = p_iACode;
		m_caAnalCodeList[m_iCount-1].m_iPCode = p_iPCode;
		m_caAnalCodeList[m_iCount-1].m_iFCode = p_iFCode;
		m_caAnalCodeList[m_iCount-1].m_iProCode = p_iProCode;
	}
	else
	{
		m_caAnalCodeList[m_iCount].m_iSigCode = p_iSigCode;
		m_caAnalCodeList[m_iCount].m_iSCode = p_iSCode;
		m_caAnalCodeList[m_iCount].m_iACode = p_iACode;
		m_caAnalCodeList[m_iCount].m_iPCode = p_iPCode;
		m_caAnalCodeList[m_iCount].m_iFCode = p_iFCode;
		m_caAnalCodeList[m_iCount].m_iProCode = p_iProCode;

		m_iCount++;
	}
	if (p_iSCode)
		m_iFlagCode |= SERVICE_EXIST;
	if (p_iACode)
		m_iFlagCode |= APPLICATION_EXIST;
	if (p_iPCode)
		m_iFlagCode |= PROTOCOL_EXIST;
	if (p_iFCode)
		m_iFlagCode |= FUNCTION_EXIST;
}
//#######################################################################
void FlowAnal::setAnswer(u_int32_t  p_iAnserCode)
{
	m_iAnswerProCode = p_iAnserCode;
	m_iFlag |= ANSWER_EXIST;
}
//#######################################################################
void FlowAnal::print()
{
	int iIndex;
	for (iIndex=0; iIndex<m_iCount; iIndex++)
		m_caAnalCodeList[iIndex].print();
	printf("\n");
}
//#######################################################################
void FlowAnal::print(FILE *fp)
{
	int iIndex;
	for (iIndex=0; iIndex<m_iCount; iIndex++)
		m_caAnalCodeList[iIndex].print(fp);
	fprintf(fp,"\n");
}
//#######################################################################
void FlowAnal::getCode(u_int64_t *p_iSigCode, u_int32_t *p_iSCode, u_int32_t *p_iACode, u_int32_t *p_iPCode, u_int32_t *p_iFCode, u_int32_t *p_iProCode)
{
	*p_iSigCode = m_caAnalCodeList[m_iCount-1].m_iSigCode;
	*p_iSCode = m_caAnalCodeList[m_iCount-1].m_iSCode;
	*p_iACode = m_caAnalCodeList[m_iCount-1].m_iACode;
	*p_iPCode = m_caAnalCodeList[m_iCount-1].m_iPCode;
	*p_iFCode = m_caAnalCodeList[m_iCount-1].m_iFCode;
	*p_iProCode = m_caAnalCodeList[m_iCount-1].m_iProCode;
}
//#######################################################################
void FlowAnal::getFinalCode(u_int64_t *p_iSigSCode, u_int32_t *p_iSCode, u_int64_t *p_iSigACode, u_int32_t *p_iACode, u_int64_t *p_iSigPCode, u_int32_t *p_iPCode, u_int64_t *p_iSigFCode, u_int32_t *p_iFCode, u_int64_t *p_iSigProCode, u_int32_t *p_iProCode)
{
	int iIndex;

	int iSLevel=0;
	int iALevel=0;
	int iPLevel=0;
	int iFLevel=0;

	int iStored_SLevel=0;
	int iStored_ALevel=0;
	int iStored_PLevel=0;
	int iStored_FLevel=0;

	*p_iSigSCode	= 0;
	*p_iSCode		= 0;
	*p_iSigACode	= 0;
	*p_iACode		= 0;
	*p_iSigPCode	= 0;
	*p_iPCode		= 0;
	*p_iSigFCode	= 0;
	*p_iFCode		= 0;
	*p_iSigProCode	= 0;
	*p_iProCode		= 0;

	for (iIndex=0;iIndex < m_iCount ; iIndex++)
	{
		//service level 설정
		if (m_caAnalCodeList[iIndex].m_iSCode % 100)
		{
			iSLevel=3;
		}
		else if (m_caAnalCodeList[iIndex].m_iSCode % 10000)
		{
			iSLevel=2;
		}
		else if (m_caAnalCodeList[iIndex].m_iSCode)
		{
			iSLevel=1;
		}
		else
		{
			iSLevel=0;
		}

		//application level 설정
		if (m_caAnalCodeList[iIndex].m_iACode % 10000)
		{
			iALevel=2;
		}
		else if (m_caAnalCodeList[iIndex].m_iACode)
		{
			iALevel=1;
		}
		else
		{
			iALevel=0;
		}

		//protocol level 설정
		if (m_caAnalCodeList[iIndex].m_iPCode % 100)
		{
			iPLevel=2;
		}
		else if (m_caAnalCodeList[iIndex].m_iPCode)
		{
			iPLevel=1;
		}
		else
		{
			iPLevel=0;
		}
		
		//function level 설정
		if (m_caAnalCodeList[iIndex].m_iFCode)
		{
			iFLevel=1;
		}
		else
		{
			iFLevel=0;
		}
			
		//service 결정
		if (iStored_SLevel == 0)
		{
			*p_iSigSCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iSCode = m_caAnalCodeList[iIndex].m_iSCode;
			iStored_SLevel = iSLevel;
		}
		else if (iStored_SLevel < iSLevel)
		{
			*p_iSigSCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iSCode = m_caAnalCodeList[iIndex].m_iSCode;
			iStored_SLevel = iSLevel;
		}

		//application 결정
		if (iStored_ALevel == 0)
		{
			*p_iSigACode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iACode = m_caAnalCodeList[iIndex].m_iACode;
			iStored_ALevel = iALevel;
		}
		else if (iStored_ALevel < iALevel)
		{
			*p_iSigACode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iACode = m_caAnalCodeList[iIndex].m_iACode;
			iStored_ALevel = iALevel;
		}

		//protocol 결정
		if (iStored_PLevel == 0)
		{
			*p_iSigPCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iPCode = m_caAnalCodeList[iIndex].m_iPCode;
			iStored_PLevel = iPLevel;
		}
		else if (iStored_PLevel < iPLevel)
		{
			*p_iSigPCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iPCode = m_caAnalCodeList[iIndex].m_iPCode;
			iStored_PLevel = iPLevel;
		}

		//function 결정
		if (iStored_FLevel == 0)
		{
			*p_iSigFCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iFCode = m_caAnalCodeList[iIndex].m_iFCode;
			iStored_FLevel = iFLevel;
		}
		else if (iStored_FLevel < iFLevel)
		{
			*p_iSigFCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iFCode = m_caAnalCodeList[iIndex].m_iFCode;
			iStored_FLevel = iFLevel;
		}
		//process 결정
		if (*p_iProCode == 0)
		{
			*p_iSigProCode = m_caAnalCodeList[iIndex].m_iSigCode;
			*p_iProCode = m_caAnalCodeList[iIndex].m_iProCode;
		}
	}

}
//#######################################################################
void FlowTwowayContainer::set(PacketContainer* r)
{
	//FlowBasic setting
	flow.srcaddr = r->pkt.src_addr;
	flow.dstaddr = r->pkt.dst_addr;
	flow.srcport = r->pkt.src_port;
	flow.dstport = r->pkt.dst_port;
	flow.prot = r->pkt.ip_proto;
	
	//FlowStat setting (forward)  첫패킷으로 방향을 결정하므로 첫 pkt는 무조건 forward임
	flow.flag |= 0x10;
	
}
//#######################################################################
void FlowTwowayContainer::update(PacketContainer *r)
{
	FlowStat *stat = NULL;

	if ( isForwardDirection(&r->pkt) )
	{
		stat = &forward;
		flow.flag |= 0x10;
	}

	else
	{
		stat = &backward;
		flow.flag |= 0x20;
	}

	// update start & end time values
	//=============================================================
	if ( stat->dOctets == 0 )  // first packet of this direction
	{
		copyTimeval(&stat->start, r->pkt.time_sec, r->pkt.time_usec);
		copyTimeval(&stat->end, r->pkt.time_sec, r->pkt.time_usec);
	}
	else
	{
		if ( timeCompare(&stat->start, r->pkt.time_sec, r->pkt.time_usec) > 0 )
			copyTimeval(&stat->start, r->pkt.time_sec, r->pkt.time_usec);
		else if ( timeCompare(&stat->end, r->pkt.time_sec, r->pkt.time_usec) < 0 )
			copyTimeval(&stat->end, r->pkt.time_sec, r->pkt.time_usec);
	}
	//=============================================================

	// update pkt count & byte count
	//=============================================================
	stat->dPkts		+= 1;
	stat->dOctets	+= r->pkt.real_pkt_len;
	//=============================================================

	// update TCP flag count
	//=============================================================
	if ( (r->pkt.tcp_flags & TCP_FLAG_SYN) && (stat->syn < 0xFF) )   stat->syn++ ;
	if ( (r->pkt.tcp_flags & TCP_FLAG_RST) && (stat->rst < 0xFF) )   stat->rst++ ;
	if ( (r->pkt.tcp_flags & TCP_FLAG_FIN) && (stat->fin < 0xFF) )   stat->fin++ ;			
	if ( (r->pkt.tcp_flags & TCP_FLAG_ACK) && (stat->ack < 0xFF) )   stat->ack++ ;
	if ( (r->pkt.tcp_flags & TCP_FLAG_PSH) && (stat->psh < 0xFF) )   stat->psh++ ;
	if ( (r->pkt.tcp_flags & TCP_FLAG_URG) && (stat->payload < 0xFF) )   stat->payload++ ;
	//=============================================================

	if ( r->pkt.real_payload_len )		stat->flag |= 0x01;			// payload data exist

	// update server address
	//=============================================================
	if ( r->pkt.tcp_flags == 0x02 )	// SYN PKT
	{
		if ( stat == &forward )	flow.flag |= 0x01;	// server port is destination port			
		else flow.flag |= 0x02;	// server port is client port
	}
	else if ( r->pkt.tcp_flags == 0x12 ) // SYN-ACK PKT
	{
		if ( stat == &forward ) flow.flag |= 0x02;	// server port is client port			
		else flow.flag |= 0x01;	// server port is destination port
	}
	//=============================================================
}
//######################################################################
int FlowTwowayContainer::isForwardDirection(Packet *r)
{
	if( r->src_addr		!= flow.srcaddr )	return 0;
	if( r->dst_addr		!= flow.dstaddr )	return 0;
	if( r->src_port		!= flow.srcport )	return 0;
	if( r->dst_port		!= flow.dstport )	return 0;
	if( r->ip_proto		!= flow.prot    )	return 0;

	return 1;
}


//######################################################################
void FlowTwowayContainer::copyTimeval(struct timeval *dst, unsigned int src_sec, unsigned int src_usec)
{
	dst->tv_sec = src_sec;
	dst->tv_usec = src_usec;
}


//######################################################################
int FlowTwowayContainer::timeCompare(struct timeval *a, unsigned int b_sec, unsigned int b_usec)
{
	// return negative --> a < b
	// return positive --> a > b
	// retrun zero     --> a == b
	int ret = a->tv_sec - b_sec;

	if ( ret != 0 )	return ret;
	
	return a->tv_usec - b_usec;
}

//#######################################################################
void FlowTwowayContainer::setCode(u_int64_t p_iSigCode, u_int32_t p_iSCode, u_int32_t p_iACode, u_int32_t p_iPCode, u_int32_t p_iFCode, u_int32_t p_iProCode)
{
	code.setCode(p_iSigCode, p_iSCode, p_iACode, p_iPCode, p_iFCode, p_iProCode);
	flow.flag |= ANAL;
}
//#######################################################################
void FlowTwowayContainer::setAnswerProCode(u_int32_t p_iAnswerProCode)
{
	code.setAnswer(p_iAnswerProCode);
	flow.flag |= ANAL;
}
//#######################################################################
void FlowTwowayContainer::print( )
{
	int count=0;
	printf("\n\n");

	printf("file: %3d	flow: %3d	",m_iFileID, m_iFlowID);


	flow.print();
	
	if(flow.flag & FORWARD)
	{
		printf("                                                               > ");
		forward.print();
	}
	if(flow.flag & BACKWARD) 
	{
		printf("                                                               < "); 
		backward.print();
	}
	if(flow.flag & ANAL)
	{
		code.print();
		if (code.m_iFlag & ANSWER_EXIST)
			printf("%d\n",code.m_iAnswerProCode);
	}
	if(flow.flag & WITH_PKT) 
	{
		printf("                                                               stored pkt : [forward=%2d] [backward=%2d]\n",
			withpkt.f_stored_pkt, withpkt.b_stored_pkt);
		
		PacketContainer *go;
		for (go=headPkt;go!=NULL ;go=go->next )
		{
			count++;
			printf("         ");
			go->pkt.print();
			printf("         ");
			go->printPayload(1200);
			
		}
	}
	//getchar();
}
//#######################################################################
void FlowTwowayContainer::print(FILE *fp )
{
	fprintf(fp,"\n\n");

	fprintf(fp, "%3d	",m_iFileID);

	flow.print(fp);
	
	if(flow.flag & FORWARD)
	{
		fprintf(fp,"                                                               > ");
		forward.print(fp);
	}
	if(flow.flag & BACKWARD) 
	{
		fprintf(fp,"                                                               < "); 
		backward.print(fp);
	}
	if(flow.flag & ANAL)
	{
		code.print(fp);
		if (code.m_iFlag & ANSWER_EXIST)
			fprintf(fp,"%d\n",code.m_iAnswerProCode);
	}
	if(flow.flag & WITH_PKT) 
	{
		fprintf(fp,"                                                               stored pkt : [forward=%2d] [backward=%2d]\n",
			withpkt.f_stored_pkt, withpkt.b_stored_pkt);
		
		PacketContainer *go;
		for (go=headPkt;go!=NULL ;go=go->next )
		{
			fprintf(fp,"         ");
			go->pkt.print(fp);
			fprintf(fp,"         ");
			go->printPayload(fp);
			
		}
		
		
	}


	//getchar();
}

