#include "include.h"
#include "util.h"
#include "flowHash.h"



//#############################################################################################
FlowHash::FlowHash(void)
{
	m_cpFlowTwowayContainerHT = new FlowTwowayContainer[MAXHASH];
	memset(m_cpFlowTwowayContainerHT, 0, sizeof(FlowTwowayContainer) * MAXHASH );

	m_cFPBToTal.reset();
	m_cFPBIdentified.reset();

	m_iFlowIndex=0;

	m_cFlowTwoWayContainerList.clear();
	m_cPacketContainerList.clear();
}
//#############################################################################################
FlowHash::~FlowHash(void)
{
}
//######################################################################
void FlowHash::reset()
{
	FlowTwowayContainer *go, *head;
	int iIndex;
	PacketContainer *pktC;

	u_int64_t	flow_count = 0;
	u_int64_t	pkt_count = 0;
	

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		while(head->next)
		{
			go = head->next;
			head->next = go->next;

			while ( go->headPkt )
			{
				pktC = go->headPkt;
				go->headPkt = pktC->next;
				delete pktC;
				pktC = NULL;
				pkt_count++;
			}

			delete go;
			go = NULL;
			flow_count++;
		}
	}
	memset(m_cpFlowTwowayContainerHT, 0, sizeof(FlowTwowayContainer) * MAXHASH );

	m_cFPBToTal.reset();
	m_cFPBIdentified.reset();

	m_iFlowIndex=0;

	m_cFlowTwoWayContainerList.clear();
	m_cPacketContainerList.clear();
}
//######################################################################
void FlowHash::resetAnal()
{
	int iIndex;
	FlowTwowayContainer *go, *head;

	for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for ( go = head->next;  go != NULL;  go = go->next )
		{

			if (go->flow.flag & ANAL)
			{
				go->flow.flag^=ANAL;			//ANAL flag unset
				go->code.reset();
			}
		}
	}
	recal();
}
//######################################################################
void FlowHash::recal()
{
	m_cFPBToTal.reset();
	m_cFPBIdentified.reset();

	int iIndex;
	FlowTwowayContainer *go, *head;

	for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for ( go = head->next;  go != NULL;  go = go->next )
		{
			m_cFPBToTal.setFlow(m_cFPBToTal.getFlow() + 1);
			m_cFPBToTal.setPkt(m_cFPBToTal.getPkt() + go->forward.dPkts + go->backward.dPkts);
			m_cFPBToTal.setByte(m_cFPBToTal.getByte() +	go->forward.dOctets + go->backward.dOctets);

			if (go->flow.flag & ANAL)
			{
				m_cFPBIdentified.setFlow(m_cFPBIdentified.getFlow() + 1);
				m_cFPBIdentified.setPkt(m_cFPBIdentified.getPkt() + go->forward.dPkts + go->backward.dPkts);
				m_cFPBIdentified.setByte(m_cFPBIdentified.getByte() +	go->forward.dOctets + go->backward.dOctets);
			}
		}
	}
}
//######################################################################
void FlowHash::print()
{
	recal();

	m_cFPBToTal.print();
	m_cFPBIdentified.print();

	printf("%10.02f(%llu/%llu)	%10.02f(%llu/%llu)	%10.02f(%llu/%llu)\n",
		(float)m_cFPBIdentified.getFlow()*100/m_cFPBToTal.getFlow(),m_cFPBIdentified.getFlow(),m_cFPBToTal.getFlow(),
		(float)m_cFPBIdentified.getPkt()*100/m_cFPBToTal.getPkt(),m_cFPBIdentified.getPkt(),m_cFPBToTal.getPkt(),
		(float)m_cFPBIdentified.getByte()*100/m_cFPBToTal.getByte(),m_cFPBIdentified.getByte(),m_cFPBToTal.getByte());
	
}
//######################################################################
void FlowHash::printDetail()
{
	int iIndex;
	FlowTwowayContainer *go, *head;

	for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for ( go = head->next;  go != NULL;  go = go->next )
		{
			go->print();
		}
	}
}
//######################################################################
void FlowHash::print(char *p_caLogFileName)
{
	FILE					*fp_log;

	recal();

	if ( (fp_log = fopen(p_caLogFileName, "at")) != NULL )
	{
		m_cFPBToTal.print(fp_log);
		m_cFPBIdentified.print(fp_log);
		fprintf(fp_log,"%10.02f	%10.02f	%10.02f\r\n\r\n\r\n",
			(float)m_cFPBIdentified.getFlow()*100/m_cFPBToTal.getFlow(),
			(float)m_cFPBIdentified.getPkt()*100/m_cFPBToTal.getPkt(),
			(float)m_cFPBIdentified.getByte()*100/m_cFPBToTal.getByte());

		fclose(fp_log);
	}
	else
		g_err((char*)"FlowHash::print():fopen error");


	
}
//######################################################################
void FlowHash::printDetail(char *p_caLogFileName)
{
	int iIndex;
	FlowTwowayContainer *go, *head;
	FILE					*fp_log;

	if ( (fp_log = fopen(p_caLogFileName, "at")) != NULL )
	{
		for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
		{
			head = &m_cpFlowTwowayContainerHT[iIndex];
			for ( go = head->next;  go != NULL;  go = go->next )
			{
				go->print(fp_log);
			}
		}

		fclose(fp_log);
	}
	else
		g_err((char*)"FlowHash::printDetail():fopen error");
}




//######################################################################
void FlowHash::resetFlowListSortByTime()
{
	FlowTwowayContainer *go, *head;
	int iIndex;

	m_cFlowTwoWayContainerList.clear();

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for (go=head->next;go ;go=go->next )
		{
			//go->print();
			m_cFlowTwoWayContainerList.push_back(go);
		}
	}
	//sort
	m_cFlowTwoWayContainerList.sort(Compare());
}
//######################################################################
void FlowHash::resetPktListSortByTime()
{
	FlowTwowayContainer *go, *head;
	PacketContainer *goPkt;
	int iIndex;

	m_cPacketContainerList.clear();

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for (go=head->next;go ;go=go->next )
		{
			//go->print();

			for (goPkt=go->headPkt;goPkt!=NULL ;goPkt=goPkt->next )
			{
				m_cPacketContainerList.push_back(goPkt);
			}
		}
	}
	//sort
	m_cPacketContainerList.sort(ComparePkt());
}
//######################################################################
void FlowHash::printFlowList()
{
	list<FlowTwowayContainer*>::iterator it;
	for (it = m_cFlowTwoWayContainerList.begin();it!=m_cFlowTwoWayContainerList.end() ;it++ )
	{
		(*it)->print();
	}
}
//######################################################################
void FlowHash::printFlowList(char *p_caLogFileName)
{
	FILE					*fp_log;

	list<FlowTwowayContainer*>::iterator it;

	if ( (fp_log = fopen(p_caLogFileName, "wt")) != NULL )
	{
		for (it = m_cFlowTwoWayContainerList.begin();it!=m_cFlowTwoWayContainerList.end() ;it++ )
		{
			(*it)->print(fp_log);
		}
		fclose(fp_log);
	}
	else
		g_err((char*)"FlowHash::printFlowList():fopen error");
}
//######################################################################
void FlowHash::printPktList()
{
	list<PacketContainer*>::iterator it;
	for (it = m_cPacketContainerList.begin();it!=m_cPacketContainerList.end() ;it++ )
	{
		(*it)->pkt.print();
		(*it)->printPayload(100);
	}
}
//######################################################################
void FlowHash::printPktList(char *p_caLogFileName)
{
	FILE					*fp_log;

	list<PacketContainer*>::iterator it;

	if ( (fp_log = fopen(p_caLogFileName, "wt")) != NULL )
	{
		for (it = m_cPacketContainerList.begin();it!=m_cPacketContainerList.end() ;it++ )
		{
			(*it)->pkt.print(fp_log);
			(*it)->printPayload(100,fp_log);
		}
		fclose(fp_log);
	}
	else
		g_err((char*)"FlowHash::printPktList():fopen error");
}

//######################################################################
void FlowHash::insert(PacketContainer *r)
{
	unsigned int key;
	FlowTwowayContainer *go, *head;

	key = hashing(&r->pkt);
	head = &m_cpFlowTwowayContainerHT[key];
	for ( go = head->next;
		  go && !isSameRecord(&r->pkt, &go->flow) && !isSameRecordReverse(&r->pkt, &go->flow);
		  go = go->next );
	
	if (go == NULL)		//flow의 첫 pkt이 입력된 경우
	{
		go = new FlowTwowayContainer();
		go->set(r);						//FlowBasic만 설정	

		go->next = head->next;
		head->next = go;

		m_cFPBToTal.setFlow(m_cFPBToTal.getFlow() + 1);
	}
	
	go->update(r);						//FlowStat 정보 업데이트

	m_cFPBToTal.setPkt(m_cFPBToTal.getPkt() + 1);
	m_cFPBToTal.setByte(m_cFPBToTal.getByte() + r->pkt.real_pkt_len);
	
	if (r->pkt.real_payload_len)
	{
		if ( go->withpkt.f_stored_pkt >= MAX_STORE_PKT )	return;
		if ( go->withpkt.b_stored_pkt >= MAX_STORE_PKT )	return;

		if ( isSameRecord(&r->pkt, &go->flow) )			
			go->withpkt.f_stored_pkt++;
		else
			go->withpkt.b_stored_pkt++;

		this->insertForFlowWithPkt(r, go); // 이부분에서 FlowContainer 안에 PacketContainer 링크드 리스트로 추가됨.
	}
}
//######################################################################
void FlowHash::deleteNonData()
{
	FlowTwowayContainer *go, *pre, *head;
	int iIndex;
	PacketContainer *pktC;

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		go=head->next;
		while(go)
		{
			if ((go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt) == 0)
			{
				if (go==head->next)	//첫 엔트리
				{
					head->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=head->next;
				}
				else
				{
					pre->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=pre->next;
				}
			}
			else
			{
				pre=go;
				go=go->next;
			}
		}
	}
}
//######################################################################
void FlowHash::deleteSynAckRst()
{
	FlowTwowayContainer *go, *pre, *head;
	int iIndex;
	PacketContainer *pktC;

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		go=head->next;
		while(go)
		{
			if (go->forward.syn && (go->forward.syn == go->backward.ack) && (go->forward.syn == go->backward.rst))
			{
				if (go==head->next)	//첫 엔트리
				{
					head->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=head->next;
				}
				else
				{
					pre->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=pre->next;
				}
			}
			else
			{
				pre=go;
				go=go->next;
			}
		}
	}
}
//######################################################################
void FlowHash::deleteTcpOneWay()
{
	FlowTwowayContainer *go, *pre, *head;
	int iIndex;
	PacketContainer *pktC;

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		go=head->next;
		while(go)
		{
			if ((go->flow.prot == 6 ) && !(go->flow.flag & BACKWARD))
			{
				if (go==head->next)	//첫 엔트리
				{
					head->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=head->next;
				}
				else
				{
					pre->next = go->next;

					while ( go->headPkt )
					{
						pktC = go->headPkt;
						go->headPkt = pktC->next;
						delete pktC;
						pktC = NULL;
					}
					delete go;
					go=pre->next;
				}
			}
			else
			{
				pre=go;
				go=go->next;
			}
		}
	}
}
//######################################################################
void FlowHash::deleteRetransmission()
{
	FlowTwowayContainer *go, *pre, *head;
	int iIndex;
	PacketContainer *pktC, *pre_pktC;;
	int				iCount=0;
	u_int32_t		tcp_sn=0;
	u_int32_t		time_sec=0;
	u_int16_t		real_payload_len=0;

	for(iIndex=0; iIndex<MAXHASH; iIndex++)
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		go=head->next;

		while(go)
		{
			iCount=0; tcp_sn=0; time_sec=0; real_payload_len=0;

			for (pktC = go->headPkt ; pktC ; pktC=pktC->next )
			{
				iCount++;
				if (iCount == 1)		// 첫 pkt
				{
					time_sec = pktC->pkt.time_sec;
					tcp_sn = pktC->pkt.tcp_sn;
					real_payload_len = pktC->pkt.real_payload_len;
				}
				else
				{
					if ((pktC->pkt.ip_proto == 6)&&(abs(pktC->pkt.time_sec - time_sec)<2) && (pktC->pkt.tcp_sn == tcp_sn) && (real_payload_len))
					{
						pre_pktC->next = pktC->next;
						m_cFPBToTal.setPkt(m_cFPBToTal.getPkt() - 1);
						m_cFPBToTal.setByte(m_cFPBToTal.getByte() -pktC->pkt.real_pkt_len);
						if (isSameRecord(&pktC->pkt, &go->flow))
						{
							go->withpkt.f_stored_pkt--;
							go->forward.dPkts--;
						}
						else
						{
							go->withpkt.b_stored_pkt--;
							go->backward.dPkts--;
						}
						delete pktC;
						pktC = pre_pktC;
					}
					time_sec = pktC->pkt.time_sec;
					tcp_sn = pktC->pkt.tcp_sn;
					real_payload_len = pktC->pkt.real_payload_len;
				}
				pre_pktC=pktC;
			}
			go=go->next;
		}
	}
}

//######################################################################
void FlowHash::store(char *p_caFlowFileName)
{
	if (m_cFPBToTal.getFlow() == 0) return;

	FILE *fp;
	int flow_count, pkt_count, i, stored_pkt;
	PacketContainer *pktC;
	FlowTwowayContainer *go, *head;
	int basic_len   = sizeof(FlowBasic);
	int stat_len    = sizeof(FlowStat);
	int anal_len    = sizeof(FlowAnal);
	int withpkt_len = sizeof(FlowWithPkt);
	int pktInfoLen  = sizeof(PacketStoredInfo);
	int len;

	flow_count = pkt_count = 0;

	if ( (fp = fopen(p_caFlowFileName, "wb")) != NULL )	
	{
		for ( i = 0;  i < MAXHASH;  i++ )
		{
			head = &m_cpFlowTwowayContainerHT[i];
			for ( go = head->next;  go;  go = go->next )
			{
			//	go->print();

				flow_count++;

				len = fwrite(&go->flow, 1, basic_len, fp);
				if ( len != basic_len )	g_err((char*)"FlowHash::store():fwrite basic");

				if ( go->flow.flag & 0x10 ) {
					len = fwrite(&go->forward, 1, stat_len, fp);
					if ( len != stat_len )	g_err((char*)"FlowHash::store():fwrite forward stat");
				}

				if ( go->flow.flag & 0x20 ) {
					len = fwrite(&go->backward, 1, stat_len, fp);
					if ( len != stat_len )	g_err((char*)"FlowHash::store():fwrite backward stat");
				}

				if ( go->flow.flag & 0x40 ) {
					len = fwrite(&go->code, 1, anal_len, fp);
					if ( len != anal_len )	g_err((char*)"FlowHash::store():fwrite anal");
				}

				if ( go->flow.flag & 0x80 ) {
					len = fwrite(&go->withpkt, 1, withpkt_len, fp);
					if ( len != withpkt_len )	g_err((char*)"FlowHash::store():fwrite withpkt");
				}
				
				//go->print();
				
				stored_pkt = 0;
				for ( pktC = go->headPkt;  pktC;  pktC = pktC->next )
				{
					pkt_count++;
					stored_pkt++;

					len = fwrite(&pktC->pktInfo, 1, pktInfoLen, fp);
					if ( len != pktInfoLen )	g_err((char*)"FlowHash::store():fwrite pktInfo");

					len = fwrite(pktC->payload, 1, pktC->pkt.stored_pkt_len, fp);
					if ( len != pktC->pkt.stored_pkt_len )	g_err((char*)"FlowHash::store():fwrite payload");
				}

				//stat과 withpkt 의 pkt 개수 확인
			/*	if ( go->forward.dPkts + go->backward.dPkts != go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt )
				{
					go->print();

					printf("stat : %d	%d	withpkt : %d	%d\n",go->forward.dPkts, go->backward.dPkts, go->withpkt.f_stored_pkt, go->withpkt.b_stored_pkt);
					g_err((char*)"FlowHash::store():stored pkt is not same (stat, withpkt");
				}
				*/

				//실제 저장된 pkt 개수 확인
				if ( stored_pkt != go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt )
				{
					go->print();

					printf("%d	%d	%d\n",stored_pkt, go->withpkt.f_stored_pkt, go->withpkt.b_stored_pkt);
					g_err((char*)"FlowHash::store():stored pkt is not same");
				}
			}
		}
		fclose(fp);
	}
	else
		g_err((char*)"FlowHash::store():fopen output");

	/*
	if (m_cFPBToTal.flow != flow_count || m_cFPBToTal.pkt != pkt_count)
	{
		printf("m_cFPBToTal.flow : %llu	flow_count : %d	m_cFPBToTal.pkt : %llu	pkt_count : %d\n",
			m_cFPBToTal.flow, flow_count, m_cFPBToTal.pkt, pkt_count);
		g_err((char*)"FlowHash::store():stored flow and pkt is not same");
	}
	*/
}
//######################################################################
void FlowHash::storeToTargetPathEachFlow(char *p_caResultFlowFilePathName)
{
	FlowTwowayContainer *go, *head;
	PacketContainer *pktC;
	int flow_count, pkt_count, i, stored_pkt;
	char				srcIP[30];
	char				dstIP[30];
	u_int16_t			srcPort;
	u_int16_t			dstPort;
	char				caTargetFileName[1024];
	FILE *fp;
	int len;
	int basic_len   = sizeof(FlowBasic);
	int stat_len    = sizeof(FlowStat);
	int anal_len    = sizeof(FlowAnal);
	int withpkt_len = sizeof(FlowWithPkt);
	int pktInfoLen  = sizeof(PacketStoredInfo);


	for ( i = 0;  i < MAXHASH;  i++ )
	{
		head = &m_cpFlowTwowayContainerHT[i];
		for ( go = head->next;  go;  go = go->next )
		{
			if (go->flow.srcaddr < go->flow.dstaddr)
			{
				g_convertAddrToString(srcIP, go->flow.srcaddr);
				g_convertAddrToString(dstIP, go->flow.dstaddr);
				srcPort = go->flow.srcport;
				dstPort = go->flow.dstport;
			}
			else
			{
				g_convertAddrToString(srcIP, go->flow.dstaddr);
				g_convertAddrToString(dstIP, go->flow.srcaddr);
				srcPort = go->flow.dstport;
				dstPort = go->flow.srcport;
			}
			sprintf(caTargetFileName,"%s%s-%d-%s",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP);
			mkdir(caTargetFileName, 0777);
			sprintf(caTargetFileName,"%s%s-%d-%s/%s_%d-%d-%s_%d.fwp",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP, 
				srcIP, srcPort, go->flow.prot, dstIP, dstPort);
			//puts(caTargetFileName);

			if ( (fp = fopen(caTargetFileName, "wb")) == NULL )	g_err((char*)"fopen output");

			len = fwrite(&go->flow, 1, basic_len, fp);
			if ( len != basic_len )	g_err((char*)"fwrite basic");

			if ( go->flow.flag & 0x10 ) {
				len = fwrite(&go->forward, 1, stat_len, fp);
				if ( len != stat_len )	g_err((char*)"fwrite forward stat");
			}

			if ( go->flow.flag & 0x20 ) {
				len = fwrite(&go->backward, 1, stat_len, fp);
				if ( len != stat_len )	g_err((char*)"fwrite backward stat");
			}

			if ( go->flow.flag & 0x40 ) {
				len = fwrite(&go->code, 1, anal_len, fp);
				if ( len != anal_len )	g_err((char*)"fwrite anal");
			}

			if ( go->flow.flag & 0x80 ) {
				len = fwrite(&go->withpkt, 1, withpkt_len, fp);
				if ( len != withpkt_len )	g_err((char*)"fwrite withpkt");
			}
			
			//go->print();
			
			stored_pkt = 0;
			for ( pktC = go->headPkt;  pktC;  pktC = pktC->next )
			{
				pkt_count++;
				stored_pkt++;

				len = fwrite(&pktC->pktInfo, 1, pktInfoLen, fp);
				if ( len != pktInfoLen )	g_err((char*)"fwrite pktInfo");

				len = fwrite(pktC->payload, 1, pktC->pkt.stored_pkt_len, fp);
				if ( len != pktC->pkt.stored_pkt_len )	g_err((char*)"fwrite payload");
			}

			if ( stored_pkt != go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt )
			{
				go->print();
				printf("%d	%d	%d\n",stored_pkt, go->withpkt.f_stored_pkt, go->withpkt.b_stored_pkt);
				g_err((char*)"stored pkt is not same");
			}

			fclose(fp);
		}
	}
}//######################################################################
void FlowHash::storeToTargetPathUDPFlow(char *p_caResultFlowFilePathName)
{
	FlowTwowayContainer *pre, *go, *head;
	PacketContainer *pktC;
	int flow_count, pkt_count, i, stored_pkt;
	char				srcIP[30];
	char				dstIP[30];
	u_int16_t			srcPort;
	u_int16_t			dstPort;
	char				caTargetFileName[1024];
	FILE *fp;
	int len;
	int basic_len   = sizeof(FlowBasic);
	int stat_len    = sizeof(FlowStat);
	int anal_len    = sizeof(FlowAnal);
	int withpkt_len = sizeof(FlowWithPkt);
	int pktInfoLen  = sizeof(PacketStoredInfo);


	for ( i = 0;  i < MAXHASH;  i++ )
	{
		head = &m_cpFlowTwowayContainerHT[i];
		for (pre=head, go = head->next;  go;  pre=go, go = go->next )
		{
			if (go->flow.prot != 6)
			{
				if (go->flow.srcaddr < go->flow.dstaddr)
				{
					g_convertAddrToString(srcIP, go->flow.srcaddr);
					g_convertAddrToString(dstIP, go->flow.dstaddr);
					srcPort = go->flow.srcport;
					dstPort = go->flow.dstport;
				}
				else
				{
					g_convertAddrToString(srcIP, go->flow.dstaddr);
					g_convertAddrToString(dstIP, go->flow.srcaddr);
					srcPort = go->flow.dstport;
					dstPort = go->flow.srcport;
				}
				sprintf(caTargetFileName,"%s%s-%d-%s",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP);
				mkdir(caTargetFileName, 0777);
				sprintf(caTargetFileName,"%s%s-%d-%s/%s_%d-%d-%s_%d.fwp",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP, 
					srcIP, srcPort, go->flow.prot, dstIP, dstPort);
				//puts(caTargetFileName);

				if ( (fp = fopen(caTargetFileName, "wb")) == NULL )	g_err((char*)"fopen output");

				len = fwrite(&go->flow, 1, basic_len, fp);
				if ( len != basic_len )	g_err((char*)"fwrite basic");

				if ( go->flow.flag & 0x10 ) {
					len = fwrite(&go->forward, 1, stat_len, fp);
					if ( len != stat_len )	g_err((char*)"fwrite forward stat");
				}

				if ( go->flow.flag & 0x20 ) {
					len = fwrite(&go->backward, 1, stat_len, fp);
					if ( len != stat_len )	g_err((char*)"fwrite backward stat");
				}

				if ( go->flow.flag & 0x40 ) {
					len = fwrite(&go->code, 1, anal_len, fp);
					if ( len != anal_len )	g_err((char*)"fwrite anal");
				}

				if ( go->flow.flag & 0x80 ) {
					len = fwrite(&go->withpkt, 1, withpkt_len, fp);
					if ( len != withpkt_len )	g_err((char*)"fwrite withpkt");
				}
				
				//go->print();
				
				stored_pkt = 0;
				for ( pktC = go->headPkt;  pktC;  pktC = pktC->next )
				{
					pkt_count++;
					stored_pkt++;

					len = fwrite(&pktC->pktInfo, 1, pktInfoLen, fp);
					if ( len != pktInfoLen )	g_err((char*)"fwrite pktInfo");

					len = fwrite(pktC->payload, 1, pktC->pkt.stored_pkt_len, fp);
					if ( len != pktC->pkt.stored_pkt_len )	g_err((char*)"fwrite payload");
				}

				if ( stored_pkt != go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt )
				{
					go->print();
					printf("%d	%d	%d\n",stored_pkt, go->withpkt.f_stored_pkt, go->withpkt.b_stored_pkt);
					g_err((char*)"stored pkt is not same");
				}

				fclose(fp);
				
				pre->next = go->next;
				delete go;
				go = pre;
			}
		}
	}
}
//######################################################################
void FlowHash::store(char *p_caResultFlowFilePathName, char *p_caResultFlowFileName)
{
	PacketContainer *pktC;
	FlowTwowayContainer *go, *head;
	int basic_len   = sizeof(FlowBasic);
	int stat_len    = sizeof(FlowStat);
	int anal_len    = sizeof(FlowAnal);
	int withpkt_len = sizeof(FlowWithPkt);
	int pktInfoLen  = sizeof(PacketStoredInfo);
	int len;

	char				caTargetFileName[1024];
	char				srcIP[30];
	char				dstIP[30];

	FILE *fp;
	int flow_count, pkt_count, i, stored_pkt;

	

	flow_count = pkt_count = 0;
	for ( i = 0;  i < MAXHASH;  i++ )
	{
		head = &m_cpFlowTwowayContainerHT[i];
		for ( go = head->next;  go;  go = go->next )
		{
		//	go->print();
			if (go->flow.srcaddr < go->flow.dstaddr)
			{
				g_convertAddrToString(srcIP, go->flow.srcaddr);
				g_convertAddrToString(dstIP, go->flow.dstaddr);
			}
			else
			{
				g_convertAddrToString(srcIP, go->flow.dstaddr);
				g_convertAddrToString(dstIP, go->flow.srcaddr);
			}

			sprintf(caTargetFileName,"%s%s-%d-%s",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP);
			mkdir(caTargetFileName, 0777);
			sprintf(caTargetFileName,"%s%s-%d-%s/%s",p_caResultFlowFilePathName,srcIP, go->flow.prot, dstIP, p_caResultFlowFileName);
		//	puts(caTargetFileName);
		//	go->print();
		//	getchar();

			if ( (fp = fopen(caTargetFileName, "wb")) == NULL )	g_err((char*)"fopen output");

			flow_count++;

			len = fwrite(&go->flow, 1, basic_len, fp);
			if ( len != basic_len )	g_err((char*)"fwrite basic");

			if ( go->flow.flag & 0x10 ) {
				len = fwrite(&go->forward, 1, stat_len, fp);
				if ( len != stat_len )	g_err((char*)"fwrite forward stat");
			}

			if ( go->flow.flag & 0x20 ) {
				len = fwrite(&go->backward, 1, stat_len, fp);
				if ( len != stat_len )	g_err((char*)"fwrite backward stat");
			}

			if ( go->flow.flag & 0x40 ) {
				len = fwrite(&go->code, 1, anal_len, fp);
				if ( len != anal_len )	g_err((char*)"fwrite anal");
			}

			if ( go->flow.flag & 0x80 ) {
				len = fwrite(&go->withpkt, 1, withpkt_len, fp);
				if ( len != withpkt_len )	g_err((char*)"fwrite withpkt");
			}
			
			//go->print();
			
			stored_pkt = 0;
			for ( pktC = go->headPkt;  pktC;  pktC = pktC->next )
			{
				pkt_count++;
				stored_pkt++;

				len = fwrite(&pktC->pktInfo, 1, pktInfoLen, fp);
				if ( len != pktInfoLen )	g_err((char*)"fwrite pktInfo");

				len = fwrite(pktC->payload, 1, pktC->pkt.stored_pkt_len, fp);
				if ( len != pktC->pkt.stored_pkt_len )	g_err((char*)"fwrite payload");
			}

			if ( stored_pkt != go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt )
			{
				go->print();

				printf("%d	%d	%d\n",stored_pkt, go->withpkt.f_stored_pkt, go->withpkt.b_stored_pkt);
				g_err((char*)"stored pkt is not same");
			}

			fclose(fp);
		}
	}

	

	printf("storeTwowayFlowPktData() Summary [Total Flow:%6d] [Total Packet:%6d] \n", flow_count, pkt_count);

}

//######################################################################
int FlowHash::loadPktToFlowWithPkt(char *p_caFlowFileName)
{
	PacketContainer cPacketContainer;
	FILE *fp;
	int len;

	if ( (fp = fopen(p_caFlowFileName, "rb")) != NULL )
	{
		while ( len = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp) )
		{
			if ( len != sizeof(PacketStoredInfo) )	g_err((char*)"FlowHash::loadPktToFlowWithPkt() : file open error pktInfo");

			memset(cPacketContainer.payload, 0, MAX_PACKET_DATA);
			len = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp);
			if ( len != cPacketContainer.pktInfo.stored_len )	g_err((char*)"FlowHash::loadPktToFlowWithPkt() : file open error stored_len");
			
			cPacketContainer.pkt.set(&cPacketContainer.pktInfo, cPacketContainer.payload);
			//
			//cPacketContainer.pkt.print();
			//cPacketContainer.printPayload();
			this->insert(&cPacketContainer);
		}

		fclose(fp);
	}
	else
	{
		g_err((char*)"FlowHash::loadPktToFlowWithPkt() : file open error");
		return 0;
	}
	return 1;
}

//######################################################################
unsigned int FlowHash::hashing(Packet *r)
{
	unsigned int a, b, c, d, e, f, ret;

	a = b = c = d = e = f = 0;
	memcpy( &a, (char*)&r->src_addr,     2 );
	memcpy( &b, (char*)&r->src_addr + 2, 2 );
	memcpy( &c, (char*)&r->dst_addr,     2 );
	memcpy( &d, (char*)&r->dst_addr + 2, 2 );	
	memcpy( &e, (char*)&r->src_port,     2 );
	memcpy( &f, (char*)&r->dst_port,     2 );

	ret = ( a + b + c + d + e + f ) & 0x00007FFF;
	return ret;
}
//######################################################################
int FlowHash::isSameRecord(Packet *a, FlowBasic *b)
{
	if ( a->src_addr	!= b->srcaddr )	return 0;
	if ( a->dst_addr	!= b->dstaddr )	return 0;
	if ( a->src_port	!= b->srcport )	return 0;
	if ( a->dst_port	!= b->dstport )	return 0;
	if ( a->ip_proto	!= b->prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::isSameRecordReverse(Packet *a, FlowBasic *b)
{
	if ( a->src_addr	!= b->dstaddr )	return 0;
	if ( a->dst_addr	!= b->srcaddr )	return 0;
	if ( a->src_port	!= b->dstport )	return 0;
	if ( a->dst_port	!= b->srcport )	return 0;
	if ( a->ip_proto	!= b->prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::isSameRecord(Packet *a, Packet *b)
{
	if ( a->src_addr	!= b->src_addr )	return 0;
	if ( a->dst_addr	!= b->dst_addr )	return 0;
	if ( a->src_port	!= b->src_port )	return 0;
	if ( a->dst_port	!= b->dst_port )	return 0;
	if ( a->ip_proto	!= b->ip_proto )	return 0;

	return 1;
}
//######################################################################
u_int32_t FlowHash::loadFlow(char* p_caTragetDirectory)
{
	//p_caTragetDirectory 저장되어 있는 모든 fwp 파일을 hash에 로드하고 파일 개수 리턴
	int				iTotalFwpFileCount;
	struct dirent	**filelist;
	int				fileCount = 0;
	char			caTargetFwpFileName[1024]={0,};
	DIR				*dp;
	u_int32_t		iIndex;
	struct			stat statbuf;

	iTotalFwpFileCount = scandir(p_caTragetDirectory, &filelist, isFwpfile, mysort);		//count fwp file
	
	if ( (dp = opendir(p_caTragetDirectory)) != NULL )
	{
		chdir(p_caTragetDirectory);
		for (iIndex=0; iIndex < iTotalFwpFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetFwpFileName, "%s/%s", p_caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetFwpFileName);
				this->loadFlow(caTargetFwpFileName, fileCount++);
			}
		}
		closedir(dp);
	}
	else
	{
		printf("dir : %s\n", p_caTragetDirectory);
		g_err((char*)"FlowHash::loadFlow() : can't open dir");
	}
	return  iTotalFwpFileCount;
}
//######################################################################
int FlowHash::loadFlow(char *p_caFlowFileName, int p_iFileCount)
{

	FILE *fp_Load;
	FlowTwowayContainer			cFlowTwowayContainer;
	int iReadLen;
	
	if ((fp_Load = fopen( p_caFlowFileName, "rb")) != NULL )
	{
			
		cFlowTwowayContainer.reset();
		
		while ( iReadLen = fread( &cFlowTwowayContainer.flow, 1, sizeof(FlowBasic), fp_Load) )
		{
			if( iReadLen != sizeof(FlowBasic) )
			{					
				g_err((char*)"FlowHash::loadFlow(): flow file read error");
			}
			if(cFlowTwowayContainer.flow.flag & FORWARD )		fread( &cFlowTwowayContainer.forward, 1, sizeof(FlowStat), fp_Load );
			if(cFlowTwowayContainer.flow.flag & BACKWARD )		fread( &cFlowTwowayContainer.backward, 1, sizeof(FlowStat), fp_Load );
			if(cFlowTwowayContainer.flow.flag & ANAL )			fread( &cFlowTwowayContainer.code, 1, sizeof(FlowAnal), fp_Load );
			if(cFlowTwowayContainer.flow.flag & WITH_PKT )		fread( &cFlowTwowayContainer.withpkt, 1, sizeof(FlowWithPkt), fp_Load );
			
			
			//cFlowTwowayContainer.print();
			//m_iFileID에 파일 번호 기입
			cFlowTwowayContainer.m_iFileID = p_iFileCount;
			//
			//printf("%d\n",cFlowTwowayContainer.m_iFileID);
			
			m_cFPBToTal.setFlow(m_cFPBToTal.getFlow() + 1);
			m_cFPBToTal.setPkt(m_cFPBToTal.getPkt() + cFlowTwowayContainer.forward.dPkts + cFlowTwowayContainer.backward.dPkts);
			m_cFPBToTal.setByte(m_cFPBToTal.getByte() + cFlowTwowayContainer.forward.dOctets + cFlowTwowayContainer.backward.dOctets);

			if (cFlowTwowayContainer.flow.flag & ANAL)
			{
				m_cFPBIdentified.setFlow(m_cFPBIdentified.getFlow() + 1);
				m_cFPBIdentified.setPkt(m_cFPBIdentified.getPkt() + cFlowTwowayContainer.forward.dPkts + cFlowTwowayContainer.backward.dPkts);
				m_cFPBIdentified.setByte(m_cFPBIdentified.getByte() + cFlowTwowayContainer.forward.dOctets + cFlowTwowayContainer.backward.dOctets);
			}

			//flow insert
			insert(&cFlowTwowayContainer, fp_Load);
			cFlowTwowayContainer.reset();
		}
		fclose(fp_Load);
	}
	else
	{
		g_err((char*)"FlowHash::loadFlow() : file open error");
		return 0;
	}

	//m_cFPBToTal.print();
	return 1;
}
//######################################################################
int FlowHash::setCode(FlowTwowayContainer* p_cpFlowTwowayContainer)
{
	unsigned int iKey;
	FlowTwowayContainer *go, *head;
	int iIndex;

	iKey = hashing(&p_cpFlowTwowayContainer->flow);
	head = &m_cpFlowTwowayContainerHT[iKey];
	
	for ( go = head->next;
		  go && !isSameRecord(&p_cpFlowTwowayContainer->flow, &go->flow) && !isSameRecordReverse(&p_cpFlowTwowayContainer->flow, &go->flow);
		  go = go->next );
	if ( go == NULL )
	{
		return 0;
	}
	else
	{
		if (go->code.m_iCount)			// 분석된 결과가 있는 경우만
		{
			for (iIndex=0;iIndex<go->code.m_iCount ;iIndex++ )
			{
				p_cpFlowTwowayContainer->setCode(go->code.m_caAnalCodeList[iIndex].m_iSigCode,
					go->code.m_caAnalCodeList[iIndex].m_iSCode,
					go->code.m_caAnalCodeList[iIndex].m_iACode,
					go->code.m_caAnalCodeList[iIndex].m_iPCode,
					go->code.m_caAnalCodeList[iIndex].m_iFCode,
					go->code.m_caAnalCodeList[iIndex].m_iProCode);
			}
			return 1;
		}
		else
			return 0;
	}
}
//######################################################################
void FlowHash::insert(FlowTwowayContainer *p_cpFlowTwowayContainer, FILE *p_fpLoad)
{
	unsigned int iKey;
	FlowTwowayContainer *go, *head;
	int iIndex;
	int iMaxPkt;
	PacketContainer pktRecord, *pktGo;
	int iLen;
	int checkPkt;

	iKey = hashing(&p_cpFlowTwowayContainer->flow);
	head = &m_cpFlowTwowayContainerHT[iKey];

	
	for ( go = head->next;
		  go && !isSameRecord(p_cpFlowTwowayContainer, go) && !isSameRecordReverse(p_cpFlowTwowayContainer, go);
		  go = go->next );
		
	if ( go == NULL )
	{
		//puts("new");
		go = new FlowTwowayContainer(p_cpFlowTwowayContainer);
	
		go->next = head->next;
		head->next = go;

		go->m_iFlowID = m_iFlowIndex++;				//flow ID
		
		//pkt 추가
		if (go->flow.flag & WITH_PKT)
		{
			iMaxPkt = go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt;
			//
		//	printf("max %d\n",iMaxPkt);

			for ( iIndex = 0;  iIndex < iMaxPkt;  iIndex++ )
			{
				iLen = fread(&pktRecord.pktInfo, 1, sizeof(PacketStoredInfo), p_fpLoad);
				if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"fread pktInfoLen");
				iLen = fread(pktRecord.payload, 1, pktRecord.pktInfo.stored_len, p_fpLoad);
				if ( iLen != pktRecord.pktInfo.stored_len )	g_err((char*)"fread payload");

				pktRecord.pkt.set(&pktRecord.pktInfo, pktRecord.payload);

				//pktRecord.print();
			//	pktRecord.pkt.print();

				this->insertForFlowWithPkt(&pktRecord, go);
			}
			checkPkt=0;
			for (pktGo=go->headPkt;pktGo ;pktGo=pktGo->next )
				checkPkt++;
			if (checkPkt != (go->withpkt.f_stored_pkt+go->withpkt.b_stored_pkt))
			{
				printf("%d	%d\n",checkPkt, (go->withpkt.f_stored_pkt+go->withpkt.b_stored_pkt));
				g_err((char*)"FlowHash::insert(): pkt count differ!!");
			}
		}

	}
	else
	{
		p_cpFlowTwowayContainer->print();
		go->print();
	//	getchar();

		//puts("alread");
	
		//g_err((char*)"FlowHash::insert() : conflict flow");
		//충돌시 두번째 오는 flow 무시
		if (p_cpFlowTwowayContainer->flow.flag & WITH_PKT)
		{
			iMaxPkt = p_cpFlowTwowayContainer->withpkt.f_stored_pkt + p_cpFlowTwowayContainer->withpkt.b_stored_pkt;
			//
		//	printf("max %d\n",iMaxPkt);

			for ( iIndex = 0;  iIndex < iMaxPkt;  iIndex++ )
			{
				iLen = fread(&pktRecord.pktInfo, 1, sizeof(PacketStoredInfo), p_fpLoad);
				if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"fread pktInfoLen");
				iLen = fread(pktRecord.payload, 1, pktRecord.pktInfo.stored_len, p_fpLoad);
				if ( iLen != pktRecord.pktInfo.stored_len )	g_err((char*)"fread payload");
			}
		}
	}

//	printf("%d	%d\n",p_cpFlowTwowayContainer->m_iFileID, go->m_iFileID);
//	go->print();
//	print();
//	getchar();
}
//######################################################################
void FlowHash::insertForFlowWithPkt(PacketContainer *r, FlowTwowayContainer *go)
{	
	PacketContainer *pktC, *pre_pktC, *go_pktC;

	pktC = new PacketContainer();
	pktC->set(r);
	pktC->next = NULL;

	pktC->pkt.stored_pkt = pktC->payload;
	pktC->pkt.stored_payload = &(pktC->payload[pktC->pkt.stored_pkt_len - pktC->pkt.stored_payload_len]);

	go->flow.flag |= WITH_PKT;

	if ( go->headPkt == NULL )
	{
		go->headPkt = pktC;
		pktC->pre = NULL;
		pktC->next = NULL;
		go->lastPkt = pktC;
	}
	else
	{
		go->lastPkt->next = pktC;
		pktC->pre = go->lastPkt;
		go->lastPkt = pktC;
		go->lastPkt->next = NULL;
		
		if(go->flow.prot == 6)
		{
			modOutoforder(go);
		}
	}
}
//######################################################################
unsigned int FlowHash::hashing(FlowBasic *r)
{
	unsigned int a, b, c, d, e, f, ret;

	a = b = c = d = e = f = 0;
	memcpy( &a, (char *)&r->srcaddr,      2 );
	memcpy( &b, (char *)&r->srcaddr + 2 , 2 );
	memcpy( &c, (char *)&r->dstaddr,      2 );
	memcpy( &d, (char *)&r->dstaddr + 2 , 2 );	
	memcpy( &e, (char *)&r->srcport,      2 );
	memcpy( &f, (char *)&r->dstport,      2 );

	ret = ( a + b + c + d + e + f ) & 0x00007FFF;
	return ret;
}
//######################################################################
int FlowHash::isSameRecord(FlowBasic *a, FlowBasic *b)
{
	if ( a->srcaddr		!= b->srcaddr )	return 0;
	if ( a->dstaddr		!= b->dstaddr )	return 0;
	if ( a->srcport		!= b->srcport )	return 0;
	if ( a->dstport		!= b->dstport )	return 0;
	if ( a->prot		!= b->prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::isSameRecordReverse(FlowBasic *a, FlowBasic *b)
{
	if ( a->srcaddr		!= b->dstaddr )	return 0;
	if ( a->dstaddr		!= b->srcaddr )	return 0;
	if ( a->srcport		!= b->dstport )	return 0;
	if ( a->dstport		!= b->srcport )	return 0;
	if ( a->prot		!= b->prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::isSameRecord(FlowTwowayContainer *a, FlowTwowayContainer *b)
{
	if (a->m_iFileID			!= b->m_iFileID)	return 0;
	
	if ( a->flow.srcaddr		!= b->flow.srcaddr )	return 0;
	if ( a->flow.dstaddr		!= b->flow.dstaddr )	return 0;
	if ( a->flow.srcport		!= b->flow.srcport )	return 0;
	if ( a->flow.dstport		!= b->flow.dstport )	return 0;
	if ( a->flow.prot		!= b->flow.prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::isSameRecordReverse(FlowTwowayContainer *a, FlowTwowayContainer *b)
{
	if (a->m_iFileID			!= b->m_iFileID)	return 0;

	if ( a->flow.srcaddr		!= b->flow.dstaddr )	return 0;
	if ( a->flow.dstaddr		!= b->flow.srcaddr )	return 0;
	if ( a->flow.srcport		!= b->flow.dstport )	return 0;
	if ( a->flow.dstport		!= b->flow.srcport )	return 0;
	if ( a->flow.prot		!= b->flow.prot    )	return 0;

	return 1;
}
//######################################################################
int FlowHash::crossOrderResolver(void)
{
	int iIndex, CO_Flag, flow_CO_Flag;
	u_int32_t CO_count = 0;
	int pre_count = 0;
	int post_count = 0;

	FlowTwowayContainer *go, *head;
	PacketContainer *pre_pktC, *go_pktC;
	
	for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
	{
		head = &m_cpFlowTwowayContainerHT[iIndex];
		for ( go = head->next;  go != NULL;  go = go->next )
		{
			if (go->flow.prot != 6) continue;
			if (go->withpkt.f_stored_pkt + go->withpkt.b_stored_pkt == 0)	continue;
			CO_Flag = 0;
			flow_CO_Flag = 0;			
			
			for ( pre_pktC = go->headPkt, go_pktC = pre_pktC->next;  go_pktC;  pre_pktC = go_pktC, go_pktC = go_pktC->next )
			{
				for (; pre_pktC && crossOrderDetector(go->flow, pre_pktC, go_pktC); )
				{
					CO_Flag++;
					CO_count++;
					flow_CO_Flag = 1;

					go_pktC->pre = pre_pktC->pre;
					if (pre_pktC->pre != NULL)	pre_pktC->pre->next = go_pktC;	//pre_pktC->pre와 go_pktC와의 관계 먼저 해결

					pre_pktC->next = go_pktC->next;
					if (go_pktC->next != NULL)	go_pktC->next->pre = pre_pktC;	//pre_pktC와 go_pktC->next와의 관계 해결

					pre_pktC->pre = go_pktC;		
					go_pktC->next = pre_pktC;		//pre_pktC와 go_pktC와의 관계 해결

					if (pre_pktC == go->headPkt)	go->headPkt = go_pktC;

					pre_pktC = go_pktC->pre;

				}
				for (int i = 0; i < CO_Flag; i++)	go_pktC = go_pktC->next;
				CO_Flag = 0;
			}
		}
	}
	return CO_count;
}
//######################################################################
int FlowHash::crossOrderDetector(FlowBasic flow, PacketContainer *cp_pre_pkt, PacketContainer *cp_go_pkt)
{
	if ( !isSameRecord(&cp_pre_pkt->pkt, &flow) && isSameRecord(&cp_go_pkt->pkt, &flow) )
	{
		if ((cp_pre_pkt->pkt.tcp_an <= cp_go_pkt->pkt.tcp_sn) && (cp_pre_pkt->pkt.tcp_sn >= cp_go_pkt->pkt.tcp_an))
		{
			return 1;
		}
	}
	return 0;
}
//######################################################################
void FlowHash::modRetransmission(FlowTwowayContainer *go, PacketContainer *sameDirectionRecentPkt, PacketContainer *curPkt, int status)
{
	if(status == SAME_SEQUENCE)
	{
		if(sameDirectionRecentPkt->pkt.real_payload_len <= curPkt->pkt.real_payload_len)
		{
			// curPkt 삭제
			if(sameDirectionRecentPkt->pkt.real_payload_len < curPkt->pkt.real_payload_len)
				sameDirectionRecentPkt->repacketFlag = 1;

			go->lastPkt = curPkt->pre;
			go->lastPkt->next = NULL;

			if (isSameRecord(&curPkt->pkt, &go->flow))
				go->withpkt.f_stored_pkt--;
			else
				go->withpkt.b_stored_pkt--;

			curPkt->next = NULL;
			curPkt->pre = NULL;
			//curPkt = NULL;

			delete curPkt;
		}
		else if(sameDirectionRecentPkt->pkt.real_payload_len > curPkt->pkt.real_payload_len)
		{
			//sameDirectionRecentPkt 삭제
			curPkt->repacketFlag = 1;
			if(sameDirectionRecentPkt == go->headPkt)
			{
				if(sameDirectionRecentPkt->next == curPkt)
				{
					//sameDirection 바로 뒤가 curPkt

					go->headPkt = curPkt;
					curPkt->pre = NULL;

					if (isSameRecord(&sameDirectionRecentPkt->pkt, &go->flow))
						go->withpkt.f_stored_pkt--;
					else
						go->withpkt.b_stored_pkt--;

					sameDirectionRecentPkt->pre = NULL;
					sameDirectionRecentPkt->next = NULL;
					//sameDirectionRecentPkt = NULL;

					delete sameDirectionRecentPkt;
				}
				else
				{
					//sameDirection과 curPkt 사이에 패킷존재
					go->lastPkt = curPkt->pre;
					go->lastPkt->next = NULL;

					go->headPkt = curPkt;
					curPkt->pre = NULL;
					curPkt->next = sameDirectionRecentPkt->next;
					sameDirectionRecentPkt->next->pre = curPkt;

					if (isSameRecord(&sameDirectionRecentPkt->pkt, &go->flow))
						go->withpkt.f_stored_pkt--;
					else
						go->withpkt.b_stored_pkt--;

					sameDirectionRecentPkt->pre = NULL;
					sameDirectionRecentPkt->next = NULL;
					//sameDirectionRecentPkt = NULL;

					delete sameDirectionRecentPkt;
				}
			}
			else
			{
				if(sameDirectionRecentPkt->next == curPkt)
				{
					//sameDirection 바로 뒤가 curPkt
					
					sameDirectionRecentPkt->pre->next = curPkt;
					curPkt->pre = sameDirectionRecentPkt->pre;

					if (isSameRecord(&sameDirectionRecentPkt->pkt, &go->flow))
						go->withpkt.f_stored_pkt--;
					else
						go->withpkt.b_stored_pkt--;

					sameDirectionRecentPkt->pre = NULL;
					sameDirectionRecentPkt->next = NULL;
					//sameDirectionRecentPkt = NULL;

					delete sameDirectionRecentPkt;
				}
				else
				{
					//sameDirection과 curPkt 사이에 패킷존재
					go->lastPkt = curPkt->pre;
					go->lastPkt->next = NULL;
					
					sameDirectionRecentPkt->pre->next = curPkt;
					curPkt->pre = sameDirectionRecentPkt->pre;
					curPkt->next = sameDirectionRecentPkt->next;
					sameDirectionRecentPkt->next->pre = curPkt;

					if (isSameRecord(&sameDirectionRecentPkt->pkt, &go->flow))
						go->withpkt.f_stored_pkt--;
					else
						go->withpkt.b_stored_pkt--;

					sameDirectionRecentPkt->pre = NULL;
					sameDirectionRecentPkt->next = NULL;
					//sameDirectionRecentPkt = NULL;

					delete sameDirectionRecentPkt;
				}
			}
		}
	}

	else if(status == AFTER_REPACKET)
	{
		if(sameDirectionRecentPkt->repacketFlag)
		{
			go->lastPkt = curPkt->pre;
			go->lastPkt->next = NULL;

			if (isSameRecord(&curPkt->pkt, &go->flow))
				go->withpkt.f_stored_pkt--;
			else
				go->withpkt.b_stored_pkt--; 

			curPkt->next = NULL;
			curPkt->pre = NULL;
			//curPkt = NULL;

			delete curPkt;
		}
	}
}
//######################################################################
void FlowHash::modOutoforder(FlowTwowayContainer *go)
{
	PacketContainer *fromPkt = NULL;
	PacketContainer *toPkt = NULL;
	PacketContainer *sameDirectionRecentPkt = NULL;
	PacketContainer *goPkt = NULL;
	PacketContainer *movePkt = NULL;

	movePkt = go->lastPkt;

	goPkt = movePkt->pre;
	
	//puts("process start");
	while(goPkt)
	{
		if(isSameRecord(&goPkt->pkt, &movePkt->pkt))
		{
			sameDirectionRecentPkt = goPkt;
			//puts("same direction found!");
			break;
		}
		goPkt = goPkt->pre;
	}
	if(sameDirectionRecentPkt == NULL)
	{
		//puts("same direction not found");
		return;
	}
	
	
	if(sameDirectionRecentPkt->pkt.tcp_sn == movePkt->pkt.tcp_sn)		// 방향과 seqeunce가 같은 retransmission detect
	{
		modRetransmission(go, sameDirectionRecentPkt, movePkt, SAME_SEQUENCE);
		return;
	}
	
	else if(sameDirectionRecentPkt->pkt.tcp_sn + sameDirectionRecentPkt->pkt.real_payload_len < movePkt->pkt.tcp_sn)	// 재패킷화로 인해 sequence가 어긋난 패킷의 처리 부분
	{
		modRetransmission(go, sameDirectionRecentPkt, movePkt, AFTER_REPACKET);
		return;
	}
	
	else if(sameDirectionRecentPkt->pkt.tcp_sn > movePkt->pkt.tcp_sn)		// outoforder detect 부분
	{
		goPkt = sameDirectionRecentPkt->pre;

		while(goPkt)
		{
			if(isSameRecord(&goPkt->pkt, &sameDirectionRecentPkt->pkt))
			{
				if(goPkt->pkt.tcp_sn < movePkt->pkt.tcp_sn)
				{
					fromPkt = goPkt;
					break;
				}
			}
			goPkt = goPkt->pre;
		}

		//fromPkt을 못찾으면 
		if(fromPkt == NULL)
		{
			//puts("out-of-order samedirection not found");
			// same 앞에서부터 headpkt까지 검사하여 위치결정
			goPkt = sameDirectionRecentPkt->pre;
			//printfLinkeddList(go);
			//getchar();
			

			while(goPkt != go->headPkt)
			{
				if(goPkt == NULL)
					break;
				if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an == movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
				{
					//puts("AA");
					//movePkt은 goPkt의 앞에 위치
					go->lastPkt = movePkt->pre;
					go->lastPkt->next = NULL;

					goPkt->pre->next = movePkt;
					movePkt->pre = goPkt->pre;

					movePkt->next = goPkt;
					goPkt->pre = movePkt;
					
					return;
				}
				else if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an < movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
				{
					//puts("BB");
					//movePkt은 goPkt의 뒤에 위치
					go->lastPkt = movePkt->pre;
					go->lastPkt->next = NULL;

					goPkt->next->pre = movePkt;
					movePkt->next = goPkt->next;

					movePkt->pre = goPkt;
					goPkt->next = movePkt;

					return;
				}
				goPkt = goPkt->pre;
			}
			//puts("CC");
			// 맞는 조건이 없으면 headPkt(맨앞) 위치
			go->lastPkt = movePkt->pre;
			go->lastPkt->next = NULL;

			go->headPkt->pre = movePkt;
			movePkt->next = go->headPkt;

			movePkt->pre = NULL;
			go->headPkt = movePkt;

			return;
		}
	
		goPkt = fromPkt->next;

		while(goPkt != sameDirectionRecentPkt)
		{
			if(isSameRecord(&goPkt->pkt, &fromPkt->pkt))
			{
				toPkt = goPkt;
				break;
			}
			goPkt = goPkt->next;
		}

		//toPkt을 못찾으면

		if(toPkt == NULL)
		{
			//sameDirectionRecentPkt 앞부터 fromPkt 까지 검사하여 위치결정
			goPkt = sameDirectionRecentPkt->pre;
			//puts("DD");
			while(goPkt != fromPkt)
			{
				if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an == movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
				{
					//movePkt은 goPkt의 앞에 위치
					go->lastPkt = movePkt->pre;
					go->lastPkt->next = NULL;

					goPkt->pre->next = movePkt;
					movePkt->pre = goPkt->pre;

					movePkt->next = goPkt;
					goPkt->pre = movePkt;
					//puts("FF");
					return;
				}
				else if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an < movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
				{
					//movePkt은 goPkt의 뒤에 위치
					go->lastPkt = movePkt->pre;
					go->lastPkt->next = NULL;

					goPkt->next->pre = movePkt;
					movePkt->next = goPkt->next;

					movePkt->pre = goPkt;
					goPkt->next = movePkt;
					//puts("GG");
					return;
				}
				goPkt = goPkt->pre;
			}
			// 맞는 조건이 없으면 fromPkt 뒤에 위치
			go->lastPkt = movePkt->pre;
			go->lastPkt->next = NULL;

			fromPkt->next->pre = movePkt;
			movePkt->next = fromPkt->next;

			movePkt->pre = fromPkt;
			fromPkt->next = movePkt;
			//puts("HH");
			return;
		}

		goPkt = toPkt->pre;

		//from과 to를 찾은후
		
		while(goPkt != fromPkt)
		{
			if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an == movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
			{
				//movePkt은 goPkt의 앞에 위치
				
				go->lastPkt = movePkt->pre;
				go->lastPkt->next = NULL;

				goPkt->pre->next = movePkt;
				movePkt->pre = goPkt->pre;
				
				movePkt->next = goPkt;
				goPkt->pre = movePkt;
				//puts("II");
				return;
			}
			else if( !isSameRecord(&goPkt->pkt, &movePkt->pkt) && goPkt->pkt.tcp_an < movePkt->pkt.tcp_sn + movePkt->pkt.real_payload_len )
			{
				
				//movePkt은 goPkt의 뒤에 위치
				//puts("JJ");
				go->lastPkt = movePkt->pre;
				go->lastPkt->next = NULL;

				goPkt->next->pre = movePkt;
				movePkt->next = goPkt->next;

				movePkt->pre = goPkt;
				goPkt->next = movePkt;
				
				return;
			}
			goPkt = goPkt->pre;
		}
		// 맞는 조건에 없으면 fromPkt 뒤에 위치
		go->lastPkt = movePkt->pre;
		go->lastPkt->next = NULL;

		fromPkt->next->pre = movePkt;
		movePkt->next = fromPkt->next;

		movePkt->pre = fromPkt;
		fromPkt->next = movePkt;
		//puts("KK");
		return;
	}
}