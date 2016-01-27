#include "sequence.h"
//######################################################################
Header::Header()
{
	this->reset();
}
//#######################################################################
Header::~Header()
{
	this->reset();
}
//#######################################################################
void Header::reset()
{
	uiProtocol=0;
	liProtocol.clear();
	usSrcAddr.uiAddr=0;
	usSrcAddr.uiCIDR=0;
	lsSrcAddr.clear();
	usDstAddr.uiAddr=0;
	usDstAddr.uiCIDR=0;
	lsDstAddr.clear();
	uiSrcPort=0;
	liSrcPort.clear();
	uiDstPort=0;
	liDstPort.clear();
}
//#######################################################################
void Header::print()
{
	char cStrProtocol[20]={0,};
	char cStrSrcAddr[20]={0,};
	char cStrSrcCIDR[20]={0,};
	char cStrDstAddr[20]={0,};
	char cStrDstCIDR[20]={0,};
	char cStrSrcPort[20]={0,};
	char cStrDstPort[20]={0,};

	if (this->uiProtocol == IP_PROTO_TCP)
	{
		strcpy(cStrProtocol, "tcp");
	}
	else if (this->uiProtocol == IP_PROTO_UDP)
	{
		strcpy(cStrProtocol, "udp");
	}
	else
	{
		strcpy(cStrProtocol, "any");
	}
	
	if (!this->usSrcAddr.uiAddr)
		strcpy(cStrSrcAddr, "any");
	else
	{
		g_convertAddrToString(cStrSrcAddr, getSrcAddrCIDR_start());
		if (this->usSrcAddr.uiCIDR != 32)
			sprintf(cStrSrcCIDR, "/%d",this->usSrcAddr.uiCIDR);
	}

	if (!this->usDstAddr.uiAddr)
		strcpy(cStrDstAddr, "any");
	else
	{
		g_convertAddrToString(cStrDstAddr, getDstAddrCIDR_start());
		if (this->usDstAddr.uiCIDR != 32)
			sprintf(cStrDstCIDR, "/%d",this->usDstAddr.uiCIDR);
	}

	if (!this->uiSrcPort)
		strcpy(cStrSrcPort, "any");
	else
		sprintf(cStrSrcPort, "%d", this->uiSrcPort);

	if (!this->uiDstPort)
		strcpy(cStrDstPort, "any");
	else
		sprintf(cStrDstPort, "%d", this->uiDstPort);

	printf("%s %s%s %s -> %s%s %s", cStrProtocol, cStrSrcAddr, cStrSrcCIDR ,cStrSrcPort, cStrDstAddr, cStrDstCIDR, cStrDstPort);
}//#######################################################################
void Header::print(FILE* p_fpFile)
{
	char cStrProtocol[20]={0,};
	char cStrSrcAddr[20]={0,};
	char cStrSrcCIDR[20]={0,};
	char cStrDstAddr[20]={0,};
	char cStrDstCIDR[20]={0,};
	char cStrSrcPort[20]={0,};
	char cStrDstPort[20]={0,};

	if (this->uiProtocol == IP_PROTO_TCP)
	{
		strcpy(cStrProtocol, "tcp");
	}
	else if (this->uiProtocol == IP_PROTO_UDP)
	{
		strcpy(cStrProtocol, "udp");
	}
	else
	{
		strcpy(cStrProtocol, "any");
	}

	if (!this->usSrcAddr.uiAddr)
		strcpy(cStrSrcAddr, "any");
	else
	{
		g_convertAddrToString(cStrSrcAddr, getSrcAddrCIDR_start());
		if (this->usSrcAddr.uiCIDR != 32)
			sprintf(cStrSrcCIDR, "/%d",this->usSrcAddr.uiCIDR);
	}

	if (!this->usDstAddr.uiAddr)
		strcpy(cStrDstAddr, "any");
	else
	{
		g_convertAddrToString(cStrDstAddr, getDstAddrCIDR_start());
		if (this->usDstAddr.uiCIDR != 32)
			sprintf(cStrDstCIDR, "/%d",this->usDstAddr.uiCIDR);
	}

	if (!this->uiSrcPort)
		strcpy(cStrSrcPort, "any");
	else
		sprintf(cStrSrcPort, "%d", this->uiSrcPort);

	if (!this->uiDstPort)
		strcpy(cStrDstPort, "any");
	else
		sprintf(cStrDstPort, "%d", this->uiDstPort);

	fprintf(p_fpFile,"%s %s%s %s -> %s%s %s", cStrProtocol, cStrSrcAddr, cStrSrcCIDR ,cStrSrcPort, cStrDstAddr, cStrDstCIDR, cStrDstPort);
}
//#######################################################################
void Header::print(list<ADDR>* p_lAddr)
{
	list<ADDR>::iterator itADDR;
	char cStrAddr[20]={0,};

	for (itADDR = p_lAddr->begin(); itADDR != p_lAddr->end(); ++itADDR)
	{
		g_convertAddrToString(cStrAddr, itADDR->uiAddr);
		printf("%s	%d\n",cStrAddr, itADDR->uiCIDR);
	}
}




//#######################################################################
void Header::setProt(u_int8_t p_uiProt)
{
	this->uiProtocol = p_uiProt;
}
//#######################################################################
u_int8_t Header::getProt()
{
	return this->uiProtocol;
}
//#######################################################################
list<u_int8_t>::iterator Header::getProtListBegin()
{
	return this->liProtocol.begin();
}
//#######################################################################
list<u_int8_t>::iterator Header::getProtListEnd()
{
	return this->liProtocol.end();
}





//#######################################################################
void Header::setMaskSrcAddr(u_int32_t p_uiMask)
{
	list<ADDR>::iterator itADDR;
	u_int32_t uiTempAddr;

	for (itADDR = lsSrcAddr.begin(); itADDR != lsSrcAddr.end(); ++itADDR)
	{
		uiTempAddr = ntohl(itADDR->uiAddr);
		uiTempAddr &= p_uiMask;
		itADDR->uiAddr = htonl(uiTempAddr);
	}
}
//#######################################################################
void Header::setMaskDstAddr(u_int32_t p_uiMask)
{
	list<ADDR>::iterator itADDR;
	u_int32_t uiTempAddr;

	for (itADDR = lsDstAddr.begin(); itADDR != lsDstAddr.end(); ++itADDR)
	{
		uiTempAddr = ntohl(itADDR->uiAddr);
		uiTempAddr &= p_uiMask;
		itADDR->uiAddr = htonl(uiTempAddr);
	}
}
//#######################################################################
void Header::finalize()
{
	this->liProtocol.sort();
	this->liProtocol.unique();
	if (this->liProtocol.size() == 1)
		this->uiProtocol = this->liProtocol.front();
	else
		this->uiProtocol = 0;


	this->liSrcPort.sort();
	this->liSrcPort.unique();
	if (this->liSrcPort.size() == 1)
		this->uiSrcPort = this->liSrcPort.front();
	else
		this->uiSrcPort = 0;


	this->liDstPort.sort();
	this->liDstPort.unique();
	if (this->liDstPort.size() == 1)
		this->uiDstPort = this->liDstPort.front();
	else
		this->uiDstPort = 0;

	u_int32_t cidr;
	u_int32_t mask;
	u_int32_t uiIndex;
	
	for (cidr=32;cidr>=0 ;cidr=cidr-8)
	{
		mask= 0xFFFFFFFF;
		for (uiIndex=0; uiIndex < (32-cidr) ; ++uiIndex)
		{
			mask = mask << 1;
		}
		setMaskSrcAddr(mask);
		this->lsSrcAddr.sort(CompareAddr());
		this->lsSrcAddr.unique(isSame());
		if (this->lsSrcAddr.size() == 1)
		{
			this->usSrcAddr.uiAddr = this->lsSrcAddr.front().uiAddr;
			this->usSrcAddr.uiCIDR = cidr;
			break;
		}
		else
		{
			this->usSrcAddr.uiAddr = 0;
			this->usSrcAddr.uiCIDR = 0;
		}
	}

	for (cidr=32;cidr>=0 ;cidr=cidr-8)
	{
		mask= 0xFFFFFFFF;
		for (uiIndex=0; uiIndex < (32-cidr) ; ++uiIndex)
		{
			mask = mask << 1;
		}
		setMaskDstAddr(mask);
		this->lsDstAddr.sort(CompareAddr());
		this->lsDstAddr.unique(isSame());
		if (this->lsDstAddr.size() == 1)
		{
			this->usDstAddr.uiAddr = this->lsDstAddr.front().uiAddr;
			this->usDstAddr.uiCIDR = cidr;
			break;
		}
		else
		{
			this->usDstAddr.uiAddr = 0;
			this->usDstAddr.uiCIDR = 0;
		}
	}
}
//#######################################################################
void Header::setHeader(Header* p_cpHeader)
{
	list<u_int8_t>::iterator itInt8;
	list<u_int16_t>::iterator itInt16;
	list<ADDR>::iterator itADDR;

	this->uiProtocol = p_cpHeader->uiProtocol;

	for (itInt8 = p_cpHeader->liProtocol.begin(); itInt8 != p_cpHeader->liProtocol.end(); ++itInt8)
		this->liProtocol.push_back(*itInt8);

	this->usSrcAddr.uiAddr = p_cpHeader->usSrcAddr.uiAddr;
	this->usSrcAddr.uiCIDR = p_cpHeader->usSrcAddr.uiCIDR;

	for (itADDR = p_cpHeader->lsSrcAddr.begin(); itADDR != p_cpHeader->lsSrcAddr.end(); ++itADDR)
		this->lsSrcAddr.push_back(*itADDR);

	this->usDstAddr.uiAddr = p_cpHeader->usDstAddr.uiAddr;
	this->usDstAddr.uiCIDR = p_cpHeader->usDstAddr.uiCIDR;

	for (itADDR = p_cpHeader->lsDstAddr.begin(); itADDR != p_cpHeader->lsDstAddr.end(); ++itADDR)
		this->lsDstAddr.push_back(*itADDR);

	this->uiSrcPort = p_cpHeader->uiSrcPort;

	for (itInt16 = p_cpHeader->liSrcPort.begin(); itInt16 != p_cpHeader->liSrcPort.end(); ++itInt16)
		this->liSrcPort.push_back(*itInt16);

	this->uiDstPort = p_cpHeader->uiDstPort;

	for (itInt16 = p_cpHeader->liDstPort.begin(); itInt16 != p_cpHeader->liDstPort.end(); ++itInt16)
		this->liDstPort.push_back(*itInt16);

	this->finalize();
}
//#######################################################################
void Header::setHeader(FlowTwowayContainer* p_cFlowTwowayContainer)
{
	//flow의 헤더 정보를 이용하여 cHeader set

	ADDR sTempAddr;

	this->liProtocol.push_back(p_cFlowTwowayContainer->flow.prot);

	sTempAddr.uiAddr = p_cFlowTwowayContainer->flow.srcaddr; 
	sTempAddr.uiCIDR = 32;
	this->lsSrcAddr.push_back(sTempAddr);

	this->liSrcPort.push_back(p_cFlowTwowayContainer->flow.srcport);
	
	sTempAddr.uiAddr = p_cFlowTwowayContainer->flow.dstaddr; 
	sTempAddr.uiCIDR = 32;
	this->lsDstAddr.push_back(sTempAddr);

	this->liDstPort.push_back(p_cFlowTwowayContainer->flow.dstport);

	this->finalize();
}
//#######################################################################
void Header::setHeaderReverse(FlowTwowayContainer* p_cFlowTwowayContainer)
{
	//flow의 헤더 정보를 이용하여 cHeader set

	ADDR sTempAddr;

	this->liProtocol.push_back(p_cFlowTwowayContainer->flow.prot);

	sTempAddr.uiAddr = p_cFlowTwowayContainer->flow.dstaddr; 
	sTempAddr.uiCIDR = 32;
	this->lsSrcAddr.push_back(sTempAddr);

	this->liSrcPort.push_back(p_cFlowTwowayContainer->flow.dstport);
	
	sTempAddr.uiAddr = p_cFlowTwowayContainer->flow.srcaddr; 
	sTempAddr.uiCIDR = 32;
	this->lsDstAddr.push_back(sTempAddr);

	this->liDstPort.push_back(p_cFlowTwowayContainer->flow.srcport);

	this->finalize();
}
//#######################################################################
u_int32_t Header::getSrcAddrCIDR_start()
{
	if (this->usSrcAddr.uiCIDR == 32) return this->usSrcAddr.uiAddr;
	
	u_int32_t uiIndex;

	u_int32_t uiTempAddr = ntohl(this->usSrcAddr.uiAddr);

	for (uiIndex=0; uiIndex < (32-this->usSrcAddr.uiCIDR) ; ++uiIndex)
	{
		uiTempAddr = uiTempAddr >> 1;
	}

	for (uiIndex=0; uiIndex < (32-this->usSrcAddr.uiCIDR) ; ++uiIndex)
	{
		uiTempAddr = uiTempAddr << 1;
	}
	return htonl(uiTempAddr);
}
//#######################################################################
u_int32_t Header::getDstAddrCIDR_start()
{
	if (this->usDstAddr.uiCIDR == 32) return this->usDstAddr.uiAddr;
	
	u_int32_t uiIndex;

	u_int32_t uiTempAddr = ntohl(this->usDstAddr.uiAddr);

	for (uiIndex=0; uiIndex < (32-this->usDstAddr.uiCIDR) ; ++uiIndex)
	{
		uiTempAddr = uiTempAddr >> 1;
	}

	for (uiIndex=0; uiIndex < (32-this->usDstAddr.uiCIDR) ; ++uiIndex)
	{
		uiTempAddr = uiTempAddr << 1;
	}
	return htonl(uiTempAddr);

}
//#######################################################################
u_int32_t Header::getSrcAddrCIDR_end()
{
	if (this->usSrcAddr.uiCIDR == 32) return this->usSrcAddr.uiAddr;

	u_int32_t	uiIndex;
	u_int32_t	iPad = 0x00000001;

	u_int32_t uiTempAddr = ntohl(this->usSrcAddr.uiAddr);

	for (uiIndex=0;uiIndex < (32-this->usSrcAddr.uiCIDR); ++uiIndex)
	{
		uiTempAddr |= iPad;
		iPad = iPad * 2;
	}
	return htonl(uiTempAddr);
}
//#######################################################################
u_int32_t Header::getDstAddrCIDR_end()
{
	if (this->usDstAddr.uiCIDR == 32) return this->usDstAddr.uiAddr;

	u_int32_t	uiIndex;
	u_int32_t	iPad = 0x00000001;

	u_int32_t uiTempAddr = ntohl(this->usDstAddr.uiAddr);

	for (uiIndex=0;uiIndex < (32-this->usDstAddr.uiCIDR); ++uiIndex)
	{
		uiTempAddr |= iPad;
		iPad = iPad * 2;
	}
	return htonl(uiTempAddr);
}
//#######################################################################
int Header::cmpHeader(Header* p_cpHeader)	//p_cpHeader와 비교하여 작으면 -1, 크면 1, 같으면 0
{
	if (this->uiProtocol < p_cpHeader->uiProtocol) return -1;
	if (this->uiProtocol > p_cpHeader->uiProtocol) return 1;

	if (ntohl(this->getSrcAddrCIDR_start()) < ntohl(p_cpHeader->getSrcAddrCIDR_start())) return -1;
	if (ntohl(this->getSrcAddrCIDR_start()) > ntohl(p_cpHeader->getSrcAddrCIDR_start())) return 1;
		
	if (this->uiSrcPort < p_cpHeader->uiSrcPort) return -1;
	if (this->uiSrcPort > p_cpHeader->uiSrcPort) return 1;

	if (ntohl(this->getDstAddrCIDR_start()) < ntohl(p_cpHeader->getDstAddrCIDR_start())) return -1;
	if (ntohl(this->getDstAddrCIDR_start()) > ntohl(p_cpHeader->getDstAddrCIDR_start())) return 1;
	
	
	if (this->uiDstPort < p_cpHeader->uiDstPort) return -1;
	if (this->uiDstPort > p_cpHeader->uiDstPort) return -1;

	return 0;
}
//#######################################################################
bool Header::isIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer)
{
	
	if (this->uiProtocol)
		if (this->uiProtocol != p_cpFlowTwowayContainer->flow.prot)
			return false;

	if (this->uiSrcPort)
		if (this->uiSrcPort != p_cpFlowTwowayContainer->flow.srcport)
			return false;

	if (this->uiDstPort)
		if (this->uiDstPort != p_cpFlowTwowayContainer->flow.dstport)
			return false;

	if (this->usSrcAddr.uiAddr)
		if ((ntohl(this->getSrcAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.srcaddr)) || (ntohl(this->getSrcAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.srcaddr)))
			return false;

	if (this->usDstAddr.uiAddr)
		if ((ntohl(this->getDstAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.dstaddr)) || (ntohl(this->getDstAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.dstaddr)))
			return false;

	return true;
	
}
//#######################################################################
bool Header::isForwardIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer)
{
	
	if (this->uiProtocol)
		if (this->uiProtocol != p_cpFlowTwowayContainer->flow.prot)
			return false;

	if (this->uiSrcPort)
		if (this->uiSrcPort != p_cpFlowTwowayContainer->flow.srcport)
			return false;

	if (this->uiDstPort)
		if (this->uiDstPort != p_cpFlowTwowayContainer->flow.dstport)
			return false;

	if (this->usSrcAddr.uiAddr)
		if ((ntohl(this->getSrcAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.srcaddr)) || (ntohl(this->getSrcAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.srcaddr)))
			return false;

	if (this->usDstAddr.uiAddr)
		if ((ntohl(this->getDstAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.dstaddr)) || (ntohl(this->getDstAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.dstaddr)))
			return false;

	//puts("Header::isForwardIndentify() : yes");
	return true;
	
}
//#######################################################################
bool Header::isBackwardIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer)
{
	
	if (this->uiProtocol)
		if (this->uiProtocol != p_cpFlowTwowayContainer->flow.prot)
			return false;

	if (this->uiSrcPort)
		if (this->uiSrcPort != p_cpFlowTwowayContainer->flow.dstport)
			return false;

	if (this->uiDstPort)
		if (this->uiDstPort != p_cpFlowTwowayContainer->flow.srcport)
			return false;

	if (this->usSrcAddr.uiAddr)
		if ((ntohl(this->getSrcAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.dstaddr)) || (ntohl(this->getSrcAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.dstaddr)))
			return false;

	if (this->usDstAddr.uiAddr)
		if ((ntohl(this->getDstAddrCIDR_start()) > ntohl(p_cpFlowTwowayContainer->flow.srcaddr)) || (ntohl(this->getDstAddrCIDR_end()) < ntohl(p_cpFlowTwowayContainer->flow.srcaddr)))
			return false;
	//puts("Header::isBackwardIndentify() : yes");
	return true;
}
//#######################################################################
bool Header::isIndentify(PacketContainer* p_cpPacketContainer)
{
	if (this->uiProtocol)
		if (this->uiProtocol != p_cpPacketContainer->pkt.ip_proto)
			return false;

	if (this->uiSrcPort)
		if (this->uiSrcPort != p_cpPacketContainer->pkt.src_port)
			return false;

	if (this->uiDstPort)
		if (this->uiDstPort != p_cpPacketContainer->pkt.dst_port)
			return false;

	if (this->usSrcAddr.uiAddr)
		if ((ntohl(this->getSrcAddrCIDR_start()) > ntohl(p_cpPacketContainer->pkt.src_addr)) || (ntohl(this->getSrcAddrCIDR_end()) < ntohl(p_cpPacketContainer->pkt.src_addr)))
			return false;

	if (this->usDstAddr.uiAddr)
		if ((ntohl(this->getDstAddrCIDR_start()) > ntohl(p_cpPacketContainer->pkt.dst_addr)) || (ntohl(this->getDstAddrCIDR_end()) < ntohl(p_cpPacketContainer->pkt.dst_addr)))
			return false;

	return true;
}










//#######################################################################
Content::Content()
{
	this->reset();
}
//#######################################################################
Content::~Content()
{
}
//#######################################################################
void Content::reset()
{
	uiID=0;
	uiProtocol = 0;
	uiField = 0;
	vcChars.clear();
	uiOffset=0;
	uiDepth=0;
	uiDistance=0;
	uiWithin=0;
}

//#######################################################################
void Content::print()
{
	//모든 멤버 변수에 저장된 값을 화면에 출력

	printf("id : %d ",this->uiID);
	printf("Len : %d ",this->getLength());
	if (!this->getLength()) g_err((char*)"Content::print() : getLength() is zoro");
	
	printf("Protocol : %s %s %s "
		,this->uiProtocol & PROT_UNKNOWN ? "UNKOWN" : ""
		,this->uiProtocol & PROT_HTTP ? "HTTP" : ""
		,this->uiProtocol & PROT_TLS ? "TLS" : ""); 

		if (this->uiProtocol & PROT_UNKNOWN)
			printf("%s ", this->uiField & PROT_UNKNOWN_DATA ? "DATA" : "");
		
		if (this->uiProtocol & PROT_HTTP)
			printf("%s %s %s %s %s %s %s %s ", this->uiField & PROT_HTTP_METHOD ? "METHOD" : "", this->uiField & PROT_HTTP_URL ? "URL" : ""
									, this->uiField & PROT_HTTP_HOST ? "HOST" : "", this->uiField & PROT_HTTP_USER ? "USER" : ""
									, this->uiField & PROT_HTTP_REF ? "REF" : "", this->uiField & PROT_HTTP_COOK ? "COOK" : ""
									, this->uiField & PROT_HTTP_RESPONSE ? "RESPONSE" : "", this->uiField & PROT_HTTP_DATA ? "DATA" : "");

		if (this->uiProtocol & PROT_TLS)
			printf("%s %s %s %s %s %s ", this->uiField & PROT_TLS_CHANGESPEC ? "CHANGESPEC" : "", this->uiField & PROT_TLS_ALERT ? "ALERT" : ""
								, this->uiField & PROT_TLS_HANDSHAKE ? "HANDSHAKE" : "", this->uiField & PROT_TLS_APPLICATION ? "APPLICATION" : ""
								, this->uiField & PROT_TLS_HEARTBEAT ? "HEARTBEAT" : "", this->uiField & PROT_TLS_DATA ? "DATA" : "");
	if (!this->uiProtocol) g_err((char*)"Content::print() : protocol unset");
	
	
	printf("(content:\"");
	this->printContent();
	printf("\"; ");
	this->printLocation();
	printf(")");
}
//#######################################################################
void Content::print(FILE* p_fpFile)
{
	//모든 멤버 변수에 저장된 값을 파일에 출력

	fprintf(p_fpFile, "id : %d ",this->uiID);
	fprintf(p_fpFile, "Len : %d ",this->getLength());
	if (!this->getLength()) g_err((char*)"Content::print() : getLength() is zoro");
	
	fprintf(p_fpFile, "Protocol : %s %s %s "
		,this->uiProtocol & PROT_UNKNOWN ? "UNKOWN" : ""
		,this->uiProtocol & PROT_HTTP ? "HTTP" : ""
		,this->uiProtocol & PROT_TLS ? "TLS" : ""); 
		
		if (this->uiProtocol & PROT_UNKNOWN)
			fprintf(p_fpFile, "%s ", this->uiField & PROT_UNKNOWN_DATA ? "DATA" : "");

		if (this->uiProtocol & PROT_HTTP)
			fprintf(p_fpFile, "%s %s %s %s %s %s %s %s ", this->uiField & PROT_HTTP_METHOD ? "METHOD" : "", this->uiField & PROT_HTTP_URL ? "URL" : ""
									, this->uiField & PROT_HTTP_HOST ? "HOST" : "", this->uiField & PROT_HTTP_USER ? "USER" : ""
									, this->uiField & PROT_HTTP_REF ? "REF" : "", this->uiField & PROT_HTTP_COOK ? "COOK" : ""
									, this->uiField & PROT_HTTP_RESPONSE ? "RESPONSE" : "", this->uiField & PROT_HTTP_DATA ? "DATA" : "");

		if (this->uiProtocol & PROT_TLS)
			fprintf(p_fpFile, "%s %s %s %s %s %s ", this->uiField & PROT_TLS_CHANGESPEC ? "CHANGESPEC" : "", this->uiField & PROT_TLS_ALERT ? "ALERT" : ""
								, this->uiField & PROT_TLS_HANDSHAKE ? "HANDSHAKE" : "", this->uiField & PROT_TLS_APPLICATION ? "APPLICATION" : ""
								, this->uiField & PROT_TLS_HEARTBEAT ? "HEARTBEAT" : "", this->uiField & PROT_TLS_DATA ? "DATA" : "");
	if (!this->uiProtocol) g_err((char*)"Content::print() : protocol unset");
	

	fprintf(p_fpFile, "(content:\"");
	printContent(p_fpFile);
	fprintf(p_fpFile, "\"; ");
	printLocation(p_fpFile);
	fprintf(p_fpFile, ")");
}

//#######################################################################
void Content::printContent()
{
	//vcChars에 저장된 문자를 화면에 출력, printable 문자는 그대로, non-printable 문자는 16진수로 출력

	vector<char>::iterator itChar;

	for (itChar = this->getCharsVectorBegin(); itChar != this->getCharsVectorEnd(); ++itChar)
	{
		if (((*itChar >=' ') && (*itChar <= '~')) && (*itChar != ';') && (*itChar != '\\') && (*itChar != '"') && (*itChar != '|')&& (*itChar != '<')&& (*itChar != '>'))
		{
			printf("%c", *itChar);
		}
		else
			printf("|%02x|", (unsigned)(unsigned char)*itChar);
	}
}
//#######################################################################
void Content::printContent(FILE* p_fpFile)
{
	//vcChars에 저장된 문자를 파일에 출력, printable 문자는 그대로, non-printable 문자는 16진수로 출력

	vector<char>::iterator itChar;

	for (itChar = this->getCharsVectorBegin(); itChar != this->getCharsVectorEnd(); ++itChar)
	{
		if (((*itChar >=' ') && (*itChar <= '~')) && (*itChar != ';') && (*itChar != '\\') && (*itChar != '"') && (*itChar != '|')&& (*itChar != '<')&& (*itChar != '>'))
		{
			fprintf(p_fpFile, "%c", *itChar);
		}
		else
			fprintf(p_fpFile, "|%02x|", (unsigned)(unsigned char)*itChar);
	}
}
//#######################################################################
void Content::printLocation(int iFlag)
{
	//위치 정보 화면에 출력, COMMON 이면 모두 출력, FIRST 이면 첫 content를 의미하며, offset, depth만 출력, NO_FIRST 이면 두번째 이후 content를 의미하며, within만 출력 

	if (iFlag != NO_FIRST)
	{
		printf("offset:");
		printf("%u",this->getOffset());
		printf("; ");

		printf("depth:");
		printf("%u",this->getDepth());
		printf("; ");
	}
	
	if (iFlag != FIRST)
	{
		printf("within:");
		printf("%u",this->getWithin());
		printf("; ");

		printf("distance:");
		printf("%u",this->getDistance());
		printf("; ");
	}
}
//#######################################################################
void Content::printLocation(FILE* p_fpFile, int iFlag)
{
	//위치 정보 파일에 출력, COMMON 이면 모두 출력, FIRST 이면 첫 content를 의미하며, offset, depth만 출력, NO_FIRST 이면 두번째 이후 content를 의미하며, within만 출력 

	if (iFlag != NO_FIRST)
	{
		fprintf(p_fpFile, "offset:");
		fprintf(p_fpFile, "%u",this->getOffset());
		fprintf(p_fpFile, "; ");

		fprintf(p_fpFile, "depth:");
		fprintf(p_fpFile, "%u",this->getDepth());
		fprintf(p_fpFile, "; ");
	}
	
	if (iFlag != FIRST)
	{
		fprintf(p_fpFile, "within:");
		fprintf(p_fpFile, "%u",this->getWithin());
		fprintf(p_fpFile, "; ");
	}
}
//#######################################################################
void Content::printSnortForm(int iFlag)
{
	//snort 엔진에 바로 적용할 수 있는 형태로 화면에 출력

	printf("content:\"");
	printContent();
	printf("\"; ");
	printLocation(iFlag);
}
//#######################################################################
void Content::printSnortForm(FILE* p_fpFile, int iFlag)
{
	//snort 엔진에 바로 적용할 수 있는 형태로 파일에 출력
	
	fprintf(p_fpFile, "content:\"");
	printContent(p_fpFile);
	fprintf(p_fpFile, "\"; ");
	printLocation(p_fpFile, iFlag);
}
//#######################################################################
void Content::printSnortFormHTML(int iFlag)
{
	//웹페이지에 바로 적용할 수 있는 형태로 화면에 출력
	printf("content:%s\"", HIGHLIGHT_START_1);
	printContent();
	printf("\"%s; ", HIGHLIGHT_END_1);
	printLocation(iFlag);
}
//#######################################################################
void Content::printSnortFormHTML(FILE* p_fpFile, int iFlag)
{
	//웹페이지에 바로 적용할 수 있는 형태로 파일에 출력

	fprintf(p_fpFile, "content:%s\"", HIGHLIGHT_START_1);
	printContent(p_fpFile);
	fprintf(p_fpFile, "\"%s; ", HIGHLIGHT_END_1);
	printLocation(p_fpFile, iFlag);
}
//#######################################################################
u_int32_t Content::getID()
{
	return this->uiID;
}
//#######################################################################
u_int32_t Content::getProt()
{
	return this->uiProtocol;
}
//#######################################################################
u_int32_t Content::getField()
{
	return this->uiField;
}
//#######################################################################
u_int32_t Content::getOffset()
{
	return this->uiOffset;
}
//#######################################################################
u_int32_t Content::getDepth()
{
	return this->uiDepth;
}
//#######################################################################
u_int32_t Content::getDistance()
{
	return this->uiDistance;
}
//#######################################################################
u_int32_t Content::getWithin()
{
	return this->uiWithin;
}
//#######################################################################
void Content::setID(u_int32_t p_iID)
{
	this->uiID = p_iID;
}
//#######################################################################
void Content::setProt(u_int32_t p_iProt)
{
	this->uiProtocol = p_iProt;
}
//#######################################################################
void Content::setField(u_int32_t p_iField)
{
	this->uiField = p_iField;
}
//#######################################################################
void Content::addField(u_int32_t p_iField)
{
	this->uiField |= p_iField;
}
//#######################################################################
void Content::setOffset(u_int32_t p_iOffset)
{
	this->uiOffset = p_iOffset;
}
//#######################################################################
void Content::setDepth(u_int32_t p_iDepth)
{
	this->uiDepth = p_iDepth;
}
//#######################################################################
void Content::setDistance(u_int32_t p_iDistance)
{
	this->uiDistance = p_iDistance;
}
//#######################################################################
void Content::setWithin(u_int32_t p_iWithin)
{
	this->uiWithin = p_iWithin;
}
//#######################################################################
vector<char>::iterator Content::getCharsVectorBegin()
{
	return this->vcChars.begin();
}
//#######################################################################
vector<char>::iterator Content::getCharsVectorEnd()
{
	return this->vcChars.end();
}
//#######################################################################
void Content::setContent(Content* p_cpContent)
{
	vector<char>::iterator it;

	this->reset();

	this->setProt(p_cpContent->getProt());
	this->setField(p_cpContent->getField());
	for (it = p_cpContent->getCharsVectorBegin(); it != p_cpContent->getCharsVectorEnd(); ++it)
	{
		this->vcChars.push_back(*it);
	}
}


//#######################################################################
void Content::concatenateContent(PacketContainer *p_cPkt, int p_iMaxLength)
{
	//p_cPkt의 payload 중 p_iMaxLength 길이만큼을 저장. 단 p_iMaxLength -1이면 페이로드 전체 복사
	
	int iBeforLength = vcChars.size();
	
	
	for ( int i = p_cPkt->pkt.stored_pkt_len - p_cPkt->pkt.stored_payload_len;  i < p_cPkt->pkt.stored_pkt_len;  i++ )
	{
		if (p_iMaxLength != -1)
			if (vcChars.size() >= p_iMaxLength)
				return;

		vcChars.push_back(p_cPkt->payload[i]);
	}

	//에러체크
	if (p_iMaxLength == -1)
	{
		if (vcChars.size()-iBeforLength != p_cPkt->pkt.stored_payload_len)
		{
			printf("vcChars.size()-iBeforLength : %d p_cPkt->pkt.stored_payload_len : %d\n",vcChars.size()-iBeforLength, p_cPkt->pkt.stored_payload_len);
			g_err((char*)"Content::concatenateContent() : contetn size error (1)");
		}
	}
	else
	{
		if (vcChars.size()-iBeforLength > p_iMaxLength)
		{
			printf("vcChars.size()-iBeforLength : %d p_iMaxLength : %d\n",vcChars.size()-iBeforLength, p_iMaxLength);
			g_err((char*)"Content::concatenateContent() : contetn size error (2)");
		}
	}
}
//#######################################################################
void Content::concatenateOneChar(char* p_cpChar)
{
	//입력받은 문자를 vcChar에  붙임

	this->vcChars.push_back(*p_cpChar);
}
//#######################################################################
void Content::concatenateChars(char* p_cpChars, int p_iCharsSize)
{
	//입력받은 문자열을 p_iCharsSize 만큼 vcChar에  붙임
	int iIndex;

	for (iIndex=0; iIndex<p_iCharsSize ; iIndex++)
	{
		this->vcChars.push_back(*(p_cpChars+iIndex));
	}
}
//#######################################################################
void Content::concatenateOneHex(int* p_cpHex)
{
	//입력받은 16진수를 vcChar에  붙임

	this->vcChars.push_back(*p_cpHex);
}
//#######################################################################
void Content::extract(Content* p_cpResultContent, int p_iStart, int p_iEnd)
{
	//자신의 cContent에서 p_iStart~p_iEnd를 추출하여 p_cpResultContent에 저장

	if (p_iEnd > this->getLength()) g_err((char*)"Content::extract() : end offset over length!!");
	if (p_iStart > p_iEnd) g_err((char*)"Content::extract() : start offset over end offset!!");

	int iIndex;

	for (iIndex=p_iStart; iIndex<p_iEnd ; iIndex++)
	{
		p_cpResultContent->vcChars.push_back(this->vcChars[iIndex]);
	}
}
//#######################################################################
void Content::join(Content* p_cpContent)
{
	//p_cpContent의 마지막 char을 자신의 vcChars에 추가

	this->concatenateOneChar(&p_cpContent->vcChars.back());
}
//#######################################################################
u_int32_t Content::getLength()
{
	return vcChars.size();
}
//#######################################################################
int Content::isInclude(int p_iOffset, Content* p_cpContent)
{
	//p_cpContent가 자신에게 p_iOffset 이후 포함되면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴 

	vector<char>::iterator it;

	// p_iOffset이 자신의 길이보다 크거나 같으면 return 0
	if (this->vcChars.size() <= p_iOffset) return 0;

	// 검사해야하는 길이(this->vcChars.size()-p_iOffset)가 p_cpContent 길이보다 짧으면 return 0
	if ((this->vcChars.size()-p_iOffset) < p_cpContent->vcChars.size()) return 0;

	// 검사
	it = std::search(this->vcChars.begin()+p_iOffset, this->vcChars.end(), p_cpContent->vcChars.begin(), p_cpContent->vcChars.end());

	if (it != this->vcChars.end())		//성공
	{
		return ( it - this->vcChars.begin() ) + p_cpContent->vcChars.size();
	}
	else
	{
		return 0;
	}
}
//#######################################################################
int Content::isInclude(int p_iOffset, Content* p_cpContent, int p_iProtocol, int p_iField)
{
	//프로토콜, 필드로 파싱 후 포함여부 확인. p_cpContent가 자신에게 p_iOffset 이후 포함되면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴 

	if (this->getProt() != p_iProtocol)	return 0;
	if (!(this->getField() & p_iField)) return 0;

	if ((this->getField() & p_iField) != p_iField)
		g_err((char*)" Content::isInclude() : p_iField has several bits!!");

//	this->print();
//	p_cpContent->print();
//	getchar();

	int iStart;		//검사 시작 위치
	int iEnd;		//검사 종료 위치

	if (this->getIndex(&iStart, &iEnd, p_iProtocol, p_iField))		//자신의 content에서 검사 구간을 계산한다.
	{

	}


}
//#######################################################################
bool Content::getIndex(int* p_iStart, int* p_iEnd, int p_iProtocol, int p_iField)
{
	//자신의 content에서 필드 구간을 확인, p_iStart, p_iEnd에 명시
	if (this->getProt() != p_iProtocol)	return 0;
	if (!(this->getField() & p_iField)) return 0;

	if ((this->getField() & p_iField) != p_iField)
		g_err((char*)" Content::getIndex() : p_iField has several bits!!");

//	if (p_iProtocol & )
//	{
//	}


}
//#######################################################################
int Content::cmpContent(Content* p_cpContent)	
{
	//p_cpContent와 비교하여 길이가 짧으면 -1, 크면 1
	if (this->vcChars.size() < p_cpContent->vcChars.size()) return -1;
	if (this->vcChars.size() > p_cpContent->vcChars.size()) return 1;

	//길이가 같으면 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 길이도 같고 내용도 같은면 0
	return memcmp(&this->vcChars[0], &p_cpContent->vcChars[0], this->vcChars.size());
}
//#######################################################################
bool Content::isJoinable(Content* p_cpContent)
{
	// 결합가능한가? 길이 2 이상만 입력, 자신의 마지막 K-1 길이와 대상의 첫 K-1 길이가 동일한지
	if ((this->vcChars.size() < 2) || (p_cpContent->vcChars.size() < 2)) g_err((char*)"Content::isJoinable() : content lenth under 2");
	if (this->vcChars.size() != p_cpContent->vcChars.size()) g_err((char*)"Content::isJoinable() : content lenth differ");
	
	return !(memcmp(&this->vcChars[1], &p_cpContent->vcChars[0], this->vcChars.size()-1));
}
//#######################################################################
bool Content::isFixContent()
{
	if ((uiDepth - this->getLength()) == uiOffset) return true;

	return false;
}
//#######################################################################
void Content::setField()
{
	SequenceVector cSequenceVectorTemp;
	Sequence	cSequenceTemp;

	if (!this->getProt())
		g_err((char*)"Content::setField() : no prot");

	if (this->getProt() & PROT_UNKNOWN)
	{
		this->addField(PROT_UNKNOWN_DATA);
	}
	if (this->getProt() & PROT_HTTP)
	{
		cSequenceVectorTemp.reset();
		cSequenceTemp.setContent(this);
		cSequenceTemp.parserHTTP(&cSequenceVectorTemp);
		this->setField(cSequenceTemp.getContentField());
	}
	if (this->getProt() & PROT_TLS)
	{
		cSequenceVectorTemp.reset();
		cSequenceTemp.setContent(this);
		cSequenceTemp.parserTLS(&cSequenceVectorTemp);
		this->setField(cSequenceTemp.getContentField());
	}
}






//#######################################################################
Suspect::Suspect()
{
	this->reset();
}
//#######################################################################
Suspect::~Suspect()
{
	this->reset();
}
//#######################################################################
void Suspect::reset()
{
	uiSusID = 0;
	uiSusOffset = 0;
}
//#######################################################################
void Suspect::print() const
{
	printf("(%u:%u)",uiSusID, uiSusOffset);
}
//#######################################################################
void Suspect::print(FILE* p_fpFile) const
{
	fprintf(p_fpFile, "(%u:%u)",uiSusID, uiSusOffset);
}
//#######################################################################
void Suspect::setSusID(u_int32_t p_uiSusSeqID)
{
	this->uiSusID = p_uiSusSeqID;
}
//#######################################################################
void Suspect::setSusOffset(u_int32_t p_uiSusOffset)
{
	this->uiSusOffset = p_uiSusOffset;
}
//#######################################################################
u_int32_t Suspect::getSusID() const
{
	return this->uiSusID;
}
//#######################################################################
u_int32_t Suspect::getSusOffset() const
{
	return this->uiSusOffset;
}



//#######################################################################
Rule::Rule()
{
	this->reset();
}
//#######################################################################
Rule::~Rule()
{
	this->reset();
}
//#######################################################################
void Rule::reset()
{
	uiID=0;
	scSuspects.clear();
	uiSupp=0;
	uiMaxSupp=0;
	uiProtocol=0;
	uiField=0;
	
	cHeader.reset();
	uiContentCount=0;
	lcContents.clear();

	cRule_PKT_IdentifiedTraffic.reset();
	cRule_PKT_TotalTraffic.reset();

	cRule_FLOW_IdentifiedTraffic.reset();
	cRule_FLOW_TotalTraffic.reset();
}

//#######################################################################
void Rule::print()
{
	//모든 멤버 변수에 저장된 값을 화면에 출력

	list<Content>::iterator itContent;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;
	
	printf("RuleID : %u ",this->getID());
	printf("Supp : %u/%u ",this->getSupp(),this->getMaxSupp());
	printf("Protocol : %s %s %s "
		,this->uiProtocol & PROT_UNKNOWN ? "UNKOWN" : ""
		,this->uiProtocol & PROT_HTTP ? "HTTP" : ""
		,this->uiProtocol & PROT_TLS ? "TLS" : ""); 

		if (this->uiProtocol & PROT_UNKNOWN)
			printf("%s ", this->uiField & PROT_UNKNOWN_DATA ? "DATA" : "");
		
		if (this->uiProtocol & PROT_HTTP)
			printf("%s %s %s %s %s %s %s %s ", this->uiField & PROT_HTTP_METHOD ? "METHOD" : "", this->uiField & PROT_HTTP_URL ? "URL" : ""
									, this->uiField & PROT_HTTP_HOST ? "HOST" : "", this->uiField & PROT_HTTP_USER ? "USER" : ""
									, this->uiField & PROT_HTTP_REF ? "REF" : "", this->uiField & PROT_HTTP_COOK ? "COOK" : ""
									, this->uiField & PROT_HTTP_RESPONSE ? "RESPONSE" : "", this->uiField & PROT_HTTP_DATA ? "DATA" : "");

		if (this->uiProtocol & PROT_TLS)
			printf("%s %s %s %s %s %s ", this->uiField & PROT_TLS_CHANGESPEC ? "CHANGESPEC" : "", this->uiField & PROT_TLS_ALERT ? "ALERT" : ""
								, this->uiField & PROT_TLS_HANDSHAKE ? "HANDSHAKE" : "", this->uiField & PROT_TLS_APPLICATION ? "APPLICATION" : ""
								, this->uiField & PROT_TLS_HEARTBEAT ? "HEARTBEAT" : "", this->uiField & PROT_TLS_DATA ? "DATA" : "");
	if (!this->uiProtocol) g_err((char*)"Content::print() : protocol unset");
	

	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		printf("F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	if (cpPktTotal->getPkt())
	{
		printf("P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}

	if (scSuspects.size())
	{
		printf("suspect : %d ", scSuspects.size());
		printSuspectSet();
	}
	
	printf("\nFix : %c ", isFixContent()?'T':'F');
	this->cHeader.print();	
	printf("\n");

	for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
	{
		printf("                     ");
		itContent->print();
		printf("\n");
	}
	printf("\n");
}
//#######################################################################
void Rule::print(FILE* p_fpFile)
{
	//모든 멤버 변수에 저장된 값을 파일에 출력
	
	list<Content>::iterator itContent;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;
	
	fprintf(p_fpFile, "RuleID : %u ",this->getID());
	fprintf(p_fpFile, "Supp : %u/%u ",this->getSupp(),this->getMaxSupp());
	
	fprintf(p_fpFile, "Protocol : %s %s %s "
		,this->uiProtocol & PROT_UNKNOWN ? "UNKOWN" : ""
		,this->uiProtocol & PROT_HTTP ? "HTTP" : ""
		,this->uiProtocol & PROT_TLS ? "TLS" : ""); 

		if (this->uiProtocol & PROT_UNKNOWN)
			fprintf(p_fpFile, "%s ", this->uiField & PROT_UNKNOWN_DATA ? "DATA" : "");
		
		if (this->uiProtocol & PROT_HTTP)
			fprintf(p_fpFile, "%s %s %s %s %s %s %s %s ", this->uiField & PROT_HTTP_METHOD ? "METHOD" : "", this->uiField & PROT_HTTP_URL ? "URL" : ""
									, this->uiField & PROT_HTTP_HOST ? "HOST" : "", this->uiField & PROT_HTTP_USER ? "USER" : ""
									, this->uiField & PROT_HTTP_REF ? "REF" : "", this->uiField & PROT_HTTP_COOK ? "COOK" : ""
									, this->uiField & PROT_HTTP_RESPONSE ? "RESPONSE" : "", this->uiField & PROT_HTTP_DATA ? "DATA" : "");

		if (this->uiProtocol & PROT_TLS)
			fprintf(p_fpFile, "%s %s %s %s %s %s ", this->uiField & PROT_TLS_CHANGESPEC ? "CHANGESPEC" : "", this->uiField & PROT_TLS_ALERT ? "ALERT" : ""
								, this->uiField & PROT_TLS_HANDSHAKE ? "HANDSHAKE" : "", this->uiField & PROT_TLS_APPLICATION ? "APPLICATION" : ""
								, this->uiField & PROT_TLS_HEARTBEAT ? "HEARTBEAT" : "", this->uiField & PROT_TLS_DATA ? "DATA" : "");
	if (!this->uiProtocol) g_err((char*)"Content::print() : protocol unset");
	
	
	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		fprintf(p_fpFile, "F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	if (cpPktTotal->getPkt())
	{
		fprintf(p_fpFile, "P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}

	if (scSuspects.size())
	{
		printf("suspect : %d ", scSuspects.size());
		printSuspectSet(p_fpFile);
	}
	
	fprintf(p_fpFile, "\r\nFix : %c ", isFixContent()?'T':'F');
	this->cHeader.print(p_fpFile);	
	fprintf(p_fpFile, "\r\n");

	for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
	{
		fprintf(p_fpFile, "                     ");
		itContent->print(p_fpFile);
		fprintf(p_fpFile, "\r\n");
	}
	fprintf(p_fpFile, "\r\n");
}
//#######################################################################
void Rule::printSnortForm()
{
	//snort 엔진에 바로 적용할 수 있는 형태로 화면에 출력

	list<Content>::iterator itContent;
	
	printf("alert ");
	
	this->cHeader.print();	printf(" ");
	
	printf("(");
		printf("sid: %d; ",this->getID() + BASE_SID);

		for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
		{
			if (itContent == this->getContentsListBegin())		//첫 content인 경우, offset, depth만 출력
			{
				itContent->printSnortForm(FIRST);
			}
			else												//첫 content가 아닌 경우, within만 출력
			{
				itContent->printSnortForm(NO_FIRST);
			}
		}
	printf(")");
	printf("\n");
}
//#######################################################################
void Rule::printSnortForm(FILE* p_fpFile)
{
	//snort 엔진에 바로 적용할 수 있는 형태로 파일에 출력

	list<Content>::iterator itContent;
	
	fprintf(p_fpFile, "alert ");
	
	this->cHeader.print(p_fpFile);	fprintf(p_fpFile, " ");
	
	fprintf(p_fpFile, "(");
		fprintf(p_fpFile, "sid: %d; ",this->getID() + BASE_SID);

		for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
		{
			if (itContent == this->getContentsListBegin())		//첫 content인 경우, offset, depth만 출력
			{
				itContent->printSnortForm(p_fpFile, FIRST);
			}
			else												//첫 content가 아닌 경우, within만 출력
			{
				itContent->printSnortForm(p_fpFile, NO_FIRST);
			}
		}
	fprintf(p_fpFile, ")");
	fprintf(p_fpFile, "\r\n");
}
//#######################################################################
void Rule::printSnortFormHTML()
{
	//웹페이지에 바로 적용할 수 있는 형태로 화면에 출력

	list<Content>::iterator itContent;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;
	
	printf("Support : %s%d/%d%s files; ", HIGHLIGHT_START_1, this->getSupp(), this->getMaxSupp(), HIGHLIGHT_END_1);

	if (this->isFixContent())
	{
		printf("%s(FIX); %s ", HIGHLIGHT_START_2, HIGHLIGHT_END_2);
	}

	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		printf("F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu); ",
			(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	if (cpPktTotal->getPkt())
	{
		printf("P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu); ",
			(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}

	printf("\n");
	
	printf("alert ");
	
	printf("%s",HIGHLIGHT_START_3);;
	this->cHeader.print();
	printf("%s",HIGHLIGHT_END_3);;
	printf(" ");
	
	printf("(");
		printf("sid: %d; ",this->getID() + BASE_SID);

		for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
		{
			if (itContent == this->getContentsListBegin())		//첫 content인 경우, offset, depth만 출력
			{
				itContent->printSnortFormHTML(FIRST);
			}
			else												//첫 content가 아닌 경우, within만 출력
			{
				itContent->printSnortFormHTML(NO_FIRST);
			}
		}
	printf(")");
	printf("\n");
}
//#######################################################################
void Rule::printSnortFormHTML(FILE* p_fpFile)
{
	//웹페이지에 바로 적용할 수 있는 형태로 파일에 출력

	list<Content>::iterator itContent;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;
	
	fprintf(p_fpFile, "Support : %s%d/%d%s files; ", HIGHLIGHT_START_1, this->getSupp(), this->getMaxSupp(), HIGHLIGHT_END_1);

	if (this->isFixContent())
	{
		fprintf(p_fpFile, "%s(FIX); %s ", HIGHLIGHT_START_2, HIGHLIGHT_END_2);
	}

	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		fprintf(p_fpFile, "F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu); ",
			(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	if (cpPktTotal->getPkt())
	{
		fprintf(p_fpFile, "P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu); ",
			(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}

	fprintf(p_fpFile, "\r\n");
	
	fprintf(p_fpFile, "alert ");
	
	fprintf(p_fpFile, "%s",HIGHLIGHT_START_3);;
	this->cHeader.print(p_fpFile);
	fprintf(p_fpFile, "%s",HIGHLIGHT_END_3);;
	fprintf(p_fpFile, " ");
	
	fprintf(p_fpFile, "(");
		fprintf(p_fpFile, "sid: %d; ",this->getID() + BASE_SID);

		for (itContent =this->getContentsListBegin() ;itContent !=this->getContentsListEnd() ; ++itContent)
		{
			if (itContent == this->getContentsListBegin())		//첫 content인 경우, offset, depth만 출력
			{
				itContent->printSnortFormHTML(p_fpFile, FIRST);
			}
			else												//첫 content가 아닌 경우, within만 출력
			{
				itContent->printSnortFormHTML(p_fpFile, NO_FIRST);
			}
		}
	fprintf(p_fpFile, ")");
	fprintf(p_fpFile, "\r\n");
}
//#######################################################################
void Rule::printSuspectSet()
{
	set<Suspect>::iterator itSuspect;

	printf("< ");
	for (itSuspect = scSuspects.begin(); itSuspect != scSuspects.end(); ++itSuspect)
		itSuspect->print();
	printf(">");
}
//#######################################################################
void Rule::printSuspectSet(FILE* p_fpFile)
{
	set<Suspect>::iterator itSuspect;

	fprintf(p_fpFile, "< ");
	for (itSuspect = scSuspects.begin(); itSuspect != scSuspects.end(); ++itSuspect)
	{
		itSuspect->print(p_fpFile);
	}
	fprintf(p_fpFile, ">");
}
//#######################################################################
void Rule::setID(u_int32_t p_uiID)
{
	this->uiID = p_uiID;
}
//#######################################################################
void Rule::setSupp(u_int32_t p_uiSupp)
{
	this->uiSupp = p_uiSupp;
}
//#######################################################################
void Rule::increaseSupp()
{
	this->uiSupp++;
}
//#######################################################################
void Rule::setProt(u_int32_t p_uiProt)
{
	this->uiProtocol = p_uiProt;
}
//#######################################################################
void Rule::setField(u_int32_t p_iField)
{
	this->uiField = p_iField;
}
//#######################################################################
u_int32_t Rule::getID()
{
	return this->uiID;
}
//#######################################################################
u_int32_t Rule::getSupp()
{
	return this->uiSupp;
}
//#######################################################################
u_int32_t Rule::getMaxSupp()
{
	return this->uiMaxSupp;
}
//#######################################################################
u_int32_t Rule::getProt()
{
	return this->uiProtocol;
}
//#######################################################################
u_int32_t Rule::getField()
{
	return this->uiField;
}
//#######################################################################
u_int32_t Rule::getContentSize()
{
	return this->lcContents.size();
}
//#######################################################################
Header* Rule::getHeader()
{
	return &(this->cHeader);
}
//#######################################################################
list<Content>::iterator Rule::getContentsListBegin()
{
	return this->lcContents.begin();
}
//#######################################################################
list<Content>::iterator Rule::getContentsListEnd()
{
	return this->lcContents.end();
}
//#######################################################################
FPB* Rule::getPktIdentifiedTraffic()
{
	return &(this->cRule_PKT_IdentifiedTraffic);
}
//#######################################################################
FPB* Rule::getPktTotalTraffic()
{
	return &(this->cRule_PKT_TotalTraffic);
}
//#######################################################################
FPB* Rule::getFlowIdentifiedTraffic()
{
	return &(this->cRule_FLOW_IdentifiedTraffic);
}
//#######################################################################
FPB* Rule::getFlowTotalTraffic()
{
	return &(this->cRule_FLOW_TotalTraffic);
}
//#######################################################################
void Rule::setIntersectionSuspects(Rule* p_cpRule1, Rule* p_cpRule2)
{
	//두 규칙의 용의자 교집합을 추출

	set<Suspect>::iterator itFirst1 =  p_cpRule1->scSuspects.begin();
	set<Suspect>::iterator itLast1 =  p_cpRule1->scSuspects.end();
	set<Suspect>::iterator itFirst2 =  p_cpRule2->scSuspects.begin();
	set<Suspect>::iterator itLast2 =  p_cpRule2->scSuspects.end();

	Suspect cSuspectTemp;

	while ((itFirst1 != itLast1) && (itFirst2 != itLast2))
	{
		if (itFirst1->getSusID() < itFirst2->getSusID()) ++itFirst1;
		else if (itFirst2->getSusID() < itFirst1->getSusID()) ++itFirst2;
		else
		{
			cSuspectTemp.reset();
			cSuspectTemp.setSusID(itFirst1->getSusID());
			cSuspectTemp.setSusOffset(itFirst1->getSusOffset()<itFirst2->getSusOffset()?itFirst1->getSusOffset():itFirst2->getSusOffset());
			this->scSuspects.insert(cSuspectTemp);
			++itFirst1;
			++itFirst2;
		}
	}
}
//#######################################################################
void Rule::resetSupspects()
{
	this->scSuspects.clear();
}
//#######################################################################
u_int32_t Rule::getFirstContentLength()
{
	list<Content>::iterator itContent = this->lcContents.begin();
	return itContent->getLength();

}

//#######################################################################
void Rule::insert(Content* p_cpContent)
{
	//p_cpContent에 ID를 설정하고 추가

//	p_cpContent->uiID = this->uiContentCount++;
	this->setProt(this->getProt() | p_cpContent->getProt());
	this->setField(this->getField() | p_cpContent->getField());
	lcContents.push_back(*p_cpContent);
}
//#######################################################################
void Rule::insertSingleContent(Rule* p_cpRule)
{
	//p_cpRule의 첫번째 content만 추가
	
	list<Content>::iterator itContent = p_cpRule->getContentsListBegin();
	this->insert(&(*itContent));
}
//#######################################################################
void Rule::insertMultiContent(Rule* p_cpRule)
{
	//p_cpRule의 모든 content 추가
	
	list<Content>::iterator itContent;

	for (itContent = p_cpRule->getContentsListBegin(); itContent != p_cpRule->getContentsListEnd() ; ++itContent)
	{		
		this->insert(&(*itContent));
	}
}
//#######################################################################
void Rule::joinSingleContent(Rule* p_cpRule)
{
	//p_cpRule의 첫번째 content의 마지막 문자만 추가

	list<Content>::iterator itContent1 = this->lcContents.begin();
	list<Content>::iterator itContent2 = p_cpRule->lcContents.begin();

	if (this->getProt() != p_cpRule->getProt())
		g_err((char*)"Rule::joinSingleContent() : protocol differ!!");

	if (this->getField() != p_cpRule->getField())
		g_err((char*)"Rule::joinSingleContent() : field differ!!");

	itContent1->join(&(*itContent2));
}
//#######################################################################
void Rule::joinMultiContent(Rule* p_cpRule)
{
	///p_cpRule의 모든 content 추가 후 고유화
	
	list<Content>::reverse_iterator itContent;

	if (this->getProt() != p_cpRule->getProt())
		g_err((char*)"Rule::joinMultiContent() : protocol differ!!");

	itContent = p_cpRule->lcContents.rbegin();
	
	this->insert(&(*itContent));
}
//#######################################################################
u_int32_t Rule::getSingleContentLength()
{
	list<Content>::iterator itContent = this->lcContents.begin();
	return itContent->getLength();

}
//#######################################################################
u_int32_t Rule::getMultiContentCount()
{
	return this->getContentSize();
}

//#######################################################################
int Rule::cmpContent(Rule* p_cpRule)
{
	//p_cRule와 비교하여 갯수가 적으면 -1 크면 1, 
	//갯수가 같고 길이가 짧으면 -1, 크면 1, 
	//갯수와 길이가 같고 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 
	//갯수, 길이, 내용도 같은면 0

	list<Content>::iterator itContent1; 
	list<Content>::iterator itContent2; 


	if (this->getContentSize() < p_cpRule->getContentSize()) return -1;
	if (this->getContentSize() > p_cpRule->getContentSize()) return 1;

	for (itContent1 = this->getContentsListBegin(), itContent2 = p_cpRule->getContentsListBegin();
			(itContent1 != this->getContentsListEnd()) && (itContent2 != p_cpRule->getContentsListEnd());
				itContent1++, itContent2++)
	{
		if (itContent1->cmpContent(&(*itContent2)) < 0) return -1;
		if (itContent1->cmpContent(&(*itContent2)) > 0) return 1;
	}
	return 0;
}
//#######################################################################
bool Rule::isJoinableSingleContent(Rule* p_cpRule)
{
	//각 rule의 첫번째 content를 대상으로 공통 부분이 존재하는지 여부, 단 길이가 1이면 무조건 결합 가능

	list<Content>::iterator itContent1 = this->getContentsListBegin();
	list<Content>::iterator itContent2 = p_cpRule->getContentsListBegin();
	
	if (itContent1->vcChars.size() != itContent2->vcChars.size())	g_err((char*)"Rule::isJoinableFirstContent() differ content size");

	if (itContent1->vcChars.size() == 1) return true;
	
	return itContent1->isJoinable(&(*itContent2));
}
//#######################################################################
bool Rule::isJoinableMultiContent(Rule* p_cpRule)
{
	//자신과 p_cpRule의 conten set 교집합의 길이가 자신의 길이 - 1 이면 참

	list<Content>::iterator itContent1;
	list<Content>::iterator itContent2;

	if (this->getContentSize() != p_cpRule->getContentSize())	g_err((char*)"Rule::isJoinableMultiContent() differ rule size");

	if (this->getContentSize() == 1) return true;

	itContent1 = this->getContentsListBegin();
	itContent2 = p_cpRule->getContentsListBegin();

	itContent1++;
	for (;(itContent1->getID() == itContent2->getID()) && (itContent1 != this->getContentsListEnd()) ; ++itContent1, ++itContent2 );
	
	if (itContent1 == this->getContentsListEnd())
	{
		return true;
	}
	return false;
}
//#######################################################################
bool Rule::isJoinableProtSingle(Rule* p_cpRule)
{
	//동일한 프로토콜, 필드이면 OK

	if (this->getProt() != p_cpRule->getProt()) return false;
	if (this->getField() != p_cpRule->getField()) return false;
	return true;

}
//#######################################################################
bool Rule::isJoinableProtMulti(Rule* p_cpRule)
{
	//동일한 프로토콜이면 OK
	
	if (this->getProt() != p_cpRule->getProt()) return false;
	return true;
}
//#######################################################################
bool Rule::isDuplicate(SequenceVector* p_cpSequenceVector)
{
	//한sequence에서 여러번 출현하면 참

	vector<Sequence>::iterator itSequence;
	
	for(itSequence = p_cpSequenceVector->vcSequence.begin(); itSequence!=p_cpSequenceVector->vcSequence.end(); itSequence++)
	{
		if (this->getProt() != itSequence->getContentProt()) continue;			
		if (this->getField() != itSequence->getContentField()) continue;	//필드까지 동일한 해야 함

		if (itSequence->getNumberofExistence(this) > 1)
			return true;
	}
	return false;
}
//#######################################################################
bool Rule::isFixContent()
{
	list<Content>::iterator itContent;

	for (itContent = this->getContentsListBegin(); itContent != this->getContentsListEnd(); ++itContent)
	{
		if (!itContent->isFixContent())
		{
			return false;
		}
	}
	return true;
}
//#######################################################################
void Rule::setSingleSuspectSet(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성		
	
	int iIndex;
	list<Content>::iterator itContent;
	int iOffset;
	Suspect cSuspectTemp;

	
	for (iIndex = 0; iIndex < p_cpSequenceVector->vcSequence.size(); iIndex++)									//자신의 content가 sequence에 포함되면 sequence id와 offset를 용의 집합에 추가
	{
		if (p_cpSequenceVector->vcSequence[iIndex].getContentProt() != this->getProt()) continue;				//sequence와 rule의 프로토콜이 다르면 skip
		if (p_cpSequenceVector->vcSequence[iIndex].getContentField() != this->getField()) continue;				//sequence 필드에 ruel 필드가 다르면 skip
		
		iOffset = 0;	//최초 처음부터 탐색
		
		itContent = this->getContentsListBegin();

		iOffset = p_cpSequenceVector->vcSequence[iIndex].cContent.isInclude(iOffset, &(*itContent));		// content의 iOffset부터 itContent를 찾음. 성공하면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴

		if (iOffset)				//탐색 성공
		{
			cSuspectTemp.reset();
			cSuspectTemp.setSusID(iIndex);							//seqID 저장
			cSuspectTemp.setSusOffset(iOffset-itContent->getLength());	//offset 저장
			this->scSuspects.insert(cSuspectTemp);
		}
	}
}
//#######################################################################
void Rule::setMultiSuspectSet(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성		

	int iIndex;
	int iOffset;
	Suspect cSuspectTemp;

	for (iIndex = 0; iIndex < p_cpSequenceVector->vcSequence.size(); iIndex++)									//자신의 content가 sequence의 vcMultiContent에 포함되면 sequence id와 offset(vcMultiContent의 인덱스)를 용의 집합에 추가
	{
	//	p_cpSequenceVector->vcSequence[iIndex].print();

		if (p_cpSequenceVector->vcSequence[iIndex].getContentProt() != this->getProt()) continue;				//sequence와 rule의 프로토콜이 다르면 skip

		iOffset = 0;	//최초 처음부터 탐색

		iOffset = p_cpSequenceVector->vcSequence[iIndex].isInclude(iOffset, this);								//ruel의 content list가 sequence의 multiContent에 순서에 맞게 있는지 확인, 성공하면 시작 위치, 실패하면 -1, content ID 사용, 연속되지 않아도 순서만 맞으면 OK

		if (iOffset != -1)				//탐색 성공
		{
			cSuspectTemp.reset();
			cSuspectTemp.setSusID(iIndex);			//seqID 저장
			cSuspectTemp.setSusOffset(iOffset);		//offset 저장
			this->scSuspects.insert(cSuspectTemp);

	//		printf("yes\n");

	//		p_cpSequenceVector->vcSequence[iIndex].print();
	//		this->print();
		}
		else
		{
	//		printf("no\n");
	//		p_cpSequenceVector->vcSequence[iIndex].print();
	//		this->print();
		}

	//	getchar();
	}
}
//#######################################################################
void Rule::setSupportSingle(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp)
{
	//용의 리스를를 활용하여 supp 계산

	set<Suspect>::iterator itSuspect;
	list<Content>::iterator itContent;
	int iTragetSeqID;
	int iStartOffset;
	int iOffset;
	u_int64_t uiFlag;
	u_int64_t uiIncludeFlag;

	int temp;
	this->uiMaxSupp = p_uiMaxSupp;

//	print();
	//용의 리스트만 검사
	uiIncludeFlag=0;
	for (itSuspect = this->scSuspects.begin(); itSuspect != this->scSuspects.end(); )
	{
		
		iTragetSeqID = itSuspect->getSusID();		//용의자
		iStartOffset = itSuspect->getSusOffset();		//용의 sequence에서 출할발 위치

		if (p_cpSequenceVector->vcSequence[iTragetSeqID].getFileID() >= 64)
			g_err((char*)"Rule::setSupportSingle() : max file count is 64");

		itContent = this->getContentsListBegin();			//singel 규칙이기 때문에 첫 content만 비교
		
		iOffset = p_cpSequenceVector->vcSequence[iTragetSeqID].cContent.isInclude(iStartOffset, &(*itContent));
		
		if(iOffset)					//찾음
		{
			uiFlag = 1;
			uiFlag = uiFlag << (p_cpSequenceVector->vcSequence[iTragetSeqID].getFileID());

			if (!(uiIncludeFlag & uiFlag))	//이미 검사된 호스트는 skip!!
				this->increaseSupp();															//supp 증가

			const_cast<Suspect&>(*itSuspect).setSusOffset(iOffset - itContent->getLength());	//offset 갱신
			uiIncludeFlag |= uiFlag;															//호스트 flag 셋

			itSuspect++;
		}
		else						//못찾음
		{
			temp = this->scSuspects.size();

			this->scSuspects.erase(itSuspect++);

			if ((temp - 1) != this->scSuspects.size())
			{
				g_err((char*)"Rule::setSupportSingle() : suspect set delete error");
			}
		}
	}
}
//#######################################################################
void Rule::setSupportMulti(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp)
{
	//용의 리스를를 활용하여 supp 계산
	set<Suspect>::iterator itSuspect;
	int iTragetSeqID;
	int iStartOffset;
	int iOffset;
	u_int64_t uiFlag;
	u_int64_t uiIncludeFlag=0;
	int temp;
	this->uiMaxSupp = p_uiMaxSupp;
	
//	this->print();
	//용의 리스트만 검사
	for (itSuspect = this->scSuspects.begin(); itSuspect != this->scSuspects.end(); )
	{
		iTragetSeqID = itSuspect->getSusID();		//용의자
		iStartOffset = itSuspect->getSusOffset();	//용의 sequence의 multiContent에서 출할발 인덱스 위치

		if (p_cpSequenceVector->vcSequence[iTragetSeqID].getFileID() >= 64)
			g_err((char*)"Rule::setSupportSingle() : max file count is 64");

		//검사
		iOffset = p_cpSequenceVector->vcSequence[iTragetSeqID].isInclude(iStartOffset, this);	//찾으면 시작 인덱스, 실패시 -1

		if(iOffset != -1)					//찾음
		{
			uiFlag = 1;
			uiFlag = uiFlag << (p_cpSequenceVector->vcSequence[iTragetSeqID].getFileID());

			if (!(uiIncludeFlag & uiFlag))	//이미 검사된 호스트는 skip!!
				this->increaseSupp();															//supp 증가

			const_cast<Suspect&>(*itSuspect).setSusOffset(iOffset);	//offset 갱신
			uiIncludeFlag |= uiFlag;															//호스트 flag 셋

			itSuspect++;
		}
		else
		{
			temp = this->scSuspects.size();

			this->scSuspects.erase(itSuspect++);

			if ((temp - 1) != this->scSuspects.size())
			{
				g_err((char*)"Rule::setSupportSingle() : suspect set delete error");
			}
		}
	}
//	this->print();
//	getchar();
}
//#######################################################################
void Rule::setCompleteness(FlowHash* p_cpFlowHash)							
{
	//p_cpFlowHash의 FlowList, PktList를 이용하여 분석율 계산

	list<FlowTwowayContainer*>::iterator itFlow;
	list<PacketContainer*>::iterator itPkt;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;

	//flow 검사
	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	for (itFlow = p_cpFlowHash->m_cFlowTwoWayContainerList.begin();itFlow!=p_cpFlowHash->m_cFlowTwoWayContainerList.end() ;itFlow++ )
	{
		//(*itFlow)->print();
				
		cpFlowTotal->setFlow(cpFlowTotal->getFlow() + 1);
		cpFlowTotal->setPkt(cpFlowTotal->getPkt() + (*itFlow)->forward.dPkts + (*itFlow)->backward.dPkts);
		cpFlowTotal->setByte(cpFlowTotal->getByte() + (*itFlow)->forward.dOctets + (*itFlow)->backward.dOctets);

		if(this->isIndentify(*itFlow))
		{
			cpFlowIdentified->setFlow(cpFlowIdentified->getFlow() + 1);
			cpFlowIdentified->setPkt(cpFlowIdentified->getPkt() + (*itFlow)->forward.dPkts + (*itFlow)->backward.dPkts);
			cpFlowIdentified->setByte(cpFlowIdentified->getByte() + (*itFlow)->forward.dOctets + (*itFlow)->backward.dOctets);
		}
		//getchar();
	}

	//pkt 검사

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	for (itPkt = p_cpFlowHash->m_cPacketContainerList.begin();itPkt!=p_cpFlowHash->m_cPacketContainerList.end() ;itPkt++ )
	{
		//(*itPkt)->pkt.print();

		cpPktTotal->setPkt(cpPktTotal->getPkt() + 1);
		cpPktTotal->setByte(cpPktTotal->getByte() + (*itPkt)->pkt.real_pkt_len);

		if(this->isIndentify(*itPkt))
		{
			cpPktIdentified->setPkt(cpPktIdentified->getPkt() + 1);
			cpPktIdentified->setByte(cpPktIdentified->getByte() + (*itPkt)->pkt.real_pkt_len);
		}
	}
}
//#######################################################################
bool Rule::isIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer)
{
	//p_cpFlowTwowayContainer 의 모든 패킷 중 하나라도 분석되면 true

	u_int32_t				uiTempProt = 0;
	SequenceVector			cSequenceListTemp;
	PacketContainer			*PktGO;

	if (cSequenceListTemp.isHTTP(p_cpFlowTwowayContainer))  uiTempProt = PROT_HTTP;
	else if (cSequenceListTemp.isTLS(p_cpFlowTwowayContainer))  uiTempProt = PROT_TLS;
	else uiTempProt = PROT_UNKNOWN;

	if (!(this->getProt() & uiTempProt))		return false;		// 동일한 프로토콜 아니면 false
	
	for ( PktGO = p_cpFlowTwowayContainer->headPkt;  PktGO!=NULL;  PktGO = PktGO->next)	// 모든 packet 순회
	{
		if (this->isIndentify(PktGO))		//하나라도 분석하면 true
			return true;
	}
	return false;
}

//#######################################################################
bool Rule::isIndentify(PacketContainer* p_cpPacketContainer)					
{
	//p_cpPacketContainer의 분석 여부

	Content					cContentTemp;

	if (!(this->cHeader.isIndentify(p_cpPacketContainer))) 	return false;
	
	cContentTemp.reset();
	cContentTemp.concatenateContent(p_cpPacketContainer, -1);				//-1 : 패킷의 모든 payload를 cContentTemp로 복사

	return this->isIdentify(&cContentTemp);
}


//#######################################################################
void Rule::setLocation(SequenceVector* p_cpSequenceVector)
{
	//cpSequenceList를 참조하여 content의 위치 정보 기입

	list<Content>::iterator itContent;
	set<Suspect>::iterator itSuspect;
	vector<Content>::iterator itContentVec;
	int iOffsetStart;
		
	//this->print();
	
	//모든 content 검사
	for (itContent = this->getContentsListBegin(); itContent != this->getContentsListEnd() ; ++itContent)			
	{
		//용의자 sequence만 검사
		for (itSuspect = this->scSuspects.begin(); itSuspect != this->scSuspects.end(); ++itSuspect)
		{
		//	p_cpSequenceVector->vcSequence[itSuspect->getSusID()].print();
			// 용의자 sequence 내 multi content 검사
			for (itContentVec = p_cpSequenceVector->vcSequence[itSuspect->getSusID()].vcMultiContent.begin(); itContentVec != p_cpSequenceVector->vcSequence[itSuspect->getSusID()].vcMultiContent.end(); ++itContentVec)
			{
				if (itContentVec->getID() == itContent->getID())
				{
					iOffsetStart = itContentVec->getOffset();

				//	printf("%d\n",iOffsetStart);

					//offset 작아지는 방향으로
					if (itContent->getOffset() > iOffsetStart )
						itContent->setOffset(iOffsetStart);
					//depth 커지는 방향으로
					if (itContent->getDepth() < (iOffsetStart + itContent->getLength()))
						itContent->setDepth(iOffsetStart + itContent->getLength());
				}
			}
		}
		// depth는 offset으로 부터 상대적 거리
		itContent->setDepth(itContent->getDepth() - itContent->getOffset());
	}
}
//#######################################################################
void Rule::setHeader(SequenceVector* p_cpSequenceVector)
{
	// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 헤더 정보 set

	set<Suspect>::iterator itSuspect;

	for (itSuspect = this->scSuspects.begin(); itSuspect != this->scSuspects.end(); ++itSuspect)
	{
	//	itSuspect->print();
	//	p_cpSequenceVector->vcSequence[itSuspect->getSusID()].print();

		this->cHeader.setHeader(&(p_cpSequenceVector->vcSequence[itSuspect->getSusID()].cHeader));
	}
}
//#######################################################################
bool Rule::isIdentify(Content* p_cpContent)													//flow, pkt 분석하는 것도 이걸로 이용
{
	int iOffsetStart;
	list<Content>::iterator itContent;

	
	for (itContent = this->getContentsListBegin(); itContent != this->getContentsListEnd() ; ++itContent)			//모든 content 검사
	{
		iOffsetStart = p_cpContent->isInclude(itContent->getOffset(), &(*itContent));									//매칭 시 매칭 시작 위치 + content 길이, 실패시 0 리턴
		if (!iOffsetStart) return false;
	}
	return true;
}
//#######################################################################
void Rule::uniqueContent()
{	//자신의 content들을 고유화
	this->lcContents.sort(CompareContent());
	this->lcContents.sort(CompareField());
	this->lcContents.unique(isSameContent());
}
//#######################################################################
void Rule::uniqueField()
{
	//DATA를 제외한 HTTP만 필드별로 정렬 후 가장 길이가 긴 content만 남기고 삭제

	this->uniqueContent();
	this->lcContents.unique(isSameField());
}






//#######################################################################
RuleList::RuleList()
{
	this->reset();
}
//#######################################################################
RuleList::~RuleList()
{
	this->reset();
}
//#######################################################################
void RuleList::reset()
{
	
	uiRuleCount=0;
	lcRules.clear();

	cRuleList_PKT_IdentifiedTraffic.reset();
	cRuleList_PKT_TotalTraffic.reset();

	cRuleList_FLOW_IdentifiedTraffic.reset();
	cRuleList_FLOW_TotalTraffic.reset();
}
//#######################################################################
void RuleList::print()
{
	list<Rule>::iterator itRule;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;


	for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
	{
		itRule->print();
	}
	printf("Total %u = %u rules\n", this->uiRuleCount, lcRules.size());


	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		printf("F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	if (cpPktTotal->getPkt())
	{
		printf("P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) ",
			(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}
}
//#######################################################################
void RuleList::print(char* p_cpFileName)
{
	FILE *fp;
	list<Rule>::iterator itRule;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;

	if ( (fp = fopen(p_cpFileName, "wt")) != NULL )
	{
		for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
		{
			itRule->print(fp);
		}
		fprintf(fp, "Total %u = %u rules\n", this->uiRuleCount, lcRules.size());


		cpFlowTotal = this->getFlowTotalTraffic();
		cpFlowIdentified = this->getFlowIdentifiedTraffic();
		if (cpFlowTotal->getFlow())
		{
			fprintf(fp, "F-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) %.02f(%llu/%llu) ",
				(float)cpFlowIdentified->getFlow() * 100 / cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
				(float)cpFlowIdentified->getPkt() * 100 / cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
				(float)cpFlowIdentified->getByte() * 100 / cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
		}

		cpPktTotal = this->getPktTotalTraffic();
		cpPktIdentified = this->getPktIdentifiedTraffic();
		if (cpPktTotal->getPkt())
		{
			fprintf(fp, "P-Com: %.02f(%llu/%llu) %.02f(%llu/%llu) ",
				(float)cpPktIdentified->getPkt() * 100 / cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
				(float)cpPktIdentified->getByte() * 100 / cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
		}
		fclose(fp);
	}
	else
		g_err((char*)"RuleList::print():fopen error");
}
//#######################################################################
void RuleList::printSnortForm()
{
	list<Rule>::iterator itRule;
	for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
	{
		itRule->printSnortForm();
	}
	printf("Total %u = %u rules\n", this->uiRuleCount, lcRules.size());
}
//#######################################################################
void RuleList::printSnortForm(char* p_cpFileName)
{
	list<Rule>::iterator itRule;
	FILE *fp;
	
	if ( (fp = fopen(p_cpFileName, "wt")) != NULL )
	{
		for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
		{
			itRule->printSnortForm(fp);
		}
		fclose(fp);
	}
	else
		g_err((char*)"RuleList::printSnortForm():fopen error");
}
//#######################################################################
void RuleList::printSnortFormHTML()
{
	list<Rule>::iterator itRule;
	for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
	{
		itRule->printSnortFormHTML();
		printf("\n");
	}
	printf("Total %u = %u rules\n", this->uiRuleCount, lcRules.size());
}
//#######################################################################
void RuleList::printSnortFormHTML(char* p_cpFileName)
{
	list<Rule>::iterator itRule;
	FILE *fp;
	
	if ( (fp = fopen(p_cpFileName, "wt")) != NULL )
	{
		for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
		{
			itRule->printSnortFormHTML(fp);
			fprintf(fp, "\r\n");
		}
		fclose(fp);
	}
	else
		g_err((char*)"RuleList::printSnortFormHTML():fopen error");
}
//#######################################################################
void RuleList::setRuleCount(u_int32_t p_uiRuleCount)
{
	this->uiRuleCount = p_uiRuleCount;
}
//#######################################################################
u_int32_t RuleList::getRuleCount()
{
	return this->uiRuleCount;
}
//#######################################################################
u_int32_t RuleList::getRuleSize()
{
	return this->lcRules.size();
}
//#######################################################################
FPB* RuleList::getPktIdentifiedTraffic()
{
	return &(this->cRuleList_PKT_IdentifiedTraffic);
}
//#######################################################################
FPB* RuleList::getPktTotalTraffic()
{
	return &(this->cRuleList_PKT_TotalTraffic);
}
//#######################################################################
FPB* RuleList::getFlowIdentifiedTraffic()
{
	return &(this->cRuleList_FLOW_IdentifiedTraffic);
}
//#######################################################################
FPB* RuleList::getFlowTotalTraffic()
{
	return &(this->cRuleList_FLOW_TotalTraffic);
}
//#######################################################################
list<Rule>::iterator RuleList::getRuleListBegin()
{
	return this->lcRules.begin();
}
//#######################################################################
list<Rule>::iterator RuleList::getRuleListEnd()
{
	return this->lcRules.end();
}
		
//#######################################################################
u_int32_t RuleList::getStartIndexTargetLength(u_int32_t p_uiTargetLength)
{
	// rule 리스트에서 추출 대상 길이(p_uiTargetLength)가 시작하는 인텍스

	list<Rule>::reverse_iterator itRule;
	u_int32_t uiInedex = this->lcRules.size();
	
	for (itRule=this->lcRules.rbegin();itRule!=this->lcRules.rend() ;++itRule)
	{
		if (itRule->getFirstContentLength() != p_uiTargetLength)
			return uiInedex;

		//printf("%d	%d \n",uiInedex, itRule->getFirstContentLength());
		uiInedex--;
	}
	return 0;
}
//#######################################################################
u_int32_t RuleList::getStartIndexTargetCount(u_int32_t p_uiTargetCount)
{
	// rule 리스트에서 추출 대상 개수(p_uiTargetCount)가 시작하는 인텍스

	list<Rule>::reverse_iterator itRule;
	u_int32_t uiInedex = this->lcRules.size();
	
	for (itRule=this->lcRules.rbegin();itRule!=this->lcRules.rend() ;++itRule)
	{
		if (itRule->getContentSize() != p_uiTargetCount)
			return uiInedex;

		//printf("%d	%d \n",uiInedex, itRule->getFirstContentLength());
		uiInedex--;
	}
	return 0;
}
//#######################################################################
void RuleList::resetSupspects()
{
	list<Rule>::iterator itRule;
	for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
	{
		itRule->resetSupspects();
	}
}
//#######################################################################
void RuleList::insert(Rule* p_cpRule)
{
	//p_cpRule에 ID를 설정하고 lcRules 리스트에 추가, 단, content가 존재하는 경우

	if (p_cpRule->getSingleContentLength() == 0)
		return;
	p_cpRule->setID(this->getRuleCount());
	this->setRuleCount(this->getRuleCount()+1);
	lcRules.push_back(*p_cpRule);
}
//#######################################################################
void RuleList::insert(RuleList* p_cpRuleList)
{
	list<Rule>::iterator itRule;
	for (itRule =p_cpRuleList->lcRules.begin() ;itRule !=p_cpRuleList->lcRules.end() ; ++itRule)
	{
		this->insert(&(*itRule));
	}
}

//#######################################################################
void RuleList::unique()
{
	//프로토콜, content 순으로 정렬 후, 동일한 규칙 하나로 합침
	lcRules.sort(CompareContent());
	lcRules.sort(CompareProt());
	lcRules.unique(isSame());
}
//#######################################################################
void RuleList::uniqueField()
{
	
	list<Rule>::iterator itRule;
	for (itRule =this->lcRules.begin() ;itRule !=this->lcRules.end() ; ++itRule)
	{
		itRule->uniqueField();
	}
}
//#######################################################################
void RuleList::sortFlowLevelCompByte()
{
	lcRules.sort(CompareFlowLevelCompByte());
}
//#######################################################################
void RuleList::sortFlowLevelCompPkt()
{
	lcRules.sort(CompareFlowLevelCompPkt());
}

//#######################################################################
void RuleList::sortContentFix()
{
	lcRules.sort(CompareContentFix());
}
//#######################################################################
void RuleList::sortSupport()
{
	lcRules.sort(CompareSupport());
}

//#######################################################################
void RuleList::extractSingleConentLength1(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceList에 존재하는 protocol, field에 한해 모든 경우(256)의 길이 1인 content를 RuleList에 추가

	vector<Sequence>::iterator itSequence;
	list<u_int32_t> lProtocolList;
	list<u_int32_t>::iterator itProt;
	list<u_int32_t> lFieldList;
	list<u_int32_t>::iterator itField;
	Rule	cTempRule;
	Content	cTempContent;
	int iHex;

	//모든 protocol 추출
	for (itSequence=p_cpSequenceVector->vcSequence.begin();itSequence!=p_cpSequenceVector->vcSequence.end() ;itSequence++ )
	{
		lProtocolList.push_back(itSequence->getContentProt());
	}
	lProtocolList.sort();
	lProtocolList.unique();

	//모든 field 추출
	for (itSequence=p_cpSequenceVector->vcSequence.begin();itSequence!=p_cpSequenceVector->vcSequence.end() ;itSequence++ )
	{
		lFieldList.push_back(itSequence->getContentField());
	}
	lFieldList.sort();
	lFieldList.unique();

	
	//모든 경우에 대해 길이 1 content 생성
	for (itProt=lProtocolList.begin();itProt!=lProtocolList.end() ;itProt++ )
	{
		for (itField=lFieldList.begin();itField!=lFieldList.end() ;itField++ )
		{
			for (iHex = 0; iHex < 256; iHex++)
			{
				cTempContent.reset();
				cTempContent.setProt(*itProt);
				cTempContent.setField(*itField);
				cTempContent.concatenateOneHex(&iHex);
			//	cTempContent.print();
				
				cTempRule.reset();
				cTempRule.insert(&cTempContent);
			//	cTempRule.print();
			
				this->insert(&cTempRule);
			}
		}
	}
}
//#######################################################################
void RuleList::extractSingleConent(u_int32_t p_uiLow, u_int32_t p_uiHigh, RuleList* p_cpRuleList, u_int32_t p_uiTargetContentLength, SequenceVector* cpSequenceList, u_int32_t p_uiMinSupp, u_int32_t p_uiMaxSupp)
{
	//p_cpRuleList 의 low~high rule과 전체 rule을 사용하여 p_uiTargetContentLength+1 content 생성, 생성에 참여한 룰은 삭제하기 위해 supp =0
	
	list<Rule>::iterator itRule1_low, itRule1_high, itRule1_go;
	list<Rule>::iterator itRule2_low, itRule2_high, itRule2_go;

	u_int32_t uiIndex;
	Rule	cTempRule;

	//rule1 set
	for (uiIndex=0,itRule1_low = p_cpRuleList->lcRules.begin();  uiIndex < p_uiLow ;++uiIndex, ++itRule1_low);
	for (itRule1_high=itRule1_low; uiIndex < p_uiHigh ; ++uiIndex, ++itRule1_high);

	//rule2 set
	for (itRule2_low = p_cpRuleList->lcRules.begin(); itRule2_low->getSingleContentLength() < p_uiTargetContentLength ;++itRule2_low);
	itRule2_high = p_cpRuleList->lcRules.end();

	//비교
	for (itRule1_go = itRule1_low; itRule1_go != itRule1_high; itRule1_go++)
	{
		for (itRule2_go = itRule2_low;itRule2_go != itRule2_high; itRule2_go++)
		{
			if (!itRule1_go->isJoinableProtSingle(&(*itRule2_go))) continue;			//동일한 프로토콜, 필드 끼리

			if (itRule1_go->getSingleContentLength() != p_uiTargetContentLength) g_err((char*)"RuleList::extractSingleConent() : traget index error");
			if (itRule2_go->getSingleContentLength() != p_uiTargetContentLength) g_err((char*)"RuleList::extractSingleConent() : traget index error");
					
			if (itRule1_go->isJoinableSingleContent(&(*itRule2_go)))		//각 rule의 첫번째 content를 대상으로 공통 부분이 존재하는지 여부, 단 길이가 1이면 무조건 결합 가능
			{
				cTempRule.reset();
				cTempRule.setIntersectionSuspects(&(*itRule1_go), &(*itRule2_go));	//두 규칙의 용의자 교집합을 추출
				if ((cTempRule.scSuspects.size() == 0) || (cTempRule.scSuspects.size() < p_uiMinSupp)) continue;		//용의자 집합이 0이거나 minSupp보다 작으면 skip!!
				
				cTempRule.insertSingleContent(&(*itRule1_go));		//cTempRule에 itRule1_go의 첫번째 content 전체 insert
				cTempRule.joinSingleContent(&(*itRule2_go));		//cTempRule의 첫번째 content에 itRule2_go의 첫벗째 content 마지막 문자 추가

				if (cTempRule.getSingleContentLength() != (p_uiTargetContentLength+1)) g_err((char*)"RuleList::extractSingleConent() : new rule lenth error");

			//	itRule1_go->print();
			//	itRule2_go->print();
				cTempRule.setSupportSingle(cpSequenceList, p_uiMaxSupp);	// 생성된 rule의 supp값 확인
			
				if (cTempRule.getSupp() >= p_uiMinSupp)				// supp를 만족하면, 추가하고 생성에 참가한 rule들은 supp 0으로 set 
				{
					this->insert(&cTempRule);
					if (itRule1_go->getSupp() <= cTempRule.getSupp())
						itRule1_go->setSupp(0);							//rule 생성에 참여한 rule은 생성된 rule에 포함되므로 삭제 (supp =0) deleteUnderSupport()에서 삭제
					if (itRule2_go->getSupp() <= cTempRule.getSupp())
						itRule2_go->setSupp(0);
				}
			}
		}
	}
}
//#######################################################################
void RuleList::extractMultiConentLength1(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceVector의 multi-content의 각 요소를 추출

	vector<Sequence>::iterator itSequence;
	vector<Content>::iterator itContent;
	Sequence cSequenceTemp;
	Rule	cRuleTemp;

	cSequenceTemp.reset();
	for (itSequence=p_cpSequenceVector->vcSequence.begin();itSequence!=p_cpSequenceVector->vcSequence.end() ;++itSequence)
	{
		for (itContent = itSequence->vcMultiContent.begin(); itContent != itSequence->vcMultiContent.end(); ++itContent)
		{
			cSequenceTemp.vcMultiContent.push_back(*itContent);
		}
	}
	cSequenceTemp.uniqueMultiContentForSameID();


	for (itContent = cSequenceTemp.vcMultiContent.begin(); itContent != cSequenceTemp.vcMultiContent.end(); ++itContent)
	{
		cRuleTemp.reset();
		cRuleTemp.insert(&(*itContent));
	//	cRuleTemp.print();
		this->insert(&cRuleTemp);
	}
}
//#######################################################################
void RuleList::extractMultiConent(u_int32_t p_uiLow, u_int32_t p_uiHigh, RuleList* p_cpRuleList, u_int32_t p_uiTargetContentCount, SequenceVector* cpSequenceList, u_int32_t p_uiMinSupp, u_int32_t p_uiMaxSupp)
{
	//p_cpRuleList 의 전체 rule을 사용하여 p_uiTargetContentCount+1 content 생성, 생성에 참여한 룰은 삭제하기 위해 supp =0

	list<Rule>::iterator itRule1_low, itRule1_high, itRule1_go;
	list<Rule>::iterator itRule2_low, itRule2_high, itRule2_go;

	u_int32_t uiIndex;
	Rule	cTempRule;

	//rule1 set
	for (uiIndex=0,itRule1_low = p_cpRuleList->lcRules.begin();  uiIndex < p_uiLow ;++uiIndex, ++itRule1_low);
	for (itRule1_high=itRule1_low; uiIndex < p_uiHigh ; ++uiIndex, ++itRule1_high);

	//rule2 set
	for (itRule2_low = p_cpRuleList->lcRules.begin(); itRule2_low->getMultiContentCount() < p_uiTargetContentCount ;++itRule2_low);
	itRule2_high = p_cpRuleList->lcRules.end();

	//비교
	for (itRule1_go = itRule1_low; itRule1_go != itRule1_high; itRule1_go++)
	{
		for (itRule2_go = itRule2_low;itRule2_go != itRule2_high; itRule2_go++)
		{
			if (itRule1_go == itRule2_go) continue;								//다중 content에서는 같은 content를 제외

			if (!itRule1_go->isJoinableProtMulti(&(*itRule2_go))) continue;		//동일한 프로토콜이면 OK, 

			if (itRule1_go->getMultiContentCount() != p_uiTargetContentCount) g_err((char*)"RuleList::extractMultiConent() : traget index error");
			if (itRule2_go->getMultiContentCount() != p_uiTargetContentCount) g_err((char*)"RuleList::extractMultiConent() : traget index error");
			
			if (itRule1_go->isJoinableMultiContent(&(*itRule2_go)))		//itRule1_go과 itRule2_go의 content set 교집합의 길이가 p_uiTargetContentCount-1인 경우
			{
				cTempRule.reset();
				cTempRule.setIntersectionSuspects(&(*itRule1_go), &(*itRule2_go));	//두 규칙의 용의자 교집합을 추출
				if ((cTempRule.scSuspects.size() == 0) || (cTempRule.scSuspects.size() < p_uiMinSupp)) continue;		//용의자 집합이 0이거나 minSupp보다 작으면 skip!!

				cTempRule.insertMultiContent(&(*itRule1_go));		//cTempRule에 itRule1_go의 모든 content insert
				cTempRule.joinMultiContent(&(*itRule2_go));			//cTempRule에 itRule2_go의 모든 content insert한후 고유화

				if (cTempRule.getMultiContentCount() != (p_uiTargetContentCount+1))	g_err((char*)"RuleList::extractMultiConent() : new rule lenth error");

			//	itRule1_go->print();
			//	itRule2_go->print();
				cTempRule.setSupportMulti(cpSequenceList, p_uiMaxSupp);			// 생성된 rule의 supp값 확인

			//	cTempRule.print();
			//	getchar();

				if (cTempRule.getSupp() >= p_uiMinSupp)				// supp를 만족하면, 추가하고 생성에 참가한 rule들은 supp 0으로 set 
				{
					this->insert(&cTempRule);
					if (itRule1_go->getSupp() <= cTempRule.getSupp())
						itRule1_go->setSupp(0);							//rule 생성에 참여한 rule은 생성된 rule에 포함되므로 삭제 (supp =0) deleteUnderSupport()에서 삭제
					if (itRule2_go->getSupp() <= cTempRule.getSupp())
						itRule2_go->setSupp(0);
				}
			}
		}
	}
}
//#######################################################################
void RuleList::setSingleSuspectSet(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성		
	
	list<Rule>::iterator itRule;
	
	for (itRule = this->getRuleListBegin(); itRule != this->getRuleListEnd() ; ++itRule)
	{
		itRule->setSingleSuspectSet(p_cpSequenceVector);
	}
}
//#######################################################################
void RuleList::setMultiSuspectSet(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성		
	
	list<Rule>::iterator itRule;
	
	for (itRule = this->getRuleListBegin(); itRule != this->getRuleListEnd() ; ++itRule)
	{
		itRule->setMultiSuspectSet(p_cpSequenceVector);
	}
}

//#######################################################################
void RuleList::setSupportSingle( SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp)
{
	list<Rule>::iterator itRule;
	
	for (itRule = this->getRuleListBegin(); itRule != this->getRuleListEnd() ; ++itRule)
	{
		itRule->setSupportSingle(p_cpSequenceVector, p_uiMaxSupp);
	}
}
//#######################################################################
void RuleList::setSupportMulti( SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp)
{
	list<Rule>::iterator itRule;

	for (itRule = this->getRuleListBegin(); itRule != this->getRuleListEnd() ; ++itRule)
	{
		itRule->setSupportMulti(p_cpSequenceVector, p_uiMaxSupp);
	}
}
//#######################################################################
void RuleList::deleteUnderSupport(u_int32_t p_uiMinSupp)
{
	list<Rule>::iterator itRule;
	
	for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ; )
	{
		if (itRule->getSupp() <  p_uiMinSupp)
		{
			this->lcRules.erase(itRule++);
		}
		else
			itRule++;
	}
}
//#######################################################################
void RuleList::deleteDuplicate(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMinSupp)
{
	//한 sequence에서 여러번 출현하는 rule 삭제

	list<Rule>::iterator itRule;

	//한 sequence에서 여러번 출현하는 rule supp 0으로 set
	for (itRule = this->getRuleListBegin(); itRule != this->getRuleListEnd() ; ++itRule)
	{
		if (itRule->isDuplicate(p_cpSequenceVector))
			itRule->setSupp(0);
	}

	//supp 0인 rule 삭제
	this->deleteUnderSupport(p_uiMinSupp);
	
}
//#######################################################################
void RuleList::trimUnderContentLength(u_int32_t p_uiMinLength, SequenceVector* p_cpSequenceVector)
{
	//MIN_CONTENT_LENGTH 보다 짧은 content 삭제	, 단 모든 용의 sequence의 길이와 동일하면 유지(GET 경우)	
	list<Rule>::iterator itRule;
	set<Suspect>::iterator itSuspect;
	int iDeleteFlag;
	
	for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ;)
	{
		//모든 용의 sequece를 검사하여 규칙의 길이보다 크면 flag set
		iDeleteFlag=0;
		for (itSuspect = itRule->scSuspects.begin(); itSuspect != itRule->scSuspects.end(); ++itSuspect)
		{
			if (itRule->getSingleContentLength() < p_cpSequenceVector->vcSequence[itSuspect->getSusID()].getContentLength())
			{
				iDeleteFlag = 1;
				break;
			}
		}
		
		//flag가 set되어 있고 p_uiMinLength 보다 작으면 삭제
		if (iDeleteFlag && (itRule->getSingleContentLength() <  p_uiMinLength))
		{
			this->lcRules.erase(itRule++);
		}
		else
			itRule++;
	}
}
//#######################################################################
void RuleList::setLocation(SequenceVector* p_cpSequenceVector)
{
	//cpSequenceList를 참조하여 content의 위치 정보 기입

	list<Rule>::iterator itRule;
	
	for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ;++itRule)
	{
		itRule->setLocation(p_cpSequenceVector);
	}
}
//#######################################################################
void RuleList::setHeader(SequenceVector* p_cpSequenceVector)
{
	// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 헤더 정보 set

	//p_cpFlowHash를 참조하여 rule의 헤더 기입
	list<Rule>::iterator itRule;
	list<u_int8_t>::iterator itProt;
	Header* cpHeader;
	
	// 모든 rule에 대해 헤더 정보 set
	for (itRule=this->getRuleListBegin();itRule!=this->getRuleListEnd() ;++itRule)
	{
		itRule->setHeader(p_cpSequenceVector);
	}

	// 만약 프로토콜이 any로 설정되면 모든 경우의 rule 생성
	for (itRule=this->getRuleListBegin();itRule!=this->getRuleListEnd() ;++itRule)
	{
		cpHeader = itRule->getHeader();
		if (cpHeader->getProt() == 0 )
		{
		//	itRule->print();

			for (itProt=cpHeader->getProtListBegin();itProt!=cpHeader->getProtListEnd() ; ++itProt)
			{
				//printf("%d\n",*itProt );
				cpHeader->setProt(*itProt);
				this->insert(&(*itRule));
			}
			itRule->setSupp(0);
		}
	}
	this->deleteUnderSupport(1);
}
//#######################################################################
void RuleList::setCompleteness(FlowHash* p_cpFlowHash)
{
	//실제 원본 트래픽인 p_cpFlowHash을 참조하여 현재 보유한 규칙의 분석률 측정

	list<Rule>::iterator itRule;
	FPB* cpFlowIdentified;	FPB* cpFlowTotal;
	FPB* cpPktIdentified;	FPB* cpPktTotal;
	
	//rule 별 분석
	for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ;++itRule)
	{
		//
	//	if (itRule->getID() != 15576) continue;
		
		itRule->setCompleteness(p_cpFlowHash);

		if (itRule->cRule_FLOW_IdentifiedTraffic.getFlow() == 0)
		{
			itRule->print();
			g_err((char*)"RuleList::setCompleteness() : complete error");
		}
	}

	

	//통합 분석 flow
	list<FlowTwowayContainer*>::iterator itFlow;
	cpFlowTotal = this->getFlowTotalTraffic();
	cpFlowIdentified = this->getFlowIdentifiedTraffic();
	for (itFlow = p_cpFlowHash->m_cFlowTwoWayContainerList.begin();itFlow!=p_cpFlowHash->m_cFlowTwoWayContainerList.end() ;itFlow++ )
	{
		//(*itFlow)->print();
		
		cpFlowTotal->setFlow(cpFlowTotal->getFlow() + 1);
		cpFlowTotal->setPkt(cpFlowTotal->getPkt() + (*itFlow)->forward.dPkts + (*itFlow)->backward.dPkts);
		cpFlowTotal->setByte(cpFlowTotal->getByte() + (*itFlow)->forward.dOctets + (*itFlow)->backward.dOctets);

		for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ;++itRule)
		{
			if(itRule->isIndentify(*itFlow))
			{
				cpFlowIdentified->setFlow(cpFlowIdentified->getFlow() + 1);
				cpFlowIdentified->setPkt(cpFlowIdentified->getPkt() + (*itFlow)->forward.dPkts + (*itFlow)->backward.dPkts);
				cpFlowIdentified->setByte(cpFlowIdentified->getByte() + (*itFlow)->forward.dOctets + (*itFlow)->backward.dOctets);

				break;		// 통합 분석이기 때문에 한번이라도 분석되면 해당 플로우에 대해 더이상 분석하지 않음
			}
		}
	}

	//통합 분석 pkt
	list<PacketContainer*>::iterator itPkt;
	cpPktTotal = this->getPktTotalTraffic();
	cpPktIdentified = this->getPktIdentifiedTraffic();
	for (itPkt = p_cpFlowHash->m_cPacketContainerList.begin();itPkt!=p_cpFlowHash->m_cPacketContainerList.end() ;itPkt++ )
	{
		//(*itPkt)->print();
		
		cpPktTotal->setPkt(cpPktTotal->getPkt() + 1);
		cpPktTotal->setByte(cpPktTotal->getByte() + (*itPkt)->pkt.real_pkt_len);

		for (itRule=this->lcRules.begin();itRule!=this->lcRules.end() ;++itRule)
		{
			if(itRule->isIndentify(*itPkt))
			{
				cpPktIdentified->setPkt(cpPktIdentified->getPkt() + 1);
				cpPktIdentified->setByte(cpPktIdentified->getByte() + (*itPkt)->pkt.real_pkt_len);

				break;			// 통합 분석이기 때문에 한번이라도 분석되면 해당 패킷에 대해 더이상 분석하지 않음
			}
		}
	}
}










//#######################################################################
Sequence::Sequence()
{
	this->reset();
}
//#######################################################################
Sequence::~Sequence()
{
	this->reset();
}
//#######################################################################
void Sequence::reset()
{
	this->uiSequenceID=0;
	this->uiFileID=0;
	this->cPktID.reset();
	this->cHeader.reset();
	this->cContent.reset();
	this->vcMultiContent.clear();
}
//#######################################################################
void Sequence::resetSequenceID()
{
	this->uiSequenceID=0;
}
//#######################################################################
void Sequence::resetPktID()
{
	this->cPktID.reset();
}
//#######################################################################
void Sequence::resetHeader()
{
	this->cHeader.reset();
}		
//#######################################################################
void Sequence::resetContent()
{
	this->cContent.reset();
}
//#######################################################################
void Sequence::resetMultiContent()
{
	this->vcMultiContent.clear();
}
//#######################################################################
void Sequence::print()
{
	int i;
	
	printf("SequenceID : %u	",this->uiSequenceID);
	printf("FileID : %u	",this->uiFileID);
	printf("PktIDList : ");
	this->cPktID.print();
	
	this->cHeader.print();	
	
	printf("\n");
	
	printf("Content : ");
	this->cContent.print();	
	printf("\n");

	for (i = 0;i < this->vcMultiContent.size() ;++i )
	{
		printf("Multi-Content[%d] : ",i);
		vcMultiContent[i].print();
		printf("\n");
	}
}
//#######################################################################
void Sequence::setSequenceID(u_int32_t p_uiSequenceID)
{
	this->uiSequenceID = p_uiSequenceID;
}
//#######################################################################
void Sequence::setFileID(u_int32_t p_uiFileID)
{
	this->uiFileID = p_uiFileID;
}
//#######################################################################
void Sequence::setPktID(Suspect	p_cPktID)
{
	this->cPktID.setSusID(p_cPktID.getSusID());
	this->cPktID.setSusOffset(p_cPktID.getSusOffset());
}
//#######################################################################
void Sequence::setHeader(Header* p_cpHeader)
{
	this->cHeader.setHeader(p_cpHeader);
}
//#######################################################################
void Sequence::setContent(Content* p_cpContent)
{
	if (this->getContentLength())
		g_err((char*)"Sequence::setContent() : already has content!");

	this->cContent.setContent(p_cpContent);
}
//#######################################################################
u_int32_t Sequence::getSequenceID()
{
	return this->uiSequenceID;
}
//#######################################################################
u_int32_t Sequence::getFileID()
{
	return this->uiFileID;
}
//#######################################################################
Suspect Sequence::getPktID()
{
	return this->cPktID;
}
//#######################################################################
Header* Sequence::getHeader()
{
	return &(this->cHeader);
}
//#######################################################################
u_int32_t Sequence::getContentProt()
{
	return this->cContent.getProt();
}
//#######################################################################
u_int32_t Sequence::getContentField()
{
	return this->cContent.getField();
}
//#######################################################################
u_int32_t Sequence::getContentLength()
{
	return this->cContent.getLength();
}
//#######################################################################
int Sequence::isInclude(int p_iOffset, Rule* p_cpRule)
{
	//ruel의 content list가 sequence의 multiContent에 순서에 맞게 있는지 확인, 성공하면 시작 위치, 실패하면 -1, content ID 사용, 연속되지 않아도 순서만 맞으면 OK

//	this->print();
//	p_cpRule->print();

	int iIndex;
	list<Content>::iterator itContent;
	int iStartOffset=0;
	bool bFirstFlag=false;

	// p_iOffset이 자신의 multiContent 길이보다 크거나 같으면 return -1
	if (this->vcMultiContent.size() <= p_iOffset) return -1;

	// 검사해야하는 길이(this->vcMultiContent.size()-p_iOffset)가 p_cpRule의 content 개수보다 짧으면 return -1
	if ((this->vcMultiContent.size()-p_iOffset) < p_cpRule->getContentSize()) return -1;

	//검사
	itContent = p_cpRule->getContentsListBegin();
	for (iIndex = p_iOffset; iIndex < this->vcMultiContent.size() ; ++iIndex)
	{
		if (this->vcMultiContent[iIndex].getID() == itContent->getID())
		{
			if (bFirstFlag == false)	//첫번째 매칭 위치 기억
			{
				iStartOffset = iIndex;
				bFirstFlag = true;
			}
			itContent++;
		}
		if (itContent == p_cpRule->getContentsListEnd())
		{
			return iStartOffset;
		}
	}
	return -1;
}
//#######################################################################
int Sequence::cmpContent(Sequence p_cSequence)	//p_cSequence와 비교하여 길이가 짧으면 -1, 크면 1, 길이가 같으면 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 길이도 같고 내용도 같은면 0
{
	return this->cContent.cmpContent(&p_cSequence.cContent);
}
//#######################################################################
u_int32_t Sequence::getNumberofExistence(Rule* p_cpRule)	//p_cpRule이 Sequence에 관찰되는 횟수 리턴
{
	int iOffset = 0;
	int NOE=0;
	list<Content>::iterator itContent;

	while (iOffset < this->getContentLength())
	{
		for (itContent = p_cpRule->getContentsListBegin(); itContent != p_cpRule->getContentsListEnd(); ++itContent )
		{
			iOffset = this->cContent.isInclude(iOffset, &(*itContent));		// content의 iOffset부터 itContent를 찾음. 성공하면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴
			if (!iOffset) return NOE;
		}
		NOE++;
	}
	return NOE;
}
//#######################################################################
void Sequence::parserHTTP(SequenceVector* p_cpResultSequenceVector)
{
	//자신의 cContent를 HTTP 필드별로 파싱하여 p_cpResultSequenceVector에 저장

	if (!(this->getContentProt() & PROT_HTTP))
		g_err((char*)"Sequence::parserHTTP() : protocol differ");
	
	Sequence cSequenceTemp;

	//request
	if (this->isHttpReqest())	//HTTP 메소드로 시작하는지 여부
	{
		cSequenceTemp.reset();
		this->parserHTTPMethod(&cSequenceTemp);					//method
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);
		
		cSequenceTemp.reset();
		this->parserHTTPUrl(&cSequenceTemp);					//url
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);

		cSequenceTemp.reset();
		this->parserHTTPHost(&cSequenceTemp);					//host
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);

		cSequenceTemp.reset();
		this->parserHTTPUser(&cSequenceTemp);					//user-agent
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);

		/*
		cSequenceTemp.reset();
		this->parserHTTPReferer(&cSequenceTemp);				//referer
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);

		cSequenceTemp.reset();
		this->parserHTTPCookie(&cSequenceTemp);					//coookie
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);
		*/
	}
	//response
	else if (this->isHttpResponse())	//HTTP 버젼 정보로 시작하는지 여부
	{
		cSequenceTemp.reset();
		this->parserHTTPResponse(&cSequenceTemp);				//response
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);

		cSequenceTemp.reset();
		this->parserHTTPData(&cSequenceTemp);					//data
		cSequenceTemp.setFileID(this->getFileID());
		cSequenceTemp.setHeader(this->getHeader());
		p_cpResultSequenceVector->insert(&cSequenceTemp);
	}
	//fragment packet			
	else
	{
		this->cContent.addField(PROT_HTTP_DATA);
		this->setSequenceID(this->getSequenceID()*100);
		p_cpResultSequenceVector->insert(this);
	}
}
//#######################################################################
bool Sequence::isHttpReqest()
{
	//HTTP request 여부 확인
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"GET", strlen("GET")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"POST", strlen("POST")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"HEAD", strlen("HEAD")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"TRACE", strlen("TRACE")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"PUT", strlen("PUT")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"DELETE", strlen("DELETE")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"OPTION", strlen("OPTION")) == 0) return true;
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"CONNECT", strlen("CONNECT")) == 0) return true;
	return false;
}
//#######################################################################
bool Sequence::isHttpResponse()
{
	//HTTP response 여부 확인
	if (this->getContentLength() < (strlen("HTTP/")+3)) return false;
	
	if (memcmp(&(this->cContent.vcChars[0]), (const void*)"HTTP/", strlen("HTTP/")) == 0)
		if ( ('0' <= this->cContent.vcChars[strlen("HTTP/")]) && (this->cContent.vcChars[strlen("HTTP/")] <= '9') )
			if ( this->cContent.vcChars[strlen("HTTP/")+1] == '.' )
				if ( ('0' <= this->cContent.vcChars[strlen("HTTP/")+2]) && (this->cContent.vcChars[strlen("HTTP/")+2] <= '9') )
					return true;
	return false;
}
//#######################################################################
void Sequence::parserHTTPMethod(Sequence* p_cpResultSequence)
{
	//method 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;

	//start set
	iSart = 0;
	
	//end set
	cContentTemp.reset();
	cContentTemp.concatenateChars((char*)" ", strlen(" "));
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();//전체길이에서 컨텐츠 길이를 빼면, 메서드 내용에 접근 가능
	
	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_METHOD);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPUrl(Sequence* p_cpResultSequence)
{
	//url 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;
	int iEnd1, iEnd2;

	//start set
	cContentTemp.reset();
	cContentTemp.concatenateChars((char*)" ", strlen(" "));
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0) return;
	
	//end set 
	
	cContentTemp.reset();
	cContentTemp.concatenateChars((char*)" HTTP/", strlen(" HTTP/"));
	iEnd1 = this->cContent.isInclude(iSart, &cContentTemp);

	cContentTemp.reset();
	cContentTemp.concatenateChars((char*)"?", strlen("?"));
	iEnd2 = this->cContent.isInclude(iSart, &cContentTemp);

	if ((iEnd1 == 0) && (iEnd2 == 0)) return;
	
	if (iEnd1 && !iEnd2) iEnd = iEnd1 - strlen(" HTTP/");
	else if (!iEnd1 && iEnd2) iEnd = iEnd2 - strlen("?");
	else if (iEnd1 && iEnd2)
	{
		iEnd = (iEnd1 - strlen(" HTTP/") < iEnd2 - strlen("?")) ? iEnd1 - strlen(" HTTP/") : iEnd2 - strlen("?");
	}
	else
		g_err((char*)"Sequence::parserHTTPUrl() : parser error");
		
	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_URL);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPHost(Sequence* p_cpResultSequence)
{
	//host 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	cContentTemp.concatenateChars((char*)"Host: ", strlen("Host: "));
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0) return;
	iSart -= strlen("Host: ");
	
	//end set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_HOST);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPUser(Sequence* p_cpResultSequence)
{
	//user-agent 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	cContentTemp.concatenateChars((char*)"UserAgent: ", strlen("UserAgent: "));
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0)
	{
		cContentTemp.reset();
		iHex = 0x0D;
		cContentTemp.concatenateOneHex(&iHex);
		iHex = 0x0A;
		cContentTemp.concatenateOneHex(&iHex);
		cContentTemp.concatenateChars((char*)"User-Agent: ", strlen("User-Agent: "));
		iSart = this->cContent.isInclude(0, &cContentTemp);
		if (iSart == 0) return;
		iSart -= strlen("User-Agent: ");

	}
	else
		iSart -= strlen("UserAgent: ");
	
	//end set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_USER);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPReferer(Sequence* p_cpResultSequence)
{
	//referer 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	cContentTemp.concatenateChars((char*)"Referer: ", strlen("Referer: "));
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0) return;
	iSart -= strlen("Referer: ");
	
	//end set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_REF);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPCookie(Sequence* p_cpResultSequence)
{
	//cookie 필드만 추출하여 p_cpResultSequence에 저장

	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	cContentTemp.concatenateChars((char*)"Cookie: ", strlen("Cookie: "));
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0) return;
	iSart -= strlen("Cookie: ");
	
	//end set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_COOK);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);
	
	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPResponse(Sequence* p_cpResultSequence)
{
	//data 필드만 추출하여 p_cpResultSequence에 저장
	
	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	iSart = 0;
	
	//end set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iEnd = this->cContent.isInclude(iSart, &cContentTemp);
	if (iEnd == 0) return;
	iEnd -= cContentTemp.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_RESPONSE);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);
	
	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserHTTPData(Sequence* p_cpResultSequence)
{
	//data 필드만 추출하여 p_cpResultSequence에 저장
	
	Content cContentTemp;
	int iSart;
	int iEnd;
	int iHex;

	//start set
	cContentTemp.reset();
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0D;
	cContentTemp.concatenateOneHex(&iHex);
	iHex = 0x0A;
	cContentTemp.concatenateOneHex(&iHex);
	iSart = this->cContent.isInclude(0, &cContentTemp);
	if (iSart == 0) return;
	
	//end set
	iEnd = this->cContent.getLength();

	//추출
	cContentTemp.reset();
	this->cContent.extract(&cContentTemp, iSart, iEnd);		//자신의 cContent에서 iSart~iEnd를 추출하여 cContentTemp에 저장
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_HTTP_DATA);
	
	//sequence content set
	p_cpResultSequence->setContent(&cContentTemp);

	//pkt id set
	this->cPktID.setSusOffset(iSart);
	p_cpResultSequence->setPktID(this->cPktID);
}
//#######################################################################
void Sequence::parserTLS(SequenceVector* p_cpResultSequenceVector)
{
	//자신의 cContent를 TLS 필드별로 파싱하여 p_cpResultSequenceVector에 저장

	if (!(this->getContentProt() & PROT_TLS)) return;

	Sequence cSequenceTemp;
	Content cContentTemp;
	int iIndex = 0;
	int iSart;
	int iEnd;
	char strTemp[5];
	long lSizeTemp;
	
	// TLS 메시지 단위로 파싱
	while ((iIndex < this->getContentLength()) && (isTLSHeader(&(this->cContent.vcChars[iIndex]))))
	{
		cSequenceTemp.reset();
		cContentTemp.reset();

		iSart = iIndex;
		sprintf(strTemp, "%02x%02x", (unsigned)(unsigned char)this->cContent.vcChars[iIndex+3], (unsigned)(unsigned char)this->cContent.vcChars[iIndex+4]);
		lSizeTemp = strtoul(strTemp, NULL, 16);
		iEnd = iSart + 5 + lSizeTemp;	//header(3) + size(2) + data
		if (iEnd > this->getContentLength())	//fragmantation
			iEnd = this->getContentLength();
			
		this->cContent.extract(&cContentTemp, iSart, iEnd);
		if (!cContentTemp.getLength()) return;

		//content  protocol, field set
		cContentTemp.setProt(this->getContentProt());
		if (cContentTemp.vcChars[0] == 0x14) cContentTemp.setField(PROT_TLS_CHANGESPEC);
		else if (cContentTemp.vcChars[0] == 0x15) cContentTemp.setField(PROT_TLS_ALERT);
		else if (cContentTemp.vcChars[0] == 0x16) cContentTemp.setField(PROT_TLS_HANDSHAKE);
		else if (cContentTemp.vcChars[0] == 0x17) cContentTemp.setField(PROT_TLS_APPLICATION);
		else if (cContentTemp.vcChars[0] == 0x18) cContentTemp.setField(PROT_TLS_HEARTBEAT);
		else
			g_err((char*)"Sequence::parserTLS() : TLS field error");

		if ((cContentTemp.getProt() & this->getContentProt()) && (cContentTemp.getField() & PROT_TLS_HANDSHAKE))
		{
			cSequenceTemp.setFileID(this->getFileID());
			cSequenceTemp.setHeader(this->getHeader());
			cSequenceTemp.setContent(&cContentTemp);

			//pkt id set
			this->cPktID.setSusOffset(iSart);
			cSequenceTemp.setPktID(this->cPktID);
					
			//결과 저장
			p_cpResultSequenceVector->insert(&cSequenceTemp);
		}

		iIndex = iEnd;
	}
	if (iIndex == this->getContentLength())
		return;

	/* //handshake만 고려 나머지는 시그니쳐로써 의미가 없음
	//TLS 헤더가 아닌 경우

	cSequenceTemp.reset();
	cContentTemp.reset();

	iSart = iIndex;
	iEnd = this->getContentLength();

	this->cContent.extract(&cContentTemp, iSart, iEnd);
	if (!cContentTemp.getLength()) return;

	//content  protocol, field set
	cContentTemp.setProt(this->getContentProt());
	cContentTemp.setField(PROT_TLS_DATA);
	
	//sequence content set
	cSequenceTemp.setContent(&cContentTemp);

	//자신의 cotnetn filed add
	this->cContent.addField(cSequenceTemp.getContentField());

	//결과 저장
	p_cpResultSequenceVector->insert(&cSequenceTemp);
	*/
}
//#######################################################################
bool Sequence::isTLSHeader(char* p_cpStr)
{
	//p_cpStr을 시작으로 3바이트가 TLS header인지 검사
	if ((*p_cpStr < 0x14) || (*p_cpStr > 0x18)) return false;
	if (*(p_cpStr+1) != 0x03) return false;
	if ((*(p_cpStr+2) > 0x03)) return false;
	return true;
}
//#######################################################################
void Sequence::uniqueMultiContentForSameOffset()
{
	std::stable_sort(vcMultiContent.begin(), vcMultiContent.end(), CompareLength());	
	std::stable_sort(vcMultiContent.begin(), vcMultiContent.end(), CompareOffset());		

	std::vector<Content>::iterator it;
	
	it = std::unique(vcMultiContent.begin(), vcMultiContent.end(), isSameOffset());		//offset 동일한지 여부로 고유화
	vcMultiContent.resize(std::distance(vcMultiContent.begin(), it));
}
//#######################################################################
void Sequence::uniqueMultiContentForSameID()
{
	std::stable_sort(vcMultiContent.begin(), vcMultiContent.end(), CompareID());	

	std::vector<Content>::iterator it;
	
	it = std::unique(vcMultiContent.begin(), vcMultiContent.end(), isSameID());		//ID 동일한지 여부로 고유화
	vcMultiContent.resize(std::distance(vcMultiContent.begin(), it));
}







//#######################################################################
SequenceVector::SequenceVector()
{
	this->reset();
}
//#######################################################################
SequenceVector::~SequenceVector()
{
	this->reset();
}
//#######################################################################
void SequenceVector::reset()
{
	vcSequence.clear();
}

//#######################################################################
void SequenceVector::print()
{
	int iIndex;

	for (iIndex = 0;iIndex < vcSequence.size() ; ++iIndex)
		vcSequence[iIndex].print();
	
	printf("Total %u = %u sequences\n", iIndex, vcSequence.size());
}
//#######################################################################
u_int32_t SequenceVector::getSequenceSize()
{
	return this->vcSequence.size();
}
//#######################################################################
void SequenceVector::load(FlowHash* p_cpFlowHash, int p_iMaxPktCountForward, int p_iMaxPktCountBackward, int p_iMaxSequenceLength)
{
	//p_cpFlowHash에 저장된 fwp를 읽어 vcSequence에 저장 
	u_int32_t				iIndex;			//flow hash 탐색용
	u_int32_t				uiTempProt;		//flow hash를 sequece에 저장할때, protocol를 확인함. isHTTP(), isTLS() 이용
	FlowTwowayContainer		*go, *head;
	PacketContainer			*PktGO;
	Sequence				cSequenceTemp;	//Sequence
	Content					cContentTemp;
	Suspect					cSuspectTemp;
	Header					cHeaderTemp;
	u_int32_t				uiForwardCurrentPkt;
	u_int32_t				uiBackwardCurrentPkt;

	u_int32_t				uiSequenceID = 0;
	u_int32_t				uiPktID = 0;

	for ( iIndex = 0;  iIndex < MAXHASH;  iIndex++ )
	{
		head = &(p_cpFlowHash->m_cpFlowTwowayContainerHT[iIndex]);
		for ( go = head->next;  go != NULL;  go = go->next )				// 모든 flow 순회
		{
			cSequenceTemp.reset();

			//sequence fileID set
			cSequenceTemp.setFileID(go->m_iFileID);
			
			//protocol check
			uiTempProt = 0;
			if (this->isHTTP(go))  uiTempProt = PROT_HTTP;
			else if (this->isTLS(go))  uiTempProt = PROT_TLS;
			else uiTempProt = PROT_UNKNOWN;

			uiForwardCurrentPkt =0;
			uiBackwardCurrentPkt =0;
			for ( PktGO = go->headPkt;  PktGO!=NULL;  PktGO = PktGO->next) //packet
			{
				cSequenceTemp.resetSequenceID();
				cSequenceTemp.resetPktID();
				cSequenceTemp.resetHeader();
				cSequenceTemp.resetContent();
				
				cContentTemp.reset();
				cContentTemp.setProt(uiTempProt);
				cContentTemp.concatenateContent(PktGO, p_iMaxSequenceLength);		//PktGO의 payload 중 p_iMaxSequenceLength 길이만큼을 저장. 단 p_iMaxSequenceLength -1이면 페이로드 전체 복사
				cSequenceTemp.setContent(&cContentTemp);
				
				if(go->isForwardDirection(&PktGO->pkt)) //forward packet
				{
					uiForwardCurrentPkt++;
					if ((p_iMaxPktCountForward == -1) || (uiForwardCurrentPkt <= p_iMaxPktCountForward))
					{
						cSequenceTemp.setSequenceID(uiSequenceID++);
						cSuspectTemp.reset();
						cSuspectTemp.setSusID(uiPktID++);
						cSuspectTemp.setSusOffset(0);
						cSequenceTemp.setPktID(cSuspectTemp);

						cHeaderTemp.reset();
						cHeaderTemp.setHeader(go);
						cSequenceTemp.setHeader(&cHeaderTemp);
						this->insert(&cSequenceTemp);
					}
				}
				else									//backward packet
				{
					uiBackwardCurrentPkt++;
					if ((p_iMaxPktCountBackward == -1) || (uiBackwardCurrentPkt <= p_iMaxPktCountBackward))
					{
						cSequenceTemp.setSequenceID(uiSequenceID++);
						cSuspectTemp.reset();
						cSuspectTemp.setSusID(uiPktID++);
						cSuspectTemp.setSusOffset(0);
						cSequenceTemp.setPktID(cSuspectTemp);

						cHeaderTemp.reset();
						cHeaderTemp.setHeaderReverse(go);
						cSequenceTemp.setHeader(&cHeaderTemp);
						this->insert(&cSequenceTemp);
					}
				}
				if ((p_iMaxPktCountForward != -1) && (p_iMaxPktCountBackward != -1))
					if ((uiForwardCurrentPkt > p_iMaxPktCountForward) && (uiBackwardCurrentPkt > p_iMaxPktCountBackward))
						break;
			}
		}
	}
}
//#############################################################################################
bool SequenceVector::isHTTP(FlowTwowayContainer* p_cpFlow)
{
	PacketContainer			*PktGO;

	PktGO = p_cpFlow->headPkt;

	while (PktGO)
	{
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"GET", strlen("GET"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"POST", strlen("POST"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"HEAD", strlen("HEAD"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"TRACE", strlen("TRACE"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"PUT", strlen("PUT"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"DELETE", strlen("DELETE"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"OPTION", strlen("OPTION"))== 0) return true;
		if (memcmp(PktGO->payload+(PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len), (const void*)"CONNECT", strlen("CONNECT"))== 0) return true;

		PktGO = PktGO->next;
	}
	return false;
}
//#############################################################################################
bool SequenceVector::isTLS(FlowTwowayContainer* p_cpFlow)
{
	int index;
	PacketContainer			*PktGO;

	PktGO = p_cpFlow->headPkt;

	while (PktGO)
	{
		if ( PktGO->pkt.stored_payload_len >= 3)
		{
			
			index = PktGO->pkt.stored_pkt_len - PktGO->pkt.stored_payload_len;
			if ((PktGO->payload[index] >= 0x14) && (PktGO->payload[index] <= 0x18))
				if (((PktGO->payload[index+1] == 0x03) && (PktGO->payload[index+2] == 0x00)) ||
					((PktGO->payload[index+1] == 0x03) && (PktGO->payload[index+2] == 0x01)) ||
					((PktGO->payload[index+1] == 0x03) && (PktGO->payload[index+2] == 0x02)) ||
					((PktGO->payload[index+1] == 0x03) && (PktGO->payload[index+2] == 0x03)))
						return true;
		}
			
		PktGO = PktGO->next;
	}

	return false;
}
//#############################################################################################
void SequenceVector::integrate(RuleList* p_cpRuleList)
{
	list<Rule>::iterator itRule;
	set<Suspect>::iterator itSuspect;

	for (itRule = p_cpRuleList->getRuleListBegin(); itRule != p_cpRuleList->getRuleListEnd(); ++itRule)
	{
	//	itRule->print();
		
		for (itSuspect = itRule->scSuspects.begin(); itSuspect != itRule->scSuspects.end(); ++itSuspect )
		{
	//		itSuspect->print();
			
			// content id set
			itRule->getContentsListBegin()->setID(itRule->getID());
			// content offset set
			itRule->getContentsListBegin()->setOffset(itSuspect->getSusOffset());

			this->vcSequence[itSuspect->getSusID()].vcMultiContent.push_back(*(itRule->getContentsListBegin()));
	//		this->vcSequence[itSuspect->getSusID()].print();
		}
	}
}
//#############################################################################################
void SequenceVector::integrate(SequenceVector* p_cpSequenceVector)
{
	vector<Sequence>::iterator itSequence;
	vector<Content>::iterator itContent;

	for (itSequence = p_cpSequenceVector->vcSequence.begin(); itSequence != p_cpSequenceVector->vcSequence.end(); ++itSequence)
	{
	//	itSequence->print();
		if (!itSequence->vcMultiContent.size()) continue;
		
		for (itContent = itSequence->vcMultiContent.begin(); itContent != itSequence->vcMultiContent.end(); ++itContent )
		{
	//		itContent->print();
			
			// content offset set
			itContent->setOffset(itContent->getOffset() + itSequence->cPktID.getSusOffset());

	//		printf("%d\n", itSequence->cPktID.getSusID());

			this->vcSequence[itSequence->cPktID.getSusID()].vcMultiContent.push_back(*itContent);

	//		this->vcSequence[itSuspect->getSusID()].print();

		}
	}

	//multi content 정렬 offset 기준
	for (itSequence = this->vcSequence.begin(); itSequence != this->vcSequence.end(); ++itSequence)
	{
		itSequence->uniqueMultiContentForSameOffset();
	}
}
//#############################################################################################
void SequenceVector::parser()
{
	//프로토콜 필드별로 sequence 쪼갬
	vector<Sequence>::iterator itSequence;
	SequenceVector	cSequenceVectorTemp;

	cSequenceVectorTemp.reset();
	//파싱 (파싱 성공 여부는 필드 명시 여부로 확인)
	for (itSequence=this->vcSequence.begin()  ;  itSequence!=this->vcSequence.end()  ;  itSequence++ )
	{
	//	itSequence->print();

		//UNKNOWN
		if (itSequence->getContentProt() & PROT_UNKNOWN)
		{
			itSequence->cContent.addField(PROT_UNKNOWN_DATA);
			cSequenceVectorTemp.insert(&(*itSequence));
		}
		//HTTP
		else if (itSequence->getContentProt() & PROT_HTTP)
		{
			itSequence->parserHTTP(&cSequenceVectorTemp);			//	itSequence를 필드별로 파싱하여 cSequenceVectorTemp에 저장 리턴
		}
		//TLS
		else if (itSequence->getContentProt() & PROT_TLS)
		{
			itSequence->parserTLS(&cSequenceVectorTemp);			//	itSequence를 필드별로 파싱하여 cSequenceVectorTemp에 저장 리턴
		}
		else
		{
			g_err((char*)"SequenceVector::parser() : No PROT");
		}
	}

	// 자신 초기화
	this->reset();

	//parse된 sequence 자신으로 복사
	this->insert(&cSequenceVectorTemp);

	//seqID 재 설정
	u_int32_t		uiSequenceID = 0;
	for (itSequence = this->vcSequence.begin(); itSequence != this->vcSequence.end() ; ++itSequence)
	{
		itSequence->setSequenceID(uiSequenceID++);
	}

}
//#######################################################################
void SequenceVector::breadkField()
{
	//field 별 sequence 개수 개산
/*
#define PROT_UNKNOWN				0x00000001
#define PROT_HTTP					0x00000002
#define PROT_TLS					0x00000004

#define PROT_UNKNOWN_DATA			0x00000001

#define PROT_HTTP_METHOD			0x00000001
#define PROT_HTTP_URL				0x00000002
#define PROT_HTTP_HOST				0x00000004
#define PROT_HTTP_USER				0x00000008
#define PROT_HTTP_REF				0x00000010
#define PROT_HTTP_COOK				0x00000020
#define PROT_HTTP_RESPONSE			0x00000040
#define PROT_HTTP_DATA				0x00000080

#define PROT_TLS_CHANGESPEC			0x00000001
#define PROT_TLS_ALERT				0x00000002
#define PROT_TLS_HANDSHAKE			0x00000004
#define PROT_TLS_APPLICATION		0x00000008
#define PROT_TLS_HEARTBEAT			0x00000010
#define PROT_TLS_DATA				0x00000020
*/
	vector<Sequence>::iterator itSequence;
	
	int iPROT_UNKNOWN = 0;	int iPROT_HTTP = 0;	int iPROT_TLS = 0;

	int iPROT_UNKNOWN_DATA = 0;

	int iPROT_HTTP_METHOD = 0;	int iPROT_HTTP_URL = 0;
	int iPROT_HTTP_HOST	 = 0;	int iPROT_HTTP_USER = 0;
	int iPROT_HTTP_REF = 0;	int iPROT_HTTP_COOK = 0;
	int iPROT_HTTP_RESPONSE = 0; int iPROT_HTTP_DATA = 0;

	int iPROT_TLS_CHANGESPEC = 0;	int iPROT_TLS_ALERT = 0;
	int iPROT_TLS_HANDSHAKE = 0;	int iPROT_TLS_APPLICATION = 0;
	int iPROT_TLS_HEARTBEAT = 0;	int iPROT_TLS_DATA = 0;

	for (itSequence=this->vcSequence.begin();itSequence!=this->vcSequence.end() ;itSequence++ )
	{
		if (itSequence->getContentProt() & PROT_UNKNOWN)
		{
			iPROT_UNKNOWN++;
			if (itSequence->getContentField() & PROT_UNKNOWN_DATA)
				iPROT_UNKNOWN_DATA++;
		}
		if (itSequence->getContentProt() & PROT_HTTP)
		{
			iPROT_HTTP++;
			if (itSequence->getContentField() & PROT_HTTP_METHOD)
				iPROT_HTTP_METHOD++;
			if (itSequence->getContentField() & PROT_HTTP_URL)
				iPROT_HTTP_URL++;
			if (itSequence->getContentField() & PROT_HTTP_HOST)
				iPROT_HTTP_HOST++;
			if (itSequence->getContentField() & PROT_HTTP_USER)
				iPROT_HTTP_USER++;
			if (itSequence->getContentField() & PROT_HTTP_REF)
				iPROT_HTTP_REF++;
			if (itSequence->getContentField() & PROT_HTTP_COOK)
				iPROT_HTTP_COOK++;
			if (itSequence->getContentField() & PROT_HTTP_RESPONSE)
				iPROT_HTTP_RESPONSE++;
			if (itSequence->getContentField() & PROT_HTTP_DATA)
				iPROT_HTTP_DATA++;
		}
		
		if (itSequence->getContentProt() & PROT_TLS)
		{
			iPROT_TLS++;
			if (itSequence->getContentField() & PROT_TLS_CHANGESPEC)
				iPROT_TLS_CHANGESPEC++;
			if (itSequence->getContentField() & PROT_TLS_ALERT)
				iPROT_TLS_ALERT++;
			if (itSequence->getContentField() & PROT_TLS_HANDSHAKE)
				iPROT_TLS_HANDSHAKE++;
			if (itSequence->getContentField() & PROT_TLS_APPLICATION)
				iPROT_TLS_APPLICATION++;
			if (itSequence->getContentField() & PROT_TLS_HEARTBEAT)
				iPROT_TLS_HEARTBEAT++;
			if (itSequence->getContentField() & PROT_TLS_DATA)
				iPROT_TLS_DATA++;
		}
	}

	printf("iPROT_UNKNOWN : %d\n",iPROT_UNKNOWN);
		printf("iPROT_UNKNOWN_DATA : %d\n",
			iPROT_UNKNOWN_DATA);
	printf("iPROT_HTTP : %d\n",iPROT_HTTP);
		printf("iPROT_HTTP_METHOD : %d iPROT_HTTP_URL : %d iPROT_HTTP_HOST : %d iPROT_HTTP_USER : %d iPROT_HTTP_REF : %d iPROT_HTTP_COOK : %d iPROT_HTTP_RESPONSE : %d iPROT_HTTP_DATA : %d\n",
			iPROT_HTTP_METHOD, iPROT_HTTP_URL, iPROT_HTTP_HOST, iPROT_HTTP_USER, iPROT_HTTP_REF, iPROT_HTTP_COOK, iPROT_HTTP_RESPONSE, iPROT_HTTP_DATA);
	printf("iPROT_TLS : %d\n",iPROT_TLS);
		printf("iPROT_TLS_CHANGESPEC : %d iPROT_TLS_ALERT : %d iPROT_TLS_HANDSHAKE : %d iPROT_TLS_APPLICATION : %d iPROT_TLS_HEARTBEAT : %d iPROT_TLS_DATA : %d\n",
			iPROT_TLS_CHANGESPEC, iPROT_TLS_ALERT, iPROT_TLS_HANDSHAKE,	iPROT_TLS_APPLICATION, iPROT_TLS_HEARTBEAT, iPROT_TLS_DATA);
}
//#######################################################################
void SequenceVector::insert(Sequence* p_cpSequence)
{
	//p_cpSequence의 ID를 설정하고 vcSequence에 추가 

	if (p_cpSequence->getContentLength())
		vcSequence.push_back(*p_cpSequence);	
}
//#############################################################################################
void SequenceVector::insert(SequenceVector* p_cpSequenceVector)
{
	//p_cpSequenceList의 모든 sequence를 복사

	vector<Sequence>::iterator itSequence;
	
	for (itSequence=p_cpSequenceVector->vcSequence.begin();itSequence!=p_cpSequenceVector->vcSequence.end() ;itSequence++ )
	{
		if (itSequence->getContentLength())
		{
			this->insert(&(*itSequence));
		}
	}
}
//#######################################################################
void SequenceVector::unique()
{
	//fileID, content가 동일하면 하나합침, content, fileId 순으로 정렬
	std::stable_sort(vcSequence.begin(), vcSequence.end(), CompareContent());		//content 기준으로 정렬	 (길이가 짧거나 낮은 알파벳 우선)	
	std::stable_sort(vcSequence.begin(), vcSequence.end(), CompareContentField());	//content field 기준으로 정렬	
	std::stable_sort(vcSequence.begin(), vcSequence.end(), CompareContentProt());	//content protocol 기준으로 정렬	
	std::stable_sort(vcSequence.begin(), vcSequence.end(), CompareFileID());		//fileID 기준으로 정렬	 (작은 숫자 우선)	

	std::vector<Sequence>::iterator it;
	
	it = std::unique(vcSequence.begin(), vcSequence.end(), isSame());		//fileID, protocol, field, content가 동일한지 여부로 고유화
	vcSequence.resize(std::distance(vcSequence.begin(), it));
}
//#######################################################################
void SequenceVector::sortContent()
{
	std::sort(vcSequence.begin(), vcSequence.end(), CompareContent());

	//seqID 재 설정
	vector<Sequence>::iterator itSequence;
	u_int32_t		uiSequenceID = 0;
	for (itSequence = this->vcSequence.begin(); itSequence != this->vcSequence.end() ; ++itSequence)
	{
		itSequence->setSequenceID(uiSequenceID++);
	}
}

