//#####################################################################
//
//		twowayFlow.h
//		programmed by tmskim
//		2008.11.07
//
//######################################################################

#include <sys/types.h>
#include "packet.h"
#include "util.h"

#ifndef __TwowayFlow_h
#define __TwowayFlow_h

//#################################################
#define PAYLOAD_EXIST	0x01
#define FRAG_PKT		0x02
#define HTTP_PKT		0x04
//#################################################
class FlowStat
{
public:
	struct timeval		start;					// {u_int32_t tv_sec; u_int32_t tv_usec;}
	struct timeval		end;					// {u_int32_t tv_sec; u_int32_t tv_usec;}

	u_int32_t			dPkts;					// O # Packets sent in Duration 
	u_int32_t			dOctets;				// O # Octets sent in Duration 	
	
	u_int8_t			syn;					// O # of SYN packet in flow 
	u_int8_t			fin;					// O # of FIN packet in flow  
	u_int8_t			rst;					// O # of RST packet in flow  
	u_int8_t			ack;					// O # of ACK packet in flow  	
	
	u_int8_t			psh;					// O # of PSH packet in flow  
	u_int8_t			payload;				// O # pkts whose payload are stored or transmitted  

	u_int8_t			con;					// 0 continue count 0-255
	u_int8_t			flag;					// 0 0x01 Payload, 0x02 Fragmented Pkt, 0x04 HTTP

public:
	FlowStat(void){memset(this, 0, sizeof(FlowStat));};
	FlowStat(FlowStat *r){memcpy(this, r, sizeof(FlowStat));};
	~FlowStat(void){};

	void reset(){memset(this, 0, sizeof(FlowStat));};
	void set(FlowStat* r){memcpy(this, r, sizeof(FlowStat));};

	double calcDuration();
	int isContinue();
	void print();
	void print(FILE *fp);
};
//#################################################
#define SRV_DST		0x01
#define SRV_SRC		0x02
#define HTTP		0x04
#define ABNORMAL	0x08
#define FORWARD		0x10
#define BACKWARD	0x20
#define ANAL		0x40
#define WITH_PKT	0x80
//#################################################
class FlowBasic
{
public:
	u_int32_t			srcaddr;				// O Source IP Address 
	u_int32_t			dstaddr;				// O Destination IP Address 
	u_int16_t			srcport;				// O TCP/UDP source port number or equivalent 
	u_int16_t			dstport;				// O TCP/UDP dest port number or equivalent 

	u_int8_t			prot;				    // O IP protocol, e.g., 6=TCP, 17=UDP, ... 
	u_int8_t			flag;					// O 0x01 srv->dst, 0x02 srv->src, 0x04 HTTP, 08 abnormal, 0x10 forward Flow, 0x20 reverse Flow, 0x40 anal, 0x80 flow with pkt
	u_int8_t			con;					// X continue count 0-255
	u_int8_t			pad;					// X ???

public:
	FlowBasic(void){memset(this, 0, sizeof(FlowBasic));};
	FlowBasic(FlowBasic *r){memcpy(this, r, sizeof(FlowBasic));};
	~FlowBasic(void){};

	void reset(){memset(this, 0, sizeof(FlowBasic));};
	void set(FlowBasic* r){memcpy(this, r, sizeof(FlowBasic));};

	int clientPort();
	int serverPort();
	void print();
	void print(FILE *fp);
};
//#################################################
class FlowWithPkt
{
public:
	u_int32_t				f_stored_pkt;	// stored packet count in forward flow (max=10)
	u_int32_t				b_stored_pkt;	// stored packet count in backward flow (max=10)
	u_int8_t				pad1;
	u_int8_t				pad2;
	

public:
	FlowWithPkt(void){memset(this, 0, sizeof(FlowWithPkt));};
	FlowWithPkt(FlowWithPkt *r){memcpy(this, r, sizeof(FlowWithPkt));};
	~FlowWithPkt(void){};

	void reset(){memset(this, 0, sizeof(FlowWithPkt));};
	void set(FlowWithPkt* r){memcpy(this, r, sizeof(FlowWithPkt));};

	void print();
	void print(FILE *fp);
};
//#################################################
#define FLOWANAL_CODE_COUNT					10

#define SIGCODE_HEADER			1
#define SIGCODE_DNS				2
#define SIGCODE_STATISTIC		3
#define SIGCODE_BEHAVIOR		4
#define SIGCODE_PAYLOAD			5
#define SIGCODE_INTEGRATION		6
#define SIGCODE_CORRELATION		7

#define SIGCODE_SERVICE			1
#define SIGCODE_APPLICATION		2
#define SIGCODE_PROTOCOL		3
#define SIGCODE_FUNCTION		4

#define SIGGENERATORIDENTIFIER	1000000000000000ULL
#define SIGIDENTIFIER			100000000000000ULL
#define SIGANALCODE				1000000ULL
//#################################################
class AnalCode
{
public:
	u_int64_t			m_iSigCode;
	u_int32_t			m_iSCode;
	u_int32_t			m_iACode;
	u_int16_t			m_iPCode;
	u_int16_t			m_iFCode;
	u_int32_t			m_iProCode;

public:
	AnalCode(void){memset(this, 0, sizeof(AnalCode));};
	AnalCode(AnalCode *r){memcpy(this, r, sizeof(AnalCode));};
	~AnalCode(void){};

	void reset(){memset(this, 0, sizeof(AnalCode));};
	void set(AnalCode* r){memcpy(this, r, sizeof(AnalCode));};

	void print();
	void print(FILE *fp);
};
#define LIST_OVER_FLOW			0x01
#define ANSWER_EXIST			0x02

#define SERVICE_EXIST			0x10
#define APPLICATION_EXIST		0x20
#define PROTOCOL_EXIST			0x40
#define FUNCTION_EXIST			0x80
//#################################################
class FlowAnal
{
public:
	AnalCode				m_caAnalCodeList[FLOWANAL_CODE_COUNT];
	u_int8_t				m_iCount;
	u_int8_t				m_iFlag;	
	u_int16_t				m_iFlagCode;

	u_int32_t				m_iAnswerProCode;

public:
	FlowAnal(void){memset(this, 0, sizeof(FlowAnal));};
	FlowAnal(FlowAnal *r){memcpy(this, r, sizeof(FlowAnal));};
	~FlowAnal(void){};

	void reset(){memset(this, 0, sizeof(FlowAnal));};
	void set(FlowAnal* r){memcpy(this, r, sizeof(FlowAnal));};

	void setCode(u_int64_t p_iSigCode, u_int32_t p_iSCode, u_int32_t p_iACode, u_int32_t p_iPCode, u_int32_t p_iFCode, u_int32_t p_iProCode);
	void setAnswer(u_int32_t  p_iAnserCode);
	void print();
	void print(FILE *fp);

	void getCode(u_int64_t *p_iSigCode, u_int32_t *p_iSCode, u_int32_t *p_iACode, u_int32_t *p_iPCode, u_int32_t *p_iFCode, u_int32_t *p_iProCode);
	void getFinalCode(u_int64_t *p_iSigSCode, u_int32_t *p_iSCode, u_int64_t *p_iSigACode, u_int32_t *p_iACode, u_int64_t *p_iSigPCode, u_int32_t *p_iPCode, u_int64_t *p_iSigFCode, u_int32_t *p_iFCode, u_int64_t *p_iSigProCode, u_int32_t *p_iProCode);
};
//#################################################
class FlowTwowayContainer
{
public:

	//
	u_int32_t				m_iFileID;
	u_int32_t				m_iFlowID;

	FlowBasic				flow;
	FlowStat				forward;
	FlowStat				backward;
	FlowWithPkt				withpkt;
	FlowAnal				code;

	PacketContainer			*headPkt;
	PacketContainer			*lastPkt;

	FlowTwowayContainer		*next;		

public:
	FlowTwowayContainer(void){memset(this, 0, sizeof(FlowTwowayContainer));};
	FlowTwowayContainer(FlowTwowayContainer *r){memcpy(this, r, sizeof(FlowTwowayContainer));};
	~FlowTwowayContainer(void){};
	void reset(){memset(this, 0, sizeof(FlowTwowayContainer));};

	void set(FlowTwowayContainer* r){memcpy(this, r, sizeof(FlowTwowayContainer));};	
	void set(PacketContainer *r);		//r(pkt)로 flow 설정 FlowBasic만

	void print();
	void print(FILE *fp);
	void setCode(u_int64_t p_iSigCode, u_int32_t p_iSCode, u_int32_t p_iACode, u_int32_t p_iPCode, u_int32_t p_iFCode, u_int32_t p_iProCode);
	void setAnswerProCode(u_int32_t p_iAnswerProCode);

	void update(PacketContainer *r);	//FlowStat 정보 업데이트
	int isForwardDirection(Packet *r);	//forward 인지 검사
	void copyTimeval(struct timeval *dst, unsigned int src_sec, unsigned int src_usec);
	int timeCompare(struct timeval *a, unsigned int b_sec, unsigned int b_usec);

};





#endif
