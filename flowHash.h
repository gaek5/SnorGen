#include "include.h"
#include "twowayFlow.h"
#include "veri.h"
#include "loadbar.h"
#include <list>
using namespace std;

#ifndef __FlowHash_h
#define __FlowHash_h

#define	MAX_STORE_PKT		10
#define MAXHASH				32768	

#define SAME_SEQUENCE		0		//완전히 동일한 packet
#define AFTER_REPACKET		1		//re-paketer 처리
//#############################################################################
class FlowHash		
{
	public:
		FlowTwowayContainer		*m_cpFlowTwowayContainerHT;
		
		FPB						m_cFPBToTal;
		FPB						m_cFPBIdentified;

		int						m_iFlowIndex;

		list<FlowTwowayContainer*> m_cFlowTwoWayContainerList;
		list<PacketContainer*> m_cPacketContainerList;

	public:
		FlowHash();
		~FlowHash();

		void reset();
		void resetAnal();
		void recal();										//m_cFPBToTal, m_cFPBIdentified 계산
	
		void print();										//m_cFPBToTal,m_cFPBIdentified 화면에 출력 
		void printDetail();									//fwp 화면에 출력 
		void printFlowList();								//m_cFlowTwoWayContainerList 화면에 출력
		void printPktList();
		void print(char *p_caLogFileName);					//m_cFPBToTal,m_cFPBIdentified 파일에 출력 
		void printDetail(char *p_caLogFileName);			//fwp 파일에 출력 
		void printFlowList(char *p_caLogFileName);			//m_cFlowTwoWayContainerList 파일에 출력
		void printPktList(char *p_caLogFileName);			

		
		u_int32_t loadFlow(char* p_caTragetDirectory);			//p_caTragetDirectory 저장되어 있는 모든 fwp 파일을 hash에 로드하고 파일 개수 리턴
		int loadFlow(char *p_caFlowFileName, int p_iFileCount);	//flow나 fwp를 읽어 메모리에 로드, p_iFileCount를 flow의 fileID에 set
		int loadPktToFlowWithPkt(char *p_caFlowFileName);		//pkt를 읽어 fwp를 메모리에 로드
		void insert(PacketContainer *r);						//r(pkt)를 메모리에 fwp로 로드
		
		
		void store(char *p_caFlowFileName);					//메모리에 로드된 flow나 fwp를 해당 파일에 저장
		void store(char *p_caResultFlowFilePathName, char *p_caResultFlowFileName); //메모리에 로드된 flow나 fwp를 해당 파일에 저장

		void deleteNonData();								//data pkt이 없는 fwp 삭제
		void deleteSynAckRst();								//TCP 중 Syn-AckRst 패킷으로만 구성된 플로우를 삭제
		void deleteTcpOneWay();								//TCP 중 one way 플로우를 삭제
		void deleteRetransmission();						//TCP 중 Retransmission pkt를 삭제 기준 : TCP && 이전 패킷과 2초 이내 발생 && 이전 패킷과 Sequence Num  동일 && paylaod 유
		
		void resetFlowListSortByTime();															//FlowTwowayContainer를 list로 구성하고 forward의 start 기준으로 sort
			struct Compare {																	
				bool operator()(FlowTwowayContainer* lhs, FlowTwowayContainer* rhs)						
				{
					if (lhs->forward.start.tv_sec < rhs->forward.start.tv_sec)
						return true;
					if ((lhs->forward.start.tv_sec == rhs->forward.start.tv_sec) && (lhs->forward.start.tv_usec < rhs->forward.start.tv_usec))
						return true;
					return false;
				}
			};
		void resetPktListSortByTime();
			struct ComparePkt {																	
				bool operator()(PacketContainer* lhs, PacketContainer* rhs)						
				{
					if (lhs->pkt.time_sec < rhs->pkt.time_sec)
						return true;
					if ((lhs->pkt.time_sec == rhs->pkt.time_sec) && (lhs->pkt.time_usec < rhs->pkt.time_usec))
						return true;
					return false;
				}
			};

		int crossOrderResolver(void);
		int crossOrderDetector(FlowBasic flow, PacketContainer *cp_pre_pkt, PacketContainer *cp_go_pkt);
	
	private:
		void insert(FlowTwowayContainer *p_cpFlowTwowayContainer, FILE *p_fpLoad);	//flow를 메모리에 로드 fwp일수도 있기 때문에 file pointer를 같이 넘김
		void insertForFlowWithPkt(PacketContainer *r, FlowTwowayContainer *go);		//go(flow)에 pkt를 붙임
			
		unsigned int hashing(FlowBasic *r);
		int isSameRecord(FlowBasic *a, FlowBasic *b);
		int isSameRecordReverse(FlowBasic *a, FlowBasic *b);
		int isSameRecord(FlowTwowayContainer *a, FlowTwowayContainer *b);
		int isSameRecordReverse(FlowTwowayContainer *a, FlowTwowayContainer *b);

		unsigned int hashing(Packet *r);											//r(pkt)를 이용하여 hash key 생성
		int isSameRecord(Packet *a, FlowBasic *b);									//a(pkt)와 b(flow)와 순방향으로 같은 레코드인지
		int isSameRecordReverse(Packet *a, FlowBasic *b);							//a(pkt)와 b(flow)와 역방향으로 같은 레코드인지

		int isSameRecord(Packet *a, Packet *b);

		int setCode(FlowTwowayContainer* p_cpFlowTwowayContainer);
		void storeToTargetPathEachFlow(char *p_caResultFlowFilePathName);
		void storeToTargetPathUDPFlow(char *p_caResultFlowFilePathName);

		void modRetransmission(FlowTwowayContainer *go, PacketContainer *sameDirectionRecentPkt, PacketContainer *curPkt, int status);
		void modOutoforder(FlowTwowayContainer *go);
};

#endif
