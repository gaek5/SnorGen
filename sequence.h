#ifndef __sequence_h
#define __sequence_h

#include "include.h"
#include "twowayFlow.h"
#include "packet.h"
#include "loadbar.h"
#include "veri.h"
#include "ip.h"
#include "flowHash.h"
#include "uniqueCount.h"
#include <vector>
#include <list>
#include <map>
#include <set>
#include <algorithm>    // std::search
using namespace std;

class Header;
class Content;
class Suspect;
class Rule;
class RuleList;
class Sequence;
class SequenceVector;
class ContentSequence;
class ContentSequenceList;

#define BASE_SID			1000000

#define COMMON				0
#define FIRST				1
#define NO_FIRST			2

#define HIGHLIGHT_START_1	"<span class='run_hl1'>"
#define HIGHLIGHT_END_1		"</span>"
#define HIGHLIGHT_START_2	"<span class='run_hl2'>"
#define HIGHLIGHT_END_2		"</span>"
#define HIGHLIGHT_START_3	"<span class='run_hl3'>"
#define HIGHLIGHT_END_3		"</span>"

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




//######################################################################
class Header
{
	public:
		typedef struct sAddr
		{
			u_int32_t	uiAddr;
			u_int8_t	uiCIDR;

		}ADDR;

		u_int8_t	uiProtocol;
		list<u_int8_t> liProtocol;
		ADDR		usSrcAddr;
		list<ADDR> lsSrcAddr;
		ADDR		usDstAddr;
		list<ADDR> lsDstAddr;
		u_int16_t	uiSrcPort;
		list<u_int16_t> liSrcPort;
		u_int16_t	uiDstPort;
		list<u_int16_t> liDstPort;

	public:
		Header();
		~Header();
		void reset();
		void print();
		void print(FILE* p_fpFile);
		void print(list<ADDR>* p_lAddr);

		void setProt(u_int8_t p_uiProt);
		void setHeader(Header* p_cpHeader);
		void setHeader(FlowTwowayContainer* p_cFlowTwowayContainer);			//flow의 헤더 정보를 이용하여 cHeader set
		void setHeaderReverse(FlowTwowayContainer* p_cFlowTwowayContainer);		//flow의 헤더 정보를 이용하여 cHeader set
		
		u_int8_t getProt();
		list<u_int8_t>::iterator getProtListBegin();
		list<u_int8_t>::iterator getProtListEnd();

		int cmpHeader(Header* p_cpHeader);										//p_cpHeader와 비교하여 작으면 -1, 크면 1, 같으면 0
		void setMaskSrcAddr(u_int32_t p_uiMask);
		void setMaskDstAddr(u_int32_t p_uiMask);
		u_int32_t getSrcAddrCIDR_start();
		u_int32_t getDstAddrCIDR_start();
		u_int32_t getSrcAddrCIDR_end();
		u_int32_t getDstAddrCIDR_end();
		void finalize();
			struct CompareAddr {																	
				bool operator()(ADDR lhs, ADDR rhs){
					return (ntohl(lhs.uiAddr) > ntohl(rhs.uiAddr));
				}
			};
			struct isSame {																	
				bool operator()(ADDR lhs, ADDR rhs){
					if (ntohl(lhs.uiAddr) == ntohl(rhs.uiAddr))
						return true;
					else
						return false;				
				}
			};
		bool isIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer);
			bool isForwardIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer);
			bool isBackwardIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer);
		bool isIndentify(PacketContainer* p_cpPacketContainer);
};
//######################################################################
class Content
{
	public:
		u_int32_t	uiID;
		
		u_int32_t	uiProtocol;					//HTTP, TLS, UNKNOWN
		u_int32_t	uiField;					//HTTP Field, TLS Field
		vector<char> vcChars;
		
		u_int32_t	uiOffset;
		u_int32_t	uiDepth;
		u_int32_t	uiDistance;
		u_int32_t	uiWithin;
		
	public:
		Content();
		~Content();
		void reset();
		
		void print();												//모든 멤버 변수에 저장된 값을 화면에 출력
		void print(FILE* p_fpFile);									//모든 멤버 변수에 저장된 값을 파일에 출력
		void printContent();										//vcChars에 저장된 문자를 화면에 출력, printable 문자는 그대로, non-printable 문자는 16진수로 출력
		void printContent(FILE* p_fpFile);							//vcChars에 저장된 문자를 파일에 출력, printable 문자는 그대로, non-printable 문자는 16진수로 출력
		void printLocation(int iFlag=COMMON);						//위치 정보 화면에 출력, COMMON 이면 모두 출력, FIRST 이면 첫 content를 의미하며, offset, depth만 출력, NO_FIRST 이면 두번째 이후 content를 의미하며, within만 출력 
		void printLocation(FILE* p_fpFile, int iFlag=COMMON);		//위치 정보 파일에 출력, COMMON 이면 모두 출력, FIRST 이면 첫 content를 의미하며, offset, depth만 출력, NO_FIRST 이면 두번째 이후 content를 의미하며, within만 출력 
		void printSnortForm(int iFlag=COMMON);						//snort 엔진에 바로 적용할 수 있는 형태로 화면에 출력
		void printSnortForm(FILE* p_fpFile, int iFlag=COMMON);		//snort 엔진에 바로 적용할 수 있는 형태로 파일에 출력
		void printSnortFormHTML(int iFlag=COMMON);					//웹페이지에 바로 적용할 수 있는 형태로 화면에 출력
		void printSnortFormHTML(FILE* p_fpFile, int iFlag=COMMON);	//웹페이지에 바로 적용할 수 있는 형태로 파일에 출력

		u_int32_t getID();
		u_int32_t getProt();
		u_int32_t getField();
		u_int32_t getLength();
		u_int32_t getOffset();
		u_int32_t getDepth();
		u_int32_t getDistance();
		u_int32_t getWithin();
		void setID(u_int32_t p_iID);
		void setProt(u_int32_t p_iProt);
		void setField(u_int32_t p_iField);
		void addField(u_int32_t p_iField);
		void setOffset(u_int32_t p_iOffset);
		void setDepth(u_int32_t p_iDepth);
		void setDistance(u_int32_t p_iDistance);
		void setWithin(u_int32_t p_iWithin);
		vector<char>::iterator getCharsVectorBegin();
		vector<char>::iterator getCharsVectorEnd();
		void setContent(Content* p_cpContent);
	
		void concatenateOneChar(char* p_cpChar);									//입력받은 문자를 vcChar에  붙임
		void concatenateChars(char* p_cpChars, int p_iCharsSize);					//입력받은 문자열을 p_iCharsSize 만큼 vcChar에  붙임
		void concatenateOneHex(int* p_cpHex);										//입력받은 16진수를 vcChar에  붙임
		void concatenateContent(PacketContainer *p_cPkt, int p_uiMaxLength);		//p_cPkt의 payload 중 p_uiMaxLength 길이만큼을 저장. 단 p_uiMaxLength -1이면 페이로드 전체 복사

		void extract(Content* p_cpResultContent, int p_iStart, int p_iEnd);			//자신의 cContent에서 p_iStart~p_iEnd를 추출하여 p_cpResultContent에 저장
		
		void join(Content* p_cpContent);		//p_cpContent의 마지막 char을 자신의 vcChars에 추가
		int cmpContent(Content* p_cpContent);	//p_cpContent와 비교하여 길이가 짧으면 -1, 크면 1, 길이가 같으면 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 길이도 같고 내용도 같은면 0
		int isInclude(int p_iOffset, Content* p_cpContent);									//p_cpContent가 자신에게 p_iOffset 이후 포함되면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴 
		int isInclude(int p_iOffset, Content* p_cpContent, int p_iProtocol, int p_iField);	//프로토콜, 필드로 파싱 후 포함여부 확인. p_cpContent가 자신에게 p_iOffset 이후 포함되면 매칭 offset+contetn 길이를 리턴. 실패시 0 리턴 
		bool getIndex(int* p_iStart, int* p_iEnd, int p_iProtocol, int p_iField);			//자신의 content에서 필드 구간을 확인, p_iStart, p_iEnd에 명시
		bool isJoinable(Content* p_cpContent);	// 결합가능한가? 길이 2 이상만 입력, 자신의 마지막 K-1 길이와 대상의 첫 K-1 길이가 동일한지
		
		bool isFixContent();

		void setField();
};
//######################################################################
class Suspect
{
	private:
		u_int32_t	uiSusID;					//검사할 sequence ID
		u_int32_t	uiSusOffset;				//검사 시작 offset
	
	public:
		Suspect();
		~Suspect();
		void reset();
		void print() const;
		void print(FILE* p_fpFile) const;
		
		void setSusID(u_int32_t p_uiSusSeqID);
		void setSusOffset(u_int32_t p_uiSusOffset);

		u_int32_t getSusID()	const;
		u_int32_t getSusOffset() const;

		struct lessSuspect {									//seqID 기준으로 set 정의
			bool operator()(Suspect lhs, Suspect rhs){
				return lhs.getSusID() < rhs.getSusID();
			}
		};
};
//######################################################################
class Rule
{
	public:
		u_int32_t	uiID;									//rule ID, start from 0
		set<Suspect, Suspect::lessSuspect>	scSuspects;		//suspect sequence id set
		u_int32_t	uiSupp;									//number of unique file
		u_int32_t	uiMaxSupp;								//max number of unique file
		u_int32_t	uiProtocol;								//HTTP, TLS, UNKNOWN
		u_int32_t	uiField;								//HTTP Field, TLS Field
		Header		cHeader;								//header
		u_int32_t	uiContentCount;							//index of content for setting ID
		list<Content> lcContents;							//contents list

		FPB		cRule_PKT_IdentifiedTraffic;				//volume of identified traffic in packet-level
		FPB		cRule_PKT_TotalTraffic;						//volume of total traffic in packet-level
		FPB		cRule_FLOW_IdentifiedTraffic;				//volume of identified traffic in flow-level
		FPB		cRule_FLOW_TotalTraffic;					//volume of total traffic in flow-level

	public:
		Rule();
		~Rule();
		void reset();
		
		void print();									//모든 멤버 변수에 저장된 값을 화면에 출력
		void print(FILE* p_fpFile);						//모든 멤버 변수에 저장된 값을 파일에 출력
		void printSnortForm();							//snort 엔진에 바로 적용할 수 있는 형태로 화면에 출력
		void printSnortForm(FILE* p_fpFile);			//snort 엔진에 바로 적용할 수 있는 형태로 파일에 출력			
		void printSnortFormHTML();						//웹페이지에 바로 적용할 수 있는 형태로 화면에 출력
		void printSnortFormHTML(FILE* p_fpFile);		//웹페이지에 바로 적용할 수 있는 형태로 파일에 출력
		void printSuspectSet();							//용의 sequence 집합을 화면에 출력
		void printSuspectSet(FILE* p_fpFile);			//용의 sequence 집합을 파일에 출력
		
		void setID(u_int32_t p_uiID);					//get set 함수
		void setSupp(u_int32_t p_uiSupp);
		void increaseSupp();									
		void setProt(u_int32_t p_uiProt);
		void setField(u_int32_t p_iField);
		u_int32_t getID();
		u_int32_t getSupp();
		u_int32_t getMaxSupp();
		u_int32_t getProt();
		u_int32_t getField();
		u_int32_t getContentSize();
		Header* getHeader();
		list<Content>::iterator getContentsListBegin();
		list<Content>::iterator getContentsListEnd();
		FPB* getPktIdentifiedTraffic();
		FPB* getPktTotalTraffic();
		FPB* getFlowIdentifiedTraffic();
		FPB* getFlowTotalTraffic();

		void setIntersectionSuspects(Rule* p_cpRule1, Rule* p_cpRule2);	//두 규칙의 용의자 교집합을 추출

		void resetSupspects();

		u_int32_t getFirstContentLength();
		
		void insert(Content* p_cpContent);				//p_cpContent에 ID를 설정하고 추가							
		void insertSingleContent(Rule* p_cpRule);		//p_cpRule의 첫번째 content만 추가
		void insertMultiContent(Rule* p_cpRule);		//p_cpRule의 모든 content 추가
		u_int32_t getSingleContentLength();				//rule의 첫번째 content의 길이를 리턴
		u_int32_t getMultiContentCount();				//rule의 content 개수 리턴
		void joinSingleContent(Rule* p_cpRule);			//p_cpRule의 첫번째 content의 마지막 문자만 추가
		void joinMultiContent(Rule* p_cpRule);			//p_cpRule의 모든 content 추가 후 고유화

		int cmpContent(Rule* p_cpRule);							//p_cRule와 비교하여 갯수가 적으면 -1 크면 1, 갯수가 같고 길이가 짧으면 -1, 크면 1, 갯수와 길이가 같고 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 갯수, 길이, 내용도 같은면 0
		
		bool isJoinableSingleContent(Rule* p_cpRule);											//rule의 첫번째 content를 대상으로 공통 부분이 존재하는지 여부, 단 길이가 1이면 무조건 결합 가능
		bool isJoinableMultiContent(Rule* p_cpRule);											//자신과 p_cpRule의 conten set 교집합의 길이가 자신의 길이 - 1 이면 참
		bool isJoinableProtSingle(Rule* p_cpRule);												//동일한 프로토콜, 필드이면 OK
		bool isJoinableProtMulti(Rule* p_cpRule);												//동일한 프로토콜이면 OK
		bool isDuplicate(SequenceVector* p_cpSequenceVector);									//한sequence에서 여러번 출현하면 참

		bool isFixContent();
		void setSingleSuspectSet(SequenceVector* p_cpSequenceVector);								//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성				
		void setMultiSuspectSet(SequenceVector* p_cpSequenceVector);								//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성				
		void setSupportSingle(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp);			
		void setSupportMulti(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp);			
				
		void setLocation(SequenceVector* p_cpSequenceVector);										//cpSequenceList를 참조하여 content의 위치 정보 기입
		void setHeader(SequenceVector* p_cpSequenceVector);																				// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 헤더 정보 set

		void setCompleteness(FlowHash* p_cpFlowHash);											//p_cpFlowHash의 FlowList, PktList를 이용하여 분석율 계산
			bool isIndentify(FlowTwowayContainer* p_cpFlowTwowayContainer);							//p_cpFlowTwowayContainer의 분석 여부
				bool isForwardIdentifyConentList(FlowTwowayContainer* p_cpFlowTwowayContainer);		//lcContents 모두가 p_cpFlowTwowayContainer의 분석 여부
				bool isBackwardIdentifyConentList(FlowTwowayContainer* p_cpFlowTwowayContainer);	//lcContents 모두가 p_cpFlowTwowayContainer의 분석 여부
			bool isIndentify(PacketContainer* p_cpPacketContainer);									//p_cpPacketContainer의 분석 여부
				bool isIdentifyConentList(PacketContainer* p_cpPacketContainer);
		
		bool isIdentify(Content* p_cpContent);
		
		void uniqueContent();									//자신의 content들을 고유화
		void uniqueField();										//DATA를 제외한 HTTP만 필드별로 정렬 후 가장 길이가 긴 content만 남기고 삭제
		
		//stl sort에서는 return false인 경우 자리 바꿈
		struct CompareContent {									//content 기준으로 정렬	
			bool operator()(Content lhs, Content rhs){
				if ((lhs.cmpContent(&rhs)) > 0) return true;
				return false;
			}
		};
		struct CompareField {									//field 기준으로 정렬	
			bool operator()(Content lhs, Content rhs){
				if (lhs.getField() < rhs.getField()) return true;
				return false;
			}
		};
		

		//stl unique에서는 return true인 경우 하나로 합침
		struct isSameContent {									// content, field 이 동일하면 하나로 합침												
			bool operator()(Content lhs, Content rhs){
				if (((lhs.cmpContent(&rhs)) == 0) && (lhs.getField() == rhs.getField()))
					return true;
				else
					return false;				
			}
		};
		struct isSameField {									// field 가 동일하면 하나로 합침												
			bool operator()(Content lhs, Content rhs){
				if ((lhs.getProt() & rhs.getProt()) != PROT_HTTP) return false;
				if ((lhs.getField() & rhs.getField()) & PROT_HTTP_DATA) return false;
				if (lhs.getField() != rhs.getField()) return false;
				return true;				
			}
		};
};
//######################################################################
class RuleList
{
	public:
		u_int32_t	uiRuleCount;								//index of content for setting ID
		list<Rule> lcRules;

		FPB		cRuleList_PKT_IdentifiedTraffic;
		FPB		cRuleList_PKT_TotalTraffic;

		FPB		cRuleList_FLOW_IdentifiedTraffic;
		FPB		cRuleList_FLOW_TotalTraffic;
		
	public:
		RuleList();
		~RuleList();
		void reset();
		void print();
		void print(char* p_cpFileName);
		void printSnortForm();
		void printSnortForm(char* p_cpFileName);
		void printSnortFormHTML();
		void printSnortFormHTML(char* p_cpFileName);

		void setRuleCount(u_int32_t p_uiRuleCount);
		u_int32_t getRuleCount();
		u_int32_t getRuleSize();
		FPB* getPktIdentifiedTraffic();
		FPB* getPktTotalTraffic();
		FPB* getFlowIdentifiedTraffic();
		FPB* getFlowTotalTraffic();
		list<Rule>::iterator getRuleListBegin();
		list<Rule>::iterator getRuleListEnd();

		u_int32_t getStartIndexTargetLength(u_int32_t p_uiTargetLength);	// rule 리스트에서 추출 대상 길이(p_uiTargetLength)가 시작하는 인텍스
		u_int32_t getStartIndexTargetCount(u_int32_t p_uiTargetcount);		// rule 리스트에서 추출 대상 개수(p_uiTargetCount)가 시작하는 인텍스

		void resetSupspects();

		void insert(Rule* p_cpRule);							//p_cpRule에 ID를 설정하고 lcRules 리스트에 추가, 단, content가 존재하는 경우
		void insert(RuleList* p_cpRuleList);
				
		void extractSingleConentLength1(SequenceVector* p_cpSequenceVector);	//p_cpSequenceVector에 존재하는 protocol, field에 한해 모든 경우(256)의 길이 1인 content를 RuleList에 추가
		void extractMultiConentLength1(SequenceVector* p_cpSequenceVector);		//p_cpSequenceVector의 multi-content의 각 요소를 추출
		void extractSingleConent(u_int32_t p_uiLow, u_int32_t p_uiHigh, RuleList* p_cpRuleList, u_int32_t p_uiTargetContentLength, SequenceVector* cpSequenceList, u_int32_t p_uiMinSupp, u_int32_t p_uiMaxSupp);	//p_cpRuleList 의 low~high rule과 전체 rule을 사용하여 p_uiTargetContentLength+1 content 생성, 생성에 참여한 룰은 삭제하기 위해 supp =0
		void extractMultiConent(u_int32_t p_uiLow, u_int32_t p_uiHigh, RuleList* p_cpRuleList, u_int32_t p_uiTargetContentCount, SequenceVector* cpSequenceList, u_int32_t p_uiMinSupp, u_int32_t p_uiMaxSupp);	//p_cpRuleList 의 전체 rule을 사용하여 p_uiTargetContentCount+1 content 생성, 생성에 참여한 룰은 삭제하기 위해 supp =0
		void setSingleSuspectSet(SequenceVector* p_cpSequenceVector);					//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성				
		void setMultiSuspectSet(SequenceVector* p_cpSequenceVector);					//p_cpSequenceVector를 읽어 rule의 용의자 sequence 집합을 구성				
		void setSupportSingle(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp);
		void setSupportMulti(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMaxSupp);
		
		void deleteUnderSupport(u_int32_t p_uiMinSupp);
		void deleteDuplicate(SequenceVector* p_cpSequenceVector, u_int32_t p_uiMinSupp); //한 sequence에서 여러번 출현하는 rule 삭제
		void trimUnderContentLength(u_int32_t p_uiMinLength, SequenceVector* p_cpSequenceVector);				//p_uiMinLength 보다 짧은 content 삭제	, 단 모든 용의 sequence의 길이와 동일하면 유지(GET 경우)	
		
		void setLocation(SequenceVector* p_cpSequenceVector);				//cpSequenceList를 참조하여 content의 위치 정보 기입
		void setHeader(SequenceVector* p_cpSequenceVector);																				// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 헤더 정보 set

		void setCompleteness(FlowHash* p_cpFlowHash);				//개별 규칙별로 분석률 체크
		
		void unique();											//프로토콜, content 순으로 정렬 후, 동일한 규칙 하나로 합침
		void uniqueField();										//필드별로 정렬 후 가장 길이가 긴 content만 남기고 삭제
		void sortFlowLevelCompByte();
		void sortFlowLevelCompPkt();
		void sortContentFix();
		void sortSupport();

		//stl sort에서는 return false인 경우 자리 바꿈
		struct CompareContent {									//content 기준으로 정렬	 (갯수가 적거나 길이가 짧거나 낮은 알파벳 우선)													
			bool operator()(Rule lhs, Rule rhs){
				if (lhs.cmpContent(&rhs) < 0) return true;
				return false;
			}
		};
		struct CompareProt {									//protocol 기준으로 정렬
			bool operator()(Rule lhs, Rule rhs){
				if (lhs.getProt() < rhs.getProt()) return true;
				return false;
			}
		};
		struct CompareFlowLevelCompByte {																	
			bool operator()(Rule lhs, Rule rhs){
				FPB* cpLhsFlowIdentifiedTraffic = lhs.getFlowIdentifiedTraffic();
				FPB* cpRhsFlowIdentifiedTraffic = rhs.getFlowIdentifiedTraffic();
				if(cpLhsFlowIdentifiedTraffic->getByte() > cpRhsFlowIdentifiedTraffic->getByte()) 
					return true;
				return false;
			}
		};
		struct CompareFlowLevelCompPkt {																	
			bool operator()(Rule lhs, Rule rhs){
				FPB* cpLhsFlowIdentifiedTraffic = lhs.getFlowIdentifiedTraffic();
				FPB* cpRhsFlowIdentifiedTraffic = rhs.getFlowIdentifiedTraffic();
				if(cpLhsFlowIdentifiedTraffic->getPkt() > cpRhsFlowIdentifiedTraffic->getPkt()) 
					return true;
				return false;
			}
		};
		struct CompareContentFix {																	
			bool operator()(Rule lhs, Rule rhs){
				if(lhs.isFixContent() && !rhs.isFixContent()) 
					return true;
				return false;
			}
		};
		struct CompareSupport {																	
			bool operator()(Rule lhs, Rule rhs){
				if(lhs.getSupp() > rhs.getSupp()) 
					return true;
				return false;
			}
		};


		//stl unique에서는 return true인 경우 하나로 합침
		struct isSame {											// content, protocol이 동일하면 하나로 합침												
			bool operator()(Rule lhs, Rule rhs){
				if ((lhs.cmpContent(&rhs) == 0) && (lhs.getProt() == rhs.getProt()))
					return true;
				else
					return false;				
			}
		};
};
//######################################################################
class Sequence
{
	public:
	u_int32_t		uiSequenceID;
	u_int32_t		uiFileID;
	Suspect			cPktID;
	Header			cHeader;
	Content			cContent;
	vector<Content> vcMultiContent;

	public:
		Sequence();
		~Sequence();
		void reset();
		void resetSequenceID();
		void resetPktID();
		void resetHeader();
		void resetContent();
		void resetMultiContent();
		void print();
		
		void setSequenceID(u_int32_t p_uiSequenceID);
		void setFileID(u_int32_t p_uiFileID);
		void setPktID(Suspect	p_cPktID);
		void setHeader(Header* p_cpHeader);
		void setContent(Content* p_cpContent);
		
		u_int32_t getSequenceID();
		u_int32_t getFileID();
		Suspect getPktID();
		Header* getHeader();
		u_int32_t getContentProt();
		u_int32_t getContentField();
		u_int32_t getContentLength();

		int isInclude(int p_iOffset, Rule* p_cpRule);									//ruel의 content list가 sequence의 multiContent에 순서에 맞게 있는지 확인, 성공하면 시작 위치, 실패하면 -1, content ID 사용, 연속되지 않아도 순서만 맞으면 OK
		
		int cmpContent(Sequence p_cSequence);							//p_cSequence와 비교하여 길이가 짧으면 -1, 크면 1, 길이가 같으면 작은 16진수를 가지면 -1, 큰 16진수를 가지면 1, 길이도 같고 내용도 같은면 0
		u_int32_t getNumberofExistence(Rule* p_cpRule);					//p_cpRule이 Sequence에 관찰되는 횟수 리턴
						
		void parserHTTP(SequenceVector* p_cpResultSequenceVector);			//자신의 cContent를 HTTP 필드별로 파싱하여 p_cpResultSequenceVector에 저장
			bool isHttpReqest();										//HTTP request 여부 확인
			bool isHttpResponse();										//HTTP response 여부 확인
			void parserHTTPMethod(Sequence* p_cpResultSequence);		//method 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPUrl(Sequence* p_cpResultSequence);			//url 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPHost(Sequence* p_cpResultSequence);			//host 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPUser(Sequence* p_cpResultSequence);			//user-agent 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPReferer(Sequence* p_cpResultSequence);		//referer 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPCookie(Sequence* p_cpResultSequence);		//cookie 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPResponse(Sequence* p_cpResultSequence);		//response 필드만 추출하여 p_cpResultSequence에 저장
			void parserHTTPData(Sequence* p_cpResultSequence);			//data 필드만 추출하여 p_cpResultSequence에 저장
		void parserTLS(SequenceVector* p_cpResultSequenceVector);			//자신의 cContent를 TLS 필드별로 파싱하여 p_cpResultSequenceVector에 저장
			bool isTLSHeader(char* p_cpStr);							//p_cpStr을 시작으로 3바이트가 TLS header인지 검사

		void uniqueMultiContentForSameOffset();							//offset이 동일하면 길이가 긴것만 취함
		void uniqueMultiContentForSameID();								//ID이 동일하면 하나만 취함

		//stl sort에서는 return false인 경우 자리 바꿈
		struct CompareOffset {									//content offset 기준으로 정렬	 (작은 offset 우선)							
			bool operator()(Content lhs, Content rhs){
				if (lhs.getOffset() < rhs.getOffset()) return true;
				return false;
			}
		};
		struct CompareLength {									//content length 기준으로 정렬	 (긴 length 우선)							
			bool operator()(Content lhs, Content rhs){
				if (lhs.getLength() > rhs.getLength()) return true;
				return false;
			}
		};
		struct CompareID {										//content ID 기준으로 정렬	 (작은 ID 우선)							
			bool operator()(Content lhs, Content rhs){
				if (lhs.getID() < rhs.getID()) return true;
				return false;
			}
		};

		//stl unique에서는 return true인 경우 하나로 합침
		struct isSameOffset {											//offset가 동일한지 여부로 고유화									
			bool operator()(Content lhs, Content rhs){
				if (lhs.getOffset() == rhs.getOffset())
					return true;
				else
					return false;				
			}
		};
		struct isSameID {												//ID가 동일한지 여부로 고유화									
			bool operator()(Content lhs, Content rhs){
				if (lhs.getID() == rhs.getID())
					return true;
				else
					return false;				
			}
		};
};
//######################################################################
class SequenceVector
{
	public:
		vector<Sequence> vcSequence;
	
	public:
		SequenceVector();
		~SequenceVector();
		void reset();
		void print();

		u_int32_t getSequenceSize();
		
		void load(FlowHash* p_cpFlowHash, int p_iMaxPktCountForward, int p_iMaxPktCountBackward, int p_iMaxSequenceLength);	//p_cpFlowHash에 저장된 fwp를 읽어 vcSequence에 저장 
			bool isHTTP(FlowTwowayContainer* p_cpFlow);
			bool isTLS(FlowTwowayContainer* p_cpFlow);
		
		void integrate(RuleList* p_cpRuleList);				//p_cpRuleList의 content를 source sequence로 모음
		void integrate(SequenceVector* p_cpSequenceVector);	//p_cpSequenceVector의 multi content를 source pkt로 모음
		
		void parser();										//프로토콜 필드별로 sequence 쪼갬

		void breadkField();									//field 별 sequence 개수 개산

		void insert(Sequence* p_cpSequence);				//p_cpSequence의 ID를 설정하고 vcSequence에 추가 
		void insert(SequenceVector* p_cpSequenceVector);	//p_cpSequenceList의 모든 sequence를 복사

		
		
		
		void unique();											//fileID, content가 동일하면 하나합침, content, fileId 순으로 정렬
		void sortContent();

		//stl sort에서는 return false인 경우 자리 바꿈
		struct CompareContent {									//content 기준으로 정렬	 (길이가 짧거나 낮은 알파벳 우선)							
			bool operator()(Sequence lhs, Sequence rhs){
				if (lhs.cmpContent(rhs) < 0 ) return true;
				return false;
			}
		};
		struct CompareContentField {									//content Field기준으로 정렬	 
			bool operator()(Sequence lhs, Sequence rhs){
				if (lhs.getContentField() < rhs.getContentField()) return true;
				return false;
			}
		};
		struct CompareContentProt {									//content Prot기준으로 정렬	 
			bool operator()(Sequence lhs, Sequence rhs){
				if (lhs.getContentProt() < rhs.getContentProt()) return true;
				return false;
			}
		};
		struct CompareFileID {									//fileID 기준으로 정렬	 (작은 숫자 우선)									
			bool operator()(Sequence lhs, Sequence rhs){
				if (lhs.getFileID() < rhs.getFileID()) return true;
				return false;
			}
		};
		//stl unique에서는 return true인 경우 하나로 합침
		struct isSame {											//fileID, content가 동일한지 여부로 고유화									
			bool operator()(Sequence lhs, Sequence rhs){
				if ((lhs.getFileID() == rhs.getFileID()) 
					&& (lhs.getContentProt() == rhs.getContentProt()) 
					&& (lhs.getContentField() == rhs.getContentField()) 
					&& (lhs.cmpContent(rhs)==0))
					return true;
				else
					return false;				
			}
		};
};

#endif
