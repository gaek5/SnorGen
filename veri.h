/*###################################################################################################
이름		:	veri

버젼 정보	:	1.0.0(2010-01-11)	(shyoon)	최초작성


기능		:	

주요 함수	:	
				
###################################################################################################*/
#include "include.h"


#ifndef __Veri_h
#define __Veri_h


//#################################################
class FPB
{
	private:
		u_int64_t				flow;
		u_int64_t				pkt;
		u_int64_t				byte;

	public:
		FPB(void){memset(this, 0, sizeof(FPB));};
		FPB(FPB *cpRecord){memcpy(this, cpRecord, sizeof(FPB));};
		~FPB(void){};

		void reset(){memset(this, 0, sizeof(FPB));};
		void print();
		void print(FILE *p_fp);

		void set(FPB *cpRecord){memcpy(this, cpRecord, sizeof(FPB));};
		void setFlow(u_int64_t p_uiFlow);
		void setPkt(u_int64_t p_uiPkt);
		void setByte(u_int64_t p_uiByte);

		u_int64_t getFlow();
		u_int64_t getPkt();
		u_int64_t getByte();
};
//#################################################
class VeriRecord
{
	public:
		FPB						tp;
		FPB						fp;
		FPB						fnMis;
		FPB						fnUn;

	public:
		VeriRecord(void){memset(this, 0, sizeof(VeriRecord));};
		VeriRecord(VeriRecord *cpRecord){memcpy(this, cpRecord, sizeof(VeriRecord));};
		~VeriRecord(void){};

		void reset(){memset(this, 0, sizeof(VeriRecord));};
		void set(VeriRecord* cpRecord){memcpy(this, cpRecord, sizeof(VeriRecord));};
};


#endif
