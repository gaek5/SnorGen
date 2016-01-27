/*###################################################################################################
이름		:	TimeChecker

버젼 정보	:	1.0.0(2010-01-14)	(shyoon)	최초작성


기능		:	프로그램 실행 시간 체크, 로깅

주요 함수	:	void startClock();
				시작 시간 체크

				void endClock();
				종료 시간 체크, 화면에 출력

				void logClock(char* p_cpPreFix, char* p_caDutyPerson, int iPeriod);
				시간 정보 로깅
				
###################################################################################################*/
#include "include.h"

#define MIN			60	
#define HOUR		3600
#define DAY			86400
#define WEEK		604800
#define	MONTH		2592000
#define YEAR		31708800
#define DECADE		315360000
#define NONE		0

#ifndef __TimeChecker_h
#define __TimeChecker_h


//#################################################
class TimeChecker
{
	public:
		clock_t		m_cStartTime;
		clock_t		m_cEndTime;
		struct tms	m_stStartTime;
		struct tms	m_stEndTime;
	

	public:
		TimeChecker(void){memset(this, 0, sizeof(TimeChecker));};
		~TimeChecker(void){};

		void reset(){memset(this, 0, sizeof(TimeChecker));};

		void startClock();
		void endClock();

		void print();
		void print(FILE* fp);

		void logClock(char* p_cpPreFix, char* p_caDutyPerson, int iPeriod);
};


	


#endif
