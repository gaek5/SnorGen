/*################################################################################################################
이름		:	util.c

버젼정보	:	1.0.0	(2002_07_05)	tmskim	최초작성
				1.1.0	(2010_01_01)	shyoon	기능추가
				1.2.0	(2010_02_01)	shyoon	기능추가 (g_setFileName)
				1.3.0	(2010_04_07)	shyoon	기능추가 (char* g_setTime(time_t p_cpTime, int p_iUnit))
				1.3.1	(2010_04_12)	shyoon	기능수정 (void g_setTime(char* p_cpStr, time_t p_cpTime, int p_iUnit))
				1.4.0	(2010_04_15)	shyoon	기능추가 (int g_setLogFileName(char* p_caFileName, char* p_caPathName))
				1.5.0	(2011-07-11)	shyoon	기능추가 (int g_setLogFileName(char* p_caFileName, char* p_caPathName, char *p_cpPreFix))
				1.6.0	(2011-10-13)	shyoon	기능추가 (int g_isLabAddr(unsigned int p_uiAddr))
				1.7.0	(2011-10-26)	shyoon	기능추가 (void g_writeLogYear(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime))

기능		:	프로그램에 자주 사용하는 함수를 구현
#################################################################################################################*/
#include "include.h"

#define MIN			60	
#define HOUR		3600
#define DAY			86400
#define WEEK		604800
#define	MONTH		2592000
#define YEAR		31708800
#define DECADE		315360000
#define NONE		0

#ifndef __util_h
#define __util_h
/*################################################################################################################
이름		:	void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime, int p_iUnit);

기능		:	입력으로 들어오는 정보를 이용하여 파일명 생성
				(path)(prefix)(unit) 
				ex)/data/Traffic_Trace/flow/flow_twoway/flow_twoway_2009_10_01_12_12

				unit define
				#define MIN			60	
				#define HOUR		3600
				#define DAY			86400
				#define WEEK		604800
				#define	MONTH		2592000
				#define YEAR		31708800
				#define DECADE		315360000
				#define NONE		0

입력		:	char *p_cpFileName				완성된 파일이름이 저장 될 곳
				char *p_cpPathName				파일이름의 path
				char *p_cpPreFix				파일이름의 prefix
				time_t p_tTargetTime			파일이름의 현재 시간
				int p_iUnit						파일 이름의 단위 (YEAR: 파일이름_2009   DAY: 파일이름_2009_10_01 ........)
#################################################################################################################*/
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime, int p_iUnit);
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix1, char *p_cpPreFix2, time_t p_tTargetTime, int p_iUnit);

/*################################################################################################################
이름		:	void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime, char *p_cpPostFix, int p_iUnit);

기능		:	입력으로 들어오는 정보(postfix 포함)를 이용하여 파일명 생성
				(path)(prefix)(unit)(postfix) 
				ex)/data/Traffic_Trace/flow/flow_twoway/flow_twoway_2009_10_01_12_12
				
				unit define
				#define MIN			60	
				#define HOUR		3600
				#define DAY			86400
				#define WEEK		604800
				#define	MONTH		2592000
				#define YEAR		31708800
				#define DECADE		315360000
				#define NONE		0

입력		:	char *p_cpFileName				완성된 파일이름이 저장 될 곳
				char *p_cpPathName				파일이름의 path
				char *p_cpPreFix				파일이름의 prefix
				time_t p_tTargetTime			파일이름의 현재 시간
				char *p_cpPostFix				파일이름의 postfix
				int p_iUnit						파일 이름의 단위 (YEAR: 파일이름_2009   DAY: 파일이름_2009_10_01 ........)
#################################################################################################################*/
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime, char *p_cpPostFix, int p_iUnit);
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix1, char *p_cpPreFix2, time_t p_tTargetTime, char *p_cpPostFix, int p_iUnit);

/*################################################################################################################
이름		:	void g_writeLogYear(char *p_cpPreFix, char *p_cpStr);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "year"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
#################################################################################################################*/
void g_writeLogYear(char *p_cpPreFix, char *p_cpStr);

/*################################################################################################################
이름		:	void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "month"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009_01

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
#################################################################################################################*/
void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr);

/*################################################################################################################
이름		:	void g_writeLogDay(char *p_cpPreFix, char *p_cpStr);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "day"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009_01_23

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
#################################################################################################################*/
void g_writeLogDay(char *p_cpPreFix, char *p_cpStr);

/*################################################################################################################
이름		:	void g_writeLogYear(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "year"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
				time_t p_tTagetTime				지정시간
#################################################################################################################*/
void g_writeLogYear(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

/*################################################################################################################
이름		:	void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "month"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009_01

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
				time_t p_tTagetTime				지정시간
#################################################################################################################*/
void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

/*################################################################################################################
이름		:	void g_writeLogDay(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

기능		:	입력 받은 p_cpPreFix 이름으로 /var/log 하위에 입력받은 p_cpStr을 logging 한다. 파일 단위는 "day"이다.
				ex)/var/log/프로그램명_(p_cpPreFix)_2009_01_23

입력		:	char *p_cpPreFix				로그파일 prefix
				char *p_cpStr					로그 내용
				time_t p_tTagetTime				지정시간
#################################################################################################################*/
void g_writeLogDay(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime);

/*################################################################################################################
이름		:	void g_err(char* p_cpStr);

기능		:	입력 받은 p_cpStr과 errorno를 출력하고 종료

입력		:	char* p_cpStr					화면에 출력할 에러메세지
#################################################################################################################*/
void g_err(char* p_cpStr);

/*################################################################################################################
이름		:	void g_p(char* p_cpStr);

기능		:	입력 받은 p_cpStr을 출력

입력		:	char* p_cpStr					화면에 출력할 메세지
#################################################################################################################*/
void g_p(char* p_cpStr);

/*################################################################################################################
이름		:	void g_p_time();

기능		:	현재 시각을 화면에 출력한다.
#################################################################################################################*/
void g_p_time();

/*################################################################################################################
이름		:	void g_delete(char* p_cpStr);

기능		:	입력 받은 p_cpStr 파일 이름을 삭제

입력		:	char* p_cpStr					삭제할 파일 이름
#################################################################################################################*/
void g_delete(char* p_cpStr);

/*################################################################################################################
이름		:	int g_setTime(char *p_cpTimeStr);

기능		:	입력 받은 p_cpTimeStr(ex: 2009-12-26-00-00)을 초로 바꿔준다.

입력		:	char* p_cpTimeStr					초로 바꿀 분형태의 시간 스트링

출력		:	int									변환된 초
#################################################################################################################*/
int g_setTime(char *p_cpTimeStr);

/*################################################################################################################
이름		:	void g_setTime(char* p_cpStr, time_t p_cpTime, int p_iUnit)

기능		:	입력 받은 p_cpTime을 string으로 변환 후 p_cpStr에 저장 (ex: 2009-12-26-00-00)

입력		:	char* p_cpStr					저장될 변수
				time_t p_cpTime					변환할 초
				int p_iUnit						단위 

출력		:	
################################################################################################################*/
void g_setTime(char* p_cpStr, time_t p_cpTime, int p_iUnit);

/*################################################################################################################
이름		:	void g_calTime(char *p_cpLogPreFix, struct timeval p_stStartTime, struct timeval p_stEndTime);

기능		:	p_stStartTime과 p_stEndTime차이 값을 계산하여 logging 
				ex)
				/var/log/프로그램 이름_(p_cpLogPreFix)_2009_12_00

입력		:	char* p_cpLogPreFix					로그 prefix
				struct timeval p_stStartTime		start 타임
				struct timeval p_stEndTime			end 타임
#################################################################################################################*/
void g_calTime(char *p_cpLogPreFix, struct timeval p_stStartTime, struct timeval p_stEndTime);

/*################################################################################################################
이름		:	int g_isValidAddr(unsigned int p_uiAddr);

기능		:	입력 받은 IP 주소(p_uiAddr)가 유효한 주소인지 확인

입력		:	unsigned int p_uiAddr				조사하기 위한 IP 주소

출력		:	1								유효
				0								비유효
#################################################################################################################*/
int g_isValidAddr(unsigned int p_uiAddr);

/*################################################################################################################
이름		:	int g_isLocalAddr(unsigned int p_uiAddr);

기능		:	입력 받은 IP 주소(p_uiAddr)가 내부 주소인지 확인 (163.152.207.0 ~ 163.152.239.255)

입력		:	unsigned int p_uiAddr				조사하기 위한 IP 주소

출력		:	1								내부
				0								외부
#################################################################################################################*/
int g_isLocalAddr(unsigned int p_uiAddr);

/*################################################################################################################
이름		:	void g_convertAddrToString(char* p_cpStr, u_int32_t p_ui32Addr);

기능		:	입력 받은 IP 주소(p_ui32Addr)를 스트링 형태로 변환 후 p_cpStr에 저장한다.

입력		:	char* p_cpStr					변환된 스트링이 저장될 곳
				u_int32_t p_ui32Addr			변환되게 월하는 주소
#################################################################################################################*/
void g_convertAddrToString(char* p_cpStr, u_int32_t p_ui32Addr);

/*################################################################################################################
이름		:	u_int32_t g_convertStringtoAddr(char* p_cpStr);

기능		:	입력 받은 스트링 형태의 주소를 숫자로 변환

입력		:	char* p_cpStr					변환할 스트링 형태의 주소

출력		:	u_int32_t						변환된 주소
#################################################################################################################*/
u_int32_t g_convertStringtoAddr(char* p_cpStr);

/*################################################################################################################
이름		:	int g_setLogFileName(char* p_caFileName, char* p_caPathName);

기능		:	입력 받은 패스에서 가장 최근에 수정된 파일이름을 검색

입력		:	char* p_caFileName					찾은 파일 명을 저장할 변수
				char* p_caPathName					찾을 폴더 이름

출력		:	int									1: 찾음     0:파일 없음
#################################################################################################################*/
int g_setLogFileName(char* p_caFileName, char* p_caPathName);

/*################################################################################################################
이름		:	int g_setLogFileName(char* p_caFileName, char* p_caPathName, char *p_cpPreFix);

기능		:	입력 받은 패스에서 가장 최근에 수정된 파일이름을 검색

입력		:	char* p_caFileName					찾은 파일 명을 저장할 변수
				char* p_caPathName					찾을 폴더 이름
				char* p_cpPreFix					찾을 파일의 frefix

출력		:	int									1: 찾음     0:파일 없음
#################################################################################################################*/
int g_setLogFileName(char* p_caFileName, char* p_caPathName, char *p_cpPreFix);

/*################################################################################################################
이름		:	int g_isLabAddr(unsigned int p_uiAddr);

기능		:	입력 받은 IP 주소(p_uiAddr)가 연구실 주소인지 확인 (163.152.219.184 ~ 163.152.219.220)

입력		:	unsigned int p_uiAddr				조사하기 위한 IP 주소

출력		:	1								내부
				0								외부
#################################################################################################################*/
int g_isLabAddr(unsigned int p_uiAddr);

bool isDigit(char ch);			//입력 받은 ch가 숫자 문자(0~9)인지 검사
bool isHexChar(char ch);		//입력 받은 ch가 16진수 문자(a~z or A~Z)인지 검사
#endif
