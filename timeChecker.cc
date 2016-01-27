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
#include "timeChecker.h"
#include "util.h"

//################################################################
void TimeChecker::startClock()
{
    m_cStartTime = times(&m_stStartTime);
}
//################################################################
void TimeChecker::endClock()
{
	m_cEndTime = times(&m_stEndTime);
}
//################################################################
void TimeChecker::print()
{
   printf("Real Time: %.2fs, User Time %.2fs, System Time %.2fs\n",
	(double)(m_cEndTime - m_cStartTime)/100,
	(double)((m_stEndTime.tms_utime - m_stStartTime.tms_utime) + (m_stEndTime.tms_cutime - m_stStartTime.tms_cutime))/100,
	(double)((m_stEndTime.tms_stime - m_stStartTime.tms_stime) + (m_stEndTime.tms_cstime - m_stStartTime.tms_cstime))/100);
}
//################################################################
void TimeChecker::print(FILE* fp)
{
	 fprintf(fp,"Real Time: %.2fs, User Time %.2fs, System Time %.2fs\r\n",
	(double)(m_cEndTime - m_cStartTime)/100,
	(double)((m_stEndTime.tms_utime - m_stStartTime.tms_utime) + (m_stEndTime.tms_cutime - m_stStartTime.tms_cutime))/100,
	(double)((m_stEndTime.tms_stime - m_stStartTime.tms_stime) + (m_stEndTime.tms_cstime - m_stStartTime.tms_cstime))/100);
}
//################################################################
void TimeChecker::logClock(char* p_cpPreFix, char* p_caDutyPerson, int iPeriod)
{
	char caLogFile[256];
	char caTempStr[256];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = time(NULL);
	struct tm *stTargetTime = localtime( &tCurrentTime );
	
	sprintf(caTempStr,"%s_%s_%s_",program_invocation_short_name,p_cpPreFix,p_caDutyPerson);

	g_setFileName(caLogFile, (char*)"/var/log/",caTempStr,tCurrentTime,(char*)".log", iPeriod);

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d %02d:%02d:%02d - Real Time: %.2fs, User Time %.2fs, System Time %.2fs\nn", 
		stTargetTime->tm_mday, stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec,
		(double)(m_cEndTime - m_cStartTime)/100,
        (double)((m_stEndTime.tms_utime - m_stStartTime.tms_utime) + (m_stEndTime.tms_cutime - m_stStartTime.tms_cutime))/100,
        (double)((m_stEndTime.tms_stime - m_stStartTime.tms_stime) + (m_stEndTime.tms_cstime - m_stStartTime.tms_cstime))/100);
	
	fclose(fpLogFile);
}
