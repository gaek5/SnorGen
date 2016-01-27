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

기능		:	프로그램에 자주 사용하는 함수를 구현
#################################################################################################################*/
#include "util.h"

#define MAXSTR	256


//######################################################################
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime, int p_iUnit)
{
	struct tm stTargetTime;
	
	memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
	if (p_iUnit == MIN)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d_%02d_%02d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min);
	if (p_iUnit == HOUR)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d_%02d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour);
	if (p_iUnit == DAY)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);

	if (p_iUnit == WEEK)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = stTargetTime.tm_mday - stTargetTime.tm_wday;
		stTargetTime.tm_wday = 0;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);
	}

	if (p_iUnit == MONTH)
		sprintf(p_cpFileName,"%s%s%04d_%02d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1);

	if (p_iUnit == YEAR)
		sprintf(p_cpFileName,"%s%s%04d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900);

	if (p_iUnit == DECADE)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = 1;
		stTargetTime.tm_mon = 0;
		stTargetTime.tm_year = stTargetTime.tm_year - stTargetTime.tm_year%10;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );

		sprintf(p_cpFileName,"%s%s%04d",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900);
	}
	
	if (p_iUnit == NONE)
		sprintf(p_cpFileName,"%s%s",p_cpPathName,p_cpPreFix);

	
//	printf("------------]%s\n",p_cpFileName);

}
//######################################################################
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix1, char *p_cpPreFix2, time_t p_tTargetTime, int p_iUnit)
{
	struct tm stTargetTime;
	
	memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
	if (p_iUnit == MIN)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d_%02d_%02d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min);
	if (p_iUnit == HOUR)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d_%02d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour);
	if (p_iUnit == DAY)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);

	if (p_iUnit == WEEK)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = stTargetTime.tm_mday - stTargetTime.tm_wday;
		stTargetTime.tm_wday = 0;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);
	}

	if (p_iUnit == MONTH)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1);

	if (p_iUnit == YEAR)
		sprintf(p_cpFileName,"%s%s%s%04d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900);

	if (p_iUnit == DECADE)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = 1;
		stTargetTime.tm_mon = 0;
		stTargetTime.tm_year = stTargetTime.tm_year - stTargetTime.tm_year%10;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );

		sprintf(p_cpFileName,"%s%s%s%04d",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900);
	}
	
	if (p_iUnit == NONE)
		sprintf(p_cpFileName,"%s%s%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2);

	
//	printf("------------]%s\n",p_cpFileName);

}
//######################################################################
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix, time_t p_tTargetTime,char *p_cpPostFix, int p_iUnit)
{
	struct tm stTargetTime;
	
	memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
	if (p_iUnit == MIN)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d_%02d_%02d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min,p_cpPostFix);
	if (p_iUnit == HOUR)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d_%02d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour,p_cpPostFix);
	if (p_iUnit == DAY)
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday,p_cpPostFix);
	if (p_iUnit == WEEK)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = stTargetTime.tm_mday - stTargetTime.tm_wday;
		stTargetTime.tm_wday = 0;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
		sprintf(p_cpFileName,"%s%s%04d_%02d_%02d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday,p_cpPostFix);
	}

	if (p_iUnit == MONTH)
		sprintf(p_cpFileName,"%s%s%04d_%02d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1,p_cpPostFix);

	if (p_iUnit == YEAR)
		sprintf(p_cpFileName,"%s%s%04d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900,p_cpPostFix);

	if (p_iUnit == DECADE)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = 1;
		stTargetTime.tm_mon = 0;
		stTargetTime.tm_year = stTargetTime.tm_year - stTargetTime.tm_year%10;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );

		sprintf(p_cpFileName,"%s%s%04d%s",p_cpPathName,p_cpPreFix,
			stTargetTime.tm_year + 1900,p_cpPostFix);
	}


	if (p_iUnit == NONE)
		sprintf(p_cpFileName,"%s%s%s",p_cpPathName,p_cpPreFix,p_cpPostFix);
}
//######################################################################
void g_setFileName(char *p_cpFileName, char *p_cpPathName, char *p_cpPreFix1, char *p_cpPreFix2, time_t p_tTargetTime,char *p_cpPostFix, int p_iUnit)
{
	struct tm stTargetTime;
	
	memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
	if (p_iUnit == MIN)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d_%02d_%02d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min,p_cpPostFix);
	if (p_iUnit == HOUR)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d_%02d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour,p_cpPostFix);
	if (p_iUnit == DAY)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday,p_cpPostFix);
	if (p_iUnit == WEEK)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = stTargetTime.tm_mday - stTargetTime.tm_wday;
		stTargetTime.tm_wday = 0;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );
	
		sprintf(p_cpFileName,"%s%s%s%04d_%02d_%02d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday,p_cpPostFix);
	}

	if (p_iUnit == MONTH)
		sprintf(p_cpFileName,"%s%s%s%04d_%02d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1,p_cpPostFix);

	if (p_iUnit == YEAR)
		sprintf(p_cpFileName,"%s%s%s%04d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900,p_cpPostFix);

	if (p_iUnit == DECADE)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = 1;
		stTargetTime.tm_mon = 0;
		stTargetTime.tm_year = stTargetTime.tm_year - stTargetTime.tm_year%10;
		p_tTargetTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_tTargetTime), sizeof(struct tm) );

		sprintf(p_cpFileName,"%s%s%s%04d%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,
			stTargetTime.tm_year + 1900,p_cpPostFix);
	}


	if (p_iUnit == NONE)
		sprintf(p_cpFileName,"%s%s%s%s",p_cpPathName,p_cpPreFix1,p_cpPreFix2,p_cpPostFix);
}

//######################################################################
void g_writeLogYear(char *p_cpPreFix, char *p_cpStr) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = time(NULL);
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d_%02d %02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_mon +1, stTargetTime->tm_mday, stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}

//######################################################################
void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = time(NULL);
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d_%02d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900, stTargetTime->tm_mon +1); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d %02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_mday, stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}


//######################################################################
void g_writeLogDay(char *p_cpPreFix, char *p_cpStr) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = time(NULL);
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d_%02d_%02d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900, stTargetTime->tm_mon +1, stTargetTime->tm_mday); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}


//######################################################################
void g_writeLogYear(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = p_tTagetTime;
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d_%02d %02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_mon +1, stTargetTime->tm_mday, stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}

//######################################################################
void g_writeLogMonth(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = p_tTagetTime;
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d_%02d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900, stTargetTime->tm_mon +1); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d %02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_mday, stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}


//######################################################################
void g_writeLogDay(char *p_cpPreFix, char *p_cpStr, time_t p_tTagetTime) 
{
	char caLogFile[MAXSTR];
	FILE* fpLogFile = NULL;
	time_t tCurrentTime = p_tTagetTime;
	struct tm *stTargetTime = localtime( &tCurrentTime );

	sprintf(caLogFile, "/var/log/%s_%s_%04d_%02d_%02d.log", program_invocation_short_name, p_cpPreFix, stTargetTime->tm_year + 1900, stTargetTime->tm_mon +1, stTargetTime->tm_mday); 

	if( ( fpLogFile = fopen(caLogFile, "aw") ) == NULL )return;
	
	fprintf( fpLogFile, "%02d:%02d:%02d - [%s]\n", 
		stTargetTime->tm_hour, stTargetTime->tm_min, stTargetTime->tm_sec, p_cpStr );
	fclose(fpLogFile);
}


//######################################################################
void g_err(char* p_cpStr)
{
	printf("ERROR: %s \n", p_cpStr);
	printf("ERROR: %s \n", strerror(errno) );
	exit(1);
}

//######################################################################
void g_p(char* p_cpStr)
{
	printf("STR: %s \n", p_cpStr);
}

//######################################################################
void g_p_time()
{
	struct timeval stTargetTime;
	time_t t2;
	char *cp_Str;
	
	gettimeofday( &stTargetTime, NULL);
	t2 = (time_t)stTargetTime.tv_sec;
	cp_Str = ctime(&t2);
	printf("CurrentTime: %d : %s",  (int) t2, cp_Str);

	printf("CurrentTime: %d : %d \n", stTargetTime.tv_sec, stTargetTime.tv_usec);
}
//######################################################################
void g_delete(char* p_cpStr)
{
	char caDeleteFile[256];

	sprintf(caDeleteFile,"find %s -delete",p_cpStr);
	system(caDeleteFile);
}
//######################################################################
int g_setTime(char *time_str)
{
	struct tm stTargetTime;

	if( !time_str || time_str[0]=='\0' ) return 0;

	memset(&stTargetTime, 0, sizeof(struct tm));
	stTargetTime.tm_year  = atoi( strtok(time_str, "-_") ) - 1900;
	stTargetTime.tm_mon	= atoi( strtok(NULL, "-_") ) - 1;
	stTargetTime.tm_mday	= atoi( strtok(NULL, "-_") );
	stTargetTime.tm_hour	= atoi( strtok(NULL, "-_") );
	stTargetTime.tm_min	= atoi( strtok(NULL, "-_") );

	return mktime(&stTargetTime);
}
//########################################################################################################
void g_setTime(char* p_cpStr, time_t p_cpTime, int p_iUnit)
{
	struct tm stTargetTime;
	
	memcpy(&stTargetTime, localtime(&p_cpTime), sizeof(struct tm) );
	
	if (p_iUnit == MIN)
		sprintf(p_cpStr,"%04d_%02d_%02d_%02d_%02d",stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour, stTargetTime.tm_min);
	if (p_iUnit == HOUR)
		sprintf(p_cpStr,"%04d_%02d_%02d_%02d",stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday, stTargetTime.tm_hour);
	if (p_iUnit == DAY)
		sprintf(p_cpStr,"%04d_%02d_%02d",stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);

	if (p_iUnit == WEEK)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = stTargetTime.tm_mday - stTargetTime.tm_wday;
		stTargetTime.tm_wday = 0;
		p_cpTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_cpTime), sizeof(struct tm) );
	
		sprintf(p_cpStr,"%04d_%02d_%02d",stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1, stTargetTime.tm_mday);
	}

	if (p_iUnit == MONTH)
		sprintf(p_cpStr,"%04d_%02d",stTargetTime.tm_year + 1900, stTargetTime.tm_mon +1);

	if (p_iUnit == YEAR)
		sprintf(p_cpStr,"%04d",stTargetTime.tm_year + 1900);

	if (p_iUnit == DECADE)
	{
		stTargetTime.tm_min = 0;
		stTargetTime.tm_hour = 0;
		stTargetTime.tm_mday = 1;
		stTargetTime.tm_mon = 0;
		stTargetTime.tm_year = stTargetTime.tm_year - stTargetTime.tm_year%10;
		p_cpTime = mktime(&stTargetTime);
		memcpy(&stTargetTime, localtime(&p_cpTime), sizeof(struct tm) );

		sprintf(p_cpStr,"%04d",stTargetTime.tm_year + 1900);
	}
}
//########################################################################################################
void g_calTime(char *p_cpLogPreFix, struct timeval p_stStartTime, struct timeval p_stEndTime)
{
	struct timeval	stConsumedTime;
	char caLogFile[256];
	char caLogstr[256];

	stConsumedTime.tv_sec = p_stEndTime.tv_sec - p_stStartTime.tv_sec;
	stConsumedTime.tv_usec = p_stEndTime.tv_usec - p_stStartTime.tv_usec;
	if ( stConsumedTime.tv_usec < 0 )
	{
		stConsumedTime.tv_sec -= 1;
		stConsumedTime.tv_usec = (p_stEndTime.tv_usec - p_stStartTime.tv_usec + 1000000);
	}

	printf("function timeCheck() took %ld.%03ld seconds\n", stConsumedTime.tv_sec,
			stConsumedTime.tv_usec / 1000);	//	pay attention to divide 'tv_usec' by 1000
	
	sprintf(caLogstr,"computation Time	:	%ld.%03ld	", stConsumedTime.tv_sec,
			stConsumedTime.tv_usec / 1000);
	sprintf(caLogFile,"%s",p_cpLogPreFix);

	g_writeLogDay(caLogFile, caLogstr);

}	
//########################################################################################################
int g_isValidAddr(unsigned int p_uiAddr)
{
	unsigned int uiAddr;

	uiAddr = ntohl(p_uiAddr);
	if ( uiAddr == 0x00000000 )							return 0;       // 0.0.0.0
	if ( 0x0A000000 <= uiAddr && uiAddr <= 0x0AFFFFFF  )	return 0;       // 10.0.0.0     ~ 10.255.255.255	<- private
	if ( 0x7F000000 <= uiAddr && uiAddr <= 0x7F0000FF  )	return 0;       // 127.0.0.0    ~ 127.0.0.255		<- Loopback
	if ( 0xAC100001 <= uiAddr && uiAddr <= 0xAC1FFFFF  )	return 0;       // 172.16.0.1   ~ 172.31.255.255	<- private
	if ( 0xC0A80001 <= uiAddr && uiAddr <= 0xC0A8FFFF  )	return 0;       // 192.168.0.1  ~ 192.168.255.255	<- private
	if ( 0xE0000001 <= uiAddr && uiAddr <= 0xFFFFFFFF  )	return 0;       // 224.0.0.1    ~ 255.255.255.255	<- multicast
	return 1;
}
//########################################################################################################
int g_isLocalAddr(unsigned int p_uiAddr)
{
	unsigned int uiAddr;

	uiAddr = ntohl(p_uiAddr);

	if ( 0xA398CF00 <= uiAddr && uiAddr <= 0xA398EFFF ) return 1;       // 163.152.207.0 ~ 163.152.239.255
	return 0;
}
//########################################################################################################
void g_convertAddrToString(char* p_cpStr, u_int32_t p_ui32Addr)
{
	struct in_addr siAddr;

	memset(&siAddr, 0, sizeof(struct in_addr) );
	memcpy(&siAddr, &p_ui32Addr, 4);
	strcpy(p_cpStr, (const char *)inet_ntoa(siAddr) );
}
//########################################################################################################
u_int32_t g_convertStringtoAddr(char* p_cpStr)
{
	return inet_addr(p_cpStr);

}
//########################################################################################################
int g_setLogFileName(char* p_caFileName, char* p_caPathName)
{
	DIR *dp;
	struct dirent *entry;
	struct stat	statbuf;
	time_t tLastMtime=0;

	
	chdir(p_caPathName);
	dp = opendir(p_caPathName);

	while ( (entry = readdir(dp) ) != NULL ) // readdir 은 다음디렉터리 항목에 대한 구조체의 포인터를 돌려줌
	{
		lstat( entry->d_name, &statbuf );   //  L stat  파일 이름을 받는다.

		if( S_ISDIR( statbuf.st_mode ) )   //디렉토리에 대한 판정 ok
			continue;
		
		//printf("%s	%d\n",entry->d_name,statbuf.st_ctime); 
		
		if (tLastMtime < statbuf.st_ctime)		//last status change
		{
			tLastMtime = statbuf.st_ctime;
			sprintf(p_caFileName, "%s%s", p_caPathName, entry->d_name);
		}
	}
	if (tLastMtime == 0)		//파일 없음
	{
		return 0;
	}
	return 1;
}
//########################################################################################################
int g_setLogFileName(char* p_caFileName, char* p_caPathName, char *p_cpPreFix)
{
	DIR *dp;
	struct dirent *entry;
	struct stat	statbuf;
	time_t tLastMtime=0;

	
	chdir(p_caPathName);
	dp = opendir(p_caPathName);

	while ( (entry = readdir(dp) ) != NULL ) // readdir 은 다음디렉터리 항목에 대한 구조체의 포인터를 돌려줌
	{
		lstat( entry->d_name, &statbuf );   //  L stat  파일 이름을 받는다.

		if( S_ISDIR( statbuf.st_mode ) )   //디렉토리에 대한 판정 ok
			continue;
		if (strstr(entry->d_name, p_cpPreFix)==NULL)
			continue;
		
		//printf("%s	%d\n",entry->d_name,statbuf.st_ctime); 
		
		if (tLastMtime < statbuf.st_ctime)		//last status change
		{
			tLastMtime = statbuf.st_ctime;
			sprintf(p_caFileName, "%s%s", p_caPathName, entry->d_name);
		}
	}
	if (tLastMtime == 0)		//파일 없음
	{
		return 0;
	}
	return 1;
}
//########################################################################################################
int g_isLabAddr(unsigned int p_uiAddr)
{
	unsigned int uiAddr;

	uiAddr = ntohl(p_uiAddr);

	if ( 0xA398DBB8 <= uiAddr && uiAddr <= 0xA398DBDC ) return 1;       // 163.152.219.184 ~ 163.152.219.220
	return 0;
}
//########################################################################################################
bool isDigit(char ch)
{
	if ( ch >= '0' && ch <= '9' )
		return true;
	return false;
}
//########################################################################################################
bool isHexChar(char ch)
{
	if ( ch >= 'A' && ch <= 'F' )
		return true;

	if ( ch >= 'a' && ch <= 'f' )
		return true;
	return false;
}
