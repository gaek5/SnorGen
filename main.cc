/*#####################################################################
이름		:	SnorGen

버젼정보	:	1.0.0	2014-10-24	(shyoon)	test_sequntial_pattern-1.7.0 을 온라인 버젼으로 변경
				1.1.0	2014-10-27	(shyoon)	content offset 표시
				1.2.0	2014-10-30	(shyoon)	content minimum length define문으로 정의, 파라미터가 2개이면 비교, ./SonrGen A B  B를 fwp까지 진행, A fwp를 넣고 결과 출력, A fwp 삭제
				1.3.0	2014-11-01	(shyoon)	IS_FLOW_SEQUENCE : flow, packet 단위 flog 추가, MAX_SEQUENCE_LENGTH : sequence 최대 길이 추가
				1.4.0	2014-11-01	(shyoon)	pthread 추가, MAX_PKT_COUNT 추가 packet 단위로 적용할때 최대 몇개의 pkt를 로드할지 결정 
				1.5.0	2014-11-02	(shyoon)	innerthread 추가, support 계산도 Thread로
				1.6.0	2014-11-03	(shyoon)	support 계산만 Thread로 구현
				1.7.0	2014-11-03	(shyoon)	packet 기준으로 규칙이 매칭하는 트래픽 양 계산
				2.0.0	2014-11-03	(shyoon)	class 정리	(A:101rules, 18.045; B: 384rules, 5m24.419;) 
				2.1.0	2014-11-03	(shyoon)	K+1 생성시 뒤에서부터 support 확인, support 넘으면 생성에 참여한 K supp 0으로 셋 (A:133rules, 14.939; B: 613rules, 4m52.227;) 
												벡터 포함여부 함수 search() 적용 (A:133rules, 10.986; B: 613rules, 3m56.206;) 
												서버변경 (A:133rules, 6.455; B: 613rules, 2m0.260;) 
				2.2.0	2014-11-11	(shyoon)	snort form protocol 표시 
												setCompleteness()
				2.3.0	2014-11-13	(shyoon)	K+1 생성시 생성되는 K+1의 SUPP 보다 K의 SUPP가 더 크면 삭제 안함
				2.4.0	2014-11-13	(shyoon)	protocol any시 모든 경우 규칙 추가
												log에 Flow-level complteness, Packet-level complteness
												depth 버그
												정렬 : supp -> pkt comp
				2.5.0	2014-11-17	(shyoon)	web버젼에 맞게 수정
				2.6.0	2014-11-18	(shyoon)	support 1 출력되는 버그 수정
												threshold log에 출력
												total Rule 버그 수정
												support hight
				3.0.0	2014-11-26	(shyoon)	옵션 처리 -p tragetPath -b blackList
				3.1.0	2014-11-26	(shyoon)	blacklist 적용 content가 blacklist를 포함하면 해당 blacklist로 content 분리
				3.2.0	2014-11-27	(shyoon)	sequence, rule에 프로토콜 표시
												HTTP 이면, HTTP whiteList 적용 method, host, useragent, referer
				3.3.0	2014-11-28	(shyoon)	옵션 에러 처리 갯수 안맞으면 에러
												TLS whitelist
				3.4.0	2014-11-28	(shyoon)	multi content 구현
				3.5.0	2014-12-02	(shyoon)	프로그램 정리
												split 구현
				3.6.0	2014-12-03	(shyoon)	프로그램 정리
												sequence에서 header 정보 제외
												1차 완성
				3.7.0	2014-12-05	(shyoon)	파서 구현
				3.8.0	2014-12-08	(shyoon)	black, white, split 제거 
												multi thread 적용
				3.9.0	2014-12-14	(shyoon)	suspect list 적용, supp 검사할때 suspect list(seqID, offset)만 검사

				3.10.0	2014-12-31	(shyoon)	파일 1개 입력 시 result.txt에 에러 표시

				4.0.0	2015-02-09	(shyoon)	sequence로 변환	(fileID, pktIDList, header, content(contentID, protocol, field, chatVector, location))
												TLS parser 0x16 handshake만 적용
												multi contetn lenght 1 추출 완료
				
				4.0.1	2015-02-10	(shyoon)	multi contetn 추출

				4.0.2	2015-02-11	(shyoon)	header 처리

				4.0.3	2015-02-11	(shyoon)	location 처리
												
기능		:	
				
주의사항	:	
				
실행방법	:	./SnorGen $traget_path

주요함수	: 
########################################################################*/

#include "include.h" 
#include "util.h"
#include "pcaptopkt.h"
#include "pkttoflowwithpkt.h"
#include "captopcap.h"
#include "sequenceExtracter.h"
#include "timeChecker.h"
#include "loadbar.h"

#define MAXSTR 256
//#######################################################################
#define THREAD_COUNT				4
#define PARSER						1		// 0 : parser off, 1: parser on
#define DIFF_MIN_SUPP				2		// 0 : min_supp is file_count, 1 : min_supp is file_count-1 ....
#define MIN_CONTENT_LENGTH			3		// -1 : nolimit
#define MAX_PKT_COUNT_FORWARD		-1		// -1 : nolimit
#define MAX_PKT_COUNT_BACKWARD		-1		// -1 : nolimit
#define MAX_SEQUENCE_LENGTH			-1		// -1 : nolimit
//#######################################################################
int main(int argc, char** argv)
{ 
	int						opt;
	char					caTargetDirectory[1024]={0,};
	char					caResultDirectory[1024]={0,};
	char					caLogFileName[1024]={0,};
	char					caResultFileName[1024]={0,};
	char					caResultTextFileName[1024]={0,};
	char					caHTMLFileName[1024]={0,};
	FILE*					fp_log;
	TimeChecker				cTimeChecker;

	int						iTotalFwpFileCount;
	struct					dirent **filelist;
	DIR						*dp;
	u_int32_t				iIndex;
	struct					stat statbuf;
	char					caTargetFwpFileName[1024]={0,};
	char					caStoreFwpFileName[1024]={0,};
	char					caCMD[1024]={0,};

	while((opt = getopt(argc, argv, ":hp:")) != -1 )
	{
		switch(opt)
		{
			case 'h':
				printf("[USAGE} : ./Snorgen -p targetPath [-b -w]\n");
				exit(0);
				break;
			case 'p':
				strcpy(caTargetDirectory, optarg);
				//puts(caTargetDirectory);
				break;
			case ':':
				printf("%c option needs a value\n",optopt);
				exit(0);
				break;
			case '?':
				printf("unknown option: %c\n",optopt);
				exit(0);
				break;
		}
	}
	if (optind < argc)
	{
		printf("[USAGE} : ./Snorgen -p targetPath\n");
		exit(0);
	}

	//make result path															<--------   log, result 저장 장소
	sprintf(caResultDirectory, "%s/tmp", caTargetDirectory);
	sprintf(caCMD, "rm -rf %s",caResultDirectory);
	system(caCMD);
	mkdir(caResultDirectory, 0777);

	sprintf(caResultDirectory, "%s/result", caTargetDirectory);
	sprintf(caCMD, "rm -rf %s",caResultDirectory);
	system(caCMD);
	mkdir(caResultDirectory, 0777);

	sprintf(caLogFileName,"%s/log.txt", caResultDirectory);
	sprintf(caResultFileName,"%s/rule.rules", caResultDirectory);
	sprintf(caResultTextFileName,"%s/rule.txt", caResultDirectory);
	sprintf(caHTMLFileName,"%s/ruleHTML.txt", caResultDirectory);

	//log file open
	if ( (fp_log = fopen(caLogFileName, "wt")) != NULL )
	{


		fprintf(fp_log,"SnorGen\r\n");
		fprintf(fp_log,"Made by Sung-Ho Yoon	(sungho_yoon@korea.ac.kr)\r\n");
		fprintf(fp_log,"Network Management Lab. Korea Univ.   (nmlab.korea.ac.kr)\r\n");
		fprintf(fp_log,"final version. 3.8.0 (2014-12-08)\r\n");
		fprintf(fp_log,"\r\n");
		//
		//puts(caTargetDirectory);

		fprintf(fp_log,"--Configuration--\r\n");
		fprintf(fp_log,"THREAD_COUNT : %d\r\n", THREAD_COUNT);
		fprintf(fp_log,"PARSER : %s\r\n", PARSER?"ON":"OFF");
		fprintf(fp_log,"DIFF_MIN_SUPP : %d (1 : min_supp is (file_count-1))\r\n", DIFF_MIN_SUPP);
		fprintf(fp_log,"MIN_CONTENT_LENGTH : %d\r\n", MIN_CONTENT_LENGTH);
		fprintf(fp_log,"MAX_PKT_COUNT_FORWARD : %d (-1 : nolimit)\r\n", MAX_PKT_COUNT_FORWARD);
		fprintf(fp_log,"MAX_PKT_COUNT_BACKWARD : %d (-1 : nolimit)\r\n", MAX_PKT_COUNT_BACKWARD);
		fprintf(fp_log,"MAX_SEQUENCE_LENGTH : %d (-1 : nolimit)\r\n", MAX_SEQUENCE_LENGTH);
		fprintf(fp_log,"\r\n");

	
		cTimeChecker.reset();
		cTimeChecker.startClock();
		fprintf(fp_log,"--file checking start.--\r\n");
		


		///분석 1단계 완료 _ 이성호(1.18)
		//기본적인 전처리 과정
		//**************************************************************************************************
			//convert cap to pcap with snaplen	captopcap.h   $tatget_path/tmp/file_name.pcap 으로 저장
			convertFromCapToPcap(caTargetDirectory, fp_log);
			fprintf(fp_log,"\r\n");
			
			//convert pcap to pkt
			convertFromPcapToPkt(caTargetDirectory, fp_log);
			fprintf(fp_log,"\r\n");
			
			
			//convert pkt to flow_with_pkt
			convertFromPktToFwp(caTargetDirectory, fp_log);
		//**************************************************************************************************

		fprintf(fp_log,"--file checking end.--\r\n");
		cTimeChecker.endClock();
		cTimeChecker.print(fp_log);
		fprintf(fp_log,"\r\n");

		

		cTimeChecker.reset();
		cTimeChecker.startClock();

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Snorgen 핵심 파트 , 룰 생성
		fprintf(fp_log,"--rule generating start.--\r\n");

			//gernerate pattern
			sequence(caTargetDirectory, THREAD_COUNT, PARSER, DIFF_MIN_SUPP, MIN_CONTENT_LENGTH, MAX_PKT_COUNT_FORWARD, MAX_PKT_COUNT_BACKWARD, MAX_SEQUENCE_LENGTH, fp_log, caResultTextFileName, caResultFileName, caHTMLFileName);			//<--------   규칙 생성
		
		fprintf(fp_log,"--rule generating end.--\r\n");
		cTimeChecker.endClock();
		cTimeChecker.print(fp_log);
		fprintf(fp_log,"\r\n");


		fclose(fp_log);
	}
	else
	{
		g_err((char*)"Snorget main() : logfile fopen error");
	}

}
