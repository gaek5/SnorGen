#include "sequenceExtracter.h"

//########################################################################################
void sequence(char* p_caTargetDirectory, u_int32_t p_uiThreadCount, u_int32_t p_uiParser, u_int32_t p_uiDiffSupp, int p_iMinContentLength, int p_iMaxPktCountForward, int p_iMaxPktCountBackward, int p_iMaxSequenceLength, FILE* p_fpLogFile, char* p_caResultTextFileName, char* p_caResultFileName, char* p_caHTMLFileName)	//2014-12-08
{
	//###################################################
	//###################################################
	//###################################################
	//################ 전처리 ###########################
	//###################################################
	//###################################################
	//###################################################

	//###################################################
	//p_caTargetDirectory/tmp 디렉토리에서 .fwp 파일을 읽어 hash에 로드 
	char		caTragetDirectory[1024]={0,};
	FlowHash	cFlowHash;
	int			iTotalFwpFileCount;

	sprintf(caTragetDirectory, "%s/tmp", p_caTargetDirectory);			//fwp가 저장되어 있는 디렉토리 이름 set
	//puts(caTragetDirectory);
	
	cFlowHash.reset();
	iTotalFwpFileCount = cFlowHash.loadFlow(caTragetDirectory);			//caTragetDirectory에 저장되어 있는 모든 fwp 파일을 hash에 로드하고 파일 개수 리턴
	cFlowHash.resetFlowListSortByTime();
//	cFlowHash.printFlowList();
	cFlowHash.resetPktListSortByTime();
//	cFlowHash.printPktList();
	
	printf("total file count : %d\n", iTotalFwpFileCount);
	fprintf(p_fpLogFile,"total file count : %d\r\n", iTotalFwpFileCount);
	
	if (iTotalFwpFileCount >= 64)										//예외 처리 - 파일 개수 64이상 금지 (support 측정시 64bits flag 사용)
	{
		fprintf(p_fpLogFile,"ERROR!! : MAX file_count is 64. current file_count : %d\r\n", iTotalFwpFileCount);
		g_err((char*)"sequence() : file count error");
	}

	if (iTotalFwpFileCount < 2)											//예외처리 - 파일 개수 최소 2 이상 필요
	{
		FILE*					fp;
		if ( (fp = fopen(p_caHTMLFileName, "wt")) != NULL )
		{
			fprintf(fp, "<span class='run_hl1'>ERROR: minimum file count 2 for SronGen</span>\r\n");
			fclose(fp);
		}

		fprintf(p_fpLogFile, "ERROR: minimum file count 2 for SronGen\r\n");
		g_err((char*)"ERROR: minimum file count 2 for SronGen");
	}
	
	//######################################################################
	//hash에 저장된 fwp를 읽어 SequenceSet에 저장
	SequenceVector cMultiSequenceVector;
	SequenceVector cSingleSequenceVector;
	
	cMultiSequenceVector.reset();
	cMultiSequenceVector.load(&cFlowHash, p_iMaxPktCountForward, p_iMaxPktCountBackward, p_iMaxSequenceLength);	//cFlowHash에 저장된 fwp를 읽어 cSequence에 저장 
//	cMultiSequenceVector.print();

	printf("after load cMultiSequenceVector : %d\n",cMultiSequenceVector.getSequenceSize());
	fprintf(p_fpLogFile,"after load total Sequence : %d\r\n",cMultiSequenceVector.getSequenceSize());

	cSingleSequenceVector.reset();
	cSingleSequenceVector.insert(&cMultiSequenceVector);
	
	if (p_uiParser)
	{
		//######################################################################
		//cSequence를 프로토콜 파서로 쪼갬
		cSingleSequenceVector.parser();
	//	cSingleSequenceVector.print();

		printf("after parser cSingleSequenceVector : %d\n",cSingleSequenceVector.getSequenceSize());
		fprintf(p_fpLogFile,"after parser total cSingleSequenceVector : %d\r\n",cSingleSequenceVector.getSequenceSize());
	}
	
	cSingleSequenceVector.sortContent();			//support 계산시 빠르게 하기 위해 fileid 섞음	
//	cSingleSequenceVector.print();
	cSingleSequenceVector.breadkField();				//field 별 sequence 개수 개산


	//###################################################
	//###################################################
	//###################################################
	//################ 단일콘덴츠추출 ##################
	//###################################################
	//###################################################
	//###################################################

		
	//######################################################################				
	int iTargetSupp = iTotalFwpFileCount - p_uiDiffSupp;
	const int	iMinSupp = 2;
	if (iTargetSupp < iMinSupp) 
		iTargetSupp = iMinSupp;
	
	RuleList	cDetermineSingleRuleList;
	RuleList	cCandiSingleRuleList;
	
	int iContentLenght;

	int			lots_of_thread;
	int			res;
	pthread_t	a_thread[p_uiThreadCount];
	void		*thread_result;
	THRED_ARG	threadArg[p_uiThreadCount];	

	
	//######################################################################
	//길이 1인 후보패턴 추출
	printf("######### Extract Candidate content 1 (supp:%d)#########\n",iTargetSupp);
	cCandiSingleRuleList.extractSingleConentLength1(&cSingleSequenceVector);
	printf("cCandiSingleRuleList : %d\n",cCandiSingleRuleList.getRuleSize());
	cCandiSingleRuleList.setSingleSuspectSet(&cSingleSequenceVector);					//발견된 가능성이 있는 용의자 sequence의 집합을 규칙에 미리 기록
	cCandiSingleRuleList.setSupportSingle(&cSingleSequenceVector, iTotalFwpFileCount);
	cCandiSingleRuleList.deleteUnderSupport(iTargetSupp);
	printf("after delete under supp cCandiSingleRuleList : %d\n",cCandiSingleRuleList.getRuleSize());
//	cCandiSingleRuleList.print();

	//######################################################################
	//길이 K인 후보패턴 추출
	iContentLenght=1;
	while (cCandiSingleRuleList.getRuleSize())
	{
		//######################################################################
		//길이 K인 패턴 복사 (cCandiSingleRuleList -> cDetermineSingleRuleList)
		printf("#########  Copy Detemine content %d  (supp:%d)#########\n",iContentLenght,iTargetSupp);
		cDetermineSingleRuleList.insert(&cCandiSingleRuleList);
		//cDetermineSingleRuleList.print();
		printf("cDetermineSingleRuleList : %d\n",cDetermineSingleRuleList.getRuleSize());

		//######################################################################
		//	길이 K인 패턴으로 iContentLenght+1인 후보 패턴 추출
		printf("######### Extract Candidate content %d (supp:%d)#########\n",iContentLenght+1,iTargetSupp);

		cCandiSingleRuleList.reset();
		if (p_uiThreadCount)
		{
			for (lots_of_thread=0; lots_of_thread < p_uiThreadCount; lots_of_thread++)
			{
				threadArg[lots_of_thread].m_iIndex = lots_of_thread;							//thread 인덱스
				threadArg[lots_of_thread].m_iTotalThreadCount = p_uiThreadCount;				//thread 총 개수
				threadArg[lots_of_thread].m_cpSequenceVector = &cSingleSequenceVector;				//sequence 리스트
				threadArg[lots_of_thread].m_cpDetermineRuleList = &cDetermineSingleRuleList;	//추출된 rule 리스트
				threadArg[lots_of_thread].m_iTrargetLength = iContentLenght;					//추출 대상 길이
				threadArg[lots_of_thread].m_uiStartIndexTargetLength = cDetermineSingleRuleList.getStartIndexTargetLength(iContentLenght);	// 추출된 rule 리스트에서 추출 대상 길이가 시작하는 인텍스
				threadArg[lots_of_thread].m_uiTargetSupp = iTargetSupp;							//target 지지도
				threadArg[lots_of_thread].m_uiMaxSupp = iTotalFwpFileCount;						//파일 개수


				res = pthread_create(&a_thread[lots_of_thread], NULL, insertCandiSingle, (void *)&threadArg[lots_of_thread]);
				if (res != 0)
				{
					perror("thread creation failed");
					exit(EXIT_FAILURE);
				}
			}
			for (lots_of_thread=0; lots_of_thread < p_uiThreadCount; lots_of_thread++)
			{
				res = pthread_join(a_thread[lots_of_thread], &thread_result);
				if (res!=0)
				{
					perror("thread join failed");
					exit(EXIT_FAILURE);
				}
				cCandiSingleRuleList.insert(&threadArg[lots_of_thread].m_cpTempCandiRuleList);
				threadArg[lots_of_thread].m_cpTempCandiRuleList.reset();
			}
		}
		else																						//<------------  no thread
		{
			cCandiSingleRuleList.extractSingleConent(cDetermineSingleRuleList.getStartIndexTargetLength(iContentLenght), cDetermineSingleRuleList.getRuleSize(), &cDetermineSingleRuleList, iContentLenght, &cSingleSequenceVector, iTargetSupp, iTotalFwpFileCount);	// 길이 iContentLenght인 룰을 결합하여 iContentLenght+1을 만듬, 결합에 사용한 룰은 제거 (supp = 0)

		}
		cDetermineSingleRuleList.deleteUnderSupport(iTargetSupp);
		
		printf("cCandiSingleRuleList : %d\n",cCandiSingleRuleList.getRuleSize());
				
		iContentLenght++;
	}
	printf("after single extraction cDetermineSingleRuleList : %d\n",cDetermineSingleRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after single extraction single content rule : %d\r\n",cDetermineSingleRuleList.getRuleSize());
//	cDetermineSingleRuleList.print();

	if (p_iMinContentLength > 0)
	{
		//MIN_CONTENT_LENGTH 보다 짧은 content 삭제	, 단 모든 용의 sequence의 길이와 동일하면 유지(GET 경우)								
		cDetermineSingleRuleList.trimUnderContentLength(p_iMinContentLength, &cSingleSequenceVector);
		printf("after trim cDetermineSingleRuleList : %d\n",cDetermineSingleRuleList.getRuleSize());
		fprintf(p_fpLogFile,"after trim single content rule : %d\r\n",cDetermineSingleRuleList.getRuleSize());
	}
//	cDetermineSingleRuleList.print();



	//###################################################
	//###################################################
	//###################################################
	//################ 다중콘덴츠추출 ##################
	//###################################################
	//###################################################
	//###################################################

	RuleList	cDetermineMultiRuleList;
	RuleList	cCandiMultiRuleList;


	cSingleSequenceVector.integrate(&cDetermineSingleRuleList);			//cDetermineSingleRuleList의 content를 source sequence로 모음
//	cSingleSequenceVector.print();

	cMultiSequenceVector.integrate(&cSingleSequenceVector);				//cSingleSequenceVector의 multi content를 source pkt로 모음
//	cMultiSequenceVector.print();

	//######################################################################
	//길이 1인 후보패턴 추출
	printf("######### Extract Candidate multi-content 1 (supp:%d)#########\n",iTargetSupp);
	cCandiMultiRuleList.extractMultiConentLength1(&cMultiSequenceVector);
	printf("cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());
	cCandiMultiRuleList.setMultiSuspectSet(&cMultiSequenceVector);					//발견된 가능성이 있는 용의자 sequence의 집합을 규칙에 미리 기록
	cCandiMultiRuleList.setSupportMulti(&cMultiSequenceVector, iTotalFwpFileCount);
	cCandiMultiRuleList.deleteUnderSupport(iTargetSupp);
	printf("after delete under supp cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());
//	cCandiMultiRuleList.print();

	//######################################################################
	//길이 K인 후보패턴 추출
	iContentLenght=1;
	while (cCandiMultiRuleList.getRuleSize())
	{
		//######################################################################
		//길이 K인 패턴 복사 (cCandiMultiRuleList -> cDetermineMultiRuleList)
		printf("#########  Copy Detemine content %d  (supp:%d)#########\n",iContentLenght,iTargetSupp);
		cDetermineMultiRuleList.insert(&cCandiMultiRuleList);
	//	cDetermineMultiRuleList.print();
		printf("cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());

		//######################################################################
		//	길이 K인 패턴으로 iContentLenght+1인 후보 패턴 추출
		printf("######### Extract Candidate content %d (supp:%d)#########\n",iContentLenght+1,iTargetSupp);

		cCandiMultiRuleList.reset();
		cCandiMultiRuleList.extractMultiConent(cDetermineMultiRuleList.getStartIndexTargetCount(iContentLenght), cDetermineMultiRuleList.getRuleSize(), &cDetermineMultiRuleList, iContentLenght, &cMultiSequenceVector, iTargetSupp, iTotalFwpFileCount);	// 길이 iContentLenght인 룰을 결합하여 iContentLenght+1을 만듬, 결합에 사용한 룰은 제거 (supp = 0)
		cDetermineMultiRuleList.deleteUnderSupport(iTargetSupp);
		printf("cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());
				
		iContentLenght++;
	}
	printf("after multi extraction cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after multi extraction multi content rule : %d\r\n",cDetermineMultiRuleList.getRuleSize());
//	cDetermineMultiRuleList.print();


	
	
	//###################################################
	//###################################################
	//###################################################
	//############### 콘텐츠 위치 기입 #################
	//###################################################
	//###################################################
	//###################################################


	cDetermineMultiRuleList.setLocation(&cMultiSequenceVector);																// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 콘텐츠 위치 정보 set
	printf("after setLocation cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after setLocation multi content rule : %d\r\n",cDetermineMultiRuleList.getRuleSize());
//	cDetermineMultiRuleList.print();

	
	
	
	
	
	//###################################################
	//###################################################
	//###################################################
	//################## 헤더 기입 #####################
	//###################################################
	//###################################################
	//###################################################


	cDetermineMultiRuleList.setHeader(&cMultiSequenceVector);																// rule의 suspects list와 실제 패킷 집합인 cMultiSequenceVector을 참고하여 헤더 정보 set
	printf("after setHeader cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after setHeader multi content rule : %d\r\n",cDetermineMultiRuleList.getRuleSize());
//	cDetermineMultiRuleList.print();


	//###################################################
	//###################################################
	//###################################################
	//################ 분석률확인 ######################
	//###################################################
	//###################################################
	//###################################################

	cDetermineMultiRuleList.setCompleteness(&cFlowHash);
	printf("after setCompleteness cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after setCompleteness multi content rule : %d\r\n",cDetermineMultiRuleList.getRuleSize());
	cDetermineMultiRuleList.print();
	
	
	
	
return;






/*


	cDetermineSingleRuleList.resetSupspects();			//signle content를 위해 사용한 suspect set은 더이상 유효하지 않기 때문에 삭제
	
	cDetermineSingleRuleList.setLocation(&cSequenceVector);								//	cSequenceMultiList를 참조하여 content의 위치정보 set
	printf("after set location cDetermineSingleRuleList : %d\n",cDetermineSingleRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after set location single content rule : %d\r\n",cDetermineSingleRuleList.getRuleSize());
//	cDetermineSingleRuleList.print();


	//###################################################
	//###################################################
	//###################################################
	//######### 헤더 및 개별 분석률기입 ################
	//###################################################
	//###################################################
	//###################################################
		
	cDetermineSingleRuleList.setHeader(&cFlowHash, p_iMaxPktCountForward, p_iMaxPktCountBackward, p_iMaxSequenceLength);		//	cFlowHash를 참조하여 rule의 헤더정보 set
	printf("after setHeader location cDetermineSingleRuleList : %d\n",cDetermineSingleRuleList.getRuleSize());
	fprintf(p_fpLogFile,"after setHeader location single content rule : %d\r\n",cDetermineSingleRuleList.getRuleSize());
	//cDetermineSingleRuleList.print();
	
		
	//###################################################
	//###################################################
	//###################################################
	//################ 분석률확인 ######################
	//###################################################
	//###################################################
	//###################################################

	
	fprintf(p_fpLogFile,"total Rule : %d\r\n",cDetermineSingleRuleList.getRuleSize());
	cDetermineSingleRuleList.setCompleteness(&cFlowHash);
	
	FPB* cpFlowTotal = cDetermineSingleRuleList.getFlowTotalTraffic();
	FPB* cpFlowIdentified = cDetermineSingleRuleList.getFlowIdentifiedTraffic();
	FPB* cpPktTotal = cDetermineSingleRuleList.getPktTotalTraffic();
	FPB* cpPktIdentified = cDetermineSingleRuleList.getPktIdentifiedTraffic();
	if (cpFlowTotal->getFlow())
	{
		fprintf(p_fpLogFile,"Flow-level Completness\r\n flow: %.02f(%llu/%llu) pkt: %.02f(%llu/%llu) byte: %.02f(%llu/%llu)\r\n",
			(float)cpFlowIdentified->getFlow()*100/cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt()*100/cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte()*100/cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
		printf("Flow-level Completness\r\n flow: %.02f(%llu/%llu) pkt: %.02f(%llu/%llu) byte: %.02f(%llu/%llu)\r\n",
			(float)cpFlowIdentified->getFlow()*100/cpFlowTotal->getFlow(), cpFlowIdentified->getFlow(), cpFlowTotal->getFlow(),
			(float)cpFlowIdentified->getPkt()*100/cpFlowTotal->getPkt(), cpFlowIdentified->getPkt(), cpFlowTotal->getPkt(),
			(float)cpFlowIdentified->getByte()*100/cpFlowTotal->getByte(), cpFlowIdentified->getByte(), cpFlowTotal->getByte());
	}

	if (cpPktTotal->getPkt())
	{
		fprintf(p_fpLogFile,"Pcaket-level Completness\r\n pkt:%.02f(%llu/%llu) byte:%.02f(%llu/%llu)\r\n",
			(float)cpPktIdentified->getPkt()*100/cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte()*100/cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
		printf("Pcaket-level Completness\r\n pkt:%.02f(%llu/%llu) byte:%.02f(%llu/%llu)\r\n",
			(float)cpPktIdentified->getPkt()*100/cpPktTotal->getPkt(), cpPktIdentified->getPkt(), cpPktTotal->getPkt(),
			(float)cpPktIdentified->getByte()*100/cpPktTotal->getByte(), cpPktIdentified->getByte(), cpPktTotal->getByte());
	}
	//cDetermineSingleRuleList.print();


	//###################################################
	//###################################################
	//###################################################
	//################ 정렬 #############################
	//###################################################
	//###################################################
	//###################################################

	//정렬 
	cDetermineSingleRuleList.sortFlowLevelCompPkt();
	cDetermineSingleRuleList.sortFirstContentFix();
	cDetermineSingleRuleList.sortSupport();


		
	//###################################################
	//###################################################
	//###################################################
	//################ 출력 #############################
	//###################################################
	//###################################################
	//###################################################

	//최종 결과 출력
	cDetermineSingleRuleList.print();
	cDetermineSingleRuleList.print(p_caResultTextFileName);
	cDetermineSingleRuleList.printSnortFormHTML(p_caHTMLFileName);
	cDetermineSingleRuleList.printSnortForm(p_caResultFileName);
	
	return;


*/











	



	
	

/*


		
	//###################################################
	//###################################################
	//###################################################
	//################ 다중콘덴츠추출 ##################
	//###################################################
	//###################################################
	//###################################################

	RuleList	cDetermineMultiRuleList;
	RuleList	cCandiMultiRuleList;

	int iContentCount;

	//######################################################################
	//길이 1인 후보패턴 추출
	printf("######### Extract Candidate Sequence 1 (supp:%d)#########\n",iTargetSupp);
	cCandiMultiRuleList.extractMultiConentLength1(&cDetermineSingleRuleList);			//다중 content의 길이 1은 단일 content를 의미
	printf("cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());
	cCandiMultiRuleList.setMultiSuspectSet(&cSequenceMultiVector);					//발견된 가능성이 있는 용의자 sequence의 집합을 규칙에 미리 기록
	cCandiMultiRuleList.setSupportMulti(&cSequenceMultiVector, iTotalFwpFileCount);
	cCandiMultiRuleList.deleteUnderSupport(iTargetSupp);
	printf("after delete under supp cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());
//	cCandiMultiRuleList.print();
//	return;

	//######################################################################
	//길이 K인 후보패턴 추출
	iContentCount=1;
	while (cCandiMultiRuleList.getRuleSize())
	{
		//######################################################################
		//길이 K인 패턴 복사 (cCandiMultiRuleList -> cDetermineMultiRuleList)
		printf("#########  Copy Detemine Sequence %d  (supp:%d)#########\n",iContentCount,iTargetSupp);
		cDetermineMultiRuleList.insert(&cCandiMultiRuleList);
		//cDetermineMultiRuleList.print();
		printf("cDetermineMultiRuleList : %d\n",cDetermineMultiRuleList.getRuleSize());

		//######################################################################
		//	길이 K인 패턴으로 iContentCount+1인 후보 패턴 추출
		printf("######### Extract Candidate Sequence %d (supp:%d)#########\n",iContentCount+1,iTargetSupp);

		cCandiMultiRuleList.reset();
		if (p_uiThreadCount)
		{
			for (lots_of_thread=0; lots_of_thread < p_uiThreadCount; lots_of_thread++)
			{
				threadArg[lots_of_thread].m_iIndex = lots_of_thread;
				threadArg[lots_of_thread].m_iTotalThreadCount = p_uiThreadCount;
				threadArg[lots_of_thread].m_cpSequenceVector = &cSequenceMultiVector;
				threadArg[lots_of_thread].m_cpDetermineRuleList = &cDetermineMultiRuleList;
				threadArg[lots_of_thread].m_iTrargetLength = iContentCount;
				threadArg[lots_of_thread].m_uiStartIndexTargetLength = cDetermineMultiRuleList.getStartIndexTargetCount(iContentCount);	
				threadArg[lots_of_thread].m_uiTargetSupp = iTargetSupp;
				threadArg[lots_of_thread].m_uiMaxSupp = iTotalFwpFileCount;						//파일 개수


				res = pthread_create(&a_thread[lots_of_thread], NULL, insertCandiMulti, (void *)&threadArg[lots_of_thread]);
				if (res != 0)
				{
					perror("thread creation failed");
					exit(EXIT_FAILURE);
				}
			}
			for (lots_of_thread=0; lots_of_thread < p_uiThreadCount; lots_of_thread++)
			{
				res = pthread_join(a_thread[lots_of_thread], &thread_result);
				if (res!=0)
				{
					perror("thread join failed");
					exit(EXIT_FAILURE);
				}
				cCandiMultiRuleList.insert(&threadArg[lots_of_thread].m_cpTempCandiRuleList);
				threadArg[lots_of_thread].m_cpTempCandiRuleList.reset();
			}

		}
		else
		{
			cCandiMultiRuleList.extractMultiConent(cDetermineMultiRuleList.getStartIndexTargetCount(iContentCount), cDetermineMultiRuleList.getRuleSize(), &cDetermineMultiRuleList, iContentCount, &cSequenceMultiVector, iTargetSupp, iTotalFwpFileCount);	// 길이 iContentLenght인 룰을 결합하여 iContentCount+1을 만듬, 결합에 사용한 룰은 제거 (supp = 0)
		}
		cCandiMultiRuleList.unique();			//생성된 규칙 각각을 필드, content로 정렬하고, 각 규칙을 프로토콜, 
	
		cDetermineMultiRuleList.deleteUnderSupport(iTargetSupp);
		
		printf("cCandiMultiRuleList : %d\n",cCandiMultiRuleList.getRuleSize());

		iContentCount++;
	}
//		cDetermineMultiRuleList.print();
	//getchar();
//	return;









	cDetermineMultiRuleList.uniqueField();									//필드가 여러개 명시된 규칙은 content가 가장 긴 것만 남기고 삭제
//	cDetermineMultiRuleList.setLocation(&cSequenceMultiVector);				//	cSequenceMultiList를 참조하여 content의 위치정보 set
	cDetermineMultiRuleList.print();
	
	return;
	*/
	
}
//########################################################################################
void *insertCandiSingle(void *arg)
{
	
	THRED_ARG* spArg = (THRED_ARG*)arg;

	int iLow = (int)( (spArg->m_cpDetermineRuleList->getRuleSize() - spArg->m_uiStartIndexTargetLength) / spArg->m_iTotalThreadCount) * spArg->m_iIndex;
	int iHigh = (int)((spArg->m_cpDetermineRuleList->getRuleSize() - spArg->m_uiStartIndexTargetLength) / spArg->m_iTotalThreadCount) * (spArg->m_iIndex+1);

	iLow += spArg->m_uiStartIndexTargetLength;
	iHigh += spArg->m_uiStartIndexTargetLength;

	if (spArg->m_iIndex+1 == spArg->m_iTotalThreadCount) //마지막 쓰레드는 끝까지 검사
		iHigh = spArg->m_cpDetermineRuleList->getRuleSize();

	//printf("%d	%d	%d\n",spArg->m_iIndex, iLow, iHigh);

	spArg->m_cpTempCandiRuleList.reset();

	spArg->m_cpTempCandiRuleList.extractSingleConent(iLow, iHigh, spArg->m_cpDetermineRuleList, spArg->m_iTrargetLength, spArg->m_cpSequenceVector, spArg->m_uiTargetSupp, spArg->m_uiMaxSupp);

//	printf("thread %d finish\n",spArg->m_iIndex);
	
	pthread_exit(NULL);
}
//########################################################################################
void *insertCandiMulti(void *arg)
{
	
	THRED_ARG* spArg = (THRED_ARG*)arg;

	int iLow = (int)( (spArg->m_cpDetermineRuleList->getRuleSize() - spArg->m_uiStartIndexTargetLength) / spArg->m_iTotalThreadCount) * spArg->m_iIndex;
	int iHigh = (int)((spArg->m_cpDetermineRuleList->getRuleSize() - spArg->m_uiStartIndexTargetLength) / spArg->m_iTotalThreadCount) * (spArg->m_iIndex+1);

	iLow += spArg->m_uiStartIndexTargetLength;
	iHigh += spArg->m_uiStartIndexTargetLength;

	if (spArg->m_iIndex+1 == spArg->m_iTotalThreadCount) //마지막 쓰레드는 끝까지 검사
		iHigh = spArg->m_cpDetermineRuleList->getRuleSize();

	//printf("%d	%d	%d\n",spArg->m_iIndex, iLow, iHigh);

	spArg->m_cpTempCandiRuleList.reset();

	spArg->m_cpTempCandiRuleList.extractMultiConent(iLow, iHigh, spArg->m_cpDetermineRuleList, spArg->m_iTrargetLength, spArg->m_cpSequenceVector, spArg->m_uiTargetSupp, spArg->m_uiMaxSupp);

//	printf("thread %d finish\n",spArg->m_iIndex);
	
	pthread_exit(NULL);
}
