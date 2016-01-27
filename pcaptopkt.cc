#include "pcaptopkt.h"

//########################################################################################
void convertFromPcapToPkt(char* p_caTargetDirectory, FILE* p_fpLogFile)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	
	char					caTargetPcapFileName[1024]={0,};
	char					caStorePktFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	u_int32_t				iIndex;
	u_int32_t				uiTotalPcapFileCount;
		
	u_int32_t				uiTotalPcapEntryCount;
	u_int32_t				uiTotalTCPPcapEntryCount;
	u_int32_t				uiTotalUDPPcapEntryCount;
	u_int32_t				uiTotalOtherPcapEntryCount;

	u_int32_t				uiStorePcapEntryCount;
	u_int32_t				uiStoreTCPPcapEntryCount;
	u_int32_t				uiStoreUDPPcapEntryCount;
	u_int32_t				uiStoreOtherPcapEntryCount;
	
	
	PacketStoredInfo 		pktInfo;
	unsigned char			*payload;
	PcapReader				pcap;
	Packet					pkt;

	FILE					*fp_pkt;
	FILE					*fp_log;



	//make target path 
	sprintf(caTragetDirectory, "%s/tmp", p_caTargetDirectory);
//	puts(caTragetDirectory);
		
	//count pcap file
	uiTotalPcapFileCount = scandir(caTragetDirectory, &filelist, isPcapfile, mysort);

	//all pcap file read in target path for count
	uiTotalPcapEntryCount = 0;
	uiTotalTCPPcapEntryCount = 0;
	uiTotalUDPPcapEntryCount = 0;
	uiTotalOtherPcapEntryCount = 0;
	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				pcap.reset(); pktInfo.reset(); pkt.reset();

				//pcap file open
				pcap.offlineFileOpen(caTargetPcapFileName); // PCAP열기
				
				while ( (payload = pcap.readPkt(&pktInfo)) != NULL ) ////////////////////////////////////////CHECK : pcap_next 함수를 통해 패킷정보를 받아와 'payload' 변수에 저장
				{
					pkt.set(&pktInfo, payload);

					//total
					uiTotalPcapEntryCount++;
					
					//TCP
					if( pkt.ip_proto == IPPROTO_TCP)
						uiTotalTCPPcapEntryCount++;				
					//UDP
					if( pkt.ip_proto == IPPROTO_UDP)
						uiTotalUDPPcapEntryCount++;				
					//Other
					if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP) )
						uiTotalOtherPcapEntryCount++;
					
					pktInfo.reset();
					pkt.reset();
				}

				//pcap file close
				pcap.offlineFileClose();
			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiTotalPcapEntryCount != (uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount))
	{	
		printf("uiTotalPcapEntryCount : %d != uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount : %d\n", 
			uiTotalPcapEntryCount, uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount);
		g_err((char*)"total pcap count error");
	}


	//all pcap file read in target path for convert

	uiStorePcapEntryCount = 0;
	uiStoreTCPPcapEntryCount = 0;
	uiStoreUDPPcapEntryCount = 0;
	uiStoreOtherPcapEntryCount = 0;


	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStorePktFileName, "%s/%s.pkt", caTragetDirectory, caTemp );
				//	puts(caStorePktFileName);

				//만약 변환될 파일이 이미 존재하면 다시 변환하지 않는다.
				if (access(caStorePktFileName, F_OK))
				{

						//pkt file open
						if( (fp_pkt = fopen( caStorePktFileName, "wb")) != NULL )
						{
							pcap.reset(); pktInfo.reset(); pkt.reset();

							//pcap file open
							pcap.offlineFileOpen(caTargetPcapFileName);
							
							while ( (payload = pcap.readPkt(&pktInfo)) != NULL )
							{
								//load bar
								pkt.set(&pktInfo, payload);

								//Other
								if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
									continue;

								
								//total
								uiStorePcapEntryCount++;
								

								//TCP
								if( pkt.ip_proto == IPPROTO_TCP)
									uiStoreTCPPcapEntryCount++;				
								//UDP
								if( pkt.ip_proto == IPPROTO_UDP)
									uiStoreUDPPcapEntryCount++;				
								//Other
								if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
									uiStoreOtherPcapEntryCount++;
								

								//pkt file write					
								fwrite(&pktInfo, 1, sizeof(PacketStoredInfo),  fp_pkt);
								fwrite(payload, 1, pktInfo.stored_len, fp_pkt);

								pktInfo.reset();
								pkt.reset();
							}

							//pcap file close
							pcap.offlineFileClose();
							
							//pkt file close
							fclose(fp_pkt);
						}
						else
							g_err((char*)"PKT FILE OPEN ....!!!");

				}

			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiStorePcapEntryCount != (uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount))
	{	printf("uiStorePcapEntryCount : %d != uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount : %d\n", 
		uiStorePcapEntryCount, uiStoreTCPPcapEntryCount, uiStoreUDPPcapEntryCount, uiStoreOtherPcapEntryCount);
		g_err((char*)"store pcap count error");
	}

	//log file 
	sprintf(caStoreLogFileName, "%s/01_log_pkt.txt", caTragetDirectory);
	//puts(caStoreLogFileName);

	//write log 
	if( (fp_log = fopen( caStoreLogFileName, "wt")) != NULL )
	{
		fprintf(fp_log,"uiTotalPcapEntryCount : %d\r\n",uiTotalPcapEntryCount);
		fprintf(fp_log,"uiTotalTCPPcapEntryCount : %d\r\n",uiTotalTCPPcapEntryCount);
		fprintf(fp_log,"uiTotalUDPPcapEntryCount : %d\r\n",uiTotalUDPPcapEntryCount);
		fprintf(fp_log,"uiTotalOtherPcapEntryCount : %d\r\n\r\n",uiTotalOtherPcapEntryCount);

		fprintf(fp_log,"uiStorePcapEntryCount : %d\r\n",uiStorePcapEntryCount);
		fprintf(fp_log,"uiStoreTCPPcapEntryCount : %d\r\n",uiStoreTCPPcapEntryCount);
		fprintf(fp_log,"uiStoreUDPPcapEntryCount : %d\r\n",uiStoreUDPPcapEntryCount);
		fprintf(fp_log,"uiStoreOtherPcapEntryCount : %d\r\n",uiStoreOtherPcapEntryCount);

		fclose(fp_log);
	}
	else
		g_err((char*)"can't log file");

	
	fprintf(p_fpLogFile,"--before filter--\r\n");				//<------	log에 pcap 정보 표시
	fprintf(p_fpLogFile,"%d (TCP: %d, UDP: %d, OTHER: %d)\r\n", uiTotalPcapEntryCount, uiTotalTCPPcapEntryCount, uiTotalUDPPcapEntryCount, uiTotalOtherPcapEntryCount);

	fprintf(p_fpLogFile,"--after filter--\r\n");
	fprintf(p_fpLogFile,"%d (TCP: %d, UDP: %d, OTHER: %d)\r\n", uiTotalPcapEntryCount-uiTotalOtherPcapEntryCount, uiTotalTCPPcapEntryCount, uiTotalUDPPcapEntryCount, 0);
}
//########################################################################################
void convertFromPcapToPkt(char* p_caTargetDirectory)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	
	char					caTargetPcapFileName[1024]={0,};
	char					caStorePktFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	u_int32_t				iIndex;
	u_int32_t				uiTotalPcapFileCount;
		
	u_int32_t				uiTotalPcapEntryCount;
	u_int32_t				uiTotalTCPPcapEntryCount;
	u_int32_t				uiTotalUDPPcapEntryCount;
	u_int32_t				uiTotalOtherPcapEntryCount;

	u_int32_t				uiStorePcapEntryCount;
	u_int32_t				uiStoreTCPPcapEntryCount;
	u_int32_t				uiStoreUDPPcapEntryCount;
	u_int32_t				uiStoreOtherPcapEntryCount;
	
	
	PacketStoredInfo 		pktInfo;
	unsigned char			*payload;
	PcapReader				pcap;
	Packet					pkt;

	FILE					*fp_pkt;
	FILE					*fp_log;



	//make target path 
	sprintf(caTragetDirectory, "%s/tmp", p_caTargetDirectory);
//	puts(caTragetDirectory);
		
	//count pcap file
	uiTotalPcapFileCount = scandir(caTragetDirectory, &filelist, isPcapfile, mysort);

	//all pcap file read in target path for count
	uiTotalPcapEntryCount = 0;
	uiTotalTCPPcapEntryCount = 0;
	uiTotalUDPPcapEntryCount = 0;
	uiTotalOtherPcapEntryCount = 0;
	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				pcap.reset(); pktInfo.reset(); pkt.reset();

				//pcap file open
				pcap.offlineFileOpen(caTargetPcapFileName);
				
				while ( (payload = pcap.readPkt(&pktInfo)) != NULL )
				{
					pkt.set(&pktInfo, payload);

					//total
					uiTotalPcapEntryCount++;
					
					//TCP
					if( pkt.ip_proto == IPPROTO_TCP)
						uiTotalTCPPcapEntryCount++;				
					//UDP
					if( pkt.ip_proto == IPPROTO_UDP)
						uiTotalUDPPcapEntryCount++;				
					//Other
					if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP) )
						uiTotalOtherPcapEntryCount++;
					
					pktInfo.reset();
					pkt.reset();
				}

				//pcap file close
				pcap.offlineFileClose();
			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiTotalPcapEntryCount != (uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount))
	{	
		printf("uiTotalPcapEntryCount : %d != uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount : %d\n", 
			uiTotalPcapEntryCount, uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount);
		g_err((char*)"total pcap count error");
	}


	//all pcap file read in target path for convert

	uiStorePcapEntryCount = 0;
	uiStoreTCPPcapEntryCount = 0;
	uiStoreUDPPcapEntryCount = 0;
	uiStoreOtherPcapEntryCount = 0;


	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStorePktFileName, "%s/%s.pkt", caTragetDirectory, caTemp );
				//	puts(caStorePktFileName);

				//pkt file open
				if( (fp_pkt = fopen( caStorePktFileName, "wb")) != NULL )
				{
					pcap.reset(); pktInfo.reset(); pkt.reset();

					//pcap file open
					pcap.offlineFileOpen(caTargetPcapFileName);
					
					while ( (payload = pcap.readPkt(&pktInfo)) != NULL )
					{
						//load bar
						pkt.set(&pktInfo, payload);

						//Other
						if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
							continue;

						
						//total
						uiStorePcapEntryCount++;
						

						//TCP
						if( pkt.ip_proto == IPPROTO_TCP)
							uiStoreTCPPcapEntryCount++;				
						//UDP
						if( pkt.ip_proto == IPPROTO_UDP)
							uiStoreUDPPcapEntryCount++;				
						//Other
						if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
							uiStoreOtherPcapEntryCount++;
						

						//pkt file write					
						fwrite(&pktInfo, 1, sizeof(PacketStoredInfo),  fp_pkt);
						fwrite(payload, 1, pktInfo.stored_len, fp_pkt);

						pktInfo.reset();
						pkt.reset();
					}

					//pcap file close
					pcap.offlineFileClose();
					
					//pkt file close
					fclose(fp_pkt);
				}
				else
					g_err((char*)"PKT FILE OPEN ....!!!");

			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiStorePcapEntryCount != (uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount))
	{	printf("uiStorePcapEntryCount : %d != uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount : %d\n", 
		uiStorePcapEntryCount, uiStoreTCPPcapEntryCount, uiStoreUDPPcapEntryCount, uiStoreOtherPcapEntryCount);
		g_err((char*)"store pcap count error");
	}

	//log file 
	sprintf(caStoreLogFileName, "%s/tmp/01_log_pkt.txt", p_caTargetDirectory);
	//puts(caStoreLogFileName);

	//write log 
	if( (fp_log = fopen( caStoreLogFileName, "wt")) != NULL )
	{
		fprintf(fp_log,"uiTotalPcapEntryCount : %d\r\n",uiTotalPcapEntryCount);
		fprintf(fp_log,"uiTotalTCPPcapEntryCount : %d\r\n",uiTotalTCPPcapEntryCount);
		fprintf(fp_log,"uiTotalUDPPcapEntryCount : %d\r\n",uiTotalUDPPcapEntryCount);
		fprintf(fp_log,"uiTotalOtherPcapEntryCount : %d\r\n\r\n",uiTotalOtherPcapEntryCount);

		fprintf(fp_log,"uiStorePcapEntryCount : %d\r\n",uiStorePcapEntryCount);
		fprintf(fp_log,"uiStoreTCPPcapEntryCount : %d\r\n",uiStoreTCPPcapEntryCount);
		fprintf(fp_log,"uiStoreUDPPcapEntryCount : %d\r\n",uiStoreUDPPcapEntryCount);
		fprintf(fp_log,"uiStoreOtherPcapEntryCount : %d\r\n",uiStoreOtherPcapEntryCount);

		fclose(fp_log);
	}
	else
		g_err((char*)"can't log file");

}
//########################################################################################
void convertFromPcapToPkt(char* p_caCurrentWorkingDirectory, char *p_cpDataPath, char *p_cpPcapPath, u_int32_t p_uiTrial_num, char *p_cpPktPath, char *p_cpLogPath)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	char					caStoreDirectory[1024]={0,};
	char					caStoreLogDirectory[1024]={0,};

	char					caTargetPcapFileName[1024]={0,};
	char					caStorePktFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	u_int32_t				iIndex;
	u_int32_t				uiTotalPcapFileCount;
		
	u_int32_t				uiCurrentPcapEntryCount;

	u_int32_t				uiTotalPcapEntryCount;
	u_int32_t				uiTotalLocalLocalPcapEntryCount;
	u_int32_t				uiTotalRemoteRemotePcapEntryCount;
	u_int32_t				uiTotalTCPPcapEntryCount;
	u_int32_t				uiTotalUDPPcapEntryCount;
	u_int32_t				uiTotalOtherPcapEntryCount;

	u_int32_t				uiStorePcapEntryCount;
	u_int32_t				uiStoreLocalLocalPcapEntryCount;
	u_int32_t				uiStoreRemoteRemotePcapEntryCount;
	u_int32_t				uiStoreTCPPcapEntryCount;
	u_int32_t				uiStoreUDPPcapEntryCount;
	u_int32_t				uiStoreOtherPcapEntryCount;
	
	
	PacketStoredInfo 		pktInfo;
	unsigned char			*payload;
	PcapReader				pcap;
	Packet					pkt;

	FILE					*fp_pkt;
	FILE					*fp_log;



	//make target path 
	sprintf(caTragetDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpPcapPath);
//	puts(caTragetDirectory);
	
	//make store path 
	sprintf(caStoreDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpPktPath);
//	puts(caStoreDirectory);

	//make store directory 
	mkdir(caStoreDirectory, 0777);

	//make loge path 
	sprintf(caStoreLogDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpLogPath);
//	puts(caStoreLogDirectory);

	//make log directory 
	mkdir(caStoreLogDirectory, 0777);

	//count pcap file
	uiTotalPcapFileCount = scandir(caTragetDirectory, &filelist, isPcapfile, mysort);

	//all pcap file read in target path for count
	
	uiTotalPcapEntryCount = 0;
	uiTotalLocalLocalPcapEntryCount = 0;
	uiTotalRemoteRemotePcapEntryCount = 0;
	uiTotalTCPPcapEntryCount = 0;
	uiTotalUDPPcapEntryCount = 0;
	uiTotalOtherPcapEntryCount = 0;
	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				pcap.reset(); pktInfo.reset(); pkt.reset();

				//pcap file open
				pcap.offlineFileOpen(caTargetPcapFileName);
				
				while ( (payload = pcap.readPkt(&pktInfo)) != NULL )
				{
					pkt.set(&pktInfo, payload);

					//total
					uiTotalPcapEntryCount++;
					
					//local-local
					if (g_isLocalAddr(pkt.src_addr) && g_isLocalAddr(pkt.dst_addr))
						uiTotalLocalLocalPcapEntryCount++;
					
					//remote-remote
					if (!g_isLocalAddr(pkt.src_addr) && !g_isLocalAddr(pkt.dst_addr))
						uiTotalRemoteRemotePcapEntryCount++;

					//TCP
					if( pkt.ip_proto == IPPROTO_TCP)
						uiTotalTCPPcapEntryCount++;				
					//UDP
					if( pkt.ip_proto == IPPROTO_UDP)
						uiTotalUDPPcapEntryCount++;				
					//Other
					if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP) )
						uiTotalOtherPcapEntryCount++;
					
					pktInfo.reset();
					pkt.reset();
				}

				//pcap file close
				pcap.offlineFileClose();
			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiTotalPcapEntryCount != (uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount))
	{	
		printf("uiTotalPcapEntryCount : %d != uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount : %d\n", 
			uiTotalPcapEntryCount, uiTotalTCPPcapEntryCount + uiTotalUDPPcapEntryCount + uiTotalOtherPcapEntryCount);
		g_err((char*)"total pcap count error");
	}


	//all pcap file read in target path for convert
	uiCurrentPcapEntryCount = 0;

	uiStorePcapEntryCount = 0;
	uiStoreLocalLocalPcapEntryCount = 0;
	uiStoreRemoteRemotePcapEntryCount = 0;
	uiStoreTCPPcapEntryCount = 0;
	uiStoreUDPPcapEntryCount = 0;
	uiStoreOtherPcapEntryCount = 0;


	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPcapFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPcapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPcapFileName);

				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStorePktFileName, "%s/%s.pkt", caStoreDirectory, caTemp );
				//	puts(caStorePktFileName);

				//pkt file open
				if( (fp_pkt = fopen( caStorePktFileName, "wb")) != NULL )
				{
					pcap.reset(); pktInfo.reset(); pkt.reset();

					//pcap file open
					pcap.offlineFileOpen(caTargetPcapFileName);
					
					while ( (payload = pcap.readPkt(&pktInfo)) != NULL )
					{
						//load bar
						uiCurrentPcapEntryCount++;
						loadBar("convert pcap to pkt         ", uiCurrentPcapEntryCount, uiTotalPcapEntryCount, uiTotalPcapEntryCount, 75);

						pkt.set(&pktInfo, payload);

						//local-local
						if (g_isLocalAddr(pkt.src_addr) && g_isLocalAddr(pkt.dst_addr))
							continue;
						
						//remote-remote
						if (!g_isLocalAddr(pkt.src_addr) && !g_isLocalAddr(pkt.dst_addr))
							continue;
						
						//Other
						if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
							continue;

						
						//total
						uiStorePcapEntryCount++;
						
						//local-local
						if (g_isLocalAddr(pkt.src_addr) && g_isLocalAddr(pkt.dst_addr))
							uiStoreLocalLocalPcapEntryCount++;
						
						//remote-remote
						if (!g_isLocalAddr(pkt.src_addr) && !g_isLocalAddr(pkt.dst_addr))
							uiStoreRemoteRemotePcapEntryCount++;

						//TCP
						if( pkt.ip_proto == IPPROTO_TCP)
							uiStoreTCPPcapEntryCount++;				
						//UDP
						if( pkt.ip_proto == IPPROTO_UDP)
							uiStoreUDPPcapEntryCount++;				
						//Other
						if( (pkt.ip_proto != IPPROTO_TCP) && (pkt.ip_proto != IPPROTO_UDP))
							uiStoreOtherPcapEntryCount++;
						

						//pkt file write					
						fwrite(&pktInfo, 1, sizeof(PacketStoredInfo),  fp_pkt);
						fwrite(payload, 1, pktInfo.stored_len, fp_pkt);

						pktInfo.reset();
						pkt.reset();
					}

					//pcap file close
					pcap.offlineFileClose();
					
					//pkt file close
					fclose(fp_pkt);
				}
				else
					g_err((char*)"PKT FILE OPEN ....!!!");

			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//error check
	if (uiStorePcapEntryCount != (uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount))
	{	printf("uiStorePcapEntryCount : %d != uiStoreTCPPcapEntryCount + uiStoreUDPPcapEntryCount + uiStoreOtherPcapEntryCount : %d\n", 
		uiStorePcapEntryCount, uiStoreTCPPcapEntryCount, uiStoreUDPPcapEntryCount, uiStoreOtherPcapEntryCount);
		g_err((char*)"store pcap count error");
	}

	//log file 
	sprintf(caStoreLogFileName, "%s/%d_01_log_pkt.txt", caStoreLogDirectory, p_uiTrial_num );
	//puts(caStoreLogFileName);

	//write log 
	if( (fp_log = fopen( caStoreLogFileName, "wt")) != NULL )
	{
		fprintf(fp_log,"uiTotalPcapEntryCount : %d\r\n",uiTotalPcapEntryCount);
		fprintf(fp_log,"uiTotalLocalLocalPcapEntryCount : %d\r\n",uiTotalLocalLocalPcapEntryCount);
		fprintf(fp_log,"uiTotalRemoteRemotePcapEntryCount : %d\r\n",uiTotalRemoteRemotePcapEntryCount);
		fprintf(fp_log,"uiTotalTCPPcapEntryCount : %d\r\n",uiTotalTCPPcapEntryCount);
		fprintf(fp_log,"uiTotalUDPPcapEntryCount : %d\r\n",uiTotalUDPPcapEntryCount);
		fprintf(fp_log,"uiTotalOtherPcapEntryCount : %d\r\n\r\n",uiTotalOtherPcapEntryCount);

		fprintf(fp_log,"uiStorePcapEntryCount : %d\r\n",uiStorePcapEntryCount);
		fprintf(fp_log,"uiStoreLocalLocalPcapEntryCount : %d\r\n",uiStoreLocalLocalPcapEntryCount);
		fprintf(fp_log,"uiStoreRemoteRemotePcapEntryCount : %d\r\n",uiStoreRemoteRemotePcapEntryCount);
		fprintf(fp_log,"uiStoreTCPPcapEntryCount : %d\r\n",uiStoreTCPPcapEntryCount);
		fprintf(fp_log,"uiStoreUDPPcapEntryCount : %d\r\n",uiStoreUDPPcapEntryCount);
		fprintf(fp_log,"uiStoreOtherPcapEntryCount : %d\r\n",uiStoreOtherPcapEntryCount);

		fclose(fp_log);
	}
	else
		g_err((char*)"can't log file");


}
