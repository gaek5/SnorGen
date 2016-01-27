#include "pkttoflowwithpkt.h"

//########################################################################################
void convertFromPktToFwp(char* p_caTargetDirectory, FILE* p_fpLogFile)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	
	char					caTargetPktFileName[1024]={0,};
	char					caStoreFwpFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	u_int32_t				uiTotalPktFileCount;
	u_int32_t				iIndex;
	u_int32_t				uiTotalPktEntryCount;
	
	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	PacketContainer			cPacketContainer;
	FILE					*fp_pkt;
	int						iLen;

	FlowHash				cFlowHash;
	

	
	//make target path 
	sprintf(caTragetDirectory, "%s/tmp", p_caTargetDirectory);
//	puts(caTragetDirectory);
	
	//count pkt file
	uiTotalPktFileCount = scandir(caTragetDirectory, &filelist, isPktfile, mysort);

	int regFileCount=0;
	//all pkt file read in target path for convert	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPktFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				regFileCount++;

				sprintf(caTargetPktFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPktFileName);

				//store file 
				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStoreFwpFileName, "%s/%s.fwp", caTragetDirectory, caTemp );
				//	puts(caStoreFwpFileName);
				
				
				//만약 변환될 파일이 이미 존재하면 다시 변환하지 않는다.
				if (access(caStoreFwpFileName, F_OK))
				{
					fprintf(p_fpLogFile,"#%d file : %-30s - ", regFileCount, caTemp);
				
						
						
						if ( (fp_pkt = fopen(caTargetPktFileName, "rb")) != NULL )
						{
							while ( iLen = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp_pkt) )
							{
								if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"convertFromPktToFwp() : file open error pktInfo");

								iLen = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp_pkt);
								if ( iLen!= cPacketContainer.pktInfo.stored_len )	g_err((char*)"convertFromPktToFwp() : file open error stored_len");

								cPacketContainer.pkt.set(&cPacketContainer.pktInfo, cPacketContainer.payload);

								//insert
								cFlowHash.insert(&cPacketContainer);
							}
							fclose(fp_pkt);
						}
						else
							g_err((char*)"pkt file open error");

						//log file 
						sprintf(caStoreLogFileName, "%s/tmp/02_log_fwp_%s.txt", p_caTargetDirectory, filelist[iIndex]->d_name );
						//puts(caStoreLogFileName);

						//statistic log
						cFlowHash.print(caStoreLogFileName);


						//non-data fwp delete
						cFlowHash.deleteNonData();

						//statistic log
						cFlowHash.print(caStoreLogFileName);

						//log file 
						sprintf(caStoreLogFileName, "%s/tmp/02_log_fwp_detail_%s.txt", p_caTargetDirectory, filelist[iIndex]->d_name );
						//puts(caStoreLogFileName);

						//detail log
						cFlowHash.resetFlowListSortByTime();
						cFlowHash.printFlowList(caStoreLogFileName);

						//pwp file write 
						cFlowHash.store(caStoreFwpFileName);
						
					fprintf(p_fpLogFile,"flow : %llu   pkt : %llu   byte : %llu\r\n", cFlowHash.m_cFPBToTal.getFlow(), cFlowHash.m_cFPBToTal.getPkt(), cFlowHash.m_cFPBToTal.getByte());

						cFlowHash.reset();
				}


			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");


}
//########################################################################################
void convertFromPktToFwp(char* p_caTargetDirectory)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	
	char					caTargetPktFileName[1024]={0,};
	char					caStoreFwpFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	u_int32_t				uiTotalPktFileCount;
	u_int32_t				iIndex;
	u_int32_t				uiTotalPktEntryCount;
	
	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	PacketContainer			cPacketContainer;
	FILE					*fp_pkt;
	int						iLen;

	FlowHash				cFlowHash;
	

	
	//make target path 
	sprintf(caTragetDirectory, "%s/tmp", p_caTargetDirectory);
//	puts(caTragetDirectory);
	
	//count pkt file
	uiTotalPktFileCount = scandir(caTragetDirectory, &filelist, isPktfile, mysort);

	//all pkt file read in target path for count
	uiTotalPktEntryCount = 0;
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPktFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPktFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPktFileName);
				if ( (fp_pkt = fopen(caTargetPktFileName, "rb")) != NULL )
				{
					while ( iLen = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp_pkt) )
					{
						if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"convertFromPktToFwp() : file open error pktInfo");

						iLen = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp_pkt);
						if ( iLen!= cPacketContainer.pktInfo.stored_len )	g_err((char*)"convertFromPktToFwp() : file open error stored_len");

						uiTotalPktEntryCount++;
			
					}
					fclose(fp_pkt);
				}
				else
					g_err((char*)"pkt file open error");
			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//all pkt file read in target path for convert	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPktFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPktFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPktFileName);
				
				if ( (fp_pkt = fopen(caTargetPktFileName, "rb")) != NULL )
				{
					while ( iLen = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp_pkt) )
					{
						if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"convertFromPktToFwp() : file open error pktInfo");

						iLen = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp_pkt);
						if ( iLen!= cPacketContainer.pktInfo.stored_len )	g_err((char*)"convertFromPktToFwp() : file open error stored_len");

						cPacketContainer.pkt.set(&cPacketContainer.pktInfo, cPacketContainer.payload);

						//insert
						cFlowHash.insert(&cPacketContainer);
					}
					fclose(fp_pkt);
				}
				else
					g_err((char*)"pkt file open error");

				//log file 
				sprintf(caStoreLogFileName, "%s/tmp/02_log_fwp_%s.txt", p_caTargetDirectory, filelist[iIndex]->d_name );
				//puts(caStoreLogFileName);

				//statistic log
				cFlowHash.print(caStoreLogFileName);


				//non-data fwp delete
				cFlowHash.deleteNonData();

				//statistic log
				cFlowHash.print(caStoreLogFileName);

				//log file 
				sprintf(caStoreLogFileName, "%s/tmp/02_log_fwp_detail_%s.txt", p_caTargetDirectory, filelist[iIndex]->d_name );
				//puts(caStoreLogFileName);

				//detail log
				cFlowHash.printFlowList(caStoreLogFileName);

				//store file 
				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStoreFwpFileName, "%s/%s.fwp", caTragetDirectory, caTemp );
				//	puts(caStoreFwpFileName);

				//pwp file write 
				cFlowHash.store(caStoreFwpFileName);	

				cFlowHash.reset();


			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

}
//########################################################################################
void convertFromPktToFwp(char* p_caCurrentWorkingDirectory, char *p_cpDataPath, char *p_cpPktPath, u_int32_t p_uiTrial_num, char *p_cpFwpPath, char *p_cpLogPath)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	char					caStoreDirectory[1024]={0,};
	char					caStoreLogDirectory[1024]={0,};

	char					caTargetPktFileName[1024]={0,};
	char					caStoreFwpFileName[1024]={0,};
	char					caStoreLogFileName[1024]={0,};

	u_int32_t				uiTotalPktFileCount;
	u_int32_t				iIndex;
	u_int32_t				uiTotalPktEntryCount;
	u_int32_t				uiCurrentPktEntryCount;

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	PacketContainer			cPacketContainer;
	FILE					*fp_pkt;
	int						iLen;

	FlowHash				cFlowHash;
	

	
	//make target path 
	sprintf(caTragetDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpPktPath);
//	puts(caTragetDirectory);
	
	//make store path 
	sprintf(caStoreDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpFwpPath);
//	puts(caStoreDirectory);

	//make store directory 
	mkdir(caStoreDirectory, 0777);

	//make loge path 
	sprintf(caStoreLogDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpLogPath);
//	puts(caStoreLogDirectory);

	//make log directory 
	mkdir(caStoreLogDirectory, 0777);

	//count pkt file
	uiTotalPktFileCount = scandir(caTragetDirectory, &filelist, isPktfile, mysort);

	//all pkt file read in target path for count
	uiTotalPktEntryCount = 0;
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPktFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPktFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPktFileName);
				if ( (fp_pkt = fopen(caTargetPktFileName, "rb")) != NULL )
				{
					while ( iLen = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp_pkt) )
					{
						if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"convertFromPktToFwp() : file open error pktInfo");

						iLen = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp_pkt);
						if ( iLen!= cPacketContainer.pktInfo.stored_len )	g_err((char*)"convertFromPktToFwp() : file open error stored_len");

						uiTotalPktEntryCount++;
			
					}
					fclose(fp_pkt);
				}
				else
					g_err((char*)"pkt file open error");
			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");

	//all pkt file read in target path for convert
	uiCurrentPktEntryCount = 0;
	
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{
		chdir(caTragetDirectory);
		for (iIndex=0; iIndex < uiTotalPktFileCount; iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetPktFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetPktFileName);
				
				if ( (fp_pkt = fopen(caTargetPktFileName, "rb")) != NULL )
				{
					while ( iLen = fread(&cPacketContainer.pktInfo, 1, sizeof(PacketStoredInfo), fp_pkt) )
					{
						if ( iLen != sizeof(PacketStoredInfo) )	g_err((char*)"convertFromPktToFwp() : file open error pktInfo");

						iLen = fread(cPacketContainer.payload, 1, cPacketContainer.pktInfo.stored_len, fp_pkt);
						if ( iLen!= cPacketContainer.pktInfo.stored_len )	g_err((char*)"convertFromPktToFwp() : file open error stored_len");

						//load bar
						uiCurrentPktEntryCount++;
						loadBar("convert pkt to fwp          ", uiCurrentPktEntryCount, uiTotalPktEntryCount, uiTotalPktEntryCount, 75);

						cPacketContainer.pkt.set(&cPacketContainer.pktInfo, cPacketContainer.payload);

						//insert
						cFlowHash.insert(&cPacketContainer);
					}
					fclose(fp_pkt);
				}
				else
					g_err((char*)"pkt file open error");

				//log file 
				sprintf(caStoreLogFileName, "%s/%d_02_log_fwp_%s.txt", caStoreLogDirectory, p_uiTrial_num, filelist[iIndex]->d_name );
				//puts(caStoreLogFileName);

				//statistic log
				cFlowHash.print(caStoreLogFileName);


				//non-data fwp delete
				cFlowHash.deleteNonData();

				//statistic log
				cFlowHash.print(caStoreLogFileName);

				//log file 
				sprintf(caStoreLogFileName, "%s/%d_02_log_fwp_detail_%s.txt", caStoreLogDirectory, p_uiTrial_num, filelist[iIndex]->d_name );
				//puts(caStoreLogFileName);

				//detail log
				cFlowHash.printFlowList(caStoreLogFileName);

				//store file 
				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStoreFwpFileName, "%s/%s.fwp", caStoreDirectory, caTemp );
				//	puts(caStoreFwpFileName);

				//pwp file write 
				cFlowHash.store(caStoreFwpFileName);	

				cFlowHash.reset();


			}
		}
		closedir(dp);
	}
	else
		g_err((char*)"can't opendir");
}
