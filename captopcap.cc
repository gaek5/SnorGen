#include "captopcap.h"
//########################################################################################
void convertFromCapToPcap(char* p_caTargetDirectory, FILE* p_fpLogFile) // 파일 1개 이하 에러, capinfos 명령어로 trace 검증
{
	char					caTmpDirectory[1024]={0,};
	char					caTargetTrafficFileName[1024]={0,};
	char					caStorePcapFileName[1024]={0,};
	char					caTemp[1024]={0,};
	char					caCmdLine[1024]={0,};

	u_int32_t				uiTotalCapFileCount;

	int						iIndex;

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;


	// capinfos program check											<--------   해당 파일이 트래픽 파일인지 확인하는 명령어
	if (system("/usr/bin/which capinfos > /dev/null 2>&1"))
	{
		fprintf(p_fpLogFile, "ERROR: no capinfos, yum install wireshark\r\n");
		g_err((char*)"ERROR: no capinfos, yum install wireshark");
	}

	// editcap program check											<--------   pcap 형태로 변환하기 위한 명령어
	if (system("/usr/bin/which editcap > /dev/null 2>&1"))
	{
		fprintf(p_fpLogFile, "ERROR: no editcap, yum install wireshark\r\n");
		g_err((char*)"ERROR: no editcap, yum install wireshark");
	}

	




	//make tmp path															<--------   변환될 파일을 저장할 디렉토리
	sprintf(caTmpDirectory, "%s/tmp", p_caTargetDirectory);
	//puts(caTmpDirectory);

	//make tmp directory 
	sprintf(caCmdLine, "rm -rf %s",caTmpDirectory);
	system(caCmdLine);
	mkdir(caTmpDirectory, 0777);

	
	
	
	
	//check traffic 파일 
	uiTotalCapFileCount = scandir(p_caTargetDirectory, &filelist, selfile_all, mysort);
	bool fileErrorFlag = false;
	int regFileCount = 0;
	//all traffic file read in target path
	if ( (dp = opendir(p_caTargetDirectory)) != NULL )
	{	
		chdir(p_caTargetDirectory);
		for (iIndex=0;iIndex<uiTotalCapFileCount ;iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				regFileCount++;

				sprintf(caTargetTrafficFileName, "%s/%s", p_caTargetDirectory, filelist[iIndex]->d_name);
				//puts(caTargetTrafficFileName);

				fprintf(p_fpLogFile,"#%02d(%lu KB): %s - ", regFileCount, (unsigned int)statbuf.st_size/1024, filelist[iIndex]->d_name);
				

				sprintf(caCmdLine, "/usr/sbin/capinfos %s  > /dev/null 2>&1", caTargetTrafficFileName);
				if (system(caCmdLine))
				{
					fprintf(p_fpLogFile, "invalid file\r\n");
					fileErrorFlag = true;

					puts(caCmdLine);
					
				}
				else
				{
					fprintf(p_fpLogFile, "OK\r\n");
				}
			}
		}
		closedir(dp);
	}
	else
	{
		puts(p_caTargetDirectory);
		g_err((char*)"can't opendir");
	}

	if (fileErrorFlag)										//									<--------   트래픽 파일이 아닌 파일이 포함되어 있는 경우
	{
		fprintf(p_fpLogFile, "ERROR: include invalid file\r\n");
		fprintf(p_fpLogFile, "Abnormal termination\r\n");
		g_err((char*)"ERROR: include invalid file");
	}

	if (regFileCount == 0)										//									<--------   파일 개수가 1이하인 경우
	{
		fprintf(p_fpLogFile, "Please Input Traffic files!!\r\n");
		g_err((char*)"ERROR: less file count");
		
	}



	//check file count											//									<--------   앞에서 파일 개수가 1이하인 경우, 비정상 파일을 체크함으로 모두 정상적인 트래픽 파일이라 가정
	uiTotalCapFileCount = scandir(p_caTargetDirectory, &filelist, selfile_all, mysort);
	//all traffic file read in target path
	if ( (dp = opendir(p_caTargetDirectory)) != NULL )
	{	
		chdir(p_caTargetDirectory);
		for (iIndex=0;iIndex<uiTotalCapFileCount ;iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetTrafficFileName, "%s/%s", p_caTargetDirectory, filelist[iIndex]->d_name);
			//	puts(caTargetTrafficFileName);
				
				if (strstr(filelist[iIndex]->d_name,"."))
					strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				else
					strcpy(caTemp,filelist[iIndex]->d_name);
				sprintf(caStorePcapFileName, "%s/%s.pcap", caTmpDirectory, caTemp );
			//	puts(caStorePcapFileName);

				//만약 변환될 파일이 이미 존재하면 다시 변환하지 않는다.
				if (access(caStorePcapFileName, F_OK))
				{
					sprintf(caCmdLine, "editcap -d -s 1500 -T ether -F libpcap %s %s  > /dev/null 2>&1", caTargetTrafficFileName, caStorePcapFileName);		//-s 옵션을 주는 이유는 로컬에 수집된 트래픽 파일은 단편화가 되지 않아 1500을 넘게 된다 1500 이 넘게 되면 향후 pkt, fwp 변환에서 에러 발생
					if (system(caCmdLine))
					{
						puts(caCmdLine);
						g_err((char*)"ERROR: editcap running error");
					}
				}
			}
		}
		closedir(dp);
	}
	else
	{
		puts(p_caTargetDirectory);
		g_err((char*)"can't opendir");
	}
}
//########################################################################################
void convertFromCapToPcap(char* p_caTargetDirectory)
{
	char					caTmpDirectory[1024]={0,};
	char					caTargetTrafficFileName[1024]={0,};
	char					caStorePcapFileName[1024]={0,};
	char					caTemp[1024]={0,};
	char					caCmdLine[1024]={0,};

	u_int32_t				uiTotalCapFileCount;

	int						iIndex;

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;


	// editcap program chekc
	if (system("/usr/bin/which editcap > /dev/null 2>&1"))
	{
		g_err((char*)"ERROR: no editcap, yum install wireshark");
	}

	//make tmp path 
	sprintf(caTmpDirectory, "%s/tmp", p_caTargetDirectory);
	//puts(caTmpDirectory);

	//make tmp directory 
	mkdir(caTmpDirectory, 0777);


	//check file count
	uiTotalCapFileCount = scandir(p_caTargetDirectory, &filelist, isTrafficfile, mysort);
	

	//all traffic file read in target path
	if ( (dp = opendir(p_caTargetDirectory)) != NULL )
	{	
		chdir(p_caTargetDirectory);
		for (iIndex=0;iIndex<uiTotalCapFileCount ;iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				sprintf(caTargetTrafficFileName, "%s/%s", p_caTargetDirectory, filelist[iIndex]->d_name);
			//	puts(caTargetTrafficFileName);
				
				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStorePcapFileName, "%s/%s.pcap", caTmpDirectory, caTemp );
			//	puts(caStorePcapFileName);
				
				sprintf(caCmdLine, "editcap -d -s 1500 -T ether -F libpcap %s %s  > /dev/null 2>&1", caTargetTrafficFileName, caStorePcapFileName);
				if (system(caCmdLine))
				{
					puts(caCmdLine);
					g_err((char*)"ERROR: editcap running error");
				}

			}
		}
		closedir(dp);
	}
	else
	{
		puts(p_caTargetDirectory);
		g_err((char*)"can't opendir");
	}

}
//########################################################################################
void convertFromCapToPcap(char* p_caCurrentWorkingDirectory, char *p_cpDataPath, char *p_cpCapPath, u_int32_t p_uiSnapLen, u_int32_t p_uiTrial_num, char *p_cpPcapPath)
{
	char					caTemp[1024]={0,};
	char					caTragetDirectory[1024]={0,};
	char					caStoreDirectory[1024]={0,};
	
	char					caTargetCapFileName[1024]={0,};
	char					caStorePcapFileName[1024]={0,};
	
	char					caCmdLine[1024]={0,};

	int						iIndex;

	DIR						*dp;
	struct					stat statbuf;
	struct					dirent **filelist;

	u_int32_t				uiTotalCapFileCount;

	// editcap program chekc
	if (system("/usr/bin/which editcap > /dev/null 2>&1"))
	{
		g_err((char*)"ERROR: no editcap, yum install wireshark");
	}

	//make target path 
	sprintf(caTragetDirectory, "%s/%s/%d_%s",p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpCapPath);
	//puts(caTragetDirectory);
	
	//make store path 
	sprintf(caStoreDirectory, "%s/%s/%d_%s", p_caCurrentWorkingDirectory, p_cpDataPath, p_uiTrial_num, p_cpPcapPath);
	//puts(caStoreDirectory);

	//make store directory 
	mkdir(caStoreDirectory, 0777);

	//check file count
	uiTotalCapFileCount = scandir(caTragetDirectory, &filelist, isCapfile, mysort);
	

	//all file (.cap) read in target path
	if ( (dp = opendir(caTragetDirectory)) != NULL )
	{	
		chdir(caTragetDirectory);
		for (iIndex=0;iIndex<uiTotalCapFileCount ;iIndex++ )
		{
			lstat(filelist[iIndex]->d_name, &statbuf);
			if ( S_ISREG(statbuf.st_mode) )
			{
				loadBar("convert cap to pcap(file)   ", iIndex+1, uiTotalCapFileCount, uiTotalCapFileCount, 75);

				sprintf(caTargetCapFileName, "%s/%s", caTragetDirectory, filelist[iIndex]->d_name);
			//	puts(caTargetCapFileName);
				
				strncpy(caTemp,filelist[iIndex]->d_name, strstr(filelist[iIndex]->d_name,".")-filelist[iIndex]->d_name);
				sprintf(caStorePcapFileName, "%s/%s.pcap", caStoreDirectory, caTemp );
			//	puts(caStorePcapFileName);
				
				sprintf(caCmdLine, "editcap -d -s %d -T ether -F libpcap %s %s  > /dev/null 2>&1",p_uiSnapLen, caTargetCapFileName, caStorePcapFileName);
				if (system(caCmdLine))
				{
					puts(caCmdLine);
					g_err((char*)"ERROR: editcap running error");
				}

			}
		}
		closedir(dp);
	}
	else
	{
		puts(caTragetDirectory);
		g_err((char*)"can't opendir");
	}
}